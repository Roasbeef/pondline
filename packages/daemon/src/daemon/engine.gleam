//// The single writer: the one process that holds the store connection and
//// runs every transition (spec §8.4, §10.2).
////
//// The core's state machines are pure and fast, so serializing all of them
//// through one actor costs little and removes a class of bugs: no two
//// transitions of one relationship can interleave, and a transition always
//// starts from the state the previous one committed. The store's version
//// column stays as the backstop.
////
//// Each operation is one job the actor runs to the end: load the state, run
//// the pure transition with the real `Suite` and the injected clock, commit
//// the whole `Plan` through `store.commit`, tell the shell about the
//// committed effects, and reply. A job is a closure over its arguments,
//// executed against the actor's own state, so the connection never leaves
//// this process and no transaction spans a message. Callers use the typed
//// functions below and never see the job.
////
//// ## Why a `weft/actor`, and why the store opens in the initialiser
////
//// The engine is a `weft/actor` that traps exits, and `on_shutdown` closes
//// the store (`close_store`), so a supervisor's orderly stop checkpoints and releases the
//// database file instead of leaving it to garbage collection. The shutdown
//// callback is best effort (it cannot run on a brutal kill), which is
//// enough here: nothing is lost by a missed close, because every commit is
//// already durable under `synchronous=FULL`.
////
//// The first work, opening and migrating the store and writing the agent
//// identifier, stays in the initialiser and is not a `continuing` message.
//// `continuing` exists so that `start` can return before slow first work
//// and still have it ordered ahead of the first request. The engine wants
//// the opposite: a database that cannot be opened must fail the start, and
//// the supervisor with it, so that a daemon that cannot reach its state
//// never accepts a command (`node.start` relies on this). Failing in a
//// continue message would instead start an engine that has nothing to serve.
////
//// ## What the engine never does
////
//// It never touches the network. It does not send, fetch, acknowledge or
//// create a queue; it only commits the records those workers act on and
//// nudges them afterwards through `notify`. That is what makes "no send
//// before commit" and "no ack before commit" structural: the workers read
//// committed rows back through the engine's read functions and receive no
//// bytes from a plan (spec §13.1).
////
//// ## Processing an envelope
////
//// `process` follows the simulation's honest shell (`core/test/world`): an
//// envelope counts as already processed only if both its identifier and its
//// digest match the `Processed` record, because a mailbox can replay a
//// ciphertext under a fresh identifier and a different ciphertext under an
//// old one. Anything else is opened as a frame and routed by its tag: an
//// `Initial` frame to the offer that owns the queue, a `Ratchet` frame to the
//// relationship that owns it. Whatever the core refuses is committed as
//// processed-and-dropped, so the mailbox can still be acknowledged once the
//// drop is durable.
////
//// An envelope that is not a repeat is counted before it is processed
//// (`store.count_attempt`, its own transaction). One that has failed
//// `limits.max_process_attempts` times is quarantined instead (ADR-010):
//// recorded as dropped, so the fetcher acknowledges it, and written as an
//// incident for the operator, so one envelope that cannot be processed
//// cannot block its queue. The count survives a crash of the engine, which
//// is what makes a crash loop end too.
////
//// A `Ratchet` frame is first looked up by its fingerprint
//// (`relationship.fingerprint`, `store.fingerprint`). A ciphertext the
//// relationship already stored a message from is a sender's retransmit or a
//// mailbox's replay: its key is spent, so it goes to
//// `relationship.resend_receipt`, which queues the same logical receipt
//// again and delivers nothing (ADR-006, spec §7.3).
////
//// Any other ratchet message is received in two steps (ADR-010):
//// `relationship.open` decrypts it, the engine reads whether the
//// relationship already stored a message under its identifier
//// (`store.message_history`), and `relationship.receive` decides with that
//// answer. A repeated identifier is ignored by the core and recorded as an
//// incident for the operator, so a forging peer cannot make the commit fail
//// on the deliveries' uniqueness and wedge its queue. A history that
//// cannot be read is `Unavailable`, never a guess.
////
//// ## Retransmitting
////
//// `retransmit` is the sending half of ADR-006, run by the scheduler on
//// every tick. It reads the stored rows whose receipt window has passed
//// (`store.due_retransmits`), asks `retransmit.retransmit` about each
//// against the relationship as it is now, and commits either a copy of the
//// row under a fresh envelope (`store.Retransmitted`, whose `Transmit`
//// effect wakes the scheduler) or the end of its schedule
//// (`store.RetransmitStopped`). The copy's bytes come from the committed
//// row inside the store, so a retransmit never re-encrypts.
////
//// ## Job kinds and the fault hook
////
//// Every job is labelled with a `JobKind`, one per public function, which
//// names the job to a mail interceptor (`kind_label`) and to an optional
//// fault hook. `handle` asks the hook for the job's `JobFate` (`fate`), and
//// `run`'s closure applies it (`answer`): `FailBeforeApply` answers
//// `Unavailable` without running the job, and `ApplyThenFail` runs it, commit
//// and notices included, then answers `Unavailable`, the ask that applied
//// and then errored. Only a simulation sets the hook; without one every job
//// applies.
////
//// ## Flow
////
//// 1. `start` opens the store and runs `ensure_agent_id`.
//// 2. Every public operation goes through `run`, which hands a job to
////    `handle` and waits for its reply.
//// 3. Jobs commit through `commit_change`, which tells the shell the effects
////    only after `store.commit` returned.
//// 4. `handle_envelope` is the inbound path, and `open_session` the
////    outbound one for a joiner whose queue just came up.
//// 5. `retransmit` sends stored rows again whose receipt never came.

import core/crypto/pqxdh
import core/crypto/suite.{type Suite}
import core/endpoint.{type CarrierPolicy, type Endpoint}
import core/envelope.{type Padded}
import core/field
import core/frame
import core/id.{
  type Contact, type Envelope, type Id, type Invitation as InvitationKind,
  type Message as MessageKind, type Queue,
}
import core/invitation
import core/limits
import core/offer.{type Approval}
import core/plan.{type EnvelopeRef, type Plan, EnvelopeRef}
import core/relationship.{type Relationship}
import core/retransmit
import core/route.{type Inbox}
import core/secret.{type Secret}
import core/time.{type Instant}
import daemon/mail.{type Handle}
import daemon/store.{type Store}
import gleam/erlang/process.{type Name, type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/supervision
import gleam/result
import gleam/string
import telemetry/field as log_field
import telemetry/log
import weft/actor

/// How long a caller waits for the engine before the call is reported
/// `Unavailable`. A job runs after every earlier one, and a commit can wait
/// out the store's busy timeout, so this is longer than that.
const call_timeout_ms = 30_000

/// Why an operation did not happen.
pub type Failure {
  /// There is no such contact, message or invitation.
  NotFound

  /// The invitation file is not usable: malformed or expired.
  InvalidInvitation(reason: String)

  /// The core refused the transition. The reason is a fixed phrase, never a
  /// value.
  Refused(reason: String)

  /// The store or the engine could not serve the call. Nothing changed.
  Unavailable
}

/// What `process` found.
pub type Handled {
  /// The envelope was new and its outcome is now committed.
  Fresh

  /// The envelope was already processed under the same identifier and
  /// digest. Nothing of the relationship changed; its processed row is
  /// marked unacknowledged again, so the fetcher's next round names it to
  /// the mailbox even if an earlier round already had.
  Repeat
}

/// Something the shell should hear about after a commit.
pub type Notice {
  /// An effect of the committed plan.
  Nudge(effect: plan.Effect)

  /// A relationship's state changed.
  Changed(contact: Id(Contact))

  /// An offer or relationship changed phase, so the set of queues to create
  /// or fetch may have changed.
  Topology
}

/// What the engine is started with.
pub type Config {
  Config(
    /// The database file. The caller has created it `0600`.
    path: String,
    /// The cryptographic primitives.
    suite: Suite,
    /// The current time.
    clock: fn() -> Instant,
    /// Which carriers may be dialled; checked on every route read from an
    /// invitation or a `Hello`.
    policy: CarrierPolicy,
    /// Where this daemon creates its own queues.
    mailbox: Endpoint,
    /// The inbound budget `accept` grants.
    accept_budget: Int,
    /// Told what a commit made true, after the commit.
    notify: fn(Notice) -> Nil,
    /// A fault hook for the store's transactions, or `None` in production.
    store_faults: Option(store.Faults),
    /// A fault hook for the engine's jobs, or `None` in production.
    faults: Option(fn(JobKind) -> JobFate),
  )
}

/// Which operation a job is, one per public function below. It labels the
/// job for the fault hook and for a mail interceptor, and carries no
/// argument, so neither can see a value.
pub type JobKind {
  Invite
  InvitationFile
  Accept
  Provisioned
  Approve
  Decline
  Close
  RaiseBudget
  Send
  Consume
  ExpireOffers
  Process
  Contacts
  Deliveries
  MessageState
  Audit
  LiveInboxes
  PendingInboxes
  DueOutbox
  RecordSend
  Unacked
  MarkAcked
  OutboxPending
  Retransmit
  Incidents
  IncidentCount
  DrainingInboxes
}

/// What the fault hook makes of one job. Only a simulation sets a hook; a
/// production engine applies every job.
pub type JobFate {
  /// Run the job and answer with its result.
  Apply

  /// Answer `Unavailable` without running the job: nothing changed.
  FailBeforeApply

  /// Run the job, commit and notify included, then answer `Unavailable`:
  /// the caller cannot tell this from `FailBeforeApply`.
  ApplyThenFail
}

/// The actor's mailbox protocol: one variant, a labelled job to run against
/// its own state under the fate the fault hook gives it. Public only because
/// the name's type mentions it.
pub opaque type Message {
  Run(kind: JobKind, job: fn(State, JobFate) -> Nil)
}

/// Everything a job may touch: the connection and the injected
/// dependencies.
type State {
  State(
    store: Store,
    suite: Suite,
    clock: fn() -> Instant,
    policy: CarrierPolicy,
    mailbox: Endpoint,
    accept_budget: Int,
    notify: fn(Notice) -> Nil,
    faults: Option(fn(JobKind) -> JobFate),
  )
}

/// Opens the store and starts the engine under `name`. Start fails, and the
/// supervisor with it, when the database cannot be opened or migrated: a
/// daemon that cannot reach its state must not accept commands.
///
/// ## Examples
///
/// ```gleam
/// let name = process.new_name("engine")
/// let assert Ok(_) = engine.start(name, config)
/// ```
pub fn start(
  name: Name(Message),
  config: Config,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    case initial_state(config) {
      Ok(state) ->
        actor.initialised(state)
        |> actor.returning(subject)
        |> Ok

      Error(reason) -> Error(reason)
    }
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.trapping_exits(True)
  |> actor.on_shutdown(close_store)
  |> actor.start
}

/// The engine as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// engine.supervised(name, config)
/// ```
pub fn supervised(
  name: Name(Message),
  config: Config,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name, config) })
}

/// Opens the store and makes sure the daemon has an agent identifier.
fn initial_state(config: Config) -> Result(State, String) {
  use opened <- result.try(
    store.open_with(config.path, config.suite, config.store_faults)
    |> result.replace_error("the daemon database could not be opened"),
  )

  let state =
    State(
      store: opened,
      suite: config.suite,
      clock: config.clock,
      policy: config.policy,
      mailbox: config.mailbox,
      accept_budget: config.accept_budget,
      notify: config.notify,
      faults: config.faults,
    )

  use _ <- result.try(
    ensure_agent_id(state)
    |> result.replace_error("the agent identifier could not be stored"),
  )

  Ok(state)
}

/// Gives a fresh database its agent identifier (spec §3). One agent
/// principal per daemon in v1, so it is written once and never changed.
fn ensure_agent_id(state: State) -> Result(Nil, store.Error) {
  use existing <- result.try(store.meta_get(state.store, "agent_id"))

  // A database that already has an identifier keeps it.
  case existing {
    Some(_) -> Ok(Nil)

    None ->
      case field.fresh_id(state.suite) {
        Ok(agent) -> store.meta_put(state.store, "agent_id", id.to_bytes(agent))
        Error(Nil) -> Error(store.Corrupt("randomness source misbehaved"))
      }
  }
}

/// Closes the store when the engine stops in an orderly way. A close that
/// fails changes nothing: the commits it would flush are already durable.
fn close_store(state: State, _reason: process.ExitReason) -> Nil {
  let _ = store.close(state.store)
  Nil
}

/// Runs one job to completion before the next is read.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // One variant: run the job against the actor's own state, with the fate
  // the fault hook gives its kind. This is the one place every engine call
  // passes, so a hook here reaches all of them.
  case message {
    Run(kind:, job:) -> {
      job(state, fate(state, kind))
      actor.continue(state)
    }
  }
}

/// What the fault hook decides for one job. Without a hook every job
/// applies, which is production.
fn fate(state: State, kind: JobKind) -> JobFate {
  // The hook is consulted only when a simulation installed one.
  case state.faults {
    None -> Apply
    Some(decide) -> decide(kind)
  }
}

/// Hands a job to the engine and waits for its answer.
fn run(
  name: Handle(Message),
  kind: JobKind,
  job: fn(State) -> Result(a, Failure),
) -> Result(a, Failure) {
  let asked =
    mail.ask(name, kind_label(kind), call_timeout_ms, fn(reply_with) {
      Run(kind:, job: fn(state, fate) {
        process.send(reply_with, answer(state, fate, job))
      })
    })

  // An answer is the job's own result; no answer in time is `Unavailable`.
  case asked {
    Ok(answer) -> answer
    Error(Nil) -> Error(Unavailable)
  }
}

/// Runs a job under its fate and says what its caller hears. A job that
/// applies and then fails has committed and notified exactly as one that
/// succeeded; only the answer is lost, as when a reply misses its caller.
fn answer(
  state: State,
  fate: JobFate,
  job: fn(State) -> Result(a, Failure),
) -> Result(a, Failure) {
  // The fate decides whether the job runs and whether its answer survives.
  case fate {
    Apply -> job(state)

    FailBeforeApply -> Error(Unavailable)

    ApplyThenFail -> {
      let _ = job(state)
      Error(Unavailable)
    }
  }
}

// ------------------------------------------------------------- commands

/// Starts an offer: a fresh identity, prekeys and inbox, committed as
/// `Provisioning`. The invitation cannot be handed out until the provisioner
/// has created the queue, so the caller reads it back with
/// `invitation_file`.
///
/// ## Examples
///
/// ```gleam
/// engine.invite(name, "support", offer.OperatorApproves, 10)
/// // -> Ok(invitation_id)
/// ```
pub fn invite(
  name: Handle(Message),
  description: String,
  approval: Approval,
  budget: Int,
) -> Result(Id(InvitationKind), Failure) {
  run(name, Invite, fn(state) {
    use inbox <- result.try(new_inbox(state))

    let terms = relationship.Terms(inbox:, description:, budget:)
    use made <- result.try(
      offer.create(state.suite, terms, approval, state.clock())
      |> result.replace_error(Refused("the invitation could not be created")),
    )

    use _ <- result.try(commit_change(
      state,
      store.OfferStarted(made, description),
      None,
    ))

    Ok(made.state.id)
  })
}

/// The invitation file of an offer: `Some` once its queue exists, `None`
/// while it is still being created, `NotFound` once consumed or expired.
///
/// ## Examples
///
/// ```gleam
/// engine.invitation_file(name, invitation)
/// // -> Ok(Some(file))
/// ```
pub fn invitation_file(
  name: Handle(Message),
  invitation: Id(InvitationKind),
) -> Result(Option(Secret), Failure) {
  run(name, InvitationFile, fn(state) {
    use found <- result.try(
      fault(store.invitation_file(state.store, invitation)),
    )

    // The phase decides whether the file may leave the daemon. The file
    // holds the offer's append capability and prekeys, and this answer is
    // a message to another process, so it travels as a `Secret`
    // (ADR-012).
    case found {
      store.FileReady(bytes:) -> Ok(Some(secret.new(bytes)))
      store.FileNotYet -> Ok(None)
      store.FileGone -> Error(NotFound)
    }
  })
}

/// Imports an invitation file: validates it, makes a fresh identity and
/// inbox, and commits the relationship as `Joining`.
///
/// ## Examples
///
/// ```gleam
/// engine.accept(name, file_bytes, "vendor support")
/// // -> Ok(contact)
/// ```
pub fn accept(
  name: Handle(Message),
  file: BitArray,
  description: String,
) -> Result(Id(Contact), Failure) {
  run(name, Accept, fn(state) {
    use invite <- result.try(
      invitation.decode(state.suite, file)
      |> result.replace_error(InvalidInvitation(
        "the file is not a valid invitation",
      )),
    )
    use earlier <- result.try(
      fault(store.contact_by_invitation(state.store, invite.id)),
    )

    // An invitation is redeemed once (ADR-011): accepting it again, as a
    // caller retrying an answer it never saw does, returns the relationship
    // it started and starts no second joiner, until that one is closed.
    case earlier {
      Some(contact) -> Ok(contact)
      None -> join(state, invite, description)
    }
  })
}

/// Starts a joiner for an invitation not redeemed before: a fresh identity
/// and inbox, committed as `Joining`.
fn join(
  state: State,
  invite: invitation.Invitation,
  description: String,
) -> Result(Id(Contact), Failure) {
  use inbox <- result.try(new_inbox(state))

  let terms =
    relationship.Terms(inbox:, description:, budget: state.accept_budget)
  use made <- result.try(
    relationship.join(state.suite, invite, state.policy, terms, state.clock())
    |> result.map_error(join_failure),
  )

  use _ <- result.try(commit_change(
    state,
    store.Started(made, description),
    Some(made.state.contact),
  ))

  Ok(made.state.contact)
}

/// The mailbox created this queue. An offer opens, or a joiner's session
/// starts. Idempotent: a queue whose offer or relationship has moved on is
/// left alone.
///
/// ## Examples
///
/// ```gleam
/// engine.provisioned(name, queue)
/// // -> Ok(Nil)
/// ```
pub fn provisioned(
  name: Handle(Message),
  queue: Id(Queue),
) -> Result(Nil, Failure) {
  run(name, Provisioned, fn(state) {
    use offered <- result.try(fault(store.offer_by_queue(state.store, queue)))

    // The queue belongs to an offer or to a joining relationship; a queue
    // that belongs to neither has nothing waiting on it.
    case offered {
      Some(record) -> open_offer(state, record)

      None -> {
        use joining <- result.try(
          fault(store.relationship_by_queue(state.store, queue)),
        )

        // The queue belongs to an offer or to a joining relationship; a queue that belongs to neither has nothing waiting on it.
        case joining {
          Some(record) -> open_session(state, record)
          None -> Ok(Nil)
        }
      }
    }
  })
}

/// Opens a `Provisioning` offer, and leaves any other phase as it is.
fn open_offer(state: State, record: store.OfferRecord) -> Result(Nil, Failure) {
  // Only a provisioning offer has an opening to make.
  case record.offer.phase {
    offer.Provisioning(_) ->
      commit_change(
        state,
        store.OfferRevised(offer.provisioned(record.offer), record.version),
        None,
      )

    offer.Open(_) | offer.Consumed(..) | offer.Expired -> Ok(Nil)
  }
}

/// Starts the session of a `Joining` relationship: the `Initial` frame is
/// encrypted and committed with the new phase. A joiner that can no longer
/// start, because the invitation expired while its queue was being created,
/// is closed locally, since nothing will ever move it forward.
fn open_session(
  state: State,
  record: store.ContactRecord,
) -> Result(Nil, Failure) {
  let current = record.relationship

  // Only a joining relationship has a session to open.
  case current.phase {
    relationship.Joining(..) -> {
      let started = relationship.joined(state.suite, current, state.clock())

      // A refusal here cannot be retried into success, so the relationship
      // ends instead of retrying forever.
      case started {
        Ok(made) -> revise_with(state, made, record.version)

        Error(_) -> {
          let closed =
            relationship.close(state.suite, current, state.clock())
            |> result.replace_error(Refused("the relationship cannot start"))

          use made <- result.try(closed)
          revise_with(state, made, record.version)
        }
      }
    }

    relationship.AwaitingAccept(_)
    | relationship.PendingApproval(_)
    | relationship.Active(_)
    | relationship.Closed(_) -> Ok(Nil)
  }
}

/// Commits a relationship plan computed from `version`.
fn revise_with(
  state: State,
  made: Plan(Relationship),
  version: Int,
) -> Result(Nil, Failure) {
  commit_change(state, store.Revised(made, version), Some(made.state.contact))
}

/// The operator approves a pending relationship.
///
/// ## Examples
///
/// ```gleam
/// engine.approve(name, contact)
/// // -> Ok(Nil)
/// ```
pub fn approve(
  name: Handle(Message),
  contact: Id(Contact),
) -> Result(Nil, Failure) {
  run(name, Approve, fn(state) {
    use _ <- result.try(
      revise(state, contact, fn(current) {
        relationship.approve(state.suite, current, state.clock())
      }),
    )

    Ok(Nil)
  })
}

/// The operator declines a pending relationship.
///
/// ## Examples
///
/// ```gleam
/// engine.decline(name, contact)
/// // -> Ok(Nil)
/// ```
pub fn decline(
  name: Handle(Message),
  contact: Id(Contact),
) -> Result(Nil, Failure) {
  run(name, Decline, fn(state) {
    use _ <- result.try(
      revise(state, contact, fn(current) {
        relationship.decline(state.suite, current, state.clock())
      }),
    )

    Ok(Nil)
  })
}

/// Closes a relationship from our side.
///
/// ## Examples
///
/// ```gleam
/// engine.close(name, contact)
/// // -> Ok(Nil)
/// ```
pub fn close(
  name: Handle(Message),
  contact: Id(Contact),
) -> Result(Nil, Failure) {
  run(name, Close, fn(state) {
    use _ <- result.try(
      revise(state, contact, fn(current) {
        relationship.close(state.suite, current, state.clock())
      }),
    )

    Ok(Nil)
  })
}

/// Raises a relationship's inbound budget, releasing held messages.
///
/// ## Examples
///
/// ```gleam
/// engine.raise_budget(name, contact, 5)
/// // -> Ok(Nil)
/// ```
pub fn raise_budget(
  name: Handle(Message),
  contact: Id(Contact),
  by: Int,
) -> Result(Nil, Failure) {
  run(name, RaiseBudget, fn(state) {
    use _ <- result.try(
      revise(state, contact, fn(current) {
        relationship.raise_budget(current, by)
      }),
    )

    Ok(Nil)
  })
}

/// Sends an application message: the ciphertext and the advanced session
/// commit together, and the message identifier is returned. Nothing has been
/// sent when this returns; the scheduler transmits the committed row.
///
/// With a caller's idempotency `key` (ADR-011) a send is safe to retry
/// after an answer the caller never saw: a key already used on this
/// relationship for the same request answers with the first message and
/// queues nothing, and one used for a different request is refused. The key
/// commits in the send's own transaction, so it exists exactly when the
/// message does. Without a key every call is a new message.
///
/// ## Examples
///
/// ```gleam
/// engine.send(name, contact, Some("order-17"), "text/plain", <<"hi">>, None)
/// // -> Ok(message_id)
/// ```
pub fn send(
  name: Handle(Message),
  contact: Id(Contact),
  key: Option(String),
  content_type: String,
  payload: Secret,
  in_reply_to: Option(Id(MessageKind)),
) -> Result(Id(MessageKind), Failure) {
  run(name, Send, fn(state) {
    let suite = state.suite
    let clock = state.clock

    // The plaintext leaves its `Secret` only here, inside the job, for the
    // core to seal and to digest; it never rides in a message or a state
    // a crash report could print (ADR-012).
    let step = fn(current) {
      relationship.send(
        suite,
        current,
        clock(),
        content_type,
        secret.expose(payload),
        in_reply_to,
        None,
      )
    }

    // An unkeyed send is always new; a keyed one may be a retry.
    case key {
      None -> {
        use made <- result.try(revise(state, contact, step))

        // The message identifier exists only inside the outbox record the
        // plan carries.
        sent_message(made.records)
      }

      Some(key) -> {
        let digest =
          request_digest(
            state.suite,
            content_type,
            secret.expose(payload),
            in_reply_to,
          )
        keyed_send(state, contact, key, digest, step)
      }
    }
  })
}

/// A send under an idempotency key: the first message under the key on this
/// relationship, a refusal for a key reused on another request, or a new
/// send that commits the key with it.
fn keyed_send(
  state: State,
  contact: Id(Contact),
  key: String,
  digest: BitArray,
  step: fn(Relationship) -> Result(Plan(Relationship), relationship.Refusal),
) -> Result(Id(MessageKind), Failure) {
  use Nil <- result.try(check_send_key(key))
  use prior <- result.try(
    fault(store.send_by_key(state.store, contact, key, state.clock())),
  )

  // A remembered key answers for its first message, and only for it.
  case prior {
    Some(found) ->
      case state.suite.constant_time_equal(found.digest, digest) {
        True -> Ok(found.message)
        False ->
          Error(Refused("the idempotency key was used for a different message"))
      }

    None -> {
      use found <- result.try(
        fault(store.relationship_by_contact(state.store, contact)),
      )
      use record <- result.try(option.to_result(found, NotFound))
      use made <- result.try(
        step(record.relationship) |> result.map_error(refused),
      )
      use message <- result.try(sent_message(made.records))

      let change =
        store.KeyedSend(
          plan: made,
          version: record.version,
          key: store.SendKey(key:, message:, digest:),
        )
      use _ <- result.try(commit_change(state, change, Some(contact)))

      Ok(message)
    }
  }
}

/// Refuses an idempotency key that is empty or longer than
/// `limits.max_send_key_bytes`.
fn check_send_key(key: String) -> Result(Nil, Failure) {
  let size = string.byte_size(key)

  // The bound is in bytes, as the store and the wire count them.
  case size >= 1 && size <= limits.max_send_key_bytes {
    True -> Ok(Nil)
    False -> Error(Refused("the idempotency key is empty or too long"))
  }
}

/// SHA-256 over what a send asks for, each field framed so no two requests
/// share an encoding: the content type with its length, whether a reply
/// target follows and the target, then the payload.
fn request_digest(
  suite: Suite,
  content_type: String,
  payload: BitArray,
  in_reply_to: Option(Id(MessageKind)),
) -> BitArray {
  // A tag byte says whether a reply target follows, so no request without
  // one encodes like a request with one.
  let reply = case in_reply_to {
    Some(target) -> <<1, id.to_bytes(target):bits>>
    None -> <<0>>
  }

  suite.sha256(<<
    string.byte_size(content_type):32,
    content_type:utf8,
    reply:bits,
    payload:bits,
  >>)
}

/// The identifier of the application message a plan queued.
fn sent_message(
  records: List(plan.Record),
) -> Result(Id(MessageKind), Failure) {
  let queued =
    list.find_map(records, fn(record) {
      case record {
        plan.Outbound(kind: plan.ApplicationOut(message:), ..) -> Ok(message)
        plan.Outbound(..)
        | plan.Processed(..)
        | plan.Delivered(..)
        | plan.Released(..)
        | plan.PeerReceived(..)
        | plan.Remembered(..)
        | plan.RepeatedMessage(..)
        | plan.Audit(..) -> Error(Nil)
      }
    })

  result.replace_error(queued, Unavailable)
}

/// Loads a relationship, runs a transition and commits its plan.
fn revise(
  state: State,
  contact: Id(Contact),
  step: fn(Relationship) -> Result(Plan(Relationship), relationship.Refusal),
) -> Result(Plan(Relationship), Failure) {
  use found <- result.try(
    fault(store.relationship_by_contact(state.store, contact)),
  )
  use record <- result.try(option.to_result(found, NotFound))
  use made <- result.try(step(record.relationship) |> result.map_error(refused))
  use _ <- result.try(revise_with(state, made, record.version))

  Ok(made)
}

/// The agent consumed a delivery.
///
/// ## Examples
///
/// ```gleam
/// engine.consume(name, message)
/// // -> Ok(Nil)
/// ```
pub fn consume(
  name: Handle(Message),
  message: Id(MessageKind),
) -> Result(Nil, Failure) {
  run(name, Consume, fn(state) {
    use consumed <- result.try(fault(store.consume(state.store, message)))

    // A message that is not ready, held ones included, cannot be consumed.
    case consumed {
      True -> Ok(Nil)
      False -> Error(NotFound)
    }
  })
}

/// Retires offers whose acceptance deadline passed unused, dropping their
/// prekey secrets, so no fetcher polls a queue nobody can redeem.
///
/// ## Examples
///
/// ```gleam
/// engine.expire_offers(name)
/// // -> Ok(Nil)
/// ```
pub fn expire_offers(name: Handle(Message)) -> Result(Nil, Failure) {
  run(name, ExpireOffers, fn(state) {
    let now = state.clock()

    use due <- result.try(fault(store.expirable_offers(state.store, now)))

    list.try_each(due, fn(record) {
      commit_change(
        state,
        store.OfferRevised(offer.expire(record.offer, now), record.version),
        None,
      )
    })
  })
}

// ------------------------------------------------------------- inbound

/// Processes one fetched envelope and commits its outcome.
///
/// An envelope already processed under the same identifier and digest is a
/// `Repeat`, and is owed an acknowledgement again. Everything else runs
/// through the core, and whatever the core refuses is committed as dropped.
/// `Ok` means the outcome is durable and the fetcher may acknowledge it; an
/// error means nothing was committed.
///
/// ## Examples
///
/// ```gleam
/// engine.process(name, queue, envelope, padded)
/// // -> Ok(engine.Fresh)
/// ```
pub fn process(
  name: Handle(Message),
  queue: Id(Queue),
  envelope: Id(Envelope),
  padded: Padded,
) -> Result(Handled, Failure) {
  run(name, Process, fn(state) {
    handle_envelope(state, queue, envelope, padded)
  })
}

/// The inbound path: the duplicate check, then the frame.
fn handle_envelope(
  state: State,
  queue: Id(Queue),
  envelope: Id(Envelope),
  padded: Padded,
) -> Result(Handled, Failure) {
  let digest = state.suite.sha256(envelope.to_wire(padded))
  let ref = EnvelopeRef(queue:, envelope:, digest:)

  use known <- result.try(
    fault(store.processed_digest(state.store, queue, envelope)),
  )

  // Both the identifier and the digest must match: a replayed ciphertext
  // under a new identifier, or new bytes under an old one, is new work.
  case known {
    Some(stored) ->
      case state.suite.constant_time_equal(stored, digest) {
        True -> repeat(state, ref)
        False -> attempt(state, ref, padded)
      }

    None -> attempt(state, ref, padded)
  }
}

/// Answers an envelope the store already processed by owing the mailbox
/// its acknowledgement again (ADR-010, addendum).
///
/// A mailbox serves a processed envelope in two ways. Before the
/// acknowledgement, it is the batch the next round acknowledges anyway,
/// and the row is still unacknowledged. After it, the mailbox brought the
/// envelope back: restored from a backup taken before the acknowledgement,
/// or stored again by the sender's retry once the tombstone's retention
/// deadline passed, which can be up to `limits.retention_slack_seconds`
/// before the sender stops retrying. The fetcher acknowledges only what
/// `store.unacked` lists, so an envelope whose row stayed acknowledged was
/// never named again: it sat at the head of the queue until retention, and
/// a queue of them hid every envelope behind it.
///
/// Marking the row unacknowledged keeps the fetcher's one rule, acknowledge
/// exactly what the store says is committed and unacknowledged, and covers
/// both cases. The row and its digest stay, so the envelope is never
/// processed or delivered twice; no attempt is counted, since nothing
/// failed; and a queue that retires before the next round still has an
/// unacknowledged row, so the fetch manager drains it.
fn repeat(state: State, ref: EnvelopeRef) -> Result(Handled, Failure) {
  use _ <- result.try(
    fault(store.mark_unacked(state.store, ref.queue, ref.envelope)),
  )

  Ok(Repeat)
}

/// Counts this attempt durably, then processes the envelope, or quarantines
/// it once it has failed `limits.max_process_attempts` times (ADR-010).
///
/// The count commits before the core sees the envelope, so an attempt that
/// crashes the engine or fails its commit has counted, and a crash loop
/// ends in quarantine like any other failure. An attempt whose commit
/// landed is never counted again: its `Processed` row clears the count,
/// and a redelivery of it is a `Repeat` above, which is how an ask that
/// applied and then failed escapes being blamed on the envelope.
fn attempt(
  state: State,
  ref: EnvelopeRef,
  padded: Padded,
) -> Result(Handled, Failure) {
  use count <- result.try(
    fault(store.count_attempt(state.store, ref.queue, ref.envelope)),
  )

  // Within the bound the envelope is processed; past it, set aside.
  case count > limits.max_process_attempts {
    False -> new_envelope(state, ref, padded)
    True -> quarantine(state, ref, count - 1)
  }
}

/// Drops and records an envelope that failed `failures` times, so the
/// fetcher acknowledges it and the queue behind it moves. Nothing of the
/// relationship changes: an honest message set aside this way is still
/// unreceipted at its sender, whose retransmit is processed fresh.
fn quarantine(
  state: State,
  ref: EnvelopeRef,
  failures: Int,
) -> Result(Handled, Failure) {
  use owner <- result.try(
    fault(store.relationship_by_queue(state.store, ref.queue)),
  )

  let contact = option.map(owner, fn(record) { record.relationship.contact })
  let change = store.Quarantined(ref:, contact:, attempts: failures)
  use _ <- result.try(commit_change(state, change, None))

  Ok(Fresh)
}

/// Opens the frame and routes it by its tag.
fn new_envelope(
  state: State,
  ref: EnvelopeRef,
  padded: Padded,
) -> Result(Handled, Failure) {
  // An unreadable frame is dropped durably, and the mailbox is then
  // acknowledged.
  case frame.open(state.suite, padded) {
    Ok(frame.Initial(initial)) -> redeem(state, ref, initial)
    Ok(frame.Ratchet(bytes)) -> receive(state, ref, bytes)
    Error(_) -> drop(state, ref)
  }
}

/// Commits the `Processed` record of an envelope the core refused.
fn drop(state: State, ref: EnvelopeRef) -> Result(Handled, Failure) {
  use _ <- result.try(commit_change(state, store.Dropped(ref), None))
  Ok(Fresh)
}

/// An `Initial` frame goes to the offer that owns the queue.
fn redeem(
  state: State,
  ref: EnvelopeRef,
  initial: pqxdh.InitialMessage,
) -> Result(Handled, Failure) {
  use found <- result.try(fault(store.offer_by_queue(state.store, ref.queue)))

  // A queue with no offer, a duplicate of the consuming message and every
  // refusal leave the offer as it was and drop the envelope.
  case found {
    None -> drop(state, ref)

    Some(record) ->
      case
        offer.redeem(
          state.suite,
          record.offer,
          state.policy,
          ref,
          initial,
          state.clock(),
        )
      {
        Ok(offer.Redeemed(offer: consumed, plan: made)) ->
          commit_change(
            state,
            store.Redeemed(
              offer: consumed,
              offer_version: record.version,
              description: record.description,
              plan: made,
            ),
            Some(made.state.contact),
          )
          |> result.replace(Fresh)

        Ok(offer.Duplicate) | Error(_) -> drop(state, ref)
      }
  }
}

/// A `Ratchet` frame goes to the relationship that owns the queue.
fn receive(
  state: State,
  ref: EnvelopeRef,
  bytes: BitArray,
) -> Result(Handled, Failure) {
  use found <- result.try(
    fault(store.relationship_by_queue(state.store, ref.queue)),
  )

  // A queue with no relationship, or a message the session refuses, is
  // dropped without touching any state.
  case found {
    None -> drop(state, ref)

    Some(record) -> {
      let current = record.relationship

      use known <- result.try(
        fault(store.fingerprint(
          state.store,
          current.contact,
          relationship.fingerprint(state.suite, bytes),
        )),
      )

      // A ciphertext a message was already stored from is answered with its
      // receipt again and never decrypted; anything else goes through the
      // session.
      use outcome <- result.try(case known {
        Some(fingerprint) ->
          Ok(relationship.resend_receipt(
            state.suite,
            current,
            state.clock(),
            ref,
            fingerprint,
          ))

        None -> open_and_receive(state, current, ref, bytes)
      })

      // A plan commits with the relationship's new state; a refusal is
      // committed as a drop so the mailbox can still be acknowledged.
      case outcome {
        Ok(made) ->
          revise_with(state, made, record.version)
          |> result.replace(Fresh)

        Error(_) -> drop(state, ref)
      }
    }
  }
}

/// Opens a ratchet message and receives it with its identifier's history
/// read from the deliveries (ADR-010). The outer `Result` is the store's:
/// a history that cannot be read is `Unavailable` and commits nothing,
/// because guessing it either way could deliver a message twice or lose
/// one. The inner one is the core's, where a refusal becomes a drop.
fn open_and_receive(
  state: State,
  current: Relationship,
  ref: EnvelopeRef,
  bytes: BitArray,
) -> Result(Result(Plan(Relationship), relationship.Refusal), Failure) {
  let opened =
    relationship.open(state.suite, current, state.clock(), ref, bytes)

  // Only a message the session opened has an identifier to look up.
  case opened {
    Error(refusal) -> Ok(Error(refusal))

    Ok(opened) -> {
      use history <- result.try(
        fault(store.message_history(
          state.store,
          current.contact,
          relationship.opened_message(opened),
        )),
      )

      Ok(relationship.receive(opened, history))
    }
  }
}

// -------------------------------------------------------------- reads

/// Every relationship, oldest first.
///
/// ## Examples
///
/// ```gleam
/// engine.contacts(name)
/// // -> Ok([record])
/// ```
pub fn contacts(
  name: Handle(Message),
) -> Result(List(store.ContactRecord), Failure) {
  run(name, Contacts, fn(state) { fault(store.contacts(state.store)) })
}

/// Ready deliveries, oldest first.
///
/// ## Examples
///
/// ```gleam
/// engine.deliveries(name, None, 10)
/// // -> Ok([record])
/// ```
pub fn deliveries(
  name: Handle(Message),
  contact: Option(Id(Contact)),
  max: Int,
) -> Result(List(store.DeliveryRecord), Failure) {
  run(name, Deliveries, fn(state) {
    fault(store.ready_deliveries(state.store, contact, max))
  })
}

/// Where an outbound message stands.
///
/// ## Examples
///
/// ```gleam
/// engine.message_state(name, message)
/// // -> Ok(store.StoredByMailbox)
/// ```
pub fn message_state(
  name: Handle(Message),
  message: Id(MessageKind),
) -> Result(store.SentState, Failure) {
  run(name, MessageState, fn(state) {
    use found <- result.try(fault(store.sent_state(state.store, message)))
    option.to_result(found, NotFound)
  })
}

/// The most recent audit entries, newest first.
///
/// ## Examples
///
/// ```gleam
/// engine.audit(name, None, 20)
/// // -> Ok([entry])
/// ```
pub fn audit(
  name: Handle(Message),
  contact: Option(Id(Contact)),
  limit: Int,
) -> Result(List(store.AuditRecord), Failure) {
  run(name, Audit, fn(state) { fault(store.audit(state.store, contact, limit)) })
}

/// The most recent incidents, newest first: envelopes the daemon set aside
/// without delivering them (ADR-010).
///
/// ## Examples
///
/// ```gleam
/// engine.incidents(name, 20)
/// // -> Ok([record])
/// ```
pub fn incidents(
  name: Handle(Message),
  limit: Int,
) -> Result(List(store.IncidentRecord), Failure) {
  run(name, Incidents, fn(state) { fault(store.incidents(state.store, limit)) })
}

/// How many incidents were ever recorded.
///
/// ## Examples
///
/// ```gleam
/// engine.incident_count(name)
/// // -> Ok(0)
/// ```
pub fn incident_count(name: Handle(Message)) -> Result(Int, Failure) {
  run(name, IncidentCount, fn(state) {
    fault(store.incident_count(state.store))
  })
}

/// The inboxes to fetch from.
///
/// ## Examples
///
/// ```gleam
/// engine.live_inboxes(name)
/// // -> Ok([inbox])
/// ```
pub fn live_inboxes(name: Handle(Message)) -> Result(List(Inbox), Failure) {
  run(name, LiveInboxes, fn(state) { fault(store.live_inboxes(state.store)) })
}

/// The retired inboxes that still owe the mailbox an acknowledgement.
///
/// ## Examples
///
/// ```gleam
/// engine.draining_inboxes(name)
/// // -> Ok([])
/// ```
pub fn draining_inboxes(name: Handle(Message)) -> Result(List(Inbox), Failure) {
  run(name, DrainingInboxes, fn(state) {
    fault(store.draining_inboxes(state.store))
  })
}

/// The inboxes whose queue the mailbox must still be asked to create.
///
/// ## Examples
///
/// ```gleam
/// engine.pending_inboxes(name)
/// // -> Ok([inbox])
/// ```
pub fn pending_inboxes(name: Handle(Message)) -> Result(List(Inbox), Failure) {
  run(name, PendingInboxes, fn(state) {
    fault(store.pending_inboxes(state.store))
  })
}

/// The committed outbox rows that are due.
///
/// ## Examples
///
/// ```gleam
/// engine.due_outbox(name, 8)
/// // -> Ok([row])
/// ```
pub fn due_outbox(
  name: Handle(Message),
  limit: Int,
) -> Result(List(store.OutboxRow), Failure) {
  run(name, DueOutbox, fn(state) {
    fault(store.due(state.store, state.clock(), limit))
  })
}

/// Records the scheduler's report on one outbox row.
///
/// ## Examples
///
/// ```gleam
/// engine.record_send(name, envelope, store.Rejected)
/// // -> Ok(Nil)
/// ```
pub fn record_send(
  name: Handle(Message),
  envelope: Id(Envelope),
  outcome: store.SendOutcome,
) -> Result(Nil, Failure) {
  run(name, RecordSend, fn(state) {
    fault(store.record_send(state.store, state.clock(), envelope, outcome))
  })
}

/// The envelopes of a queue that are committed as processed and not yet
/// acknowledged.
///
/// ## Examples
///
/// ```gleam
/// engine.unacked(name, queue)
/// // -> Ok([envelope])
/// ```
pub fn unacked(
  name: Handle(Message),
  queue: Id(Queue),
) -> Result(List(Id(Envelope)), Failure) {
  run(name, Unacked, fn(state) { fault(store.unacked(state.store, queue)) })
}

/// Records that the mailbox acknowledged these envelopes.
///
/// ## Examples
///
/// ```gleam
/// engine.mark_acked(name, queue, [envelope])
/// // -> Ok(Nil)
/// ```
pub fn mark_acked(
  name: Handle(Message),
  queue: Id(Queue),
  envelopes: List(Id(Envelope)),
) -> Result(Nil, Failure) {
  run(name, MarkAcked, fn(state) {
    fault(store.mark_acked(state.store, queue, envelopes))
  })
}

/// How many outbox rows still wait for a mailbox.
///
/// ## Examples
///
/// ```gleam
/// engine.outbox_pending(name)
/// // -> Ok(0)
/// ```
pub fn outbox_pending(name: Handle(Message)) -> Result(Int, Failure) {
  run(name, OutboxPending, fn(state) { fault(store.pending_count(state.store)) })
}

// ---------------------------------------------------------- retransmit

/// The most due rows one `retransmit` job considers; the rest wait for the
/// scheduler's next tick.
const retransmit_batch = 16

/// Sends again every stored row whose receipt window has passed, up to
/// `retransmit_batch`, and ends the schedule of each row the core says will
/// never be sent again. Nothing is sent here: each copy is an outbox row the
/// scheduler sends like any other.
///
/// ## Examples
///
/// ```gleam
/// engine.retransmit(name)
/// // -> Ok(Nil)
/// ```
pub fn retransmit(name: Handle(Message)) -> Result(Nil, Failure) {
  run(name, Retransmit, fn(state) {
    let now = state.clock()

    use due <- result.try(
      fault(store.due_retransmits(state.store, now, retransmit_batch)),
    )

    list.try_each(due, fn(entry) { retransmit_one(state, now, entry) })
  })
}

/// Decides one due row against its relationship as it is now, and commits
/// the decision.
fn retransmit_one(
  state: State,
  now: Instant,
  entry: store.DueRetransmit,
) -> Result(Nil, Failure) {
  use found <- result.try(
    fault(store.relationship_by_contact(state.store, entry.contact)),
  )

  // A row whose relationship is gone can never be receipted.
  let decided = case found {
    Some(record) ->
      retransmit.retransmit(state.suite, record.relationship, entry.row, now)

    None -> Error(retransmit.NotActive)
  }

  // A copy is committed; a misbehaving randomness source leaves the row due;
  // every other refusal is final.
  case decided {
    Ok(made) -> {
      use _ <- result.try(commit_change(state, store.Retransmitted(made), None))
      Ok(Nil)
    }

    Error(retransmit.NoRandomness) -> Ok(Nil)

    Error(retransmit.NotRetransmitted)
    | Error(retransmit.NotActive)
    | Error(retransmit.Exhausted)
    | Error(retransmit.Expired) -> {
      use _ <- result.try(commit_change(
        state,
        store.RetransmitStopped(entry.row.envelope),
        None,
      ))
      Ok(Nil)
    }
  }
}

// ------------------------------------------------------------- helpers

/// Writes one commit and, only after it returned, tells the shell. The
/// notices follow the transaction, so a worker nudged by them finds the
/// committed rows.
fn commit_change(
  state: State,
  change: store.Commit,
  contact: Option(Id(Contact)),
) -> Result(Nil, Failure) {
  use committed <- result.try(
    fault(store.commit(state.store, state.clock(), change)),
  )

  list.each(store.effects(committed), fn(effect) { state.notify(Nudge(effect)) })

  // Topology first, so a fetcher for a new queue starts before the adapter
  // hears the relationship changed.
  state.notify(Topology)

  // A commit that names a contact also announces that its relationship changed.
  case contact {
    Some(contact) -> state.notify(Changed(contact))
    None -> Nil
  }

  Ok(Nil)
}

/// A fresh inbox at this daemon's own mailbox.
fn new_inbox(state: State) -> Result(Inbox, Failure) {
  route.new_inbox(state.suite, state.mailbox)
  |> result.replace_error(Unavailable)
}

/// Reports a storage error without its detail and answers `Unavailable`.
fn fault(outcome: Result(a, store.Error)) -> Result(a, Failure) {
  // A version conflict and every other storage error answer `Unavailable`; only the log line differs.
  case outcome {
    Ok(value) -> Ok(value)

    Error(store.Conflict) -> {
      log.warning("engine", "version_conflict", [])
      Error(Unavailable)
    }

    // SQLite's error code is an enum (`busy`, `constraint`, `ioerr`), so
    // its tag says what failed; the message beside it is not read.
    Error(store.Sql(error)) -> {
      log.warning("engine", "storage_failed", [
        log_field.tag("reason", store.Sql(error)),
        log_field.tag("code", error.code),
      ])
      Error(Unavailable)
    }

    Error(store.FutureSchema(..) as error) | Error(store.Corrupt(_) as error) -> {
      log.warning("engine", "storage_failed", [log_field.tag("reason", error)])
      Error(Unavailable)
    }
  }
}

/// A refusal of `join`, in the words the contract's errors use.
fn join_failure(refusal: relationship.Refusal) -> Failure {
  case refusal {
    relationship.InvitationExpired ->
      InvalidInvitation("the invitation has expired")

    relationship.Carrier(_) ->
      Refused("the carrier policy does not permit this invitation")

    relationship.WrongPhase
    | relationship.NotActive
    | relationship.NoSession
    | relationship.Undecryptable(_)
    | relationship.MalformedMessage(_)
    | relationship.CryptoFailed(_)
    | relationship.NoRandomness
    | relationship.TooLarge
    | relationship.PayloadTooLarge
    | relationship.ContentTypeTooLong
    | relationship.NotPositive
    | relationship.HeldFull
    | relationship.DescriptionTooLong
    | relationship.DuplicateIgnored -> refused(refusal)
  }
}

/// A core refusal as a fixed phrase. No refusal's payload is rendered: some
/// carry a typed crypto error, which holds no bytes, but a phrase per variant
/// keeps that true by construction.
fn refused(refusal: relationship.Refusal) -> Failure {
  Refused(case refusal {
    relationship.WrongPhase -> "not valid in the relationship's current phase"
    relationship.NotActive -> "the relationship is not active"
    relationship.NoSession -> "the relationship has no session"
    relationship.Undecryptable(_) -> "the message could not be decrypted"
    relationship.MalformedMessage(_) -> "the message is malformed"
    relationship.CryptoFailed(_) -> "a cryptographic step failed"
    relationship.NoRandomness -> "the randomness source failed"
    relationship.InvitationExpired -> "the invitation has expired"
    relationship.Carrier(_) -> "the carrier policy does not permit this"
    relationship.TooLarge -> "the message is too large to send"
    relationship.PayloadTooLarge -> "the payload is too large"
    relationship.ContentTypeTooLong -> "the content type is too long"
    relationship.NotPositive -> "the amount must be positive"
    relationship.HeldFull -> "too many messages are held"
    relationship.DescriptionTooLong -> "the description is too long"
    relationship.DuplicateIgnored -> "a repeated message was ignored"
  })
}

/// The fixed word a job kind is labelled with in an intercepted parcel.
///
/// ## Examples
///
/// ```gleam
/// engine.kind_label(engine.RecordSend)
/// // -> "record_send"
/// ```
pub fn kind_label(kind: JobKind) -> String {
  case kind {
    Invite -> "invite"
    InvitationFile -> "invitation_file"
    Accept -> "accept"
    Provisioned -> "provisioned"
    Approve -> "approve"
    Decline -> "decline"
    Close -> "close"
    RaiseBudget -> "raise_budget"
    Send -> "send"
    Consume -> "consume"
    ExpireOffers -> "expire_offers"
    Process -> "process"
    Contacts -> "contacts"
    Deliveries -> "deliveries"
    MessageState -> "message_state"
    Audit -> "audit"
    LiveInboxes -> "live_inboxes"
    PendingInboxes -> "pending_inboxes"
    DueOutbox -> "due_outbox"
    RecordSend -> "record_send"
    Unacked -> "unacked"
    MarkAcked -> "mark_acked"
    OutboxPending -> "outbox_pending"
    Retransmit -> "retransmit"
    Incidents -> "incidents"
    IncidentCount -> "incident_count"
    DrainingInboxes -> "draining_inboxes"
  }
}

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
//// ## Flow
////
//// 1. `start` opens the store and runs `ensure_agent_id`.
//// 2. Every public operation goes through `run`, which hands a job to
////    `handle` and waits for its reply.
//// 3. Jobs commit through `commit_change`, which tells the shell the effects
////    only after `store.commit` returned.
//// 4. `handle_envelope` is the inbound path, and `open_session` the
////    outbound one for a joiner whose queue just came up.

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
import core/offer.{type Approval}
import core/plan.{type EnvelopeRef, type Plan, EnvelopeRef}
import core/relationship.{type Relationship}
import core/route.{type Inbox}
import core/time.{type Instant}
import daemon/log
import daemon/mail
import daemon/store.{type Store}
import gleam/erlang/process.{type Name, type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result

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
  /// digest. Nothing changed; the fetcher only acknowledges.
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
  )
}

/// The actor's mailbox protocol: one variant, a job to run against its own
/// state. Public only because the name's type mentions it.
pub opaque type Message {
  Run(job: fn(State) -> Nil)
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
    store.open(config.path, config.suite)
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

/// Runs one job to completion before the next is read.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // One variant: run the job against the actor's own state.
  case message {
    Run(job:) -> {
      job(state)
      actor.continue(state)
    }
  }
}

/// Hands a job to the engine and waits for its answer.
fn run(
  name: Name(Message),
  job: fn(State) -> Result(a, Failure),
) -> Result(a, Failure) {
  let asked =
    mail.ask(name, call_timeout_ms, fn(reply_with) {
      Run(fn(state) { process.send(reply_with, job(state)) })
    })

  // An answer is the job's own result; no answer in time is `Unavailable`.
  case asked {
    Ok(answer) -> answer
    Error(Nil) -> Error(Unavailable)
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
  name: Name(Message),
  description: String,
  approval: Approval,
  budget: Int,
) -> Result(Id(InvitationKind), Failure) {
  run(name, fn(state) {
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
/// // -> Ok(Some(<<...>>))
/// ```
pub fn invitation_file(
  name: Name(Message),
  invitation: Id(InvitationKind),
) -> Result(Option(BitArray), Failure) {
  run(name, fn(state) {
    use found <- result.try(
      fault(store.invitation_file(state.store, invitation)),
    )

    // The phase decides whether the file may leave the daemon.
    case found {
      store.FileReady(bytes:) -> Ok(Some(bytes))
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
  name: Name(Message),
  file: BitArray,
  description: String,
) -> Result(Id(Contact), Failure) {
  run(name, fn(state) {
    use invite <- result.try(
      invitation.decode(state.suite, file)
      |> result.replace_error(InvalidInvitation(
        "the file is not a valid invitation",
      )),
    )
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
  })
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
  name: Name(Message),
  queue: Id(Queue),
) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
  name: Name(Message),
  contact: Id(Contact),
) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
  name: Name(Message),
  contact: Id(Contact),
) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
  name: Name(Message),
  contact: Id(Contact),
) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
  name: Name(Message),
  contact: Id(Contact),
  by: Int,
) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
/// ## Examples
///
/// ```gleam
/// engine.send(name, contact, "text/plain", <<"hi">>, None)
/// // -> Ok(message_id)
/// ```
pub fn send(
  name: Name(Message),
  contact: Id(Contact),
  content_type: String,
  payload: BitArray,
  in_reply_to: Option(Id(MessageKind)),
) -> Result(Id(MessageKind), Failure) {
  run(name, fn(state) {
    use made <- result.try(
      revise(state, contact, fn(current) {
        relationship.send(
          state.suite,
          current,
          state.clock(),
          content_type,
          payload,
          in_reply_to,
          None,
        )
      }),
    )

    // The message identifier exists only inside the outbox record the plan
    // carries.
    sent_message(made.records)
  })
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
  name: Name(Message),
  message: Id(MessageKind),
) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
pub fn expire_offers(name: Name(Message)) -> Result(Nil, Failure) {
  run(name, fn(state) {
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
/// `Repeat`. Everything else runs through the core, and whatever the core
/// refuses is committed as dropped. `Ok` means the outcome is durable and the
/// fetcher may acknowledge it; an error means nothing was committed.
///
/// ## Examples
///
/// ```gleam
/// engine.process(name, queue, envelope, padded)
/// // -> Ok(engine.Fresh)
/// ```
pub fn process(
  name: Name(Message),
  queue: Id(Queue),
  envelope: Id(Envelope),
  padded: Padded,
) -> Result(Handled, Failure) {
  run(name, fn(state) { handle_envelope(state, queue, envelope, padded) })
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
        True -> Ok(Repeat)
        False -> new_envelope(state, ref, padded)
      }

    None -> new_envelope(state, ref, padded)
  }
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

    Some(record) ->
      case
        relationship.receive(
          state.suite,
          record.relationship,
          state.clock(),
          ref,
          bytes,
        )
      {
        Ok(made) ->
          revise_with(state, made, record.version)
          |> result.replace(Fresh)

        Error(_) -> drop(state, ref)
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
  name: Name(Message),
) -> Result(List(store.ContactRecord), Failure) {
  run(name, fn(state) { fault(store.contacts(state.store)) })
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
  name: Name(Message),
  contact: Option(Id(Contact)),
  max: Int,
) -> Result(List(store.DeliveryRecord), Failure) {
  run(name, fn(state) {
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
  name: Name(Message),
  message: Id(MessageKind),
) -> Result(store.SentState, Failure) {
  run(name, fn(state) {
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
  name: Name(Message),
  contact: Option(Id(Contact)),
  limit: Int,
) -> Result(List(store.AuditRecord), Failure) {
  run(name, fn(state) { fault(store.audit(state.store, contact, limit)) })
}

/// The inboxes to fetch from.
///
/// ## Examples
///
/// ```gleam
/// engine.live_inboxes(name)
/// // -> Ok([inbox])
/// ```
pub fn live_inboxes(name: Name(Message)) -> Result(List(Inbox), Failure) {
  run(name, fn(state) { fault(store.live_inboxes(state.store)) })
}

/// The inboxes whose queue the mailbox must still be asked to create.
///
/// ## Examples
///
/// ```gleam
/// engine.pending_inboxes(name)
/// // -> Ok([inbox])
/// ```
pub fn pending_inboxes(name: Name(Message)) -> Result(List(Inbox), Failure) {
  run(name, fn(state) { fault(store.pending_inboxes(state.store)) })
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
  name: Name(Message),
  limit: Int,
) -> Result(List(store.OutboxRow), Failure) {
  run(name, fn(state) { fault(store.due(state.store, state.clock(), limit)) })
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
  name: Name(Message),
  envelope: Id(Envelope),
  outcome: store.SendOutcome,
) -> Result(Nil, Failure) {
  run(name, fn(state) {
    fault(store.record_send(state.store, envelope, outcome))
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
  name: Name(Message),
  queue: Id(Queue),
) -> Result(List(Id(Envelope)), Failure) {
  run(name, fn(state) { fault(store.unacked(state.store, queue)) })
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
  name: Name(Message),
  queue: Id(Queue),
  envelopes: List(Id(Envelope)),
) -> Result(Nil, Failure) {
  run(name, fn(state) { fault(store.mark_acked(state.store, queue, envelopes)) })
}

/// How many outbox rows still wait for a mailbox.
///
/// ## Examples
///
/// ```gleam
/// engine.outbox_pending(name)
/// // -> Ok(0)
/// ```
pub fn outbox_pending(name: Name(Message)) -> Result(Int, Failure) {
  run(name, fn(state) { fault(store.pending_count(state.store)) })
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
      log.line("engine", "a state write lost its version check")
      Error(Unavailable)
    }

    Error(store.Sql(_))
    | Error(store.FutureSchema(..))
    | Error(store.Corrupt(_)) -> {
      log.line("engine", "a storage operation failed")
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
    | relationship.DescriptionTooLong -> refused(refusal)
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
  })
}

//// A small pure world for the pairing and relationship state machines:
//// three parties (an inviter and two joiners), a mailbox, a shell that
//// commits plans, and a delivery scheduler. Tests drive it with schedules
//// of steps and read the invariants of spec §13.1 off the result.
////
//// ## What it models
////
//// Each party has a *committed store*: a relationship blob and an offer
//// blob (the `core/snapshot` encodings, decoded again on every step, so
//// every step is also a restart), the outbox rows, the set of processed
//// envelopes with their digests, and the messages delivered to its agent.
//// A transition's plan is applied to the store atomically, or discarded
//// whole by a `Crash`; nothing in between exists. The mailbox is a list of
//// stored envelopes per queue. The scheduler transmits only rows it reads
//// from a committed outbox and acknowledges only envelopes the committed
//// store holds a `Processed` record for, with the same digest.
////
//// The invariants are checked where the event happens, not at the end,
//// and recorded as strings in `violations`. That is what lets a test show
//// the checks are sharp: a `Bug` swaps in a shell that sends or
//// acknowledges before commit, and the same schedules then report
//// violations.
////
//// ## Faults
////
//// Duplicates (a redelivered envelope, a mailbox that replays a ciphertext
//// under a new envelope identifier), reordering (a fetch may pick any
//// envelope), drops (a transmit may never happen), corruption (a flipped
//// byte in a stored envelope), time passing (invitations and messages
//// expire) and crashes (a computed plan is discarded) are all steps.
////
//// Each fault class has a bit in a mask (`Fault`), and a schedule offers a
//// class only when its bit is set, so a swarm of schedules each enables a
//// different subset (`enabled_with`). An op whose class is off is never on
//// offer, so the schedule performs an honest action instead.
////
//// ## The mailbox and the scheduler match production
////
//// An outbox row has a status. The scheduler stops resending a row once the
//// mailbox answered it (`Appended`), and the mailbox keeps a tombstone for
//// every acknowledged envelope, so a retransmit after an acknowledgement is
//// answered and not stored again. A transmit whose reply is lost leaves the
//// row `Pending`, so it is retried and the mailbox answers from what it
//// already holds. Without both rules the settle would redeliver a message a
//// corrupting mailbox had spoiled, and a lost message would look healed.
////
//// ## The heal phase
////
//// `heal` turns every fault off and lets time pass: it pumps to a fixed
//// point, lets the operator approve what waits for approval, raises the
//// budget until nothing is held, and pumps again. The audits that follow
//// (`audit_quiescence`, `audit_delivery`, `audit_close`, `audit_release`)
//// check what must be true once nothing is left to do. Where a state is
//// legitimately undeliverable (the receiver closed, the message expired) or
//// is a known policy gap (the mailbox corrupted the only copy), the audit
//// records a named, counted *excuse* (`excuses_of`) instead of passing
//// silently, so a swarm can report how often each one was used.

import core/crypto/fake_suite
import core/crypto/suite.{type Suite}
import core/endpoint
import core/envelope.{type Padded}
import core/frame
import core/id
import core/invitation
import core/offer.{type Approval, type Offer}
import core/plan
import core/relationship.{type Relationship}
import core/route
import core/secret
import core/snapshot
import core/time.{Instant}
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}

/// Whether a computed plan is committed or lost to a crash.
pub type Fate {
  Commit
  Crash
}

/// Which shell the world runs: the correct one, or a deliberately broken
/// one, so a test can show the invariant checks detect the breakage.
pub type Bug {
  Correct
  SendBeforeCommit
  AckBeforeCommit
}

/// One thing that can happen. Party numbers: 0 the inviter, 1 and 2 the
/// joiners.
pub type Step {
  Setup(Int)
  Provision(Int, Fate)
  Approve(Int, Fate)
  Decline(Int, Fate)
  Close(Int, Fate)
  Send(Int, Int, Fate)
  Raise(Int)
  Expire(Int)
  Transmit(Int, Int)
  Fetch(Int, Int, Fate)
  Ack(Int)
  Corrupt(Int, Int)
  Replay(Int, Int)
  Tick(Int)

  /// A transmit whose reply is lost: the mailbox appends the envelope and
  /// the scheduler never learns it did, so the row stays `Pending`.
  TransmitLost(Int, Int)
}

/// The fault classes a schedule can switch on, one bit each in a mask.
pub type Fault {
  /// Plans lost to a crash before their commit.
  Crashes

  /// A byte flipped in a stored envelope.
  Corruption

  /// A stored ciphertext replayed under a new envelope identifier.
  Replays

  /// `Close` and `Decline`, which end a relationship.
  Destruction

  /// The clock moving, and the offer expiring.
  Clock

  /// The operator raising a budget.
  Raises

  /// A fetch that may pick any stored envelope rather than the oldest.
  Reordering

  /// A transmit whose reply is lost.
  LostReplies
}

/// Whether the mailbox has answered a row's append.
pub type RowStatus {
  /// Not yet answered: the scheduler sends it again.
  Pending

  /// The mailbox answered: the scheduler never sends it again.
  Appended
}

pub type Row {
  Row(
    envelope: BitArray,
    queue: BitArray,
    padded: Padded,
    kind: plan.OutboundKind,
    status: RowStatus,
  )
}

/// A committed application message: its identifier, the peer's queue, the
/// envelope that carries it, and the clock when it was committed.
pub type Sent {
  Sent(message: BitArray, queue: BitArray, envelope: BitArray, at: Int)
}

pub type Stored {
  Stored(envelope: BitArray, padded: Padded, digest: BitArray)
}

pub type Party {
  Party(
    queue: Option(BitArray),
    relationship: Option(BitArray),
    offer: Option(BitArray),
    outbox: List(Row),
    processed: Dict(#(BitArray, BitArray), BitArray),
    delivered: List(#(BitArray, plan.DeliveryStatus)),
    received_by_peer: List(BitArray),
    // Ratchet header (key, PN, N) of every committed ratchet row, with the
    // bytes it was committed with: a header seen with other bytes is a
    // message key used twice.
    headers: Dict(BitArray, BitArray),
    sent_messages: List(Sent),
    // The peer's queue and envelope of each `Close` committed from `Active`.
    closes: List(#(BitArray, BitArray)),
  )
}

pub type World {
  World(
    suite: Suite,
    bug: Bug,
    approval: Approval,
    budget: Int,
    now: Int,
    parties: Dict(Int, Party),
    mailbox: Dict(BitArray, List(Stored)),
    // The digest of every acknowledged envelope, by queue and identifier:
    // the mailbox answers a retransmit of one from here.
    tombstones: Dict(#(BitArray, BitArray), BitArray),
    invitation_file: Option(BitArray),
    violations: List(String),
    excuses: List(String),
    redeemed: Int,
    sent: Int,
    acked: Int,
    events: List(String),
  )
}

/// What handling one envelope decided.
type Handled {
  Handled(
    relationship: Option(Relationship),
    offer: Option(Offer),
    records: List(plan.Record),
    redeemed: Int,
  )
}

/// A world seeded with zero: its identifiers repeat from world to world,
/// which is fine for a test that builds one. A simulation run takes its seed
/// from the schedule through `new_seeded`.
pub fn new(bug: Bug, approval: Approval, budget: Int) -> World {
  new_seeded(bug, approval, budget, 0)
}

/// A world whose identifiers and keys depend only on `seed`.
pub fn new_seeded(
  bug: Bug,
  approval: Approval,
  budget: Int,
  seed: Int,
) -> World {
  let empty =
    Party(
      queue: None,
      relationship: None,
      offer: None,
      outbox: [],
      processed: dict.new(),
      delivered: [],
      received_by_peer: [],
      headers: dict.new(),
      sent_messages: [],
      closes: [],
    )

  World(
    suite: fake_suite.seeded(seed),
    bug:,
    approval:,
    budget:,
    now: 1000,
    parties: dict.from_list([#(0, empty), #(1, empty), #(2, empty)]),
    mailbox: dict.new(),
    tombstones: dict.new(),
    invitation_file: None,
    violations: [],
    excuses: [],
    redeemed: 0,
    sent: 0,
    acked: 0,
    events: [],
  )
}

pub fn party(world: World, number: Int) -> Party {
  case dict.get(world.parties, number) {
    Ok(party) -> party
    Error(Nil) -> panic as "the world has parties 0, 1 and 2"
  }
}

fn put_party(world: World, number: Int, party: Party) -> World {
  World(..world, parties: dict.insert(world.parties, number, party))
}

pub fn relationship(world: World, number: Int) -> Option(Relationship) {
  case party(world, number).relationship {
    None -> None
    Some(blob) ->
      case snapshot.decode_relationship(world.suite, blob) {
        Ok(rel) -> Some(rel)
        Error(_) -> panic as "a committed relationship snapshot decodes"
      }
  }
}

pub fn offer(world: World, number: Int) -> Option(Offer) {
  case party(world, number).offer {
    None -> None
    Some(blob) ->
      case snapshot.decode_offer(world.suite, blob) {
        Ok(found) -> Some(found)
        Error(_) -> panic as "a committed offer snapshot decodes"
      }
  }
}

pub fn count_delivered(
  world: World,
  number: Int,
  status: plan.DeliveryStatus,
) -> Int {
  party(world, number).delivered
  |> list.filter(fn(row) { row.1 == status })
  |> list.length
}

fn event(world: World, name: String) -> World {
  World(..world, events: [name, ..world.events])
}

pub fn saw(world: World, name: String) -> Bool {
  list.contains(world.events, name)
}

fn note(world: World, violation: String) -> World {
  World(..world, violations: [violation, ..world.violations])
}

/// Records a state an audit accepted without proving the property, by name.
fn excuse(world: World, name: String) -> World {
  World(..world, excuses: [name, ..world.excuses])
}

/// The excuses the audits used, oldest first, one entry per use.
pub fn excuses_of(world: World) -> List(String) {
  list.reverse(world.excuses)
}

fn at(items: List(a), index: Int) -> Option(a) {
  case list.length(items) {
    0 -> None
    size ->
      case list.drop(items, int.modulo(index, size) |> result_or_zero) {
        [first, ..] -> Some(first)
        [] -> None
      }
  }
}

fn result_or_zero(value: Result(Int, Nil)) -> Int {
  case value {
    Ok(number) -> number
    Error(Nil) -> 0
  }
}

fn instant(world: World) -> time.Instant {
  Instant(unix_seconds: world.now)
}

fn terms(world: World) -> relationship.Terms {
  let assert Ok(port) = endpoint.port(7000) as "a valid port"
  let assert Ok(inbox) = route.new_inbox(world.suite, endpoint.Loopback(port))
    as "fresh inbox"

  relationship.Terms(inbox:, description: "party", budget: world.budget)
}

// ------------------------------------------------------------ the steps

pub fn run(world: World, steps: List(Step)) -> World {
  list.fold(steps, world, step)
}

pub fn step(world: World, next: Step) -> World {
  case next {
    Setup(number) -> setup(world, number)
    Provision(number, fate) -> provision(world, number, fate)
    Approve(number, fate) -> operate(world, number, Approving, fate)
    Decline(number, fate) -> operate(world, number, Declining, fate)
    Close(number, fate) -> operate(world, number, Closing, fate)
    Send(number, tag, fate) -> operate(world, number, Sending(tag), fate)
    Raise(number) -> operate(world, number, Raising, Commit)
    Expire(number) -> expire(world, number)
    Transmit(number, index) -> transmit(world, number, index, Heard)
    TransmitLost(number, index) -> transmit(world, number, index, Lost)
    Fetch(number, index, fate) -> fetch(world, number, index, fate)
    Ack(number) -> ack(world, number)
    Corrupt(number, index) -> corrupt(world, number, index)
    Replay(number, index) -> replay(world, number, index)
    Tick(seconds) -> World(..world, now: world.now + seconds)
  }
}

fn setup(world: World, number: Int) -> World {
  let mine = party(world, number)

  case number, mine.offer, mine.relationship, world.invitation_file {
    0, None, None, _ -> setup_offer(world)
    0, _, _, _ -> world
    _, None, None, Some(file) -> setup_join(world, number, file)
    _, _, _, _ -> world
  }
}

fn setup_offer(world: World) -> World {
  let terms = terms(world)

  case offer.create(world.suite, terms, world.approval, instant(world)) {
    Ok(made) -> {
      let mine =
        Party(
          ..party(world, 0),
          queue: Some(id.to_bytes(terms.inbox.queue)),
          offer: Some(secret.expose(snapshot.encode_offer(made.state))),
        )

      put_party(world, 0, mine)
    }
    Error(_) -> note(world, "offer creation failed")
  }
}

fn setup_join(world: World, number: Int, file: BitArray) -> World {
  case invitation.decode(world.suite, file) {
    Error(_) -> note(world, "a published invitation file failed to decode")
    Ok(invite) -> {
      let terms = terms(world)

      case
        relationship.join(
          world.suite,
          invite,
          endpoint.TorOrLoopback,
          terms,
          instant(world),
        )
      {
        Ok(joining) -> {
          let mine =
            Party(
              ..party(world, number),
              queue: Some(id.to_bytes(terms.inbox.queue)),
              relationship: Some(
                secret.expose(snapshot.encode_relationship(joining.state)),
              ),
            )

          put_party(world, number, mine)
        }
        // An expired invitation is the expected refusal.
        Error(_) -> world
      }
    }
  }
}

/// The shell creates the queue and then reports it: the offer opens, or the
/// joiner's session starts.
fn provision(world: World, number: Int, fate: Fate) -> World {
  case offer(world, number), relationship(world, number) {
    Some(found), _ -> provision_offer(world, number, found, fate)
    None, Some(rel) -> provision_join(world, number, rel, fate)
    None, None -> world
  }
}

fn provision_offer(
  world: World,
  number: Int,
  found: Offer,
  fate: Fate,
) -> World {
  case found.phase {
    offer.Provisioning(stock) -> {
      let world = create_queue(world, id.to_bytes(stock.inbox.queue))
      let opened = offer.provisioned(found)
      let file = case offer.invitation(opened) {
        Ok(invite) -> Some(secret.expose(invitation.encode(invite)))
        Error(Nil) -> None
      }
      let mine =
        Party(
          ..party(world, number),
          offer: Some(secret.expose(snapshot.encode_offer(opened))),
        )

      // The queue exists either way; a crash loses only the report of it.
      case fate {
        Crash -> world
        Commit -> World(..put_party(world, number, mine), invitation_file: file)
      }
    }
    offer.Open(_) | offer.Consumed(..) | offer.Expired -> world
  }
}

fn provision_join(
  world: World,
  number: Int,
  rel: Relationship,
  fate: Fate,
) -> World {
  case rel.phase {
    relationship.Joining(..) -> {
      let world = create_queue(world, id.to_bytes(rel.inbox.queue))

      case relationship.joined(world.suite, rel, instant(world)) {
        Ok(started) ->
          finish_operation(
            world,
            number,
            fate,
            Handled(
              relationship: Some(started.state),
              offer: None,
              records: started.records,
              redeemed: 0,
            ),
          )
        Error(_) -> world
      }
    }
    relationship.AwaitingAccept(_)
    | relationship.PendingApproval(_)
    | relationship.Active(_)
    | relationship.Closed(_) -> world
  }
}

fn create_queue(world: World, queue: BitArray) -> World {
  case dict.has_key(world.mailbox, queue) {
    True -> world
    False -> World(..world, mailbox: dict.insert(world.mailbox, queue, []))
  }
}

type Operation {
  Approving
  Declining
  Closing
  Sending(Int)
  Raising
}

fn operate(
  world: World,
  number: Int,
  operation: Operation,
  fate: Fate,
) -> World {
  case relationship(world, number) {
    None -> world
    Some(rel) -> {
      let now = instant(world)
      let outcome = case operation {
        Approving -> relationship.approve(world.suite, rel, now)
        Declining -> relationship.decline(world.suite, rel, now)
        Closing -> relationship.close(world.suite, rel, now)
        Raising -> relationship.raise_budget(rel, 2)
        Sending(tag) ->
          relationship.send(
            world.suite,
            rel,
            now,
            "text/plain",
            <<tag:size(16)>>,
            None,
            None,
          )
      }

      case outcome {
        Ok(done) ->
          world
          |> record_operation(rel, operation, fate)
          |> check_raise(rel, operation, done)
          |> finish_operation(
            number,
            fate,
            Handled(
              relationship: Some(done.state),
              offer: None,
              records: done.records,
              redeemed: 0,
            ),
          )
          |> record_close(number, rel, operation, fate, done.records)
        Error(_) -> world
      }
    }
  }
}

/// Notes the operations the non-vacuity test counts, once they commit.
fn record_operation(
  world: World,
  rel: Relationship,
  operation: Operation,
  fate: Fate,
) -> World {
  case fate, operation, rel.phase {
    Crash, _, _ -> world
    Commit, Closing, relationship.Joining(..) ->
      event(world, "close-from-joining")
    Commit, Closing, relationship.AwaitingAccept(_) ->
      event(world, "close-from-awaiting")
    Commit, Declining, _ -> event(world, "decline")
    _, _, _ -> world
  }
}

/// A raise releases the oldest held messages, as many as the new room
/// admits: after `Raise` of two with `held` waiting, exactly the first
/// `min(2, held)` are released, in order, and the rest still wait.
fn check_raise(
  world: World,
  rel: Relationship,
  operation: Operation,
  done: plan.Plan(Relationship),
) -> World {
  case operation {
    Raising -> {
      let released = list.take(rel.budget.held, 2)
      let expected = case released {
        [] -> []
        [_, ..] -> [plan.Released(rel.contact, released)]
      }
      let released_records =
        list.filter(done.records, fn(record) {
          case record {
            plan.Released(..) -> True
            _ -> False
          }
        })

      case
        released_records == expected
        && done.state.budget.held == list.drop(rel.budget.held, 2)
      {
        True -> world
        False -> note(world, "raise did not release the oldest held messages")
      }
    }
    Approving | Declining | Closing | Sending(_) -> world
  }
}

/// A `Close` committed from `Active` is remembered with the peer's queue and
/// the envelope that carries it, for `audit_close`.
fn record_close(
  world: World,
  number: Int,
  rel: Relationship,
  operation: Operation,
  fate: Fate,
  records: List(plan.Record),
) -> World {
  case fate, operation, rel.phase {
    Commit, Closing, relationship.Active(_) -> {
      let mine = party(world, number)
      let closes =
        list.filter_map(records, fn(record) {
          case record {
            plan.Outbound(envelope: envelope_id, route: target, ..) ->
              Ok(#(id.to_bytes(target.queue), id.to_bytes(envelope_id)))
            _ -> Error(Nil)
          }
        })

      put_party(
        world,
        number,
        Party(..mine, closes: list.append(mine.closes, closes)),
      )
    }
    _, _, _ -> world
  }
}

/// A locally started operation's plan is committed or lost to a crash. A
/// broken shell has already put its ciphertext on the wire.
fn finish_operation(
  world: World,
  number: Int,
  fate: Fate,
  handled: Handled,
) -> World {
  let world = case world.bug {
    SendBeforeCommit -> send_rows(world, handled.records)
    Correct | AckBeforeCommit -> world
  }

  case fate {
    Crash -> world
    Commit -> commit(world, number, handled)
  }
}

/// The inviter retires an unused offer whose deadline has passed.
fn expire(world: World, number: Int) -> World {
  case offer(world, number) {
    None -> world
    Some(found) -> {
      let retired = offer.expire(found, instant(world))

      case retired == found {
        True -> world
        False ->
          Party(
            ..party(world, number),
            offer: Some(secret.expose(snapshot.encode_offer(retired))),
          )
          |> put_party(world, number, _)
          |> event("offer-expired")
      }
    }
  }
}

// ---------------------------------------------------------- the scheduler

/// What the mailbox said to an append.
type Answer {
  /// It holds the envelope, from this append or an earlier one.
  Answered

  /// It refused: the queue does not exist.
  Refused
}

/// Whether the scheduler hears the mailbox's answer.
type Reply {
  Heard
  Lost
}

/// Everything that reaches a mailbox goes through here, and the check is
/// the invariant "no send before commit": the bytes must equal a row of
/// some committed outbox. The mailbox answers a retransmit from what it
/// holds or from a tombstone, and never stores one twice.
fn wire_send(
  world: World,
  queue: BitArray,
  envelope: BitArray,
  padded: Padded,
) -> #(World, Answer) {
  let bytes = envelope.to_wire(padded)
  let committed =
    dict.values(world.parties)
    |> list.any(fn(party) {
      list.any(party.outbox, fn(row) { envelope.to_wire(row.padded) == bytes })
    })
  let world = case committed {
    True -> world
    False -> note(world, "sent before commit")
  }

  case dict.get(world.mailbox, queue) {
    // A queue that does not exist refuses the append, as a mailbox would.
    Error(Nil) -> #(world, Refused)
    Ok(stored) ->
      case
        list.any(stored, fn(item) { item.envelope == envelope })
        || dict.has_key(world.tombstones, #(queue, envelope))
      {
        True -> #(world, Answered)
        False -> #(
          World(
            ..world,
            sent: world.sent + 1,
            mailbox: dict.insert(
              world.mailbox,
              queue,
              list.append(stored, [
                Stored(envelope:, padded:, digest: digest(world, padded)),
              ]),
            ),
          ),
          Answered,
        )
      }
  }
}

/// The scheduler sends a row it reads from the committed outbox, and only
/// while the mailbox has not answered it. A reply that is lost leaves the
/// row pending, so the next attempt is answered from the mailbox's copy.
fn transmit(world: World, number: Int, index: Int, reply: Reply) -> World {
  case at(party(world, number).outbox, index) {
    None -> world
    Some(Row(status: Appended, ..)) -> world
    Some(row) -> {
      let #(world, answer) =
        wire_send(world, row.queue, row.envelope, row.padded)

      case answer, reply {
        Answered, Heard -> mark_appended(world, number, row.envelope)
        Answered, Lost | Refused, _ -> world
      }
    }
  }
}

fn mark_appended(world: World, number: Int, envelope: BitArray) -> World {
  let mine = party(world, number)

  put_party(
    world,
    number,
    Party(
      ..mine,
      outbox: list.map(mine.outbox, fn(row) {
        case row.envelope == envelope {
          True -> Row(..row, status: Appended)
          False -> row
        }
      }),
    ),
  )
}

fn digest(world: World, padded: Padded) -> BitArray {
  world.suite.sha256(envelope.to_wire(padded))
}

fn is_processed(
  world: World,
  number: Int,
  queue: BitArray,
  item: Stored,
) -> Bool {
  dict.get(party(world, number).processed, #(queue, item.envelope))
  == Ok(item.digest)
}

/// Acknowledges one stored envelope to the mailbox, which deletes it. The
/// check is the invariant "no ack before commit".
fn ack_now(world: World, number: Int, queue: BitArray, item: Stored) -> World {
  let world = case is_processed(world, number, queue, item) {
    True -> world
    False -> note(world, "acknowledged before commit")
  }
  let remaining = case dict.get(world.mailbox, queue) {
    Ok(stored) ->
      list.filter(stored, fn(other) { other.envelope != item.envelope })
    Error(Nil) -> []
  }

  World(
    ..world,
    acked: world.acked + 1,
    mailbox: dict.insert(world.mailbox, queue, remaining),
    tombstones: dict.insert(
      world.tombstones,
      #(queue, item.envelope),
      item.digest,
    ),
  )
}

fn ack(world: World, number: Int) -> World {
  case party(world, number).queue {
    None -> world
    Some(queue) -> {
      let stored = case dict.get(world.mailbox, queue) {
        Ok(stored) -> stored
        Error(Nil) -> []
      }

      list.fold(stored, world, fn(world, item) {
        case is_processed(world, number, queue, item) {
          True -> ack_now(world, number, queue, item)
          False -> world
        }
      })
    }
  }
}

fn corrupt(world: World, number: Int, index: Int) -> World {
  update_stored(world, number, index, fn(item) {
    let wire = envelope.to_wire(item.padded)
    let size = bit_array.byte_size(wire)
    let position = case int.modulo(index, 3) {
      // Every third corruption lands anywhere, usually in the padding tail.
      Ok(0) -> int.modulo(index * 7919, size) |> result_or_zero
      _ -> int.modulo(index * 7919, 100) |> result_or_zero
    }
    let assert Ok(before) = bit_array.slice(wire, 0, position)
    let assert Ok(<<byte, _:bytes>>) =
      bit_array.slice(wire, position, bit_array.byte_size(wire) - position)
    let assert Ok(after) =
      bit_array.slice(
        wire,
        position + 1,
        bit_array.byte_size(wire) - position - 1,
      )
    let flipped = <<
      before:bits,
      int.bitwise_exclusive_or(byte, 0xFF),
      after:bits,
    >>
    let assert Ok(padded) = envelope.from_wire(flipped)

    Some(Stored(..item, padded:, digest: digest(world, padded)))
  })
}

/// A mailbox that replays a ciphertext under a fresh envelope identifier,
/// the case a deduplication by envelope identifier alone cannot see.
fn replay(world: World, number: Int, index: Int) -> World {
  case party(world, number).queue {
    None -> world
    Some(queue) -> {
      let stored = case dict.get(world.mailbox, queue) {
        Ok(stored) -> stored
        Error(Nil) -> []
      }

      case at(stored, index) {
        None -> world
        Some(item) -> {
          let copy = Stored(..item, envelope: world.suite.random(id.id_bytes))

          World(
            ..world,
            mailbox: dict.insert(
              world.mailbox,
              queue,
              list.append(stored, [copy]),
            ),
          )
        }
      }
    }
  }
}

fn update_stored(
  world: World,
  number: Int,
  index: Int,
  change: fn(Stored) -> Option(Stored),
) -> World {
  case party(world, number).queue {
    None -> world
    Some(queue) -> {
      let stored = case dict.get(world.mailbox, queue) {
        Ok(stored) -> stored
        Error(Nil) -> []
      }

      case at(stored, index) {
        None -> world
        Some(item) ->
          case change(item) {
            None -> world
            Some(new) -> {
              let replaced =
                list.map(stored, fn(other) {
                  case other.envelope == item.envelope {
                    True -> new
                    False -> other
                  }
                })

              World(
                ..world,
                mailbox: dict.insert(world.mailbox, queue, replaced),
              )
            }
          }
      }
    }
  }
}

// ----------------------------------------------------------- the shell

fn fetch(world: World, number: Int, index: Int, fate: Fate) -> World {
  let mine = party(world, number)

  case mine.queue {
    None -> world
    Some(queue) -> {
      let stored = case dict.get(world.mailbox, queue) {
        Ok(stored) -> stored
        Error(Nil) -> []
      }

      case at(stored, index) {
        None -> world
        Some(item) ->
          case is_processed(world, number, queue, item) {
            // Already committed: acknowledging is all that is left to do.
            True -> world
            False -> process(world, number, queue, item, fate)
          }
      }
    }
  }
}

fn process(
  world: World,
  number: Int,
  queue: BitArray,
  item: Stored,
  fate: Fate,
) -> World {
  let assert Ok(queue_id) = id.from_bytes(queue)
  let assert Ok(envelope_id) = id.from_bytes(item.envelope)
  let ref =
    plan.EnvelopeRef(
      queue: queue_id,
      envelope: envelope_id,
      digest: item.digest,
    )
  let handled = handle(world, number, ref, item.padded)

  // A broken shell does its network work before the commit, or
  // acknowledges before it. The correct one does neither.
  let world = case world.bug {
    Correct -> world
    SendBeforeCommit -> send_rows(world, handled.records)
    AckBeforeCommit -> ack_now(world, number, queue, item)
  }

  case fate {
    Crash -> world
    Commit ->
      commit(world, number, handled)
      |> note_expired(world, number, handled)
  }
}

/// An authenticated message that changes nothing but the session, in an
/// active relationship, is an expired application message (the honest peer
/// sends nothing else that does so).
fn note_expired(
  after: World,
  before: World,
  number: Int,
  handled: Handled,
) -> World {
  case relationship(before, number), handled.relationship, handled.records {
    Some(relationship.Relationship(phase: relationship.Active(_), ..)),
      Some(relationship.Relationship(phase: relationship.Active(_), ..)),
      [plan.Processed(outcome: plan.Applied, ..)]
    -> event(after, "expired-message")
    _, _, _ -> after
  }
}

fn send_rows(world: World, records: List(plan.Record)) -> World {
  list.fold(records, world, fn(world, record) {
    case record {
      plan.Outbound(envelope: envelope_id, route: target, padded:, ..) ->
        wire_send(
          world,
          id.to_bytes(target.queue),
          id.to_bytes(envelope_id),
          padded,
        ).0
      _ -> world
    }
  })
}

/// Opens a frame and routes it to the offer or the relationship, as the
/// daemon's shell will. Anything the core refuses is recorded as dropped.
fn handle(
  world: World,
  number: Int,
  ref: plan.EnvelopeRef,
  padded: Padded,
) -> Handled {
  let dropped =
    Handled(
      relationship: None,
      offer: None,
      records: [plan.dropped(ref)],
      redeemed: 0,
    )

  case frame.open(world.suite, padded) {
    Error(_) -> dropped
    Ok(frame.Initial(initial)) ->
      case offer(world, number) {
        None -> dropped
        Some(open) ->
          case
            offer.redeem(
              world.suite,
              open,
              endpoint.TorOrLoopback,
              ref,
              initial,
              instant(world),
            )
          {
            Ok(offer.Redeemed(offer: consumed, plan: made)) ->
              Handled(
                relationship: Some(made.state),
                offer: Some(consumed),
                records: made.records,
                redeemed: 1,
              )
            Ok(offer.Duplicate) | Error(_) -> dropped
          }
      }
    Ok(frame.Ratchet(bytes)) ->
      case relationship(world, number) {
        None -> dropped
        Some(rel) ->
          case
            relationship.receive(world.suite, rel, instant(world), ref, bytes)
          {
            Ok(made) ->
              Handled(
                relationship: Some(made.state),
                offer: None,
                records: made.records,
                redeemed: 0,
              )
            Error(_) -> dropped
          }
      }
  }
}

/// Applies a plan to the committed store atomically, checking the
/// invariants that are about what a commit may contain.
fn commit(world: World, number: Int, handled: Handled) -> World {
  let before = relationship(world, number)
  let world =
    check_delivery_allowed(world, before, handled.relationship, handled.records)
  let world = case world.redeemed + handled.redeemed > 1 {
    True -> note(world, "invitation consumed twice")
    False -> World(..world, redeemed: world.redeemed + handled.redeemed)
  }
  let world = check_headers(world, number, handled.records)

  // Phase order and receipts are checked on the plan, before it applies.
  let world = check_phase(world, before, handled.relationship)
  let world = check_receipts(world, number, handled.records)
  let mine =
    list.fold(handled.records, party(world, number), fn(mine, record) {
      apply_record(mine, record, world.now)
    })
  let mine = case handled.relationship {
    Some(rel) ->
      Party(
        ..mine,
        relationship: Some(secret.expose(snapshot.encode_relationship(rel))),
      )
    None -> mine
  }
  let mine = case handled.offer {
    Some(found) ->
      Party(..mine, offer: Some(secret.expose(snapshot.encode_offer(found))))
    None -> mine
  }
  let world = put_party(world, number, mine)

  world
  |> check_canonical(number)
  |> check_budget(number)
  |> check_no_redelivery(number)
}

/// How far along a relationship is. Pairing moves forward through these and
/// never back: a closed relationship stays closed, and an active one never
/// returns to a handshake phase.
fn rank(rel: Relationship) -> Int {
  case rel.phase {
    relationship.Joining(..) -> 0
    relationship.AwaitingAccept(_) | relationship.PendingApproval(_) -> 1
    relationship.Active(_) -> 2
    relationship.Closed(_) -> 3
  }
}

fn check_phase(
  world: World,
  before: Option(Relationship),
  after: Option(Relationship),
) -> World {
  case before, after {
    Some(was), Some(now) ->
      case rank(now) < rank(was) {
        True -> note(world, "relationship phase went backwards")
        False -> world
      }
    _, _ -> world
  }
}

/// A receipt names only messages this party sent, and names each once.
fn check_receipts(
  world: World,
  number: Int,
  records: List(plan.Record),
) -> World {
  let mine = party(world, number)
  let sent = list.map(mine.sent_messages, fn(item) { item.message })

  list.fold(records, world, fn(world, record) {
    case record {
      plan.PeerReceived(messages:, ..) -> {
        let named = list.map(messages, id.to_bytes)

        case list.all(named, list.contains(sent, _)) {
          False -> note(world, "receipt names a message never sent")
          True ->
            case
              list.any(named, list.contains(mine.received_by_peer, _))
              || list.length(list.unique(named)) != list.length(named)
            {
              True -> note(world, "message receipted twice")
              False -> world
            }
        }
      }
      _ -> world
    }
  })
}

/// Application messages are never delivered before `Active`.
fn check_delivery_allowed(
  world: World,
  before: Option(Relationship),
  after: Option(Relationship),
  records: List(plan.Record),
) -> World {
  // A joiner still awaiting `Accept` may deliver the message that is itself
  // the implicit accept (ADR-004): it must end `Active`. No other phase may.
  let was_active = case before, after {
    Some(relationship.Relationship(phase: relationship.Active(_), ..)), _ ->
      True
    Some(relationship.Relationship(phase: relationship.AwaitingAccept(_), ..)),
      Some(relationship.Relationship(phase: relationship.Active(_), ..))
    -> True
    _, _ -> False
  }
  let delivers =
    list.any(records, fn(record) {
      case record {
        plan.Delivered(status: plan.Ready, ..) | plan.Released(..) -> True
        _ -> False
      }
    })

  case delivers && !was_active {
    True -> note(world, "delivered before Active")
    False -> world
  }
}

fn apply_record(mine: Party, record: plan.Record, now: Int) -> Party {
  case record {
    plan.Outbound(envelope: envelope_id, route: target, padded:, kind:, ..) ->
      Party(
        ..mine,
        outbox: list.append(mine.outbox, [
          Row(
            envelope: id.to_bytes(envelope_id),
            queue: id.to_bytes(target.queue),
            padded:,
            kind:,
            status: Pending,
          ),
        ]),
        sent_messages: case kind {
          plan.ApplicationOut(message:) ->
            list.append(mine.sent_messages, [
              Sent(
                message: id.to_bytes(message),
                queue: id.to_bytes(target.queue),
                envelope: id.to_bytes(envelope_id),
                at: now,
              ),
            ])
          plan.Handshake | plan.ReceiptOut(_) | plan.ControlOut(_) ->
            mine.sent_messages
        },
      )

    plan.Processed(queue:, envelope: envelope_id, digest:, ..) ->
      Party(
        ..mine,
        processed: dict.insert(
          mine.processed,
          #(id.to_bytes(queue), id.to_bytes(envelope_id)),
          digest,
        ),
      )

    plan.Delivered(message:, status:, ..) ->
      Party(
        ..mine,
        delivered: list.append(mine.delivered, [#(id.to_bytes(message), status)]),
      )

    plan.Released(messages:, ..) -> {
      let released = list.map(messages, id.to_bytes)

      Party(
        ..mine,
        delivered: list.map(mine.delivered, fn(row) {
          case list.contains(released, row.0), row.1 {
            True, plan.Held -> #(row.0, plan.Ready)
            _, _ -> row
          }
        }),
      )
    }

    plan.PeerReceived(messages:, ..) ->
      Party(
        ..mine,
        received_by_peer: list.append(
          mine.received_by_peer,
          list.map(messages, id.to_bytes),
        ),
      )

    plan.Remembered(..) -> mine

    plan.Audit(..) -> mine
  }
}

/// The ratchet header is the message's nonce input: its first 40 bytes are
/// the sender's key, PN and N. The same header committed with different
/// bytes means one message key sealed two messages.
fn check_headers(
  world: World,
  number: Int,
  records: List(plan.Record),
) -> World {
  list.fold(records, world, fn(world, record) {
    case record {
      plan.Outbound(padded:, ..) ->
        case frame.open(world.suite, padded) {
          Ok(frame.Ratchet(bytes)) -> {
            let assert Ok(header) = bit_array.slice(bytes, 0, 40)
            let mine = party(world, number)

            case dict.get(mine.headers, header) {
              Ok(seen) if seen != bytes -> note(world, "message key used twice")
              Ok(_) -> world
              Error(Nil) ->
                put_party(
                  world,
                  number,
                  Party(
                    ..mine,
                    headers: dict.insert(mine.headers, header, bytes),
                  ),
                )
            }
          }
          Ok(frame.Initial(_)) | Error(_) -> world
        }
      _ -> world
    }
  })
}

/// A committed snapshot decodes and re-encodes to the same bytes.
fn check_canonical(world: World, number: Int) -> World {
  case party(world, number).relationship, relationship(world, number) {
    Some(blob), Some(rel) ->
      case secret.expose(snapshot.encode_relationship(rel)) == blob {
        True -> world
        False -> note(world, "relationship snapshot is not canonical")
      }
    _, _ -> world
  }
}

/// Never more `Ready` deliveries than the budget allows, and the budget's
/// own books agree with the delivered rows: the number of `Ready` rows is
/// `used`, and every identifier in `held` has a delivered row that is
/// `Held`. Counts alone would let a message be handed to the agent while
/// the budget still lists it as held, which is the divergence the demo's
/// unpaced runs were suspected of.
fn check_budget(world: World, number: Int) -> World {
  case relationship(world, number) {
    None -> world
    Some(rel) -> {
      let ready = count_delivered(world, number, plan.Ready)
      let held = count_delivered(world, number, plan.Held)
      let held_rows_are_held =
        list.all(rel.budget.held, fn(message) {
          list.contains(party(world, number).delivered, #(
            id.to_bytes(message),
            plan.Held,
          ))
        })

      case
        ready <= rel.budget.granted
        && ready == rel.budget.used
        && held == list.length(rel.budget.held)
        && held_rows_are_held
      {
        True -> world
        False -> note(world, "budget books disagree with deliveries")
      }
    }
  }
}

/// Each application message identifier is delivered at most once.
fn check_no_redelivery(world: World, number: Int) -> World {
  let ids = list.map(party(world, number).delivered, fn(row) { row.0 })

  case list.length(list.unique(ids)) == list.length(ids) {
    True -> world
    False -> note(world, "message delivered twice")
  }
}

// ------------------------------------------------------- driving a world

/// Which steps a schedule may pick from. `Chaotic` includes the destructive
/// operator actions and the clock; `Benign` leaves them out, so that every
/// committed message has a path to delivery and the delivery audit applies.
/// Duplicates, corruption, reordering, drops and crashes are in both.
pub type Mode {
  Chaotic
  Benign
}

/// The mask with every fault class on.
pub const every_fault = 0xFF

/// A mask with exactly these classes on.
pub fn mask_of(faults: List(Fault)) -> Int {
  list.fold(faults, 0, fn(mask, fault) {
    int.bitwise_or(mask, int.bitwise_shift_left(1, bit(fault)))
  })
}

/// The bit of a class in the mask, in the order the seed format fixes.
fn bit(fault: Fault) -> Int {
  case fault {
    Crashes -> 0
    Corruption -> 1
    Replays -> 2
    Destruction -> 3
    Clock -> 4
    Raises -> 5
    Reordering -> 6
    LostReplies -> 7
  }
}

fn is_on(mask: Int, fault: Fault) -> Bool {
  int.bitwise_and(mask, int.bitwise_shift_left(1, bit(fault))) != 0
}

/// The steps a schedule may pick from at this point, with every fault class
/// on. `choice` varies which rarer steps (destructive operators, crashes,
/// faults, the clock) are offered, so ordinary progress dominates and every
/// fault still occurs.
pub fn enabled(world: World, choice: Int, mode: Mode) -> List(Step) {
  enabled_with(world, choice, mode, every_fault)
}

/// As `enabled`, for a schedule whose fault classes are the bits of `mask`.
/// A class that is off is never offered, so a pick that would have landed on
/// it lands on an honest step instead; a class that is on is still thinned
/// by `choice`, so it stays rare.
pub fn enabled_with(
  world: World,
  choice: Int,
  mode: Mode,
  mask: Int,
) -> List(Step) {
  let chaotic = mode == Chaotic
  let destructive =
    chaotic && is_on(mask, Destruction) && int.modulo(choice, 16) == Ok(0)
  let ticking = chaotic && is_on(mask, Clock) && int.modulo(choice, 16) == Ok(1)

  // The rare classes are on only when the mask allows and `choice` picks.
  let crashing = is_on(mask, Crashes) && int.modulo(choice, 3) == Ok(0)
  let corrupting = is_on(mask, Corruption) && int.modulo(choice, 11) == Ok(0)
  let replaying = is_on(mask, Replays) && int.modulo(choice, 13) == Ok(0)
  let raising = is_on(mask, Raises) && int.modulo(choice, 5) == Ok(0)
  let losing = is_on(mask, LostReplies) && int.modulo(choice, 7) == Ok(0)
  let reordering = is_on(mask, Reordering)

  // One entry per step each party can take, in a stable order.
  let per_party =
    list.flat_map([0, 1, 2], fn(number) {
      let mine = party(world, number)
      let queued = case mine.queue {
        Some(queue) ->
          case dict.get(world.mailbox, queue) {
            Ok(stored) -> list.length(stored)
            Error(Nil) -> 0
          }
        None -> 0
      }

      // Without reordering a fetch takes the oldest envelope only.
      let fetchable = case reordering {
        True -> indices(queued)
        False -> indices(int.min(queued, 1))
      }

      list.flatten([
        lifecycle(world, number, mine, destructive, raising, crashing, choice),
        pending_rows(mine, number, losing),
        case queued {
          0 -> []
          _ -> [Ack(number)]
        },
        list.flat_map(fetchable, fn(index) {
          case crashing {
            True -> [Fetch(number, index, Commit), Fetch(number, index, Crash)]
            False -> [Fetch(number, index, Commit)]
          }
        }),
        list.flat_map(indices(queued), fn(index) {
          list.flatten([
            case corrupting {
              True -> [Corrupt(number, index)]
              False -> []
            },
            case replaying {
              True -> [Replay(number, index)]
              False -> []
            },
          ])
        }),
      ])
    })

  case ticking {
    True ->
      list.append(per_party, [
        Tick(3600),
        Tick(90_000),
        Tick(700_000),
        Expire(0),
      ])
    False -> per_party
  }
}

/// The scheduler's work: a transmit for each row the mailbox has not
/// answered, and a lost-reply variant of it when that fault is on.
fn pending_rows(mine: Party, number: Int, losing: Bool) -> List(Step) {
  list.index_map(mine.outbox, fn(row, index) {
    case row.status, losing {
      Appended, _ -> []
      Pending, True -> [Transmit(number, index), TransmitLost(number, index)]
      Pending, False -> [Transmit(number, index)]
    }
  })
  |> list.flatten
}

/// A step that may also crash before its commit, when crashes are on offer.
fn with_fate(crashing: Bool, step: fn(Fate) -> Step) -> List(Step) {
  case crashing {
    True -> [step(Commit), step(Crash)]
    False -> [step(Commit)]
  }
}

fn lifecycle(
  world: World,
  number: Int,
  mine: Party,
  destructive: Bool,
  raising: Bool,
  crashing: Bool,
  choice: Int,
) -> List(Step) {
  let setup = [Setup(number)]
  let provision = with_fate(crashing, Provision(number, _))
  let closing = case destructive {
    True -> with_fate(crashing, Close(number, _))
    False -> []
  }
  let phase = case relationship(world, number) {
    Some(rel) ->
      case rel.phase {
        relationship.PendingApproval(_) ->
          list.flatten([
            with_fate(crashing, Approve(number, _)),
            case destructive {
              True -> with_fate(crashing, Decline(number, _))
              False -> []
            },
          ])
        relationship.Active(_) ->
          list.flatten([
            with_fate(crashing, Send(number, choice, _)),
            case raising {
              True -> [Raise(number)]
              False -> []
            },
            closing,
          ])
        relationship.Joining(..) | relationship.AwaitingAccept(_) -> closing
        relationship.Closed(_) -> []
      }
    None -> []
  }

  case mine.offer, mine.relationship {
    None, None -> setup
    _, _ -> list.append(provision, phase)
  }
}

/// Runs one deterministic pump: provision, transmit every committed row,
/// process every stored envelope, acknowledge. Repeated, it carries a world
/// with no faults to quiescence.
pub fn settle(world: World, rounds: Int) -> World {
  case rounds <= 0 {
    True -> world
    False -> settle(pump(world), rounds - 1)
  }
}

fn pump(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    let world = step(world, Provision(number, Commit))
    let rows = list.length(party(world, number).outbox)
    let world =
      list.fold(indices(rows), world, fn(world, index) {
        case rows {
          0 -> world
          _ -> step(world, Transmit(number, index))
        }
      })

    list.fold([0, 1, 2], world, fn(world, other) {
      let queued = case party(world, other).queue {
        Some(queue) ->
          case dict.get(world.mailbox, queue) {
            Ok(stored) -> list.length(stored)
            Error(Nil) -> 0
          }
        None -> 0
      }

      list.fold(indices(queued), world, fn(world, index) {
        case queued {
          0 -> world
          _ -> step(world, Fetch(other, index, Commit))
        }
      })
      |> step(Ack(other))
    })
  })
}

/// The most pump rounds a heal phase gives one stage to reach a fixed point.
const heal_rounds = 60

/// Pumps until a round changes neither the parties nor the mailbox, letting
/// a second of the clock pass between rounds. A stage that is still moving
/// after `heal_rounds` is recorded as a stall: the world was not
/// quiescent when the faults stopped and the budget of time ran out.
fn converge(world: World, rounds: Int) -> World {
  case rounds <= 0 {
    True -> note(world, "heal did not reach a fixed point")
    False -> {
      let next = pump(world)

      case next.parties == world.parties && next.mailbox == world.mailbox {
        True -> next
        False -> converge(step(next, Tick(1)), rounds - 1)
      }
    }
  }
}

/// The heal phase: every fault is off and time passes, and nothing else. It
/// pumps to a fixed point, lets the operator approve what waits for approval
/// (a decision, not a fault), pumps again, raises each budget until nothing
/// is held, and pumps a last time. It never retransmits a stored row and
/// never re-stores an acknowledged envelope, because the scheduler and the
/// mailbox do neither.
pub fn heal(world: World) -> World {
  world
  |> converge(heal_rounds)
  |> approve_waiting
  |> converge(heal_rounds)
  |> raise_until_released
  |> converge(heal_rounds)
}

fn approve_waiting(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    case relationship(world, number) {
      Some(relationship.Relationship(phase: relationship.PendingApproval(_), ..)) ->
        step(world, Approve(number, Commit))
      _ -> world
    }
  })
}

/// Raises each active party's budget until its held queue is empty. A raise
/// of two releases two, so the loop is bounded by the held queue's limit.
fn raise_until_released(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    raise_party(world, number, relationship.max_held_messages)
  })
}

fn raise_party(world: World, number: Int, attempts: Int) -> World {
  case relationship(world, number), attempts <= 0 {
    Some(rel), False ->
      case rel.budget.held {
        [] -> world
        [_, ..] -> raise_party(step(world, Raise(number)), number, attempts - 1)
      }
    _, _ -> world
  }
}

/// The violations the invariant checks recorded, oldest first.
pub fn violations_of(world: World) -> List(String) {
  list.reverse(world.violations)
}

/// The numbers `0` up to but not including `count`.
fn indices(count: Int) -> List(Int) {
  case count <= 0 {
    True -> []
    False -> list.append(indices(count - 1), [count - 1])
  }
}

/// Follows a schedule: each pair picks one of the steps enabled at that
/// point, the first number choosing the step and the second which rarer
/// steps are on offer.
pub fn walk(world: World, picks: List(#(Int, Int)), mode: Mode) -> World {
  walk_with(world, picks, mode, every_fault)
}

/// As `walk`, offering only the fault classes in `mask`.
pub fn walk_with(
  world: World,
  picks: List(#(Int, Int)),
  mode: Mode,
  mask: Int,
) -> World {
  list.fold(picks, world, fn(world, pick) {
    case at(enabled_with(world, pick.1, mode, mask), pick.0) {
      Some(next) -> step(world, next)
      None -> world
    }
  })
}

/// After the heal, every mailbox is empty and every committed row has been
/// answered, with one exception: a row for a queue that was never created
/// stays pending, because the append is refused until the queue exists (the
/// joiner closed before it was provisioned, so nothing creates it).
pub fn audit_quiescence(world: World) -> World {
  let world =
    dict.fold(world.mailbox, world, fn(world, _queue, stored) {
      case stored {
        [] -> world
        [_, ..] -> note(world, "a mailbox still holds an envelope after heal")
      }
    })

  list.fold([0, 1, 2], world, fn(world, number) {
    list.fold(party(world, number).outbox, world, fn(world, row) {
      case row.status, dict.has_key(world.mailbox, row.queue) {
        Appended, _ -> world
        Pending, True -> note(world, "a row was never stored after heal")
        Pending, False -> excuse(world, "row-for-a-queue-never-created")
      }
    })
  })
}

/// The party whose inbox is `queue`.
fn owner(world: World, queue: BitArray) -> Option(Int) {
  list.find([0, 1, 2], fn(number) { party(world, number).queue == Some(queue) })
  |> option.from_result
}

fn is_closed(world: World, number: Int) -> Bool {
  case relationship(world, number) {
    Some(relationship.Relationship(phase: relationship.Closed(_), ..)) -> True
    _ -> False
  }
}

/// Whether `number` processed `envelope` from `queue` as a different byte
/// string than its sender committed: the mailbox corrupted the only copy.
fn was_corrupted(
  world: World,
  number: Int,
  queue: BitArray,
  envelope: BitArray,
  original: BitArray,
) -> Bool {
  case dict.get(party(world, number).processed, #(queue, envelope)) {
    Ok(seen) -> seen != world.suite.sha256(original)
    Error(Nil) -> False
  }
}

/// The committed bytes of the row that carries `kind`, by sender.
fn row_of(world: World, number: Int, kind: plan.OutboundKind) -> Option(Row) {
  list.find(party(world, number).outbox, fn(row) { row.kind == kind })
  |> option.from_result
}

/// After the heal, every committed application message is delivered to its
/// peer exactly once, stored `Ready` or `Held`, and receipted exactly once.
/// Three states excuse a missing delivery: the receiver's relationship is
/// closed, the message's lifetime ran out on the clock, or the mailbox
/// corrupted the only copy. The last is a policy gap: a stored row is never
/// resent, so a corrupting mailbox loses the message for good. A missing
/// receipt is excused when the sender closed, or when the receipt itself was
/// corrupted the same way.
pub fn audit_delivery(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    list.fold(party(world, number).sent_messages, world, fn(world, sent) {
      case owner(world, sent.queue) {
        None -> note(world, "a message was sent to a queue no party owns")
        Some(peer) -> audit_message(world, number, peer, sent)
      }
    })
  })
}

fn audit_message(world: World, number: Int, peer: Int, sent: Sent) -> World {
  let delivered =
    list.filter(party(world, peer).delivered, fn(row) { row.0 == sent.message })
    |> list.length
  let receipts =
    list.filter(party(world, number).received_by_peer, fn(other) {
      other == sent.message
    })
    |> list.length
  let original = case row_of(world, number, plan.ApplicationOut(id_of(sent))) {
    Some(row) -> envelope.to_wire(row.padded)
    None -> <<>>
  }

  case delivered {
    0 ->
      case
        is_closed(world, peer),
        world.now > sent.at + retention,
        was_corrupted(world, peer, sent.queue, sent.envelope, original)
      {
        True, _, _ -> excuse(world, "receiver-closed")
        _, True, _ -> excuse(world, "message-expired")
        _, _, True -> excuse(world, "message-corrupted-in-mailbox")
        _, _, _ -> note(world, "committed message was never delivered")
      }
    1 -> audit_receipt(world, number, peer, receipts)
    _ -> note(world, "committed message delivered more than once")
  }
}

fn audit_receipt(world: World, number: Int, peer: Int, receipts: Int) -> World {
  case receipts {
    1 -> world
    0 ->
      case is_closed(world, number), receipt_corrupted(world, number, peer) {
        True, _ -> excuse(world, "sender-closed")
        _, True -> excuse(world, "receipt-corrupted-in-mailbox")
        _, _ -> note(world, "delivered message was never receipted")
      }
    _ -> note(world, "delivered message receipted more than once")
  }
}

/// A receipt envelope names its messages only inside the ciphertext, so the
/// excuse is as wide as the evidence: some receipt the peer sent to this
/// party's queue was processed corrupted.
fn receipt_corrupted(world: World, number: Int, peer: Int) -> Bool {
  let queue = party(world, number).queue

  list.any(party(world, peer).outbox, fn(row) {
    case row.kind, queue {
      plan.ReceiptOut(_), Some(inbox) if row.queue == inbox ->
        was_corrupted(
          world,
          number,
          inbox,
          row.envelope,
          envelope.to_wire(row.padded),
        )
      _, _ -> False
    }
  })
}

fn id_of(sent: Sent) -> id.Id(id.Message) {
  let assert Ok(message) = id.from_bytes(sent.message)
    as "a committed message identifier has the identifier size"
  message
}

/// A message's lifetime on the clock.
const retention = 604_800

/// After the heal, every `Close` committed from `Active` has closed the
/// peer, unless the mailbox corrupted that envelope (the same policy gap
/// as in `audit_delivery`).
pub fn audit_close(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    list.fold(party(world, number).closes, world, fn(world, close) {
      let #(queue, envelope_id) = close

      case owner(world, queue) {
        None -> note(world, "a close was sent to a queue no party owns")
        Some(peer) ->
          case
            is_closed(world, peer),
            close_corrupted(world, number, peer, queue, envelope_id)
          {
            True, _ -> world
            False, True -> excuse(world, "close-corrupted-in-mailbox")
            False, False -> note(world, "a close never closed the peer")
          }
      }
    })
  })
}

fn close_corrupted(
  world: World,
  number: Int,
  peer: Int,
  queue: BitArray,
  envelope_id: BitArray,
) -> Bool {
  case
    list.find(party(world, number).outbox, fn(row) {
      row.envelope == envelope_id
    })
  {
    Ok(row) ->
      was_corrupted(
        world,
        peer,
        queue,
        envelope_id,
        envelope.to_wire(row.padded),
      )
    Error(Nil) -> False
  }
}

/// After the heal's raises, no active party still holds a message back.
pub fn audit_release(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    case relationship(world, number) {
      Some(relationship.Relationship(phase: relationship.Active(_), ..)) ->
        case count_delivered(world, number, plan.Held) {
          0 -> world
          _ -> note(world, "held messages remain after the budget was raised")
        }
      _ -> world
    }
  })
}

/// Every audit that applies after a heal, in one call.
pub fn audit_all(world: World) -> World {
  world
  |> audit_quiescence
  |> audit_delivery
  |> audit_close
  |> audit_release
}

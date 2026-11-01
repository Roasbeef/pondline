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
}

pub type Row {
  Row(envelope: BitArray, queue: BitArray, padded: Padded)
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
    // Committed application messages: identifier and the peer's queue.
    sent_messages: List(#(BitArray, BitArray)),
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
    invitation_file: Option(BitArray),
    violations: List(String),
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

pub fn new(bug: Bug, approval: Approval, budget: Int) -> World {
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
    )

  World(
    suite: fake_suite.suite(),
    bug:,
    approval:,
    budget:,
    now: 1000,
    parties: dict.from_list([#(0, empty), #(1, empty), #(2, empty)]),
    mailbox: dict.new(),
    invitation_file: None,
    violations: [],
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
    Transmit(number, index) -> transmit(world, number, index)
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

/// Everything that reaches a mailbox goes through here, and the check is
/// the invariant "no send before commit": the bytes must equal a row of
/// some committed outbox.
fn wire_send(
  world: World,
  queue: BitArray,
  envelope: BitArray,
  padded: Padded,
) -> World {
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
    // A queue that does not exist drops the send, as a mailbox would.
    Error(Nil) -> world
    Ok(stored) ->
      case list.any(stored, fn(item) { item.envelope == envelope }) {
        True -> world
        False ->
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
          )
      }
  }
}

fn transmit(world: World, number: Int, index: Int) -> World {
  case at(party(world, number).outbox, index) {
    None -> world
    Some(row) -> wire_send(world, row.queue, row.envelope, row.padded)
  }
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
        )
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
  let mine =
    list.fold(handled.records, party(world, number), fn(mine, record) {
      apply_record(mine, record)
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

fn apply_record(mine: Party, record: plan.Record) -> Party {
  case record {
    plan.Outbound(envelope: envelope_id, route: target, padded:, kind:, ..) ->
      Party(
        ..mine,
        outbox: list.append(mine.outbox, [
          Row(
            envelope: id.to_bytes(envelope_id),
            queue: id.to_bytes(target.queue),
            padded:,
          ),
        ]),
        sent_messages: case kind {
          plan.ApplicationOut(message:) ->
            list.append(mine.sent_messages, [
              #(id.to_bytes(message), id.to_bytes(target.queue)),
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
/// own books agree with the delivered rows.
fn check_budget(world: World, number: Int) -> World {
  case relationship(world, number) {
    None -> world
    Some(rel) -> {
      let ready = count_delivered(world, number, plan.Ready)
      let held = count_delivered(world, number, plan.Held)

      case
        ready <= rel.budget.granted
        && ready == rel.budget.used
        && held == list.length(rel.budget.held)
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

/// The steps a schedule may pick from at this point. `choice` varies which
/// rarer steps (destructive operators, crashes, faults, the clock) are
/// offered, so ordinary progress dominates and every fault still occurs.
pub fn enabled(world: World, choice: Int, mode: Mode) -> List(Step) {
  let chaotic = mode == Chaotic
  let destructive = chaotic && int.modulo(choice, 16) == Ok(0)
  let ticking = chaotic && int.modulo(choice, 16) == Ok(1)
  let crashing = int.modulo(choice, 3) == Ok(0)
  let corrupting = int.modulo(choice, 11) == Ok(0)
  let replaying = int.modulo(choice, 13) == Ok(0)
  let raising = int.modulo(choice, 5) == Ok(0)

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

      list.flatten([
        lifecycle(world, number, mine, destructive, raising, crashing, choice),
        list.index_map(mine.outbox, fn(_, index) { Transmit(number, index) }),
        case queued {
          0 -> []
          _ -> [Ack(number)]
        },
        list.flat_map(indices(queued), fn(index) {
          list.flatten([
            [Fetch(number, index, Commit)],
            case crashing {
              True -> [Fetch(number, index, Crash)]
              False -> []
            },
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
  list.fold(picks, world, fn(world, pick) {
    case at(enabled(world, pick.1, mode), pick.0) {
      Some(next) -> step(world, next)
      None -> world
    }
  })
}

/// After a fault-free settle, every committed application message has been
/// delivered to its peer exactly once, stored `Ready` or `Held`, and its
/// receipt has come home exactly once. Records a violation for each that
/// has not. Only meaningful for a world whose relationships were never
/// closed and whose clock never moved (`Benign` schedules).
pub fn audit_delivery(world: World) -> World {
  list.fold([0, 1, 2], world, fn(world, number) {
    let mine = party(world, number)

    list.fold(mine.sent_messages, world, fn(world, sent) {
      let #(message, peer_queue) = sent
      let peers =
        list.filter([0, 1, 2], fn(other) {
          party(world, other).queue == Some(peer_queue)
        })
      let stored = case peers {
        [peer] ->
          list.filter(party(world, peer).delivered, fn(row) {
            row.0 == message && row.1 != plan.Expired
          })
          |> list.length
        _ -> 0
      }
      let receipts =
        list.filter(mine.received_by_peer, fn(other) { other == message })
        |> list.length

      case stored == 1 && receipts == 1 {
        True -> world
        False ->
          note(world, "committed message not delivered and receipted once")
      }
    })
  })
}

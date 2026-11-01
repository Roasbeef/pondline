//// What must be true of the durable state: safety after every step that
//// wrote anything, and liveness after the heal phase.
////
//// The oracle reads `View`s, built from the nodes' committed tables, and
//// `Facts`, what the runner itself did to the world (the lies it told, the
//// ops it ran and how they answered). It never reads a process's memory,
//// so a check that passes says the state on disk is right, which is what a
//// restart resumes from.
////
//// ## Safety, one named check each
////
//// - `budget_books`: each relationship's `used` equals its ready and
////   consumed deliveries, its `held` list equals its held deliveries in
////   order, and `used` never exceeds `granted`.
//// - `rows_decode`: every relationship and offer blob decodes.
//// - `active_only`: a delivery exists only for a relationship that is
////   `Active` or has since closed.
//// - `delivered_once`: one payload tag is delivered at most once per daemon
////   (the schema keeps message ids unique; this catches a message the
////   operator sent twice). A tag whose send answered `Unavailable` and was
////   retried is excused as H4.
//// - `never_resurrected`: the mailbox never stores an envelope it has
////   tombstoned.
////
//// Three more are checked by the runner at the moment a request is
//// written, against the store at that instant: no `Append` whose bytes are
//// not a committed outbox row, no `Ack` of an envelope without a committed
//// `Processed` row, and at most one `Append` per envelope in flight per
//// daemon.
////
//// ## Liveness, after the heal phase
////
//// - `outbox_settled`: every outbox row is `stored`; a `failed` one is
////   allowed only on a relationship that closed on either side, or for an
////   envelope whose response the runner lied about.
//// - `delivered_and_receipted`: every application message a daemon
////   committed is delivered exactly once on the peer's paired relationship
////   and marked `received_by_peer`, unless either side closed.
//// - `queues_drained`: every `processed` row is acknowledged, and the
////   mailbox holds nothing for a queue a live relationship reads.
//// - `offers_opened`: no offer is still `provisioning`.
//// - `pairings_settled`: no relationship is `joining`; one `awaiting` has a
////   peer that is `pending` (an operator decision). A joiner with no peer,
////   on a daemon whose `accept` answered `Unavailable` and was retried, is
////   excused as H4, one per such answer.
//// - `ops_returned`: every operator call returned, and none accepted an
////   input past a limit.
////
//// ## Excuses
////
//// An excuse matches one exact state and is counted, never silent:
////
//// - `h4_retried_send`: a duplicate payload whose send was retried after
////   `Unavailable`.
//// - `h4_retried_accept`: a joiner with no peer, one per retried accept.
//// - `lied_append`: a failed row whose `Append` response was a lie.
//// - `corrupted_fetch`: a message, receipt or handshake lost because a
////   fetch response carrying it was a lie, so the reader dropped and
////   acknowledged what the mailbox held intact.

import core/crypto/suite.{type Suite}
import core/id
import core/relationship
import core/snapshot
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import sim/ops
import sim/tables
import sqlight.{type Connection}

/// One daemon's durable state.
pub type Node {
  Node(
    name: String,
    outbox: List(tables.Outbox),
    processed: List(tables.Processed),
    deliveries: List(tables.Delivery),
    sent: List(tables.Sent),
    offers: List(tables.Offer),
    rows: List(tables.Relationship),
    /// Each relationship row decoded, keyed by contact bytes.
    decoded: Dict(BitArray, relationship.Relationship),
    /// Rows that did not decode, by table and key.
    undecodable: List(String),
  )
}

/// Everything the oracle reads at one instant.
pub type View {
  View(
    a: Node,
    b: Node,
    envelopes: List(tables.Stored),
    tombstones: List(tables.Stored),
  )
}

/// What the runner did that the oracle needs to know.
pub type Facts {
  Facts(
    /// `#(node, envelope)` of every `Append` whose response was a lie.
    lied_appends: Set(#(String, BitArray)),
    /// Payload tags whose send answered `Unavailable` before the end.
    retried_tags: Set(String),
    /// Per daemon, how many `accept` answers were `Unavailable`.
    retried_accepts: Dict(String, Int),
    /// Operator calls that never returned, by op index.
    unfinished: List(Int),
    /// Operator calls that returned something the op did not expect.
    unexpected: List(#(Int, String)),
    /// Every envelope the mailbox has tombstoned so far.
    tombstoned: Set(#(BitArray, BitArray)),
    /// Envelope ids handed to a reader inside a fetch response the runner
    /// lied about.
    corrupted: Set(BitArray),
  )
}

/// A broken property: which check, and a value-free description.
pub type Violation {
  Violation(check: String, detail: String)
}

/// A known policy gap matched exactly and counted.
pub type Excuse {
  Excuse(name: String, detail: String)
}

/// Blobs already decoded, so a check after every write decodes only the
/// rows that changed. Keyed by the blob itself: a blob that decoded once
/// decodes the same way again.
pub opaque type Cache {
  Cache(
    relationships: Dict(BitArray, Result(relationship.Relationship, Nil)),
    offers: Dict(BitArray, Result(Nil, Nil)),
  )
}

/// An empty cache.
///
/// ## Examples
///
/// ```gleam
/// oracle.new_cache()
/// ```
pub fn new_cache() -> Cache {
  Cache(relationships: dict.new(), offers: dict.new())
}

/// Reads one daemon's tables through its keeper connection.
///
/// ## Examples
///
/// ```gleam
/// oracle.read_node("a", keeper, suite, cache)
/// ```
pub fn read_node(
  name: String,
  connection: Connection,
  decoder: Suite,
  cache: Cache,
) -> #(Node, Cache) {
  let rows = tables.relationships(connection)
  let offers = tables.offers(connection)
  let #(cache, pairs) =
    list.map_fold(rows, cache, fn(cache, row) {
      let #(found, cache) = decode_relationship(cache, decoder, row.blob)
      #(cache, #(row, found))
    })
  let #(cache, offer_pairs) =
    list.map_fold(offers, cache, fn(cache, row) {
      let #(good, cache) = decode_offer(cache, decoder, row.blob)
      #(cache, #(row, good))
    })

  let decoded =
    list.filter_map(pairs, fn(pair) {
      result.map({ pair.1 }, fn(found) { #({ pair.0 }.contact, found) })
    })
  let bad_rows =
    list.filter_map(pairs, fn(pair) {
      case pair.1 {
        Ok(_) -> Error(Nil)
        Error(Nil) -> Ok("relationship " <> short({ pair.0 }.contact))
      }
    })
  let bad_offers =
    list.filter_map(offer_pairs, fn(pair) {
      case pair.1 {
        Ok(Nil) -> Error(Nil)
        Error(Nil) -> Ok("offer " <> short({ pair.0 }.invitation))
      }
    })

  let node =
    Node(
      name:,
      outbox: tables.outbox(connection),
      processed: tables.processed(connection),
      deliveries: tables.deliveries(connection),
      sent: tables.sent(connection),
      offers:,
      rows:,
      decoded: dict.from_list(decoded),
      undecodable: list.append(bad_rows, bad_offers),
    )
  #(node, cache)
}

/// A relationship blob decoded, through the cache.
fn decode_relationship(
  cache: Cache,
  decoder: Suite,
  blob: BitArray,
) -> #(Result(relationship.Relationship, Nil), Cache) {
  // A blob seen before is not decoded again.
  case dict.get(cache.relationships, blob) {
    Ok(found) -> #(found, cache)

    Error(Nil) -> {
      let found =
        snapshot.decode_relationship(decoder, blob) |> result.replace_error(Nil)
      #(
        found,
        Cache(
          ..cache,
          relationships: dict.insert(cache.relationships, blob, found),
        ),
      )
    }
  }
}

/// Whether an offer blob decodes, through the cache.
fn decode_offer(
  cache: Cache,
  decoder: Suite,
  blob: BitArray,
) -> #(Result(Nil, Nil), Cache) {
  // A blob seen before is not decoded again.
  case dict.get(cache.offers, blob) {
    Ok(good) -> #(good, cache)

    Error(Nil) -> {
      let good =
        snapshot.decode_offer(decoder, blob)
        |> result.replace(Nil)
        |> result.replace_error(Nil)
      #(good, Cache(..cache, offers: dict.insert(cache.offers, blob, good)))
    }
  }
}

/// The first eight hex digits of some bytes, for details.
///
/// ## Examples
///
/// ```gleam
/// oracle.short(<<1, 2, 3, 4, 5>>)
/// // -> "01020304"
/// ```
pub fn short(bytes: BitArray) -> String {
  bit_array.base16_encode(bytes) |> string.lowercase |> string.slice(0, 8)
}

// ------------------------------------------------------------------ safety

/// Every safety check over one view. The excuses are the H4 duplicates.
///
/// ## Examples
///
/// ```gleam
/// oracle.safety(view, facts)
/// // -> #([], [])
/// ```
pub fn safety(view: View, facts: Facts) -> #(List(Violation), List(Excuse)) {
  let per_node =
    list.flat_map([view.a, view.b], fn(node) {
      list.flatten([budget_books(node), rows_decode(node), active_only(node)])
    })
  let #(duplicates, excused) =
    list.map([view.a, view.b], fn(node) { delivered_once(node, facts) })
    |> list.fold(#([], []), fn(acc, pair) {
      #(list.append(acc.0, pair.0), list.append(acc.1, pair.1))
    })

  #(
    list.flatten([per_node, duplicates, never_resurrected(view, facts)]),
    excused,
  )
}

/// Each relationship's budget agrees with its deliveries.
fn budget_books(node: Node) -> List(Violation) {
  let name = node.name
  let deliveries = node.deliveries

  dict.to_list(node.decoded)
  |> list.flat_map(fn(pair) {
    let #(contact, found) = pair
    let mine = list.filter(deliveries, fn(row) { row.contact == contact })
    let counted =
      list.count(mine, fn(row) {
        row.status == "ready" || row.status == "consumed"
      })
    let held =
      mine
      |> list.filter(fn(row) { row.status == "held" })
      |> list.map(fn(row) { row.message })
    let budget = found.budget
    let listed = list.map(budget.held, id.to_bytes)
    let label = fn() { name <> " " <> short(contact) }

    [
      #(budget.used == counted, fn() {
        label()
        <> " used "
        <> int.to_string(budget.used)
        <> " but "
        <> int.to_string(counted)
        <> " delivered"
      }),
      #(listed == held, fn() {
        label() <> " held list differs from held deliveries"
      }),
      #(budget.used <= budget.granted, fn() {
        label() <> " used more than granted"
      }),
    ]
    |> list.filter_map(fn(claim) {
      // A claim that holds says nothing; its detail is built only if not.
      case claim.0 {
        True -> Error(Nil)
        False -> Ok(Violation(check: "budget_books", detail: { claim.1 }()))
      }
    })
  })
}

/// Every stored blob decodes.
fn rows_decode(node: Node) -> List(Violation) {
  list.map(node.undecodable, fn(what) {
    Violation(check: "rows_decode", detail: node.name <> " " <> what)
  })
}

/// Deliveries exist only for active or closed relationships.
fn active_only(node: Node) -> List(Violation) {
  list.filter_map(node.deliveries, fn(row) {
    let phase =
      list.find(node.rows, fn(found) { found.contact == row.contact })
      |> result.map(fn(found) { found.phase })

    // A missing relationship is as wrong as an unauthorized one.
    case phase {
      Ok("active") | Ok("closed") -> Error(Nil)

      _ ->
        Ok(Violation(
          check: "active_only",
          detail: node.name <> " delivery before the relationship was active",
        ))
    }
  })
}

/// No payload tag is delivered twice on one daemon, unless its send was
/// retried after `Unavailable` (H4).
fn delivered_once(
  node: Node,
  facts: Facts,
) -> #(List(Violation), List(Excuse)) {
  let tags =
    list.filter_map(node.deliveries, fn(row) { ops.tag_of(row.payload) })
  let twice =
    list.group(tags, fn(tag) { tag })
    |> dict.to_list
    |> list.filter(fn(pair) { list.drop(pair.1, 1) != [] })
    |> list.map(fn(pair) { pair.0 })
  let #(excused, failed) =
    list.partition(twice, fn(tag) { set.contains(facts.retried_tags, tag) })

  #(
    list.map(failed, fn(tag) {
      Violation(
        check: "delivered_once",
        detail: node.name <> " received payload " <> tag <> " twice",
      )
    }),
    list.map(excused, fn(tag) {
      Excuse(name: "h4_retried_send", detail: node.name <> " " <> tag)
    }),
  )
}

/// The mailbox never stores an envelope again after tombstoning it.
fn never_resurrected(view: View, facts: Facts) -> List(Violation) {
  list.filter_map(view.envelopes, fn(row) {
    // A stored envelope that was once acknowledged is a resurrection.
    case set.contains(facts.tombstoned, #(row.queue, row.envelope)) {
      True ->
        Ok(Violation(
          check: "never_resurrected",
          detail: "envelope " <> short(row.envelope) <> " stored after its ack",
        ))
      False -> Error(Nil)
    }
  })
}

// ---------------------------------------------------------------- liveness

/// Every liveness check after the heal phase.
///
/// ## Examples
///
/// ```gleam
/// oracle.liveness(view, facts)
/// // -> #([], [])
/// ```
pub fn liveness(view: View, facts: Facts) -> #(List(Violation), List(Excuse)) {
  let pairs = [#(view.a, view.b), #(view.b, view.a)]
  let #(outbox, lied) =
    list.map(pairs, fn(pair) { outbox_settled(pair.0, pair.1, facts) })
    |> merge
  let #(pairing, accepts) =
    list.map(pairs, fn(pair) { pairings_settled(pair.0, pair.1, facts) })
    |> merge
  let #(delivered, corrupted) =
    list.map(pairs, fn(pair) { delivered_and_receipted(pair.0, pair.1, facts) })
    |> merge
  let drained = queues_drained(view)

  #(
    list.flatten([
      outbox,
      delivered,
      drained,
      list.flat_map([view.a, view.b], offers_opened),
      pairing,
      ops_returned(facts),
    ]),
    list.flatten([lied, accepts, corrupted]),
  )
}

/// Concatenates per-node results.
fn merge(
  results: List(#(List(Violation), List(Excuse))),
) -> #(List(Violation), List(Excuse)) {
  list.fold(results, #([], []), fn(acc, pair) {
    #(list.append(acc.0, pair.0), list.append(acc.1, pair.1))
  })
}

/// The relationship on `peer` paired with `contact` on `node`. Pairing is
/// mutual: each sends to the other's inbox. A side with no session yet
/// (joining, or closed) pairs with the one that sends to its inbox. The
/// mutual rule matters when one invitation was redeemed twice: both
/// joiners send to the inviter's queue, but the inviter answers only one.
fn peer_of(node: Node, contact: BitArray, peer: Node) -> Option(BitArray) {
  let mine = dict.get(node.decoded, contact)
  let outbound = result.try(mine, outbound_queue)
  let inbound = result.map(mine, fn(found) { id.to_bytes(found.inbox.queue) })

  dict.to_list(peer.decoded)
  |> list.find(fn(pair) {
    let theirs = pair.1
    let their_inbox = Ok(id.to_bytes(theirs.inbox.queue))
    let their_outbound = outbound_queue(theirs)

    // With a session, my outbound is their inbox and theirs is mine or
    // absent; without one, theirs must be mine.
    case outbound {
      Ok(_) ->
        their_inbox == outbound
        && { their_outbound == inbound || result.is_error(their_outbound) }
      Error(Nil) -> their_outbound == inbound && result.is_ok(inbound)
    }
  })
  |> result.map(fn(pair) { pair.0 })
  |> option.from_result
}

/// The peer's queue a relationship sends to, once it has a session.
fn outbound_queue(found: relationship.Relationship) -> Result(BitArray, Nil) {
  case found.phase {
    relationship.AwaitingAccept(link)
    | relationship.PendingApproval(link)
    | relationship.Active(link) -> Ok(id.to_bytes(link.outbound.queue))
    relationship.Joining(..) | relationship.Closed(_) -> Error(Nil)
  }
}

/// Whether a relationship row is closed.
fn closed(node: Node, contact: BitArray) -> Bool {
  list.any(node.rows, fn(row) {
    row.contact == contact && row.phase == "closed"
  })
}

/// Whether either side of a relationship closed.
fn either_closed(node: Node, contact: BitArray, peer: Node) -> Bool {
  closed(node, contact)
  || case peer_of(node, contact, peer) {
    Some(theirs) -> closed(peer, theirs)
    None -> False
  }
}

/// Every outbox row reached the mailbox.
fn outbox_settled(
  node: Node,
  peer: Node,
  facts: Facts,
) -> #(List(Violation), List(Excuse)) {
  list.fold(node.outbox, #([], []), fn(acc, row) {
    let lied = set.contains(facts.lied_appends, #(node.name, row.envelope))
    let label = node.name <> " " <> row.kind <> " " <> short(row.envelope)

    // A stored row is done; a failed one needs a reason; a queued one is
    // stuck.
    case row.status {
      "stored" -> acc

      "failed" ->
        case either_closed(node, row.contact, peer), lied {
          True, _ -> acc
          False, True -> #(acc.0, [Excuse("lied_append", label), ..acc.1])
          False, False -> #(
            [Violation("outbox_settled", label <> " failed"), ..acc.0],
            acc.1,
          )
        }

      _ -> #(
        [Violation("outbox_settled", label <> " still queued"), ..acc.0],
        acc.1,
      )
    }
  })
}

/// Every committed application message arrived once and was receipted.
/// A message whose envelope, or a receipt from the peer on its
/// relationship, reached its reader inside a fetch response the runner
/// lied about is the `corrupted_fetch` excuse: the reader dropped the
/// altered bytes as undecryptable and acknowledged the envelope, so the
/// mailbox deleted the intact copy.
fn delivered_and_receipted(
  node: Node,
  peer: Node,
  facts: Facts,
) -> #(List(Violation), List(Excuse)) {
  list.fold(node.sent, #([], []), fn(acc, row) {
    let label = node.name <> " message " <> short(row.message)
    let mine =
      list.filter(node.outbox, fn(out) { out.message == Some(row.message) })
    let lied =
      list.any(mine, fn(out) {
        set.contains(facts.lied_appends, #(node.name, out.envelope))
      })
    let corrupted = transit_of(list.map(mine, fn(out) { out.envelope }), facts)

    // A closed side or a lie the runner told excuses the message; anything
    // else must have arrived once and come back as a receipt.
    case either_closed(node, row.contact, peer) || lied {
      True -> acc

      False ->
        case peer_of(node, row.contact, peer) {
          None -> #(
            [
              Violation("delivered_and_receipted", label <> " has no peer"),
              ..acc.0
            ],
            acc.1,
          )

          Some(theirs) -> {
            let copies =
              list.count(peer.deliveries, fn(delivery) {
                delivery.contact == theirs && delivery.message == row.message
              })

            // Exactly one copy, receipted, is the only passing shape.
            case copies, row.state {
              1, "received_by_peer" -> acc

              1, state ->
                excusable(
                  acc,
                  corrupted_on(peer, theirs, facts),
                  "delivered_and_receipted",
                  label <> " delivered but " <> state,
                )

              0, _ ->
                excusable(
                  acc,
                  corrupted,
                  "delivered_and_receipted",
                  label <> " delivered 0 times",
                )

              n, _ -> #(
                [
                  Violation(
                    "delivered_and_receipted",
                    label <> " delivered " <> int.to_string(n) <> " times",
                  ),
                  ..acc.0
                ],
                acc.1,
              )
            }
          }
        }
    }
  })
}

/// Files a finding as the `corrupted_fetch` excuse when `corrupted`, and
/// as a violation of `check` otherwise.
fn excusable(
  acc: #(List(Violation), List(Excuse)),
  transit: Transit,
  check: String,
  detail: String,
) -> #(List(Violation), List(Excuse)) {
  case transit {
    Corrupted -> #(acc.0, [Excuse("corrupted_fetch", detail), ..acc.1])
    Intact -> #([Violation(check, detail), ..acc.0], acc.1)
  }
}

/// Whether something a relationship sent may have been lost in transit to
/// a lie the runner told about a fetch response.
type Transit {
  Intact
  Corrupted
}

/// `Corrupted` when any of `envelopes` was handed to its reader inside a
/// lied-about fetch response.
fn transit_of(envelopes: List(BitArray), facts: Facts) -> Transit {
  let lost =
    list.any(envelopes, fn(envelope) { set.contains(facts.corrupted, envelope) })

  // One lost envelope is enough to explain a missing message.
  case lost {
    True -> Corrupted
    False -> Intact
  }
}

/// Whether any envelope `contact` sent from `node` was corrupted in
/// transit.
fn corrupted_on(node: Node, contact: BitArray, facts: Facts) -> Transit {
  node.outbox
  |> list.filter(fn(out) { out.contact == contact })
  |> list.map(fn(out) { out.envelope })
  |> transit_of(facts)
}

/// `Corrupted` when either is.
fn either(first: Transit, second: fn() -> Transit) -> Transit {
  case first {
    Corrupted -> Corrupted
    Intact -> second()
  }
}

/// Nothing processed is left unacknowledged, on any queue, and the mailbox
/// holds nothing for a queue a live relationship or open offer reads. A
/// queue that retired still has its committed envelopes acknowledged: the
/// fetcher acknowledges before it checks liveness, and the fetch manager
/// gives a retired queue that a restart left owing acknowledgements a
/// fetcher of its own.
fn queues_drained(view: View) -> List(Violation) {
  let live = live_queues(view)
  let unacked =
    list.flat_map([view.a, view.b], fn(node) {
      list.filter_map(node.processed, fn(row) {
        case row.acked {
          1 -> Error(Nil)
          _ ->
            Ok(Violation(
              "queues_drained",
              node.name <> " processed " <> short(row.envelope) <> " unacked",
            ))
        }
      })
    })
  let stuck =
    list.filter_map(view.envelopes, fn(row) {
      case set.contains(live, row.queue) {
        True ->
          Ok(Violation(
            "queues_drained",
            "mailbox still holds " <> short(row.envelope),
          ))
        False -> Error(Nil)
      }
    })

  list.append(unacked, stuck)
}

/// The queues some daemon still reads: live relationships' and open
/// offers' inboxes.
fn live_queues(view: View) -> Set(BitArray) {
  list.flat_map([view.a, view.b], fn(node) {
    let relationships =
      list.filter_map(node.rows, fn(row) {
        case row.phase {
          "closed" -> Error(Nil)
          _ -> Ok(row.inbox_queue)
        }
      })
    let offers =
      list.filter_map(node.offers, fn(row) {
        case row.phase {
          "open" -> Ok(row.inbox_queue)
          _ -> Error(Nil)
        }
      })

    list.append(relationships, offers)
  })
  |> set.from_list
}

/// No offer is left waiting for its queue.
fn offers_opened(node: Node) -> List(Violation) {
  list.filter_map(node.offers, fn(row) {
    case row.phase {
      "provisioning" ->
        Ok(Violation(
          "offers_opened",
          node.name <> " offer " <> short(row.invitation) <> " never opened",
        ))
      _ -> Error(Nil)
    }
  })
}

/// No pairing is stuck on a side that could have moved.
fn pairings_settled(
  node: Node,
  peer: Node,
  facts: Facts,
) -> #(List(Violation), List(Excuse)) {
  let stuck =
    list.filter_map(node.rows, fn(row) {
      let label = node.name <> " " <> short(row.contact)
      let theirs = peer_of(node, row.contact, peer)
      let corrupted =
        either(corrupted_on(node, row.contact, facts), fn() {
          case theirs {
            Some(contact) -> corrupted_on(peer, contact, facts)
            None -> Intact
          }
        })

      // Joining never waits on anyone; awaiting waits only on an operator.
      case row.phase, theirs {
        "joining", _ -> Ok(#(corrupted, Paired, label <> " still joining"))

        "awaiting", Some(contact) ->
          case list.find(peer.rows, fn(r) { r.contact == contact }) {
            Ok(found) if found.phase == "pending" -> Error(Nil)
            _ ->
              Ok(#(
                corrupted,
                Paired,
                label <> " awaiting an accept that never came",
              ))
          }

        "awaiting", None ->
          Ok(#(
            corrupted,
            Unpaired,
            label <> " awaiting with no peer relationship",
          ))

        _, _ -> Error(Nil)
      }
    })
  let #(lost, rest) = list.partition(stuck, fn(entry) { entry.0 == Corrupted })

  // A retried accept leaves at most one joiner per `Unavailable` answer
  // whose `Hello` the inviter dropped as a repeat of the consumed offer: it
  // waits with no peer. Only that shape is excused, one per answer.
  let #(unpaired, paired) =
    list.partition(rest, fn(entry) { entry.1 == Unpaired })
  let allowed = dict.get(facts.retried_accepts, node.name) |> result.unwrap(0)
  let excused = list.take(unpaired, allowed)
  let failed = list.append(paired, list.drop(unpaired, allowed))

  #(
    list.map(failed, fn(entry) { Violation("pairings_settled", entry.2) }),
    list.flatten([
      list.map(excused, fn(entry) { Excuse("h4_retried_accept", entry.2) }),
      list.map(lost, fn(entry) { Excuse("corrupted_fetch", entry.2) }),
    ]),
  )
}

/// Whether a stuck joiner has a peer relationship on the other daemon.
type Pairing {
  Paired
  Unpaired
}

/// Every operator call returned, and none took an input past a limit.
fn ops_returned(facts: Facts) -> List(Violation) {
  let hung =
    list.map(facts.unfinished, fn(index) {
      Violation(
        "ops_returned",
        "op " <> int.to_string(index) <> " never returned",
      )
    })
  let odd =
    list.map(facts.unexpected, fn(pair) {
      Violation(
        "ops_returned",
        "op " <> int.to_string(pair.0) <> ": " <> pair.1,
      )
    })

  list.append(hung, odd)
}

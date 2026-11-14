//// Rendezvous slots at the mailbox (ADR-016): `OpenRendezvous`,
//// `ClaimRendezvous`, `RendezvousSend`, `RendezvousFetch` and
//// `CloseRendezvous` against a real store through `service.serve`, the
//// sweep, the long poll through a running node, and a model-based
//// property over random interleavings.

import core/capability.{type Capability, type Provision}
import core/id.{type Id, type Rendezvous}
import core/limits
import core/mailbox/protocol.{type Response, RendezvousMessage}
import core/nameplate.{type Nameplate}
import core/time.{type Instant, Instant}
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set.{type Set}
import gleam/string
import mailbox/coordinator
import mailbox/mail
import mailbox/node
import mailbox/service
import mailbox/store.{type Store}
import mailbox/support.{cap, now}
import qcheck
import sqlight
import weft/timer

// ------------------------------------------------------------- fixtures

/// The opener's read and append capabilities in every scenario test.
const opener_read = 21

const opener_append = 22

/// The first claimant's pair, and a second would-be claimant's.
const joiner_read = 31

const joiner_append = 32

const late_read = 41

const late_append = 42

fn rid(n: Int) -> Id(Rendezvous) {
  let assert Ok(value) = id.from_bytes(<<n:size(128)>>)
  value
}

fn plate(n: Int) -> Nameplate {
  let assert Ok(value) = nameplate.from_int(n)
  value
}

/// A randomness source that answers each four-byte draw with the next of
/// `values`, and an empty draw once they run out. The values sit in a
/// subject this process owns, and `service.serve` runs in this process.
fn draws(values: List(Int)) -> service.Random {
  let queue = process.new_subject()
  list.each(values, process.send(queue, _))

  fn(bytes) {
    let bits = bytes * 8

    case process.receive(queue, 0) {
      Ok(value) -> <<value:size(bits)>>
      Error(Nil) -> <<>>
    }
  }
}

/// A fresh store with one provisioning grant, both kept for `body`.
fn with_grant(body: fn(Store, Capability(Provision)) -> a) -> a {
  use db, _ <- support.with_store
  let assert Ok(provision) = service.create_grant(db, 5, support.random(77))
  body(db, provision)
}

fn open_with(
  db: Store,
  at: Instant,
  random: service.Random,
  provision: Capability(Provision),
  slot: Int,
  lifetime: Int,
) -> Response {
  service.serve(
    db,
    at,
    random,
    protocol.OpenRendezvous(
      provision:,
      rendezvous: rid(slot),
      read: cap(opener_read),
      append: cap(opener_append),
      lifetime_seconds: lifetime,
    ),
  ).response
}

/// Opens slot `slot` at `now` for the full lifetime under nameplate
/// `drawn`.
fn open(
  db: Store,
  provision: Capability(Provision),
  slot: Int,
  drawn: Int,
) -> Response {
  open_with(db, now, draws([drawn]), provision, slot, limits.rendezvous_seconds)
}

fn claim(
  db: Store,
  at: Instant,
  drawn: Int,
  read: Int,
  append: Int,
) -> Response {
  service.handle(
    db,
    at,
    protocol.ClaimRendezvous(
      nameplate: plate(drawn),
      read: cap(read),
      append: cap(append),
    ),
  )
}

fn send(
  db: Store,
  at: Instant,
  slot: Int,
  append: Int,
  index: Int,
  body: BitArray,
) -> Response {
  service.handle(
    db,
    at,
    protocol.RendezvousSend(
      rendezvous: rid(slot),
      append: cap(append),
      index:,
      body:,
    ),
  )
}

fn fetch(db: Store, at: Instant, slot: Int, read: Int, after: Int) -> Response {
  service.handle(
    db,
    at,
    protocol.RendezvousFetch(
      rendezvous: rid(slot),
      read: cap(read),
      after:,
      wait_seconds: 0,
    ),
  )
}

fn close(db: Store, at: Instant, slot: Int, read: Int) -> Response {
  service.handle(
    db,
    at,
    protocol.CloseRendezvous(rendezvous: rid(slot), read: cap(read)),
  )
}

/// A slot opened at `now` under nameplate 4242 and claimed by the first
/// joiner at `now`.
fn with_claimed_slot(body: fn(Store, Capability(Provision)) -> a) -> a {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)
  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 4242, joiner_read, joiner_append)

  body(db, provision)
}

fn messages(pairs: List(#(Int, BitArray))) -> Response {
  protocol.RendezvousMessages(
    list.map(pairs, fn(pair) { RendezvousMessage(index: pair.0, body: pair.1) }),
  )
}

const unauthorized = protocol.Refused(protocol.Unauthorized)

/// How many rows a raw count query over the store's file returns.
fn count(path: String, statement: String) -> Int {
  let assert Ok(other) = sqlight.open(path)
  let assert Ok([total]) =
    sqlight.query(
      statement,
      on: other,
      with: [],
      expecting: support.first_int(),
    )
  let assert Ok(Nil) = sqlight.close(other)
  total
}

// ----------------------------------------------------------------- open

/// An open answers the drawn nameplate and an expiry of the requested
/// lifetime, which the mailbox clamps to `rendezvous_seconds` and to at
/// least one second.
pub fn an_open_answers_the_drawn_nameplate_and_its_expiry_test() {
  use db, provision <- with_grant

  assert open_with(db, now, draws([482_719]), provision, 1, 90)
    == protocol.RendezvousOpened(plate(482_719), time.add(now, 90))
  assert open_with(db, now, draws([7]), provision, 2, 100_000)
    == protocol.RendezvousOpened(
      plate(7),
      time.add(now, limits.rendezvous_seconds),
    )
  assert open_with(db, now, draws([8]), provision, 3, 0)
    == protocol.RendezvousOpened(plate(8), time.add(now, 1))
}

/// The identical open answers the same nameplate and expiry, later and
/// whatever the randomness says, and opens nothing new.
pub fn an_identical_open_answers_the_same_slot_test() {
  use db, provision <- with_grant

  let first = open_with(db, now, draws([11]), provision, 1, 300)
  let again = open_with(db, time.add(now, 50), draws([12]), provision, 1, 300)

  assert first == protocol.RendezvousOpened(plate(11), time.add(now, 300))
  assert again == first
  assert claim(db, now, 12, joiner_read, joiner_append) == unauthorized
}

/// The same identifier with different capabilities, a different lifetime
/// or another grant is a conflict, and the first slot stands.
pub fn a_changed_open_is_a_conflict_test() {
  use db, provision <- with_grant
  let assert Ok(other_grant) = service.create_grant(db, 5, support.random(78))
  let first = open_with(db, now, draws([11]), provision, 1, 300)

  let changed_read =
    service.serve(
      db,
      now,
      draws([12]),
      protocol.OpenRendezvous(
        provision:,
        rendezvous: rid(1),
        read: cap(99),
        append: cap(opener_append),
        lifetime_seconds: 300,
      ),
    ).response

  assert changed_read == protocol.Refused(protocol.Conflict)
  assert open_with(db, now, draws([13]), provision, 1, 301)
    == protocol.Refused(protocol.Conflict)
  assert open_with(db, now, draws([14]), other_grant, 1, 300)
    == protocol.Refused(protocol.Conflict)
  assert open_with(db, now, draws([15]), provision, 1, 300) == first
}

/// Without a grant there is no open, and the answer does not say whether
/// the identifier is taken.
pub fn an_open_needs_a_provisioning_grant_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 11)

  assert open_with(db, now, draws([12]), cap(5), 1, 300) == unauthorized
  assert open_with(db, now, draws([13]), cap(5), 2, 300) == unauthorized
}

/// One grant holds at most `max_grant_rendezvous` live slots; once one
/// expires, it may open another.
pub fn a_grant_holds_a_bounded_number_of_live_slots_test() {
  use db, provision <- with_grant
  let held = support.upto(1, limits.max_grant_rendezvous)

  list.each(held, fn(n) {
    let assert protocol.RendezvousOpened(..) =
      open_with(db, now, draws([n]), provision, n, 60 * n)
  })

  assert open_with(db, now, draws([100]), provision, 100, 600)
    == protocol.Refused(protocol.QuotaExceeded)

  // The first slot lived 60 seconds, so a minute and one second later the
  // grant has room for one more.
  let later = time.add(now, 61)
  assert open_with(db, later, draws([101]), provision, 101, 600)
    == protocol.RendezvousOpened(plate(101), time.add(later, 600))
}

/// The mailbox holds at most `max_live_rendezvous` live slots across every
/// grant, which is what keeps the nameplate space sparse.
pub fn the_mailbox_holds_a_bounded_number_of_live_slots_test() {
  let path =
    "file:rendezvous_cap_"
    <> int.to_string(support.unique())
    <> "?mode=memory&cache=shared"
  let assert Ok(db) = store.open(path)
  let per_grant = limits.max_grant_rendezvous
  let grants = limits.max_live_rendezvous / per_grant

  list.each(support.upto(1, grants), fn(g) {
    let assert Ok(provision) =
      service.create_grant(db, 1, support.random(1000 + g))

    list.each(support.upto(1, per_grant), fn(k) {
      let n = g * per_grant + k
      let assert protocol.RendezvousOpened(..) =
        open_with(db, now, draws([n]), provision, n, 600)
    })
  })

  let assert Ok(fresh) = service.create_grant(db, 1, support.random(9))
  assert open_with(db, now, draws([999_999]), fresh, 999_999, 600)
    == protocol.Refused(protocol.QuotaExceeded)

  let _ = store.close(db)
}

/// A drawn nameplate a live slot holds is drawn again, as is a draw in the
/// biased tail of the 32-bit range; a source that never produces a free one
/// within the bound answers `Unavailable` and opens nothing.
pub fn a_colliding_nameplate_is_drawn_again_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 5)

  assert open_with(db, now, draws([5, 5, 9]), provision, 2, 600)
    == protocol.RendezvousOpened(plate(9), time.add(now, 600))
  assert open_with(db, now, draws([0xffff_ffff, 17]), provision, 3, 600)
    == protocol.RendezvousOpened(plate(17), time.add(now, 600))

  let stuck = list.repeat(5, service.nameplate_draws + 1)
  assert open_with(db, now, draws(stuck), provision, 4, 600)
    == protocol.Refused(protocol.Unavailable)
  assert open_with(db, now, draws([]), provision, 4, 600)
    == protocol.Refused(protocol.Unavailable)
  assert open_with(db, now, draws([23]), provision, 4, 600)
    == protocol.RendezvousOpened(plate(23), time.add(now, 600))
}

/// A nameplate whose slot has expired is free again, even before a sweep.
pub fn an_expired_slots_nameplate_is_free_again_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) =
    open_with(db, now, draws([5]), provision, 1, 30)

  let later = time.add(now, 31)
  assert open_with(db, later, draws([5]), provision, 2, 600)
    == protocol.RendezvousOpened(plate(5), time.add(later, 600))
}

// ---------------------------------------------------------------- claim

/// A claim binds the joiner and shortens the slot's life to
/// `rendezvous_claimed_seconds` from the claim.
pub fn a_claim_binds_and_shortens_the_expiry_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)
  let at = time.add(now, 10)

  assert claim(db, at, 4242, joiner_read, joiner_append)
    == protocol.RendezvousClaimed(
      rid(1),
      time.add(at, limits.rendezvous_claimed_seconds),
    )
}

/// A claim late in the opening lifetime keeps the earlier expiry.
pub fn a_late_claim_keeps_the_earlier_expiry_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) =
    open_with(db, now, draws([4242]), provision, 1, 60)

  assert claim(db, time.add(now, 10), 4242, joiner_read, joiner_append)
    == protocol.RendezvousClaimed(rid(1), time.add(now, 60))
}

/// The identical claim answers the same again, and the expiry it set is
/// not pushed further out.
pub fn an_identical_claim_answers_the_same_test() {
  use db, _ <- with_claimed_slot
  let expiry = time.add(now, limits.rendezvous_claimed_seconds)

  assert claim(db, time.add(now, 30), 4242, joiner_read, joiner_append)
    == protocol.RendezvousClaimed(rid(1), expiry)
}

/// A different claim on a claimed slot is refused, and the first claim
/// stands: the first joiner still sends and reads, the second cannot.
pub fn the_first_claim_stands_test() {
  use db, _ <- with_claimed_slot

  assert claim(db, now, 4242, late_read, late_append) == unauthorized
  assert claim(db, now, 4242, joiner_read, late_append) == unauthorized
  assert claim(db, now, 4242, late_read, joiner_append) == unauthorized

  assert send(db, now, 1, late_append, 0, <<1>>) == unauthorized
  assert fetch(db, now, 1, late_read, -1) == unauthorized
  assert send(db, now, 1, joiner_append, 0, <<1>>) == protocol.RendezvousSent
  assert fetch(db, now, 1, opener_read, -1) == messages([#(0, <<1>>)])
}

/// An unknown nameplate, an expired slot and a claimed one answer alike.
pub fn unknown_expired_and_claimed_are_indistinguishable_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) =
    open_with(db, now, draws([1]), provision, 1, 30)
  let assert protocol.RendezvousOpened(..) = open(db, provision, 2, 2)
  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 2, joiner_read, joiner_append)
  let later = time.add(now, 31)

  let unknown = claim(db, later, 3, late_read, late_append)
  let expired = claim(db, later, 1, late_read, late_append)
  let taken = claim(db, later, 2, late_read, late_append)

  assert unknown == unauthorized
  assert expired == unknown
  assert taken == unknown
}

/// A claim may not reuse either of the opener's own capabilities: the
/// mailbox would no longer know which side spoke.
pub fn a_claim_with_the_openers_capability_is_refused_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)

  assert claim(db, now, 4242, opener_read, joiner_append) == unauthorized
  assert claim(db, now, 4242, joiner_read, opener_append) == unauthorized
  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 4242, joiner_read, joiner_append)
}

// ----------------------------------------------------------------- send

/// The same index with the same bytes is the same message; different
/// bytes are a conflict, and the first bytes stand.
pub fn a_send_is_idempotent_and_never_replaced_test() {
  use db, _ <- with_claimed_slot

  assert send(db, now, 1, opener_append, 0, <<1, 2>>) == protocol.RendezvousSent
  assert send(db, now, 1, opener_append, 0, <<1, 2>>) == protocol.RendezvousSent
  assert send(db, now, 1, opener_append, 0, <<9>>)
    == protocol.Refused(protocol.Conflict)
  assert fetch(db, now, 1, joiner_read, -1) == messages([#(0, <<1, 2>>)])
}

/// A body over the bound is too large and the largest is stored; an index
/// outside a side's range is over quota.
pub fn a_send_is_bounded_test() {
  use db, _ <- with_claimed_slot
  let largest =
    bit_array.concat(list.repeat(<<7>>, limits.max_rendezvous_body_bytes))
  let over = <<largest:bits, 7>>

  assert send(db, now, 1, opener_append, 0, over)
    == protocol.Refused(protocol.TooLarge)
  assert send(db, now, 1, opener_append, 0, largest) == protocol.RendezvousSent
  assert send(db, now, 1, opener_append, limits.max_rendezvous_messages, <<1>>)
    == protocol.Refused(protocol.QuotaExceeded)
  assert send(db, now, 1, opener_append, -1, <<1>>)
    == protocol.Refused(protocol.QuotaExceeded)
  assert send(db, now, 1, opener_append, limits.max_rendezvous_messages - 1, <<
      1,
    >>)
    == protocol.RendezvousSent
}

/// Only an append capability of one of the two sides sends: a read
/// capability, a stranger's and a missing slot are refused alike.
pub fn only_a_sides_append_capability_sends_test() {
  use db, _ <- with_claimed_slot

  assert send(db, now, 1, opener_read, 0, <<1>>) == unauthorized
  assert send(db, now, 1, joiner_read, 0, <<1>>) == unauthorized
  assert send(db, now, 1, 77, 0, <<1>>) == unauthorized
  assert send(db, now, 2, opener_append, 0, <<1>>) == unauthorized
}

/// The opener may send before anyone has claimed; the claimant reads it
/// after claiming.
pub fn the_opener_may_send_before_the_claim_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)

  assert send(db, now, 1, opener_append, 0, <<5>>) == protocol.RendezvousSent
  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 4242, joiner_read, joiner_append)
  assert fetch(db, now, 1, joiner_read, -1) == messages([#(0, <<5>>)])
}

// ---------------------------------------------------------------- fetch

/// Each side reads only the other side's messages past `after`, in index
/// order whatever order they were sent in.
pub fn a_fetch_returns_the_other_sides_messages_past_after_test() {
  use db, _ <- with_claimed_slot

  let assert protocol.RendezvousSent = send(db, now, 1, opener_append, 2, <<2>>)
  let assert protocol.RendezvousSent = send(db, now, 1, opener_append, 0, <<0>>)
  let assert protocol.RendezvousSent = send(db, now, 1, opener_append, 1, <<1>>)
  let assert protocol.RendezvousSent =
    send(db, now, 1, joiner_append, 0, <<100>>)

  assert fetch(db, now, 1, joiner_read, -1)
    == messages([#(0, <<0>>), #(1, <<1>>), #(2, <<2>>)])
  assert fetch(db, now, 1, joiner_read, 0)
    == messages([#(1, <<1>>), #(2, <<2>>)])
  assert fetch(db, now, 1, joiner_read, 2) == messages([])
  assert fetch(db, now, 1, joiner_read, -50)
    == messages([#(0, <<0>>), #(1, <<1>>), #(2, <<2>>)])
  assert fetch(db, now, 1, opener_read, -1) == messages([#(0, <<100>>)])
}

/// The opener may fetch on a slot nobody has claimed yet, and hears
/// nothing; a stranger, an append capability and a missing slot are
/// refused alike.
pub fn who_may_fetch_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)

  assert fetch(db, now, 1, opener_read, -1) == messages([])
  assert fetch(db, now, 1, opener_append, -1) == unauthorized
  assert fetch(db, now, 1, 77, -1) == unauthorized
  assert fetch(db, now, 2, opener_read, -1) == unauthorized
}

// ---------------------------------------------------------------- close

/// Either side's read capability closes the slot, and with it every
/// message; afterwards the slot answers nobody.
pub fn either_side_closes_the_slot_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 1)
  let assert protocol.RendezvousOpened(..) = open(db, provision, 2, 2)
  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 1, joiner_read, joiner_append)
  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 2, late_read, late_append)
  let assert protocol.RendezvousSent = send(db, now, 1, opener_append, 0, <<1>>)

  assert close(db, now, 1, joiner_append) == unauthorized
  assert close(db, now, 1, 77) == unauthorized
  assert close(db, now, 1, opener_read) == protocol.RendezvousClosed
  assert close(db, now, 2, late_read) == protocol.RendezvousClosed

  assert close(db, now, 1, opener_read) == unauthorized
  assert fetch(db, now, 1, joiner_read, -1) == unauthorized
  assert send(db, now, 2, opener_append, 0, <<1>>) == unauthorized
  assert claim(db, now, 1, 50, 51) == unauthorized
}

/// A close deletes the slot's messages with it.
pub fn a_close_deletes_the_messages_test() {
  use db, path <- support.with_store
  let assert Ok(provision) = service.create_grant(db, 5, support.random(77))
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 1)
  let assert protocol.RendezvousSent = send(db, now, 1, opener_append, 0, <<1>>)

  assert count(path, "SELECT COUNT(*) FROM rendezvous_messages") == 1
  let assert protocol.RendezvousClosed = close(db, now, 1, opener_read)
  assert count(path, "SELECT COUNT(*) FROM rendezvous_messages") == 0
  assert count(path, "SELECT COUNT(*) FROM rendezvous") == 0
}

// --------------------------------------------------------------- expiry

/// A slot is live at its expiry and invisible one second later to every
/// operation, before any sweep; the sweep then deletes it and its messages.
pub fn expiry_hides_a_slot_before_the_sweep_deletes_it_test() {
  use db, path <- support.with_store
  let assert Ok(provision) = service.create_grant(db, 5, support.random(77))
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)
  let assert protocol.RendezvousClaimed(_, expiry) =
    claim(db, now, 4242, joiner_read, joiner_append)
  let assert protocol.RendezvousSent = send(db, now, 1, opener_append, 0, <<1>>)

  // At the expiry itself the slot still answers (`time.is_past`).
  assert fetch(db, expiry, 1, joiner_read, -1) == messages([#(0, <<1>>)])

  let after = time.add(expiry, 1)
  assert claim(db, after, 4242, joiner_read, joiner_append) == unauthorized
  assert send(db, after, 1, opener_append, 0, <<1>>) == unauthorized
  assert send(db, after, 1, joiner_append, 0, <<2>>) == unauthorized
  assert fetch(db, after, 1, joiner_read, -1) == unauthorized
  assert fetch(db, after, 1, opener_read, -1) == unauthorized
  assert close(db, after, 1, opener_read) == unauthorized
  assert count(path, "SELECT COUNT(*) FROM rendezvous") == 1

  let assert Ok(report) = service.sweep(db, after)
  assert report.rendezvous == 1
  assert count(path, "SELECT COUNT(*) FROM rendezvous") == 0
  assert count(path, "SELECT COUNT(*) FROM rendezvous_messages") == 0
}

/// A sweep at the expiry itself leaves the slot alone.
pub fn the_sweep_spares_a_slot_at_its_expiry_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(_, expiry) = open(db, provision, 1, 1)

  let assert Ok(report) = service.sweep(db, expiry)
  assert report.rendezvous == 0
  assert fetch(db, expiry, 1, opener_read, -1) == messages([])
}

// -------------------------------------------------------------- wake-ups

/// A send wakes the reader of the other side, a close wakes both, and a
/// send before anyone has claimed wakes nobody.
pub fn sends_and_closes_name_their_wake_ups_test() {
  use db, provision <- with_grant
  let assert protocol.RendezvousOpened(..) = open(db, provision, 1, 4242)
  let opener_key = service.rendezvous_wake(cap(opener_read))
  let joiner_key = service.rendezvous_wake(cap(joiner_read))
  let serve = fn(request) { service.serve(db, now, draws([]), request) }

  let early =
    serve(protocol.RendezvousSend(rid(1), cap(opener_append), 0, <<1>>))
  assert early.wakes == []

  let assert protocol.RendezvousClaimed(..) =
    claim(db, now, 4242, joiner_read, joiner_append)

  let to_joiner =
    serve(protocol.RendezvousSend(rid(1), cap(opener_append), 1, <<1>>))
  let to_opener =
    serve(protocol.RendezvousSend(rid(1), cap(joiner_append), 0, <<1>>))
  let refused = serve(protocol.RendezvousSend(rid(1), cap(77), 0, <<1>>))
  let closed = serve(protocol.CloseRendezvous(rid(1), cap(joiner_read)))

  assert to_joiner.wakes == [joiner_key]
  assert to_opener.wakes == [opener_key]
  assert refused.wakes == []
  assert closed.wakes == [opener_key, joiner_key]
}

// ------------------------------------------------------------ long poll

/// A node with one grant, and the grant's capability.
fn start_node(
  clock_key: String,
) -> #(node.Node, Capability(Provision), String) {
  let path = support.fresh_path()
  support.set_clock(clock_key, now)

  let assert Ok(#(_, running)) =
    node.start(node.Config(
      path:,
      sweep_period_ms: 60_000,
      clock: fn() { support.read_clock(clock_key) },
      names: node.new_names(),
      timer: timer.WallClock,
      interceptor: None,
      store_faults: None,
    ))
  let assert Ok(Ok(provision)) =
    coordinator.create_grant(
      mail.direct(running.names.coordinator),
      5,
      support.random(31),
      5000,
    )

  #(running, provision, path)
}

/// Opens slot 1 through the node and returns its nameplate.
fn open_on(running: node.Node, provision: Capability(Provision)) -> Nameplate {
  let assert protocol.RendezvousOpened(nameplate:, ..) =
    node.handle(
      running,
      protocol.OpenRendezvous(
        provision:,
        rendezvous: rid(1),
        read: cap(opener_read),
        append: cap(opener_append),
        lifetime_seconds: 600,
      ),
    )
  nameplate
}

fn waiting_fetch(running: node.Node, read: Int, wait: Int) -> Response {
  node.handle(
    running,
    protocol.RendezvousFetch(
      rendezvous: rid(1),
      read: cap(read),
      after: -1,
      wait_seconds: wait,
    ),
  )
}

/// The opener long-polls an unclaimed slot; the joiner's claim and send
/// wake it at once, well inside the wait.
pub fn a_waiting_fetch_wakes_on_the_other_sides_send_test() {
  let #(running, provision, path) = start_node("rendezvous_wake")
  let plate = open_on(running, provision)

  let _ =
    process.spawn(fn() {
      process.sleep(300)
      let assert protocol.RendezvousClaimed(..) =
        node.handle(
          running,
          protocol.ClaimRendezvous(plate, cap(joiner_read), cap(joiner_append)),
        )
      node.handle(
        running,
        protocol.RendezvousSend(rid(1), cap(joiner_append), 0, <<42>>),
      )
    })

  let started = support.monotonic_ms()
  let answer = waiting_fetch(running, opener_read, 10)
  let elapsed = support.monotonic_ms() - started

  assert answer == messages([#(0, <<42>>)])
  assert elapsed >= 250
  assert elapsed < 3000

  support.remove_files(path)
}

/// A long poll that hears nothing answers an empty list when its wait runs
/// out; the waiter's own sends do not wake it.
pub fn a_waiting_fetch_times_out_empty_test() {
  let #(running, provision, path) = start_node("rendezvous_timeout")
  let _ = open_on(running, provision)

  let _ =
    process.spawn(fn() {
      process.sleep(200)
      node.handle(
        running,
        protocol.RendezvousSend(rid(1), cap(opener_append), 0, <<1>>),
      )
    })

  let started = support.monotonic_ms()
  let answer = waiting_fetch(running, opener_read, 1)
  let elapsed = support.monotonic_ms() - started

  assert answer == messages([])
  assert elapsed >= 900
  assert elapsed < 4000

  support.remove_files(path)
}

/// A wrong capability is refused at once, without waiting or registering.
pub fn a_waiting_fetch_with_a_wrong_capability_does_not_wait_test() {
  let #(running, provision, path) = start_node("rendezvous_unauth")
  let _ = open_on(running, provision)

  let started = support.monotonic_ms()
  let answer = waiting_fetch(running, 77, 10)

  assert answer == unauthorized
  assert support.monotonic_ms() - started < 1000

  support.remove_files(path)
}

/// A close by one side ends the other side's wait at once.
pub fn a_close_ends_a_waiting_fetch_test() {
  let #(running, provision, path) = start_node("rendezvous_close")
  let plate = open_on(running, provision)
  let assert protocol.RendezvousClaimed(..) =
    node.handle(
      running,
      protocol.ClaimRendezvous(plate, cap(joiner_read), cap(joiner_append)),
    )

  let _ =
    process.spawn(fn() {
      process.sleep(300)
      node.handle(running, protocol.CloseRendezvous(rid(1), cap(opener_read)))
    })

  let started = support.monotonic_ms()
  let answer = waiting_fetch(running, joiner_read, 10)

  assert answer == unauthorized
  assert support.monotonic_ms() - started < 3000

  support.remove_files(path)
}

// -------------------------------------------------------------- property

/// How many command sequences the interleaving property runs, how long each
/// may be, and the qcheck seed they are drawn from. The seed is fixed so the
/// gate is deterministic; change it in a commit to see another sample.
const interleaving_count = 200

const interleaving_length = 50

const interleaving_seed = 16_016

/// Who presents a capability: a slot's opener, one of three would-be
/// claimants, or a stranger who never opened or claimed anything.
type Actor {
  OpenerOf
  Joiner(party: Int)
  Stranger
}

/// One step of an interleaving. Slots, parties and indices are small
/// integers, so a shrink that deletes the command that opened a slot leaves
/// the rest meaningful.
type Command {
  Open(slot: Int, lifetime: Int)
  Claim(slot: Int, party: Int)
  Send(slot: Int, actor: Actor, index: Int, variant: Int)
  Fetch(slot: Int, actor: Actor, after: Int)
  Close(slot: Int, actor: Actor)
  Advance(seconds: Int)
  Sweep
}

/// What the model knows of one slot.
type Slot {
  Slot(
    nameplate: Nameplate,
    lifetime: Int,
    expires: Int,
    claimant: Option(Int),
    messages: Dict(#(Int, Int), BitArray),
  )
}

/// The model: the clock, the slots the mailbox should hold, and the names
/// of the situations the run has reached (`observe`), which the census
/// test reads.
type Model {
  Model(now: Int, slots: Dict(Int, Slot), seen: Set(String))
}

/// Why an interleaving failed. Each invariant has its own tag, checked
/// before the general comparison with the model.
type Violation {
  ThirdParty(step: Int, command: Command, response: Response)
  OwnSide(step: Int, command: Command, response: Response)
  Bounds(step: Int, detail: String)
  Disagreement(step: Int, command: Command, expected: String, got: Response)
}

/// An actor, with the opener drawn most and the stranger least. Parties 1
/// and 2 are the ones that claim; party 3 never does, so it is always an
/// outsider.
fn actors() -> qcheck.Generator(Actor) {
  qcheck.from_weighted_generators(#(4, qcheck.constant(OpenerOf)), [
    #(3, qcheck.constant(Joiner(1))),
    #(2, qcheck.constant(Joiner(2))),
    #(1, qcheck.constant(Joiner(3))),
    #(1, qcheck.constant(Stranger)),
  ])
}

fn commands() -> qcheck.Generator(Command) {
  let slot = qcheck.bounded_int(0, 1)
  let open = {
    use slot, long <- qcheck.map2(slot, qcheck.bounded_int(0, 1))
    Open(slot:, lifetime: [30, limits.rendezvous_seconds] |> pick(long))
  }
  let claim = {
    use slot, party <- qcheck.map2(slot, qcheck.bounded_int(1, 2))
    Claim(slot:, party:)
  }
  let send = {
    use slot, actor, index, variant <- qcheck.map4(
      slot,
      actors(),
      indices(),
      qcheck.from_weighted_generators(#(3, qcheck.constant(0)), [
        #(2, qcheck.constant(1)),
        #(1, qcheck.constant(2)),
      ]),
    )
    Send(slot:, actor:, index:, variant:)
  }
  let fetch = {
    use slot, actor, after <- qcheck.map3(slot, actors(), afters())
    Fetch(slot:, actor:, after:)
  }
  let close = {
    use slot, actor <- qcheck.map2(slot, actors())
    Close(slot:, actor:)
  }
  // Short steps are common and the step past every lifetime is rare, so a
  // run sees slots expire one at a time more often than all at once.
  let advance =
    qcheck.from_weighted_generators(#(4, qcheck.constant(Advance(1))), [
      #(3, qcheck.constant(Advance(60))),
      #(2, qcheck.constant(Advance(125))),
      #(1, qcheck.constant(Advance(700))),
    ])

  qcheck.from_weighted_generators(#(6, send), [
    #(3, open),
    #(3, claim),
    #(6, fetch),
    #(2, close),
    #(2, advance),
    #(1, qcheck.constant(Sweep)),
  ])
}

/// A fetch's `after`, drawn mostly from the start so fetches return what
/// is there.
fn afters() -> qcheck.Generator(Int) {
  qcheck.from_weighted_generators(#(4, qcheck.constant(-1)), [
    #(2, qcheck.constant(0)),
    #(1, qcheck.bounded_int(1, 2)),
  ])
}

/// A message index, drawn mostly low so two sends often share one, and
/// sometimes just past a side's range.
fn indices() -> qcheck.Generator(Int) {
  qcheck.from_weighted_generators(#(4, qcheck.constant(0)), [
    #(3, qcheck.constant(1)),
    #(1, qcheck.bounded_int(2, limits.max_rendezvous_messages - 1)),
    #(2, qcheck.constant(limits.max_rendezvous_messages)),
  ])
}

fn pick(values: List(Int), index: Int) -> Int {
  let assert [value, ..] = list.drop(values, index) as "index within the list"
  value
}

/// The read and append capability numbers of an actor at a slot. Every
/// slot's opener has its own pair; claimants and the stranger have one pair
/// each across every slot, as a real joiner would.
fn caps_of(slot: Int, actor: Actor) -> #(Int, Int) {
  case actor {
    OpenerOf -> #(100 + slot * 10, 101 + slot * 10)
    Joiner(party) -> #(200 + party * 10, 201 + party * 10)
    Stranger -> #(300, 301)
  }
}

/// Which byte marks a body as sent by this actor.
fn actor_code(actor: Actor) -> Int {
  case actor {
    OpenerOf -> 0
    Joiner(party) -> party
    Stranger -> 9
  }
}

/// A body naming its sender, slot, index and variant; variant 2 is one
/// byte over the bound.
fn body_of(slot: Int, actor: Actor, index: Int, variant: Int) -> BitArray {
  let head = <<actor_code(actor), slot, index, variant>>

  case variant {
    2 ->
      bit_array.concat([
        head,
        bit_array.concat(list.repeat(
          <<0>>,
          limits.max_rendezvous_body_bytes - 3,
        )),
      ])
    _ -> head
  }
}

/// The side an actor speaks for at a live slot, if any: the opener, or the
/// one claimant the slot is bound to.
fn side_of(slot: Slot, actor: Actor) -> Option(Int) {
  case actor, slot.claimant {
    OpenerOf, _ -> Some(0)
    Joiner(party), Some(bound) if party == bound -> Some(1)
    Joiner(_), _ -> None
    Stranger, _ -> None
  }
}

/// The model's live slot, if the slot is live at the model's clock.
fn live(model: Model, slot: Int) -> Option(Slot) {
  case dict.get(model.slots, slot) {
    Ok(found) if found.expires >= model.now -> Some(found)
    Ok(_) | Error(Nil) -> None
  }
}

/// A store for one interleaving, in memory and shared by name so a second
/// connection can count its rows.
fn property_store() -> #(Store, String) {
  let path =
    "file:rendezvous_property_"
    <> int.to_string(support.unique())
    <> "?mode=memory&cache=shared"
  let assert Ok(db) = store.open(path)
  #(db, path)
}

pub fn random_interleavings_keep_the_slot_rules_test() {
  qcheck.default_config()
  |> qcheck.with_test_count(interleaving_count)
  |> qcheck.with_seed(qcheck.seed(interleaving_seed))
  |> qcheck.run(
    qcheck.generic_list(
      elements_from: commands(),
      length_from: qcheck.bounded_int(0, interleaving_length),
    ),
    fn(script) {
      case check_script(with_prelude(script)) {
        Ok(_) -> Nil
        Error(violation) -> panic as string.inspect(violation)
      }
    },
  )
}

/// Every drawn script runs after the same three commands: slot 0 opened
/// for the full lifetime and claimed by party 1, and slot 1 opened for
/// thirty seconds and left unclaimed. A random tail rarely builds a claimed
/// live slot by itself, so without the prelude most runs would test only
/// refusals. The prelude is not drawn, so a shrink never removes it and the
/// tail's slot and party numbers keep their meaning.
fn with_prelude(script: List(Command)) -> List(Command) {
  [
    Open(slot: 0, lifetime: limits.rendezvous_seconds),
    Claim(slot: 0, party: 1),
    Open(slot: 1, lifetime: 30),
    ..script
  ]
}

/// Runs one interleaving against a fresh store and the model side by side,
/// and returns the situations it reached.
fn check_script(script: List(Command)) -> Result(Set(String), Violation) {
  let #(db, path) = property_store()
  let assert Ok(other) = sqlight.open(path)
  let assert Ok(provision) = service.create_grant(db, 5, support.random(77))

  let outcome =
    list.index_fold(
      script,
      Ok(Model(now: 1_000_000, slots: dict.new(), seen: set.new())),
      fn(state, command, step) {
        case state {
          Error(violation) -> Error(violation)
          Ok(model) -> run_step(db, other, provision, model, step, command)
        }
      },
    )

  let _ = sqlight.close(other)
  let _ = store.close(db)

  case outcome {
    Ok(model) -> Ok(model.seen)
    Error(violation) -> Error(violation)
  }
}

/// One command against the store, checked first against the specific
/// rules and then against the model.
fn run_step(
  db: Store,
  other: sqlight.Connection,
  provision: Capability(Provision),
  model: Model,
  step: Int,
  command: Command,
) -> Result(Model, Violation) {
  let at = Instant(model.now)
  let response = apply(db, at, provision, model, step, command)

  use Nil <- result_try(third_party(model, step, command, response))
  use Nil <- result_try(own_side(step, command, response))
  use Nil <- result_try(bounds(other, step))
  use next <- result_try(expect(model, step, command, response))

  let seen =
    observe(model, command, response)
    |> list.fold(next.seen, set.insert)

  Ok(Model(..next, seen:))
}

/// The situations one step reached, named by what the rules are about: a
/// slot opened, repeated, conflicting or replacing an expired one; a first,
/// repeated or refused claim; a send stored, conflicting or out of bounds;
/// a fetch that returned messages, or that ran while the fetcher's own side
/// had messages stored (the case the own-side rule is about); and an
/// outsider refused at a live slot.
fn observe(model: Model, command: Command, response: Response) -> List(String) {
  let state = fn(slot) {
    case dict.get(model.slots, slot), live(model, slot) {
      _, Some(_) -> "live"
      Ok(_), None -> "expired"
      Error(Nil), None -> "absent"
    }
  }
  let side = fn(slot, actor) {
    option.then(live(model, slot), side_of(_, actor))
  }

  case command, response {
    Open(slot:, ..), protocol.RendezvousOpened(..) -> ["open-" <> state(slot)]

    Open(..), protocol.Refused(protocol.Conflict) -> ["open-conflict"]

    Claim(slot:, ..), protocol.RendezvousClaimed(..) ->
      case live(model, slot) {
        Some(Slot(claimant: None, ..)) -> ["claim-first"]
        _ -> ["claim-repeat"]
      }

    Claim(slot:, ..), protocol.Refused(_) -> ["claim-refused-" <> state(slot)]

    Send(..), protocol.RendezvousSent -> ["sent"]

    Send(slot:, actor:, ..), protocol.Refused(reason) ->
      case side(slot, actor), state(slot) {
        None, "live" -> ["outsider-live"]
        _, slot_state -> [
          "send-" <> string.inspect(reason) <> "-" <> slot_state,
        ]
      }

    Fetch(slot:, actor:, ..), protocol.RendezvousMessages(messages) -> {
      let own = case live(model, slot), side(slot, actor) {
        Some(found), Some(mine) ->
          dict.keys(found.messages)
          |> list.any(fn(key) { key.0 == mine })
        _, _ -> False
      }

      case messages, own {
        [_, ..], True -> ["fetch-messages", "fetch-with-own-messages"]
        [_, ..], False -> ["fetch-messages"]
        [], True -> ["fetch-with-own-messages"]
        [], False -> ["fetch-empty"]
      }
    }

    Fetch(slot:, actor:, ..), protocol.Refused(_)
    | Close(slot:, actor:), protocol.Refused(_)
    ->
      case side(slot, actor), state(slot) {
        None, "live" -> ["outsider-live"]
        _, slot_state -> ["refused-" <> slot_state]
      }

    Close(..), protocol.RendezvousClosed -> ["closed"]

    _, _ -> []
  }
}

fn result_try(
  result: Result(a, Violation),
  then: fn(a) -> Result(Model, Violation),
) -> Result(Model, Violation) {
  case result {
    Ok(value) -> then(value)
    Error(violation) -> Error(violation)
  }
}

/// Sends one command to the store and returns its answer. A sweep and a
/// clock advance answer `RendezvousClosed` as a placeholder, which the
/// model expects for them.
fn apply(
  db: Store,
  at: Instant,
  provision: Capability(Provision),
  model: Model,
  step: Int,
  command: Command,
) -> Response {
  case command {
    Open(slot:, lifetime:) -> {
      let #(read, append) = caps_of(slot, OpenerOf)
      service.serve(
        db,
        at,
        support.random(step * 7919 % 500_000),
        protocol.OpenRendezvous(
          provision:,
          rendezvous: rid(slot),
          read: cap(read),
          append: cap(append),
          lifetime_seconds: lifetime,
        ),
      ).response
    }

    Claim(slot:, party:) -> {
      let #(read, append) = caps_of(slot, Joiner(party))
      let target = case dict.get(model.slots, slot) {
        Ok(known) -> known.nameplate
        Error(Nil) -> plate(999_000 + slot)
      }
      service.handle(
        db,
        at,
        protocol.ClaimRendezvous(target, cap(read), cap(append)),
      )
    }

    Send(slot:, actor:, index:, variant:) -> {
      let #(_, append) = caps_of(slot, actor)
      send(db, at, slot, append, index, body_of(slot, actor, index, variant))
    }

    Fetch(slot:, actor:, after:) -> {
      let #(read, _) = caps_of(slot, actor)
      fetch(db, at, slot, read, after)
    }

    Close(slot:, actor:) -> {
      let #(read, _) = caps_of(slot, actor)
      close(db, at, slot, read)
    }

    Advance(..) -> protocol.RendezvousClosed

    Sweep -> {
      let assert Ok(_) = service.sweep(db, at)
      protocol.RendezvousClosed
    }
  }
}

/// A stranger, and a joiner the slot is not bound to, are refused every
/// send, fetch and close.
fn third_party(
  model: Model,
  step: Int,
  command: Command,
  response: Response,
) -> Result(Nil, Violation) {
  let actor = case command {
    Send(slot:, actor:, ..) | Fetch(slot:, actor:, ..) | Close(slot:, actor:) ->
      Some(#(slot, actor))
    Open(..) | Claim(..) | Advance(..) | Sweep -> None
  }

  let outsider = case actor {
    Some(#(_, Stranger)) -> True
    Some(#(slot, Joiner(party))) ->
      case live(model, slot) {
        Some(found) -> found.claimant != Some(party)
        None -> True
      }
    Some(#(_, OpenerOf)) | None -> False
  }

  case outsider, response {
    True, protocol.Refused(protocol.Unauthorized) | False, _ -> Ok(Nil)
    True, _ -> Error(ThirdParty(step:, command:, response:))
  }
}

/// A fetch never returns a message its own side sent.
fn own_side(
  step: Int,
  command: Command,
  response: Response,
) -> Result(Nil, Violation) {
  case command, response {
    Fetch(actor:, ..), protocol.RendezvousMessages(messages:) -> {
      let mine =
        list.any(messages, fn(message) {
          case message.body {
            <<code, _:bits>> -> code == actor_code(actor)
            _ -> False
          }
        })
      case mine {
        True -> Error(OwnSide(step:, command:, response:))
        False -> Ok(Nil)
      }
    }

    _, _ -> Ok(Nil)
  }
}

/// No side of any slot holds more than `max_rendezvous_messages` messages,
/// an index outside them, or a body over the bound.
fn bounds(other: sqlight.Connection, step: Int) -> Result(Nil, Violation) {
  let statement =
    "SELECT COALESCE(MAX(n), 0) FROM (SELECT COUNT(*) AS n FROM rendezvous_messages GROUP BY rendezvous_id, side)"
  let assert Ok([most]) =
    sqlight.query(
      statement,
      on: other,
      with: [],
      expecting: support.first_int(),
    )
  let assert Ok([outside]) =
    sqlight.query(
      "SELECT COUNT(*) FROM rendezvous_messages WHERE message_index < 0 OR message_index >= ?1 OR length(body) > ?2",
      on: other,
      with: [
        sqlight.int(limits.max_rendezvous_messages),
        sqlight.int(limits.max_rendezvous_body_bytes),
      ],
      expecting: support.first_int(),
    )

  case most <= limits.max_rendezvous_messages && outside == 0 {
    True -> Ok(Nil)
    False ->
      Error(Bounds(
        step:,
        detail: "most "
          <> int.to_string(most)
          <> ", outside "
          <> int.to_string(outside),
      ))
  }
}

/// The model's answer to a command, compared with the store's, and the
/// model after it.
fn expect(
  model: Model,
  step: Int,
  command: Command,
  response: Response,
) -> Result(Model, Violation) {
  let disagree = fn(expected: String) {
    Error(Disagreement(step:, command:, expected:, got: response))
  }

  case command {
    Advance(seconds:) -> Ok(Model(..model, now: model.now + seconds))

    Sweep ->
      Ok(
        Model(
          ..model,
          slots: dict.filter(model.slots, fn(_, slot) {
            slot.expires >= model.now
          }),
        ),
      )

    Open(slot:, lifetime:) ->
      case live(model, slot), response {
        Some(found), protocol.RendezvousOpened(nameplate:, expires_at:)
          if found.lifetime == lifetime
        ->
          case
            nameplate == found.nameplate
            && expires_at.unix_seconds == found.expires
          {
            True -> Ok(model)
            False -> disagree("the same slot again")
          }

        Some(found), protocol.Refused(protocol.Conflict)
          if found.lifetime != lifetime
        -> Ok(model)

        None, protocol.RendezvousOpened(nameplate:, expires_at:) ->
          case expires_at.unix_seconds == model.now + lifetime {
            True ->
              Ok(
                Model(
                  ..model,
                  slots: dict.insert(
                    model.slots,
                    slot,
                    Slot(
                      nameplate:,
                      lifetime:,
                      expires: expires_at.unix_seconds,
                      claimant: None,
                      messages: dict.new(),
                    ),
                  ),
                ),
              )
            False -> disagree("a new slot")
          }

        _, _ -> disagree("an open")
      }

    Claim(slot:, party:) ->
      case live(model, slot), response {
        Some(found), protocol.RendezvousClaimed(rendezvous:, expires_at:)
          if found.claimant == None
        -> {
          let shortened =
            int.min(
              found.expires,
              model.now + limits.rendezvous_claimed_seconds,
            )
          case rendezvous == rid(slot) && expires_at.unix_seconds == shortened {
            True ->
              Ok(
                Model(
                  ..model,
                  slots: dict.insert(
                    model.slots,
                    slot,
                    Slot(..found, claimant: Some(party), expires: shortened),
                  ),
                ),
              )
            False -> disagree("the first claim")
          }
        }

        Some(found), protocol.RendezvousClaimed(rendezvous:, expires_at:)
          if found.claimant == Some(party)
        ->
          case
            rendezvous == rid(slot) && expires_at.unix_seconds == found.expires
          {
            True -> Ok(model)
            False -> disagree("the same claim again")
          }

        Some(found), protocol.Refused(protocol.Unauthorized)
          if found.claimant != None && found.claimant != Some(party)
        -> Ok(model)

        None, protocol.Refused(protocol.Unauthorized) -> Ok(model)

        _, _ -> disagree("a claim")
      }

    Send(slot:, actor:, index:, variant:) -> {
      let side = option.then(live(model, slot), side_of(_, actor))
      let body = body_of(slot, actor, index, variant)

      case live(model, slot), side {
        Some(found), Some(side) -> {
          let wanted = case
            bit_array.byte_size(body) > limits.max_rendezvous_body_bytes,
            index >= limits.max_rendezvous_messages,
            dict.get(found.messages, #(side, index))
          {
            True, _, _ -> protocol.Refused(protocol.TooLarge)
            False, True, _ -> protocol.Refused(protocol.QuotaExceeded)
            False, False, Ok(known) if known == body -> protocol.RendezvousSent
            False, False, Ok(_) -> protocol.Refused(protocol.Conflict)
            False, False, Error(Nil) -> protocol.RendezvousSent
          }

          case response == wanted, wanted {
            True, protocol.RendezvousSent ->
              Ok(
                Model(
                  ..model,
                  slots: dict.insert(
                    model.slots,
                    slot,
                    Slot(
                      ..found,
                      messages: dict.insert(
                        found.messages,
                        #(side, index),
                        body,
                      ),
                    ),
                  ),
                ),
              )
            True, _ -> Ok(model)
            False, _ -> disagree(string.inspect(wanted))
          }
        }

        _, _ ->
          case response == unauthorized {
            True -> Ok(model)
            False -> disagree("an unauthorized send")
          }
      }
    }

    Fetch(slot:, actor:, after:) -> {
      let wanted = case live(model, slot) {
        Some(found) ->
          case side_of(found, actor) {
            Some(side) ->
              found.messages
              |> dict.to_list
              |> list.filter(fn(entry) {
                entry.0.0 == 1 - side && entry.0.1 > after
              })
              |> list.sort(fn(a, b) { int.compare(a.0.1, b.0.1) })
              |> list.map(fn(entry) {
                RendezvousMessage(index: entry.0.1, body: entry.1)
              })
              |> protocol.RendezvousMessages
            None -> unauthorized
          }
        None -> unauthorized
      }

      case response == wanted {
        True -> Ok(model)
        False -> disagree(string.inspect(wanted))
      }
    }

    Close(slot:, actor:) ->
      case option.then(live(model, slot), side_of(_, actor)), response {
        Some(_), protocol.RendezvousClosed ->
          Ok(Model(..model, slots: dict.delete(model.slots, slot)))
        None, protocol.Refused(protocol.Unauthorized) -> Ok(model)
        _, _ -> disagree("a close")
      }
  }
}

/// The generator reaches every command kind, every actor kind, both
/// lifetimes and the out-of-range index, so the property is about them.
pub fn the_interleaving_generator_reaches_every_case_test() {
  let #(drawn, _) =
    qcheck.generate(commands(), 2000, qcheck.seed(interleaving_seed))

  let kinds =
    list.map(drawn, fn(command) {
      case command {
        Open(lifetime: 30, ..) -> "open-short"
        Open(..) -> "open-long"
        Claim(..) -> "claim"
        Send(index:, ..) if index == limits.max_rendezvous_messages ->
          "send-out-of-range"
        Send(variant: 2, ..) -> "send-oversized"
        Send(actor: Stranger, ..) -> "send-stranger"
        Send(..) -> "send"
        Fetch(actor: Joiner(_), ..) -> "fetch-joiner"
        Fetch(..) -> "fetch"
        Close(..) -> "close"
        Advance(..) -> "advance"
        Sweep -> "sweep"
      }
    })
    |> list.unique
    |> list.sort(string.compare)

  assert kinds
    == [
      "advance", "claim", "close", "fetch", "fetch-joiner", "open-long",
      "open-short", "send", "send-out-of-range", "send-oversized",
      "send-stranger", "sweep",
    ]
}

/// The scripts the property draws reach every situation its rules are
/// about. A generator that stopped producing one would not fail the
/// property; it would stop testing that rule.
pub fn the_interleavings_reach_every_situation_test() {
  let #(scripts, _) =
    qcheck.generate(
      qcheck.generic_list(
        elements_from: commands(),
        length_from: qcheck.bounded_int(0, interleaving_length),
      ),
      interleaving_count,
      qcheck.seed(interleaving_seed),
    )

  let reached =
    list.fold(scripts, set.new(), fn(seen, script) {
      let assert Ok(more) = check_script(with_prelude(script))
      set.union(seen, more)
    })

  let wanted = [
    "claim-first", "claim-refused-live", "claim-refused-expired", "claim-repeat",
    "closed", "fetch-messages", "fetch-with-own-messages", "open-absent",
    "open-conflict", "open-expired", "open-live", "outsider-live",
    "send-Conflict-live", "send-QuotaExceeded-live", "send-TooLarge-live",
    "send-Unauthorized-expired", "sent",
  ]

  assert list.filter(wanted, fn(name) { !set.contains(reached, name) }) == []
}

/// A whole exchange in the order ADR-016 runs it, which a property run
/// must also be able to reach: the interleaving model agrees with it.
pub fn the_model_agrees_with_a_whole_exchange_test() {
  let script = [
    Open(slot: 0, lifetime: limits.rendezvous_seconds),
    Fetch(slot: 0, actor: OpenerOf, after: -1),
    Claim(slot: 0, party: 1),
    Send(slot: 0, actor: Joiner(1), index: 0, variant: 0),
    Fetch(slot: 0, actor: OpenerOf, after: -1),
    Send(slot: 0, actor: OpenerOf, index: 0, variant: 0),
    Send(slot: 0, actor: Joiner(1), index: 1, variant: 0),
    Send(slot: 0, actor: OpenerOf, index: 1, variant: 1),
    Fetch(slot: 0, actor: Joiner(1), after: -1),
    Claim(slot: 0, party: 2),
    Fetch(slot: 0, actor: Joiner(2), after: -1),
    Close(slot: 0, actor: Joiner(1)),
    Fetch(slot: 0, actor: OpenerOf, after: -1),
    Advance(seconds: 700),
    Sweep,
  ]

  let assert Ok(_) = check_script(script)
  Nil
}

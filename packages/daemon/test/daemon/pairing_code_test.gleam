//// Pairing by spoken code (ADR-016), between real daemons and a real
//// mailbox over loopback: the honest pairing, then each way a run can end
//// without pairing, told apart on both sides with the durable count of
//// failed confirmations; a stranger who claims first; the cap on failures
//// and its window; and a daemon restarted mid-run.

import core/capability
import core/endpoint
import core/id.{type Id, type Rendezvous}
import core/limits
import core/mailbox/protocol.{RendezvousMessage}
import core/offer
import core/pairing_code
import core/rendezvous
import core/secret.{type Secret}
import daemon/api
import daemon/config
import daemon/engine
import daemon/mailbox_client
import daemon/node
import daemon/support
import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import primitives/suite as primitive_suite
import simplifile
import sqlight

// ------------------------------------------------------------- fixtures

fn text(code: Secret) -> String {
  let assert Ok(text) = bit_array.to_string(secret.expose(code))
  text
}

/// The code with its last word replaced by another word on the list: one
/// word misheard.
fn misheard(code: Secret) -> Secret {
  let assert [plate, first, second, third] = string.split(text(code), "-")
  let other = case third {
    "abandon" -> "ability"
    _ -> "abandon"
  }

  secret.new(<<plate:utf8, "-", first:utf8, "-", second:utf8, "-", other:utf8>>)
}

/// The text a daemon's failure count is kept under for a mailbox.
fn endpoint_text(mailbox: support.Mailbox) -> String {
  let assert Ok(port) = endpoint.port(mailbox.port)
  endpoint.to_string(endpoint.Loopback(port))
}

fn failures(daemon: api.Daemon, mailbox: support.Mailbox) -> Int {
  let assert Ok(count) =
    engine.rendezvous_failures(
      api.engine_handle(daemon),
      endpoint_text(mailbox),
    )
  count
}

/// How many rows a table of a SQLite file holds.
fn rows(path: String, table: String) -> Int {
  let assert Ok(connection) = sqlight.open(path)
  let assert Ok(Nil) = sqlight.exec("PRAGMA busy_timeout=5000", connection)
  let assert Ok([count]) =
    sqlight.query(
      "SELECT COUNT(*) FROM " <> table,
      on: connection,
      with: [],
      expecting: decode.field(0, decode.int, decode.success),
    )
  let assert Ok(Nil) = sqlight.close(connection)
  count
}

fn active(daemon: api.Daemon) -> Id(id.Contact) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    case list.find(views, fn(view) { view.phase == api.Active }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

/// One call to the mailbox from outside any daemon, as a stranger makes it.
fn raw(
  mailbox: support.Mailbox,
  request: protocol.Request,
) -> protocol.Response {
  let assert Ok(port) = endpoint.port(mailbox.port)
  let assert Ok(response) =
    mailbox_client.call(
      support.loopback_dialer(),
      endpoint.Loopback(port),
      "stranger",
      request,
      30_000,
    )
  response
}

fn capability(n: Int) -> capability.Capability(a) {
  let assert Ok(made) = capability.from_bytes(<<n:256>>)
  made
}

/// Claims the slot `code` names with a stranger's own capabilities.
fn claim_as_stranger(mailbox: support.Mailbox, code: Secret) -> Id(Rendezvous) {
  let assert Ok(parsed) = pairing_code.decode(text(code))
  let assert protocol.RendezvousClaimed(rendezvous:, ..) =
    raw(
      mailbox,
      protocol.ClaimRendezvous(
        nameplate: pairing_code.nameplate(parsed),
        read: capability(901),
        append: capability(902),
      ),
    )
  rendezvous
}

// ---------------------------------------------------------------- paired

/// The whole path a spoken code stands for: the inviter prints a code with
/// its ticket already stored, the joiner pairs with it, both relationships
/// become active and a message crosses, as a ticket's would. The inviter
/// reports paired, nothing is counted, and the slot is gone.
pub fn a_spoken_code_pairs_two_daemons_and_a_message_crosses_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(invited) = api.invite_code(a, "by voice", offer.AutoApprove, 5)

  // The code is handed out only once the ticket's blob is stored and the
  // slot is open, so the ticket exists before any message can be read.
  assert rows(mailbox.path, "blobs") == 1
  assert rows(mailbox.path, "rendezvous") == 1
  let assert Ok(_) = pairing_code.decode(text(invited.code))

  // A typed code arrives with its newline; the CLI trims it, so here it is
  // exact.
  let assert Ok(api.Paired(contact: Some(at_b))) =
    api.accept_code(b, invited.code, None, "inviter", None)
  assert api.await_code(a, invited.run) == Ok(api.Paired(contact: None))

  let at_a = active(a)
  assert active(b) == at_b

  let assert Ok(sent) =
    api.send(a, at_a, "text/plain", secret.new(<<"hi":utf8>>), None)
  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [first, ..] -> Some(first)
      }
    })
  assert delivered.message == sent

  assert rows(mailbox.path, "rendezvous") == 0
  assert rows(mailbox.path, "rendezvous_messages") == 0
  assert failures(a, mailbox) == 0
  assert failures(b, mailbox) == 0

  let _ = node.stop(a)
  let _ = node.stop(b)
}

// --------------------------------------------------------------- endings

/// One misheard word: the inviter's check fails and it sends nothing, the
/// joiner's confirmation goes unanswered, and each side counts one failed
/// confirmation at the mailbox. Nobody pairs and the slot is gone.
pub fn one_wrong_word_fails_and_counts_on_both_sides_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(invited) = api.invite_code(a, "misheard", offer.AutoApprove, 5)

  assert api.accept_code(b, misheard(invited.code), None, "x", None)
    == Ok(api.ConfirmationFailed)
  assert api.await_code(a, invited.run) == Ok(api.ConfirmationFailed)

  assert failures(a, mailbox) == 1
  assert failures(b, mailbox) == 1
  assert api.contacts(b) == Ok([])
  assert rows(mailbox.path, "rendezvous") == 0

  let _ = node.stop(a)
  let _ = node.stop(b)
}

/// A code nobody uses ends never claimed once its slot expires by the
/// mailbox's clock, and costs nothing.
pub fn a_code_nobody_claims_ends_never_claimed_test() {
  let shift = support.fresh("never_claimed")
  let mailbox = support.start_mailbox_on(support.shiftable_clock(shift))
  let #(a, _) = support.start_daemon(mailbox)

  let assert Ok(invited) = api.invite_code(a, "unused", offer.AutoApprove, 5)
  support.shift_clock(shift, limits.rendezvous_seconds + 1)

  assert api.await_code(a, invited.run) == Ok(api.NeverClaimed)
  assert failures(a, mailbox) == 0

  let _ = node.stop(a)
}

/// A joiner that claims, sends its first message and then goes silent
/// stalls the inviter when the claimed slot expires: the inviter answered
/// and never saw a confirmation, so nothing is counted.
pub fn a_joiner_that_stops_stalls_the_inviter_test() {
  let shift = support.fresh("stalled")
  let mailbox = support.start_mailbox_on(support.shiftable_clock(shift))
  let #(a, _) = support.start_daemon(mailbox)
  let suite = primitive_suite.suite()

  let assert Ok(invited) = api.invite_code(a, "stalls", offer.AutoApprove, 5)
  let assert Ok(code) = pairing_code.decode(text(invited.code))
  let run = claim_as_stranger(mailbox, invited.code)

  let assert Ok(#(_, m1)) = rendezvous.join(suite, code, run)
  assert raw(mailbox, protocol.RendezvousSend(run, capability(902), 0, m1))
    == protocol.RendezvousSent

  // The inviter's answer arrives, and then the joiner says nothing more.
  let assert protocol.RendezvousMessages([RendezvousMessage(index: 0, ..)]) =
    raw(mailbox, protocol.RendezvousFetch(run, capability(901), -1, 25))
  support.shift_clock(shift, limits.rendezvous_claimed_seconds + 1)

  assert api.await_code(a, invited.run) == Ok(api.Stalled)
  assert failures(a, mailbox) == 0

  let _ = node.stop(a)
}

/// A stranger who learns the nameplate and claims first spends the code.
/// The real joiner's claim is refused, plainly and at no cost, because the
/// first claim stands. The stranger's guess at the words fails the
/// inviter's check, which the inviter counts.
pub fn a_stranger_who_claims_first_spends_the_code_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)
  let suite = primitive_suite.suite()

  let assert Ok(invited) = api.invite_code(a, "guessed", offer.AutoApprove, 5)
  let run = claim_as_stranger(mailbox, invited.code)

  assert api.accept_code(b, invited.code, None, "x", None)
    == Error(api.Refused(
      "no code is open under that nameplate at the rendezvous; it may have expired or been used",
    ))
  assert failures(b, mailbox) == 0

  // The stranger runs the joiner's half with words of its own.
  let assert Ok(guess) = pairing_code.decode(text(misheard(invited.code)))
  let assert Ok(#(sent, m1)) = rendezvous.join(suite, guess, run)
  assert raw(mailbox, protocol.RendezvousSend(run, capability(902), 0, m1))
    == protocol.RendezvousSent
  let assert protocol.RendezvousMessages([RendezvousMessage(index: 0, body: m2)]) =
    raw(mailbox, protocol.RendezvousFetch(run, capability(901), -1, 25))
  let assert Ok(#(_, m3)) = rendezvous.joiner_confirm(suite, sent, m2)
  assert raw(mailbox, protocol.RendezvousSend(run, capability(902), 1, m3))
    == protocol.RendezvousSent

  assert api.await_code(a, invited.run) == Ok(api.ConfirmationFailed)
  assert failures(a, mailbox) == 1
  assert rows(mailbox.path, "rendezvous") == 0

  let _ = node.stop(a)
  let _ = node.stop(b)
}

// -------------------------------------------------------------------- cap

/// The refusal past the cap, which sends the operator to a ticket.
const capped =
  api.Refused(
    "too many pairing codes failed at this rendezvous recently; pair with a ticket instead (invite create --ticket) and compare fingerprints",
  )

/// Failures recorded longer ago than the window do not count, and are
/// pruned when the next is recorded. Once `limits.max_rendezvous_failures`
/// fall inside the window, the daemon refuses codes at that endpoint both
/// to invite and to join, before anything is minted or claimed, while
/// another endpoint is unaffected.
pub fn failures_past_the_cap_refuse_codes_at_that_endpoint_test() {
  let shift = support.fresh("cap")
  let mailbox = support.start_mailbox()
  let other = support.start_mailbox()
  let directory = support.fresh("cap_state")
  let settings =
    config.Config(
      ..support.daemon_config(mailbox, directory),
      clock: support.shiftable_clock(shift),
    )
  let assert Ok(a) = node.start(settings)
  let at = endpoint_text(mailbox)
  let record = fn() {
    let assert Ok(Nil) =
      engine.record_rendezvous_failure(api.engine_handle(a), at)
    Nil
  }

  // A full cap's worth, all of it older than the window.
  support.shift_clock(shift, 0 - limits.rendezvous_failure_window_seconds - 1)
  list.each(list.repeat(Nil, limits.max_rendezvous_failures), fn(_) { record() })
  support.shift_clock(shift, 0)

  assert failures(a, mailbox) == 0
  let assert Ok(fresh) =
    api.invite_code(a, "still allowed", offer.AutoApprove, 5)

  // Recording one now prunes the old ones; then the cap is reached.
  record()
  assert rows(directory <> "/daemon.db", "rendezvous_failures") == 1
  list.each(list.repeat(Nil, limits.max_rendezvous_failures - 1), fn(_) {
    record()
  })
  assert failures(a, mailbox) == limits.max_rendezvous_failures

  let blobs = rows(mailbox.path, "blobs")
  assert api.invite_code(a, "refused", offer.AutoApprove, 5) == Error(capped)
  assert rows(mailbox.path, "blobs") == blobs
  assert api.accept_code(a, fresh.code, None, "x", None) == Error(capped)

  // Another rendezvous is counted apart: the joiner goes on to claim there,
  // and is refused only because no such code is open there.
  assert api.accept_code(a, fresh.code, Some(endpoint_text(other)), "x", None)
    == Error(api.Refused(
      "no code is open under that nameplate at the rendezvous; it may have expired or been used",
    ))

  let _ = node.stop(a)
}

// ----------------------------------------------------------------- restart

/// A daemon stopped mid-run loses the run: after a restart the run is
/// unknown, the store holds no rendezvous rows but the failure count, and
/// nothing in the database's files spells the code or its words.
pub fn a_restart_mid_run_leaves_nothing_of_the_run_test() {
  let mailbox = support.start_mailbox()
  let #(a, settings) = support.start_daemon(mailbox)

  let assert Ok(invited) = api.invite_code(a, "restarted", offer.AutoApprove, 5)
  let _ = node.stop(a)
  let assert Ok(again) = node.start(settings)

  assert api.await_code(again, invited.run) == Error(api.NotFound)
  let database = settings.state_dir <> "/daemon.db"
  assert rows(database, "rendezvous_failures") == 0

  let spelled = text(invited.code)
  let assert [_, ..words] = string.split(spelled, "-")
  let needles = [
    spelled,
    string.join(words, "-"),
    ..list.filter(words, fn(word) { string.length(word) >= 4 })
  ]

  list.each([database, database <> "-wal"], fn(path) {
    case simplifile.read_bits(path) {
      Ok(bytes) ->
        list.each(needles, fn(needle) {
          assert !bit_array_contains(bytes, <<needle:utf8>>)
        })
      Error(_) -> Nil
    }
  })

  let _ = node.stop(again)
}

/// Whether `haystack` holds `needle` anywhere, byte for byte.
fn bit_array_contains(haystack: BitArray, needle: BitArray) -> Bool {
  let size = bit_array.byte_size(needle)

  case haystack {
    <<prefix:bytes-size(size), _:bytes>> if prefix == needle -> True
    <<_, rest:bytes>> -> bit_array_contains(rest, needle)
    _ -> False
  }
}

/// The search the restart test relies on finds a word inside other bytes
/// and nothing that is only a prefix of it. Words of three letters are left
/// out of that search, because a random key holds any given three bytes too
/// often; the full code and the joined words are always searched.
pub fn the_store_search_finds_what_it_looks_for_test() {
  assert bit_array_contains(<<"xxcradle-noble">>, <<"cradle">>)
  assert !bit_array_contains(<<"cradl">>, <<"cradle">>)
}

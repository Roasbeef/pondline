//// Pairing by spoken code (ADR-016): the two run drivers, and the process
//// that keeps an inviter's run alive after the command that started it has
//// been answered.
////
//// `core/rendezvous` is the run as pure steps: each side's state goes in,
//// the next message comes out, and nothing there knows about a mailbox, a
//// clock or a count. This module is the shell around those steps. It moves
//// each message through the rendezvous slot at the inviter's mailbox, bounds
//// the whole run by the slot's own expiry, closes the slot on every path it
//// controls, and reports how the run ended. It stores nothing: the one
//// durable fact a run can leave behind, a failed confirmation, is handed to
//// the caller's `record_failure` and written by the engine.
////
//// ## The four endings
////
//// A run ends paired or with an `Ending`, and the endings are what the
//// operator must be able to tell apart (ADR-016, "Failures are told apart
//// and counted"):
////
//// - `NeverClaimed`: the inviter's slot closed or expired with no `m1`.
//// - `Stalled`: the peer stopped mid-run, the slot expired or was closed,
////   or a message was malformed, before any confirmation verdict. A
////   malformed message or a low-order share is interference, never a guess
////   at the words, so it ends here too and is not counted.
//// - `ConfirmationFailed`: for the inviter, `inviter_release` refused
////   `confirm_J`; for the joiner, `joiner_receive` refused `m4`, or `m3` was
////   stored and no `m4` arrived before the slot closed or expired. An
////   inviter whose check failed sends nothing and closes, so from the
////   joiner's side "`m3` sent, no `m4`" is how a wrong code usually looks.
////   This is the one ending that may be a spent guess, and both drivers
////   record it before they return.
////
//// Where a lost wait lands is decided in two places, and they are the
//// counting policy: `unclaimed` reads a slot gone before `m1` as never
//// claimed, and `unanswered` reads a slot gone after `m3` as a failed
//// confirmation.
////
//// ## One step per index
////
//// Each side numbers its own messages: the joiner sends `m1` at index 0 and
//// `m3` at index 1, the inviter `m2` at 0 and `m4` at 1. `await_message`
//// asks for the peer's messages past `index - 1`, takes the first one the
//// mailbox returns at `index`, and the driver hands that one body to the
//// step and never asks for that index again. Running a step on a second
//// body at the same index would hand whoever wrote it, the peer or the
//// mailbox, which ADR-016 treats as an adversary, a second guess at the
//// words, and the mailbox's `Conflict` on a changed body is no defence when
//// the mailbox is the one lying. Any error from a step ends the run.
////
//// ## `m4` is sealed once
////
//// `inviter_release` is called once per run. `send_message` builds its
//// request before the retry loop, so a retried send carries exactly the
//// bytes the first one did, and the hand-off key and nonce never seal a
//// second plaintext.
////
//// ## Time
////
//// Every wait is `weft/poll` on the link's clock, which is the daemon's poll
//// clock, so a test can drive it. A run's deadline is its slot's remaining
//// lifetime as the caller computed it from the expiry the mailbox returned,
//// so no wait outlives the slot, and each long poll asks the mailbox to
//// hold it no longer than what remains. The registry adds a second,
//// independent bound: each inviter run is a one-task `weft` run with a
//// `deadline`, so a call that hangs past every poll's bound is abandoned
//// and the slot is closed for it.
////
//// ## The registry
////
//// `invite create --code` prints the code and then waits up to ten minutes,
//// which the local API carries as two calls: one that opens the slot and
//// answers the code, and one that waits for the run. The run must outlive
//// the first call and must not depend on the second, so a command that
//// disconnects does not strand a slot. The registry is that owner: a
//// supervised `weft/actor` that starts each run as a relayed one-task
//// `weft` run, keeps its outcome, and answers `await`. Every run has a
//// subject of its own, and the selector is rebuilt from the table after
//// each message, as `daemon/scheduler` does with its batches. A run that
//// crashes or is abandoned at its deadline has its slot closed by its
//// `abandon` function, in a run of its own so the registry never blocks on
//// the network. A restart of the registry loses its runs; their slots are
//// left to the mailbox's expiry, which is at most the opening lifetime.
////
//// ## Flow
////
//// `run_inviter` → `inviter_steps` → `await_message` → `send_message`
//// → `linger` → `close`
////
//// 1. `run_inviter` sets the deadline, runs `inviter_steps`, closes the
////    slot, and through `settle_ending` records a failed confirmation.
//// 2. `inviter_steps` waits for the first message, answers, waits for the
////    confirmation, and releases the hand-off once; `linger` then waits for
////    the joiner to close.
//// 3. `run_joiner` and `joiner_steps` are the joiner's half, ending in the
////    ticket text.
//// 4. `await_message` long-polls through `fetch_once`, and `send_message`
////    retries one fixed request; `close` ends the slot either way.
//// 5. The registry: `start` and `supervised`, `begin` and `await`, and
////    `handle`, which settles each run through `settle` and `finish`.

import core/capability.{type Append, type Capability, type Read}
import core/crypto/suite.{type Suite}
import core/id.{type Id, type Rendezvous}
import core/limits
import core/mailbox/protocol.{type Request, type Response}
import core/pairing_code.{type PairingCode}
import core/rendezvous
import core/secret.{type Secret}
import daemon/mail.{type Handle}
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Name, type Selector, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor as otp_actor
import gleam/otp/supervision
import gleam/result
import weft
import weft/actor
import weft/poll
import weft/timer

/// The budget of one rendezvous call, dial included; a long poll gets its
/// wait on top (`mailbox_client.effective_timeout`). The slot was opened or
/// claimed a moment before, so the circuit is warm and this is far shorter
/// than a ticket's cold first call.
pub const call_ms = 60_000

/// How long a wait rests between two attempts that found nothing, on top of
/// the long poll the mailbox already held.
pub const retry_ms = 250

/// How long `close` keeps trying to delete the slot.
pub const close_ms = 30_000

/// How far past its slot's lifetime the registry lets an inviter run go
/// before its `weft` deadline abandons it: one call that started just
/// before the deadline, and the close after it.
pub const run_slack_ms = 95_000

/// How long the registry keeps a finished run's outcome for a caller that
/// has not asked for it yet: the longest a slot can live.
pub const keep_ms = 600_000

/// The joiner's index for `m1` and the inviter's for `m2`: each side's first
/// message.
pub const first_index = 0

/// The joiner's index for `m3` and the inviter's for `m4`: each side's
/// second message.
pub const second_index = 1

/// How a run reaches its rendezvous: one call to the mailbox, and the clock
/// every wait is measured on. Production builds it over the daemon's dialer
/// and poll clock; a test builds it over a fake mailbox.
pub type Link {
  Link(
    /// Sends one request to the rendezvous mailbox with a budget in
    /// milliseconds. `Error(Nil)` means no answer arrived; the request may
    /// or may not have been served.
    call: fn(Request, Int) -> Result(Response, Nil),
    /// The clock the run's deadline and every wait are measured on.
    clock: poll.Clock,
  )
}

/// One side's hold on a rendezvous slot: the slot's identifier and that
/// side's own two capabilities. The capabilities are authority over the
/// slot, so a `Slot` is never logged or rendered.
pub type Slot {
  Slot(
    /// The slot, which is also the PAKE's session identifier.
    rendezvous: Id(Rendezvous),
    /// Reads the other side's messages, and closes the slot.
    read: Capability(Read),
    /// Stores this side's messages.
    append: Capability(Append),
  )
}

/// Why a run did not pair. The module doc says which side reaches which.
pub type Ending {
  /// The inviter's slot expired or was closed with no `m1`. Never the
  /// joiner's.
  NeverClaimed

  /// The run stopped before any confirmation verdict. Not a guess.
  Stalled

  /// The confirmation failed, or for the joiner `m3` was stored and no `m4`
  /// came. May be a spent guess; recorded before the driver returns.
  ConfirmationFailed
}

/// Why a wait or a send at the rendezvous ended without its answer. The
/// driver turns it into an `Ending` by where in the run it happened.
type Lost {
  /// The mailbox answered `Unauthorized`: the slot expired or was closed.
  Gone

  /// The run's deadline passed first.
  TimedOut

  /// The mailbox answered something no honest mailbox would: a message
  /// past the one expected, a conflict, or the wrong kind of answer.
  Interfered
}

/// What `await` answers about a run.
pub type Watch {
  /// The registry has no run under that identifier: it never started here,
  /// or its outcome was kept for `keep_ms` and dropped.
  Unknown

  /// The run ended: `Ok(Nil)` when `m4` was stored for the joiner.
  Ended(result: Result(Nil, Ending))
}

/// The registry's mailbox protocol. Public only because the name's type
/// mentions it.
pub opaque type Message {
  /// Start a run under its slot's identifier, bounded by `within`
  /// milliseconds, with `abandon` to close its slot if it is cut off.
  Begin(
    run: Id(Rendezvous),
    work: fn() -> Result(Nil, Ending),
    within: Int,
    abandon: fn() -> Nil,
    reply_with: Subject(Nil),
  )

  /// Answer with the run's outcome once there is one.
  Await(run: Id(Rendezvous), reply_with: Subject(Watch))

  /// A run's relay pushed an outcome or its end marker.
  Settled(key: BitArray, pulled: weft.Pulled(Nil, Ending))

  /// A cleanup run said something; the close it made is best effort, so
  /// nothing waits on it.
  Cleaned
}

/// What the registry holds.
type State {
  State(
    self: Subject(Message),
    cleanup: Subject(weft.Pulled(Nil, Nil)),
    runs: Dict(BitArray, Entry),
    timer: timer.Source,
    now: fn() -> Int,
  )
}

/// One run the registry started.
type Entry {
  Entry(
    sink: Option(Subject(weft.Pulled(Nil, Ending))),
    abandon: fn() -> Nil,
    progress: Progress,
  )
}

/// Where one run stands.
type Progress {
  /// Still going; these callers wait for its outcome.
  Running(waiters: List(Subject(Watch)))

  /// Over, at `at` on the registry's clock.
  Finished(result: Result(Nil, Ending), at: Int)
}

// ------------------------------------------------------------- inviter

/// The inviter's run, from the open slot to the end: wait for `m1`, answer
/// `m2`, wait for `m3`, check `confirm_J` and release `m4` once, then wait
/// for the joiner to close the slot. It never outlives `lifetime_ms` on the
/// link's clock, it closes the slot on every path, and it calls
/// `record_failure` exactly when it ends `ConfirmationFailed`. The ticket
/// inside `waiting` was minted and stored before this runs (ADR-016), so
/// nothing here waits on the inviter's own mailbox queue.
///
/// ## Examples
///
/// ```gleam
/// pairing.run_inviter(suite, link, slot, waiting, 600_000, record)
/// // -> Ok(Nil) once m4 is stored for the joiner
/// ```
pub fn run_inviter(
  suite: Suite,
  link: Link,
  slot: Slot,
  waiting: rendezvous.InviterWaiting,
  lifetime_ms: Int,
  record_failure: fn() -> Nil,
) -> Result(Nil, Ending) {
  let deadline = link.clock.now() + lifetime_ms
  let ended = inviter_steps(suite, link, slot, waiting, deadline)

  // The slot goes on every path, a paired one included: the joiner closes
  // it first on an honest run, and a second close is harmless.
  close(link, slot)
  settle_ending(ended, record_failure)
}

/// The inviter's messages in order, each awaited once at its index. Every
/// error ends the run, and which `Ending` it is depends on whether the
/// joiner had spoken.
fn inviter_steps(
  suite: Suite,
  link: Link,
  slot: Slot,
  waiting: rendezvous.InviterWaiting,
  deadline: Int,
) -> Result(Nil, Ending) {
  // Before `m1` nobody has spoken, so a slot that goes away is one nobody
  // claimed; only a mailbox's nonsense is a stall here.
  use m1 <- result.try(
    await_message(link, slot, first_index, deadline)
    |> result.map_error(unclaimed),
  )
  use #(answered, m2) <- result.try(
    rendezvous.inviter_answer(suite, waiting, m1)
    |> result.replace_error(Stalled),
  )
  use Nil <- result.try(
    send_message(link, slot, first_index, m2, deadline)
    |> result.replace_error(Stalled),
  )
  use m3 <- result.try(
    await_message(link, slot, second_index, deadline)
    |> result.replace_error(Stalled),
  )

  // The gate of the run, taken once: `m4` exists only if `confirm_J`
  // matched, and these bytes are the only `m4` this run ever has.
  use released <- result.try(
    rendezvous.inviter_release(suite, answered, m3)
    |> result.map_error(verdict_ending),
  )
  use Nil <- result.try(
    send_message(link, slot, second_index, released.message, deadline)
    |> result.replace_error(Stalled),
  )

  // `m4` is stored. Closing now could delete it before the joiner reads it,
  // so the inviter waits for the joiner's own close, or the slot's end.
  linger(link, slot, deadline)
  Ok(Nil)
}

/// How a lost wait for `m1` ends the inviter's run.
fn unclaimed(lost: Lost) -> Ending {
  case lost {
    Gone | TimedOut -> NeverClaimed
    Interfered -> Stalled
  }
}

/// How a step's refusal ends a run: a failed confirmation may be a guess,
/// and everything else is interference or a broken suite.
fn verdict_ending(error: rendezvous.RunError) -> Ending {
  case error {
    rendezvous.ConfirmationFailed -> ConfirmationFailed

    rendezvous.MalformedMessage
    | rendezvous.LowOrderShare
    | rendezvous.TicketLength
    | rendezvous.PrimitiveFailed -> Stalled
  }
}

/// Waits, after `m4` is stored, until the joiner closes the slot or the slot
/// ends. Either way the run is paired; the wait only keeps the inviter's own
/// close from deleting `m4` under a joiner still reading it.
fn linger(link: Link, slot: Slot, deadline: Int) -> Nil {
  // The joiner sends nothing past `m3`, so a fetch past it finds nothing
  // until the slot is gone, and how the wait ends does not matter.
  let _ = await_message(link, slot, second_index + 1, deadline)
  Nil
}

// -------------------------------------------------------------- joiner

/// The joiner's run on a claimed slot: send `m1`, wait for `m2`, send `m3`,
/// wait for `m4`, and open it. Answers the inviter's ticket text, to redeem
/// as `invite accept --ticket` does. It never outlives `lifetime_ms`, closes
/// the slot on every path, and calls `record_failure` exactly when it ends
/// `ConfirmationFailed`, which includes `m3` stored and no `m4` before the
/// slot ended. It never ends `NeverClaimed`.
///
/// ## Examples
///
/// ```gleam
/// pairing.run_joiner(suite, link, slot, code, 120_000, record)
/// // -> Ok(ticket_text)
/// ```
pub fn run_joiner(
  suite: Suite,
  link: Link,
  slot: Slot,
  code: PairingCode,
  lifetime_ms: Int,
  record_failure: fn() -> Nil,
) -> Result(Secret, Ending) {
  let deadline = link.clock.now() + lifetime_ms
  let ended = joiner_steps(suite, link, slot, code, deadline)

  // The joiner is the one that closes an honest run, once `m4` is read.
  close(link, slot)
  settle_ending(ended, record_failure)
}

/// The joiner's messages in order, each awaited once at its index.
fn joiner_steps(
  suite: Suite,
  link: Link,
  slot: Slot,
  code: PairingCode,
  deadline: Int,
) -> Result(Secret, Ending) {
  use #(sent, m1) <- result.try(
    rendezvous.join(suite, code, slot.rendezvous)
    |> result.replace_error(Stalled),
  )
  use Nil <- result.try(
    send_message(link, slot, first_index, m1, deadline)
    |> result.replace_error(Stalled),
  )
  use m2 <- result.try(
    await_message(link, slot, first_index, deadline)
    |> result.replace_error(Stalled),
  )
  use #(confirmed, m3) <- result.try(
    rendezvous.joiner_confirm(suite, sent, m2)
    |> result.map_error(verdict_ending),
  )
  use Nil <- result.try(
    send_message(link, slot, second_index, m3, deadline)
    |> result.replace_error(Stalled),
  )

  // `m3` is stored. An inviter whose check failed sends nothing and closes,
  // so a slot that ends now, by a close or its expiry, is counted as the
  // failed confirmation it most likely is.
  use m4 <- result.try(
    await_message(link, slot, second_index, deadline)
    |> result.map_error(unanswered),
  )

  rendezvous.joiner_receive(suite, confirmed, m4)
  |> result.map_error(verdict_ending)
}

/// How a lost wait for `m4` ends the joiner's run.
fn unanswered(lost: Lost) -> Ending {
  case lost {
    Gone | TimedOut -> ConfirmationFailed
    Interfered -> Stalled
  }
}

/// Records a failed confirmation and passes the result on. Both drivers end
/// here, so the count follows the one ending that may be a spent guess and
/// nothing else.
fn settle_ending(
  ended: Result(a, Ending),
  record_failure: fn() -> Nil,
) -> Result(a, Ending) {
  // Only `ConfirmationFailed` is counted (ADR-016).
  case ended {
    Error(ConfirmationFailed) -> {
      record_failure()
      ended
    }

    Error(NeverClaimed) | Error(Stalled) | Ok(_) -> ended
  }
}

// ------------------------------------------------------------ messages

/// Waits for the peer's message at `index` until `deadline` on the link's
/// clock, taking the first body the mailbox returns at that index. A caller
/// asks for each index once, so whatever else the mailbox may later claim
/// is at that index is never read.
fn await_message(
  link: Link,
  slot: Slot,
  index: Int,
  deadline: Int,
) -> Result(BitArray, Lost) {
  let waited =
    poll.until_on(
      clock: link.clock,
      within: int.max(deadline - link.clock.now(), 0),
      every: poll.Fixed(retry_ms),
      attempt: fn() { fetch_once(link, slot, index, deadline) },
    )

  // A wait that runs out is the slot's lifetime spent on this side.
  case waited {
    poll.Answered(body) -> Ok(body)
    poll.Failed(lost) -> Error(lost)
    poll.Expired -> Error(TimedOut)
  }
}

/// One long poll for the message at `index`, held by the mailbox no longer
/// than what remains of the run.
fn fetch_once(
  link: Link,
  slot: Slot,
  index: Int,
  deadline: Int,
) -> poll.Attempt(BitArray, Lost) {
  let remaining = { deadline - link.clock.now() } / 1000
  let wait_seconds = int.clamp(remaining, 0, limits.long_poll_seconds)
  let request =
    protocol.RendezvousFetch(
      rendezvous: slot.rendezvous,
      read: slot.read,
      after: index - 1,
      wait_seconds:,
    )

  // Messages decide; a slot that is gone is final; a busy mailbox or a lost
  // answer is tried again; anything else is not a rendezvous answer.
  case link.call(request, call_ms) {
    Ok(protocol.RendezvousMessages(messages:)) -> first_at(messages, index)
    Ok(protocol.Refused(protocol.Unauthorized)) -> poll.Fail(Gone)
    Ok(protocol.Refused(protocol.Unavailable)) | Error(Nil) -> poll.Retry

    Ok(protocol.Refused(protocol.Conflict))
    | Ok(protocol.Refused(protocol.QuotaExceeded))
    | Ok(protocol.Refused(protocol.TooLarge))
    | Ok(protocol.Refused(protocol.BadDeadline))
    | Ok(protocol.Refused(protocol.Malformed))
    | Ok(protocol.Refused(protocol.UnsupportedVersion))
    | Ok(protocol.QueueCreated(_))
    | Ok(protocol.Appended(_))
    | Ok(protocol.Batch(_))
    | Ok(protocol.Acked)
    | Ok(protocol.QueueDeleted)
    | Ok(protocol.BlobStored(_))
    | Ok(protocol.SealedBlob(_))
    | Ok(protocol.RendezvousOpened(..))
    | Ok(protocol.RendezvousClaimed(..))
    | Ok(protocol.RendezvousSent)
    | Ok(protocol.RendezvousClosed) -> poll.Fail(Interfered)
  }
}

/// The body of the first message at `index`, which is the first of the
/// list when the mailbox is honest. Every later message, at the same index
/// or past it, is never read.
fn first_at(
  messages: List(protocol.RendezvousMessage),
  index: Int,
) -> poll.Attempt(BitArray, Lost) {
  // Nothing yet is worth another poll; a first message at any other index
  // means the peer skipped one or the mailbox reordered them.
  case messages {
    [] -> poll.Retry
    [first, ..] if first.index == index -> poll.Done(first.body)
    [_, ..] -> poll.Fail(Interfered)
  }
}

/// Stores this side's message at `index`, retrying until the mailbox
/// answers or `deadline` passes. The request is built once, before the
/// loop, so every attempt carries the same bytes: a retried `m4` is the
/// `m4` that was sealed, never a second sealing.
fn send_message(
  link: Link,
  slot: Slot,
  index: Int,
  body: BitArray,
  deadline: Int,
) -> Result(Nil, Lost) {
  let request =
    protocol.RendezvousSend(
      rendezvous: slot.rendezvous,
      append: slot.append,
      index:,
      body:,
    )

  let sent =
    poll.until_on(
      clock: link.clock,
      within: int.max(deadline - link.clock.now(), 0),
      every: poll.Fixed(retry_ms),
      attempt: fn() { judge_send(link.call(request, call_ms)) },
    )

  // A send that never got an answer before the deadline did not happen as
  // far as the run is concerned.
  case sent {
    poll.Answered(Nil) -> Ok(Nil)
    poll.Failed(lost) -> Error(lost)
    poll.Expired -> Error(TimedOut)
  }
}

/// What one send's answer means: stored, gone, worth another try, or an
/// answer no honest mailbox gives to a send. A `Conflict` is the mailbox
/// saying another body is already at this index, which this side never
/// sent.
fn judge_send(answer: Result(Response, Nil)) -> poll.Attempt(Nil, Lost) {
  case answer {
    Ok(protocol.RendezvousSent) -> poll.Done(Nil)
    Ok(protocol.Refused(protocol.Unauthorized)) -> poll.Fail(Gone)
    Ok(protocol.Refused(protocol.Unavailable)) | Error(Nil) -> poll.Retry

    Ok(protocol.Refused(protocol.Conflict))
    | Ok(protocol.Refused(protocol.QuotaExceeded))
    | Ok(protocol.Refused(protocol.TooLarge))
    | Ok(protocol.Refused(protocol.BadDeadline))
    | Ok(protocol.Refused(protocol.Malformed))
    | Ok(protocol.Refused(protocol.UnsupportedVersion))
    | Ok(protocol.QueueCreated(_))
    | Ok(protocol.Appended(_))
    | Ok(protocol.Batch(_))
    | Ok(protocol.Acked)
    | Ok(protocol.QueueDeleted)
    | Ok(protocol.BlobStored(_))
    | Ok(protocol.SealedBlob(_))
    | Ok(protocol.RendezvousOpened(..))
    | Ok(protocol.RendezvousClaimed(..))
    | Ok(protocol.RendezvousMessages(_))
    | Ok(protocol.RendezvousClosed) -> poll.Fail(Interfered)
  }
}

/// Deletes the slot, trying for at most `close_ms`. Best effort: a close
/// that never lands leaves the slot to the mailbox's expiry, and a slot
/// already gone answers `Unauthorized`, which is as good as closed.
///
/// ## Examples
///
/// ```gleam
/// pairing.close(link, slot)
/// // -> Nil
/// ```
pub fn close(link: Link, slot: Slot) -> Nil {
  let request =
    protocol.CloseRendezvous(rendezvous: slot.rendezvous, read: slot.read)

  let _ =
    poll.until_on(
      clock: link.clock,
      within: close_ms,
      every: poll.Fixed(retry_ms),
      attempt: fn() {
        // Only a busy mailbox or a lost answer is worth another try.
        case link.call(request, call_ms) {
          Ok(protocol.Refused(protocol.Unavailable)) | Error(Nil) -> poll.Retry
          Ok(_) -> poll.Done(Nil)
        }
      },
    )

  Nil
}

/// Why text is not a pairing code, in words an operator can act on. It
/// names a word's position and never a word, because the text is the
/// secret.
///
/// ## Examples
///
/// ```gleam
/// pairing.describe_code_error(pairing_code.UnknownWord(position: 2))
/// // -> "word 2 of the code is not on the word list"
/// ```
pub fn describe_code_error(error: pairing_code.CodeError) -> String {
  case error {
    pairing_code.TooLong -> "the code is too long"

    pairing_code.BadShape ->
      "the code is not digits and words joined by single hyphens, in lowercase"

    pairing_code.BadNameplate ->
      "the code's first part is not "
      <> int.to_string(limits.nameplate_digits)
      <> " digits"

    pairing_code.UnknownWord(position:) ->
      "word "
      <> int.to_string(position)
      <> " of the code is not on the word list"
  }
}

// ------------------------------------------------------------ registry

/// Starts the registry under `name`. `timer` arms each run's deadline, and
/// `now` is the clock a finished outcome's age is measured on.
///
/// ## Examples
///
/// ```gleam
/// pairing.start(name, timer.WallClock, poll.monotonic().now)
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message),
  timer: timer.Source,
  now: fn() -> Int,
) -> otp_actor.StartResult(Subject(Message)) {
  actor.start(builder(name, timer, now))
}

/// The registry as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// pairing.supervised(name, timer.WallClock, poll.monotonic().now)
/// ```
pub fn supervised(
  name: Name(Message),
  timer: timer.Source,
  now: fn() -> Int,
) -> supervision.ChildSpecification(Subject(Message)) {
  actor.supervised(builder(name, timer, now))
}

/// The registry's actor: named, listening to its own subject and to the
/// cleanup runs' subject from the start.
fn builder(
  name: Name(Message),
  timer: timer.Source,
  now: fn() -> Int,
) -> actor.Builder(State, Message, Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    let state =
      State(
        self: subject,
        cleanup: process.new_subject(),
        runs: dict.new(),
        timer:,
        now:,
      )

    actor.initialised(state)
    |> actor.selecting(listening(state))
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
}

/// Hands a run to the registry and returns once it has started. `work` is
/// the whole run; `within` bounds it, past which it is abandoned and
/// `abandon` closes its slot. `Error(Nil)` means the registry did not
/// answer, and the caller still owns the slot.
///
/// ## Examples
///
/// ```gleam
/// pairing.begin(registry, run, fn() { pairing.run_inviter(..) }, 695_000, close_it)
/// // -> Ok(Nil)
/// ```
pub fn begin(
  registry: Handle(Message),
  run: Id(Rendezvous),
  work: fn() -> Result(Nil, Ending),
  within: Int,
  abandon: fn() -> Nil,
) -> Result(Nil, Nil) {
  mail.ask(registry, "begin", 5000, fn(reply_with) {
    Begin(run:, work:, within:, abandon:, reply_with:)
  })
}

/// Waits up to `timeout_ms` for a run's outcome. `Error(Nil)` means no
/// answer in time; the run goes on and can be asked about again.
///
/// ## Examples
///
/// ```gleam
/// pairing.await(registry, run, 700_000)
/// // -> Ok(Ended(Ok(Nil)))
/// ```
pub fn await(
  registry: Handle(Message),
  run: Id(Rendezvous),
  timeout_ms: Int,
) -> Result(Watch, Nil) {
  mail.ask(registry, "await", timeout_ms, fn(reply_with) {
    Await(run:, reply_with:)
  })
}

/// Handles one message, then listens to every run still pushing.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // A run starts, a caller waits, a run's relay reports, or a cleanup ends.
  let after = case message {
    Begin(run:, work:, within:, abandon:, reply_with:) -> {
      let started = launch(prune(state), run, work, within, abandon)
      process.send(reply_with, Nil)
      started
    }

    Await(run:, reply_with:) -> watch(state, run, reply_with)
    Settled(key:, pulled:) -> settle(state, key, pulled)
    Cleaned -> state
  }

  actor.continue(after) |> actor.with_selector(listening(after))
}

/// Drops the finished outcomes nobody asked for within `keep_ms`, so a
/// command that went away does not leave its outcome here for good.
fn prune(state: State) -> State {
  let now = state.now()

  let runs =
    dict.filter(state.runs, fn(_, entry) {
      // Only an outcome that has waited out its keep is dropped.
      case entry.progress {
        Running(_) -> True
        Finished(at:, ..) -> now - at < keep_ms
      }
    })

  State(..state, runs:)
}

/// Starts one run as a relayed one-task `weft` run with a deadline, and
/// records it. The relay is linked to the registry, so a registry restart
/// takes the run with it.
fn launch(
  state: State,
  run: Id(Rendezvous),
  work: fn() -> Result(Nil, Ending),
  within: Int,
  abandon: fn() -> Nil,
) -> State {
  let sink = process.new_subject()

  let _relay =
    weft.new([work])
    |> weft.deadline(within)
    |> weft.with_timer_source(state.timer)
    |> weft.start_relayed(sink)

  let entry = Entry(sink: Some(sink), abandon:, progress: Running([]))
  State(..state, runs: dict.insert(state.runs, id.to_bytes(run), entry))
}

/// Answers a caller at once when the run is over or unknown, or adds it to
/// the run's waiters.
fn watch(
  state: State,
  run: Id(Rendezvous),
  reply_with: Subject(Watch),
) -> State {
  let key = id.to_bytes(run)

  // The run's progress decides whether the caller waits.
  case dict.get(state.runs, key) {
    Error(Nil) -> {
      process.send(reply_with, Unknown)
      state
    }

    Ok(Entry(progress: Finished(result:, ..), ..)) -> {
      process.send(reply_with, Ended(result))
      state
    }

    Ok(Entry(progress: Running(waiters:), ..) as entry) -> {
      let waiting = Entry(..entry, progress: Running([reply_with, ..waiters]))
      State(..state, runs: dict.insert(state.runs, key, waiting))
    }
  }
}

/// Handles one thing a run's relay pushed. The relay sends the run's one
/// outcome and then exactly one end marker; a run cut off before it said
/// anything is stalled, and its slot is closed for it.
fn settle(
  state: State,
  key: BitArray,
  pulled: weft.Pulled(Nil, Ending),
) -> State {
  // The outcome decides the run's result; the end marker stops the
  // listening, and settles a run that ended without one.
  case pulled {
    weft.PulledOutcome(weft.Completed(value: Nil, ..)) ->
      finish(state, key, Ok(Nil))

    weft.PulledOutcome(weft.Failed(error:, ..)) ->
      finish(state, key, Error(error))

    // The worker died or was cut off at the deadline, so its own close
    // never ran.
    weft.PulledOutcome(weft.Crashed(..))
    | weft.PulledOutcome(weft.Abandoned(..))
    | weft.PulledOutcome(weft.NeverStarted(..))
    | weft.PulledOutcome(weft.DrainProofLost(..))
    | weft.PulledOutcome(weft.CancellationUnconfirmed(..)) ->
      state |> clean_up(key) |> finish(key, Error(Stalled))

    weft.AllDelivered | weft.RunLost(..) ->
      state |> stop_listening(key) |> finish_unsettled(key)

    // A relay waits for each delivery and never reports a pull that found
    // nothing, so this arm is the type's, not an event; it changes nothing.
    weft.NotYet -> state
  }
}

/// Closes a cut-off run's slot in a one-task run of its own, so the
/// registry never waits on the network. Its outcome is ignored.
fn clean_up(state: State, key: BitArray) -> State {
  // Only a known run has a slot to close.
  case dict.get(state.runs, key) {
    Ok(entry) -> {
      let abandon = entry.abandon
      let _relay =
        weft.new([fn() { Ok(abandon()) }])
        |> weft.deadline(close_ms + call_ms)
        |> weft.with_timer_source(state.timer)
        |> weft.start_relayed(state.cleanup)

      state
    }

    Error(Nil) -> state
  }
}

/// Records a run's result and answers everyone waiting for it. A run
/// already finished keeps its first result.
fn finish(state: State, key: BitArray, result: Result(Nil, Ending)) -> State {
  // Only a running entry has waiters to answer.
  case dict.get(state.runs, key) {
    Ok(Entry(progress: Running(waiters:), ..) as entry) -> {
      list.each(waiters, fn(waiter) { process.send(waiter, Ended(result)) })

      let done = Entry(..entry, progress: Finished(result:, at: state.now()))
      State(..state, runs: dict.insert(state.runs, key, done))
    }

    Ok(Entry(progress: Finished(..), ..)) | Error(Nil) -> state
  }
}

/// A run whose relay ended without an outcome (a scope that died) is
/// stalled, and its slot is closed for it.
fn finish_unsettled(state: State, key: BitArray) -> State {
  // Only a run that never reported is settled here.
  case dict.get(state.runs, key) {
    Ok(Entry(progress: Running(..), ..)) ->
      state |> clean_up(key) |> finish(key, Error(Stalled))

    Ok(Entry(progress: Finished(..), ..)) | Error(Nil) -> state
  }
}

/// Stops selecting a run's subject once its relay has said it is over.
fn stop_listening(state: State, key: BitArray) -> State {
  // Only a known run has a subject to drop.
  case dict.get(state.runs, key) {
    Ok(entry) ->
      State(
        ..state,
        runs: dict.insert(state.runs, key, Entry(..entry, sink: None)),
      )

    Error(Nil) -> state
  }
}

/// What the registry receives: its own mailbox, the cleanup runs, and one
/// subject per run whose relay has not yet said it is over.
fn listening(state: State) -> Selector(Message) {
  let base =
    process.new_selector()
    |> process.select(state.self)
    |> process.select_map(state.cleanup, fn(_) { Cleaned })

  dict.fold(state.runs, base, fn(selector, key, entry) {
    // A run whose relay ended has nothing more to say.
    case entry.sink {
      Some(sink) ->
        process.select_map(selector, sink, fn(pulled) { Settled(key:, pulled:) })

      None -> selector
    }
  })
}

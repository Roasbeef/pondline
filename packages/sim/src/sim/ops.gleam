//// What an operator or an agent does for each op, through `daemon/api`.
////
//// Every op that calls the daemon runs in a process of its own, spawned by
//// the runner, because a call blocks: `invite` waits for the mailbox to
//// create its queue, and any call waits for an engine whose job the runner
//// has not released yet. The op's process is just one more actor in the
//// world; the runner learns how it ended from the `Finished` message the
//// body's result is sent in.
////
//// An op reads the daemon's handle from a shared table on every attempt, so
//// a call that outlives a restart retries against the new tree, as an
//// adapter that reconnects would. `send`, `invite` and `accept` retry on
//// `Unavailable` up to `attempts` times, half a virtual second apart, which
//// is what a careful adapter does with an outcome it cannot know (H4).
//// Every send carries its payload tag as its idempotency key and an accept
//// is keyed by its invitation (ADR-011), so a retry after an ambiguous
//// failure is the same message or relationship, never a second one; the
//// count of answers that were `Unavailable` still comes back in the
//// outcome, for the trace.
////
//// An input past a limit that the daemon accepts comes back as `Other`,
//// which the oracle fails: a limit is a MUST of the spec.
////
//// ## Flow
////
//// 1. `body` maps an op to the closure its process runs.
//// 2. `send_tags`, `invite`, `accept` and `exceed` are the calls with
////    retries or limits; the rest call the API once.

import core/id
import core/limits
import core/offer
import core/secret
import daemon/api
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/result
import gleam/string
import sim/internal/ffi_vm.{type Table}
import sim/seed.{type Mode, type Op, type Party}
import sim/world.{type Outcome}

/// How many times `send`, `invite` and `accept` try before giving up.
pub const attempts = 3

/// How long an op waits between attempts, in virtual milliseconds.
pub const retry_ms = 500

/// What an op's process needs: where the current handles are, how to wait,
/// and the run's configuration.
pub type Env {
  Env(
    /// The current `api.Daemon` of each party, by party name.
    handles: Table(String, api.Daemon),
    /// Sleeps on the virtual clock.
    sleep: fn(Int) -> Nil,
    /// The production configuration.
    mode: Mode,
  )
}

/// The closure an op's process runs, or `Error(Nil)` for an op that does
/// not call the API. `index` makes payload tags and labels unique; `file`
/// is the invitation an `Accept` (or a limit on one) redeems.
///
/// ## Examples
///
/// ```gleam
/// ops.body(env, 3, seed.Consume(seed.A), Error(Nil))
/// // -> Ok(fn() { .. })
/// ```
pub fn body(
  env: Env,
  index: Int,
  op: Op,
  file: Result(BitArray, Nil),
) -> Result(fn() -> Outcome, Nil) {
  // Ops that act on the world rather than through the API have no body.
  case op {
    seed.Send(party:, contact:, size:) ->
      Ok(fn() { send_tags(env, party, contact, tags(index, 1), size) })

    seed.Burst(party:, contact:, count:) ->
      Ok(fn() { send_tags(env, party, contact, tags(index, count), 0) })

    seed.Consume(party:) -> Ok(fn() { consume(env, party) })

    seed.Invite(party:) ->
      Ok(fn() {
        invite(env, party, "invite " <> int.to_string(index), env.mode.budget)
      })

    seed.Accept(party:, pick: _) ->
      case file {
        Ok(bytes) ->
          Ok(fn() {
            accept(env, party, bytes, "accept " <> int.to_string(index))
          })
        Error(Nil) -> Error(Nil)
      }

    seed.Approve(party:) -> Ok(fn() { approve(env, party) })

    seed.End(party:, contact:, how:) ->
      Ok(fn() { end(env, party, contact, how) })

    seed.Raise(party:, contact:, by:) ->
      Ok(fn() { raise(env, party, contact, by) })

    seed.Exceed(party:, limit:) ->
      Ok(fn() { exceed(env, index, party, limit, file) })

    seed.Advance(..)
    | seed.ArmStore(..)
    | seed.ArmEngine(..)
    | seed.ArmLoss(..)
    | seed.ToggleMailbox
    | seed.ArmLie(..)
    | seed.SetSkew(..)
    | seed.Forge(..)
    | seed.Restart(..)
    | seed.Kill(..)
    | seed.RestoreMailbox -> Error(Nil)
  }
}

/// The payload tags of an op's messages: `p<index>.<n>`.
fn tags(index: Int, count: Int) -> List(String) {
  int.range(from: 0, to: count, with: [], run: fn(acc, n) {
    ["p" <> int.to_string(index) <> "." <> int.to_string(n), ..acc]
  })
  |> list.reverse
}

/// The payload of a message: its tag, a bar, and filler of a size class.
///
/// ## Examples
///
/// ```gleam
/// ops.payload("p1.0", 0)
/// // -> <<"p1.0|", ..>>
/// ```
pub fn payload(tag: String, size: Int) -> BitArray {
  // The size class picks the filler: tiny, a page, a frame, most of a bucket.
  let filler = case size {
    0 -> 16
    1 -> 1024
    2 -> 8192
    _ -> 30_000
  }

  <<tag:utf8, "|":utf8, string.repeat("x", filler):utf8>>
}

/// The tag a delivered payload carries, if it is one of ours.
///
/// ## Examples
///
/// ```gleam
/// ops.tag_of(<<"p1.0|xx">>)
/// // -> Ok("p1.0")
/// ```
pub fn tag_of(payload: BitArray) -> Result(String, Nil) {
  let text = bit_array.to_string(payload)

  // A payload that is not text, or has no bar, is not one of ours.
  case text {
    Ok(text) ->
      case string.split_once(text, "|") {
        Ok(#(tag, _)) -> Ok(tag)
        Error(Nil) -> Error(Nil)
      }

    Error(Nil) -> Error(Nil)
  }
}

/// The current handle of a party.
fn handle(env: Env, party: Party) -> Result(api.Daemon, api.ApiError) {
  case ffi_vm.table_get(env.handles, seed.party_name(party)) {
    Ok(daemon) -> Ok(daemon)
    Error(Nil) -> Error(api.Unavailable)
  }
}

/// Calls `call` against the current handle until it answers anything but
/// `Unavailable` or the attempts run out. Returns the last answer and how
/// many answers were `Unavailable`.
fn retrying(
  env: Env,
  party: Party,
  call: fn(api.Daemon) -> Result(a, api.ApiError),
  left: Int,
  unavailable: Int,
) -> #(Result(a, api.ApiError), Int) {
  // A daemon with no current handle is as unavailable as one that says so.
  let answer = case handle(env, party) {
    Ok(daemon) -> call(daemon)
    Error(error) -> Error(error)
  }

  // Only `Unavailable` is worth another try, and only while tries remain.
  case answer, left > 1 {
    Error(api.Unavailable), True -> {
      env.sleep(retry_ms)
      retrying(env, party, call, left - 1, unavailable + 1)
    }

    Error(api.Unavailable), False -> #(answer, unavailable + 1)

    _, _ -> #(answer, unavailable)
  }
}

/// The party's relationships in `phase`, oldest first.
fn contacts_in(
  env: Env,
  party: Party,
  phase: api.PhaseName,
) -> List(id.Id(id.Contact)) {
  // A daemon with no current handle is as unavailable as one that says so.
  let found = case handle(env, party) {
    Ok(daemon) -> api.contacts(daemon)
    Error(error) -> Error(error)
  }

  // A daemon that cannot answer has, as far as the op knows, no contacts.
  case found {
    Ok(views) ->
      views
      |> list.filter(fn(view) { view.phase == phase })
      |> list.map(fn(view) { view.contact })

    Error(_) -> []
  }
}

/// The `index`th of `contacts`, wrapping.
fn pick(contacts: List(a), index: Int) -> Result(a, Nil) {
  // An empty list has nothing to pick.
  case contacts {
    [] -> Error(Nil)
    _ -> list.drop(contacts, index % list.length(contacts)) |> list.first
  }
}

/// Sends one message per tag to the `contact`th active relationship.
fn send_tags(
  env: Env,
  party: Party,
  contact: Int,
  tags: List(String),
  size: Int,
) -> Outcome {
  // No active relationship means there is no one to send to yet.
  case pick(contacts_in(env, party, api.Active), contact) {
    Error(Nil) -> world.Done

    Ok(to) -> {
      let results =
        list.map(tags, fn(tag) {
          let #(answer, unavailable) =
            retrying(
              env,
              party,
              fn(daemon) {
                api.send_with_key(
                  daemon,
                  to,
                  tag,
                  "text/plain",
                  secret.new(payload(tag, size)),
                  None,
                )
                |> result.map(fn(message) {
                  // An agent asks how far its message got, as an adapter
                  // polling `status` would; the answer is not kept.
                  let _ = api.status(daemon, message)
                  message
                })
              },
              attempts,
              0,
            )
          #(tag, answer, unavailable)
        })

      sent_outcome(results)
    }
  }
}

/// What a series of sends came to: the tags committed, and those whose
/// send answered `Unavailable` first.
fn sent_outcome(
  results: List(#(String, Result(a, api.ApiError), Int)),
) -> Outcome {
  let committed =
    list.filter_map(results, fn(result) {
      case result.1 {
        Ok(_) -> Ok(result.0)
        Error(_) -> Error(Nil)
      }
    })
  let retried =
    list.filter_map(results, fn(result) {
      case result.2 > 0 {
        True -> Ok(result.0)
        False -> Error(Nil)
      }
    })

  world.Sent(tags: committed, retried:)
}

/// Reads up to fifty ready deliveries and acknowledges each.
fn consume(env: Env, party: Party) -> Outcome {
  // Both the handle and the read must succeed before anything is acknowledged.
  let found = case handle(env, party) {
    Ok(daemon) ->
      case api.receive(daemon, None, 50) {
        Ok(deliveries) -> Ok(#(daemon, deliveries))
        Error(error) -> Error(error)
      }

    Error(error) -> Error(error)
  }

  // Each delivery is acknowledged on its own; a failure leaves it for the
  // next consume.
  case found {
    Ok(#(daemon, deliveries)) -> {
      list.each(deliveries, fn(delivery) {
        let _ = api.acknowledge(daemon, delivery.message)
        Nil
      })

      // The operator's read-only calls ride along: the account of the
      // daemon and the latest audit entries.
      let _ = api.health(daemon)
      let _ = api.audit(daemon, None, 20)
      world.Done
    }

    Error(error) -> failure(error)
  }
}

/// Creates an invitation and waits for its file.
fn invite(env: Env, party: Party, description: String, budget: Int) -> Outcome {
  // The run's mode decides whether the joiner needs the operator's approval.
  let approval = case env.mode.approval {
    seed.Automatic -> offer.AutoApprove
    seed.ByOperator -> offer.OperatorApproves
  }

  let #(answer, unavailable) =
    retrying(
      env,
      party,
      fn(daemon) { api.invite(daemon, description, approval, budget) },
      attempts,
      0,
    )

  // A file is an invitation the other daemon can redeem.
  case answer {
    Ok(file) -> world.Invited(file:, retried: unavailable)
    Error(error) -> failure(error)
  }
}

/// Redeems an invitation file.
fn accept(
  env: Env,
  party: Party,
  file: BitArray,
  description: String,
) -> Outcome {
  let #(answer, unavailable) =
    retrying(
      env,
      party,
      fn(daemon) { api.accept(daemon, file, description) },
      attempts,
      0,
    )

  // The relationship exists once accept answers.
  case answer {
    Ok(_) -> world.Accepted(retried: unavailable)
    Error(error) -> failure(error)
  }
}

/// Approves every pending relationship.
fn approve(env: Env, party: Party) -> Outcome {
  contacts_in(env, party, api.PendingApproval)
  |> list.each(fn(contact) {
    // Each approval is independent; one that fails leaves the rest to go ahead.
    let _ = case handle(env, party) {
      Ok(daemon) -> api.approve(daemon, contact)
      Error(error) -> Error(error)
    }

    Nil
  })

  world.Done
}

/// Closes an active relationship, or declines a pending one.
fn end(env: Env, party: Party, contact: Int, how: seed.Ending) -> Outcome {
  // Closing applies to active relationships, declining to pending ones.
  let #(phase, call) = case how {
    seed.Close -> #(api.Active, api.close)
    seed.Decline -> #(api.PendingApproval, api.decline)
  }

  // Nothing in that phase means nothing to end.
  case pick(contacts_in(env, party, phase), contact), handle(env, party) {
    Ok(target), Ok(daemon) -> answered(call(daemon, target))
    Error(Nil), _ -> world.Done
    _, Error(error) -> failure(error)
  }
}

/// Raises an active relationship's budget.
fn raise(env: Env, party: Party, contact: Int, by: Int) -> Outcome {
  // Nothing active means nothing to raise.
  case pick(contacts_in(env, party, api.Active), contact), handle(env, party) {
    Ok(target), Ok(daemon) -> answered(api.raise_budget(daemon, target, by))
    Error(Nil), _ -> world.Done
    _, Error(error) -> failure(error)
  }
}

/// An input at or past a limit. At the limit it must be accepted like any
/// other; past it, it must be refused.
fn exceed(
  env: Env,
  index: Int,
  party: Party,
  limit: seed.Limit,
  file: Result(BitArray, Nil),
) -> Outcome {
  let at = limits.max_description_bytes
  let budget = env.mode.budget

  // Each limit is one call with one input at or one past its bound.
  case limit {
    seed.DescriptionAt -> invite(env, party, string.repeat("d", at), budget)

    seed.DescriptionPast ->
      past(invite(env, party, string.repeat("d", at + 1), budget))

    seed.AcceptDescriptionPast ->
      case file {
        Ok(bytes) -> past(accept(env, party, bytes, string.repeat("d", at + 1)))
        Error(Nil) -> world.Done
      }

    seed.BudgetZero -> invite(env, party, "zero budget", 0)

    seed.BudgetMax ->
      invite(env, party, "max budget", limits.max_budget_messages)

    seed.BudgetPast ->
      invite(env, party, "past budget", limits.max_budget_messages + 1)

    seed.PayloadAt -> sized_send(env, index, party, limits.max_body_bytes, 1)

    seed.PayloadPast ->
      past(sized_send(env, index, party, limits.max_body_bytes + 1, 1))

    seed.ContentTypeAt ->
      typed_send(env, index, party, limits.max_content_type_bytes)

    seed.ContentTypePast ->
      past(typed_send(env, index, party, limits.max_content_type_bytes + 1))

    seed.RaiseHuge -> raise(env, party, 0, limits.max_budget_messages + 5)
  }
}

/// A past-limit call's outcome: accepting it is the finding.
fn past(outcome: Outcome) -> Outcome {
  // Anything that committed is an input past a limit the daemon took.
  case outcome {
    world.Invited(..) | world.Accepted(..) ->
      world.Other("an input past a limit was accepted")

    world.Sent(tags: [_, ..], ..) ->
      world.Other("an input past a limit was accepted")

    world.Sent(tags: [], ..)
    | world.Done
    | world.Refused(_)
    | world.Unavailable
    | world.Other(_) -> outcome
  }
}

/// Sends one message whose payload is `bytes` long in total, tag included.
fn sized_send(
  env: Env,
  index: Int,
  party: Party,
  bytes: Int,
  _count: Int,
) -> Outcome {
  let tag = "p" <> int.to_string(index) <> ".0"
  let head = <<tag:utf8, "|":utf8>>
  let filler = int.max(bytes - bit_array.byte_size(head), 0)
  let body = <<head:bits, string.repeat("y", filler):utf8>>

  one_send(env, party, tag, "text/plain", body)
}

/// Sends one message whose content type is `length` bytes long.
fn typed_send(env: Env, index: Int, party: Party, length: Int) -> Outcome {
  let tag = "p" <> int.to_string(index) <> ".0"

  one_send(env, party, tag, string.repeat("t", length), payload(tag, 0))
}

/// One send to the first active relationship.
fn one_send(
  env: Env,
  party: Party,
  tag: String,
  content_type: String,
  body: BitArray,
) -> Outcome {
  // No active relationship means no one to test the limit against.
  case pick(contacts_in(env, party, api.Active), 0) {
    Error(Nil) -> world.Done

    Ok(to) -> {
      let #(answer, unavailable) =
        retrying(
          env,
          party,
          fn(daemon) {
            api.send_with_key(
              daemon,
              to,
              tag,
              content_type,
              secret.new(body),
              None,
            )
          },
          attempts,
          0,
        )

      sent_outcome([#(tag, answer, unavailable)])
    }
  }
}

/// A call that carries nothing back.
fn answered(answer: Result(Nil, api.ApiError)) -> Outcome {
  case answer {
    Ok(Nil) -> world.Done
    Error(error) -> failure(error)
  }
}

/// An API error as an outcome.
fn failure(error: api.ApiError) -> Outcome {
  case error {
    api.Unavailable -> world.Unavailable
    api.Refused(reason:) -> world.Refused(reason)
    api.NotFound -> world.Refused("not found")
    api.InvalidInvitation(reason:) -> world.Refused(reason)
  }
}

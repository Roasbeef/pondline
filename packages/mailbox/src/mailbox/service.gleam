//// The mailbox protocol's rules, as plain functions of a `Store` (spec §6).
////
//// `handle(store, now, request)` takes a typed request from
//// `core/mailbox/protocol` and returns the typed response, with the clock
//// as an argument and no process in sight. That is the whole contract an
//// HTTP handler, a later onion-message carrier or a test needs: decode into
//// a `Request`, call `handle`, encode the `Response`. In production the
//// storage coordinator is the only caller, so every request is already
//// serialized (spec §8.4); nothing here relies on that for correctness,
//// because each change is one `store.transaction`.
////
//// The rules this module is responsible for:
////
//// - Authority is a hash comparison. A presented capability is hashed and
////   compared in constant time with the stored hash of the one kind the
////   operation needs. A missing queue and a wrong capability produce the
////   same `Unauthorized`, so the mailbox is not an oracle for which queues
////   exist.
//// - An append is answered from what is already known before anything is
////   inserted: the stored envelope, or, after an acknowledgment, its
////   tombstone. The same digest returns the original receipt and a
////   different one is a `Conflict`, so an acknowledged envelope is never
////   resurrected by a retry.
//// - Quota is reserved and the row inserted in one transaction, and the
////   receipt is built only after `store.transaction` has returned, so
////   nothing is acknowledged before it is durable.
//// - A sealed invitation (ADR-009) is stored by its queue's administrator,
////   charged to that queue's quota, and fetched by whoever presents the
////   retrieve capability whose hash was stored with it. A fetch never
////   deletes it; the sweep does, once its deadline passes. A missing blob,
////   an expired one and a wrong capability all answer `Unauthorized`.
//// - A rendezvous slot (ADR-016) has two sides, and the mailbox tells them
////   apart only by which stored hash a presented capability matches: the
////   opener's pair, stored at `OpenRendezvous`, or the claimant's, bound by
////   the first `ClaimRendezvous`. A send is filed under its sender's side
////   and a fetch returns only the other side's messages, so neither side
////   ever reads its own words back and nobody else reads anything. A
////   missing slot, an expired one, a claimed one and a wrong capability
////   all answer `Unauthorized`; an expired slot is invisible from the
////   instant of its expiry, because every read of a slot filters on it.
//// - A refusal is an ordinary answer, not a failure: every check precedes
////   the first write, so a refused request commits an empty transaction.
////   Only a storage fault rolls back, and it surfaces as `Unavailable`.
////
//// `handle` never waits. `Fetch.wait_seconds` and
//// `RendezvousFetch.wait_seconds` are honored by `mailbox/node`, which can
//// hold a caller without holding the database. What it needs to know to
//// wake that caller comes back from `serve` as `Served.wakes`.
////
//// ## Randomness
////
//// `OpenRendezvous` is the one request whose answer the mailbox draws: the
//// nameplate. `serve` takes the randomness source as an argument so a test
//// can force a collision, and `handle` passes the system CSPRNG
//// (`primitives.random_bytes`), the same source `mailbox grant` uses for a
//// provisioning capability.
////
//// ## Flow
////
//// 1. `handle` is `serve` over the system CSPRNG, and `serve` dispatches
////    on the request kind and names the wake-ups a commit owes.
//// 2. `authorize` hashes the presented capability and compares it with the
////    stored hash of the one kind the operation needs.
//// 3. `store_envelope`, `fetch_batch`, `ack_envelopes`, `remove_queue`,
////    `store_blob` and `fetch_blob` then read what they need and write
////    last, each inside one transaction where they write at all.
//// 4. `open_rendezvous` checks the grant and the two caps, then
////    `draw_nameplate` picks a free nameplate; `claim_rendezvous` binds the
////    second side; `send_rendezvous`, `fetch_rendezvous` and
////    `close_rendezvous` find the live slot and the presenter's side with
////    `find_side`, which compares hashes in `side_of`.

import core/capability.{type Capability, type Read}
import core/envelope.{type Padded}
import core/id.{type Blob, type Envelope, type Id, type Queue, type Rendezvous}
import core/limits
import core/mailbox/protocol.{
  type AppendReceipt, type Request, type Response, AppendReceipt,
}
import core/nameplate.{type Nameplate}
import core/time.{type Instant}
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import mailbox/store.{
  type QueueRecord, type RendezvousRecord, type Side, type Store, Claimant,
  Opener,
}
import primitives

/// A source of cryptographically secure random bytes, injected so a test
/// can replay a sequence and production can supply the system CSPRNG. The
/// argument is the number of bytes wanted.
pub type Random =
  fn(Int) -> BitArray

/// Why a provisioning grant could not be created.
pub type GrantError {
  /// The randomness source returned the wrong number of bytes.
  BadRandomness

  /// The allowance is not positive.
  BadAllowance

  /// The database refused the write.
  Storage(error: store.Error)
}

/// Creates a provisioning grant allowing `allowance` queues and returns the
/// capability that presents it. Only the capability's hash is stored; the
/// capability itself is returned once and cannot be recovered.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(provision) = service.create_grant(store, 10, random)
/// ```
pub fn create_grant(
  store: Store,
  allowance: Int,
  random: Random,
) -> Result(Capability(provision), GrantError) {
  use <- bool.guard(allowance < 1, Error(BadAllowance))

  use provision <- result.try(
    capability.from_bytes(random(capability.capability_bytes))
    |> result.replace_error(BadRandomness),
  )

  use _ <- result.try(
    store.transaction(store, fn() {
      store.put_grant(store, hash(provision), allowance)
    })
    |> result.map_error(Storage),
  )

  Ok(provision)
}

/// An answer and the wake-ups its commit owes. Each wake is a key the
/// notification registry files waiting callers under: a queue identifier's
/// sixteen bytes after an append, or a rendezvous reader's 32-byte
/// capability hash (`rendezvous_wake`) after a send or a close. The two
/// lengths differ, so one kind of key never wakes the other.
pub type Served {
  Served(response: Response, wakes: List(BitArray))
}

/// How many nameplates `draw_nameplate` tries before it gives up and the
/// open is answered `Unavailable`. With at most `limits.max_live_rendezvous`
/// of a million nameplates taken, a draw collides less than once in a
/// thousand, so thirty-two collisions in a row means the randomness source
/// is broken, not unlucky.
pub const nameplate_draws = 32

/// Answers one request against the store with the system CSPRNG as the
/// randomness source: `serve` without the wake-ups. Never waits and never
/// raises: a storage fault is `Refused(Unavailable)`, and no answer carries
/// a capability.
///
/// ## Examples
///
/// ```gleam
/// service.handle(store, Instant(1_000), protocol.Ack(queue, read, []))
/// // -> protocol.Acked
/// ```
pub fn handle(store: Store, now: Instant, request: Request) -> Response {
  serve(store, now, primitives.random_bytes, request).response
}

/// The key a `RendezvousFetch` presenting `read` waits under, and the one a
/// send by the other side wakes: the SHA-256 of the reader's capability,
/// which is the form the mailbox already holds it in.
///
/// ## Examples
///
/// ```gleam
/// service.rendezvous_wake(read)
/// // -> <<..32 bytes..>>
/// ```
pub fn rendezvous_wake(read: Capability(Read)) -> BitArray {
  hash(read)
}

/// Answers one request against the store, drawing any random value it needs
/// from `random`, and names the wake-ups its commit owes. The storage
/// coordinator calls this and tells the notification registry after it
/// returns, so a woken caller always finds the change committed.
///
/// ## Examples
///
/// ```gleam
/// service.serve(store, Instant(1_000), primitives.random_bytes, request)
/// // -> Served(response: protocol.Acked, wakes: [])
/// ```
pub fn serve(
  store: Store,
  now: Instant,
  random: Random,
  request: Request,
) -> Served {
  // Each request kind goes to the one function that owns its rules. The
  // waits in `Fetch` and `RendezvousFetch` are ignored here by design: this
  // function never blocks.
  let outcome = case request {
    protocol.CreateQueue(provision:, queue:, read:, append:, admin:) ->
      create_queue(store, now, provision, queue, read, append, admin)
      |> result.map(unwoken)

    protocol.Append(
      queue:,
      append:,
      envelope:,
      retention_deadline:,
      ciphertext:,
    ) ->
      store_envelope(
        store,
        now,
        queue,
        append,
        envelope,
        retention_deadline,
        ciphertext,
      )
      |> result.map(appended)

    protocol.Fetch(queue:, read:, max_envelopes:, wait_seconds: _) ->
      fetch_batch(store, now, queue, read, max_envelopes)
      |> result.map(unwoken)

    protocol.Ack(queue:, read:, envelopes:) ->
      ack_envelopes(store, queue, read, envelopes)
      |> result.map(unwoken)

    protocol.DeleteQueue(queue:, admin:) ->
      remove_queue(store, queue, admin)
      |> result.map(unwoken)

    protocol.PutBlob(
      queue:,
      admin:,
      blob:,
      retrieve:,
      retention_deadline:,
      sealed:,
    ) ->
      store_blob(
        store,
        now,
        queue,
        admin,
        BlobPut(
          blob:,
          retrieve_hash: hash(retrieve),
          deadline: retention_deadline,
          sealed:,
        ),
      )
      |> result.map(unwoken)

    protocol.GetBlob(blob:, retrieve:) ->
      fetch_blob(store, now, blob, retrieve)
      |> result.map(unwoken)

    protocol.OpenRendezvous(
      provision:,
      rendezvous:,
      read:,
      append:,
      lifetime_seconds:,
    ) ->
      open_rendezvous(
        store,
        now,
        random,
        provision,
        Opening(
          rendezvous:,
          read_hash: hash(read),
          append_hash: hash(append),
          lifetime: int.clamp(lifetime_seconds, 1, limits.rendezvous_seconds),
        ),
      )
      |> result.map(unwoken)

    protocol.ClaimRendezvous(nameplate:, read:, append:) ->
      claim_rendezvous(store, now, nameplate, hash(read), hash(append))
      |> result.map(unwoken)

    protocol.RendezvousSend(rendezvous:, append:, index:, body:) ->
      send_rendezvous(store, now, rendezvous, hash(append), index, body)

    protocol.RendezvousFetch(rendezvous:, read:, after:, wait_seconds: _) ->
      fetch_rendezvous(store, now, rendezvous, hash(read), after)
      |> result.map(unwoken)

    protocol.CloseRendezvous(rendezvous:, read:) ->
      close_rendezvous(store, now, rendezvous, hash(read))
  }

  // A storage fault is reported as a refusal the client can retry, without
  // the fault's text: it is of no use to a remote caller. Nothing committed,
  // so nothing is owed a wake-up.
  case outcome {
    Ok(served) -> served
    Error(_) -> unwoken(protocol.Refused(protocol.Unavailable))
  }
}

/// An answer whose commit wakes nobody: everything but an append, a
/// rendezvous send and a rendezvous close.
fn unwoken(response: Response) -> Served {
  Served(response:, wakes: [])
}

/// An append's answer, waking the queue's long-polling fetches when an
/// envelope was stored. A repeated append that answers the original receipt
/// wakes them again, which is harmless: they fetch and find what is there.
fn appended(response: Response) -> Served {
  // Only `Appended` can add a row a fetch would return.
  case response {
    protocol.Appended(receipt:) ->
      Served(response:, wakes: [id.to_bytes(receipt.queue)])

    protocol.QueueCreated(..)
    | protocol.Batch(..)
    | protocol.Acked
    | protocol.QueueDeleted
    | protocol.BlobStored(..)
    | protocol.SealedBlob(..)
    | protocol.RendezvousOpened(..)
    | protocol.RendezvousClaimed(..)
    | protocol.RendezvousSent
    | protocol.RendezvousMessages(..)
    | protocol.RendezvousClosed
    | protocol.Refused(..) -> unwoken(response)
  }
}

/// Removes expired envelopes and blobs (releasing their quota), tombstones
/// past their deadline and expired rendezvous slots. Called periodically by
/// `mailbox/sweeper`.
///
/// ## Examples
///
/// ```gleam
/// service.sweep(store, Instant(1_000))
/// // -> Ok(SweepReport(envelopes: 0, tombstones: 0, blobs: 0, rendezvous: 0))
/// ```
pub fn sweep(
  store: Store,
  now: Instant,
) -> Result(store.SweepReport, store.Error) {
  store.sweep(store, now)
}

// ------------------------------------------------------------ CreateQueue

/// Registers a queue for the holder of a provisioning grant. The grant is
/// checked first, then the queue's existence, then the allowance, and the
/// whole sequence is one transaction so two racing creations of one
/// identifier cannot both spend allowance.
fn create_queue(
  store: Store,
  now: Instant,
  provision: Capability(a),
  queue: Id(Queue),
  read: Capability(b),
  append: Capability(c),
  admin: Capability(d),
) -> Result(Response, store.Error) {
  let wanted =
    store.QueueRecord(
      queue:,
      read_hash: hash(read),
      append_hash: hash(append),
      admin_hash: hash(admin),
      created_at: now,
      bytes_used: 0,
      capacity: limits.queue_capacity_bytes,
    )

  use <- store.transaction(store)

  use grant <- result.try(store.grant_by_hash(store, hash(provision)))

  // The grant is the only authority here, so it is checked before the
  // queue's existence is looked at: without it, `Conflict` would tell a
  // stranger which queue identifiers are taken.
  case grant {
    Some(#(stored, grant)) ->
      place_if_matching(store, wanted, hash(provision), stored, grant)

    None -> Ok(protocol.Refused(protocol.Unauthorized))
  }
}

/// Continues a creation once a grant row was found, after comparing the
/// stored hash with the presented one in constant time.
fn place_if_matching(
  store: Store,
  wanted: QueueRecord,
  presented_hash: BitArray,
  stored_hash: BitArray,
  grant: store.Grant,
) -> Result(Response, store.Error) {
  // The comparison is redundant with the lookup by hash, and kept anyway so
  // that every credential check in the mailbox is the same call.
  case primitives.constant_time_equal(stored_hash, presented_hash) {
    True -> place_queue(store, wanted, presented_hash, grant)
    False -> Ok(protocol.Refused(protocol.Unauthorized))
  }
}

/// Inserts the queue and spends one unit of allowance, or answers from the
/// queue that is already there.
fn place_queue(
  store: Store,
  wanted: QueueRecord,
  grant_hash: BitArray,
  grant: store.Grant,
) -> Result(Response, store.Error) {
  use existing <- result.try(store.queue_by_id(store, wanted.queue))

  // An existing queue decides the answer; only a free identifier reaches
  // the allowance check.
  case existing {
    // A repeat of the identical request is the same queue, so it answers
    // success without spending allowance a second time.
    Some(record) -> Ok(same_queue_or_conflict(record, wanted))

    None -> spend_allowance(store, wanted, grant_hash, grant)
  }
}

/// Creates the queue if the grant has allowance left. Queues that are later
/// deleted keep their unit spent, so a create-and-delete loop cannot turn
/// one grant into unbounded queue churn.
fn spend_allowance(
  store: Store,
  wanted: QueueRecord,
  grant_hash: BitArray,
  grant: store.Grant,
) -> Result(Response, store.Error) {
  // An exhausted grant is a quota refusal; nothing is written either way
  // until the allowance is known to cover this queue.
  case grant.queues_used < grant.allowance {
    True -> {
      use _ <- result.try(store.put_queue(store, wanted))
      use _ <- result.try(store.use_grant(store, grant_hash))
      Ok(protocol.QueueCreated(queue: wanted.queue))
    }

    False -> Ok(protocol.Refused(protocol.QuotaExceeded))
  }
}

/// Whether a repeated `CreateQueue` is the same request: all three stored
/// hashes must match. Anything else under the same identifier is a conflict.
fn same_queue_or_conflict(
  record: QueueRecord,
  wanted: QueueRecord,
) -> Response {
  let same =
    primitives.constant_time_equal(record.read_hash, wanted.read_hash)
    && primitives.constant_time_equal(record.append_hash, wanted.append_hash)
    && primitives.constant_time_equal(record.admin_hash, wanted.admin_hash)

  // Identical content is success; differing content under one identifier
  // must never be merged or overwritten.
  case same {
    True -> protocol.QueueCreated(queue: wanted.queue)
    False -> protocol.Refused(protocol.Conflict)
  }
}

// ----------------------------------------------------------------- Append

/// Authorizes an append and stores the envelope. The check, the lookup of
/// what is already known and the insert are one transaction, and the
/// receipt is returned only after it commits.
fn store_envelope(
  store: Store,
  now: Instant,
  queue: Id(Queue),
  presented: Capability(a),
  envelope: Id(Envelope),
  deadline: Instant,
  ciphertext: Padded,
) -> Result(Response, store.Error) {
  use <- store.transaction(store)

  use found <- result.try(authorize(
    store,
    queue,
    fn(record) { record.append_hash },
    presented,
  ))

  // No existence oracle: a missing queue and a wrong capability answer
  // alike.
  case found {
    None -> Ok(protocol.Refused(protocol.Unauthorized))
    Some(record) ->
      append_to(store, now, record, envelope, deadline, ciphertext)
  }
}

/// Appends to an authorized queue: answers from the stored envelope or its
/// tombstone when the identifier is known, and inserts only when it is new.
fn append_to(
  store: Store,
  now: Instant,
  record: QueueRecord,
  envelope: Id(Envelope),
  deadline: Instant,
  ciphertext: Padded,
) -> Result(Response, store.Error) {
  let bytes = envelope.to_wire(ciphertext)
  let digest = primitives.sha256(bytes)

  use stored <- result.try(store.envelope_record(store, record.queue, envelope))
  use buried <- result.try(store.tombstone(store, record.queue, envelope))

  // What is already known answers first, even when the retry's own deadline
  // would now be refused: the original acceptance stands (spec §6.4), and
  // after an acknowledgment only the tombstone remembers it.
  case stored, buried {
    Some(known), _ ->
      Ok(replay(record, envelope, digest, known.digest, known.deadline))

    None, Some(known) ->
      Ok(replay(record, envelope, digest, known.digest, known.deadline))

    None, None -> insert_new(store, now, record, envelope, deadline, bytes)
  }
}

/// The answer to an append for an identifier the mailbox already knows: the
/// original receipt if the digest matches, a conflict if it does not.
fn replay(
  record: QueueRecord,
  envelope: Id(Envelope),
  digest: BitArray,
  known_digest: BitArray,
  deadline: Instant,
) -> Response {
  // Same bytes are a retry and get the first answer again; different bytes
  // under one identifier are a conflict, whatever became of the original.
  case primitives.constant_time_equal(digest, known_digest) {
    True ->
      protocol.Appended(receipt: AppendReceipt(
        queue: record.queue,
        envelope:,
        digest:,
        retention_deadline: deadline,
      ))

    False -> protocol.Refused(protocol.Conflict)
  }
}

/// Accepts a never-seen envelope if its deadline is inside the retention
/// window and its bytes fit the queue's remaining quota. Both checks come
/// before the write, so a refusal changes nothing.
fn insert_new(
  store: Store,
  now: Instant,
  record: QueueRecord,
  envelope: Id(Envelope),
  deadline: Instant,
  bytes: BitArray,
) -> Result(Response, store.Error) {
  let latest = time.add(now, limits.message_retention_seconds)
  let size = bit_array.byte_size(bytes)

  let deadline_ok =
    deadline.unix_seconds > now.unix_seconds
    && deadline.unix_seconds <= latest.unix_seconds

  // The deadline is judged before the quota, so a client with a bad clock
  // is told so rather than being told the queue is full.
  case deadline_ok, record.bytes_used + size <= record.capacity {
    False, _ -> Ok(protocol.Refused(protocol.BadDeadline))

    True, False -> Ok(protocol.Refused(protocol.QuotaExceeded))

    True, True -> {
      let digest = primitives.sha256(bytes)

      use _ <- result.try(store.put_envelope(
        store,
        record.queue,
        envelope,
        digest,
        deadline,
        bytes,
      ))

      Ok(
        protocol.Appended(receipt: receipt(record, envelope, digest, deadline)),
      )
    }
  }
}

/// The receipt for an envelope accepted now, binding queue, envelope,
/// content digest and the accepted deadline (spec §6.4).
fn receipt(
  record: QueueRecord,
  envelope: Id(Envelope),
  digest: BitArray,
  deadline: Instant,
) -> AppendReceipt {
  AppendReceipt(
    queue: record.queue,
    envelope:,
    digest:,
    retention_deadline: deadline,
  )
}

// ------------------------------------------------------------------ Fetch

/// Authorizes a fetch and returns up to one batch of live envelopes in
/// queue order. Read-only, so it opens no transaction.
fn fetch_batch(
  store: Store,
  now: Instant,
  queue: Id(Queue),
  presented: Capability(a),
  max_envelopes: Int,
) -> Result(Response, store.Error) {
  use found <- result.try(authorize(
    store,
    queue,
    fn(record) { record.read_hash },
    presented,
  ))

  // Authorization decides before anything is read from the queue.
  case found {
    None -> Ok(protocol.Refused(protocol.Unauthorized))

    Some(record) -> {
      // A request for fewer than one envelope is read as one: "at most
      // zero" is never what a long-polling client means.
      let count = int.clamp(max_envelopes, 1, limits.fetch_batch_envelopes)

      use rows <- result.try(store.live_envelopes(
        store,
        record.queue,
        now,
        count,
      ))

      Ok(protocol.Batch(envelopes: within_byte_budget(rows, 0)))
    }
  }
}

/// The longest prefix of `rows` whose ciphertext fits in
/// `limits.fetch_batch_bytes`. It stops at the first envelope that does not
/// fit rather than skipping it, so the batch is always a prefix of the
/// queue's order and an acknowledgment of it never leaves a gap behind an
/// envelope the client has not seen.
fn within_byte_budget(
  rows: List(envelope.StoredEnvelope),
  used: Int,
) -> List(envelope.StoredEnvelope) {
  // Walk the queue's order, spending the byte budget as each envelope is
  // taken.
  case rows {
    [] -> []

    [row, ..rest] -> {
      let total = used + bit_array.byte_size(envelope.to_wire(row.ciphertext))

      // The first envelope that would overspend ends the batch.
      case total <= limits.fetch_batch_bytes {
        True -> [row, ..within_byte_budget(rest, total)]
        False -> []
      }
    }
  }
}

// -------------------------------------------------------------------- Ack

/// Authorizes an acknowledgment and deletes exactly the named envelopes,
/// each leaving a tombstone, in one transaction. An identifier that is not
/// stored, or was already acknowledged, changes nothing.
fn ack_envelopes(
  store: Store,
  queue: Id(Queue),
  presented: Capability(a),
  envelopes: List(Id(Envelope)),
) -> Result(Response, store.Error) {
  use <- store.transaction(store)

  use found <- result.try(authorize(
    store,
    queue,
    fn(record) { record.read_hash },
    presented,
  ))

  // Authorization decides first, then the size of the list, then the
  // deletion. The size test stops at the bound instead of counting a list
  // an attacker made long.
  let within_bound = case list.drop(envelopes, limits.fetch_batch_envelopes) {
    [] -> True
    [_, ..] -> False
  }

  // The three outcomes, in the order they are decided.
  case found, within_bound {
    None, _ -> Ok(protocol.Refused(protocol.Unauthorized))

    // A client only ever acknowledges what one fetch returned, so a longer
    // list is not honest traffic and is refused rather than looped over.
    Some(_), False -> Ok(protocol.Refused(protocol.TooLarge))

    Some(record), True -> {
      use _ <- result.try(
        list.try_each(envelopes, fn(envelope) {
          store.remove_envelope(store, record.queue, envelope)
          |> result.replace(Nil)
        }),
      )

      Ok(protocol.Acked)
    }
  }
}

// ------------------------------------------------------------ DeleteQueue

/// Authorizes the queue's administrator and deletes the queue with its
/// envelopes and tombstones. A repeated delete finds no queue and so reads
/// as `Unauthorized`, the same answer a stranger gets.
fn remove_queue(
  store: Store,
  queue: Id(Queue),
  presented: Capability(a),
) -> Result(Response, store.Error) {
  use <- store.transaction(store)

  use found <- result.try(authorize(
    store,
    queue,
    fn(record) { record.admin_hash },
    presented,
  ))

  // Only the administrator capability reaches the deletion.
  case found {
    None -> Ok(protocol.Refused(protocol.Unauthorized))

    Some(record) -> {
      use _ <- result.try(store.delete_queue(store, record.queue))
      Ok(protocol.QueueDeleted)
    }
  }
}

// ------------------------------------------------------------------ blobs

/// What a `PutBlob` asks to store, with its capability already hashed.
type BlobPut {
  BlobPut(
    blob: Id(Blob),
    retrieve_hash: BitArray,
    deadline: Instant,
    sealed: BitArray,
  )
}

/// Authorizes a blob's store against the paying queue's administrator and
/// places it. The check, the lookup of the locator and the insert are one
/// transaction.
fn store_blob(
  store: Store,
  now: Instant,
  queue: Id(Queue),
  presented: Capability(a),
  put: BlobPut,
) -> Result(Response, store.Error) {
  use <- store.transaction(store)

  use found <- result.try(authorize(
    store,
    queue,
    fn(record) { record.admin_hash },
    presented,
  ))

  // Only the queue's administrator may spend its quota on a blob, and a
  // missing queue answers like a wrong capability.
  case found {
    None -> Ok(protocol.Refused(protocol.Unauthorized))
    Some(record) -> place_blob(store, now, record, put)
  }
}

/// Answers from the locator's existing row when it is taken, and inserts
/// only when it is free. A retry of the identical request is the same blob
/// whatever its deadline now says, as for an envelope (spec §6.4).
fn place_blob(
  store: Store,
  now: Instant,
  record: QueueRecord,
  put: BlobPut,
) -> Result(Response, store.Error) {
  let digest = primitives.sha256(put.sealed)

  use existing <- result.try(store.blob_record(store, put.blob))

  // A taken locator decides the answer before any bound is looked at.
  case existing {
    Some(known) -> {
      let same =
        known.queue == record.queue
        && primitives.constant_time_equal(
          known.retrieve_hash,
          put.retrieve_hash,
        )
        && primitives.constant_time_equal(known.digest, digest)

      // Same request: the original stands. Anything else under the same
      // locator must never replace it.
      case same {
        True -> Ok(protocol.BlobStored(blob: put.blob))
        False -> Ok(protocol.Refused(protocol.Conflict))
      }
    }

    None -> insert_blob(store, now, record, put, digest)
  }
}

/// Stores a new blob if it fits the size bound, its deadline is inside the
/// retention window and its bytes fit the queue's quota. Every check comes
/// before the write, so a refusal changes nothing.
fn insert_blob(
  store: Store,
  now: Instant,
  record: QueueRecord,
  put: BlobPut,
  digest: BitArray,
) -> Result(Response, store.Error) {
  let size = bit_array.byte_size(put.sealed)
  let latest = time.add(now, limits.message_retention_seconds)

  let deadline_ok =
    put.deadline.unix_seconds > now.unix_seconds
    && put.deadline.unix_seconds <= latest.unix_seconds

  // Size first (the codec already bounds it, but `handle` has other
  // callers), then the deadline, then the quota, as for an envelope.
  case
    size <= limits.max_ticket_blob_bytes,
    deadline_ok,
    record.bytes_used + size <= record.capacity
  {
    False, _, _ -> Ok(protocol.Refused(protocol.TooLarge))

    True, False, _ -> Ok(protocol.Refused(protocol.BadDeadline))

    True, True, False -> Ok(protocol.Refused(protocol.QuotaExceeded))

    True, True, True -> {
      use _ <- result.try(store.put_blob(
        store,
        record.queue,
        put.blob,
        put.retrieve_hash,
        digest,
        put.deadline,
        put.sealed,
      ))

      Ok(protocol.BlobStored(blob: put.blob))
    }
  }
}

/// Returns a live blob to whoever presents its retrieve capability.
/// Read-only, so it opens no transaction, and it deletes nothing: a joiner
/// that crashed after a fetch may fetch again.
fn fetch_blob(
  store: Store,
  now: Instant,
  blob: Id(Blob),
  presented: Capability(a),
) -> Result(Response, store.Error) {
  use found <- result.map(store.live_blob(store, blob, now))

  // Missing, expired and a wrong capability are one answer, so the mailbox
  // is no oracle for which locators exist.
  case found {
    Some(#(stored, sealed)) ->
      case primitives.constant_time_equal(stored, hash(presented)) {
        True -> protocol.SealedBlob(sealed:)
        False -> protocol.Refused(protocol.Unauthorized)
      }

    None -> protocol.Refused(protocol.Unauthorized)
  }
}

// ------------------------------------------------------------- rendezvous

/// What an `OpenRendezvous` asks for, with its capabilities already hashed
/// and its lifetime already clamped.
type Opening {
  Opening(
    rendezvous: Id(Rendezvous),
    read_hash: BitArray,
    append_hash: BitArray,
    lifetime: Int,
  )
}

/// Opens a slot for the holder of a provisioning grant (ADR-016). The grant
/// is checked first, as for `CreateQueue`, so a stranger cannot learn which
/// identifiers are taken; then expired slots are purged, the identifier is
/// looked up, the two caps are checked and a nameplate is drawn, all in one
/// transaction.
fn open_rendezvous(
  store: Store,
  now: Instant,
  random: Random,
  provision: Capability(a),
  opening: Opening,
) -> Result(Response, store.Error) {
  let presented = hash(provision)

  use <- store.transaction(store)

  use grant <- result.try(store.grant_by_hash(store, presented))

  // The grant is the only authority an open has. The comparison repeats
  // the lookup by hash so every credential check is the same call.
  case grant {
    Some(#(stored, _)) ->
      case primitives.constant_time_equal(stored, presented) {
        True -> place_rendezvous(store, now, random, presented, opening)
        False -> Ok(protocol.Refused(protocol.Unauthorized))
      }

    None -> Ok(protocol.Refused(protocol.Unauthorized))
  }
}

/// Answers a repeated open from the slot already under its identifier, or
/// opens a new one. Expired slots are purged first, so an identifier whose
/// slot expired is free again and a nameplate is only ever compared with
/// live ones.
fn place_rendezvous(
  store: Store,
  now: Instant,
  random: Random,
  grant_hash: BitArray,
  opening: Opening,
) -> Result(Response, store.Error) {
  use _ <- result.try(store.purge_expired_rendezvous(store, now))
  use existing <- result.try(store.live_rendezvous(
    store,
    opening.rendezvous,
    now,
  ))

  // A taken identifier decides the answer before any quota is counted, as
  // a repeated `CreateQueue` does not spend allowance twice.
  case existing {
    Some(record) -> Ok(same_rendezvous_or_conflict(record, grant_hash, opening))
    None -> admit_rendezvous(store, now, random, grant_hash, opening)
  }
}

/// Whether a repeated open is the identical request: the same grant, the
/// same two capabilities and the same clamped lifetime answer the slot's
/// nameplate and its current expiry, which a claim may have shortened.
/// Anything else under the identifier is a conflict.
fn same_rendezvous_or_conflict(
  record: RendezvousRecord,
  grant_hash: BitArray,
  opening: Opening,
) -> Response {
  let same =
    primitives.constant_time_equal(record.grant_hash, grant_hash)
    && primitives.constant_time_equal(
      record.opener_read_hash,
      opening.read_hash,
    )
    && primitives.constant_time_equal(
      record.opener_append_hash,
      opening.append_hash,
    )
    && record.lifetime == opening.lifetime

  // Identical content is the same slot; different content must never
  // replace it.
  case same {
    True ->
      protocol.RendezvousOpened(
        nameplate: record.nameplate,
        expires_at: record.expires_at,
      )

    False -> protocol.Refused(protocol.Conflict)
  }
}

/// Opens a new slot if the grant and the mailbox both have room. The grant's
/// cap comes first so a holder at its own limit is told so even when the
/// mailbox is also full; both are `QuotaExceeded`.
fn admit_rendezvous(
  store: Store,
  now: Instant,
  random: Random,
  grant_hash: BitArray,
  opening: Opening,
) -> Result(Response, store.Error) {
  use counts <- result.try(store.rendezvous_counts(store, grant_hash, now))

  let room =
    counts.held < limits.max_grant_rendezvous
    && counts.live < limits.max_live_rendezvous

  // The mailbox-wide cap is what keeps the nameplate space sparse, so a
  // blind claim hits a live slot at most once in a thousand (ADR-016).
  case room {
    False -> Ok(protocol.Refused(protocol.QuotaExceeded))
    True -> open_with_nameplate(store, now, random, grant_hash, opening)
  }
}

/// Draws a free nameplate and inserts the slot under it. A source that
/// cannot produce a free nameplate within `nameplate_draws` tries answers
/// `Unavailable` and writes nothing.
fn open_with_nameplate(
  store: Store,
  now: Instant,
  random: Random,
  grant_hash: BitArray,
  opening: Opening,
) -> Result(Response, store.Error) {
  use drawn <- result.try(draw_nameplate(store, random, nameplate_draws))

  // The draw is the last check; only a nameplate in hand reaches the write.
  case drawn {
    None -> Ok(protocol.Refused(protocol.Unavailable))

    Some(plate) -> {
      let expires_at = time.add(now, opening.lifetime)

      use _ <- result.try(store.put_rendezvous(
        store,
        store.RendezvousRecord(
          rendezvous: opening.rendezvous,
          nameplate: plate,
          grant_hash:,
          opener_read_hash: opening.read_hash,
          opener_append_hash: opening.append_hash,
          claim: store.Unclaimed,
          lifetime: opening.lifetime,
          expires_at:,
        ),
      ))

      Ok(protocol.RendezvousOpened(nameplate: plate, expires_at:))
    }
  }
}

/// Draws a nameplate uniformly at random among those no live slot holds,
/// by rejection: a 32-bit draw at or above the largest multiple of the
/// nameplate space is thrown away so the remainder carries no modulo bias,
/// and a nameplate a live slot holds is thrown away so the result is
/// uniform over the free ones. Each throw costs one of `remaining` tries.
fn draw_nameplate(
  store: Store,
  random: Random,
  remaining: Int,
) -> Result(Option(Nameplate), store.Error) {
  use <- bool.guard(remaining < 1, Ok(None))

  let space = nameplate_space()
  let unbiased = draw_space / space * space

  // A draw of the wrong size or in the biased tail is no nameplate at all.
  case random(4) {
    <<value:size(32)>> if value < unbiased ->
      try_nameplate(store, random, remaining, value % space)

    _ -> draw_nameplate(store, random, remaining - 1)
  }
}

/// Keeps a drawn nameplate if no live slot holds it, or draws again.
fn try_nameplate(
  store: Store,
  random: Random,
  remaining: Int,
  value: Int,
) -> Result(Option(Nameplate), store.Error) {
  // The value is below `nameplate_space()`, so `from_int` accepts it; its
  // `Error` arm is unreachable and is spent as a failed try all the same.
  case nameplate.from_int(value) {
    Ok(plate) -> {
      use taken <- result.try(store.nameplate_taken(store, plate))

      // A collision with a live slot is the redraw the uniformity needs.
      case taken {
        False -> Ok(Some(plate))
        True -> draw_nameplate(store, random, remaining - 1)
      }
    }

    Error(Nil) -> draw_nameplate(store, random, remaining - 1)
  }
}

/// How many values a draw of four random bytes can take.
const draw_space = 0x1_0000_0000

/// How many nameplates there are: ten to the `limits.nameplate_digits`.
fn nameplate_space() -> Int {
  list.fold(list.repeat(10, limits.nameplate_digits), 1, int.multiply)
}

/// Binds a claimant to the live slot the nameplate names. The first claim
/// stands: once bound, only the identical pair is answered, and every other
/// claim gets the same `Unauthorized` an unknown or expired nameplate gets.
fn claim_rendezvous(
  store: Store,
  now: Instant,
  plate: Nameplate,
  read_hash: BitArray,
  append_hash: BitArray,
) -> Result(Response, store.Error) {
  use <- store.transaction(store)

  use found <- result.try(store.live_rendezvous_at(store, plate, now))

  // Unknown and expired nameplates are one answer, before the claim is
  // looked at.
  case found {
    None -> Ok(protocol.Refused(protocol.Unauthorized))

    Some(record) ->
      case record.claim {
        store.Unclaimed ->
          bind_claimant(store, now, record, read_hash, append_hash)

        store.Claimed(read_hash: bound_read, append_hash: bound_append) ->
          Ok(
            repeat_claim(record, #(bound_read, bound_append), #(
              read_hash,
              append_hash,
            )),
          )
      }
  }
}

/// Binds the first claimant and shortens the slot's life to the earlier of
/// its expiry and `limits.rendezvous_claimed_seconds` from now. A claimant
/// presenting either of the opener's own capabilities is refused: the
/// mailbox could no longer tell the two sides apart.
fn bind_claimant(
  store: Store,
  now: Instant,
  record: RendezvousRecord,
  read_hash: BitArray,
  append_hash: BitArray,
) -> Result(Response, store.Error) {
  let collides =
    primitives.constant_time_equal(record.opener_read_hash, read_hash)
    || primitives.constant_time_equal(record.opener_append_hash, append_hash)

  let shortened = time.add(now, limits.rendezvous_claimed_seconds)

  // A claim only ever shortens a slot's life: a claim late in the opening
  // lifetime keeps the earlier expiry it already had.
  let expires_at = case time.is_past(shortened, deadline: record.expires_at) {
    True -> record.expires_at
    False -> shortened
  }

  // Only a pair distinct from the opener's may become the second side.
  case collides {
    True -> Ok(protocol.Refused(protocol.Unauthorized))

    False -> {
      use _ <- result.try(store.claim_rendezvous(
        store,
        record.rendezvous,
        read_hash,
        append_hash,
        expires_at,
      ))

      Ok(protocol.RendezvousClaimed(rendezvous: record.rendezvous, expires_at:))
    }
  }
}

/// The answer to a claim on a slot already claimed: the identical pair is
/// the first claim's retry and gets its answer again, and anything else is
/// refused without touching the slot.
fn repeat_claim(
  record: RendezvousRecord,
  bound: #(BitArray, BitArray),
  presented: #(BitArray, BitArray),
) -> Response {
  let same =
    primitives.constant_time_equal(bound.0, presented.0)
    && primitives.constant_time_equal(bound.1, presented.1)

  // A second claimant must learn nothing, not even that the slot exists.
  case same {
    True ->
      protocol.RendezvousClaimed(
        rendezvous: record.rendezvous,
        expires_at: record.expires_at,
      )

    False -> protocol.Refused(protocol.Unauthorized)
  }
}

/// Stores one message under its sender's side, and wakes the other side's
/// waiting fetches. The side is whichever stored append hash the presented
/// capability matches; the bounds come after authority, so a stranger
/// learns nothing from them.
fn send_rendezvous(
  store: Store,
  now: Instant,
  rendezvous: Id(Rendezvous),
  append_hash: BitArray,
  index: Int,
  body: BitArray,
) -> Result(Served, store.Error) {
  use <- store.transaction(store)

  use sender <- result.try(find_side(
    store,
    rendezvous,
    now,
    Appending,
    append_hash,
  ))

  // A missing or expired slot and a capability of neither side are one
  // answer.
  case sender {
    None -> Ok(unwoken(protocol.Refused(protocol.Unauthorized)))
    Some(#(record, side)) -> file_message(store, record, side, index, body)
  }
}

/// Checks a sender's message against the per-side bounds and files it, or
/// answers from the message already filed under its index.
fn file_message(
  store: Store,
  record: RendezvousRecord,
  side: Side,
  index: Int,
  body: BitArray,
) -> Result(Served, store.Error) {
  let fits = bit_array.byte_size(body) <= limits.max_rendezvous_body_bytes
  let in_range = index >= 0 && index < limits.max_rendezvous_messages

  // Size first (the codec already bounds it, but `serve` has other callers),
  // then the index, which is what bounds a side's messages.
  case fits, in_range {
    False, _ -> Ok(unwoken(protocol.Refused(protocol.TooLarge)))

    True, False -> Ok(unwoken(protocol.Refused(protocol.QuotaExceeded)))

    True, True -> {
      let digest = primitives.sha256(body)

      use stored <- result.try(store.rendezvous_message_digest(
        store,
        record.rendezvous,
        side,
        index,
      ))

      // The same bytes again are a retry and answer as the first did, waking
      // the reader again in case the first wake-up was lost. Different bytes
      // under a filed index never replace them.
      case stored {
        Some(known) ->
          case primitives.constant_time_equal(known, digest) {
            True -> Ok(sent(record, side))
            False -> Ok(unwoken(protocol.Refused(protocol.Conflict)))
          }

        None -> {
          use _ <- result.try(store.put_rendezvous_message(
            store,
            record.rendezvous,
            side,
            index,
            digest,
            body,
          ))

          Ok(sent(record, side))
        }
      }
    }
  }
}

/// A send's answer, waking whoever reads what `side` sent: the other side,
/// if it is there yet.
fn sent(record: RendezvousRecord, side: Side) -> Served {
  Served(response: protocol.RendezvousSent, wakes: readers(record, other(side)))
}

/// The wake keys of whoever reads on `side`: the opener's read hash, or the
/// claimant's once the slot is claimed and nothing before.
fn readers(record: RendezvousRecord, side: Side) -> List(BitArray) {
  case side, record.claim {
    Opener, _ -> [record.opener_read_hash]
    Claimant, store.Claimed(read_hash:, ..) -> [read_hash]
    Claimant, store.Unclaimed -> []
  }
}

/// Returns the other side's messages past `after`. Read-only, so it opens no
/// transaction; a fetch on a slot nobody has claimed is the opener's to
/// make, and it answers an empty list.
fn fetch_rendezvous(
  store: Store,
  now: Instant,
  rendezvous: Id(Rendezvous),
  read_hash: BitArray,
  after: Int,
) -> Result(Response, store.Error) {
  use reader <- result.try(find_side(store, rendezvous, now, Reading, read_hash))

  // The reader's side is known only from its capability, and it is the
  // other side's messages it is owed, never its own.
  case reader {
    None -> Ok(protocol.Refused(protocol.Unauthorized))

    Some(#(_, side)) -> {
      use messages <- result.try(store.rendezvous_messages(
        store,
        rendezvous,
        other(side),
        int.max(after, -1),
      ))

      Ok(protocol.RendezvousMessages(messages:))
    }
  }
}

/// Deletes a slot for either side's reader, and wakes both sides' waiting
/// fetches so they learn at once that it is gone.
fn close_rendezvous(
  store: Store,
  now: Instant,
  rendezvous: Id(Rendezvous),
  read_hash: BitArray,
) -> Result(Served, store.Error) {
  use <- store.transaction(store)

  use closer <- result.try(find_side(store, rendezvous, now, Reading, read_hash))

  // A repeated close finds no slot and reads as `Unauthorized`, the answer a
  // stranger gets.
  case closer {
    None -> Ok(unwoken(protocol.Refused(protocol.Unauthorized)))

    Some(#(record, _)) -> {
      use _ <- result.try(store.delete_rendezvous(store, record.rendezvous))

      let wakes =
        list.append(readers(record, Opener), readers(record, Claimant))

      Ok(Served(response: protocol.RendezvousClosed, wakes:))
    }
  }
}

/// Which of a side's two capabilities a request presents: a fetch or a
/// close reads, a send appends.
type Authority {
  Reading
  Appending
}

/// The live slot and the side whose capability of kind `authority` hashes
/// to `presented`, or `None` when the slot is missing, expired, or matches
/// neither side. The three are one answer, so no caller can tell them
/// apart.
fn find_side(
  store: Store,
  rendezvous: Id(Rendezvous),
  now: Instant,
  authority: Authority,
  presented: BitArray,
) -> Result(Option(#(RendezvousRecord, Side)), store.Error) {
  use found <- result.map(store.live_rendezvous(store, rendezvous, now))

  option.then(found, fn(record) {
    side_of(record, authority, presented)
    |> option.map(fn(side) { #(record, side) })
  })
}

/// Which side a presented hash belongs to: the opener's stored hash of the
/// kind in question, or the claimant's when the slot is claimed. Both
/// comparisons run in constant time, and an unclaimed slot has only one
/// side to match.
fn side_of(
  record: RendezvousRecord,
  authority: Authority,
  presented: BitArray,
) -> Option(Side) {
  let #(opener, claimant) = stored_hashes(record, authority)
  let is_opener = primitives.constant_time_equal(opener, presented)

  // An unclaimed slot has no second hash to compare with.
  let is_claimant = case claimant {
    Some(stored) -> primitives.constant_time_equal(stored, presented)
    None -> False
  }

  // A claim that repeats an opener capability is refused at claim time, so
  // the two cannot both match.
  case is_opener, is_claimant {
    True, _ -> Some(Opener)
    False, True -> Some(Claimant)
    False, False -> None
  }
}

/// The opener's stored hash of the kind `authority` names, and the
/// claimant's once the slot is claimed.
fn stored_hashes(
  record: RendezvousRecord,
  authority: Authority,
) -> #(BitArray, Option(BitArray)) {
  case authority, record.claim {
    Reading, store.Claimed(read_hash:, ..) -> #(
      record.opener_read_hash,
      Some(read_hash),
    )
    Appending, store.Claimed(append_hash:, ..) -> #(
      record.opener_append_hash,
      Some(append_hash),
    )
    Reading, store.Unclaimed -> #(record.opener_read_hash, None)
    Appending, store.Unclaimed -> #(record.opener_append_hash, None)
  }
}

/// The side whose messages a reader on `side` is owed.
fn other(side: Side) -> Side {
  case side {
    Opener -> Claimant
    Claimant -> Opener
  }
}

// ---------------------------------------------------------------- helpers

/// The queue when it exists and `presented` hashes to the stored hash that
/// `select` picks, which is how one function serves read, append and admin
/// without letting any of them stand in for another.
fn authorize(
  store: Store,
  queue: Id(Queue),
  select: fn(QueueRecord) -> BitArray,
  presented: Capability(a),
) -> Result(Option(QueueRecord), store.Error) {
  use found <- result.map(store.queue_by_id(store, queue))

  // A missing queue and a failed comparison are both `None`, so callers
  // cannot tell them apart.
  case found {
    Some(record) -> matching(record, select(record), presented)
    None -> None
  }
}

/// The record if the presented capability hashes to `stored`.
fn matching(
  record: QueueRecord,
  stored: BitArray,
  presented: Capability(a),
) -> Option(QueueRecord) {
  case primitives.constant_time_equal(stored, hash(presented)) {
    True -> Some(record)
    False -> None
  }
}

/// SHA-256 of a capability, the only form in which it is stored or
/// compared.
fn hash(capability: Capability(a)) -> BitArray {
  // The capability is exposed only to be hashed; the hash is what is stored
  // and compared, and the bytes go no further than this call.
  primitives.sha256(capability.expose(capability))
}

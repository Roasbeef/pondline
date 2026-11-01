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
//// - A refusal is an ordinary answer, not a failure: every check precedes
////   the first write, so a refused request commits an empty transaction.
////   Only a storage fault rolls back, and it surfaces as `Unavailable`.
////
//// `handle` never waits. `Fetch.wait_seconds` is honored by `mailbox/node`,
//// which can hold a caller without holding the database.
////
//// ## Flow
////
//// 1. `handle` dispatches on the request kind.
//// 2. `authorize` hashes the presented capability and compares it with the
////    stored hash of the one kind the operation needs.
//// 3. `store_envelope`, `fetch_batch`, `ack_envelopes`, `remove_queue`,
////    `store_blob` and `fetch_blob` then read what they need and write
////    last, each inside one transaction where they write at all.

import core/capability.{type Capability}
import core/envelope.{type Padded}
import core/id.{type Blob, type Envelope, type Id, type Queue}
import core/limits
import core/mailbox/protocol.{
  type AppendReceipt, type Request, type Response, AppendReceipt,
}
import core/time.{type Instant}
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import mailbox/store.{type QueueRecord, type Store}
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

/// Answers one request against the store. Never waits and never raises: a
/// storage fault is `Refused(Unavailable)`, and no answer carries a
/// capability.
///
/// ## Examples
///
/// ```gleam
/// service.handle(store, Instant(1_000), protocol.Ack(queue, read, []))
/// // -> protocol.Acked
/// ```
pub fn handle(store: Store, now: Instant, request: Request) -> Response {
  // Each request kind goes to the one function that owns its rules. The
  // wait in `Fetch` is ignored here by design: this function never blocks.
  let outcome = case request {
    protocol.CreateQueue(provision:, queue:, read:, append:, admin:) ->
      create_queue(store, now, provision, queue, read, append, admin)

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

    protocol.Fetch(queue:, read:, max_envelopes:, wait_seconds: _) ->
      fetch_batch(store, now, queue, read, max_envelopes)

    protocol.Ack(queue:, read:, envelopes:) ->
      ack_envelopes(store, queue, read, envelopes)

    protocol.DeleteQueue(queue:, admin:) -> remove_queue(store, queue, admin)

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

    protocol.GetBlob(blob:, retrieve:) -> fetch_blob(store, now, blob, retrieve)
  }

  // A storage fault is reported as a refusal the client can retry, without
  // the fault's text: it is of no use to a remote caller.
  case outcome {
    Ok(response) -> response
    Error(_) -> protocol.Refused(protocol.Unavailable)
  }
}

/// Removes expired envelopes (releasing their quota) and tombstones past
/// their deadline. Called periodically by `mailbox/sweeper`.
///
/// ## Examples
///
/// ```gleam
/// service.sweep(store, Instant(1_000))
/// // -> Ok(SweepReport(envelopes: 0, tombstones: 0, blobs: 0))
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

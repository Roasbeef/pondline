//// The mailbox protocol as typed commands (spec §6.2).
////
//// The network binding is HTTP/1.1 with TLV bodies today, but storage and
//// policy never see HTTP: a request is decoded into one of these values,
//// handled, and answered with a `Response`. A later carrier, such as
//// Lightning onion messages, decodes into the same values (spec §6.2,
//// "the extension point for a later non-Tor carrier").
////
//// Each request carries the one capability its operation needs, typed by
//// authority, so a request that presents the wrong kind of credential is
//// not a request the type admits. The queue's creator chooses the queue
//// identifier and all three of its capabilities, which makes `CreateQueue`
//// idempotent without a server allocation: the same request twice is the
//// same queue, and a different request under the same identifier is a
//// conflict.

import core/capability.{
  type Admin, type Append, type Capability, type Provision, type Read,
  type Retrieve,
}
import core/envelope.{type Padded, type StoredEnvelope}
import core/id.{type Blob, type Envelope, type Id, type Queue}
import core/time.{type Instant}

/// The protocol version this build speaks.
pub const version = 1

/// A typed mailbox command.
pub type Request {
  /// Register a queue under a provisioning allowance. Idempotent for an
  /// identical request.
  CreateQueue(
    provision: Capability(Provision),
    queue: Id(Queue),
    read: Capability(Read),
    append: Capability(Append),
    admin: Capability(Admin),
  )

  /// Store one immutable ciphertext (spec §6.4). The same bytes under the
  /// same envelope identifier return the original receipt; different bytes
  /// are a conflict.
  Append(
    queue: Id(Queue),
    append: Capability(Append),
    envelope: Id(Envelope),
    retention_deadline: Instant,
    ciphertext: Padded,
  )

  /// Return up to `max_envelopes` stored envelopes without deleting them,
  /// waiting up to `wait_seconds` for one to arrive (spec §6.5). Both are
  /// clamped to `core/limits` by the mailbox.
  Fetch(
    queue: Id(Queue),
    read: Capability(Read),
    wait_seconds: Int,
    max_envelopes: Int,
  )

  /// Delete exactly these envelopes after durable local processing. Never
  /// a cursor: an envelope not named is never deleted.
  Ack(queue: Id(Queue), read: Capability(Read), envelopes: List(Id(Envelope)))

  /// Delete the queue and everything in it.
  DeleteQueue(queue: Id(Queue), admin: Capability(Admin))

  /// Hold a sealed invitation for a ticket (ADR-009) until
  /// `retention_deadline`, charged to `queue`'s quota and authorized by its
  /// administrator. The mailbox keeps only the hash of `retrieve`. The same
  /// request twice is the same blob; a different one under the same
  /// locator is a conflict.
  PutBlob(
    queue: Id(Queue),
    admin: Capability(Admin),
    blob: Id(Blob),
    retrieve: Capability(Retrieve),
    retention_deadline: Instant,
    sealed: BitArray,
  )

  /// Return the sealed invitation stored under `blob`, without deleting it:
  /// a joiner that crashes after fetching can fetch again (ADR-009).
  GetBlob(blob: Id(Blob), retrieve: Capability(Retrieve))
}

/// The mailbox's evidence that it accepted an envelope (spec §6.4). It
/// binds the queue, envelope, content digest and accepted deadline, and is
/// evidence of acceptance, not of honesty.
pub type AppendReceipt {
  AppendReceipt(
    queue: Id(Queue),
    envelope: Id(Envelope),
    digest: BitArray,
    retention_deadline: Instant,
  )
}

/// A typed mailbox answer.
pub type Response {
  /// The queue exists with the requested capabilities.
  QueueCreated(queue: Id(Queue))

  /// The envelope is durably stored.
  Appended(receipt: AppendReceipt)

  /// Stored envelopes, oldest first, within the batch limits. Possibly
  /// empty after a long poll that saw nothing.
  Batch(envelopes: List(StoredEnvelope))

  /// The named envelopes are gone. Repeated acknowledgments are harmless.
  Acked

  /// The queue is gone.
  QueueDeleted

  /// The sealed invitation is durably stored under this locator.
  BlobStored(blob: Id(Blob))

  /// The sealed invitation stored under the requested locator.
  SealedBlob(sealed: BitArray)

  /// The request was not carried out.
  Refused(reason: Refusal)
}

/// Why a request was refused. A missing queue and a wrong capability are
/// both `Unauthorized`, so the mailbox is not an oracle for which queues
/// exist.
pub type Refusal {
  /// The capability does not grant this operation on this queue.
  Unauthorized

  /// Same identifier, different content.
  Conflict

  /// Byte, envelope or operation quota exhausted.
  QuotaExceeded

  /// A body or batch larger than `core/limits` allows.
  TooLarge

  /// The retention deadline is in the past or beyond the allowance.
  BadDeadline

  /// The request did not decode.
  Malformed

  /// The request names a protocol version this mailbox does not speak.
  UnsupportedVersion

  /// The mailbox is temporarily unable to serve; retry later.
  Unavailable
}

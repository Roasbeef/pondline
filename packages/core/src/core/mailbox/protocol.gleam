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
////
//// A rendezvous (ADR-016) is the one structure with two parties. The
//// inviter opens a slot with its own read and append capabilities and is
//// told a nameplate; the joiner claims the slot by that nameplate with its
//// own pair. From then on each side writes with its append capability and
//// reads the other side's messages with its read capability, and the
//// mailbox tells the sides apart only by which stored hash a presented
//// capability matches. The bodies are opaque to the mailbox: it never holds
//// the pairing code's words, a key or an identity.

import core/capability.{
  type Admin, type Append, type Capability, type Provision, type Read,
  type Retrieve,
}
import core/envelope.{type Padded, type StoredEnvelope}
import core/id.{type Blob, type Envelope, type Id, type Queue, type Rendezvous}
import core/nameplate.{type Nameplate}
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

  /// Open a rendezvous slot under a provisioning allowance (ADR-016), with
  /// the opener's own read and append capabilities, for
  /// `lifetime_seconds`, which the mailbox clamps to
  /// `limits.rendezvous_seconds`. The mailbox draws the nameplate. The
  /// identical request answers the same nameplate; a different one under
  /// the same identifier is a conflict.
  OpenRendezvous(
    provision: Capability(Provision),
    rendezvous: Id(Rendezvous),
    read: Capability(Read),
    append: Capability(Append),
    lifetime_seconds: Int,
  )

  /// Bind the claimant's read and append capabilities to the unclaimed
  /// live slot this nameplate names. The first claim stands: the identical
  /// claim answers the same again, and any other claim, an unknown
  /// nameplate and an expired slot are all `Unauthorized`.
  ClaimRendezvous(
    nameplate: Nameplate,
    read: Capability(Read),
    append: Capability(Append),
  )

  /// Store message `index` (from 0 to `limits.max_rendezvous_messages - 1`)
  /// of the side whose append capability this is, for the other side to
  /// fetch. The same bytes twice are the same message; different bytes
  /// under one index are a conflict.
  RendezvousSend(
    rendezvous: Id(Rendezvous),
    append: Capability(Append),
    index: Int,
    body: BitArray,
  )

  /// Return the other side's messages whose index is greater than `after`
  /// (`-1` for all of them), in index order, waiting up to `wait_seconds`
  /// for one to arrive. The wait is clamped to `limits.long_poll_seconds`.
  RendezvousFetch(
    rendezvous: Id(Rendezvous),
    read: Capability(Read),
    after: Int,
    wait_seconds: Int,
  )

  /// Delete the slot and every message in it. Either side's read
  /// capability may close it.
  CloseRendezvous(rendezvous: Id(Rendezvous), read: Capability(Read))
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

/// One message of a rendezvous: the sender's own number for it and its
/// opaque bytes.
pub type RendezvousMessage {
  RendezvousMessage(index: Int, body: BitArray)
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

  /// The rendezvous slot is open under this nameplate until `expires_at`.
  RendezvousOpened(nameplate: Nameplate, expires_at: Instant)

  /// The claim is bound to this slot, which now lives until `expires_at`.
  RendezvousClaimed(rendezvous: Id(Rendezvous), expires_at: Instant)

  /// The rendezvous message is stored for the other side.
  RendezvousSent

  /// The other side's messages past the requested index, in index order.
  /// Possibly empty after a long poll that saw nothing.
  RendezvousMessages(messages: List(RendezvousMessage))

  /// The rendezvous slot and its messages are gone.
  RendezvousClosed

  /// The request was not carried out.
  Refused(reason: Refusal)
}

/// Why a request was refused. A missing queue and a wrong capability are
/// both `Unauthorized`, so the mailbox is not an oracle for which queues
/// exist; the same holds for a missing, expired or already claimed
/// rendezvous slot.
pub type Refusal {
  /// The capability does not grant this operation on this queue or slot.
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

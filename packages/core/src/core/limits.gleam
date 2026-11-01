//// The provisional limits of the core specification (`docs/spec.md`, §11.3),
//// held in one module so that no bound is restated in the code that obeys
//// it.
////
//// Every value here is an engineering starting point rather than a measured
//// optimum, and none is a wire contract until `CryptoProfileV1` and the
//// mailbox binding freeze. Changing one is a one-line edit; the decision to
//// change it belongs in an ADR, because a peer or a mailbox may already
//// advertise the old value.
////
//// Sizes are in bytes and durations in seconds.

import gleam/list

/// How long an invitation may wait to be redeemed (24 hours).
pub const invitation_window_seconds = 86_400

/// The default lifetime of a temporary support relationship (2 hours).
pub const support_relationship_seconds = 7200

/// The longest an ordinary message is retained, before the relationship's own
/// policy narrows it (7 days).
pub const message_retention_seconds = 604_800

/// The largest application body one message may carry (64 KiB).
pub const max_body_bytes = 65_536

/// The largest ciphertext a mailbox stores for one envelope (256 KiB).
pub const max_ciphertext_bytes = 262_144

/// The sizes a ciphertext is padded up to, smallest first. The largest is
/// `max_ciphertext_bytes`, so a ciphertext that fits no bucket is one the
/// mailbox would refuse anyway.
pub const padding_buckets = [4096, 16_384, 65_536, 262_144]

/// The most envelopes one `Fetch` returns.
pub const fetch_batch_envelopes = 16

/// The most ciphertext bytes one `Fetch` returns (1 MiB).
pub const fetch_batch_bytes = 1_048_576

/// The longest a `Fetch` waits for activity before answering empty.
pub const long_poll_seconds = 25

/// A new queue's storage allowance (64 MiB). Message-count and rate limits
/// are separate and not yet fixed.
pub const queue_capacity_bytes = 67_108_864

/// The most message keys a ratchet will derive and store to cover one gap in
/// a chain (1000, Signal's figure). A header claiming a larger gap is
/// refused outright, so a forged message number costs one comparison rather
/// than an unbounded KDF loop. A mailbox that reorders or drops more than
/// this many messages in a row has broken the conversation anyway.
pub const max_skip_per_message = 1000

/// The most skipped message keys one ratchet state retains across all of its
/// chains (2000, twice the per-gap bound, so one full gap fits in each of two
/// chains). The store is also what a serialized state grows by, so the bound
/// caps the state's size. Storing past it evicts the oldest keys rather than
/// refusing: a message whose key was evicted is undecryptable, as any lost
/// message is, but a session never wedges because earlier messages were lost.
pub const max_skipped_message_keys = 2000

/// The largest message number a chain can carry: a header holds it in 32
/// bits, so a sending chain that has used every number must stop rather than
/// wrap and reuse a message key.
pub const max_message_number = 4_294_967_295

/// The padded size of a ciphertext of `size` bytes: the smallest bucket that
/// holds it. A ciphertext larger than every bucket has no padded size and
/// must be refused before it is stored, so the caller gets `Error(Nil)`
/// rather than a bucket that would truncate it.
///
/// ## Examples
///
/// ```gleam
/// limits.padded_size(5000)
/// // -> Ok(16_384)
///
/// limits.padded_size(300_000)
/// // -> Error(Nil)
/// ```
pub fn padded_size(size: Int) -> Result(Int, Nil) {
  list.find(padding_buckets, fn(bucket) { size <= bucket })
}

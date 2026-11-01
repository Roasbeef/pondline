//// The one error type the `core/crypto` modules share.
////
//// No variant carries a key, a plaintext or a ciphertext: the only payloads
//// are static labels naming which field or signature was at fault. That is
//// what lets a caller log or return any of these (`docs/gleam-style.md`
//// Part IV §7), and it is why a failed decrypt says only that
//// authentication failed, never how far it got.

/// Why a cryptographic operation was refused.
pub type Error {
  /// Input bytes did not have the shape the named field requires: a wrong
  /// length, a truncated or oversized encoding, or an unknown version. The
  /// label is a fixed string such as "x25519 public key".
  Malformed(what: String)

  /// A signature did not verify. The label names which one: "identity
  /// binding", "signed prekey" or "post-quantum prekey".
  BadSignature(which: String)

  /// An X25519 agreement failed, which for the real primitive means the peer
  /// supplied a low-order public key.
  KeyAgreementFailed

  /// The suite's primitive reported failure on well-formed input, which a
  /// correct suite never does for sizes this module has already checked.
  PrimitiveFailed

  /// The AEAD refused the message: wrong key, tampering, or a message that
  /// was never sent to this state.
  AuthenticationFailed

  /// The message's key is already spent or was never retained: a replay, or
  /// a message older than anything the store still holds.
  MessageKeyUnavailable

  /// The header claims a gap in the chain larger than
  /// `limits.max_skip_per_message`.
  SkipLimitExceeded

  /// Retaining the keys for this gap would pass
  /// `limits.max_skipped_message_keys`.
  SkippedKeyStoreFull

  /// The sending chain has used all 2^32 message numbers.
  CounterExhausted

  /// This state has no sending chain yet: a responder must receive the
  /// initiator's first message before it can send.
  NoSendingChain

  /// The responder's identity is not the one the prekey bundle was signed by.
  IdentityMismatch

  /// The initial message names a prekey bundle other than the one this
  /// responder holds.
  UnknownBundle
}

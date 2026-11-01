// Types, events and the test-case configuration shared by every machine.
//
// The model abstracts the cryptography to opaque tokens. A ciphertext is a
// tCt: what it carries (kind, the logical message it belongs to, the message
// identifier the receiver keys deliveries on, and which sealing produced it)
// plus two damage bits a mailbox can set. Two ciphertexts are the same bytes
// exactly when the tuples are equal, so tuple equality is the digest a
// mailbox and the processed rule compare.

// What an envelope's ciphertext is, once decrypted.
enum tKind { KApp, KAccept, KReceipt }

// A ciphertext.
//
// - msg is the logical message (the agent's send) and exists only so the
//   monitors can name what reached the agent. The protocol never reads it,
//   except to look up the message's expiry, which is authenticated content.
// - mid is the message identifier inside the plaintext. Honest code uses
//   mid == msg; the re-encrypt mutant gives a copy a new one.
// - seal names the sealing. Each sealing is under its own ratchet key, so
//   (kind, mid, seal) is the key a decrypt spends. A retransmit keeps the
//   seal (same committed bytes); a forger sealing new bytes under a used
//   identifier bumps it.
// - dmg is a mailbox flipping a bit in the ratchet bytes: the envelope no
//   longer decrypts and its fingerprint no longer matches.
// - pad is a mailbox flipping a bit in the unauthenticated zero padding:
//   the envelope digest changes, the fingerprint and the decrypt do not
//   (core/envelope.gleam: "The zeros are not authenticated").
type tCt = (kind: tKind, msg: int, mid: int, seal: int, dmg: bool, pad: bool);

// The ratchet key a ciphertext is sealed under.
type tKey = (kind: tKind, mid: int, seal: int);

// The fingerprint key: SHA-256 of the ratchet bytes inside the padding,
// which an undamaged copy of the same sealing shares (ADR-006).
type tFp = (mid: int, seal: int);

// A remembered fingerprint (plan.Fingerprint): the message and how many
// receipts it has been answered with.
type tFpRec = (msg: int, receipts: int);

// An envelope as the mailbox stores and serves it.
type tEnv = (env: int, ct: tCt);

// A stored envelope: the bytes as they are now (possibly damaged) and the
// digest recorded at insert, which is what a repeated append is compared
// against (mailbox/service.gleam replay).
type tStored = (env: int, ct: tCt, orig: tCt);

// An outbox row (daemon/store.gleam outbox table).
enum tStatus { Queued, Stored, Failed }
type tRow = (ct: tCt, q: int, status: tStatus, copies: int, sched: bool);

// The sender-side state of a message (sent_messages.state).
enum tSent { LocallyQueued, StoredByMailbox, ReceivedByPeer }

// The relationship phase, reduced to the two the receiver passes through
// after its Hello: waiting for Accept, then active.
enum tPhase { AwaitingAccept, Active }

// The mailbox's answer to an Append, with the client's timeout folded in.
enum tRes { RAppended, RConflict, RUnavailable, RTimeout }

// What one call of the inbound path did: committed (or found it already
// committed), failed without committing, or crashed the daemon.
enum tPRes { POk, PFail, PCrashed }

// The fetcher's state (daemon/fetcher.gleam: Acking, Polling, BackingOff),
// plus Idle for a long poll that is parked waiting for new mail.
enum tFState { FIdle, FAcking, FFetching, FBackoff }

// Timer kinds: an outbox row's transport retry, an outbox row's receipt
// window (ADR-006 retransmit), and the fetcher's backoff.
enum tTimer { TRetry, TWindow, TBackoff }

// The configuration of one test case: sizes, fault budgets, which rulings
// are in force, and which mutants are switched on.
type tCfg = (
  nMsgs: int,
  maxRetx: int,
  maxAttempts: int,
  pairing: bool,

  // The most envelopes one Fetch returns (limits.fetch_batch_envelopes).
  batchMax: int,

  // Mailbox and network faults (all bounded).
  fLoss: int,
  fCorrupt: int,
  fPad: int,
  fReplay: int,
  fDup: int,
  fReorder: int,
  fDrop: int,
  fDown: int,
  fDupReq: int,
  fRestore: int,
  fEarlySweep: int,

  // Daemon faults, per daemon.
  fCrashA: int,
  fCrashB: int,
  fProcFailA: int,
  fProcFailB: int,

  // Messages whose expiry the clock may pass, and forged repeats.
  fExpire: int,
  fForge: int,

  // Rulings, true as the design stands.
  retransmit: bool,
  fingerprint: bool,
  h2: bool,
  quarantine: bool,
  implicitAccept: bool,

  // Mutants, all false as the design stands.
  mReencrypt: bool,
  mSendBeforeCommit: bool,
  mAckBeforeCommit: bool,
  mReceiptForExpired: bool,
  mIgnoreExpiry: bool,
  mTightAnswers: bool,

  // Not a ruling: the model of a fix for the counterexample in
  // docs/formal/p.md ("An acknowledged envelope served again"). True
  // re-acknowledges a Repeat whose envelope was already acknowledged; false
  // is the code as it stands.
  reackRepeat: bool
);

// The two queues: A (the inviter, which sends application messages) reads
// QA; B (the joiner, which receives them and sends receipts) reads QB.
fun QA(): int { return 1; }
fun QB(): int { return 2; }

// ------------------------------------------------------------- protocol

// An Append request and its answer.
event eAppend: (client: machine, epoch: int, q: int, env: int, ct: tCt);
event eAppendDup: (q: int, env: int, ct: tCt);
event eAppendResp: (epoch: int, env: int, res: tRes);

// A Fetch request and its answer; ok is false for a refusal or timeout.
event eFetch: (client: machine, epoch: int, q: int);
event eFetchResp: (epoch: int, ok: bool, batch: seq[tEnv]);

// An Ack request and its answer.
event eAck: (client: machine, epoch: int, q: int, envs: seq[int]);
event eAckResp: (epoch: int, ok: bool, envs: seq[int]);

// The mailbox ends a parked long poll: there is new mail on this queue.
event eNewMail: int;

// The mailbox learns who reads each queue.
event eOwners: (a: machine, b: machine);

// Timers.
event eSetTimer: (target: machine, kind: tTimer, arg: int, epoch: int);
event eTimer: (kind: tTimer, arg: int, epoch: int);

// The clock passes a message's expiry.
event eExpire: int;
event eClockTick;

// The agent on A asks its daemon to send the next message.
event eAgentSend;

// --------------------------------------------------------- observations

// A row's ciphertext committed to an outbox.
event eCommitCt: tCt;

// A daemon put a ciphertext on the wire in an Append.
event eWire: tCt;

// The sender committed logical message m (the liveness obligation).
event eCommittedMsg: int;

// The receiver durably stored logical message m for its agent.
event eDelivered: int;

// The receiver queued a receipt for logical message m.
event eReceiptQueued: int;

// The sender committed PeerReceived for logical message m.
event eSenderReceived: int;

// The receiver's own clock passed m's expiry.
event eRecvExpired: int;

// A processed record committed for an envelope, and an Ack naming envelopes.
event eProcCommitted: int;
event eAckSent: seq[int];

// A mailbox queue now holds n envelopes.
event eQueueLen: (q: int, n: int);

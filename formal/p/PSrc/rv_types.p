// Types, events and the test-case configuration of the rendezvous model
// (ADR-016, pairing by spoken code): the slot's lifecycle at the mailbox and
// the two runs that use it. The delivery model's types are in types.p; the
// two models share a project and nothing else.
//
// The cryptography is abstracted to the interface the ProVerif model
// established (docs/formal/crypto.md, "Spoken pairing codes"). A message is
// a tRvMsg that names its author, the author's run, the code the author
// holds (or, for the attacker, the candidate it is guessing) and the context
// (the slot identifier) the author built the run on. A step succeeds
// exactly when both sides hold the same code and context and the message
// answers the one this side sent. A side with the wrong code learns only the
// verdict the protocol reveals, and each verdict obtained against an honest
// party with a guessed code is one guess (eRvGuess).

// What a rendezvous message is, once its length is checked: junk (the wrong
// length, MalformedMessage), or one of the four messages.
enum tRvKind { RJunk, RM1, RM2, RM3, RM4 }

// A rendezvous message.
//
// - author and run name who computed it; an attacker's messages carry
//   RvAtk() as author.
// - code is the author's code: the words an honest party was given, or the
//   attacker's candidate. Codes are small integers, one per honest run, so
//   a guess is a choice of element and the model can count them.
// - ctx is the slot identifier (sid) the author's public context names.
// - peer, peerRun and peerCode name the message this one answers: m2
//   answers m1, m3 answers m2, m4 answers m3. peerCode is the code of the
//   message answered, so an m3 carries the candidate it was computed
//   against, which is what an attacker playing inviter checks it with.
// - seal numbers an inviter's sealing of m4 (one per run, ADR-016); seq
//   numbers the m3s a joiner computed, so two different m3s of one run are
//   two different messages (only a mutant computes a second one).
type tRvMsg = (kind: tRvKind, author: int, run: int, code: int, ctx: int,
  peer: int, peerRun: int, peerCode: int, seal: int, nth: int);

// A message as the mailbox files it: the side it came from (0 the opener,
// 1 the claimant), its index, and the slot instance it was filed to.
type tRvStored = (side: int, index: int, msg: tRvMsg, filed: int);

// A slot at the mailbox (mailbox/store RendezvousRecord). Capabilities are
// integers; cR and cA are 0 while the slot is unclaimed.
type tRvSlot = (plate: int, oR: int, oA: int, cR: int, cA: int,
  expires: int, msgs: seq[tRvStored]);

// The requests of the rendezvous protocol (core/mailbox/protocol) and their
// answers. t is the client's clock, which the mailbox reads as its own (the
// model has no clock skew).
enum tRvOp { OOpen, OClaim, OSend, OFetch, OClose }

type tRvReq = (client: machine, cid: int, t: int, op: tRvOp, sid: int,
  plate: int, rcap: int, acap: int, index: int, after: int, msg: tRvMsg);

// AOdd is any answer no honest mailbox gives to that request (a wrong kind,
// QuotaExceeded, TooLarge); with AConflict it is what pairing.gleam calls
// Interfered.
enum tRvAns { AOpened, AClaimed, ASent, AMessages, AClosed, AUnauthorized,
  AConflict, AUnavailable, AOdd }

type tRvResp = (cid: int, ans: tRvAns, sid: int, plate: int, expires: int,
  items: seq[tRvStored]);

// How a run ended (daemon/pairing Ending, plus Paired and Lost). ELost is a
// run the daemon's restart took with it: no ending is reported and nothing
// is counted.
enum tRvEnding { EPaired, ENeverClaimed, EStalled, EConfFailed, ELost }

// The configuration of one rendezvous test case.
type tRvCfg = (
  // Durations, in model units of ten seconds (core/limits, daemon/pairing).
  lOpen: int,       // rendezvous_seconds, 600 s
  lClaim: int,      // rendezvous_claimed_seconds, 120 s
  callMax: int,     // pairing.call_ms, 60 s: a call's budget
  closeWin: int,    // pairing.close_ms, 30 s
  slack: int,       // pairing.run_slack_ms, 95 s, rounded UP to 100 s
  claimWin: int,    // api.ticket_wait_ms, 240 s: how long an open or a claim is retried
  claimCall: int,   // api.ticket_call_ms, 120 s: the budget of one open or claim call
  window: int,      // rendezvous_failure_window_seconds, scaled down
  cap: int,         // max_rendezvous_failures
  horizon: int,     // the clock stops here

  // The world.
  nPlates: int,     // nameplates the mailbox draws from
  nCodes: int,      // codes the attacker guesses among (0 .. nCodes-1)

  // The driver's script.
  rounds: int,      // invitations made one after another
  conc: int,        // invitations open at once in each round
  joiner: int,      // 0 none, 1 on time, 2 late (after the slot ended), 3 any
  misheard: bool,   // the joiner was told a wrong word
  gap: int,         // units the driver waits between rounds
  overlap: bool,    // a round starts once its inviters end, not its joiners
  restartA: int,    // restarts of the inviter's daemon
  restartB: int,    // restarts of the joiner's daemon
  expect: bool,     // the driver states the outcome liveness owes

  // The honest mailbox's network faults.
  fDrop: int,       // a request or its answer lost: the client times out
  fBusy: int,       // Unavailable
  fDupReq: int,     // a request served twice
  sweep: bool,      // the sweep may run

  // The external attacker (a party with no mailbox privileges).
  atkKnown: int,    // claims a nameplate it learnt, ahead of the joiner
  atkBlind: int,    // claims random nameplates
  atkOpen: int,     // opens slots of its own (to catch a recycled nameplate)
  atkProbe: int,    // presents capabilities of neither side
  atkSilent: bool,  // having claimed, says nothing

  // The mailbox as the attacker in the middle.
  mitm: bool,
  mForge: int,      // forged messages
  mHold: int,       // answers held across time (or never given)
  mLie: int,        // false Unauthorized
  mOdd: int,        // answers no honest mailbox gives
  mitmLate: bool,   // the strategy of cxRvAbandon (see rv_mailbox.p)

  // Fixes the model proposes (docs/formal/p.md), false as implemented.
  fixJoinerCount: bool,  // a joiner that handed m3 over counts any ending but Paired
  fixRecordFirst: bool,  // the inviter records a failed check before it closes

  // Mutants, all false as the design stands.
  mutSecond: bool,       // a joiner steps on a second m2 at index 0
  mutNoCheck: bool,      // the inviter releases without checking confirm_J
  mutReseal: bool,       // m4 is sealed again on every send attempt
  mutAcceptAny: bool,    // the joiner accepts any well-formed m4
  mutClaimReplace: bool, // a second claim replaces the first
  mutOwnSide: bool,      // a fetch returns the reader's own messages too
  mutNeither: bool,      // a capability of neither side acts as the opener
  mutNoExpiry: bool,     // send and fetch do not check the slot's expiry
  mutStalePlate: bool,   // a recycled nameplate keeps its old slot's messages
  mutCountAll: bool,     // NeverClaimed and Stalled are counted too
  mutJoinerNoCount: bool,// the joiner does not count "m3 stored, no m4"
  mutNoCap: bool,        // the cap is not checked
  mutUnbounded: bool,    // a run has no deadline and retries a gone slot

  // The bound RvGuessBound checks: failed guesses against one daemon inside
  // one window.
  bound: int
);

// Party identifiers: the two honest daemons and the attacker.
fun RvA(): int { return 1; }
fun RvB(): int { return 2; }
fun RvAtk(): int { return 9; }

// Sides at the slot.
fun RvOpener(): int { return 0; }
fun RvClaimant(): int { return 1; }

// A message no one sent.
fun RvNoMsg(): tRvMsg {
  return (kind = RJunk, author = 0, run = 0, code = -1, ctx = 0, peer = 0,
    peerRun = 0, peerCode = -1, seal = 0, nth = 0);
}

// ------------------------------------------------------------- protocol

event eRvReq: tRvReq;
event eRvResp: tRvResp;

// A modelling device, not a message: the mailbox tells a client that its
// call is in flight across time (held, or lost), so the client waits on the
// clock and times the call out at callMax.
event eRvHeld: int;

// ------------------------------------------------------------- the clock

// Time passes only when every participant (each run, the driver, the
// attacker) is waiting on it, so an honest exchange takes no time and a
// slot expires only while somebody waits.
event eRvTick: int;
event eRvRegister: machine;
event eRvListen: machine;
event eRvWaiting: (who: machine, t: int);
event eRvDone: machine;

// The driver holds the clock while a run it asked for is being started.
event eRvHold;
event eRvUnhold;

// ----------------------------------------------- driver, daemons, runs

// invite_code: an inviter run with these words. accept_code: a joiner run
// for this nameplate and these words.
event eRvInvite: (t: int, words: int);
event eRvAccept: (t: int, plate: int, words: int);

// The operator reads the code to the joiner's operator (and, in some cases,
// the attacker overhears the nameplate).
event eRvCode: (plate: int, words: int, sid: int);

// The daemon refused to start (the cap), or a claim was refused.
event eRvNoRun: (daemon: int, words: int);

// A run ended (to the driver).
event eRvOver: (daemon: int, words: int, ending: tRvEnding);

// A run asks its daemon to count a failed confirmation (record_failure).
event eRvRecord: (run: int, epoch: int, t: int, ending: tRvEnding);

// The daemon restarts; its runs die with it.
event eRvRestart;
event eRvKill;

// ---------------------------------------------------------- observations

// The attacker obtained a confirmation verdict against an honest party:
// side 0 against the inviter, 1 against the joiner. code is the honest
// party's code, cand the attacker's candidate.
event eRvGuess: (target: int, side: int, code: int, cand: int, run: int,
  key: int, t: int);

// A run started, at a daemon whose recorded failures in the window were
// `failures`; expires is the slot expiry the run was given.
event eRvRunStart: (daemon: int, run: int, side: int, code: int, t: int,
  expires: int);
event eRvRunEnd: (daemon: int, run: int, side: int, code: int,
  ending: tRvEnding, m3Stored: bool, m4Lost: bool, recorded: bool, t: int);

// A daemon refused a code at the cap.
event eRvCapRefused: (daemon: int, t: int);

// A failed confirmation was written to the daemon's durable count.
event eRvRecorded: (daemon: int, run: int, t: int, ending: tRvEnding);

// An inviter (or the attacker, holding a code) sealed m4; verdict is what
// the confirmation check actually said.
event eRvRelease: (author: int, run: int, seal: int, code: int, ctx: int,
  verdict: bool);

// An m4 send attempt left the inviter with these sealed bytes.
event eRvM4Out: (run: int, seal: int);

// A joiner accepted a hand-off.
event eRvAccepted: (run: int, code: int, ctx: int, author: int,
  authorRun: int, seal: int);

// The honest mailbox's view: a slot opened, a claim bound, an operation
// served, a message served, the current time.
event eRvOpened: (sid: int, plate: int, oR: int, oA: int, expires: int);
event eRvClaimed: (sid: int, cR: int, cA: int, expires: int);
event eRvAccess: (sid: int, cap: int, side: int, t: int);
event eRvServed: (sid: int, readerSide: int, msgSide: int, filed: int);
event eRvNow: int;

// The configuration the monitors need.
event eRvSetup: tRvCfg;

// What the driver expects of an honest pairing (liveness).
event eRvExpect: (words: int, inviter: tRvEnding, joiner: tRvEnding);

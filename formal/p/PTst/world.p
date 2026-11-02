// The world every test case runs: one mailbox with both queues, a timer, a
// clock, and the two daemons. A test case is a configuration.

module Pondline = { Daemon, Mailbox, Timer, Clock };

// The design as it stands: every ruling on, every mutant off, no faults.
// Two messages, two retransmits and two process attempts before quarantine
// keep the space small; the limits are 5, 5 and 5 in core/limits.gleam.
fun Base(): tCfg {
  return (
    nMsgs = 2,
    maxRetx = 2,
    maxAttempts = 2,
    pairing = true,
    batchMax = 16,
    fLoss = 0,
    fCorrupt = 0,
    fPad = 0,
    fReplay = 0,
    fDup = 0,
    fReorder = 0,
    fDrop = 0,
    fDown = 0,
    fDupReq = 0,
    fRestore = 0,
    fEarlySweep = 0,
    fCrashA = 0,
    fCrashB = 0,
    fProcFailA = 0,
    fProcFailB = 0,
    fExpire = 0,
    fForge = 0,
    retransmit = true,
    fingerprint = true,
    h2 = true,
    quarantine = true,
    implicitAccept = true,
    mReencrypt = false,
    mSendBeforeCommit = false,
    mAckBeforeCommit = false,
    mReceiptForExpired = false,
    mIgnoreExpiry = false,
    mTightAnswers = false,
    reackRepeat = true
  );
}

fun Launch(cfg: tCfg) {
  var timer: machine;
  var mbox: machine;
  var a: machine;
  var b: machine;
  var nodes: seq[machine];

  timer = new Timer();
  mbox = new Mailbox(cfg);
  a = new Daemon((cfg = cfg, isA = true, mbox = mbox, timer = timer));
  b = new Daemon((cfg = cfg, isA = false, mbox = mbox, timer = timer));
  send mbox, eOwners, (a = a, b = b);

  nodes += (0, mbox);
  nodes += (1, a);
  nodes += (2, b);
  new Clock((cfg = cfg, nodes = nodes));
}

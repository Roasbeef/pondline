// Test cases for the design as it stands. Each must pass every monitor.
//
// The fault budgets keep the "spoiling" faults, those that cost a message
// one of its 1 + maxRetx chances (a lost or corrupted envelope in either
// queue, a quarantined envelope), at or below maxRetx. Every other fault
// (drops, duplicates, reordering, padding damage, replays, outages,
// crashes) is recoverable without spending a copy and is budgeted freely.
// PTst/judge.p shows that one spoiling fault more breaks liveness, so the
// budget is the boundary of the claim, not a margin of safety.

// No faults: pairing, two messages, receipts.
machine DrvHappy {
  start state S { entry { Launch(Base()); } }
}

// The network and an unavailable mailbox: nothing is lost.
machine DrvNetwork {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fDrop = 3;
      c.fDown = 2;
      c.fDupReq = 2;
      c.fDup = 1;
      c.fReorder = 2;
      Launch(c);
    }
  }
}

// Crashes at every commit point on both daemons.
machine DrvCrash {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fCrashA = 2;
      c.fCrashB = 2;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// A mailbox that loses and corrupts after Appended (two spoils), damages
// padding and reorders.
machine DrvMailbox {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fLoss = 1;
      c.fCorrupt = 1;
      c.fPad = 1;
      c.fRestore = 1;
      c.fEarlySweep = 1;
      c.fReorder = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// A replaying mailbox against the receipt-answer bound, with a loss and a
// crash at the receiver.
machine DrvReplay {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fReplay = 2;
      c.fLoss = 1;
      c.fPad = 1;
      c.fCrashB = 1;
      Launch(c);
    }
  }
}

// Replays against the answer bound with the spoil budget full: two
// replays and two losses, one message, maxRetx = 2. A replay spends an
// answer, but its receipt reaches the sender unless it too is lost, so
// replays do not lower the number of losses it takes to starve the sender.
machine DrvBoundReplay {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.nMsgs = 1;
      c.pairing = false;
      c.fReplay = 2;
      c.fLoss = 2;
      Launch(c);
    }
  }
}

test tcBoundReplay [main=DrvBoundReplay]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvBoundReplay });

// Transient process failures at both daemons, enough to quarantine one
// envelope on each side (two spoils), with a crash.
machine DrvQuarantine {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fProcFailA = 2;
      c.fProcFailB = 2;
      c.fCrashB = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// A byzantine authenticated peer repeats a message identifier (H2).
machine DrvForger {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fForge = 1;
      c.fReorder = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// H2 off, quarantine on: quarantine alone unblocks the queue.
machine DrvH2Off {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.h2 = false;
      c.fForge = 1;
      Launch(c);
    }
  }
}

// The clock passes a message's expiry, learnt by each node at its own
// time, with a loss and crashes.
machine DrvExpiry {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fExpire = 1;
      c.fEarlySweep = 1;
      c.fLoss = 1;
      c.fCrashA = 1;
      c.fCrashB = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// Everything at once, spoils within the bound.
machine DrvAll {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fLoss = 1;
      c.fPad = 1;
      c.fReplay = 1;
      c.fRestore = 1;
      c.fEarlySweep = 1;
      c.fDup = 1;
      c.fReorder = 1;
      c.fDrop = 2;
      c.fDown = 1;
      c.fDupReq = 1;
      c.fCrashA = 1;
      c.fCrashB = 1;
      c.fProcFailB = 1;
      c.fExpire = 1;
      c.fForge = 1;
      Launch(c);
    }
  }
}

// Three retransmits, one message, three spoils: the bound at a larger R.
machine DrvThreeSpoils {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.nMsgs = 1;
      c.maxRetx = 3;
      c.fLoss = 2;
      c.fCorrupt = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

test tcHappy [main=DrvHappy]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvHappy });

test tcNetwork [main=DrvNetwork]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvNetwork });

test tcCrash [main=DrvCrash]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCrash });

test tcMailbox [main=DrvMailbox]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvMailbox });

test tcReplay [main=DrvReplay]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvReplay });

test tcQuarantine [main=DrvQuarantine]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvQuarantine });

test tcForger [main=DrvForger]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvForger });

test tcH2Off [main=DrvH2Off]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvH2Off });

test tcExpiry [main=DrvExpiry]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvExpiry });

test tcAll [main=DrvAll]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvAll });

test tcThreeSpoils [main=DrvThreeSpoils]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvThreeSpoils });

// ------------------------------------------------------------ controls
//
// Each recall and counterexample in PTst/judge.p restores one rule and adds
// one fault. A control keeps the restored rule and drops that fault, and
// must pass: it shows the judge's failure comes from the pair, not from the
// restored rule alone or from a modelling slip.

// No retransmit, every fault that spends no copy.
machine DrvCtlNoRetransmit {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.retransmit = false;
      c.fDrop = 2;
      c.fDown = 1;
      c.fDupReq = 1;
      c.fDup = 1;
      c.fCrashA = 1;
      c.fCrashB = 1;
      Launch(c);
    }
  }
}

// No fingerprint lookup, the same faults.
machine DrvCtlNoFingerprint {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fingerprint = false;
      c.fDrop = 2;
      c.fDown = 1;
      c.fDupReq = 1;
      c.fDup = 1;
      c.fCrashA = 1;
      c.fCrashB = 1;
      Launch(c);
    }
  }
}

// Neither H2 nor quarantine, an honest peer.
machine DrvCtlPreH2 {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.h2 = false;
      c.quarantine = false;
      c.fDrop = 2;
      c.fLoss = 1;
      c.fCrashB = 1;
      Launch(c);
    }
  }
}

// No implicit accept, no fault that reorders.
machine DrvCtlNoImplicitAccept {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.implicitAccept = false;
      Launch(c);
    }
  }
}

// The pre-fix Repeat handling, every fault except a restore and the sweep:
// the control for the cx* recall cases.
machine DrvCtlNoReack {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.reackRepeat = false;
      c.fLoss = 1;
      c.fCorrupt = 1;
      c.fPad = 1;
      c.fReplay = 1;
      c.fDup = 1;
      c.fDrop = 2;
      c.fCrashA = 1;
      c.fCrashB = 1;
      Launch(c);
    }
  }
}

// Two losses with maxRetx = 2 and one message: within the bound.
machine DrvCtlTwoLosses {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.nMsgs = 1;
      c.fLoss = 2;
      Launch(c);
    }
  }
}

test tcCtlTwoLosses [main=DrvCtlTwoLosses]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCtlTwoLosses });

test tcCtlNoRetransmit [main=DrvCtlNoRetransmit]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCtlNoRetransmit });

test tcCtlNoFingerprint [main=DrvCtlNoFingerprint]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCtlNoFingerprint });

test tcCtlPreH2 [main=DrvCtlPreH2]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCtlPreH2 });

test tcCtlNoImplicitAccept [main=DrvCtlNoImplicitAccept]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCtlNoImplicitAccept });

test tcCtlNoReack [main=DrvCtlNoReack]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Pondline, { DrvCtlNoReack });

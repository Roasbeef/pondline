// The judge: test cases that must FAIL. judge.sh runs each and requires
// the checker to report a bug from the named monitor.
//
// - mut*: a mutant of the model that breaks the rule one safety monitor
//   guards. A monitor no mutant can trip is decoration.
// - recall*: a historical rule restored (the code before a fix), with a
//   generic fault mix and no hint about where the bug is.
// - calib*: the fault budget one spoiling fault past maxRetx. The design
//   cases claim liveness up to the bound; these show the bound is tight and
//   that the liveness monitor is sharp at its edge.
// - cx*: the counterexample against the current design found by this
//   model (docs/formal/p.md), reproduced with the code's behaviour.

// ------------------------------------------------------------- mutants

// A retransmit sealed again from the current session: a second message
// under a second identifier, delivered twice.
machine DrvMutReencrypt {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.mReencrypt = true;
      Launch(c);
    }
  }
}

machine DrvMutSendBeforeCommit {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.mSendBeforeCommit = true;
      Launch(c);
    }
  }
}

machine DrvMutAckBeforeCommit {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.mAckBeforeCommit = true;
      Launch(c);
    }
  }
}

// An expired message answered with a receipt.
machine DrvMutReceiptForExpired {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.mReceiptForExpired = true;
      c.fExpire = 1;
      Launch(c);
    }
  }
}

machine DrvMutIgnoreExpiry {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.mIgnoreExpiry = true;
      c.fExpire = 1;
      Launch(c);
    }
  }
}

// The receiver answers a remembered ciphertext one time fewer than
// max_retransmits beyond the first receipt. Liveness needs every answer:
// with maxRetx spoiled envelopes the last copy's receipt is the only one
// that gets through. tcCtlTwoLosses is the same without the mutant, and
// passes.
machine DrvMutTightAnswers {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.nMsgs = 1;
      c.mTightAnswers = true;
      c.fLoss = 2;
      Launch(c);
    }
  }
}

// ------------------------------------------------------------- recalls

// (a) Before ADR-006: the scheduler stops at Appended, and a mailbox loses
// an envelope after acknowledging its append.
machine DrvRecallNoRetransmit {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.retransmit = false;
      c.fLoss = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// (b) ADR-006 without the receiver half: no fingerprint lookup.
machine DrvRecallNoFingerprint {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.fingerprint = false;
      c.fLoss = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// (c) Before the H2 and quarantine rulings: a repeated message identifier
// fails the store's UNIQUE constraint on every attempt.
machine DrvRecallPreH2 {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.h2 = false;
      c.quarantine = false;
      c.fForge = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// (d) Before ADR-004: an application message in AwaitingAccept advances
// the session and is dropped.
machine DrvRecallNoImplicitAccept {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.implicitAccept = false;
      c.fReorder = 1;
      c.fDrop = 1;
      Launch(c);
    }
  }
}

// ---------------------------------------------------------- calibration

// Three envelopes spoiled with maxRetx = 2.
machine DrvCalibSpoils {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.nMsgs = 1;
      c.fLoss = 2;
      c.fCorrupt = 1;
      Launch(c);
    }
  }
}

// Two losses and one quarantined envelope with maxRetx = 2: quarantine
// spends a copy like any loss. tcCtlTwoLosses is the same without the
// process failures, and passes.
machine DrvCalibQuarantine {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.nMsgs = 1;
      c.fLoss = 2;
      c.fProcFailB = 2;
      Launch(c);
    }
  }
}

// ----------------------------------------------------- counterexamples

// The design case tcAll with the code's Repeat handling: a generic fault
// mix, no fault aimed at the defect.
machine DrvCxGeneric {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.reackRepeat = false;
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

// A mailbox restored from a backup serves an envelope the receiver already
// acknowledged, under its own identifier and bytes, at the head of the
// queue. With a batch of one it blocks the queue.
machine DrvCxRestore {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.reackRepeat = false;
      c.pairing = false;
      c.batchMax = 1;
      c.fRestore = 1;
      Launch(c);
    }
  }
}

// The same with a batch of one, the shape of a queue holding
// fetch_batch_envelopes such envelopes at its head: a later message is
// never fetched.
machine DrvCxBlock {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.reackRepeat = false;
      c.pairing = false;
      c.batchMax = 1;
      c.fRestore = 1;
      c.fReorder = 1;
      Launch(c);
    }
  }
}

// The path the checker first found in tcExpiry, restated without the
// model slip that first exposed it (docs/formal/p.md): the sender's append
// response is lost, the receiver processes and acknowledges the envelope,
// its tombstone is swept inside the retention slack, and the sender's
// retry stores it again under the same identifier.
machine DrvCxLateRetry {
  start state S {
    entry {
      var c: tCfg;

      c = Base();
      c.reackRepeat = false;
      c.fEarlySweep = 1;
      c.fCrashA = 1;
      c.fDrop = 2;
      Launch(c);
    }
  }
}

test mutReencrypt [main=DrvMutReencrypt]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvMutReencrypt });

test mutSendBeforeCommit [main=DrvMutSendBeforeCommit]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvMutSendBeforeCommit });

test mutAckBeforeCommit [main=DrvMutAckBeforeCommit]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvMutAckBeforeCommit });

test mutReceiptForExpired [main=DrvMutReceiptForExpired]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvMutReceiptForExpired });

test mutIgnoreExpiry [main=DrvMutIgnoreExpiry]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvMutIgnoreExpiry });

test recallNoRetransmit [main=DrvRecallNoRetransmit]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvRecallNoRetransmit });

test recallNoFingerprint [main=DrvRecallNoFingerprint]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvRecallNoFingerprint });

test recallPreH2 [main=DrvRecallPreH2]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvRecallPreH2 });

test recallNoImplicitAccept [main=DrvRecallNoImplicitAccept]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvRecallNoImplicitAccept });

test calibSpoils [main=DrvCalibSpoils]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvCalibSpoils });

test calibQuarantine [main=DrvCalibQuarantine]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvCalibQuarantine });

test cxRestore [main=DrvCxRestore]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvCxRestore });

test cxLateRetry [main=DrvCxLateRetry]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvCxLateRetry });

// QueuesDrain is left out so that the report names the consequence that
// matters: a message behind the envelope is never delivered.
test cxBlock [main=DrvCxBlock]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted in (union Reedwire, { DrvCxBlock });

test cxGeneric [main=DrvCxGeneric]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvCxGeneric });

test mutTightAnswers [main=DrvMutTightAnswers]:
  assert AtMostOnceDelivery, NoSendBeforeCommit, NoAckBeforeCommit, ReceiptOnlyForStored,
    NoExpiredDelivery, DeliveredAndReceipted, QueuesDrain in (union Reedwire, { DrvMutTightAnswers });

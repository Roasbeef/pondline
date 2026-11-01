// Liveness monitors. Every fault in the model is bounded, so every run of a
// correct model reaches a point where no machine has work left. A monitor
// still in a hot state there is a liveness violation ("at the end of program
// execution"), and one that stays hot through an endless run (a fetcher
// retrying the same envelope forever) is reported once the checker's
// fair-step bound runs out ("potential liveness bug").

// Every committed message that the clock has not passed the expiry of is
// eventually stored for the receiving agent, and its sender eventually
// commits the receipt (ADR-006).
spec DeliveredAndReceipted observes eCommittedMsg, eDelivered, eSenderReceived, eExpire {
  var waitingDelivery: set[int];
  var waitingReceipt: set[int];
  var expired: set[int];

  start cold state Settled {
    on eCommittedMsg do (m: int) { Owe(m); }
    on eDelivered do (m: int) { Discharge(m, true); }
    on eSenderReceived do (m: int) { Discharge(m, false); }
    on eExpire do (m: int) { Forgive(m); }
  }

  hot state Owed {
    on eCommittedMsg do (m: int) { Owe(m); }
    on eDelivered do (m: int) { Discharge(m, true); }
    on eSenderReceived do (m: int) { Discharge(m, false); }
    on eExpire do (m: int) { Forgive(m); }
  }

  fun Owe(m: int) {
    if (!(m in expired)) {
      waitingDelivery += (m);
      waitingReceipt += (m);
    }

    Settle();
  }

  fun Discharge(m: int, delivery: bool) {
    if (delivery) {
      if (m in waitingDelivery) {
        waitingDelivery -= (m);
      }
    } else {
      if (m in waitingReceipt) {
        waitingReceipt -= (m);
      }
    }

    Settle();
  }

  fun Forgive(m: int) {
    expired += (m);
    if (m in waitingDelivery) {
      waitingDelivery -= (m);
    }

    if (m in waitingReceipt) {
      waitingReceipt -= (m);
    }

    Settle();
  }

  fun Settle() {
    if (sizeof(waitingDelivery) == 0 && sizeof(waitingReceipt) == 0) {
      goto Settled;
    }

    goto Owed;
  }
}

// No queue is blocked forever: every envelope a mailbox holds is eventually
// acknowledged or swept, so a poison envelope cannot hold the ones behind it
// (docs/dst/plan.md, the quarantine ruling).
spec QueuesDrain observes eQueueLen {
  var lens: map[int, int];

  start cold state Empty {
    on eQueueLen do (l: (q: int, n: int)) { Track(l.q, l.n); }
  }

  hot state Holding {
    on eQueueLen do (l: (q: int, n: int)) { Track(l.q, l.n); }
  }

  fun Track(q: int, n: int) {
    var k: int;
    var total: int;

    lens[q] = n;
    foreach (k in keys(lens)) {
      total = total + lens[k];
    }

    if (total == 0) {
      goto Empty;
    }

    goto Holding;
  }
}

// Safety monitors. Each guards one rule of spec §13.1 or §7.3, and each has
// a mutant in PTst/mutants.p that breaks the rule and must be caught.

// The receiving agent sees each logical message at most once (spec §13.1,
// "No replay-driven local redelivery").
spec AtMostOnceDelivery observes eDelivered {
  var seen: set[int];

  start state Watching {
    on eDelivered do (m: int) {
      assert !(m in seen), format("message {0} delivered to the agent twice", m);
      seen += (m);
    }
  }
}

// Every ciphertext on the wire was committed to an outbox first (spec §13.1,
// "No send before commit"). A copy is the same ciphertext as its original,
// so either commit covers it; the comparison ignores the damage bits, which
// only a mailbox sets.
spec NoSendBeforeCommit observes eCommitCt, eWire {
  var committed: set[tKey];

  start state Watching {
    on eCommitCt do (ct: tCt) {
      committed += ((kind = ct.kind, mid = ct.mid, seal = ct.seal));
    }

    on eWire do (ct: tCt) {
      assert (kind = ct.kind, mid = ct.mid, seal = ct.seal) in committed,
        format("ciphertext {0} sent before it was committed", ct);
    }
  }
}

// The mailbox is acknowledged only for envelopes whose processing committed
// (spec §13.1, "No delete before commit").
spec NoAckBeforeCommit observes eProcCommitted, eAckSent {
  var done: set[int];

  start state Watching {
    on eProcCommitted do (env: int) {
      done += (env);
    }

    on eAckSent do (envs: seq[int]) {
      var e: int;

      foreach (e in envs) {
        assert e in done, format("envelope {0} acknowledged before its processing committed", e);
      }
    }
  }
}

// A receipt is queued, and a sender marks a message ReceivedByPeer, only
// for a message the receiver durably stored (spec §7.3).
spec ReceiptOnlyForStored observes eDelivered, eReceiptQueued, eSenderReceived {
  var stored: set[int];

  start state Watching {
    on eDelivered do (m: int) {
      stored += (m);
    }

    on eReceiptQueued do (m: int) {
      assert m in stored, format("receipt queued for message {0}, which was never stored", m);
    }

    on eSenderReceived do (m: int) {
      assert m in stored, format("sender saw a receipt for message {0}, which was never stored", m);
    }
  }
}

// Nothing the receiver's clock holds expired reaches its agent (spec §8.3).
spec NoExpiredDelivery observes eRecvExpired, eDelivered {
  var expired: set[int];

  start state Watching {
    on eRecvExpired do (m: int) {
      expired += (m);
    }

    on eDelivered do (m: int) {
      assert !(m in expired), format("message {0} delivered after the receiver saw it expire", m);
    }
  }
}

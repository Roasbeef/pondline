// Rendezvous test cases for the design as it stands (ADR-016 as
// daemon/pairing.gleam, daemon/api.gleam and mailbox/service.gleam
// implement it). Each must pass every monitor it asserts.
//
// RvGuessBound, the bound property 7 claims, is asserted where the design
// meets it. Where an attacker plays inviter to an honest joiner (through an
// honest mailbox or as the mailbox), the design does not meet it; those
// cases assert everything else here, and PTst/rv_judge.p holds the
// counterexamples (cxRv*), which must keep failing until the code changes.
// The tcRvFix* cases run the two changes docs/formal/p.md proposes and
// assert the bound.

// Two honest daemons, one code, an honest mailbox: both pair.
machine DrvRvHappy {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.expect = true;
      RvLaunch(c);
    }
  }
}

// A busy mailbox and duplicated requests cost retries and no time: the pair
// still forms inside the claimed slot's two minutes.
machine DrvRvBusy {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.fBusy = 3;
      c.fDupReq = 3;
      c.expect = true;
      RvLaunch(c);
    }
  }
}

// Lost requests and answers: each costs a whole call's budget, so a pairing
// may not finish inside its slot; whatever happens is safe, every run ends,
// and m4 is resent with the bytes sealed once.
machine DrvRvLossy {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.fDrop = 3;
      c.fBusy = 2;
      c.fDupReq = 2;
      RvLaunch(c);
    }
  }
}

// Nobody claims the code: the inviter ends never claimed, counting nothing.
machine DrvRvNever {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.expect = true;
      RvLaunch(c);
    }
  }
}

// A misheard word: both sides fail confirmation and each counts one.
machine DrvRvMisheard {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.misheard = true;
      c.expect = true;
      RvLaunch(c);
    }
  }
}

// An attacker who overheard the nameplate claims ahead of the joiner and
// plays joiner with a candidate code, or claims and says nothing. The real
// joiner's claim is refused at no cost; the inviter's verdict is the one
// guess, and it is counted.
machine DrvRvAttJoiner {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.atkKnown = 1;
      c.atkProbe = 2;
      c.atkSilent = $;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

// A blind claimer racing the real joiner over three nameplates.
machine DrvRvBlind {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.atkBlind = 3;
      c.fBusy = 1;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

// Expiry and recycling: the joiner arrives on time or after the slot has
// ended; with one nameplate, a second invitation recycles it, so a late
// joiner holding the first code claims the second code's slot. The sweep
// runs when it likes. A third party probes the slots.
machine DrvRvRecycle {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.nPlates = 1;
      c.rounds = 2;
      c.joiner = 3;
      c.overlap = true;
      c.atkProbe = 3;
      c.horizon = 220;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

// An attacker opens slots of its own and waits for a late joiner to claim
// a recycled nameplate, then plays inviter: it reads m3 (a guess against the
// joiner) and spoils the end however suits it.
machine DrvRvAttInviter {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.nPlates = 1;
      c.joiner = 2;
      c.atkOpen = 3;
      c.horizon = 220;
      RvLaunch(c);
    }
  }
}

// The mailbox is the attacker in the middle: it forges as joiner and as
// inviter, serves two messages at one index and messages out of order,
// holds and loses answers, lies Unauthorized and answers nonsense.
machine DrvRvMitm {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.mitm = true;
      c.mForge = 4;
      c.mHold = 2;
      c.mLie = 2;
      c.mOdd = 2;
      RvLaunch(c);
    }
  }
}

// The failure cap across several runs: an attacker who overhears each
// nameplate claims it first with a candidate. After three failures inside
// the window the daemon refuses codes until the oldest leaves it.
machine DrvRvCap {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.rounds = 6;
      c.gap = 8;
      c.joiner = 0;
      c.nCodes = 6;
      c.atkKnown = 6;
      c.horizon = 400;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

// The cap with two invitations open at once, the mailbox playing joiner to
// both: the bound is the cap less one plus the runs in flight.
machine DrvRvCapConc {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.rounds = 3;
      c.conc = 2;
      c.gap = 4;
      c.joiner = 0;
      c.nCodes = 6;
      c.mitm = true;
      c.mForge = 12;
      c.horizon = 400;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

// Restarts of either daemon mid-run lose the run: nothing is closed or
// counted by the dead process, the slot is left to expire, and the next
// run starts clean. An attacker overhears the nameplate. A restart after a
// verdict and before its record loses the count, so the bound grows by one
// per restart.
machine DrvRvRestart {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.rounds = 3;
      c.gap = 2;
      c.joiner = 3;
      c.nCodes = 3;
      c.atkKnown = 1;
      c.restartA = 1;
      c.restartB = 1;
      c.horizon = 300;
      c.bound = c.cap - 1 + c.conc + c.restartA;
      RvLaunch(c);
    }
  }
}

// The two proposed changes, against the attacks that defeat the bound
// without them: an attacker playing inviter through an honest mailbox, and
// the mailbox in the middle with every deviation.
machine DrvRvFixAttInviter {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.nPlates = 1;
      c.joiner = 2;
      c.atkOpen = 3;
      c.horizon = 220;
      c.fixJoinerCount = true;
      c.fixRecordFirst = true;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

machine DrvRvFixMitm {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.mitm = true;
      c.mForge = 4;
      c.mHold = 2;
      c.mLie = 2;
      c.mOdd = 2;
      c.fixJoinerCount = true;
      c.fixRecordFirst = true;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

machine DrvRvFixLate {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.mitm = true;
      c.mForge = 2;
      c.mitmLate = true;
      c.fixJoinerCount = true;
      c.fixRecordFirst = true;
      RvLaunch(c);
    }
  }
}

test tcRvHappy [main=DrvRvHappy]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd, RvOutcomes in (union PondlineRv, { DrvRvHappy });

test tcRvBusy [main=DrvRvBusy]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd, RvOutcomes in (union PondlineRv, { DrvRvBusy });

test tcRvLossy [main=DrvRvLossy]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvLossy });

test tcRvNever [main=DrvRvNever]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd, RvOutcomes in (union PondlineRv, { DrvRvNever });

test tcRvMisheard [main=DrvRvMisheard]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd, RvOutcomes in (union PondlineRv, { DrvRvMisheard });

test tcRvAttJoiner [main=DrvRvAttJoiner]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvAttJoiner });

test tcRvBlind [main=DrvRvBlind]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvBlind });

test tcRvRecycle [main=DrvRvRecycle]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvRecycle });

test tcRvAttInviter [main=DrvRvAttInviter]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvRunsEnd in (union PondlineRv, { DrvRvAttInviter });

test tcRvMitm [main=DrvRvMitm]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvRunsEnd in (union PondlineRv, { DrvRvMitm });

test tcRvCap [main=DrvRvCap]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvCap });

test tcRvConcCap [main=DrvRvCapConc]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvCapConc });

test tcRvRestart [main=DrvRvRestart]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvRestart });

test tcRvFixAttInviter [main=DrvRvFixAttInviter]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvFixAttInviter });

test tcRvFixMitm [main=DrvRvFixMitm]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvGuessBound, RvRunsEnd in (union PondlineRv, { DrvRvFixMitm });

test tcRvFixLate [main=DrvRvFixLate]:
  assert RvGuessPerCode, RvReleaseConfirmed, RvAcceptReleased, RvFirstClaim, RvIsolation,
    RvSlotLife, RvCounting, RvGuessCounted, RvRunsEnd in (union PondlineRv, { DrvRvFixLate });

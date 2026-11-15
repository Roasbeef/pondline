// The rendezvous judge: cases that must FAIL. judge.sh runs each and
// requires the checker to report a bug from the named monitor.
//
// - mutRv*: a mutant that reintroduces one real bug, each switched on in a
//   world where the bug matters. Each names the property that must catch
//   it.
// - cxRv*: the counterexamples this model found in the design as
//   implemented (docs/formal/p.md, "The rendezvous: what the model found").
//   They must keep failing until the code changes; the tcRvFix* design
//   cases are their controls.
// - calibRv*: the guess bound one run past what the design gives.

// --------------------------------------------------------------- mutants

// 1. A joiner that steps on a second m2 at index 0 hands the mailbox a
// verdict per m2 it serves.
machine DrvMutRvSecond {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.mitm = true;
      c.mForge = 8;
      c.mutSecond = true;
      RvLaunch(c);
    }
  }
}

// 2. The inviter seals m4 whatever confirm_J said.
machine DrvMutRvNoCheck {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.atkKnown = 1;
      c.mutNoCheck = true;
      RvLaunch(c);
    }
  }
}

// 2. m4 is sealed again on every send attempt.
machine DrvMutRvReseal {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.mutReseal = true;
      RvLaunch(c);
    }
  }
}

// 3. The joiner accepts any well-formed m4.
machine DrvMutRvAcceptAny {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.mitm = true;
      c.mForge = 6;
      c.mutAcceptAny = true;
      RvLaunch(c);
    }
  }
}

// 4. A second claim replaces the first.
machine DrvMutRvClaimReplace {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.atkKnown = 1;
      c.mutClaimReplace = true;
      RvLaunch(c);
    }
  }
}

// 5. A fetch returns the reader's own messages.
machine DrvMutRvOwnSide {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.mutOwnSide = true;
      RvLaunch(c);
    }
  }
}

// 5. A capability of neither side acts as the opener.
machine DrvMutRvNeither {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.atkProbe = 3;
      c.mutNeither = true;
      RvLaunch(c);
    }
  }
}

// 6. Send and fetch do not check the slot's expiry. A silent claimant
// shortens the slot to two minutes; the inviter keeps polling past them.
machine DrvMutRvNoExpiry {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.atkKnown = 1;
      c.atkSilent = true;
      c.sweep = false;
      c.mutNoExpiry = true;
      RvLaunch(c);
    }
  }
}

// 6. A recycled nameplate keeps its old slot's messages.
machine DrvMutRvStalePlate {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.nPlates = 1;
      c.rounds = 2;
      c.mutStalePlate = true;
      RvLaunch(c);
    }
  }
}

// 7. A never-claimed (or stalled) run is counted.
machine DrvMutRvCountAll {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.mutCountAll = true;
      RvLaunch(c);
    }
  }
}

// 7. The joiner does not count "m3 stored, no m4".
machine DrvMutRvJoinerNoCount {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.misheard = true;
      c.mutJoinerNoCount = true;
      RvLaunch(c);
    }
  }
}

// 7. The cap is not checked.
machine DrvMutRvNoCap {
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
      c.mutNoCap = true;
      RvLaunch(c);
    }
  }
}

// 6 and 8. A run with no deadline that retries a slot that is gone. The
// inviter's run is still cut off by the registry's deadline; the joiner's,
// which has no registry, is not: after a misheard word the inviter closes
// and the joiner polls the gone slot for ever.
machine DrvMutRvUnbounded {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.misheard = true;
      c.mutUnbounded = true;
      RvLaunch(c);
    }
  }
}

// ------------------------------------------------------- counterexamples

// An attacker that plays inviter to a late joiner on a recycled nameplate,
// through an honest mailbox, reads m3 and then ends the joiner's run
// without a count (junk at index 1 or a message at index 2).
machine DrvCxRvAttInviter {
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

// The mailbox in the middle with every deviation.
machine DrvCxRvMitm {
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

// The mailbox plays joiner to the inviter, delivers its m3 at the last
// wait's end, and holds the close: the registry's deadline kills the run
// before settle_ending records. The joiner-side fix is on, so only the
// inviter's path is under test.
machine DrvCxRvAbandon {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.mitm = true;
      c.mForge = 2;
      c.mitmLate = true;
      c.fixJoinerCount = true;
      RvLaunch(c);
    }
  }
}

// The same strategy over four runs inside one (lengthened) window: none is
// counted, so the cap never refuses and the guesses exceed what the cap
// was meant to allow.
machine DrvCxRvPastCap {
  start state S {
    entry {
      var c: tRvCfg;

      c = RvBase();
      c.joiner = 0;
      c.rounds = 4;
      c.nCodes = 6;
      c.window = 400;
      c.horizon = 400;
      c.mitm = true;
      c.mForge = 8;
      c.mitmLate = true;
      c.fixJoinerCount = true;
      c.bound = c.cap - 1 + c.conc;
      RvLaunch(c);
    }
  }
}

// ------------------------------------------------------------ calibration

// Two invitations open at once: the cap admits both while the count is
// below it, so the guesses reach the cap less one plus two. A bound of the
// cap alone (the ADR's "three") does not hold.
machine DrvCalibRvConc {
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
      c.bound = c.cap;
      RvLaunch(c);
    }
  }
}

test mutRvSecond [main=DrvMutRvSecond]:
  assert RvGuessPerCode in (union PondlineRv, { DrvMutRvSecond });

test mutRvNoCheck [main=DrvMutRvNoCheck]:
  assert RvReleaseConfirmed in (union PondlineRv, { DrvMutRvNoCheck });

test mutRvReseal [main=DrvMutRvReseal]:
  assert RvReleaseConfirmed in (union PondlineRv, { DrvMutRvReseal });

test mutRvAcceptAny [main=DrvMutRvAcceptAny]:
  assert RvAcceptReleased in (union PondlineRv, { DrvMutRvAcceptAny });

test mutRvClaimReplace [main=DrvMutRvClaimReplace]:
  assert RvFirstClaim in (union PondlineRv, { DrvMutRvClaimReplace });

test mutRvOwnSide [main=DrvMutRvOwnSide]:
  assert RvIsolation in (union PondlineRv, { DrvMutRvOwnSide });

test mutRvNeither [main=DrvMutRvNeither]:
  assert RvIsolation in (union PondlineRv, { DrvMutRvNeither });

test mutRvNoExpiry [main=DrvMutRvNoExpiry]:
  assert RvSlotLife in (union PondlineRv, { DrvMutRvNoExpiry });

test mutRvStalePlate [main=DrvMutRvStalePlate]:
  assert RvSlotLife in (union PondlineRv, { DrvMutRvStalePlate });

test mutRvCountAll [main=DrvMutRvCountAll]:
  assert RvCounting in (union PondlineRv, { DrvMutRvCountAll });

test mutRvJoinerNoCount [main=DrvMutRvJoinerNoCount]:
  assert RvCounting in (union PondlineRv, { DrvMutRvJoinerNoCount });

test mutRvNoCap [main=DrvMutRvNoCap]:
  assert RvCounting in (union PondlineRv, { DrvMutRvNoCap });

test mutRvUnbounded [main=DrvMutRvUnbounded]:
  assert RvSlotLife, RvRunsEnd in (union PondlineRv, { DrvMutRvUnbounded });

test cxRvAttInviter [main=DrvCxRvAttInviter]:
  assert RvGuessCounted in (union PondlineRv, { DrvCxRvAttInviter });

test cxRvMitm [main=DrvCxRvMitm]:
  assert RvGuessCounted in (union PondlineRv, { DrvCxRvMitm });

test cxRvAbandon [main=DrvCxRvAbandon]:
  assert RvGuessCounted in (union PondlineRv, { DrvCxRvAbandon });

test cxRvPastCap [main=DrvCxRvPastCap]:
  assert RvGuessBound in (union PondlineRv, { DrvCxRvPastCap });

test calibRvConc [main=DrvCalibRvConc]:
  assert RvGuessBound in (union PondlineRv, { DrvCalibRvConc });

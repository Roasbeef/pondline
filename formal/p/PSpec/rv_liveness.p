// Liveness of the rendezvous model (property 8). The clock stops at each
// case's horizon, so every run of a correct model reaches a point where no
// machine has work left; a monitor still hot there is a violation "at the
// end of program execution".

// Every run ends: one that started (opened or claimed) and never reported
// an ending, or died with its daemon, holds this monitor hot.
spec RvRunsEnd observes eRvRunStart, eRvRunEnd {
  var live: set[int];

  start cold state Quiet {
    on eRvRunStart do (r: (daemon: int, run: int, side: int, code: int, t: int, expires: int)) {
      live += (r.run);
      goto Running;
    }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      Ended(r.run);
    }
  }

  hot state Running {
    on eRvRunStart do (r: (daemon: int, run: int, side: int, code: int, t: int, expires: int)) {
      live += (r.run);
    }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      Ended(r.run);
    }
  }

  fun Ended(run: int) {
    if (run in live) {
      live -= (run);
    }

    if (sizeof(live) == 0) {
      goto Quiet;
    }
  }
}

// The outcomes an honest world owes, under fairness and an honest mailbox:
// two daemons holding the same code inside the slot's lifetime both end
// paired; a misheard word ends in a failed confirmation on both sides; an
// inviter whose slot nobody claims ends never claimed. The driver states
// each expectation (eRvExpect) when the code is read out; joiner code -1
// means no joiner.
spec RvOutcomes observes eRvExpect, eRvRunEnd {
  var owed: map[(side: int, code: int), tRvEnding];

  start cold state Settled {
    on eRvExpect do (e: (words: int, inviter: tRvEnding, joiner: tRvEnding)) { Owe(e.words, e.inviter, e.joiner); }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      Check(r.side, r.code, r.ending);
    }
  }

  hot state Owed {
    on eRvExpect do (e: (words: int, inviter: tRvEnding, joiner: tRvEnding)) { Owe(e.words, e.inviter, e.joiner); }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      Check(r.side, r.code, r.ending);
    }
  }

  // The joiner's code is the inviter's, or 50 more when the joiner was told
  // a wrong word (the driver's convention).
  fun Owe(words: int, inviter: tRvEnding, joiner: tRvEnding) {
    owed[(side = 0, code = words)] = inviter;
    if (joiner == EPaired) {
      owed[(side = 1, code = words)] = joiner;
    } else if (joiner == EConfFailed) {
      owed[(side = 1, code = words + 50)] = joiner;
    }

    goto Owed;
  }

  fun Check(side: int, code: int, ending: tRvEnding) {
    var k: (side: int, code: int);

    k = (side = side, code = code);
    if (k in owed) {
      assert owed[k] == ending,
        format("the run on side {0} with code {1} ended {2}; an honest world owes {3}", side, code, ending, owed[k]);
      owed -= (k);
    }

    if (sizeof(owed) == 0) {
      goto Settled;
    }
  }
}

// Monitors of the rendezvous model: ADR-016's lifecycle claims, numbered as
// in docs/formal/p.md ("The rendezvous"). Each has a mutant in
// PTst/rv_judge.p that must trip it.

// 1. Guess budget per run. Against one code the attacker obtains at most one
// confirmation verdict from the inviter's side and one from the joiner's:
// the "two guesses per run" of ADR-016, which rests on each daemon stepping
// only on the first message at each index. A verdict is counted once per
// message the honest side computed (key), however often the attacker reads
// it.
spec RvGuessPerCode observes eRvGuess {
  var seen: set[(run: int, side: int, key: int)];
  var count: map[int, map[int, int]];

  start state Watching {
    on eRvGuess do (g: (target: int, side: int, code: int, cand: int, run: int, key: int, t: int)) {
      var k: (run: int, side: int, key: int);
      var n: int;

      k = (run = g.run, side = g.side, key = g.key);
      if (k in seen) {
        return;
      }

      seen += (k);
      if (!(g.code in count)) {
        count[g.code] = default(map[int, int]);
      }

      if (!(g.side in count[g.code])) {
        count[g.code][g.side] = 0;
      }

      count[g.code][g.side] = count[g.code][g.side] + 1;
      n = count[g.code][g.side];
      assert n <= 1,
        format("the attacker obtained {0} verdicts against code {1} from side {2}", n, g.code, g.side);
    }
  }
}

// 2. No release without confirmation: an inviter seals m4 only after a
// confirmation from a joiner holding its code and context, at most once per
// run, and every send of m4 carries the bytes it sealed.
spec RvReleaseConfirmed observes eRvRelease, eRvM4Out {
  var sealed: map[(author: int, run: int), int];

  start state Watching {
    on eRvRelease do (r: (author: int, run: int, seal: int, code: int, ctx: int, verdict: bool)) {
      var k: (author: int, run: int);

      k = (author = r.author, run = r.run);
      assert r.verdict,
        format("run {0} released the hand-off without a matching confirmation", r.run);
      assert !(k in sealed),
        format("run {0} sealed the hand-off a second time", r.run);
      sealed[k] = r.seal;
    }

    on eRvM4Out do (o: (run: int, seal: int)) {
      var k: (author: int, run: int);
      var a: int;
      var found: bool;

      foreach (k in keys(sealed)) {
        if (k.run == o.run) {
          found = true;
          assert sealed[k] == o.seal,
            format("run {0} resent the hand-off with different bytes", o.run);
        }
      }

      assert found, format("run {0} sent a hand-off it never sealed", o.run);
    }
  }
}

// 3. No acceptance without release: a joiner accepts a ticket only if a
// party holding the joiner's code released it, in a run on the joiner's
// slot. (A party that guessed the code holds it; that is the risk the guess
// budget bounds, not a breach of this rule.)
spec RvAcceptReleased observes eRvRelease, eRvAccepted {
  var released: set[(author: int, run: int, seal: int, code: int, ctx: int)];

  start state Watching {
    on eRvRelease do (r: (author: int, run: int, seal: int, code: int, ctx: int, verdict: bool)) {
      released += ((author = r.author, run = r.run, seal = r.seal, code = r.code, ctx = r.ctx));
    }

    on eRvAccepted do (a: (run: int, code: int, ctx: int, author: int, authorRun: int, seal: int)) {
      assert (author = a.author, run = a.authorRun, seal = a.seal, code = a.code, ctx = a.ctx) in released,
        format("joiner run {0} accepted a hand-off that no holder of its code released on its slot", a.run);
    }
  }
}

// 4. First claim stands: a claimed slot's holder is never replaced, and no
// later claimant reads or writes it.
spec RvFirstClaim observes eRvClaimed, eRvAccess {
  var holder: map[int, (cR: int, cA: int)];

  start state Watching {
    on eRvClaimed do (c: (sid: int, cR: int, cA: int, expires: int)) {
      if (c.sid in holder) {
        assert holder[c.sid] == (cR = c.cR, cA = c.cA),
          format("a second claim replaced the holder of slot {0}", c.sid);
      }

      holder[c.sid] = (cR = c.cR, cA = c.cA);
    }

    on eRvAccess do (a: (sid: int, cap: int, side: int, t: int)) {
      if (a.side == RvClaimant()) {
        assert a.sid in holder && (a.cap == holder[a.sid].cR || a.cap == holder[a.sid].cA),
          format("a claimant other than the first reached slot {0}", a.sid);
      }
    }
  }
}

// 5. Isolation: only a side's own capabilities act for it, so a third party
// never reads or writes a slot, and a side is never served its own
// messages.
spec RvIsolation observes eRvOpened, eRvClaimed, eRvAccess, eRvServed {
  var opener: map[int, (r: int, a: int)];
  var claimant: map[int, (r: int, a: int)];

  start state Watching {
    on eRvOpened do (o: (sid: int, plate: int, oR: int, oA: int, expires: int)) {
      opener[o.sid] = (r = o.oR, a = o.oA);
    }

    on eRvClaimed do (c: (sid: int, cR: int, cA: int, expires: int)) {
      claimant[c.sid] = (r = c.cR, a = c.cA);
    }

    on eRvAccess do (a: (sid: int, cap: int, side: int, t: int)) {
      if (a.side == RvOpener()) {
        assert a.sid in opener && (a.cap == opener[a.sid].r || a.cap == opener[a.sid].a),
          format("a capability of neither side acted on slot {0} as its opener", a.sid);
      } else {
        assert a.sid in claimant && (a.cap == claimant[a.sid].r || a.cap == claimant[a.sid].a),
          format("a capability of neither side acted on slot {0} as its claimant", a.sid);
      }
    }

    on eRvServed do (s: (sid: int, readerSide: int, msgSide: int, filed: int)) {
      assert s.readerSide != s.msgSide,
        format("slot {0} served side {1} its own message", s.sid, s.readerSide);
    }
  }
}

// 6. A slot's life bounds everything done with it: an expired slot is
// invisible to every operation whether or not the sweep has run, a message
// is only ever served from the slot instance it was filed to (so a recycled
// nameplate carries nothing of its old slot), and a run ends within a fixed
// bound of the expiry it was given. The bound is the code's: the last
// attempt of each remaining step may start at the deadline and run a whole
// call (pairing.call_ms), and the close adds close_ms and one more call.
// That a recycled nameplate never yields a release or an acceptance across
// runs is checked by monitors 2 and 3, which bind both to the code and the
// slot.
spec RvSlotLife observes eRvSetup, eRvOpened, eRvClaimed, eRvAccess, eRvServed, eRvRunStart,
    eRvRunEnd, eRvNow {
  var bound: int;
  var expiry: map[int, int];
  var runs: map[int, int];

  start state Watching {
    on eRvSetup do (c: tRvCfg) {
      bound = 4 * c.callMax + c.closeWin;
    }

    on eRvOpened do (o: (sid: int, plate: int, oR: int, oA: int, expires: int)) {
      expiry[o.sid] = o.expires;
    }

    on eRvClaimed do (c: (sid: int, cR: int, cA: int, expires: int)) {
      expiry[c.sid] = c.expires;
    }

    on eRvAccess do (a: (sid: int, cap: int, side: int, t: int)) {
      assert a.t <= expiry[a.sid],
        format("slot {0} served an operation at {1}, after it expired at {2}", a.sid, a.t, expiry[a.sid]);
    }

    on eRvServed do (s: (sid: int, readerSide: int, msgSide: int, filed: int)) {
      assert s.filed == s.sid,
        format("slot {0} served a message filed to slot {1}, an expired slot of the same nameplate", s.sid, s.filed);
    }

    on eRvRunStart do (r: (daemon: int, run: int, side: int, code: int, t: int, expires: int)) {
      runs[r.run] = r.expires;
    }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      if (r.run in runs) {
        runs -= (r.run);
      }
    }

    on eRvNow do (t: int) {
      var r: int;

      foreach (r in keys(runs)) {
        assert t <= runs[r] + bound,
          format("run {0} outlived its slot: still going at {1}, its slot expired at {2}", r, t, runs[r]);
      }
    }
  }
}

// 7. Counting: only a failed confirmation is counted; a joiner whose m3
// was stored and whose wait for m4 ended (the slot gone or the time spent)
// counts it; and a daemon opens or claims no rendezvous while the cap's
// worth of failures lies inside the window.
spec RvCounting observes eRvSetup, eRvRecorded, eRvRunEnd, eRvAdmit {
  var cap: int;
  var window: int;
  var records: map[int, seq[int]];

  start state Watching {
    on eRvSetup do (c: tRvCfg) {
      cap = c.cap;
      window = c.window;
    }

    on eRvRecorded do (r: (daemon: int, run: int, t: int, ending: tRvEnding)) {
      assert r.ending == EConfFailed,
        format("daemon {0} counted run {1}, which ended {2}", r.daemon, r.run, r.ending);
      if (!(r.daemon in records)) {
        records[r.daemon] = default(seq[int]);
      }

      records[r.daemon] += (sizeof(records[r.daemon]), r.t);
    }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      if (r.side == RvClaimant() && r.m3Stored && r.m4Lost && r.ending != ELost) {
        assert r.recorded && r.ending == EConfFailed,
          format("joiner run {0} stored m3, saw no m4, and did not count it", r.run);
      }
    }

    on eRvAdmit do (a: (daemon: int, t: int)) {
      var n: int;
      var at: int;

      if (a.daemon in records) {
        foreach (at in records[a.daemon]) {
          if (at > a.t - window) {
            n = n + 1;
          }
        }
      }

      assert n < cap,
        format("daemon {0} started a rendezvous with {1} failures in the window, past the cap", a.daemon, n);
    }
  }
}

// 7, the consequence. Failed guesses the attacker obtains against one
// daemon inside any one window are at most the case's bound (tRvCfg.bound).
// The design cases state the bound the design gives; docs/formal/p.md says
// what it is and where it does not hold.
spec RvGuessBound observes eRvSetup, eRvGuess {
  var bound: int;
  var window: int;
  var seen: set[(run: int, side: int, key: int)];
  var times: map[int, seq[int]];

  start state Watching {
    on eRvSetup do (c: tRvCfg) {
      bound = c.bound;
      window = c.window;
    }

    on eRvGuess do (g: (target: int, side: int, code: int, cand: int, run: int, key: int, t: int)) {
      var k: (run: int, side: int, key: int);
      var n: int;
      var at: int;

      k = (run = g.run, side = g.side, key = g.key);
      if (k in seen || g.cand == g.code) {
        return;
      }

      seen += (k);
      if (!(g.target in times)) {
        times[g.target] = default(seq[int]);
      }

      times[g.target] += (sizeof(times[g.target]), g.t);
      foreach (at in times[g.target]) {
        if (at > g.t - window) {
          n = n + 1;
        }
      }

      assert n <= bound,
        format("the attacker obtained {0} failed guesses against daemon {1} inside one window; the bound is {2}",
          n, g.target, bound);
    }
  }
}

// 7, per run. Every failed guess the attacker obtains against an honest run
// is counted by that run: a run that gave one ends having recorded a failed
// confirmation, unless its daemon's restart took it (that loss is the
// environment's, and RvGuessBound's bound carries it). This is what makes
// the cap bound the guesses at all; RvGuessBound is its consequence across
// runs.
spec RvGuessCounted observes eRvGuess, eRvRunEnd {
  var owing: set[int];

  start state Watching {
    on eRvGuess do (g: (target: int, side: int, code: int, cand: int, run: int, key: int, t: int)) {
      if (g.cand != g.code) {
        owing += (g.run);
      }
    }

    on eRvRunEnd do (r: (daemon: int, run: int, side: int, code: int, ending: tRvEnding,
        m3Stored: bool, m4Lost: bool, recorded: bool, t: int)) {
      if (r.run in owing && r.ending != ELost) {
        assert r.recorded,
          format("run {0} gave the attacker a failed guess and ended {1} without counting it", r.run, r.ending);
      }
    }
  }
}

// The world every rendezvous test case runs: a clock, one mailbox, the
// inviter's daemon (A), the joiner's daemon (B), the attacker if the case
// has one, and the driver, which plays both operators. A case is a
// configuration.

module PondlineRv = { RvClock, RvMailbox, RvDaemon, RvRun, RvAttacker, RvDriver };

// The design as it stands, with the limits in model units of ten seconds:
// a slot lives 60 units (600 s) from its open and at most 12 (120 s) after
// its claim; a call's budget is 6 (60 s), a close keeps trying for 3 (30 s),
// and the registry lets an inviter run 10 (100 s, rounding run_slack_ms's
// 95 s up) past its lifetime. The failure window is scaled down from 24
// hours to 40 units: what matters is that it is longer than a run and
// shorter than a case. Three nameplates and four codes keep the space small
// and make recycling and right guesses reachable.
fun RvBase(): tRvCfg {
  return (
    lOpen = 60,
    lClaim = 12,
    callMax = 6,
    closeWin = 3,
    slack = 10,
    claimWin = 24,
    claimCall = 12,
    window = 40,
    cap = 3,
    horizon = 150,
    nPlates = 3,
    nCodes = 4,
    rounds = 1,
    conc = 1,
    joiner = 1,
    misheard = false,
    gap = 0,
    overlap = false,
    restartA = 0,
    restartB = 0,
    expect = false,
    fDrop = 0,
    fBusy = 0,
    fDupReq = 0,
    sweep = true,
    atkKnown = 0,
    atkBlind = 0,
    atkOpen = 0,
    atkProbe = 0,
    atkSilent = false,
    mitm = false,
    mForge = 0,
    mHold = 0,
    mLie = 0,
    mOdd = 0,
    mitmLate = false,
    fixJoinerCount = false,
    fixRecordFirst = false,
    mutSecond = false,
    mutNoCheck = false,
    mutReseal = false,
    mutAcceptAny = false,
    mutClaimReplace = false,
    mutOwnSide = false,
    mutNeither = false,
    mutNoExpiry = false,
    mutStalePlate = false,
    mutCountAll = false,
    mutJoinerNoCount = false,
    mutNoCap = false,
    mutUnbounded = false,
    bound = 2
  );
}

fun RvLaunch(cfg: tRvCfg) {
  var clock: machine;
  var mbox: machine;
  var a: machine;
  var b: machine;
  var atk: machine;
  var hasAtk: bool;

  clock = new RvClock(cfg.horizon);
  mbox = new RvMailbox(cfg);
  send clock, eRvListen, mbox;
  a = new RvDaemon((cfg = cfg, me = RvA(), clock = clock, mbox = mbox));
  b = new RvDaemon((cfg = cfg, me = RvB(), clock = clock, mbox = mbox));

  atk = mbox;
  hasAtk = cfg.atkKnown > 0 || cfg.atkBlind > 0 || cfg.atkOpen > 0 || cfg.atkProbe > 0;
  if (hasAtk) {
    atk = new RvAttacker((cfg = cfg, clock = clock, mbox = mbox));
  }

  new RvDriver((cfg = cfg, clock = clock, a = a, b = b, atk = atk, hasAtk = hasAtk));
}

// The two operators. Each round the inviter's operator makes `conc` codes,
// with words no other run uses; each code is read out to the joiner's
// operator, who enters it on time, late (after the slot has ended, so the
// nameplate may have been recycled), at either, or never. Restarts of
// either daemon come at random while runs are going. The driver also says
// what an honest world owes (eRvExpect) when the case asks it to.
machine RvDriver {
  var cfg: tRvCfg;
  var clock: machine;
  var a: machine;
  var b: machine;
  var atk: machine;
  var hasAtk: bool;
  var now: int;

  var round: int;
  var pending: int;
  var pendingJoin: int;
  var nextRoundAt: int;
  var accepts: seq[(at: int, plate: int, words: int)];
  var restartsA: int;
  var restartsB: int;

  start state Driving {
    entry (p: (cfg: tRvCfg, clock: machine, a: machine, b: machine, atk: machine, hasAtk: bool)) {
      cfg = p.cfg;
      clock = p.clock;
      a = p.a;
      b = p.b;
      atk = p.atk;
      hasAtk = p.hasAtk;
      restartsA = cfg.restartA;
      restartsB = cfg.restartB;
      announce eRvSetup, cfg;
      send a, eRvSetDriver, this;
      send b, eRvSetDriver, this;
      send clock, eRvRegister, this;
      StartRound();
      send clock, eRvUnhold;
      Idle();
    }

    on eRvTick do (t: int) {
      var keep: seq[(at: int, plate: int, words: int)];
      var x: (at: int, plate: int, words: int);

      now = Max(now, t);

      foreach (x in accepts) {
        if (x.at <= now) {
          send clock, eRvHold;
          send b, eRvAccept, (t = now, plate = x.plate, words = x.words);
        } else {
          keep += (sizeof(keep), x);
        }
      }

      accepts = keep;

      if (pending + pendingJoin > 0 && restartsA > 0 && choose(8) == 0) {
        restartsA = restartsA - 1;
        send a, eRvRestart;
      }

      if (pending + pendingJoin > 0 && restartsB > 0 && choose(8) == 0) {
        restartsB = restartsB - 1;
        send b, eRvRestart;
      }

      if (nextRoundAt >= 0 && nextRoundAt <= now && pending == 0) {
        StartRound();
      }

      Idle();
    }

    // The inviter's operator reads the code out.
    on eRvCode do (c: (plate: int, words: int, sid: int)) {
      var mode: int;
      var told: int;

      if (hasAtk) {
        send atk, eRvCode, c;
      }

      mode = cfg.joiner;
      if (mode == 3) {
        mode = 1 + choose(2);
      }

      told = c.words;
      if (cfg.misheard) {
        told = c.words + 50;
      }

      if (mode == 1) {
        accepts += (sizeof(accepts), (at = now, plate = c.plate, words = told));
        pendingJoin = pendingJoin + 1;
      } else if (mode == 2) {
        accepts += (sizeof(accepts), (at = now + cfg.lOpen + 1 + choose(3), plate = c.plate, words = told));
        pendingJoin = pendingJoin + 1;
      }

      if (cfg.expect) {
        if (mode == 0) {
          announce eRvExpect, (words = c.words, inviter = ENeverClaimed, joiner = ELost);
        } else if (cfg.misheard) {
          announce eRvExpect, (words = c.words, inviter = EConfFailed, joiner = EConfFailed);
        } else {
          announce eRvExpect, (words = c.words, inviter = EPaired, joiner = EPaired);
        }
      }

      Idle();
    }

    // An invitation or a joiner's attempt is over (refused at the cap,
    // refused at the claim, ended, or lost to a restart).
    on eRvNoRun do (w: (daemon: int, words: int)) {
      if (w.daemon == RvA()) {
        pending = pending - 1;
      } else {
        pendingJoin = pendingJoin - 1;
      }

      Next();
      Idle();
    }

    on eRvOver do (o: (daemon: int, words: int, ending: tRvEnding)) {
      if (o.daemon == RvA()) {
        pending = pending - 1;
      } else {
        pendingJoin = pendingJoin - 1;
      }

      Next();
      Idle();
    }
  }

  state Done {
    ignore eRvTick, eRvCode, eRvNoRun, eRvOver;
  }

  fun StartRound() {
    var i: int;

    nextRoundAt = -1;
    i = 0;
    while (i < cfg.conc) {
      send clock, eRvHold;
      send a, eRvInvite, (t = now, words = round * cfg.conc + i);
      pending = pending + 1;
      i = i + 1;
    }
  }

  // A round is over when every run it started has ended and every joiner
  // has entered its code; with overlap, once its inviters have ended. The
  // case is over when both are.
  fun Next() {
    if (pending > 0 || (!cfg.overlap && (pendingJoin > 0 || sizeof(accepts) > 0))) {
      return;
    }

    if (round + 1 >= cfg.rounds && (pendingJoin > 0 || sizeof(accepts) > 0)) {
      return;
    }

    round = round + 1;
    if (round < cfg.rounds) {
      nextRoundAt = now + cfg.gap;
      if (cfg.gap == 0) {
        StartRound();
      }

      return;
    }

    send clock, eRvDone, this;
    goto Done;
  }

  fun Idle() {
    send clock, eRvWaiting, (who = this, t = now);
  }
}

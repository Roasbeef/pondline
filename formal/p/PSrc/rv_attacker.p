// The logical clock of the rendezvous model, and the external attacker.
//
// RvClock advances time one unit (ten seconds) at a time, and only when
// every participant (each run, the driver, the attacker) says it is waiting
// on the clock at the current time. So an honest exchange happens in no
// time, a slot expires only while somebody waits, and a call the mailbox
// holds lets time pass while its client waits for it to time out. The
// driver holds the clock while a run it asked for is being started, so a
// new run never misses a tick. The clock stops at the case's horizon.
//
// RvAttacker is a party with no mailbox privileges: it reaches the slot
// only through the honest service. It may claim a nameplate it overheard
// (ahead of the joiner) or one at random, and then play joiner with a
// candidate code; open slots of its own and, when a joiner claims one (a
// recycled nameplate), play inviter with a candidate; and present
// capabilities of neither side. Playing inviter it reads the joiner's m3,
// which is a guess against the joiner (it checks its candidate offline),
// and then does what suits it: an m4 that opens if the candidate was right,
// or junk, or a message past the expected index, or nothing, or a close.

machine RvClock {
  var horizon: int;
  var now: int;
  var holds: int;
  var participants: set[machine];
  var waiting: set[machine];
  var listeners: seq[machine];

  start state Ticking {
    // The driver holds the clock from the start and lets go once it has
    // registered, so no time passes before the case begins.
    entry (h: int) {
      horizon = h;
      holds = 1;
    }

    on eRvRegister do (m: machine) {
      participants += (m);

      // A participant that registers late starts at the current time.
      send m, eRvTick, now;
    }

    on eRvListen do (m: machine) {
      listeners += (sizeof(listeners), m);
    }

    on eRvHold do {
      holds = holds + 1;
    }

    on eRvUnhold do {
      holds = holds - 1;
      TryTick();
    }

    on eRvWaiting do (w: (who: machine, t: int)) {
      if (w.t == now && w.who in participants) {
        waiting += (w.who);
      }

      TryTick();
    }

    on eRvDone do (m: machine) {
      if (m in participants) {
        participants -= (m);
      }

      if (m in waiting) {
        waiting -= (m);
      }

      TryTick();
    }
  }

  fun TryTick() {
    var m: machine;

    if (holds > 0 || sizeof(participants) == 0 || sizeof(waiting) < sizeof(participants)
        || now >= horizon) {
      return;
    }

    now = now + 1;
    waiting = default(set[machine]);
    announce eRvNow, now;

    foreach (m in listeners) {
      send m, eRvTick, now;
    }

    foreach (m in participants) {
      send m, eRvTick, now;
    }
  }
}

// What the attacker is doing: nothing, playing joiner on a slot it claimed,
// playing inviter on a slot it opened, or probing a slot.
enum tRvJob { JNone, JJoin, JInvite, JProbe }

machine RvAttacker {
  var cfg: tRvCfg;
  var clock: machine;
  var mbox: machine;
  var now: int;

  var cid: int;
  var inFlight: int;
  var held: bool;
  var callStart: int;
  var nextTick: bool;

  var job: tRvJob;
  var step: int;
  var sid: int;
  var rcap: int;
  var acap: int;
  var cand: int;
  var run: int;
  var theirs: tRvMsg;
  var serial: int;

  // The nameplate a claim names.
  var plateArg: int;

  var knownLeft: int;
  var blindLeft: int;
  var openLeft: int;
  var probeLeft: int;
  var overheard: seq[int];
  var sids: seq[int];

  start state Acting {
    entry (p: (cfg: tRvCfg, clock: machine, mbox: machine)) {
      cfg = p.cfg;
      clock = p.clock;
      mbox = p.mbox;
      knownLeft = cfg.atkKnown;
      blindLeft = cfg.atkBlind;
      openLeft = cfg.atkOpen;
      probeLeft = cfg.atkProbe;
      send clock, eRvRegister, this;
    }

    // The attacker overhears a code's nameplate (and learns its slot,
    // which is not secret) the moment the inviter's operator reads it out.
    on eRvCode do (c: (plate: int, words: int, sid: int)) {
      overheard += (sizeof(overheard), c.plate);
      sids += (sizeof(sids), c.sid);
      if (job == JNone && knownLeft > 0) {
        knownLeft = knownLeft - 1;
        StartJoin(c.plate);
      }

      Idle();
    }

    on eRvTick do (t: int) {
      now = Max(now, t);

      // It leaves at the horizon, or once it has nothing left to try.
      if (now >= cfg.horizon - 1 || (job == JNone && inFlight == 0 && knownLeft == 0
          && blindLeft == 0 && openLeft == 0 && probeLeft == 0)) {
        send clock, eRvDone, this;
        goto Gone;
      }

      if (inFlight != 0 && held && now >= callStart + cfg.callMax) {
        inFlight = 0;
        job = JNone;
      } else if (inFlight == 0 && nextTick) {
        Again();
      } else if (inFlight == 0 && job == JNone) {
        Choose();
      }

      Idle();
    }

    on eRvHeld do (c: int) {
      if (c == inFlight) {
        held = true;
      }

      Idle();
    }

    on eRvResp do (r: tRvResp) {
      if (r.cid == inFlight) {
        inFlight = 0;
        Answer(r);
      }

      Idle();
    }
  }

  state Gone {
    ignore eRvTick, eRvHeld, eRvResp, eRvCode;
  }

  fun Idle() {
    if (inFlight == 0 || held) {
      send clock, eRvWaiting, (who = this, t = now);
    }
  }

  fun Choose() {
    if (blindLeft > 0 && $) {
      blindLeft = blindLeft - 1;
      StartJoin(choose(cfg.nPlates));
    } else if (openLeft > 0 && sizeof(overheard) > 0 && $) {
      // It opens once it knows a code is out, to catch that code's
      // nameplate when it is recycled.
      openLeft = openLeft - 1;
      serial = serial + 1;
      job = JInvite;
      step = 0;
      sid = 500 + serial;
      rcap = 9000 + serial * 10 + 1;
      acap = 9000 + serial * 10 + 2;
      run = 3000 + serial;
      cand = choose(cfg.nCodes);
      Call(OOpen, 0, -1, RvNoMsg());
    } else if (probeLeft > 0 && sizeof(sids) > 0 && $) {
      probeLeft = probeLeft - 1;
      serial = serial + 1;
      job = JProbe;
      sid = choose(sids);
      rcap = 8000 + serial;
      acap = 8000 + serial;
      if ($) {
        Call(OSend, 0, -1, RvNoMsg());
      } else if ($) {
        Call(OFetch, 0, -1, RvNoMsg());
      } else {
        Call(OClose, 0, -1, RvNoMsg());
      }
    }
  }

  fun StartJoin(plate: int) {
    serial = serial + 1;
    job = JJoin;
    step = 0;
    rcap = 9000 + serial * 10 + 1;
    acap = 9000 + serial * 10 + 2;
    run = 3000 + serial;
    cand = choose(cfg.nCodes);
    theirs = RvNoMsg();
    plateArg = plate;
    Call(OClaim, 0, -1, RvNoMsg());
  }

  fun Call(op: tRvOp, index: int, after: int, m: tRvMsg) {
    cid = cid + 1;
    inFlight = cid;
    held = false;
    callStart = now;
    nextTick = false;
    send mbox, eRvReq, (client = this, cid = cid, t = now, op = op, sid = sid,
      plate = plateArg, rcap = rcap, acap = acap, index = index, after = after, msg = m);
  }

  // A fetch found nothing yet: try again next tick, for as long as the slot
  // lives.
  fun Again() {
    if (job == JJoin && step == 2) {
      Call(OFetch, 0, -1, RvNoMsg());
    } else if (job == JJoin && step == 3) {
      Call(OFetch, 0, 0, RvNoMsg());
    } else if (job == JInvite && step == 1) {
      Call(OFetch, 0, -1, RvNoMsg());
    } else if (job == JInvite && step == 2) {
      Call(OFetch, 0, 0, RvNoMsg());
    }
  }

  fun Answer(r: tRvResp) {
    var m: tRvMsg;

    if (job == JProbe) {
      job = JNone;
      return;
    }

    // A busy mailbox, or no free nameplate yet, ends this attempt; the
    // attacker keeps its budget and may try again later.
    if (r.ans == AUnavailable) {
      if (job == JInvite && step == 0) {
        openLeft = openLeft + 1;
      }

      job = JNone;
      return;
    }

    if (job == JJoin) {
      Joining(r);
      return;
    }

    if (job == JInvite) {
      Inviting(r);
    }
  }

  // Playing joiner: claim, m1 under the candidate, read m2, m3 under the
  // same candidate, read m4 (the inviter's verdict), close.
  fun Joining(r: tRvResp) {
    var m: tRvMsg;

    if (step == 0) {
      if (r.ans != AClaimed) {
        job = JNone;
        return;
      }

      sid = r.sid;
      if (cfg.atkSilent) {
        // Having claimed, the attacker says nothing; the slot runs out.
        job = JNone;
        return;
      }

      m = RvNoMsg();
      m.kind = RM1;
      m.author = RvAtk();
      m.run = run;
      m.code = cand;
      m.ctx = sid;
      step = 1;
      Call(OSend, 0, -1, m);
      return;
    }

    if (step == 1) {
      step = 2;
      Call(OFetch, 0, -1, RvNoMsg());
      return;
    }

    if (step == 2) {
      if (r.ans != AMessages) {
        job = JNone;
        return;
      }

      if (sizeof(r.items) == 0) {
        nextTick = true;
        return;
      }

      theirs = r.items[0].msg;
      m = RvNoMsg();
      m.kind = RM3;
      m.author = RvAtk();
      m.run = run;
      m.code = cand;
      m.ctx = sid;
      m.peer = theirs.author;
      m.peerRun = theirs.run;
      step = 4;
      Call(OSend, 1, 0, m);
      return;
    }

    if (step == 4) {
      step = 3;
      Call(OFetch, 0, 0, RvNoMsg());
      return;
    }

    // step 3: m4 or nothing; either way the verdict is in.
    if (r.ans == AMessages && sizeof(r.items) == 0) {
      nextTick = true;
      return;
    }

    job = JNone;
  }

  // Playing inviter on a slot of its own: read m1, answer m2 under the
  // candidate, read m3 (a guess against the joiner), then hand off or spoil.
  fun Inviting(r: tRvResp) {
    var m: tRvMsg;
    var spoil: int;

    if (step == 0) {
      if (r.ans != AOpened) {
        job = JNone;
        return;
      }

      step = 1;
      Call(OFetch, 0, -1, RvNoMsg());
      return;
    }

    // m2 is filed; wait for m3.
    if (step == 5) {
      step = 2;
      Call(OFetch, 0, 0, RvNoMsg());
      return;
    }

    if (r.ans != AMessages && step != 3) {
      job = JNone;
      return;
    }

    if (step == 1) {
      if (sizeof(r.items) == 0) {
        nextTick = true;
        return;
      }

      theirs = r.items[0].msg;
      m = RvNoMsg();
      m.kind = RM2;
      m.author = RvAtk();
      m.run = run;
      m.code = cand;
      m.ctx = sid;
      m.peer = theirs.author;
      m.peerRun = theirs.run;
      step = 5;
      Call(OSend, 0, -1, m);
      return;
    }

    if (step == 2) {
      if (sizeof(r.items) == 0) {
        nextTick = true;
        return;
      }

      theirs = r.items[0].msg;
      if (theirs.kind != RM3) {
        job = JNone;
        return;
      }

      if (theirs.peer == RvAtk()) {
        announce eRvGuess, (target = theirs.author, side = 1, code = theirs.code,
          cand = theirs.peerCode, run = theirs.run, key = theirs.nth, t = now);
      }

      step = 3;
      m = RvNoMsg();
      m.author = RvAtk();
      m.run = run;
      m.ctx = sid;

      // A right candidate seals an m4 that opens.
      if (theirs.peer == RvAtk() && theirs.peerCode == theirs.code) {
        m.kind = RM4;
        m.code = theirs.code;
        m.peer = theirs.author;
        m.peerRun = theirs.run;
        m.seal = 1;
        announce eRvRelease, (author = RvAtk(), run = run, seal = 1, code = m.code,
          ctx = sid, verdict = true);
        Call(OSend, 1, 0, m);
        return;
      }

      // A wrong one: junk at index 1, a message at index 2, nothing, or a
      // close.
      spoil = choose(4);
      if (spoil == 0) {
        Call(OSend, 1, 0, m);
      } else if (spoil == 1) {
        m.kind = RM4;
        Call(OSend, 2, 1, m);
      } else if (spoil == 2) {
        job = JNone;
      } else {
        Call(OClose, 0, -1, RvNoMsg());
      }

      return;
    }

    job = JNone;
  }
}

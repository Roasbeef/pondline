// A daemon's side of pairing by spoken code (daemon/api.gleam: invite_code,
// accept_code, check_failures, record_failure, lifetime_ms; daemon/pairing:
// run_inviter, run_joiner, await_message, send_message, close,
// settle_ending, and the registry's deadline).
//
// RvDaemon holds the one durable fact, the failure count (store
// rendezvous_failures), checks it before starting a run, starts the run,
// and writes a record when a run asks. A restart bumps its epoch and kills
// every run it holds: the run is not durable (ADR-016), so a killed run
// reports nothing and counts nothing, and a record from an older epoch is a
// record the dead process never made.
//
// RvRun is one run, inviter (side 0) or joiner (side 1), written as the
// phases of the Gleam drivers. Every wait is poll.until_on: an immediate
// first attempt, a retry at the next tick while the deadline has not
// passed, and one attempt at the deadline. An attempt is a call whose
// answer arrives at once from an honest mailbox, or, when the mailbox holds
// or loses it, times out after callMax; an attempt started at the deadline
// runs to its end, which is how a run overruns its deadline by up to one
// call, and its close by closeWin plus one call.

machine RvDaemon {
  var cfg: tRvCfg;
  var me: int;
  var clock: machine;
  var mbox: machine;
  var driver: machine;
  var now: int;
  var epoch: int;
  var nextRun: int;

  // The durable failure records' times.
  var records: seq[int];

  // The live runs and their codes.
  var runs: map[int, machine];
  var codes: map[int, int];

  start state Init {
    entry (p: (cfg: tRvCfg, me: int, clock: machine, mbox: machine)) {
      cfg = p.cfg;
      me = p.me;
      clock = p.clock;
      mbox = p.mbox;
      nextRun = me * 100;
      send clock, eRvListen, this;
    }

    on eRvTick do (t: int) {
      now = Max(now, t);
    }

    on eRvInvite do (r: (t: int, words: int)) {
      Start(r.t, 0, r.words, -1);
    }

    on eRvAccept do (r: (t: int, plate: int, words: int)) {
      Start(r.t, 1, r.words, r.plate);
    }

    // A run's request to count a failed confirmation. A run killed by a
    // restart is gone, and so is its record.
    on eRvRecord do (r: (run: int, epoch: int, t: int, ending: tRvEnding)) {
      if (r.epoch == epoch && r.run in runs) {
        records += (sizeof(records), r.t);
        announce eRvRecorded, (daemon = me, run = r.run, t = r.t, ending = r.ending);
      }
    }

    // A run ended; the driver hears it after any record it asked for, as
    // record_failure is a call the run makes before it returns.
    on eRvOver do (o: (daemon: int, words: int, ending: tRvEnding)) {
      // The run's identifier rides in `daemon` on this hop.
      if (o.daemon in runs) {
        runs -= (o.daemon);
        codes -= (o.daemon);
        send driver, eRvOver, (daemon = me, words = o.words, ending = o.ending);
      }
    }

    on eRvRestart do {
      var r: int;

      epoch = epoch + 1;
      foreach (r in keys(runs)) {
        send runs[r], eRvKill;
        send driver, eRvOver, (daemon = me, words = codes[r], ending = ELost);
      }

      runs = default(map[int, machine]);
      codes = default(map[int, int]);
    }

    on eRvSetDriver do (d: machine) {
      driver = d;
    }
  }

  // check_failures, then the run. The clock is held by the driver until
  // the run registers with it, or until this refusal.
  fun Start(t: int, side: int, words: int, plate: int) {
    var m: machine;

    now = Max(now, t);
    if (Failures() >= cfg.cap && !cfg.mutNoCap) {
      announce eRvCapRefused, (daemon = me, t = now);
      send driver, eRvNoRun, (daemon = me, words = words);
      send clock, eRvUnhold;
      return;
    }

    announce eRvAdmit, (daemon = me, t = now);
    nextRun = nextRun + 1;
    m = new RvRun((cfg = cfg, me = me, daemon = this, clock = clock, mbox = mbox,
      driver = driver, run = nextRun, epoch = epoch, side = side, words = words,
      plate = plate, t = now));
    runs[nextRun] = m;
    codes[nextRun] = words;
  }

  // rendezvous_failures: the records inside the window before now.
  fun Failures(): int {
    var n: int;
    var at: int;

    foreach (at in records) {
      if (at > now - cfg.window) {
        n = n + 1;
      }
    }

    return n;
  }
}

event eRvSetDriver: machine;
event eRvAdmit: (daemon: int, t: int);

// Where a run is.
enum tRvPhase { POpen, PClaim, PAwait, PSend, PLinger, PClose, PEnded }

machine RvRun {
  var cfg: tRvCfg;
  var me: int;
  var daemon: machine;
  var clock: machine;
  var mbox: machine;
  var driver: machine;
  var run: int;
  var epoch: int;
  var side: int;
  var words: int;
  var plate: int;
  var now: int;

  // The slot as this side holds it.
  var sid: int;
  var rcap: int;
  var acap: int;
  var expires: int;

  // The run's deadline (pairing: link.clock.now() + lifetime_ms), the
  // registry's (lifetime + run_slack_ms; the inviter only), and the
  // current wait's.
  var deadline: int;
  var registryAt: int;
  var waitUntil: int;

  // The current phase, the index it waits for or sends at, and the body.
  var phase: tRvPhase;
  var index: int;
  var body: tRvMsg;

  // The call in flight.
  var cid: int;
  var inFlight: int;
  var held: bool;
  var callStart: int;
  var nextTick: bool;

  // What the run has seen and decided.
  var m1: tRvMsg;
  var m2: tRvMsg;
  var m3: tRvMsg;
  var m4: tRvMsg;
  var seal: int;
  var m3Seq: int;
  var answered: seq[tRvMsg];
  var m3Handed: bool;
  var m3Stored: bool;
  var m4Lost: bool;
  var ending: tRvEnding;
  var recorded: bool;
  var started: bool;

  start state Running {
    entry (p: (cfg: tRvCfg, me: int, daemon: machine, clock: machine, mbox: machine,
        driver: machine, run: int, epoch: int, side: int, words: int, plate: int, t: int)) {
      cfg = p.cfg;
      me = p.me;
      daemon = p.daemon;
      clock = p.clock;
      mbox = p.mbox;
      driver = p.driver;
      run = p.run;
      epoch = p.epoch;
      side = p.side;
      words = p.words;
      plate = p.plate;
      now = p.t;
      rcap = run * 10 + 1;
      acap = run * 10 + 2;
      ending = EPaired;

      send clock, eRvRegister, this;
      send clock, eRvUnhold;

      // invite_code draws the identifier and opens the slot; accept_code
      // claims the nameplate. Both are retried as a ticket's calls are.
      if (side == 0) {
        sid = run;
        Enter(POpen, 0, RvNoMsg(), now + cfg.claimWin);
      } else {
        Enter(PClaim, 0, RvNoMsg(), now + cfg.claimWin);
      }

      Idle();
    }

    on eRvTick do (t: int) {
      now = Max(now, t);

      // The registry's weft deadline kills the worker wherever it is,
      // including inside its own close, before settle_ending records.
      if (side == 0 && started && registryAt > 0 && now >= registryAt) {
        Abandon();
        return;
      }

      // A held or lost call runs out of its budget: poll sees Error(Nil),
      // a Retry, after the time the call took.
      if (inFlight != 0 && held && now >= callStart + Budget()) {
        inFlight = 0;
        Retry(true);
      } else if (inFlight == 0 && nextTick) {
        Attempt();
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
      // An answer to a call this side already gave up on reaches nobody.
      if (r.cid != inFlight) {
        Idle();
        return;
      }

      inFlight = 0;
      Judge(r);
      Idle();
    }

    on eRvKill do {
      announce eRvRunEnd, (daemon = me, run = run, side = side, code = words, ending = ELost,
        m3Stored = m3Stored, m4Lost = m4Lost, recorded = recorded, t = now);
      Finish();
    }
  }

  // A run that ended, or died with its daemon, hears nothing more.
  state Ended {
    ignore eRvTick, eRvHeld, eRvResp, eRvKill;
  }

  // ------------------------------------------------------------- polling

  fun Enter(ph: tRvPhase, idx: int, b: tRvMsg, until: int) {
    phase = ph;
    index = idx;
    body = b;
    waitUntil = until;
    Attempt();
  }

  fun Attempt() {
    var req: tRvReq;

    nextTick = false;
    cid = cid + 1;
    inFlight = cid;
    held = false;
    callStart = now;
    req = (client = this, cid = cid, t = now, op = OFetch, sid = sid, plate = plate,
      rcap = rcap, acap = acap, index = index, after = index - 1, msg = body);

    if (phase == POpen) {
      req.op = OOpen;
    } else if (phase == PClaim) {
      req.op = OClaim;
    } else if (phase == PSend) {
      req.op = OSend;
      if (side == 0 && index == 1) {
        // The mutant seals again on every attempt; the design resends the
        // bytes it sealed once.
        if (cfg.mutReseal) {
          seal = seal + 1;
          req.msg.seal = seal;
          announce eRvRelease, (author = me, run = run, seal = seal, code = words,
            ctx = sid, verdict = true);
        }

        announce eRvM4Out, (run = run, seal = req.msg.seal);
      }

      if (side == 1 && index == 1) {
        m3Handed = true;
      }
    } else if (phase == PClose) {
      req.op = OClose;
    } else if (phase == PAwait && side == 1 && index == 1 && cfg.mutSecond) {
      // The mutant keeps reading index 0 while it waits for m4.
      req.after = -1;
    }

    send mbox, eRvReq, req;
  }

  // An attempt returned Retry (an empty batch, Unavailable, or a call that
  // ran out). poll.until_on ends the wait once its budget is spent;
  // otherwise it tries again: at once after a call that took its whole
  // budget, at the next tick after an answer that took none.
  fun Retry(slow: bool) {
    if (now >= waitUntil && !(cfg.mutUnbounded && phase != PClose)) {
      Lost(2);
      return;
    }

    if (slow) {
      Attempt();
      return;
    }

    nextTick = true;
  }

  // A call's budget: an open or a claim is a ticket's call
  // (rendezvous_call, ticket_call_ms), every later one pairing.call_ms.
  fun Budget(): int {
    if (phase == POpen || phase == PClaim) {
      return cfg.claimCall;
    }

    return cfg.callMax;
  }

  // Declares this run waiting on the clock when it has nothing in flight,
  // or only a call the mailbox is holding.
  fun Idle() {
    if (phase != PEnded && (inFlight == 0 || held)) {
      send clock, eRvWaiting, (who = this, t = now);
    }
  }

  // --------------------------------------------------------- the answers

  fun Judge(r: tRvResp) {
    var lost: int;

    // Gone (0), Interfered (1) and TimedOut (2) are pairing.gleam's Lost.
    if (phase == POpen) {
      if (r.ans == AOpened) {
        Opened(r);
      } else if (r.ans == AUnavailable) {
        Retry(false);
      } else {
        NoRun();
      }

      return;
    }

    if (phase == PClaim) {
      if (r.ans == AClaimed) {
        Claimed(r);
      } else if (r.ans == AUnavailable) {
        Retry(false);
      } else {
        // A refused claim is a plain Refused and costs nothing.
        NoRun();
      }

      return;
    }

    if (phase == PClose) {
      if (r.ans == AUnavailable) {
        Retry(false);
        return;
      }

      Settle();
      return;
    }

    if (r.ans == AUnavailable) {
      Retry(false);
      return;
    }

    if (r.ans == AUnauthorized) {
      if (cfg.mutUnbounded) {
        Retry(false);
        return;
      }

      Lost(0);
      return;
    }

    if (phase == PSend) {
      if (r.ans == ASent) {
        Sent();
      } else {
        Lost(1);
      }

      return;
    }

    // An await (or the inviter's linger).
    if (r.ans != AMessages) {
      Lost(1);
      return;
    }

    Messages(r.items);
  }

  // first_at: the first message of the batch decides. Nothing is a Retry,
  // and a first message at any other index is Interfered.
  fun Messages(items: seq[tRvStored]) {
    var it: tRvStored;
    var rest: seq[tRvStored];

    if (cfg.mutSecond && side == 1 && index == 1) {
      // The mutant steps on every new m2 it is served while it waits.
      foreach (it in items) {
        if (it.index == 0 && it.msg.kind == RM2 && it.msg != m2 && Fresh(it.msg)) {
          answered += (sizeof(answered), it.msg);
          Confirm(it.msg, false);
        } else if (it.index >= 1) {
          rest += (sizeof(rest), it);
        }
      }

      items = rest;
    }

    if (sizeof(items) == 0) {
      Retry(false);
      return;
    }

    if (items[0].index != index) {
      Lost(1);
      return;
    }

    Got(items[0].msg);
  }

  fun Fresh(m: tRvMsg): bool {
    var a: tRvMsg;

    foreach (a in answered) {
      if (a == m) {
        return false;
      }
    }

    return true;
  }

  // ------------------------------------------------------------ the steps

  // invite_code: the slot is open; the run starts with the slot's remaining
  // life as its lifetime (lifetime_ms), and the code goes to the operator.
  fun Opened(r: tRvResp) {
    plate = r.plate;
    expires = r.expires;
    deadline = now + Lifetime(r.expires, cfg.lOpen);
    registryAt = deadline + cfg.slack;
    started = true;
    announce eRvRunStart, (daemon = me, run = run, side = side, code = words, t = now,
      expires = expires);
    send driver, eRvCode, (plate = plate, words = words, sid = sid);
    Enter(PAwait, 0, RvNoMsg(), deadline);
  }

  fun Claimed(r: tRvResp) {
    sid = r.sid;
    expires = r.expires;
    deadline = now + Lifetime(r.expires, cfg.lClaim);
    started = true;
    announce eRvRunStart, (daemon = me, run = run, side = side, code = words, t = now,
      expires = expires);

    // rendezvous.join: m1 under this side's code and the slot it claimed.
    m1 = RvNoMsg();
    m1.kind = RM1;
    m1.author = me;
    m1.run = run;
    m1.code = words;
    m1.ctx = sid;
    Enter(PSend, 0, m1, deadline);
  }

  // lifetime_ms: the remainder by the mailbox's expiry when it lies between
  // one unit and the cap, else the cap.
  fun Lifetime(exp: int, cap: int): int {
    if (exp - now >= 1 && exp - now <= cap) {
      return exp - now;
    }

    return cap;
  }

  fun Sent() {
    if (side == 0 && index == 0) {
      Enter(PAwait, 1, RvNoMsg(), deadline);
      return;
    }

    if (side == 0 && index == 1) {
      // m4 is stored; wait for the joiner's close or the slot's end.
      Enter(PLinger, 2, RvNoMsg(), deadline);
      return;
    }

    if (side == 1 && index == 0) {
      Enter(PAwait, 0, RvNoMsg(), deadline);
      return;
    }

    m3Stored = true;
    Enter(PAwait, 1, RvNoMsg(), deadline);
  }

  fun Got(m: tRvMsg) {
    if (phase == PLinger) {
      // Nothing the joiner sends past m3 matters; the run is paired.
      End(EPaired);
      return;
    }

    if (side == 0 && index == 0) {
      Answer1(m);
    } else if (side == 0 && index == 1) {
      Release(m);
    } else if (side == 1 && index == 0) {
      answered += (sizeof(answered), m);
      Confirm(m, true);
    } else {
      Receive(m);
    }
  }

  // inviter_answer: a wrong length is MalformedMessage, a stall. A wrong
  // code is not detectable here.
  fun Answer1(m: tRvMsg) {
    var out: tRvMsg;

    if (m.kind != RM1) {
      End(EStalled);
      return;
    }

    m1 = m;
    out = RvNoMsg();
    out.kind = RM2;
    out.author = me;
    out.run = run;
    out.code = words;
    out.ctx = sid;
    out.peer = m.author;
    out.peerRun = m.run;
    Enter(PSend, 0, out, deadline);
  }

  // inviter_release: the gate of the run, taken once. The check succeeds
  // exactly when the session the inviter answered is the joiner's whose m3
  // this is, under the same code and context.
  fun Release(m: tRvMsg) {
    var verdict: bool;
    var out: tRvMsg;

    if (m.kind != RM3) {
      End(EStalled);
      return;
    }

    verdict = m.author == m1.author && m.run == m1.run && m.peer == me && m.peerRun == run
      && m1.code == words && m1.ctx == sid && m.code == words && m.ctx == sid;

    // Playing joiner to this inviter, the attacker chose m1, so this
    // verdict tests its candidate.
    if (m1.author == RvAtk()) {
      announce eRvGuess, (target = me, side = 0, code = words, cand = m1.code, run = run,
        key = 0, t = now);
    }

    if (!verdict && !cfg.mutNoCheck) {
      ending = EConfFailed;
      if (cfg.fixRecordFirst) {
        Record();
      }

      Enter(PClose, 0, RvNoMsg(), now + cfg.closeWin);
      return;
    }

    seal = seal + 1;
    out = RvNoMsg();
    out.kind = RM4;
    out.author = me;
    out.run = run;
    out.code = words;
    out.ctx = sid;
    out.peer = m.author;
    out.peerRun = m.run;
    out.seal = seal;
    announce eRvRelease, (author = me, run = run, seal = seal, code = words, ctx = sid,
      verdict = verdict);
    Enter(PSend, 1, out, deadline);
  }

  // joiner_confirm: m3 answers m2 under this side's code. The joiner learns
  // nothing about the inviter's words here.
  fun Confirm(m: tRvMsg, first: bool) {
    var out: tRvMsg;

    if (m.kind != RM2) {
      End(EStalled);
      return;
    }

    m3Seq = m3Seq + 1;
    out = RvNoMsg();
    out.kind = RM3;
    out.author = me;
    out.run = run;
    out.code = words;
    out.ctx = sid;
    out.peer = m.author;
    out.peerRun = m.run;
    out.peerCode = m.code;
    out.nth = m3Seq;

    if (first) {
      m2 = m;
      m3 = out;
      Enter(PSend, 1, out, deadline);
      return;
    }

    // The mutant's second m3 goes out beside the first, answer unread.
    cid = cid + 1;
    send mbox, eRvReq, (client = this, cid = cid, t = now, op = OSend, sid = sid,
      plate = plate, rcap = rcap, acap = acap, index = 1, after = 0, msg = out);
  }

  // joiner_receive: a wrong length is MalformedMessage, a tag that does not
  // open is ConfirmationFailed.
  fun Receive(m: tRvMsg) {
    var opens: bool;

    if (m.kind != RM4) {
      if (cfg.fixJoinerCount) {
        End(EConfFailed);
      } else {
        End(EStalled);
      }

      return;
    }

    opens = m.author == m2.author && m.run == m2.run && m.peer == me && m.peerRun == run
      && m2.code == words && m.code == words && m.ctx == sid && m2.ctx == sid;

    if (opens || cfg.mutAcceptAny) {
      announce eRvAccepted, (run = run, code = words, ctx = sid, author = m.author,
        authorRun = m.run, seal = m.seal);
      End(EPaired);
      return;
    }

    End(EConfFailed);
  }

  // A wait or a send ended without its answer: Gone (0), Interfered (1) or
  // TimedOut (2). Where it happened decides the ending (unclaimed,
  // unanswered, and replace_error(Stalled) everywhere else).
  fun Lost(why: int) {
    if (phase == POpen || phase == PClaim) {
      NoRun();
      return;
    }

    if (phase == PClose) {
      Settle();
      return;
    }

    if (phase == PLinger) {
      End(EPaired);
      return;
    }

    // unclaimed: before m1, a slot gone or a wait run out was never claimed.
    if (side == 0 && phase == PAwait && index == 0) {
      if (why == 1) {
        End(EStalled);
      } else {
        End(ENeverClaimed);
      }

      return;
    }

    // unanswered: m3 stored and the wait for m4 lost.
    if (side == 1 && phase == PAwait && index == 1) {
      if (why == 1) {
        if (cfg.fixJoinerCount) {
          End(EConfFailed);
        } else {
          End(EStalled);
        }

        return;
      }

      m4Lost = true;
      if (cfg.mutJoinerNoCount) {
        End(EStalled);
      } else {
        End(EConfFailed);
      }

      return;
    }

    // The proposed fix: once m3 has left this side, anything but a pairing
    // may be a spent guess.
    if (side == 1 && cfg.fixJoinerCount && m3Handed) {
      End(EConfFailed);
      return;
    }

    End(EStalled);
  }

  // The run's steps are over; close the slot on every path.
  fun End(e: tRvEnding) {
    ending = e;
    Enter(PClose, 0, RvNoMsg(), now + cfg.closeWin);
  }

  // settle_ending: record a failed confirmation, then report.
  fun Settle() {
    if (ending == EConfFailed
        || (cfg.mutCountAll && (ending == ENeverClaimed || ending == EStalled))) {
      Record();
    }

    Report();
  }

  fun Record() {
    if (!recorded) {
      recorded = true;
      send daemon, eRvRecord, (run = run, epoch = epoch, t = now, ending = ending);
    }
  }

  // The registry cuts the run off: Stalled, its slot closed by a cleanup
  // run of its own, nothing recorded.
  fun Abandon() {
    cid = cid + 1;
    send mbox, eRvReq, (client = this, cid = cid, t = now, op = OClose, sid = sid,
      plate = plate, rcap = rcap, acap = acap, index = 0, after = 0, msg = RvNoMsg());
    ending = EStalled;
    Report();
  }

  fun NoRun() {
    phase = PEnded;
    send daemon, eRvOver, (daemon = run, words = words, ending = ELost);
    send clock, eRvDone, this;
    goto Ended;
  }

  fun Report() {
    announce eRvRunEnd, (daemon = me, run = run, side = side, code = words, ending = ending,
      m3Stored = m3Stored, m4Lost = m4Lost, recorded = recorded, t = now);
    send daemon, eRvOver, (daemon = run, words = words, ending = ending);
    Finish();
  }

  fun Finish() {
    phase = PEnded;
    send clock, eRvDone, this;
    goto Ended;
  }
}

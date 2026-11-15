// The rendezvous mailbox (mailbox/service.gleam: open_rendezvous,
// claim_rendezvous, send_rendezvous, fetch_rendezvous, close_rendezvous,
// find_side, side_of; mailbox/store.gleam: live_rendezvous,
// live_rendezvous_at, purge_expired_rendezvous, sweep) and the network in
// front of it.
//
// Honest behaviour, as the code has it:
//
// - An open first purges expired slots, then answers a repeated identifier
//   from its slot (identical caps) or Conflict, then draws a nameplate among
//   those no live slot holds. With nPlates small, nameplates are recycled
//   as soon as a slot is closed or expires and is purged.
// - A claim finds the live slot holding the nameplate (an expired one is
//   invisible whether or not it was swept), binds the first claimant,
//   shortens the expiry to the earlier of the current one and now + lClaim,
//   answers the identical claim again, and refuses everything else with
//   Unauthorized: the first claim stands.
// - Send, fetch and close find the live slot and the side whose stored
//   capability of the right kind matches; anything else is Unauthorized. A
//   send at a filed index answers the same bytes again and Conflict for
//   different bytes; a fetch returns the other side's messages past `after`
//   in index order, never the reader's own.
//
// The network may lose a request or its answer (the client times out after
// callMax), answer Unavailable, or deliver a request twice.
//
// With cfg.mitm the mailbox is the attacker (ADR-016: "It alone can play
// joiner to the inviter and inviter to the joiner in one run"). It keeps the
// honest store underneath, so everything it serves honestly is what an
// honest mailbox would serve, and on top it may hold an answer across time
// or forever, answer a false Unauthorized, answer what no honest mailbox
// would, forge messages as the joiner (to the inviter) and as the inviter
// (to the joiner), serve two messages at one index, and serve a message past
// the one expected first. It sees every request, so a joiner's m3 computed
// against a forged m2 is a guess the moment it arrives.
//
// The honest path announces what the monitors of first claim, isolation and
// expiry check (eRvOpened, eRvClaimed, eRvAccess, eRvServed). What the
// attacker in the middle forges is not announced: those properties are
// claims about an honest mailbox.

machine RvMailbox {
  var cfg: tRvCfg;
  var now: int;
  var slots: map[int, tRvSlot];

  // Under mutStalePlate: the messages a closed or expired slot left under
  // its nameplate, which the next slot to draw that nameplate inherits.
  var plateMsgs: map[int, seq[tRvStored]];

  var dropLeft: int;
  var busyLeft: int;
  var dupLeft: int;
  var forgeLeft: int;
  var holdLeft: int;
  var lieLeft: int;
  var oddLeft: int;

  // Answers held across time: released at the tick `at`, or never (-1).
  var held: seq[(client: machine, resp: tRvResp, at: int)];

  // The attacker's candidates per slot: playing joiner to the inviter
  // (candI) and inviter to the joiner (candJ).
  var candI: map[int, int];
  var candJ: map[int, int];

  start state Serving {
    entry (c: tRvCfg) {
      cfg = c;
      dropLeft = c.fDrop;
      busyLeft = c.fBusy;
      dupLeft = c.fDupReq;
      forgeLeft = c.mForge;
      holdLeft = c.mHold;
      lieLeft = c.mLie;
      oddLeft = c.mOdd;
    }

    on eRvTick do (t: int) {
      var i: int;
      var keep: seq[(client: machine, resp: tRvResp, at: int)];

      now = Max(now, t);

      // The sweep runs when it runs: an expired slot must be invisible
      // before it, so the model lets it lag.
      if (cfg.sweep && $) {
        Purge();
      }

      // A held answer is released at its time; the attacker may also let
      // one go early.
      i = 0;
      while (i < sizeof(held)) {
        if (held[i].at >= 0 && (held[i].at <= now || (!cfg.mitmLate && $))) {
          send held[i].client, eRvResp, held[i].resp;
        } else {
          keep += (sizeof(keep), held[i]);
        }

        i = i + 1;
      }

      held = keep;
    }

    on eRvReq do (r: tRvReq) {
      now = Max(now, r.t);

      if (cfg.mitm) {
        Middle(r);
        return;
      }

      Network(r);
    }
  }

  // ------------------------------------------------------- the network

  // An honest mailbox behind a faulty network.
  fun Network(r: tRvReq) {
    var resp: tRvResp;

    if (busyLeft > 0 && $) {
      busyLeft = busyLeft - 1;
      send r.client, eRvResp, Answer(r.cid, AUnavailable);
      return;
    }

    // A lost request, or a served request whose answer is lost: either way
    // the client hears nothing and times out.
    if (dropLeft > 0 && choose(4) == 0) {
      dropLeft = dropLeft - 1;
      if ($) {
        Serve(r);
      }

      send r.client, eRvHeld, r.cid;
      return;
    }

    resp = Serve(r);

    // The same request delivered twice; the second answer goes nowhere.
    if (dupLeft > 0 && $) {
      dupLeft = dupLeft - 1;
      Serve(r);
    }

    send r.client, eRvResp, resp;
  }

  // ------------------------------------------------- the honest service

  fun Serve(r: tRvReq): tRvResp {
    if (r.op == OOpen) {
      return Open(r);
    }

    if (r.op == OClaim) {
      return Claim(r);
    }

    if (r.op == OSend) {
      return SendMsg(r);
    }

    if (r.op == OFetch) {
      return Fetch(r);
    }

    return Close(r);
  }

  // place_rendezvous: purge, repeat or conflict, then draw a free nameplate.
  fun Open(r: tRvReq): tRvResp {
    var s: tRvSlot;
    var free: seq[int];
    var p: int;
    var sid: int;
    var taken: bool;
    var resp: tRvResp;

    Purge();

    if (r.sid in slots) {
      s = slots[r.sid];
      if (s.oR == r.rcap && s.oA == r.acap) {
        resp = Answer(r.cid, AOpened);
        resp.sid = r.sid;
        resp.plate = s.plate;
        resp.expires = s.expires;
        return resp;
      }

      return Answer(r.cid, AConflict);
    }

    p = 0;
    while (p < cfg.nPlates) {
      taken = false;
      foreach (sid in keys(slots)) {
        if (slots[sid].plate == p) {
          taken = true;
        }
      }

      if (!taken) {
        free += (sizeof(free), p);
      }

      p = p + 1;
    }

    if (sizeof(free) == 0) {
      return Answer(r.cid, AUnavailable);
    }

    p = choose(free);
    s = (plate = p, oR = r.rcap, oA = r.acap, cR = 0, cA = 0,
      expires = now + cfg.lOpen, msgs = default(seq[tRvStored]));

    // The mutant: messages keyed by nameplate, so a recycled nameplate
    // brings its old slot's messages into the new slot.
    if (cfg.mutStalePlate && p in plateMsgs) {
      s.msgs = plateMsgs[p];
      plateMsgs -= (p);
    }

    slots[r.sid] = s;
    announce eRvOpened, (sid = r.sid, plate = p, oR = r.rcap, oA = r.acap,
      expires = s.expires);

    resp = Answer(r.cid, AOpened);
    resp.sid = r.sid;
    resp.plate = p;
    resp.expires = s.expires;
    return resp;
  }

  // claim_rendezvous, bind_claimant and repeat_claim.
  fun Claim(r: tRvReq): tRvResp {
    var sid: int;
    var found: int;
    var s: tRvSlot;
    var resp: tRvResp;

    // live_rendezvous_at: the live slot holding the nameplate, blind to an
    // expired one whether or not the sweep has run.
    found = -1;
    foreach (sid in keys(slots)) {
      if (slots[sid].plate == r.plate && slots[sid].expires >= now) {
        found = sid;
      }
    }

    if (found < 0) {
      return Answer(r.cid, AUnauthorized);
    }

    s = slots[found];
    if (s.cR == 0) {
      if (s.oR == r.rcap || s.oA == r.acap) {
        return Answer(r.cid, AUnauthorized);
      }

      Bind(found, r);
    } else if (s.cR == r.rcap && s.cA == r.acap) {
      // The first claimant's retry gets the same answer.
    } else if (cfg.mutClaimReplace) {
      Bind(found, r);
    } else {
      return Answer(r.cid, AUnauthorized);
    }

    resp = Answer(r.cid, AClaimed);
    resp.sid = found;
    resp.plate = r.plate;
    resp.expires = slots[found].expires;
    return resp;
  }

  // Binds a claimant and shortens the slot's life; a claim only ever
  // shortens it.
  fun Bind(sid: int, r: tRvReq) {
    var s: tRvSlot;

    s = slots[sid];
    s.cR = r.rcap;
    s.cA = r.acap;
    s.expires = Min(s.expires, now + cfg.lClaim);
    slots[sid] = s;
    announce eRvClaimed, (sid = sid, cR = r.rcap, cA = r.acap, expires = s.expires);
  }

  // send_rendezvous and file_message.
  fun SendMsg(r: tRvReq): tRvResp {
    var side: int;
    var s: tRvSlot;
    var i: int;

    side = SideOf(r.sid, r.acap, true, !cfg.mutNoExpiry);
    if (side < 0) {
      return Answer(r.cid, AUnauthorized);
    }

    announce eRvAccess, (sid = r.sid, cap = r.acap, side = side, t = now);

    if (r.index < 0 || r.index >= 4) {
      return Answer(r.cid, AOdd);
    }

    s = slots[r.sid];
    i = 0;
    while (i < sizeof(s.msgs)) {
      if (s.msgs[i].side == side && s.msgs[i].index == r.index) {
        if (s.msgs[i].msg == r.msg) {
          return Answer(r.cid, ASent);
        }

        return Answer(r.cid, AConflict);
      }

      i = i + 1;
    }

    s.msgs += (sizeof(s.msgs), (side = side, index = r.index, msg = r.msg, filed = r.sid));
    slots[r.sid] = s;
    return Answer(r.cid, ASent);
  }

  // fetch_rendezvous: the other side's messages past `after`, in index
  // order.
  fun Fetch(r: tRvReq): tRvResp {
    var side: int;
    var resp: tRvResp;
    var it: tRvStored;

    side = SideOf(r.sid, r.rcap, false, !cfg.mutNoExpiry);
    if (side < 0) {
      return Answer(r.cid, AUnauthorized);
    }

    announce eRvAccess, (sid = r.sid, cap = r.rcap, side = side, t = now);

    resp = Answer(r.cid, AMessages);
    resp.items = Past(r.sid, side, r.after);
    foreach (it in resp.items) {
      announce eRvServed, (sid = r.sid, readerSide = side, msgSide = it.side, filed = it.filed);
    }

    return resp;
  }

  // The messages a reader on `side` is served past `after`, by index. The
  // mutant serves the reader's own messages beside the other side's.
  fun Past(sid: int, side: int, after: int): seq[tRvStored] {
    var out: seq[tRvStored];
    var idx: int;
    var it: tRvStored;

    idx = after + 1;
    if (idx < 0) {
      idx = 0;
    }

    while (idx < 4) {
      foreach (it in slots[sid].msgs) {
        if (it.index == idx && (it.side != side || cfg.mutOwnSide)) {
          out += (sizeof(out), it);
        }
      }

      idx = idx + 1;
    }

    return out;
  }

  // close_rendezvous: either side's reader deletes the slot.
  fun Close(r: tRvReq): tRvResp {
    var side: int;

    side = SideOf(r.sid, r.rcap, false, true);
    if (side < 0) {
      return Answer(r.cid, AUnauthorized);
    }

    announce eRvAccess, (sid = r.sid, cap = r.rcap, side = side, t = now);
    Forget(r.sid);
    return Answer(r.cid, AClosed);
  }

  // find_side and side_of: the side whose capability of this kind matches,
  // on a live slot, or -1. An unclaimed slot has only the opener's side.
  fun SideOf(sid: int, cap: int, append: bool, checkExpiry: bool): int {
    var s: tRvSlot;

    if (!(sid in slots)) {
      return -1;
    }

    s = slots[sid];
    if (checkExpiry && s.expires < now) {
      return -1;
    }

    if ((append && cap == s.oA) || (!append && cap == s.oR)) {
      return RvOpener();
    }

    if (s.cR != 0 && ((append && cap == s.cA) || (!append && cap == s.cR))) {
      return RvClaimant();
    }

    if (cfg.mutNeither) {
      return RvOpener();
    }

    return -1;
  }

  // purge_expired_rendezvous and the sweep.
  fun Purge() {
    var gone: seq[int];
    var sid: int;

    foreach (sid in keys(slots)) {
      if (slots[sid].expires < now) {
        gone += (sizeof(gone), sid);
      }
    }

    foreach (sid in gone) {
      Forget(sid);
    }
  }

  fun Forget(sid: int) {
    if (cfg.mutStalePlate) {
      plateMsgs[slots[sid].plate] = slots[sid].msgs;
    }

    slots -= (sid);
  }

  // --------------------------------------------- the attacker in the middle

  fun Middle(r: tRvReq) {
    var resp: tRvResp;
    var side: int;
    var forged: bool;

    // Every request passes through the attacker. An m3 computed against
    // the attacker's own m2 tells it whether its candidate was the
    // joiner's code: a guess against the joiner, whatever is answered.
    if (r.op == OSend && r.msg.kind == RM3 && r.msg.peer == RvAtk()) {
      announce eRvGuess, (target = r.msg.author, side = 1, code = r.msg.code,
        cand = r.msg.peerCode, run = r.msg.run, key = r.msg.nth, t = now);
    }

    // The strategy of cxRvAbandon: hold every close for ever, and hold the
    // inviter's last wait for m3 until just before the call times out.
    if (cfg.mitmLate && r.op == OClose) {
      Serve(r);
      held += (sizeof(held), (client = r.client, resp = Answer(r.cid, AClosed), at = -1));
      send r.client, eRvHeld, r.cid;
      return;
    }

    if (cfg.mitmLate && r.op == OFetch && r.after == 0
        && SideOf(r.sid, r.rcap, false, true) == RvOpener()) {
      if (now < slots[r.sid].expires) {
        resp = Answer(r.cid, AMessages);
        send r.client, eRvResp, resp;
        return;
      }

      resp = Answer(r.cid, AMessages);
      resp.items += (0, (side = RvClaimant(), index = 1, msg = ForgeFor(r.sid, RvOpener(), 1),
        filed = r.sid));
      held += (sizeof(held), (client = r.client, resp = resp, at = now + cfg.callMax - 1));
      send r.client, eRvHeld, r.cid;
      return;
    }

    // Otherwise the honest store answers first, and the attacker decides
    // what the client hears.
    resp = Serve(r);
    forged = false;

    if (r.op == OFetch && resp.ans == AMessages && forgeLeft > 0 && (cfg.mitmLate || $)) {
      side = SideOf(r.sid, r.rcap, false, true);
      if (side >= 0) {
        forgeLeft = forgeLeft - 1;
        resp.items = Forged(r.sid, side, r.after, resp.items);
        forged = true;
      }
    }

    // Lies and nonsense are spent on the run's own messages: refusing an
    // open or a claim only denies service, which needs no model.
    if (!forged && (r.op == OSend || r.op == OFetch) && lieLeft > 0 && $) {
      lieLeft = lieLeft - 1;
      resp = Answer(r.cid, AUnauthorized);
    } else if (!forged && (r.op == OSend || r.op == OFetch) && oddLeft > 0 && $) {
      oddLeft = oddLeft - 1;
      if ($) {
        resp = Answer(r.cid, AOdd);
      } else {
        resp = Answer(r.cid, AConflict);
      }
    }

    if ((r.op == OSend || r.op == OFetch) && holdLeft > 0 && $) {
      holdLeft = holdLeft - 1;
      if ($) {
        held += (sizeof(held), (client = r.client, resp = resp, at = now + 1 + choose(cfg.callMax)));
      } else {
        held += (sizeof(held), (client = r.client, resp = resp, at = -1));
      }

      send r.client, eRvHeld, r.cid;
      return;
    }

    send r.client, eRvResp, resp;
  }

  // A batch with a forged message in it, at the expected index or the one
  // past it, alone, ahead of the honest one, or behind it (two messages at
  // one index).
  fun Forged(sid: int, side: int, after: int, honest: seq[tRvStored]): seq[tRvStored] {
    var out: seq[tRvStored];
    var idx: int;
    var it: tRvStored;
    var how: int;

    idx = after + 1;
    if (idx < 0) {
      idx = 0;
    }

    if (!cfg.mitmLate && $ && idx < 3) {
      idx = idx + 1;
    }

    it = (side = 1 - side, index = idx, msg = ForgeFor(sid, side, idx), filed = sid);

    how = choose(3);
    if (cfg.mitmLate) {
      how = 0;
    }

    if (how == 0) {
      out += (0, it);
      return out;
    }

    if (how == 1) {
      out += (0, it);
      foreach (it in honest) {
        out += (sizeof(out), it);
      }

      return out;
    }

    out = honest;
    out += (sizeof(out), it);
    return out;
  }

  // What the attacker can compute for a reader on `side` at `idx`. Playing
  // joiner to the inviter (the reader is the opener) it sends m1 under its
  // candidate and then the m3 of that session; playing inviter to the joiner
  // it answers the joiner's m1 with m2 under a fresh candidate, and sends an
  // m4 that opens only if the joiner's m3 showed the candidate right.
  fun ForgeFor(sid: int, side: int, idx: int): tRvMsg {
    var m: tRvMsg;
    var it: tRvStored;
    var theirs: tRvMsg;

    m = RvNoMsg();
    m.author = RvAtk();
    m.run = 1000 + sid;
    m.ctx = sid;

    if (side == RvOpener()) {
      if (!(sid in candI)) {
        candI[sid] = choose(cfg.nCodes);
      }

      m.code = candI[sid];
      if (idx == 0) {
        m.kind = RM1;
      } else if (idx == 1) {
        m.kind = RM3;
        theirs = Stored(sid, RvOpener(), 0);
        m.peer = theirs.author;
        m.peerRun = theirs.run;
      }

      return m;
    }

    if (idx == 0) {
      candJ[sid] = choose(cfg.nCodes);
      m.kind = RM2;
      m.code = candJ[sid];
      theirs = Stored(sid, RvClaimant(), 0);
      m.peer = theirs.author;
      m.peerRun = theirs.run;
      m.peerCode = theirs.code;
      return m;
    }

    if (idx == 1) {
      theirs = Stored(sid, RvClaimant(), 1);

      // The joiner's m3 shows whether the candidate was right; only then
      // can the attacker seal an m4 that opens. Otherwise it sends junk or
      // a wrong m4.
      if (theirs.kind == RM3 && theirs.peer == RvAtk() && theirs.peerCode == theirs.code) {
        m.kind = RM4;
        m.code = theirs.code;
        m.peer = theirs.author;
        m.peerRun = theirs.run;
        m.seal = 1;
        announce eRvRelease, (author = RvAtk(), run = m.run, seal = 1, code = m.code,
          ctx = sid, verdict = true);
        return m;
      }

      if ($) {
        m.kind = RM4;
        m.code = choose(cfg.nCodes);
        m.peer = theirs.author;
        m.peerRun = theirs.run;
      }
    }

    return m;
  }

  // The message filed on `side` at `idx`, or none.
  fun Stored(sid: int, side: int, idx: int): tRvMsg {
    var it: tRvStored;

    if (!(sid in slots)) {
      return RvNoMsg();
    }

    foreach (it in slots[sid].msgs) {
      if (it.side == side && it.index == idx) {
        return it.msg;
      }
    }

    return RvNoMsg();
  }
}

// ------------------------------------------------------------- helpers

fun Answer(cid: int, ans: tRvAns): tRvResp {
  return (cid = cid, ans = ans, sid = 0, plate = -1, expires = 0,
    items = default(seq[tRvStored]));
}

fun Max(a: int, b: int): int {
  if (a > b) {
    return a;
  }

  return b;
}

fun Min(a: int, b: int): int {
  if (a < b) {
    return a;
  }

  return b;
}

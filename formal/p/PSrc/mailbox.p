// The mailbox (mailbox/service.gleam, mailbox/store.gleam) and the network
// in front of it.
//
// Append is idempotent by envelope identifier and digest: the same bytes
// again get the first answer, from the stored envelope or, once it was
// acknowledged, from its tombstone; different bytes get Conflict. Fetch is
// non-destructive and returns the queue in insertion order. Ack deletes
// exactly the named envelopes and leaves a tombstone for each. The sweep at
// a message's expiry removes its envelopes and their tombstones.
//
// Every fault lives here and is bounded by the test case: a request or a
// response dropped (the client sees a timeout), the mailbox down (it
// answers Unavailable), a request delivered twice, and, applied when a
// Fetch arrives, an envelope lost or corrupted after its append was
// answered, its padding damaged, a ciphertext replayed under a fresh
// envelope identifier, the batch reordered, and an envelope served twice
// in one batch.

machine Mailbox {
  var cfg: tCfg;
  var owners: map[int, machine];
  var stored: map[int, seq[tStored]];
  var tombs: map[int, map[int, tCt]];
  var nextReplay: int;

  var lossLeft: int;
  var corruptLeft: int;
  var padLeft: int;
  var replayLeft: int;
  var dupLeft: int;
  var reorderLeft: int;
  var dropLeft: int;
  var downLeft: int;
  var dupReqLeft: int;
  var restoreLeft: int;
  var earlySweepLeft: int;

  // Messages whose expiry this mailbox's clock has passed.
  var expired: set[int];

  start state Init {
    entry (c: tCfg) {
      cfg = c;
      lossLeft = c.fLoss;
      corruptLeft = c.fCorrupt;
      padLeft = c.fPad;
      replayLeft = c.fReplay;
      dupLeft = c.fDup;
      reorderLeft = c.fReorder;
      dropLeft = c.fDrop;
      downLeft = c.fDown;
      dupReqLeft = c.fDupReq;
      restoreLeft = c.fRestore;
      earlySweepLeft = c.fEarlySweep;
      nextReplay = 9000;
      stored[QA()] = default(seq[tStored]);
      stored[QB()] = default(seq[tStored]);
      tombs[QA()] = default(map[int, tCt]);
      tombs[QB()] = default(map[int, tCt]);
    }

    on eOwners do (o: (a: machine, b: machine)) {
      owners[QA()] = o.a;
      owners[QB()] = o.b;
      goto Serving;
    }

    defer eAppend, eAppendDup, eFetch, eAck, eExpire;
  }

  state Serving {
    on eAppend do (r: (client: machine, epoch: int, q: int, env: int, ct: tCt)) {
      var res: tRes;

      if (Refuse()) {
        send r.client, eAppendResp, (epoch = r.epoch, env = r.env, res = RUnavailable);
        return;
      }

      if (Drop()) {
        send r.client, eAppendResp, (epoch = r.epoch, env = r.env, res = RTimeout);
        return;
      }

      res = Append(r.q, r.env, r.ct);

      // The same request delivered again later, whose answer goes nowhere.
      if (dupReqLeft > 0 && $) {
        dupReqLeft = dupReqLeft - 1;
        send this, eAppendDup, (q = r.q, env = r.env, ct = r.ct);
      }

      if (Drop()) {
        res = RTimeout;
      }

      send r.client, eAppendResp, (epoch = r.epoch, env = r.env, res = res);
    }

    on eAppendDup do (r: (q: int, env: int, ct: tCt)) {
      Append(r.q, r.env, r.ct);
    }

    on eFetch do (r: (client: machine, epoch: int, q: int)) {
      var batch: seq[tEnv];

      if (Refuse() || Drop()) {
        send r.client, eFetchResp, (epoch = r.epoch, ok = false, batch = batch);
        return;
      }

      Faults(r.q);
      batch = Serve(r.q);
      if (Drop()) {
        send r.client, eFetchResp, (epoch = r.epoch, ok = false, batch = default(seq[tEnv]));
        return;
      }

      send r.client, eFetchResp, (epoch = r.epoch, ok = true, batch = batch);
    }

    on eAck do (r: (client: machine, epoch: int, q: int, envs: seq[int])) {
      if (Refuse() || Drop()) {
        send r.client, eAckResp, (epoch = r.epoch, ok = false, envs = r.envs);
        return;
      }

      AckAll(r.q, r.envs);
      if (Drop()) {
        send r.client, eAckResp, (epoch = r.epoch, ok = false, envs = r.envs);
        return;
      }

      send r.client, eAckResp, (epoch = r.epoch, ok = true, envs = r.envs);
    }

    on eExpire do (m: int) {
      expired += (m);
      Sweep(QA(), m);
      Sweep(QB(), m);
    }
  }

  fun Refuse(): bool {
    if (downLeft > 0 && $) {
      downLeft = downLeft - 1;
      return true;
    }

    return false;
  }

  fun Drop(): bool {
    if (dropLeft > 0 && $) {
      dropLeft = dropLeft - 1;
      return true;
    }

    return false;
  }

  fun Find(q: int, env: int): int {
    var i: int;

    i = 0;
    while (i < sizeof(stored[q])) {
      if (stored[q][i].env == env) {
        return i;
      }

      i = i + 1;
    }

    return -1;
  }

  // service.append_to: what is already known answers first, from the
  // stored envelope's recorded digest or from the tombstone.
  fun Append(q: int, env: int, ct: tCt): tRes {
    var i: int;

    i = Find(q, env);
    if (i >= 0) {
      if (stored[q][i].orig == ct) {
        return RAppended;
      }

      return RConflict;
    }

    if (env in tombs[q]) {
      if (tombs[q][env] == ct) {
        return RAppended;
      }

      return RConflict;
    }

    // insert_new judges the offered deadline by the mailbox's clock. Every
    // offer is at most the message's expiry, so once that has passed here
    // a new envelope of the message is refused BadDeadline, which the
    // sender treats as transient (scheduler.classify_refusal).
    if (ct.kind == KApp && ct.msg in expired) {
      return RUnavailable;
    }

    Insert(q, env, ct);
    return RAppended;
  }

  // An insert ends the owner's parked long poll.
  fun Insert(q: int, env: int, ct: tCt) {
    stored[q] += (sizeof(stored[q]), (env = env, ct = ct, orig = ct));
    announce eQueueLen, (q = q, n = sizeof(stored[q]));
    send owners[q], eNewMail, q;
  }

  fun AckAll(q: int, envs: seq[int]) {
    var e: int;
    var i: int;

    foreach (e in envs) {
      i = Find(q, e);
      if (i >= 0) {
        tombs[q][e] = stored[q][i].orig;
        stored[q] -= (i);
      }
    }

    announce eQueueLen, (q = q, n = sizeof(stored[q]));
  }

  // The retention sweep: a message's envelopes and tombstones go once it
  // expires (retention deadlines never exceed the message's expiry).
  fun Sweep(q: int, m: int) {
    var i: int;
    var e: int;
    var gone: seq[int];

    i = 0;
    while (i < sizeof(stored[q])) {
      if (stored[q][i].orig.kind == KApp && stored[q][i].orig.msg == m) {
        stored[q] -= (i);
      } else {
        i = i + 1;
      }
    }

    foreach (e in keys(tombs[q])) {
      if (tombs[q][e].kind == KApp && tombs[q][e].msg == m) {
        gone += (sizeof(gone), e);
      }
    }

    foreach (e in gone) {
      tombs[q] -= (e);
    }

    announce eQueueLen, (q = q, n = sizeof(stored[q]));
  }

  // Storage faults, applied to the queue being fetched. Each is a fault
  // after the append was answered: the sender already holds Appended.
  fun Faults(q: int) {
    var i: int;
    var s: tStored;
    var t: tCt;
    var e: int;

    if (lossLeft > 0 && sizeof(stored[q]) > 0 && $) {
      lossLeft = lossLeft - 1;
      stored[q] -= (choose(sizeof(stored[q])));
      announce eQueueLen, (q = q, n = sizeof(stored[q]));
    }

    if (corruptLeft > 0 && sizeof(stored[q]) > 0 && $) {
      corruptLeft = corruptLeft - 1;
      i = choose(sizeof(stored[q]));
      stored[q][i].ct.dmg = true;
    }

    if (padLeft > 0 && sizeof(stored[q]) > 0 && $) {
      padLeft = padLeft - 1;
      i = choose(sizeof(stored[q]));
      stored[q][i].ct.pad = true;
    }

    // A replay re-serves a ciphertext the mailbox holds, or held, under an
    // identifier it makes up.
    if (replayLeft > 0 && $) {
      if (sizeof(stored[q]) > 0 && $) {
        replayLeft = replayLeft - 1;
        nextReplay = nextReplay + 1;
        Insert(q, nextReplay, stored[q][choose(sizeof(stored[q]))].orig);
      } else if (sizeof(keys(tombs[q])) > 0) {
        replayLeft = replayLeft - 1;
        nextReplay = nextReplay + 1;
        e = choose(keys(tombs[q]));
        Insert(q, nextReplay, tombs[q][e]);
      }
    }

    // A restore from a backup taken before an acknowledgement: the
    // envelope is back under its own identifier, at its old place at the
    // head of the queue, and its tombstone is gone.
    if (restoreLeft > 0 && sizeof(keys(tombs[q])) > 0 && $) {
      restoreLeft = restoreLeft - 1;
      e = choose(keys(tombs[q]));
      t = tombs[q][e];
      tombs[q] -= (e);
      stored[q] += (0, (env = e, ct = t, orig = t));
      announce eQueueLen, (q = q, n = sizeof(stored[q]));
      send owners[q], eNewMail, q;
    }

    // A tombstone swept before its message expires. An original's
    // retention deadline, and so its tombstone's, is offered
    // retention_slack_seconds short of the message's expiry (ADR-008), so
    // for up to that long the mailbox has forgotten an envelope whose
    // sender may still retry it.
    if (earlySweepLeft > 0 && sizeof(keys(tombs[q])) > 0 && $) {
      earlySweepLeft = earlySweepLeft - 1;
      tombs[q] -= (choose(keys(tombs[q])));
    }

    // Queue order is a convenience, not a guarantee (spec §6.5).
    if (reorderLeft > 0 && sizeof(stored[q]) > 1 && $) {
      reorderLeft = reorderLeft - 1;
      i = choose(sizeof(stored[q]));
      s = stored[q][i];
      stored[q] -= (i);
      stored[q] += (0, s);
    }
  }

  fun Serve(q: int): seq[tEnv] {
    var batch: seq[tEnv];
    var i: int;

    // The oldest batchMax envelopes, in queue order (LiveEnvelopes: ORDER
    // BY seq LIMIT max).
    i = 0;
    while (i < sizeof(stored[q]) && i < cfg.batchMax) {
      batch += (i, (env = stored[q][i].env, ct = stored[q][i].ct));
      i = i + 1;
    }

    if (dupLeft > 0 && sizeof(batch) > 0 && $) {
      dupLeft = dupLeft - 1;
      batch += (sizeof(batch), batch[choose(sizeof(batch))]);
    }

    return batch;
  }
}

// Timers: a request for a wake-up is answered later, at a point the
// scheduler chooses, which is how "a receipt window passed" and "a backoff
// elapsed" are abstracted. Nothing about real durations survives.
machine Timer {
  start state Ticking {
    on eSetTimer do (t: (target: machine, kind: tTimer, arg: int, epoch: int)) {
      send t.target, eTimer, (kind = t.kind, arg = t.arg, epoch = t.epoch);
    }
  }
}

// The clock: passes the expiry of up to fExpire messages, after a delay the
// scheduler chooses, telling each node separately (each judges by its own
// clock).
machine Clock {
  var cfg: tCfg;
  var nodes: seq[machine];
  var delay: int;

  start state Waiting {
    entry (p: (cfg: tCfg, nodes: seq[machine])) {
      cfg = p.cfg;
      nodes = p.nodes;
      if (cfg.fExpire > 0) {
        delay = choose(40);
        send this, eClockTick;
      }
    }

    on eClockTick do {
      var k: int;
      var m: int;
      var n: machine;

      if (delay > 0) {
        delay = delay - 1;
        send this, eClockTick;
        return;
      }

      k = 0;
      while (k < cfg.fExpire) {
        m = choose(cfg.nMsgs);
        foreach (n in nodes) {
          send n, eExpire, m;
        }

        k = k + 1;
      }
    }
  }
}

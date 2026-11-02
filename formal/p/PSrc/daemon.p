// A client daemon: the outbox and scheduler (daemon/scheduler.gleam,
// daemon/store.gleam outbox), the retransmit sweep (daemon/engine.gleam
// retransmit, core/retransmit.gleam), the fetcher (daemon/fetcher.gleam) and
// the inbound path (daemon/engine.gleam handle_envelope and receive,
// core/relationship.gleam receive, resend_receipt and store_application).
//
// Two instances run. A is the inviter: it commits an Accept (when pairing is
// modelled) and the agent's application messages, retransmits them, and
// reads receipts from QA. B is the joiner: it reads QB, stores application
// messages for its agent and queues receipts back to QA.
//
// State is split the way the daemon splits it. Everything a SQLite commit
// writes is durable and survives a crash; the in-flight set, the fetcher's
// state and the epoch are volatile and are reset by a crash. Every handler
// runs atomically, so one handler is one transaction plus the sends that
// follow it, and a crash point is a nondeterministic choice placed between
// a commit and the network action that must follow it.

machine Daemon {
  var cfg: tCfg;
  var isA: bool;
  var mbox: machine;
  var timer: machine;
  var myQ: int;
  var peerQ: int;

  // ------------------------------------------------------------ durable

  var outbox: map[int, tRow];
  var outOrder: seq[int];
  var sentState: map[int, tSent];
  var processed: map[int, tCt];
  var acked: set[int];
  var fingerprints: map[tFp, tFpRec];
  var delivered: map[int, int];
  var spent: set[tKey];
  var phase: tPhase;
  var attempts: map[int, int];
  var nextEnv: int;
  var receiptSeq: int;
  var agentNext: int;
  var expired: set[int];

  // Fault budgets this daemon spends.
  var crashesLeft: int;
  var procFailsLeft: int;
  var forgesLeft: int;

  // ----------------------------------------------------------- volatile

  var epoch: int;
  var inFlight: set[int];
  var fstate: tFState;
  var wake: bool;

  start state Init {
    entry (p: (cfg: tCfg, isA: bool, mbox: machine, timer: machine)) {
      cfg = p.cfg;
      isA = p.isA;
      mbox = p.mbox;
      timer = p.timer;

      if (isA) {
        myQ = QA();
        peerQ = QB();
        nextEnv = 1000;
        crashesLeft = cfg.fCrashA;
        procFailsLeft = cfg.fProcFailA;
        forgesLeft = cfg.fForge;
        phase = Active;
      } else {
        myQ = QB();
        peerQ = QA();
        nextEnv = 2000;
        crashesLeft = cfg.fCrashB;
        procFailsLeft = cfg.fProcFailB;

        // The joiner sent its Hello and waits for the inviter's Accept,
        // unless pairing is left out of the test case.
        if (cfg.pairing) {
          phase = AwaitingAccept;
        } else {
          phase = Active;
        }
      }

      fstate = FIdle;
      goto Running;
    }
  }

  state Running {
    entry {

      // The inviter approved, so it is Active and its Accept is its first
      // committed row; its agent's messages follow, one per event, so that
      // their sends interleave with everything else.
      if (isA && cfg.pairing) {
        SendAccept();
      }

      if (isA) {
        send this, eAgentSend;
      }

      StartRound();
    }

    on eAgentSend do { AgentSend(); }

    on eAppendResp do (r: (epoch: int, env: int, res: tRes)) {
      OnAppendResp(r);
    }

    on eFetchResp do (r: (epoch: int, ok: bool, batch: seq[tEnv])) {
      OnFetchResp(r);
    }

    on eAckResp do (r: (epoch: int, ok: bool, envs: seq[int])) {
      OnAckResp(r);
    }

    on eNewMail do (q: int) { StartRound(); }

    on eTimer do (t: (kind: tTimer, arg: int, epoch: int)) {
      OnTimer(t);
    }

    on eExpire do (m: int) {
      expired += (m);
      if (!isA) {
        announce eRecvExpired, m;
      }
    }
  }

  // ============================================================== crash

  // A crash point. Volatile state is lost and the daemon restarts at once
  // from what it committed; requests it had in flight are answered to the
  // old epoch and ignored, as a reply to a dead connection would be.
  fun MaybeCrash(): bool {
    if (crashesLeft > 0 && $) {
      crashesLeft = crashesLeft - 1;
      epoch = epoch + 1;
      inFlight = default(set[int]);
      fstate = FIdle;
      wake = false;
      Restart();
      return true;
    }

    return false;
  }

  // The restart path is the ordinary loop reading committed rows back: the
  // scheduler's startup tick sends every queued row, the retransmit sweep
  // finds every row whose window is running, and the fetcher begins a
  // round, which acknowledges whatever was processed and never acked.
  fun Restart() {
    var i: int;
    var env: int;

    i = 0;
    while (i < sizeof(outOrder)) {
      env = outOrder[i];
      if (outbox[env].status == Queued) {
        SendRow(env);
      }

      if (outbox[env].sched) {
        send timer, eSetTimer, (target = this, kind = TWindow, arg = env, epoch = epoch);
      }

      i = i + 1;
    }

    if (isA && agentNext < cfg.nMsgs) {
      send this, eAgentSend;
    }

    StartRound();
  }

  // ============================================================= outbox

  fun NewEnv(): int {
    nextEnv = nextEnv + 1;
    return nextEnv;
  }

  // Inserts an immutable ciphertext into the outbox (spec §8.2 step 4).
  fun CommitRow(ct: tCt, copies: int): int {
    var env: int;

    env = NewEnv();
    outbox[env] = (ct = ct, q = peerQ, status = Queued, copies = copies, sched = false);
    outOrder += (sizeof(outOrder), env);
    announce eCommitCt, ct;
    return env;
  }

  // Whether a row is past its deadline by this daemon's clock. Receipts
  // carry their own week-long expiry, which the model does not advance.
  fun RowExpired(ct: tCt): bool {
    if (ct.kind == KApp) {
      return ct.msg in expired;
    }

    return false;
  }

  // Sends one committed row. The bytes come from the row, never from the
  // caller, which is what "no send before commit" rests on. A row past its
  // deadline is failed without a send (scheduler.gleam).
  fun SendRow(env: int) {
    var row: tRow;

    row = outbox[env];
    if (row.status != Queued || env in inFlight) {
      return;
    }

    if (RowExpired(row.ct)) {
      outbox[env].status = Failed;
      return;
    }

    inFlight += (env);
    announce eWire, row.ct;
    send mbox, eAppend, (client = this, epoch = epoch, q = row.q, env = env, ct = row.ct);
  }

  fun SendAccept() {
    var env: int;
    var ct: tCt;

    ct = (kind = KAccept, msg = -1, mid = -1, seal = 0, dmg = false, pad = false);
    env = CommitRow(ct, 0);
    if (MaybeCrash()) {
      return;
    }

    SendRow(env);
  }

  // The agent's send: seal, commit, and only then transmit. The commit and
  // the liveness obligation are one step, so a crash after it is "commit
  // then crash before send" and the restart sends the row.
  fun AgentSend() {
    var m: int;
    var ct: tCt;
    var env: int;
    var forged: tCt;

    if (agentNext >= cfg.nMsgs) {
      return;
    }

    m = agentNext;
    ct = (kind = KApp, msg = m, mid = m, seal = 0, dmg = false, pad = false);

    // Mutant: put the ciphertext on the wire before the outbox row commits.
    if (cfg.mSendBeforeCommit) {
      env = NewEnv();
      inFlight += (env);
      announce eWire, ct;
      send mbox, eAppend, (client = this, epoch = epoch, q = peerQ, env = env, ct = ct);
      outbox[env] = (ct = ct, q = peerQ, status = Queued, copies = 0, sched = false);
      outOrder += (sizeof(outOrder), env);
      announce eCommitCt, ct;
    } else {
      env = CommitRow(ct, 0);
    }

    agentNext = agentNext + 1;
    sentState[m] = LocallyQueued;
    announce eCommittedMsg, m;

    // A byzantine but authenticated peer seals different bytes under the
    // identifier it just used (the H2 hypothesis of the DST audit).
    if (forgesLeft > 0) {
      forgesLeft = forgesLeft - 1;
      forged = (kind = KApp, msg = m, mid = m, seal = 1, dmg = false, pad = false);
      SendRow(CommitRow(forged, 0));
    }

    if (MaybeCrash()) {
      return;
    }

    SendRow(env);
    if (agentNext < cfg.nMsgs) {
      send this, eAgentSend;
    }
  }

  fun OnAppendResp(r: (epoch: int, env: int, res: tRes)) {
    if (r.epoch != epoch || !(r.env in inFlight)) {
      return;
    }

    inFlight -= (r.env);

    // A crash before the outcome is recorded is the append response lost.
    if (MaybeCrash()) {
      return;
    }

    if (r.res == RAppended) {
      RecordStored(r.env);
    } else if (r.res == RConflict) {
      outbox[r.env].status = Failed;
    } else {
      send timer, eSetTimer, (target = this, kind = TRetry, arg = r.env, epoch = epoch);
    }
  }

  // record_send(Stored): the row is stored, the message advances to
  // StoredByMailbox, and a row that a receipt could still end gets its
  // retransmit_at from retransmit.due_at.
  fun RecordStored(env: int) {
    var row: tRow;

    row = outbox[env];
    if (row.status != Queued) {
      return;
    }

    outbox[env].status = Stored;
    if (row.ct.kind == KApp && row.ct.mid in sentState && sentState[row.ct.mid] == LocallyQueued) {
      sentState[row.ct.mid] = StoredByMailbox;
    }

    if (Schedulable(row)) {
      outbox[env].sched = true;
      send timer, eSetTimer, (target = this, kind = TWindow, arg = env, epoch = epoch);
    }
  }

  // retransmit.due_at: application messages and controls only, fewer than
  // max_retransmits copies so far, not receipted, not past the deadline.
  fun Schedulable(row: tRow): bool {
    if (!cfg.retransmit) {
      return false;
    }

    if (row.ct.kind == KReceipt) {
      return false;
    }

    if (row.copies >= cfg.maxRetx || RowExpired(row.ct)) {
      return false;
    }

    if (row.ct.kind == KApp && Receipted(row.ct.mid)) {
      return false;
    }

    return true;
  }

  fun Receipted(mid: int): bool {
    return mid in sentState && sentState[mid] == ReceivedByPeer;
  }

  // A receipt window passed for a stored row (engine.retransmit_one). The
  // copy is the same committed ciphertext under a fresh envelope, committed
  // as an ordinary queued row; the replaced row's schedule ends.
  fun Retransmit(env: int) {
    var row: tRow;
    var ct: tCt;
    var fresh: int;

    row = outbox[env];
    if (!row.sched) {
      return;
    }

    // retransmit.check_bounds: Exhausted or Expired ends the schedule.
    if (row.copies >= cfg.maxRetx || RowExpired(row.ct) || (row.ct.kind == KApp && Receipted(row.ct.mid))) {
      outbox[env].sched = false;
      return;
    }

    ct = row.ct;

    // Mutant: seal the copy again from the current session, which makes a
    // new message under a new identifier (ADR-006, "Why the same bytes").
    if (cfg.mReencrypt && ct.kind == KApp) {
      ct.seal = row.copies + 1;
      ct.mid = ct.msg + 100 * (row.copies + 1);
      sentState[ct.mid] = LocallyQueued;
    }

    fresh = CommitRow(ct, row.copies + 1);
    outbox[env].sched = false;
    if (MaybeCrash()) {
      return;
    }

    SendRow(fresh);
  }

  fun OnTimer(t: (kind: tTimer, arg: int, epoch: int)) {
    if (t.epoch != epoch) {
      return;
    }

    if (t.kind == TRetry) {
      SendRow(t.arg);
    } else if (t.kind == TWindow) {
      Retransmit(t.arg);
    } else {
      if (fstate == FBackoff) {
        fstate = FIdle;
        StartRound();
      }
    }
  }

  // ============================================================ fetcher

  // One round: acknowledge what the store says is processed and unacked,
  // then long-poll and process the batch in order. A round that is already
  // running notes the wake-up instead, so new mail is never missed.
  fun StartRound() {
    var pending: seq[int];
    var e: int;

    if (fstate != FIdle) {
      wake = true;
      return;
    }

    wake = false;
    foreach (e in keys(processed)) {
      if (!(e in acked)) {
        pending += (sizeof(pending), e);
      }
    }

    if (sizeof(pending) > 0) {
      fstate = FAcking;
      announce eAckSent, pending;
      send mbox, eAck, (client = this, epoch = epoch, q = myQ, envs = pending);
    } else {
      fstate = FFetching;
      send mbox, eFetch, (client = this, epoch = epoch, q = myQ);
    }
  }

  fun Backoff() {
    fstate = FBackoff;
    send timer, eSetTimer, (target = this, kind = TBackoff, arg = 0, epoch = epoch);
  }

  fun OnAckResp(r: (epoch: int, ok: bool, envs: seq[int])) {
    var e: int;

    if (r.epoch != epoch || fstate != FAcking) {
      return;
    }

    if (!r.ok) {
      Backoff();
      return;
    }

    foreach (e in r.envs) {
      acked += (e);
    }

    fstate = FFetching;
    send mbox, eFetch, (client = this, epoch = epoch, q = myQ);
  }

  fun OnFetchResp(r: (epoch: int, ok: bool, batch: seq[tEnv])) {
    var i: int;
    var res: tPRes;
    var early: seq[int];

    if (r.epoch != epoch || fstate != FFetching) {
      return;
    }

    if (!r.ok) {
      Backoff();
      return;
    }

    // Mutant: acknowledge the batch as fetched, before any commit.
    if (cfg.mAckBeforeCommit && sizeof(r.batch) > 0) {
      i = 0;
      while (i < sizeof(r.batch)) {
        early += (i, r.batch[i].env);
        i = i + 1;
      }

      announce eAckSent, early;
      send mbox, eAck, (client = this, epoch = epoch + 1000, q = myQ, envs = early);
    }

    // In order, stopping at the first envelope the engine cannot commit
    // (fetcher.process_batch).
    i = 0;
    while (i < sizeof(r.batch)) {
      res = Process(r.batch[i].env, r.batch[i].ct);
      if (res == PCrashed) {
        return;
      }

      if (res == PFail) {
        Backoff();
        return;
      }

      i = i + 1;
    }

    fstate = FIdle;
    if (sizeof(r.batch) > 0 || wake) {
      StartRound();
    }
  }

  // ============================================================ inbound

  // engine.handle_envelope. The processed rule first (identifier and
  // digest), then quarantine, then the frame: a ratchet frame is looked up
  // by fingerprint before it is decrypted (engine.receive).
  fun Process(env: int, ct: tCt): tPRes {
    var fp: tFp;

    // The processed rule: same identifier and digest is a Repeat, and
    // nothing of the relationship is committed. The fetcher acknowledges
    // only rows with acked = 0, so engine.repeat marks an envelope that
    // was already acknowledged, and is served again, unacknowledged: the
    // next round names it (ADR-010, addendum). reackRepeat off is the code
    // before that fix, which never acknowledged such an envelope again.
    if (env in processed && processed[env] == ct) {
      if (cfg.reackRepeat && env in acked) {
        acked -= (env);
      }

      return POk;
    }

    // ADR-010 (draft, branch dedup): an envelope handed to the core
    // max_process_attempts times without its outcome committing is set
    // aside the next time it is served: recorded, dropped, acknowledged.
    if (cfg.quarantine && env in attempts && attempts[env] >= cfg.maxAttempts) {
      return Commit(env, ct);
    }

    // A transient store fault: nothing commits, the attempt is counted.
    if (procFailsLeft > 0 && $) {
      procFailsLeft = procFailsLeft - 1;
      return Failed(env);
    }

    fp = (mid = ct.mid, seal = ct.seal);
    if (cfg.fingerprint && ct.kind == KApp && !ct.dmg && fp in fingerprints) {
      return ResendReceipt(env, ct, fp);
    }

    // The ratchet: a damaged ciphertext or a spent key does not decrypt,
    // and a refusal changes nothing but the processed record.
    if (ct.dmg || (kind = ct.kind, mid = ct.mid, seal = ct.seal) in spent) {
      return Commit(env, ct);
    }

    if (ct.kind == KReceipt) {
      return OnReceipt(env, ct);
    }

    if (ct.kind == KAccept) {
      spent += ((kind = ct.kind, mid = ct.mid, seal = ct.seal));
      phase = Active;
      return Commit(env, ct);
    }

    return OnApplication(env, ct);
  }

  fun Failed(env: int): tPRes {
    if (env in attempts) {
      attempts[env] = attempts[env] + 1;
    } else {
      attempts[env] = 1;
    }

    return PFail;
  }

  // Commits the Processed record (with whatever the caller already put in
  // the same transaction) and offers the crash point "after commit, before
  // ack".
  fun Commit(env: int, ct: tCt): tPRes {
    processed[env] = ct;
    if (env in acked) {
      acked -= (env);
    }

    announce eProcCommitted, env;
    if (MaybeCrash()) {
      return PCrashed;
    }

    return POk;
  }

  // relationship.resend_receipt: Active only, not past the message's
  // expiry, at most max_retransmits answers beyond the first receipt.
  fun ResendReceipt(env: int, ct: tCt, fp: tFp): tPRes {
    var known: tFpRec;
    var limit: int;

    known = fingerprints[fp];
    limit = cfg.maxRetx;

    // Mutant: one answer fewer than an honest sender can ask for.
    if (cfg.mTightAnswers) {
      limit = cfg.maxRetx - 1;
    }

    if (phase != Active || known.msg in expired || known.receipts > limit) {
      return Commit(env, ct);
    }

    fingerprints[fp] = (msg = known.msg, receipts = known.receipts + 1);
    return CommitAndSend(env, ct, QueueReceipt(known.msg, ct.mid));
  }

  // A receipt row commits in the same transaction as the processed record,
  // and is sentState only after it.
  fun QueueReceipt(m: int, mid: int): int {
    var rct: tCt;

    receiptSeq = receiptSeq + 1;
    rct = (kind = KReceipt, msg = m, mid = mid, seal = receiptSeq, dmg = false, pad = false);
    announce eReceiptQueued, m;
    return CommitRow(rct, 0);
  }

  // The engine's commit notifies the scheduler only after it returned, so
  // the receipt row is sentState after the crash point, never before.
  fun CommitAndSend(env: int, ct: tCt, row: int): tPRes {
    var res: tPRes;

    res = Commit(env, ct);
    if (res != POk) {
      return res;
    }

    SendRow(row);
    return POk;
  }

  // relationship.in_active Receipt: PeerReceived ends every schedule of a
  // row carrying the message (store.gleam end_message_schedules).
  fun OnReceipt(env: int, ct: tCt): tPRes {
    var e: int;

    spent += ((kind = ct.kind, mid = ct.mid, seal = ct.seal));
    if (ct.mid in sentState) {
      sentState[ct.mid] = ReceivedByPeer;
      foreach (e in outOrder) {
        if (outbox[e].ct.kind == KApp && outbox[e].ct.mid == ct.mid) {
          outbox[e].sched = false;
        }
      }

      announce eSenderReceived, ct.msg;
    }

    return Commit(env, ct);
  }

  // in_active / in_awaiting Application and store_application.
  fun OnApplication(env: int, ct: tCt): tPRes {
    var key: tKey;

    key = (kind = ct.kind, mid = ct.mid, seal = ct.seal);

    // ADR-004: an authenticated application message in AwaitingAccept is
    // an implicit Accept. Before it, the session advanced and the message
    // was dropped.
    if (phase == AwaitingAccept) {
      if (!cfg.implicitAccept) {
        spent += (key);
        return Commit(env, ct);
      }

      phase = Active;
    }

    // Expired: the session advances, nothing is stored or receipted.
    if (ct.msg in expired && !cfg.mIgnoreExpiry) {
      spent += (key);
      if (cfg.mReceiptForExpired) {
        return CommitAndSend(env, ct, QueueReceipt(ct.msg, ct.mid));
      }

      return Commit(env, ct);
    }

    // H2: an identifier already stored under. Ruled: ignored and
    // acknowledged. Before the ruling the store's UNIQUE (contact,
    // message_id) refused the commit, so nothing committed at all.
    if (ct.mid in delivered) {
      if (!cfg.h2) {
        return Failed(env);
      }

      spent += (key);
      return Commit(env, ct);
    }

    spent += (key);
    delivered[ct.mid] = ct.msg;
    fingerprints[(mid = ct.mid, seal = ct.seal)] = (msg = ct.msg, receipts = 1);
    announce eDelivered, ct.msg;
    return CommitAndSend(env, ct, QueueReceipt(ct.msg, ct.mid));
  }
}

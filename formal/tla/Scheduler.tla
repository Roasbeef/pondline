------------------------------ MODULE Scheduler ------------------------------
(***************************************************************************)
(* A model of the delivery scheduler,                                      *)
(* packages/daemon/src/daemon/scheduler.gleam, and the parts of the engine *)
(* and the store it talks to.                                              *)
(*                                                                         *)
(* The scheduler is one actor. Every message it handles (Nudge, Tick, its  *)
(* own Finished, and what a run's relay pushes) is one atomic step here,   *)
(* ending in `dispatch` exactly as `handle` (scheduler.gleam:395) does.    *)
(* The engine asks inside a handler (`due_outbox`, `record_send`,          *)
(* `retransmit`) are serialised by the engine actor and touch only the row *)
(* they name, so folding them into the handler's step commutes with every  *)
(* other engine client in this model.                                      *)
(*                                                                         *)
(* A run (`send_batch`, scheduler.gleam:504) is a process per run slot. It *)
(* starts tasks, completes them with a verdict, hits its deadline, or is   *)
(* lost, and it pushes each outcome and then exactly one end marker into   *)
(* the scheduler's single FIFO mailbox (weft `start_relayed`). One         *)
(* mailbox is what Erlang gives: the selector (`listening`,                *)
(* scheduler.gleam:426) matches every subject of a live run, so messages   *)
(* are taken in arrival order and no source can starve another.           *)
(*                                                                         *)
(* Mutation switches, each reintroducing a hazard commit 3035697 fixed:    *)
(*   ClaimMode = "run"     close releases only Sending(s) claims (current) *)
(*             = "batch"   close releases every row of its batch, the      *)
(*                         pre-3035697 envelope-keyed claim                *)
(*             = "anyend"  close releases every Sending claim of any run   *)
(*   HeldMode  = "held"    a failed record holds the row to the next Tick  *)
(*             = "immediate" a failed record drops the claim and the       *)
(*                         dispatch that follows resends at once           *)
(*             = "sticky"  a Tick never releases a Held claim (mutant for  *)
(*                         the liveness property)                          *)
(*   ReadMode  = "store"   dispatch reads committed `queued` rows (current)*)
(*             = "plan"    dispatch also reads rows not yet committed      *)
(*                         (mutant: a send before commit)                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    InitRows,       \* Rows committed `queued` before the scheduler starts.
    LateRows,       \* Rows the engine commits later, with or without a Nudge.
    CopyRows,       \* Rows a Tick's `retransmit` may commit as copies.
    Slots,          \* Run identities (a run's subject), recycled once closed.
    MaxInFlight,    \* `max_in_flight` (scheduler.gleam:133).
    MaxAttempts,    \* Attempts after which a row is past its deadline.
    MaxRecordFails, \* Budget of `record_send` calls that answer Error.
    MaxRunFaults,   \* Budget of RunLost markers and NeverStarted deadlines.
    MaxRestarts,    \* Budget of scheduler crashes (supervisor restarts).
    ClaimMode,      \* "run" | "batch" | "anyend"; see the header.
    HeldMode,       \* "held" | "immediate" | "sticky"; see the header.
    ReadMode        \* "store" | "plan"; see the header.

ASSUME ClaimMode \in {"run", "batch", "anyend"}
ASSUME HeldMode \in {"held", "immediate", "sticky"}
ASSUME ReadMode \in {"store", "plan"}

\* The rows `store.due` can return: committed and queued, or for the
\* "plan" mutant, also a row whose commit has not happened yet.
Readable == IF ReadMode = "store" THEN {"queued"} ELSE {"queued", "absent"}

Rows == InitRows \cup LateRows \cup CopyRows

\* The `Claim` type (scheduler.gleam:220) plus "none" for an absent key.
NoClaim == [kind |-> "none", run |-> 0]
Expiring == [kind |-> "expiring", run |-> 0]
HeldClaim == [kind |-> "held", run |-> 0]
Sending(s) == [kind |-> "sending", run |-> s]

\* One shape for every mailbox message so TLC compares like with like.
Msg(t, s, r, v) == [type |-> t, run |-> s, row |-> r, v |-> v]
TickMsg == Msg("tick", 0, 0, "none")
NudgeMsg == Msg("nudge", 0, 0, "none")
FinishedMsg(r) == Msg("finished", 0, r, "ref")
OutMsg(s, r, v) == Msg("out", s, r, v)
EndMsg(s) == Msg("end", s, 0, "none")
LostMsg(s) == Msg("lost", s, 0, "none")

FreeRun == [phase |-> "free", task |-> [r \in Rows |-> "none"]]

Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Cap(n) == IF n > MaxAttempts THEN MaxAttempts ELSE n

\* The per-period send counter saturates one past anything an invariant
\* allows, which keeps the ghost from multiplying states.
Bump(n) == IF n >= 1 + MaxRunFaults + MaxRestarts + 1 THEN n ELSE n + 1

\* `list.take` over rows in rowid order, which is the order `store.due`
\* reads them (outbox.sql `ORDER BY rowid`).
RECURSIVE FirstK(_, _)
FirstK(S, k) ==
    IF k <= 0 \/ S = {} THEN {}
    ELSE {Min(S)} \cup FirstK(S \ {Min(S)}, k - 1)

\* `Finished(row, Refused)` self-sends for expired rows, in row order.
RECURSIVE FinishedSeq(_)
FinishedSeq(S) ==
    IF S = {} THEN <<>>
    ELSE <<FinishedMsg(Min(S))>> \o FinishedSeq(S \ {Min(S)})

\* The outcomes a run's deadline settles, one per open task, in row order:
\* `Abandoned` (verdict "trans") or `NeverStarted` ("unatt").
RECURSIVE DeadlineSeq(_, _, _)
DeadlineSeq(s, S, v) ==
    IF S = {} THEN <<>>
    ELSE <<OutMsg(s, Min(S), v)>> \o DeadlineSeq(s, S \ {Min(S)}, v)

Claimed(c) == {r \in Rows : c[r].kind # "none"}

(***************************************************************************)
(* `dispatch` (scheduler.gleam:440) and `start_batch` (:476) as one pure   *)
(* function of the state after the handler's own change. The run slot is  *)
(* the lowest free one; with no free slot the dispatch is skipped, which   *)
(* is what the real code does when `due_outbox` answers Error (:470).      *)
(***************************************************************************)
Dispatch(c, st, du, at, rn, m) ==
    LET room == MaxInFlight - Cardinality(Claimed(c))
        read == FirstK({r \in Rows : st[r] \in Readable /\ du[r]},
                       2 * MaxInFlight)
        chosen == FirstK({r \in read : c[r].kind = "none"}, room)
        expired == {r \in chosen : at[r] >= MaxAttempts}
        live == chosen \ expired
        free == {s \in Slots : rn[s].phase = "free"}
        slot == IF free = {} THEN 0 ELSE Min(free)
    IN  IF room <= 0 \/ (live # {} /\ free = {})
        THEN [claim |-> c, run |-> rn, mq |-> m, started |-> {}]
        ELSE [claim |-> [r \in Rows |->
                           IF r \in expired THEN Expiring
                           ELSE IF r \in live THEN Sending(slot)
                           ELSE c[r]],
              run |-> IF live = {} THEN rn
                      ELSE [rn EXCEPT ![slot] =
                              [phase |-> "running",
                               task |-> [r \in Rows |->
                                           IF r \in live THEN "sending"
                                           ELSE "none"]]],
              mq |-> m \o FinishedSeq(expired),
              started |-> live]

(***************************************************************************

--algorithm Scheduler
variables
    \* The store's outbox (outbox.sql): status, attempts, and whether
    \* `next_attempt_at <= now`.
    status = [r \in Rows |-> IF r \in InitRows THEN "queued" ELSE "absent"],
    attempts = [r \in Rows |-> 0],
    due = [r \in Rows |-> TRUE],

    \* The actor's state: `in_flight` and the table of running batches.
    claim = [r \in Rows |-> NoClaim],
    run = [s \in Slots |-> FreeRun],

    \* The actor's one mailbox; `continuing(Tick)` puts a Tick first.
    mq = <<TickMsg>>,

    \* Fault budgets.
    recFails = 0,
    runFaults = 0,
    restarts = 0,

    \* Ghosts for the invariants. `sends` counts task starts per row since
    \* the clock last advanced, `faultsSince` the run faults and restarts in
    \* the same window; `heldPending` marks rows whose record failed since
    \* the last Tick was handled.
    sends = [r \in Rows |-> 0],
    faultsSince = 0,
    heldPending = [r \in Rows |-> FALSE],
    earlyResend = FALSE,
    staleRelease = FALSE;

define
    OutQueued(s, r) ==
        \E i \in 1..Len(mq) : mq[i].type = "out" /\ mq[i].run = s
                               /\ mq[i].row = r
    FinishedQueued(r) ==
        \E i \in 1..Len(mq) : mq[i].type = "finished" /\ mq[i].row = r
    TickQueued == \E i \in 1..Len(mq) : mq[i].type = "tick"
    NudgeQueued == \E i \in 1..Len(mq) : mq[i].type = "nudge"

    \* `record_send`'s answer: Ok, Error before the write, or Error after it
    \* (engine.gleam:425 `answer`, ApplyThenFail).
    Fates == IF recFails < MaxRecordFails
             THEN {"apply", "before", "after"} ELSE {"apply"}

    \* The copy a Tick's `retransmit_due` (scheduler.gleam:411) may commit:
    \* none, or the lowest unused copy row once some row is stored.
    CopyChoice ==
        LET unused == {r \in CopyRows : status[r] = "absent"}
        IN  {0} \cup (IF unused # {} /\ \E r \in Rows : status[r] = "stored"
                      THEN {Min(unused)} ELSE {})
end define;

\* Every handler ends in `dispatch`; this applies its result and the ghosts.
macro Commit(c1, st1, at1, du1, rn1, m1, hp1) begin
    with d = Dispatch(c1, st1, du1, at1, rn1, m1) do
        claim := d.claim || run := d.run || mq := d.mq;
        status := st1 || attempts := at1 || due := du1;
        heldPending := hp1;
        sends := [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                  ELSE sends[x_]];
        earlyResend := earlyResend \/ (\E x_ \in d.started : hp1[x_]);
    end with;
end macro;

\* `finish` (scheduler.gleam:708): record the verdict through the engine,
\* end the claim on Ok, hold it on Error, then dispatch.
macro Finish(row_, ver_, mq_) begin
    with fate \in Fates,
         write = fate \in {"apply", "after"},
         st1 = IF write /\ ver_ = "acc" THEN [status EXCEPT ![row_] = "stored"]
               ELSE IF write /\ ver_ = "ref" THEN [status EXCEPT ![row_] = "failed"]
               ELSE status,
         at1 = IF write /\ ver_ = "trans"
               THEN [attempts EXCEPT ![row_] = Cap(@ + 1)] ELSE attempts,
         du1 = IF write /\ ver_ = "trans" THEN [due EXCEPT ![row_] = FALSE]
               ELSE due,
         c1 = [claim EXCEPT ![row_] =
                 IF fate = "apply" \/ HeldMode = "immediate" THEN NoClaim
                 ELSE HeldClaim],
         hp1 = IF fate = "apply" THEN heldPending
               ELSE [heldPending EXCEPT ![row_] = TRUE] do
        recFails := recFails + (IF fate = "apply" THEN 0 ELSE 1);
        Commit(c1, st1, at1, du1, run, mq_, hp1);
    end with;
end macro;

fair process Sched = 100
begin
Handle:
    while TRUE do
        either
            \* Tick (scheduler.gleam:400): `release_held` (:527), then
            \* `retransmit_due` (:411), then `dispatch`.
            await mq # <<>> /\ Head(mq).type = "tick";
            with cp \in CopyChoice,
                 c1 = [r \in Rows |-> IF claim[r].kind = "held"
                                         /\ HeldMode # "sticky"
                                      THEN NoClaim ELSE claim[r]],
                 st1 = IF cp = 0 THEN status
                       ELSE [status EXCEPT ![cp] = "queued"],
                 du1 = IF cp = 0 THEN due ELSE [due EXCEPT ![cp] = TRUE] do
                Commit(c1, st1, attempts, du1, run, Tail(mq),
                       [r \in Rows |-> FALSE]);
            end with;
        or
            \* Nudge (scheduler.gleam:399): `dispatch`.
            await mq # <<>> /\ Head(mq).type = "nudge";
            Commit(claim, status, attempts, due, run, Tail(mq), heldPending);
        or
            \* Finished(row, Refused), sent to itself by `dispatch` for an
            \* expired row (scheduler.gleam:460): `finish`.
            await mq # <<>> /\ Head(mq).type = "finished";
            Finish(Head(mq).row, "ref", Tail(mq));
        or
            \* Settled(PulledOutcome) with an attempt (`settle` :614,
            \* `conclude` :672): `finish`.
            await mq # <<>> /\ Head(mq).type = "out"
                  /\ Head(mq).v \in {"acc", "ref", "trans"};
            Finish(Head(mq).row, Head(mq).v, Tail(mq));
        or
            \* Settled(PulledOutcome(NeverStarted)) (`conclude` :675): the
            \* claim is deleted whatever it is, then `dispatch`.
            await mq # <<>> /\ Head(mq).type = "out"
                  /\ Head(mq).v = "unatt";
            Commit([claim EXCEPT ![Head(mq).row] = NoClaim], status,
                   attempts, due, run, Tail(mq), heldPending);
        or
            \* Settled(AllDelivered | RunLost) (`settle` :628-632, `close`
            \* :689): release the run's claims, forget the batch, dispatch.
            await mq # <<>> /\ Head(mq).type \in {"end", "lost"};
            with s = Head(mq).run,
                 released = CASE ClaimMode = "run" ->
                                   {r \in Rows : claim[r] = Sending(s)}
                              [] ClaimMode = "batch" ->
                                   {r \in Rows : run[s].task[r] # "none"}
                              [] ClaimMode = "anyend" ->
                                   {r \in Rows : claim[r].kind = "sending"},
                 c1 = [r \in Rows |-> IF r \in released THEN NoClaim
                                      ELSE claim[r]] do
                staleRelease := staleRelease \/
                    (\E r \in released : claim[r].kind # "none"
                                         /\ claim[r] # Sending(s));
                Commit(c1, status, attempts, due,
                       [run EXCEPT ![s] = FreeRun], Tail(mq), heldPending);
            end with;
        or
            \* The scheduler crashes and its supervisor restarts it
            \* (`supervised` :267). The relays are linked, so every run dies
            \* with it; the new actor handles a Tick first (`builder` :286).
            await restarts < MaxRestarts;
            claim := [r \in Rows |-> NoClaim] || run := [s \in Slots |-> FreeRun]
                || mq := <<TickMsg>>;
            restarts := restarts + 1 || faultsSince := faultsSince + 1;
        end either;
    end while;
end process;

\* One weft run of sends (`send_batch`, scheduler.gleam:504), relayed.
fair process Run \in Slots
begin
Work:
    while TRUE do
        either
            \* A send ends: `classify` (:337) gives Accepted, Refused or
            \* Transient. A crashed or failed task is Transient too
            \* (`settlement` :641), so it is the same step.
            with r \in {x \in Rows : run[self].task[x] = "sending"},
                 v \in {"acc", "ref", "trans"} do
                run[self].task[r] := "done" || mq := Append(mq, OutMsg(self, r, v));
            end with;
        or
            \* All tasks settled: the scope says Done, the relay pushes
            \* AllDelivered. The marker may wait behind any number of other
            \* messages, which is what makes it stale.
            await run[self].phase = "running"
                  /\ \A x \in Rows : run[self].task[x] \in {"none", "done"};
            run[self].phase := "ended" || mq := Append(mq, EndMsg(self));
        or
            \* `weft.deadline(send_deadline_ms)`: the sends still going are
            \* Abandoned (a Transient attempt), then AllDelivered.
            await run[self].phase = "running"
                  /\ \E x \in Rows : run[self].task[x] = "sending";
            with open = {x \in Rows : run[self].task[x] = "sending"} do
                mq := mq \o DeadlineSeq(self, open, "trans")
                         \o <<EndMsg(self)>>;
                run[self] := [phase |-> "ended",
                              task |-> [x \in Rows |->
                                          IF x \in open THEN "done"
                                          ELSE run[self].task[x]]];
            end with;
        or
            \* The deadline ends the run before its tasks had a slot: each
            \* is NeverStarted. With `limit` >= the batch every task starts
            \* when the run does, so this spends a fault.
            await run[self].phase = "running" /\ runFaults < MaxRunFaults
                  /\ \E x \in Rows : run[self].task[x] = "sending";
            with open = {x \in Rows : run[self].task[x] = "sending"} do
                mq := mq \o DeadlineSeq(self, open, "unatt")
                         \o <<EndMsg(self)>>;
                run[self] := [phase |-> "ended",
                              task |-> [x \in Rows |->
                                          IF x \in open THEN "done"
                                          ELSE run[self].task[x]]];
                runFaults := runFaults + 1 || faultsSince := faultsSince + 1;
            end with;
        or
            \* The scope dies from outside: RunLost, and no further outcome.
            await run[self].phase = "running" /\ runFaults < MaxRunFaults;
            mq := Append(mq, LostMsg(self));
            run[self] := [phase |-> "ended",
                          task |-> [x \in Rows |->
                                      IF run[self].task[x] = "none" THEN "none"
                                      ELSE "done"]];
            runFaults := runFaults + 1 || faultsSince := faultsSince + 1;
        end either;
    end while;
end process;

\* `actor.periodic(every: tick_ms, sending: Tick)` (scheduler.gleam:291).
\* Firing is also the clock advancing: a retry's `next_attempt_at` passes
\* (backoff is at least two ticks, so never sooner), and the per-period
\* counters restart.
fair process Timer = 101
begin
Fire:
    while TRUE do
        await ~TickQueued;
        mq := Append(mq, TickMsg) || due := [r \in Rows |-> TRUE]
            || sends := [r \in Rows |-> 0] || faultsSince := 0;
    end while;
end process;

\* Other engine clients commit rows: `engine.send` commits an outbox row
\* and nudges (`scheduler.nudge` :304), and a nudge may be lost.
process Engine = 102
begin
Accept:
    while TRUE do
        with r \in {x \in LateRows : status[x] = "absent"}, nudge \in BOOLEAN do
            status[r] := "queued" || due[r] := TRUE;
            if nudge /\ ~NudgeQueued then
                mq := Append(mq, NudgeMsg);
            end if;
        end with;
    end while;
end process;

end algorithm;

***************************************************************************)
\* BEGIN TRANSLATION
VARIABLES status, attempts, due, claim, run, mq, recFails, runFaults, 
          restarts, sends, faultsSince, heldPending, earlyResend, 
          staleRelease

(* define statement *)
OutQueued(s, r) ==
    \E i \in 1..Len(mq) : mq[i].type = "out" /\ mq[i].run = s
                           /\ mq[i].row = r
FinishedQueued(r) ==
    \E i \in 1..Len(mq) : mq[i].type = "finished" /\ mq[i].row = r
TickQueued == \E i \in 1..Len(mq) : mq[i].type = "tick"
NudgeQueued == \E i \in 1..Len(mq) : mq[i].type = "nudge"



Fates == IF recFails < MaxRecordFails
         THEN {"apply", "before", "after"} ELSE {"apply"}



CopyChoice ==
    LET unused == {r \in CopyRows : status[r] = "absent"}
    IN  {0} \cup (IF unused # {} /\ \E r \in Rows : status[r] = "stored"
                  THEN {Min(unused)} ELSE {})


vars == << status, attempts, due, claim, run, mq, recFails, runFaults, 
           restarts, sends, faultsSince, heldPending, earlyResend, 
           staleRelease >>

ProcSet == {100} \cup (Slots) \cup {101} \cup {102}

Init == (* Global variables *)
        /\ status = [r \in Rows |-> IF r \in InitRows THEN "queued" ELSE "absent"]
        /\ attempts = [r \in Rows |-> 0]
        /\ due = [r \in Rows |-> TRUE]
        /\ claim = [r \in Rows |-> NoClaim]
        /\ run = [s \in Slots |-> FreeRun]
        /\ mq = <<TickMsg>>
        /\ recFails = 0
        /\ runFaults = 0
        /\ restarts = 0
        /\ sends = [r \in Rows |-> 0]
        /\ faultsSince = 0
        /\ heldPending = [r \in Rows |-> FALSE]
        /\ earlyResend = FALSE
        /\ staleRelease = FALSE

Sched == /\ \/ /\ mq # <<>> /\ Head(mq).type = "tick"
               /\ \E cp \in CopyChoice:
                    LET c1 == [r \in Rows |-> IF claim[r].kind = "held"
                                                 /\ HeldMode # "sticky"
                                              THEN NoClaim ELSE claim[r]] IN
                      LET st1 == IF cp = 0 THEN status
                                 ELSE [status EXCEPT ![cp] = "queued"] IN
                        LET du1 == IF cp = 0 THEN due ELSE [due EXCEPT ![cp] = TRUE] IN
                          LET d == Dispatch(c1, st1, du1, attempts, run, (Tail(mq))) IN
                            /\ /\ claim' = d.claim
                               /\ mq' = d.mq
                               /\ run' = d.run
                            /\ /\ attempts' = attempts
                               /\ due' = du1
                               /\ status' = st1
                            /\ heldPending' = [r \in Rows |-> FALSE]
                            /\ sends' = [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                                         ELSE sends[x_]]
                            /\ earlyResend' = (earlyResend \/ (\E x_ \in d.started : ([r \in Rows |-> FALSE])[x_]))
               /\ UNCHANGED <<recFails, restarts, faultsSince, staleRelease>>
            \/ /\ mq # <<>> /\ Head(mq).type = "nudge"
               /\ LET d == Dispatch(claim, status, due, attempts, run, (Tail(mq))) IN
                    /\ /\ claim' = d.claim
                       /\ mq' = d.mq
                       /\ run' = d.run
                    /\ /\ attempts' = attempts
                       /\ due' = due
                       /\ status' = status
                    /\ heldPending' = heldPending
                    /\ sends' = [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                                 ELSE sends[x_]]
                    /\ earlyResend' = (earlyResend \/ (\E x_ \in d.started : heldPending'[x_]))
               /\ UNCHANGED <<recFails, restarts, faultsSince, staleRelease>>
            \/ /\ mq # <<>> /\ Head(mq).type = "finished"
               /\ \E fate \in Fates:
                    LET write == fate \in {"apply", "after"} IN
                      LET st1 == IF write /\ "ref" = "acc" THEN [status EXCEPT ![(Head(mq).row)] = "stored"]
                                 ELSE IF write /\ "ref" = "ref" THEN [status EXCEPT ![(Head(mq).row)] = "failed"]
                                 ELSE status IN
                        LET at1 == IF write /\ "ref" = "trans"
                                   THEN [attempts EXCEPT ![(Head(mq).row)] = Cap(@ + 1)] ELSE attempts IN
                          LET du1 == IF write /\ "ref" = "trans" THEN [due EXCEPT ![(Head(mq).row)] = FALSE]
                                     ELSE due IN
                            LET c1 == [claim EXCEPT ![(Head(mq).row)] =
                                         IF fate = "apply" \/ HeldMode = "immediate" THEN NoClaim
                                         ELSE HeldClaim] IN
                              LET hp1 == IF fate = "apply" THEN heldPending
                                         ELSE [heldPending EXCEPT ![(Head(mq).row)] = TRUE] IN
                                /\ recFails' = recFails + (IF fate = "apply" THEN 0 ELSE 1)
                                /\ LET d == Dispatch(c1, st1, du1, at1, run, (Tail(mq))) IN
                                     /\ /\ claim' = d.claim
                                        /\ mq' = d.mq
                                        /\ run' = d.run
                                     /\ /\ attempts' = at1
                                        /\ due' = du1
                                        /\ status' = st1
                                     /\ heldPending' = hp1
                                     /\ sends' = [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                                                  ELSE sends[x_]]
                                     /\ earlyResend' = (earlyResend \/ (\E x_ \in d.started : hp1[x_]))
               /\ UNCHANGED <<restarts, faultsSince, staleRelease>>
            \/ /\ mq # <<>> /\ Head(mq).type = "out"
                  /\ Head(mq).v \in {"acc", "ref", "trans"}
               /\ \E fate \in Fates:
                    LET write == fate \in {"apply", "after"} IN
                      LET st1 == IF write /\ (Head(mq).v) = "acc" THEN [status EXCEPT ![(Head(mq).row)] = "stored"]
                                 ELSE IF write /\ (Head(mq).v) = "ref" THEN [status EXCEPT ![(Head(mq).row)] = "failed"]
                                 ELSE status IN
                        LET at1 == IF write /\ (Head(mq).v) = "trans"
                                   THEN [attempts EXCEPT ![(Head(mq).row)] = Cap(@ + 1)] ELSE attempts IN
                          LET du1 == IF write /\ (Head(mq).v) = "trans" THEN [due EXCEPT ![(Head(mq).row)] = FALSE]
                                     ELSE due IN
                            LET c1 == [claim EXCEPT ![(Head(mq).row)] =
                                         IF fate = "apply" \/ HeldMode = "immediate" THEN NoClaim
                                         ELSE HeldClaim] IN
                              LET hp1 == IF fate = "apply" THEN heldPending
                                         ELSE [heldPending EXCEPT ![(Head(mq).row)] = TRUE] IN
                                /\ recFails' = recFails + (IF fate = "apply" THEN 0 ELSE 1)
                                /\ LET d == Dispatch(c1, st1, du1, at1, run, (Tail(mq))) IN
                                     /\ /\ claim' = d.claim
                                        /\ mq' = d.mq
                                        /\ run' = d.run
                                     /\ /\ attempts' = at1
                                        /\ due' = du1
                                        /\ status' = st1
                                     /\ heldPending' = hp1
                                     /\ sends' = [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                                                  ELSE sends[x_]]
                                     /\ earlyResend' = (earlyResend \/ (\E x_ \in d.started : hp1[x_]))
               /\ UNCHANGED <<restarts, faultsSince, staleRelease>>
            \/ /\ mq # <<>> /\ Head(mq).type = "out"
                  /\ Head(mq).v = "unatt"
               /\ LET d == Dispatch(([claim EXCEPT ![Head(mq).row] = NoClaim]), status, due, attempts, run, (Tail(mq))) IN
                    /\ /\ claim' = d.claim
                       /\ mq' = d.mq
                       /\ run' = d.run
                    /\ /\ attempts' = attempts
                       /\ due' = due
                       /\ status' = status
                    /\ heldPending' = heldPending
                    /\ sends' = [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                                 ELSE sends[x_]]
                    /\ earlyResend' = (earlyResend \/ (\E x_ \in d.started : heldPending'[x_]))
               /\ UNCHANGED <<recFails, restarts, faultsSince, staleRelease>>
            \/ /\ mq # <<>> /\ Head(mq).type \in {"end", "lost"}
               /\ LET s == Head(mq).run IN
                    LET released == CASE ClaimMode = "run" ->
                                           {r \in Rows : claim[r] = Sending(s)}
                                      [] ClaimMode = "batch" ->
                                           {r \in Rows : run[s].task[r] # "none"}
                                      [] ClaimMode = "anyend" ->
                                           {r \in Rows : claim[r].kind = "sending"} IN
                      LET c1 == [r \in Rows |-> IF r \in released THEN NoClaim
                                                ELSE claim[r]] IN
                        /\ staleRelease' = (            staleRelease \/
                                            (\E r \in released : claim[r].kind # "none"
                                                                 /\ claim[r] # Sending(s)))
                        /\ LET d == Dispatch(c1, status, due, attempts, ([run EXCEPT ![s] = FreeRun]), (Tail(mq))) IN
                             /\ /\ claim' = d.claim
                                /\ mq' = d.mq
                                /\ run' = d.run
                             /\ /\ attempts' = attempts
                                /\ due' = due
                                /\ status' = status
                             /\ heldPending' = heldPending
                             /\ sends' = [x_ \in Rows |-> IF x_ \in d.started THEN Bump(sends[x_])
                                                          ELSE sends[x_]]
                             /\ earlyResend' = (earlyResend \/ (\E x_ \in d.started : heldPending'[x_]))
               /\ UNCHANGED <<recFails, restarts, faultsSince>>
            \/ /\ restarts < MaxRestarts
               /\ /\ claim' = [r \in Rows |-> NoClaim]
                  /\ mq' = <<TickMsg>>
                  /\ run' = [s \in Slots |-> FreeRun]
               /\ /\ faultsSince' = faultsSince + 1
                  /\ restarts' = restarts + 1
               /\ UNCHANGED <<status, attempts, due, recFails, sends, heldPending, earlyResend, staleRelease>>
         /\ UNCHANGED runFaults

Run(self) == /\ \/ /\ \E r \in {x \in Rows : run[self].task[x] = "sending"}:
                        \E v \in {"acc", "ref", "trans"}:
                          /\ mq' = Append(mq, OutMsg(self, r, v))
                          /\ run' = [run EXCEPT ![self].task[r] = "done"]
                   /\ UNCHANGED <<runFaults, faultsSince>>
                \/ /\ run[self].phase = "running"
                      /\ \A x \in Rows : run[self].task[x] \in {"none", "done"}
                   /\ /\ mq' = Append(mq, EndMsg(self))
                      /\ run' = [run EXCEPT ![self].phase = "ended"]
                   /\ UNCHANGED <<runFaults, faultsSince>>
                \/ /\ run[self].phase = "running"
                      /\ \E x \in Rows : run[self].task[x] = "sending"
                   /\ LET open == {x \in Rows : run[self].task[x] = "sending"} IN
                        /\ mq' = mq \o DeadlineSeq(self, open, "trans")
                                    \o <<EndMsg(self)>>
                        /\ run' = [run EXCEPT ![self] = [phase |-> "ended",
                                                         task |-> [x \in Rows |->
                                                                     IF x \in open THEN "done"
                                                                     ELSE run[self].task[x]]]]
                   /\ UNCHANGED <<runFaults, faultsSince>>
                \/ /\ run[self].phase = "running" /\ runFaults < MaxRunFaults
                      /\ \E x \in Rows : run[self].task[x] = "sending"
                   /\ LET open == {x \in Rows : run[self].task[x] = "sending"} IN
                        /\ mq' = mq \o DeadlineSeq(self, open, "unatt")
                                    \o <<EndMsg(self)>>
                        /\ run' = [run EXCEPT ![self] = [phase |-> "ended",
                                                         task |-> [x \in Rows |->
                                                                     IF x \in open THEN "done"
                                                                     ELSE run[self].task[x]]]]
                        /\ /\ faultsSince' = faultsSince + 1
                           /\ runFaults' = runFaults + 1
                \/ /\ run[self].phase = "running" /\ runFaults < MaxRunFaults
                   /\ mq' = Append(mq, LostMsg(self))
                   /\ run' = [run EXCEPT ![self] = [phase |-> "ended",
                                                    task |-> [x \in Rows |->
                                                                IF run[self].task[x] = "none" THEN "none"
                                                                ELSE "done"]]]
                   /\ /\ faultsSince' = faultsSince + 1
                      /\ runFaults' = runFaults + 1
             /\ UNCHANGED << status, attempts, due, claim, recFails, restarts, 
                             sends, heldPending, earlyResend, staleRelease >>

Timer == /\ ~TickQueued
         /\ /\ due' = [r \in Rows |-> TRUE]
            /\ faultsSince' = 0
            /\ mq' = Append(mq, TickMsg)
            /\ sends' = [r \in Rows |-> 0]
         /\ UNCHANGED << status, attempts, claim, run, recFails, runFaults, 
                         restarts, heldPending, earlyResend, staleRelease >>

Engine == /\ \E r \in {x \in LateRows : status[x] = "absent"}:
               \E nudge \in BOOLEAN:
                 /\ /\ due' = [due EXCEPT ![r] = TRUE]
                    /\ status' = [status EXCEPT ![r] = "queued"]
                 /\ IF nudge /\ ~NudgeQueued
                       THEN /\ mq' = Append(mq, NudgeMsg)
                       ELSE /\ TRUE
                            /\ mq' = mq
          /\ UNCHANGED << attempts, claim, run, recFails, runFaults, restarts, 
                          sends, faultsSince, heldPending, earlyResend, 
                          staleRelease >>

Next == Sched \/ Timer \/ Engine
           \/ (\E self \in Slots: Run(self))

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Sched)
        /\ \A self \in Slots : WF_vars(Run(self))
        /\ WF_vars(Timer)

\* END TRANSLATION

(***************************************************************************)
(* Invariants.                                                             *)
(***************************************************************************)

TypeOK ==
    /\ status \in [Rows -> {"absent", "queued", "stored", "failed"}]
    /\ attempts \in [Rows -> 0..MaxAttempts]
    /\ claim \in [Rows -> {NoClaim, Expiring, HeldClaim}
                           \cup {Sending(s) : s \in Slots}]

\* At most one claim per envelope, and it is the right one: a row with an
\* unsettled task in run s (still sending, or an outcome still in the
\* mailbox) is claimed by s and by nothing else, and an expired row whose
\* Finished is queued is Expiring.
OneOwner ==
    /\ \A s \in Slots, r \in Rows :
           (run[s].task[r] = "sending" \/ OutQueued(s, r))
               => claim[r] = Sending(s)
    /\ \A r \in Rows : FinishedQueued(r) => claim[r] = Expiring

\* No envelope is sent by two runs at once.
NoDoubleSend ==
    \A r \in Rows : Cardinality({s \in Slots : run[s].task[r] = "sending"}) <= 1

\* A run's end marker releases only claims its own run holds.
NoStaleRelease == ~staleRelease

\* A row whose record failed is not dispatched again before the next Tick.
HeldUntilTick == ~earlyResend

\* No busy loop: within one clock period (between two Timer fires) a row
\* is started at most once, plus once per run fault or restart in that
\* period. This is the "one resend per period" of scheduler.gleam:87-90.
\* A Tick that fires while a failing record is being written lands behind
\* the outcome being handled, so the period boundary always falls between
\* the send and the resend it releases.
NoBusyLoop == \A r \in Rows : sends[r] <= 1 + faultsSince

\* No send before commit: a run only ever holds committed rows.
SendCommitted ==
    \A s \in Slots, r \in Rows : run[s].task[r] # "none" => status[r] # "absent"

(***************************************************************************)
(* Liveness: every queued row is eventually stored or failed.              *)
(***************************************************************************)
Settles == \A r \in Rows : status[r] = "queued" ~> status[r] \in {"stored", "failed"}

=============================================================================

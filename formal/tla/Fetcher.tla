------------------------------- MODULE Fetcher -------------------------------
(***************************************************************************)
(* A model of one inbound queue's fetcher,                                 *)
(* packages/daemon/src/daemon/fetcher.gleam, with the mailbox queue, the   *)
(* store's `processed` rows, and the fetch manager that (re)starts it.     *)
(*                                                                         *)
(* The fetcher is a `weft/state_machine` (Acking, Polling, BackingOff). It *)
(* handles one message at a time, and each message is one atomic step     *)
(* here. Each network step runs as a one-task relayed run; the run's work  *)
(* is the Worker process, one engine or mailbox call per step, so a        *)
(* deadline, a crash or a failed call can land between any two of them.   *)
(* A run's outcome is pushed into the machine's mailbox.                   *)
(*                                                                         *)
(* End markers are not modelled. Every arm of `handle` (fetcher.gleam:218) *)
(* keeps its state on AllDelivered, and a RunLost can only follow an       *)
(* outcome if something outside the run kills a scope that has already     *)
(* delivered, which no process here does (the relay is linked only to the  *)
(* machine). A RunLost before the outcome is modelled: it is the run's     *)
(* only report.                                                            *)
(*                                                                         *)
(* Switches:                                                               *)
(*   RetireMode = "after_ack"   the round acks, then checks liveness, then *)
(*                              polls or stops (`after_ack` :262, current) *)
(*              = "before_ack"  the round checks liveness, then acks (the  *)
(*                              code before ef9d5c2; mutant)               *)
(*   Drain      = TRUE          the fetch manager also starts a fetcher    *)
(*                              for a retired queue with unacked rows      *)
(*                              (`reconcile`, fetch_manager.gleam:161,     *)
(*                              current); FALSE is the pre-fix manager     *)
(*   AckSource  = "store"       ack `engine.unacked` (current)             *)
(*              = "batch"       ack the batch the last poll fetched        *)
(*                              (mutant)                                   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Envs,        \* Envelopes that can reach the queue.
    InitEnvs,    \* Envelopes already in the mailbox when the fetcher starts.
    MaxFaults,   \* Budget of failed calls, abandoned runs and lost runs.
    MaxCrashes,  \* Budget of daemon crashes.
    RetireMode,  \* "after_ack" | "before_ack"
    Drain,       \* BOOLEAN
    AckSource    \* "store" | "batch"

ASSUME RetireMode \in {"after_ack", "before_ack"}
ASSUME Drain \in BOOLEAN
ASSUME AckSource \in {"store", "batch"}

Min(S) == CHOOSE x \in S : \A y \in S : x <= y

Out(t, ok) == [type |-> t, ok |-> ok]
BeginMsg == [type |-> "begin", ok |-> TRUE]

(***************************************************************************

--algorithm Fetcher
variables
    \* The mailbox's queue: an envelope has not arrived, is held, or was
    \* deleted by an Ack.
    mbox = [e \in Envs |-> IF e \in InitEnvs THEN "present" ELSE "absent"],

    \* The store: `processed` rows and their `acked` column (inbound.sql).
    processed = [e \in Envs |-> FALSE],
    acked = [e \in Envs |-> FALSE],

    \* Whether the queue is still in `store.live_inboxes`.
    live = TRUE,

    \* The machine: its state ("down" means no process), its mailbox, and
    \* whether the BackingOff state timeout is armed. `continuing(Begin)`
    \* puts a Begin first (`start` :196, :209).
    fsm = "acking",
    fq = <<BeginMsg>>,
    armed = FALSE,

    \* The current run's work: which step, the envelopes it is acking or
    \* processing, and the batch the last poll fetched (held in memory, and
    \* only read by the "batch" mutant).
    job = "none",
    wstep = "none",
    pend = {},
    lastFetched = {},

    faults = 0,
    crashes = 0;

define
    Unacked == {e \in Envs : processed[e] /\ ~acked[e]}
    CanFault == faults < MaxFaults
    Subject == IF job = "ack" THEN "acked" ELSE "polled"

    \* Nothing left that could change: the fetcher is gone and the fetch
    \* manager has no reason to start one.
    Quiescent ==
        /\ fsm \in {"stopped", "down"}
        /\ ~(live \/ (Drain /\ Unacked # {}))
end define;

\* A run reports its one outcome (`start_run` :327, relayed) and is over.
macro Report(ok) begin
    fq := Append(fq, Out(Subject, ok));
    job := "none" || wstep := "none";
end macro;

\* `begin_round` (:250): `start_run` with `ack_pending`.
macro StartAck() begin
    job := "ack" || wstep := "unacked";
    fsm := "acking";
end macro;

\* `begin_poll` (:306).
macro StartPoll() begin
    job := "poll" || wstep := "fetch";
    fsm := "polling";
end macro;

\* `failed` (:319): BackingOff with a state timeout.
macro Fail() begin
    fsm := "backoff" || armed := TRUE;
end macro;

\* The machine: `handle` (fetcher.gleam:218).
fair process Machine = "machine"
begin
Handle:
    while TRUE do
        await fsm \notin {"stopped", "down"} /\ fq # <<>>;
        with m = Head(fq) do
            fq := Tail(fq);
            if m.type = "begin" /\ fsm \in {"acking", "backoff"} then
                \* `begin_round` (:250). Before ef9d5c2 it checked
                \* `liveness` (:361) first; an engine error reads as Live.
                if RetireMode = "before_ack" then
                    with err \in IF CanFault THEN BOOLEAN ELSE {FALSE} do
                        faults := faults + (IF err THEN 1 ELSE 0);
                        if live \/ err then
                            StartAck();
                        else
                            fsm := "stopped";
                        end if;
                    end with;
                else
                    StartAck();
                end if;
            elsif m.type = "acked" /\ fsm = "acking" then
                \* `acked` (:271): the first outcome decides the step.
                if ~m.ok then
                    Fail();
                elsif RetireMode = "before_ack" then
                    StartPoll();
                else
                    \* `after_ack` (:262): liveness is checked once the
                    \* round's acknowledgements are done; Retired stops
                    \* (:265), Live polls.
                    with err \in IF CanFault THEN BOOLEAN ELSE {FALSE} do
                        faults := faults + (IF err THEN 1 ELSE 0);
                        if live \/ err then
                            StartPoll();
                        else
                            fsm := "stopped";
                        end if;
                    end with;
                end if;
            elsif m.type = "polled" /\ fsm = "polling" then
                \* `polled` (:288): a finished round starts the next
                \* (:294).
                if m.ok then
                    if RetireMode = "before_ack" then
                        with err \in IF CanFault THEN BOOLEAN ELSE {FALSE} do
                            faults := faults + (IF err THEN 1 ELSE 0);
                            if live \/ err then
                                StartAck();
                            else
                                fsm := "stopped";
                            end if;
                        end with;
                    else
                        StartAck();
                    end if;
                else
                    Fail();
                end if;
            else
                \* Every other pair keeps its state (:231, :238-241).
                skip;
            end if;
        end with;
    end while;
end process;

\* The work inside the current run, one call per step.
fair process Worker = "worker"
begin
Work:
    while TRUE do
        either
            \* `ack_pending` (:376): `engine.unacked`, the store's list.
            await job = "ack" /\ wstep = "unacked";
            either
                await CanFault;
                faults := faults + 1;
                Report(FALSE);
            or
                with p = IF AckSource = "store" THEN Unacked ELSE lastFetched do
                    if p = {} then
                        Report(TRUE);
                    else
                        pend := p || wstep := "call";
                        if AckSource = "batch" then
                            lastFetched := {};
                        end if;
                    end if;
                end with;
            end either;
        or
            \* `acknowledge` (:396): the mailbox's Ack deletes exactly the
            \* named envelopes; the answer can fail before or after that.
            await job = "ack" /\ wstep = "call";
            either
                await CanFault;
                faults := faults + 1;
                Report(FALSE);
            or
                mbox := [e \in Envs |-> IF e \in pend THEN "deleted" ELSE mbox[e]];
                either
                    wstep := "mark";
                or
                    await CanFault;
                    faults := faults + 1;
                    Report(FALSE);
                end either;
            end either;
        or
            \* `engine.mark_acked` (:409): applies, fails before, or
            \* applies and then fails; then `ack_pending` repeats.
            await job = "ack" /\ wstep = "mark";
            either
                acked := [e \in Envs |-> acked[e] \/ e \in pend];
                wstep := "unacked";
            or
                await CanFault;
                faults := faults + 1;
                Report(FALSE);
            or
                await CanFault;
                acked := [e \in Envs |-> acked[e] \/ e \in pend];
                faults := faults + 1;
                Report(FALSE);
            end either;
        or
            \* `fetch_batch` (:423): the long poll returns what the queue
            \* holds.
            await job = "poll" /\ wstep = "fetch";
            either
                await CanFault;
                faults := faults + 1;
                Report(FALSE);
            or
                with b = {e \in Envs : mbox[e] = "present"} do
                    pend := b || lastFetched := b || wstep := "process";
                end with;
            end either;
        or
            \* `process_batch` (:450): `engine.process` per envelope in
            \* order, stopping at the first that cannot commit. A poison
            \* envelope is quarantined, which commits it, after
            \* `limits.max_process_attempts` failures (engine.gleam:1120);
            \* the fault budget stands for that bound. A repeat (already
            \* processed) marks its row unacknowledged (`repeat`,
            \* engine.gleam:1093, ADR-010 addendum). Here that write changes
            \* nothing: this model's mailbox never serves a deleted envelope
            \* again, so a repeat's row is always still unacknowledged. A
            \* failure of that write is the abandon step below.
            await job = "poll" /\ wstep = "process";
            if pend = {} then
                Report(TRUE);
            else
                with e = Min(pend) do
                    if processed[e] then
                        acked[e] := FALSE || pend := pend \ {e};
                    else
                        either
                            processed[e] := TRUE || pend := pend \ {e};
                        or
                            await CanFault;
                            faults := faults + 1;
                            Report(FALSE);
                        or
                            await CanFault;
                            processed[e] := TRUE || faults := faults + 1;
                            Report(FALSE);
                        end either;
                    end if;
                end with;
            end if;
        or
            \* The run's deadline abandons the task wherever it was, or the
            \* scope is lost before it reported: `step_result` (:345) and
            \* RunLost (:283, :300) both read as a failed step.
            await job # "none" /\ CanFault;
            faults := faults + 1;
            Report(FALSE);
        end either;
    end while;
end process;

\* The BackingOff state timeout (`sm.with_state_timeout` :321) sends Begin.
fair process Timer = "timer"
begin
Fire:
    while TRUE do
        await fsm = "backoff" /\ armed;
        fq := Append(fq, BeginMsg) || armed := FALSE;
    end while;
end process;

\* `daemon/fetch_manager` `reconcile` (fetch_manager.gleam:150): a fetcher
\* per live queue (:152), and with Drain one for a retired queue that still
\* owes acknowledgements (`engine.draining_inboxes`, :161).
fair process Manager = "manager"
begin
Reconcile:
    while TRUE do
        await fsm \in {"down", "stopped"} /\ (live \/ (Drain /\ Unacked # {}));
        fsm := "acking" || fq := <<BeginMsg>> || armed := FALSE;
    end while;
end process;

\* The world: envelopes arrive, the relationship closes, the daemon crashes.
process Env = "env"
begin
Act:
    while TRUE do
        either
            with e \in {x \in Envs : mbox[x] = "absent"} do
                mbox[e] := "present";
            end with;
        or
            await live;
            live := FALSE;
        or
            \* A crash loses every process and message; the store and the
            \* mailbox keep what they committed.
            await crashes < MaxCrashes /\ fsm # "down";
            fsm := "down" || fq := <<>> || armed := FALSE;
            job := "none" || wstep := "none" || pend := {} || lastFetched := {};
            crashes := crashes + 1;
        or
            \* Nothing is left to happen; stutter rather than deadlock.
            await Quiescent;
            skip;
        end either;
    end while;
end process;

end algorithm;

***************************************************************************)
\* BEGIN TRANSLATION
VARIABLES mbox, processed, acked, live, fsm, fq, armed, job, wstep, pend, 
          lastFetched, faults, crashes

(* define statement *)
Unacked == {e \in Envs : processed[e] /\ ~acked[e]}
CanFault == faults < MaxFaults
Subject == IF job = "ack" THEN "acked" ELSE "polled"



Quiescent ==
    /\ fsm \in {"stopped", "down"}
    /\ ~(live \/ (Drain /\ Unacked # {}))


vars == << mbox, processed, acked, live, fsm, fq, armed, job, wstep, pend, 
           lastFetched, faults, crashes >>

ProcSet == {"machine"} \cup {"worker"} \cup {"timer"} \cup {"manager"} \cup {"env"}

Init == (* Global variables *)
        /\ mbox = [e \in Envs |-> IF e \in InitEnvs THEN "present" ELSE "absent"]
        /\ processed = [e \in Envs |-> FALSE]
        /\ acked = [e \in Envs |-> FALSE]
        /\ live = TRUE
        /\ fsm = "acking"
        /\ fq = <<BeginMsg>>
        /\ armed = FALSE
        /\ job = "none"
        /\ wstep = "none"
        /\ pend = {}
        /\ lastFetched = {}
        /\ faults = 0
        /\ crashes = 0

Machine == /\ fsm \notin {"stopped", "down"} /\ fq # <<>>
           /\ LET m == Head(fq) IN
                /\ fq' = Tail(fq)
                /\ IF m.type = "begin" /\ fsm \in {"acking", "backoff"}
                      THEN /\ IF RetireMode = "before_ack"
                                 THEN /\ \E err \in IF CanFault THEN BOOLEAN ELSE {FALSE}:
                                           /\ faults' = faults + (IF err THEN 1 ELSE 0)
                                           /\ IF live \/ err
                                                 THEN /\ /\ job' = "ack"
                                                         /\ wstep' = "unacked"
                                                      /\ fsm' = "acking"
                                                 ELSE /\ fsm' = "stopped"
                                                      /\ UNCHANGED << job, 
                                                                      wstep >>
                                 ELSE /\ /\ job' = "ack"
                                         /\ wstep' = "unacked"
                                      /\ fsm' = "acking"
                                      /\ UNCHANGED faults
                           /\ armed' = armed
                      ELSE /\ IF m.type = "acked" /\ fsm = "acking"
                                 THEN /\ IF ~m.ok
                                            THEN /\ /\ armed' = TRUE
                                                    /\ fsm' = "backoff"
                                                 /\ UNCHANGED << job, wstep, 
                                                                 faults >>
                                            ELSE /\ IF RetireMode = "before_ack"
                                                       THEN /\ /\ job' = "poll"
                                                               /\ wstep' = "fetch"
                                                            /\ fsm' = "polling"
                                                            /\ UNCHANGED faults
                                                       ELSE /\ \E err \in IF CanFault THEN BOOLEAN ELSE {FALSE}:
                                                                 /\ faults' = faults + (IF err THEN 1 ELSE 0)
                                                                 /\ IF live \/ err
                                                                       THEN /\ /\ job' = "poll"
                                                                               /\ wstep' = "fetch"
                                                                            /\ fsm' = "polling"
                                                                       ELSE /\ fsm' = "stopped"
                                                                            /\ UNCHANGED << job, 
                                                                                            wstep >>
                                                 /\ armed' = armed
                                 ELSE /\ IF m.type = "polled" /\ fsm = "polling"
                                            THEN /\ IF m.ok
                                                       THEN /\ IF RetireMode = "before_ack"
                                                                  THEN /\ \E err \in IF CanFault THEN BOOLEAN ELSE {FALSE}:
                                                                            /\ faults' = faults + (IF err THEN 1 ELSE 0)
                                                                            /\ IF live \/ err
                                                                                  THEN /\ /\ job' = "ack"
                                                                                          /\ wstep' = "unacked"
                                                                                       /\ fsm' = "acking"
                                                                                  ELSE /\ fsm' = "stopped"
                                                                                       /\ UNCHANGED << job, 
                                                                                                       wstep >>
                                                                  ELSE /\ /\ job' = "ack"
                                                                          /\ wstep' = "unacked"
                                                                       /\ fsm' = "acking"
                                                                       /\ UNCHANGED faults
                                                            /\ armed' = armed
                                                       ELSE /\ /\ armed' = TRUE
                                                               /\ fsm' = "backoff"
                                                            /\ UNCHANGED << job, 
                                                                            wstep, 
                                                                            faults >>
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED << fsm, armed, 
                                                                 job, wstep, 
                                                                 faults >>
           /\ UNCHANGED << mbox, processed, acked, live, pend, lastFetched, 
                           crashes >>

Worker == /\ \/ /\ job = "ack" /\ wstep = "unacked"
                /\ \/ /\ CanFault
                      /\ faults' = faults + 1
                      /\ fq' = Append(fq, Out(Subject, FALSE))
                      /\ /\ job' = "none"
                         /\ wstep' = "none"
                      /\ UNCHANGED <<pend, lastFetched>>
                   \/ /\ LET p == IF AckSource = "store" THEN Unacked ELSE lastFetched IN
                           IF p = {}
                              THEN /\ fq' = Append(fq, Out(Subject, TRUE))
                                   /\ /\ job' = "none"
                                      /\ wstep' = "none"
                                   /\ UNCHANGED << pend, lastFetched >>
                              ELSE /\ /\ pend' = p
                                      /\ wstep' = "call"
                                   /\ IF AckSource = "batch"
                                         THEN /\ lastFetched' = {}
                                         ELSE /\ TRUE
                                              /\ UNCHANGED lastFetched
                                   /\ UNCHANGED << fq, job >>
                      /\ UNCHANGED faults
                /\ UNCHANGED <<mbox, processed, acked>>
             \/ /\ job = "ack" /\ wstep = "call"
                /\ \/ /\ CanFault
                      /\ faults' = faults + 1
                      /\ fq' = Append(fq, Out(Subject, FALSE))
                      /\ /\ job' = "none"
                         /\ wstep' = "none"
                      /\ mbox' = mbox
                   \/ /\ mbox' = [e \in Envs |-> IF e \in pend THEN "deleted" ELSE mbox[e]]
                      /\ \/ /\ wstep' = "mark"
                            /\ UNCHANGED <<fq, job, faults>>
                         \/ /\ CanFault
                            /\ faults' = faults + 1
                            /\ fq' = Append(fq, Out(Subject, FALSE))
                            /\ /\ job' = "none"
                               /\ wstep' = "none"
                /\ UNCHANGED <<processed, acked, pend, lastFetched>>
             \/ /\ job = "ack" /\ wstep = "mark"
                /\ \/ /\ acked' = [e \in Envs |-> acked[e] \/ e \in pend]
                      /\ wstep' = "unacked"
                      /\ UNCHANGED <<fq, job, faults>>
                   \/ /\ CanFault
                      /\ faults' = faults + 1
                      /\ fq' = Append(fq, Out(Subject, FALSE))
                      /\ /\ job' = "none"
                         /\ wstep' = "none"
                      /\ acked' = acked
                   \/ /\ CanFault
                      /\ acked' = [e \in Envs |-> acked[e] \/ e \in pend]
                      /\ faults' = faults + 1
                      /\ fq' = Append(fq, Out(Subject, FALSE))
                      /\ /\ job' = "none"
                         /\ wstep' = "none"
                /\ UNCHANGED <<mbox, processed, pend, lastFetched>>
             \/ /\ job = "poll" /\ wstep = "fetch"
                /\ \/ /\ CanFault
                      /\ faults' = faults + 1
                      /\ fq' = Append(fq, Out(Subject, FALSE))
                      /\ /\ job' = "none"
                         /\ wstep' = "none"
                      /\ UNCHANGED <<pend, lastFetched>>
                   \/ /\ LET b == {e \in Envs : mbox[e] = "present"} IN
                           /\ lastFetched' = b
                           /\ pend' = b
                           /\ wstep' = "process"
                      /\ UNCHANGED <<fq, job, faults>>
                /\ UNCHANGED <<mbox, processed, acked>>
             \/ /\ job = "poll" /\ wstep = "process"
                /\ IF pend = {}
                      THEN /\ fq' = Append(fq, Out(Subject, TRUE))
                           /\ /\ job' = "none"
                              /\ wstep' = "none"
                           /\ UNCHANGED << processed, acked, pend, faults >>
                      ELSE /\ LET e == Min(pend) IN
                                IF processed[e]
                                   THEN /\ /\ acked' = [acked EXCEPT ![e] = FALSE]
                                           /\ pend' = pend \ {e}
                                        /\ UNCHANGED << processed, fq, job, 
                                                        wstep, faults >>
                                   ELSE /\ \/ /\ /\ pend' = pend \ {e}
                                                 /\ processed' = [processed EXCEPT ![e] = TRUE]
                                              /\ UNCHANGED <<fq, job, wstep, faults>>
                                           \/ /\ CanFault
                                              /\ faults' = faults + 1
                                              /\ fq' = Append(fq, Out(Subject, FALSE))
                                              /\ /\ job' = "none"
                                                 /\ wstep' = "none"
                                              /\ UNCHANGED <<processed, pend>>
                                           \/ /\ CanFault
                                              /\ /\ faults' = faults + 1
                                                 /\ processed' = [processed EXCEPT ![e] = TRUE]
                                              /\ fq' = Append(fq, Out(Subject, FALSE))
                                              /\ /\ job' = "none"
                                                 /\ wstep' = "none"
                                              /\ pend' = pend
                                        /\ acked' = acked
                /\ UNCHANGED <<mbox, lastFetched>>
             \/ /\ job # "none" /\ CanFault
                /\ faults' = faults + 1
                /\ fq' = Append(fq, Out(Subject, FALSE))
                /\ /\ job' = "none"
                   /\ wstep' = "none"
                /\ UNCHANGED <<mbox, processed, acked, pend, lastFetched>>
          /\ UNCHANGED << live, fsm, armed, crashes >>

Timer == /\ fsm = "backoff" /\ armed
         /\ /\ armed' = FALSE
            /\ fq' = Append(fq, BeginMsg)
         /\ UNCHANGED << mbox, processed, acked, live, fsm, job, wstep, pend, 
                         lastFetched, faults, crashes >>

Manager == /\ fsm \in {"down", "stopped"} /\ (live \/ (Drain /\ Unacked # {}))
           /\ /\ armed' = FALSE
              /\ fq' = <<BeginMsg>>
              /\ fsm' = "acking"
           /\ UNCHANGED << mbox, processed, acked, live, job, wstep, pend, 
                           lastFetched, faults, crashes >>

Env == /\ \/ /\ \E e \in {x \in Envs : mbox[x] = "absent"}:
                  mbox' = [mbox EXCEPT ![e] = "present"]
             /\ UNCHANGED <<live, fsm, fq, armed, job, wstep, pend, lastFetched, crashes>>
          \/ /\ live
             /\ live' = FALSE
             /\ UNCHANGED <<mbox, fsm, fq, armed, job, wstep, pend, lastFetched, crashes>>
          \/ /\ crashes < MaxCrashes /\ fsm # "down"
             /\ /\ armed' = FALSE
                /\ fq' = <<>>
                /\ fsm' = "down"
             /\ /\ job' = "none"
                /\ lastFetched' = {}
                /\ pend' = {}
                /\ wstep' = "none"
             /\ crashes' = crashes + 1
             /\ UNCHANGED <<mbox, live>>
          \/ /\ Quiescent
             /\ TRUE
             /\ UNCHANGED <<mbox, live, fsm, fq, armed, job, wstep, pend, lastFetched, crashes>>
       /\ UNCHANGED << processed, acked, faults >>

Next == Machine \/ Worker \/ Timer \/ Manager \/ Env

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Machine)
        /\ WF_vars(Worker)
        /\ WF_vars(Timer)
        /\ WF_vars(Manager)

\* END TRANSLATION

TypeOK ==
    /\ mbox \in [Envs -> {"absent", "present", "deleted"}]
    /\ processed \in [Envs -> BOOLEAN]
    /\ acked \in [Envs -> BOOLEAN]
    /\ fsm \in {"acking", "polling", "backoff", "stopped", "down"}
    /\ job \in {"none", "ack", "poll"}

\* Nothing is acknowledged before it is committed: the mailbox deleted only
\* processed envelopes, and the store marks acked only those.
NoAckBeforeCommit ==
    \A e \in Envs : mbox[e] = "deleted" => processed[e]

StoreAckConsistent ==
    \A e \in Envs : acked[e] => (processed[e] /\ mbox[e] = "deleted")

\* The safety shadow of AllAcked: once nothing can run again, nothing
\* committed is left unacknowledged. Breadth-first search finds the
\* shortest trace that violates it, which is the minimal witness of the
\* liveness gap.
NothingOwedAtRest == Quiescent => Unacked = {}

\* Every committed envelope is eventually acknowledged.
AllAcked == \A e \in Envs : processed[e] ~> acked[e]

=============================================================================

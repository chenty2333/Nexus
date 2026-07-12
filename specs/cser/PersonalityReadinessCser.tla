------------------ MODULE PersonalityReadinessCser ------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Bounded readiness/positive-timeout successor over one common scope.     *)
(* ReadyCommit, TimeoutCommit, and RevokeBegin share one authority gate.    *)
(* The PlusCal algorithm is the sole source of Init and Next.               *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableRejects

ASSUME /\ MaxBinding = 1
       /\ EnableRejects \in BOOLEAN

Effects == {"Sub", "Wait", "Timer"}
LiveSubStates == {"Armed", "Disabled"}
LiveWaitStates == {"Pending", "Committed"}
LiveTimerStates == {"Pending", "Committed"}

NoBinding == -1
NoGeneration == -1
NoSequence == -1
NoWinner == "None"

(* --algorithm PersonalityReadinessCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = -1,

    serviceAlive = TRUE,
    bindingEpoch = 0,
    fallbackState = "Standby",
    replacementState = "Bound",
    recoveryRevision = 0,

    sourceGeneration = 0,
    sourceSequence = 0,
    sourceReady = FALSE,

    subState = "Unused",
    subMode = "None",
    subGeneration = 0,
    subBinding = NoBinding,
    queued = FALSE,

    waitState = "Unused",
    waitBinding = NoBinding,
    timerState = "Unused",
    timerBinding = NoBinding,

    winner = NoWinner,
    frozenReady = FALSE,
    frozenSourceGeneration = NoGeneration,
    frozenSourceSequence = NoSequence,
    frozenCount = -1,
    commitCount = 0,
    publicationCount = 0,
    terminalCount = 0,

    freeSubCredits = 1,
    freeWaitCredits = 1,
    freeTimerCredits = 2,
    watchdogHeld = FALSE,
    recoveryCohort = {},

    snapshotState = "Absent",
    snapshotBinding = NoBinding,
    snapshotRevision = -1,
    snapshotSourceGeneration = NoGeneration,
    snapshotSourceSequence = NoSequence,
    snapshotSourceReady = FALSE,
    snapshotSubState = "Unused",
    snapshotSubGeneration = 0,
    snapshotQueued = FALSE,
    snapshotWaitState = "Unused",
    snapshotTimerState = "Unused",
    snapshotWinner = NoWinner,

    rejectCount = 0,
    commitAtClose = 0;

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ subState = "Unused"
                  /\ freeSubCredits = 1;
            subState := "Armed";
            subGeneration := 1;
            subBinding := bindingEpoch;
            freeSubCredits := 0;
            if sourceReady then queued := TRUE end if;
            either subMode := "Level"
            or subMode := "Edge"
            or subMode := "OneShot"
            end either;
        or
            await /\ scopeState = "Active"
                  /\ sourceGeneration = 0
                  /\ sourceSequence < 3
                  /\ ~sourceReady;
            sourceSequence := sourceSequence + 1;
            recoveryRevision := recoveryRevision + 1;
            sourceReady := TRUE;
            if subState = "Armed" then queued := TRUE end if;
            if replacementState = "Ready" then
                replacementState := "None";
                snapshotState := "Absent";
            end if;
        or
            await /\ scopeState = "Active"
                  /\ sourceSequence < 3
                  /\ sourceReady;
            sourceSequence := sourceSequence + 1;
            recoveryRevision := recoveryRevision + 1;
            sourceReady := FALSE;
            queued := FALSE;
            if replacementState = "Ready" then
                replacementState := "None";
                snapshotState := "Absent";
            end if;
        or
            await /\ scopeState = "Active"
                  /\ sourceGeneration = 0
                  /\ sourceSequence < 3;
            sourceGeneration := 1;
            sourceSequence := sourceSequence + 1;
            recoveryRevision := recoveryRevision + 1;
            sourceReady := FALSE;
            queued := FALSE;
            if replacementState = "Ready" then
                replacementState := "None";
                snapshotState := "Absent";
            end if;
        or
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ waitState = "Unused"
                  /\ timerState = "Unused"
                  /\ freeWaitCredits = 1
                  /\ freeTimerCredits > 0;
            waitState := "Pending";
            timerState := "Pending";
            waitBinding := bindingEpoch;
            timerBinding := bindingEpoch;
            freeWaitCredits := 0;
            freeTimerCredits := freeTimerCredits - 1;
        or
            \* Atomic sample/selection plus wait+timer commit.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ waitState = "Pending"
                  /\ timerState = "Pending"
                  /\ waitBinding = bindingEpoch
                  /\ timerBinding = bindingEpoch
                  /\ subState = "Armed"
                  /\ subBinding = bindingEpoch
                  /\ queued
                  /\ sourceReady;
            waitState := "Committed";
            timerState := "Committed";
            winner := "Ready";
            frozenReady := TRUE;
            frozenSourceGeneration := sourceGeneration;
            frozenSourceSequence := sourceSequence;
            frozenCount := 1;
            commitCount := commitCount + 1;
            if subMode = "Level" then
                queued := TRUE;
            else
                queued := FALSE;
                if subMode = "OneShot" then subState := "Disabled" end if;
            end if;
        or
            \* The positive timeout shares the exact same commit gate.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ waitState = "Pending"
                  /\ timerState = "Pending"
                  /\ waitBinding = bindingEpoch
                  /\ timerBinding = bindingEpoch;
            waitState := "Committed";
            timerState := "Committed";
            winner := "Timeout";
            frozenReady := FALSE;
            frozenSourceGeneration := sourceGeneration;
            frozenSourceSequence := sourceSequence;
            frozenCount := 0;
            commitCount := commitCount + 1;
        or
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ bindingEpoch < MaxBinding;
            with cohort =
                (IF subState \in LiveSubStates THEN {"Sub"} ELSE {}) \cup
                (IF waitState \in LiveWaitStates THEN {"Wait"} ELSE {}) \cup
                (IF timerState \in LiveTimerStates THEN {"Timer"} ELSE {}) do
                bindingEpoch := bindingEpoch + 1;
                recoveryRevision := recoveryRevision + 1;
                serviceAlive := FALSE;
                replacementState := "None";
                fallbackState := "Required";
                recoveryCohort := cohort;
                snapshotState := "Absent";
                if cohort # {} then
                    watchdogHeld := TRUE;
                    freeTimerCredits := freeTimerCredits - 1;
                end if;
            end with;
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None";
            snapshotState := "Captured";
            snapshotBinding := bindingEpoch;
            snapshotRevision := recoveryRevision;
            snapshotSourceGeneration := sourceGeneration;
            snapshotSourceSequence := sourceSequence;
            snapshotSourceReady := sourceReady;
            snapshotSubState := subState;
            snapshotSubGeneration := subGeneration;
            snapshotQueued := queued;
            snapshotWaitState := waitState;
            snapshotTimerState := timerState;
            snapshotWinner := winner;
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ snapshotState = "Captured"
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotRevision = recoveryRevision
                  /\ snapshotSourceGeneration = sourceGeneration
                  /\ snapshotSourceSequence = sourceSequence
                  /\ snapshotSourceReady = sourceReady
                  /\ snapshotSubState = subState
                  /\ snapshotSubGeneration = subGeneration
                  /\ snapshotQueued = queued
                  /\ snapshotWaitState = waitState
                  /\ snapshotTimerState = timerState
                  /\ snapshotWinner = winner;
            replacementState := "Ready";
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready";
            replacementState := "Bound";
            serviceAlive := TRUE;
        or
            with e \in recoveryCohort do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ ((e = "Sub" /\ subBinding # bindingEpoch)
                           \/ (e = "Wait" /\ waitBinding # bindingEpoch)
                           \/ (e = "Timer" /\ timerBinding # bindingEpoch));
                if e = "Sub" then subBinding := bindingEpoch end if;
                if e = "Wait" then waitBinding := bindingEpoch end if;
                if e = "Timer" then timerBinding := bindingEpoch end if;
                recoveryCohort := recoveryCohort \ {e};
                recoveryRevision := recoveryRevision + 1;
                if recoveryCohort \ {e} = {} then
                    watchdogHeld := FALSE;
                    freeTimerCredits := freeTimerCredits + 1;
                end if;
            end with;
        or
            \* A stale source-generation packet has no semantic side effect.
            await /\ EnableRejects
                  /\ scopeState = "Active"
                  /\ sourceGeneration = 1
                  /\ rejectCount = 0;
            rejectCount := 1;
        or
            await scopeState = "Active";
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "Closed";
            fallbackState := "Closed";
            commitAtClose := commitCount;
            snapshotState := "Absent";
            if winner = NoWinner /\ waitState = "Pending" then
                winner := "Revoke";
            end if;
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            await fallbackState = "Required";
            fallbackState := "Running";
        or
            await /\ waitState = "Committed"
                  /\ timerState = "Committed"
                  /\ scopeState \in {"Active", "Closing"};
            waitState := "Completed";
            timerState := "Completed";
            recoveryRevision := recoveryRevision + 1;
            publicationCount := publicationCount + 1;
            terminalCount := terminalCount + 2;
            freeWaitCredits := freeWaitCredits + 1;
            with remaining = recoveryCohort \ {"Wait", "Timer"} do
                freeTimerCredits := freeTimerCredits + 1
                    + IF watchdogHeld /\ remaining = {} THEN 1 ELSE 0;
                recoveryCohort := remaining;
                if watchdogHeld /\ remaining = {} then
                    watchdogHeld := FALSE;
                end if;
            end with;
            if replacementState = "Ready" then
                replacementState := "None";
                snapshotState := "Absent";
            end if;
        or
            await /\ scopeState = "Closing"
                  /\ subState \in LiveSubStates;
            subState := "Aborted";
            queued := FALSE;
            freeSubCredits := freeSubCredits + 1;
            terminalCount := terminalCount + 1;
            recoveryCohort := recoveryCohort \ {"Sub"};
            if watchdogHeld /\ recoveryCohort \ {"Sub"} = {} then
                watchdogHeld := FALSE;
                freeTimerCredits := freeTimerCredits + 1;
            end if;
        or
            await /\ scopeState = "Closing"
                  /\ waitState = "Pending";
            waitState := "Aborted";
            freeWaitCredits := freeWaitCredits + 1;
            terminalCount := terminalCount + 1;
            recoveryCohort := recoveryCohort \ {"Wait"};
            if watchdogHeld /\ recoveryCohort \ {"Wait"} = {} then
                watchdogHeld := FALSE;
                freeTimerCredits := freeTimerCredits + 1;
            end if;
        or
            await /\ scopeState = "Closing"
                  /\ timerState = "Pending";
            timerState := "Aborted";
            terminalCount := terminalCount + 1;
            with remaining = recoveryCohort \ {"Timer"} do
                freeTimerCredits := freeTimerCredits + 1
                    + IF watchdogHeld /\ remaining = {} THEN 1 ELSE 0;
                recoveryCohort := remaining;
                if watchdogHeld /\ remaining = {} then
                    watchdogHeld := FALSE;
                end if;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ subState \in {"Unused", "Aborted"}
                  /\ waitState \in {"Unused", "Completed", "Aborted"}
                  /\ timerState \in {"Unused", "Completed", "Aborted"}
                  /\ ~watchdogHeld
                  /\ recoveryCohort = {}
                  /\ freeSubCredits = 1
                  /\ freeWaitCredits = 1
                  /\ freeTimerCredits = 2;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "bc9293b5" /\ chksum(tla) = "27dc0af3")
VARIABLES scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, publicationCount, terminalCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose

vars == << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, publicationCount, terminalCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = -1
        /\ serviceAlive = TRUE
        /\ bindingEpoch = 0
        /\ fallbackState = "Standby"
        /\ replacementState = "Bound"
        /\ recoveryRevision = 0
        /\ sourceGeneration = 0
        /\ sourceSequence = 0
        /\ sourceReady = FALSE
        /\ subState = "Unused"
        /\ subMode = "None"
        /\ subGeneration = 0
        /\ subBinding = NoBinding
        /\ queued = FALSE
        /\ waitState = "Unused"
        /\ waitBinding = NoBinding
        /\ timerState = "Unused"
        /\ timerBinding = NoBinding
        /\ winner = NoWinner
        /\ frozenReady = FALSE
        /\ frozenSourceGeneration = NoGeneration
        /\ frozenSourceSequence = NoSequence
        /\ frozenCount = -1
        /\ commitCount = 0
        /\ publicationCount = 0
        /\ terminalCount = 0
        /\ freeSubCredits = 1
        /\ freeWaitCredits = 1
        /\ freeTimerCredits = 2
        /\ watchdogHeld = FALSE
        /\ recoveryCohort = {}
        /\ snapshotState = "Absent"
        /\ snapshotBinding = NoBinding
        /\ snapshotRevision = -1
        /\ snapshotSourceGeneration = NoGeneration
        /\ snapshotSourceSequence = NoSequence
        /\ snapshotSourceReady = FALSE
        /\ snapshotSubState = "Unused"
        /\ snapshotSubGeneration = 0
        /\ snapshotQueued = FALSE
        /\ snapshotWaitState = "Unused"
        /\ snapshotTimerState = "Unused"
        /\ snapshotWinner = NoWinner
        /\ rejectCount = 0
        /\ commitAtClose = 0

Environment == /\ \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ replacementState = "Bound"
                        /\ subState = "Unused"
                        /\ freeSubCredits = 1
                     /\ subState' = "Armed"
                     /\ subGeneration' = 1
                     /\ subBinding' = bindingEpoch
                     /\ freeSubCredits' = 0
                     /\ IF sourceReady
                           THEN /\ queued' = TRUE
                           ELSE /\ TRUE
                                /\ UNCHANGED queued
                     /\ \/ /\ subMode' = "Level"
                        \/ /\ subMode' = "Edge"
                        \/ /\ subMode' = "OneShot"
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ sourceGeneration = 0
                        /\ sourceSequence < 3
                        /\ ~sourceReady
                     /\ sourceSequence' = sourceSequence + 1
                     /\ recoveryRevision' = recoveryRevision + 1
                     /\ sourceReady' = TRUE
                     /\ IF subState = "Armed"
                           THEN /\ queued' = TRUE
                           ELSE /\ TRUE
                                /\ UNCHANGED queued
                     /\ IF replacementState = "Ready"
                           THEN /\ replacementState' = "None"
                                /\ snapshotState' = "Absent"
                           ELSE /\ TRUE
                                /\ UNCHANGED << replacementState, snapshotState >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, sourceGeneration, subState, subMode, subGeneration, subBinding, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ sourceSequence < 3
                        /\ sourceReady
                     /\ sourceSequence' = sourceSequence + 1
                     /\ recoveryRevision' = recoveryRevision + 1
                     /\ sourceReady' = FALSE
                     /\ queued' = FALSE
                     /\ IF replacementState = "Ready"
                           THEN /\ replacementState' = "None"
                                /\ snapshotState' = "Absent"
                           ELSE /\ TRUE
                                /\ UNCHANGED << replacementState, snapshotState >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, sourceGeneration, subState, subMode, subGeneration, subBinding, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ sourceGeneration = 0
                        /\ sourceSequence < 3
                     /\ sourceGeneration' = 1
                     /\ sourceSequence' = sourceSequence + 1
                     /\ recoveryRevision' = recoveryRevision + 1
                     /\ sourceReady' = FALSE
                     /\ queued' = FALSE
                     /\ IF replacementState = "Ready"
                           THEN /\ replacementState' = "None"
                                /\ snapshotState' = "Absent"
                           ELSE /\ TRUE
                                /\ UNCHANGED << replacementState, snapshotState >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, subState, subMode, subGeneration, subBinding, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ replacementState = "Bound"
                        /\ waitState = "Unused"
                        /\ timerState = "Unused"
                        /\ freeWaitCredits = 1
                        /\ freeTimerCredits > 0
                     /\ waitState' = "Pending"
                     /\ timerState' = "Pending"
                     /\ waitBinding' = bindingEpoch
                     /\ timerBinding' = bindingEpoch
                     /\ freeWaitCredits' = 0
                     /\ freeTimerCredits' = freeTimerCredits - 1
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ replacementState = "Bound"
                        /\ waitState = "Pending"
                        /\ timerState = "Pending"
                        /\ waitBinding = bindingEpoch
                        /\ timerBinding = bindingEpoch
                        /\ subState = "Armed"
                        /\ subBinding = bindingEpoch
                        /\ queued
                        /\ sourceReady
                     /\ waitState' = "Committed"
                     /\ timerState' = "Committed"
                     /\ winner' = "Ready"
                     /\ frozenReady' = TRUE
                     /\ frozenSourceGeneration' = sourceGeneration
                     /\ frozenSourceSequence' = sourceSequence
                     /\ frozenCount' = 1
                     /\ commitCount' = commitCount + 1
                     /\ IF subMode = "Level"
                           THEN /\ queued' = TRUE
                                /\ UNCHANGED subState
                           ELSE /\ queued' = FALSE
                                /\ IF subMode = "OneShot"
                                      THEN /\ subState' = "Disabled"
                                      ELSE /\ TRUE
                                           /\ UNCHANGED subState
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subMode, subGeneration, subBinding, waitBinding, timerBinding, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ replacementState = "Bound"
                        /\ waitState = "Pending"
                        /\ timerState = "Pending"
                        /\ waitBinding = bindingEpoch
                        /\ timerBinding = bindingEpoch
                     /\ waitState' = "Committed"
                     /\ timerState' = "Committed"
                     /\ winner' = "Timeout"
                     /\ frozenReady' = FALSE
                     /\ frozenSourceGeneration' = sourceGeneration
                     /\ frozenSourceSequence' = sourceSequence
                     /\ frozenCount' = 0
                     /\ commitCount' = commitCount + 1
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitBinding, timerBinding, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ bindingEpoch < MaxBinding
                     /\ LET cohort == (IF subState \in LiveSubStates THEN {"Sub"} ELSE {}) \cup
                                      (IF waitState \in LiveWaitStates THEN {"Wait"} ELSE {}) \cup
                                      (IF timerState \in LiveTimerStates THEN {"Timer"} ELSE {}) IN
                          /\ bindingEpoch' = bindingEpoch + 1
                          /\ recoveryRevision' = recoveryRevision + 1
                          /\ serviceAlive' = FALSE
                          /\ replacementState' = "None"
                          /\ fallbackState' = "Required"
                          /\ recoveryCohort' = cohort
                          /\ snapshotState' = "Absent"
                          /\ IF cohort # {}
                                THEN /\ watchdogHeld' = TRUE
                                     /\ freeTimerCredits' = freeTimerCredits - 1
                                ELSE /\ TRUE
                                     /\ UNCHANGED << freeTimerCredits, watchdogHeld >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ ~serviceAlive
                        /\ fallbackState = "Running"
                        /\ replacementState = "None"
                     /\ snapshotState' = "Captured"
                     /\ snapshotBinding' = bindingEpoch
                     /\ snapshotRevision' = recoveryRevision
                     /\ snapshotSourceGeneration' = sourceGeneration
                     /\ snapshotSourceSequence' = sourceSequence
                     /\ snapshotSourceReady' = sourceReady
                     /\ snapshotSubState' = subState
                     /\ snapshotSubGeneration' = subGeneration
                     /\ snapshotQueued' = queued
                     /\ snapshotWaitState' = waitState
                     /\ snapshotTimerState' = timerState
                     /\ snapshotWinner' = winner
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ ~serviceAlive
                        /\ fallbackState = "Running"
                        /\ replacementState = "None"
                        /\ snapshotState = "Captured"
                        /\ snapshotBinding = bindingEpoch
                        /\ snapshotRevision = recoveryRevision
                        /\ snapshotSourceGeneration = sourceGeneration
                        /\ snapshotSourceSequence = sourceSequence
                        /\ snapshotSourceReady = sourceReady
                        /\ snapshotSubState = subState
                        /\ snapshotSubGeneration = subGeneration
                        /\ snapshotQueued = queued
                        /\ snapshotWaitState = waitState
                        /\ snapshotTimerState = timerState
                        /\ snapshotWinner = winner
                     /\ replacementState' = "Ready"
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ ~serviceAlive
                        /\ fallbackState = "Running"
                        /\ replacementState = "Ready"
                     /\ replacementState' = "Bound"
                     /\ serviceAlive' = TRUE
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, bindingEpoch, fallbackState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ \E e \in recoveryCohort:
                          /\ /\ scopeState = "Active"
                             /\ serviceAlive
                             /\ replacementState = "Bound"
                             /\ ((e = "Sub" /\ subBinding # bindingEpoch)
                                  \/ (e = "Wait" /\ waitBinding # bindingEpoch)
                                  \/ (e = "Timer" /\ timerBinding # bindingEpoch))
                          /\ IF e = "Sub"
                                THEN /\ subBinding' = bindingEpoch
                                ELSE /\ TRUE
                                     /\ UNCHANGED subBinding
                          /\ IF e = "Wait"
                                THEN /\ waitBinding' = bindingEpoch
                                ELSE /\ TRUE
                                     /\ UNCHANGED waitBinding
                          /\ IF e = "Timer"
                                THEN /\ timerBinding' = bindingEpoch
                                ELSE /\ TRUE
                                     /\ UNCHANGED timerBinding
                          /\ recoveryCohort' = recoveryCohort \ {e}
                          /\ recoveryRevision' = recoveryRevision + 1
                          /\ IF recoveryCohort' \ {e} = {}
                                THEN /\ watchdogHeld' = FALSE
                                     /\ freeTimerCredits' = freeTimerCredits + 1
                                ELSE /\ TRUE
                                     /\ UNCHANGED << freeTimerCredits, watchdogHeld >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, queued, waitState, timerState, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose>>
                  \/ /\ /\ EnableRejects
                        /\ scopeState = "Active"
                        /\ sourceGeneration = 1
                        /\ rejectCount = 0
                     /\ rejectCount' = 1
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, commitAtClose>>
                  \/ /\ scopeState = "Active"
                     /\ closingEpoch' = authorityEpoch
                     /\ authorityEpoch' = authorityEpoch + 1
                     /\ scopeState' = "Closing"
                     /\ serviceAlive' = FALSE
                     /\ replacementState' = "Closed"
                     /\ fallbackState' = "Closed"
                     /\ commitAtClose' = commitCount
                     /\ snapshotState' = "Absent"
                     /\ IF winner = NoWinner /\ waitState = "Pending"
                           THEN /\ winner' = "Revoke"
                           ELSE /\ TRUE
                                /\ UNCHANGED winner
                     /\ UNCHANGED <<bindingEpoch, recoveryRevision, sourceGeneration, sourceSequence, sourceReady, subState, subMode, subGeneration, subBinding, queued, waitState, waitBinding, timerState, timerBinding, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount>>
               /\ UNCHANGED << publicationCount, terminalCount >>

Kernel == /\ \/ /\ fallbackState = "Required"
                /\ fallbackState' = "Running"
                /\ UNCHANGED <<scopeState, replacementState, recoveryRevision, subState, queued, waitState, timerState, publicationCount, terminalCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState>>
             \/ /\ /\ waitState = "Committed"
                   /\ timerState = "Committed"
                   /\ scopeState \in {"Active", "Closing"}
                /\ waitState' = "Completed"
                /\ timerState' = "Completed"
                /\ recoveryRevision' = recoveryRevision + 1
                /\ publicationCount' = publicationCount + 1
                /\ terminalCount' = terminalCount + 2
                /\ freeWaitCredits' = freeWaitCredits + 1
                /\ LET remaining == recoveryCohort \ {"Wait", "Timer"} IN
                     /\ freeTimerCredits' =                 freeTimerCredits + 1
                                            + IF watchdogHeld /\ remaining = {} THEN 1 ELSE 0
                     /\ recoveryCohort' = remaining
                     /\ IF watchdogHeld /\ remaining = {}
                           THEN /\ watchdogHeld' = FALSE
                           ELSE /\ TRUE
                                /\ UNCHANGED watchdogHeld
                /\ IF replacementState = "Ready"
                      THEN /\ replacementState' = "None"
                           /\ snapshotState' = "Absent"
                      ELSE /\ TRUE
                           /\ UNCHANGED << replacementState, snapshotState >>
                /\ UNCHANGED <<scopeState, fallbackState, subState, queued, freeSubCredits>>
             \/ /\ /\ scopeState = "Closing"
                   /\ subState \in LiveSubStates
                /\ subState' = "Aborted"
                /\ queued' = FALSE
                /\ freeSubCredits' = freeSubCredits + 1
                /\ terminalCount' = terminalCount + 1
                /\ recoveryCohort' = recoveryCohort \ {"Sub"}
                /\ IF watchdogHeld /\ recoveryCohort' \ {"Sub"} = {}
                      THEN /\ watchdogHeld' = FALSE
                           /\ freeTimerCredits' = freeTimerCredits + 1
                      ELSE /\ TRUE
                           /\ UNCHANGED << freeTimerCredits, watchdogHeld >>
                /\ UNCHANGED <<scopeState, fallbackState, replacementState, recoveryRevision, waitState, timerState, publicationCount, freeWaitCredits, snapshotState>>
             \/ /\ /\ scopeState = "Closing"
                   /\ waitState = "Pending"
                /\ waitState' = "Aborted"
                /\ freeWaitCredits' = freeWaitCredits + 1
                /\ terminalCount' = terminalCount + 1
                /\ recoveryCohort' = recoveryCohort \ {"Wait"}
                /\ IF watchdogHeld /\ recoveryCohort' \ {"Wait"} = {}
                      THEN /\ watchdogHeld' = FALSE
                           /\ freeTimerCredits' = freeTimerCredits + 1
                      ELSE /\ TRUE
                           /\ UNCHANGED << freeTimerCredits, watchdogHeld >>
                /\ UNCHANGED <<scopeState, fallbackState, replacementState, recoveryRevision, subState, queued, timerState, publicationCount, freeSubCredits, snapshotState>>
             \/ /\ /\ scopeState = "Closing"
                   /\ timerState = "Pending"
                /\ timerState' = "Aborted"
                /\ terminalCount' = terminalCount + 1
                /\ LET remaining == recoveryCohort \ {"Timer"} IN
                     /\ freeTimerCredits' =                 freeTimerCredits + 1
                                            + IF watchdogHeld /\ remaining = {} THEN 1 ELSE 0
                     /\ recoveryCohort' = remaining
                     /\ IF watchdogHeld /\ remaining = {}
                           THEN /\ watchdogHeld' = FALSE
                           ELSE /\ TRUE
                                /\ UNCHANGED watchdogHeld
                /\ UNCHANGED <<scopeState, fallbackState, replacementState, recoveryRevision, subState, queued, waitState, publicationCount, freeSubCredits, freeWaitCredits, snapshotState>>
             \/ /\ /\ scopeState = "Closing"
                   /\ subState \in {"Unused", "Aborted"}
                   /\ waitState \in {"Unused", "Completed", "Aborted"}
                   /\ timerState \in {"Unused", "Completed", "Aborted"}
                   /\ ~watchdogHeld
                   /\ recoveryCohort = {}
                   /\ freeSubCredits = 1
                   /\ freeWaitCredits = 1
                   /\ freeTimerCredits = 2
                /\ scopeState' = "Revoked"
                /\ UNCHANGED <<fallbackState, replacementState, recoveryRevision, subState, queued, waitState, timerState, publicationCount, terminalCount, freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState>>
          /\ UNCHANGED << authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, sourceGeneration, sourceSequence, sourceReady, subMode, subGeneration, subBinding, waitBinding, timerBinding, winner, frozenReady, frozenSourceGeneration, frozenSourceSequence, frozenCount, commitCount, snapshotBinding, snapshotRevision, snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady, snapshotSubState, snapshotSubGeneration, snapshotQueued, snapshotWaitState, snapshotTimerState, snapshotWinner, rejectCount, commitAtClose >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

TypeOK ==
    /\ scopeState \in {"Active", "Closing", "Revoked"}
    /\ authorityEpoch \in 0..1
    /\ bindingEpoch \in 0..MaxBinding
    /\ fallbackState \in {"Standby", "Required", "Running", "Closed"}
    /\ replacementState \in {"None", "Ready", "Bound", "Closed"}
    /\ sourceGeneration \in 0..1
    /\ sourceSequence \in Nat
    /\ subState \in {"Unused", "Armed", "Disabled", "Aborted"}
    /\ subMode \in {"None", "Level", "Edge", "OneShot"}
    /\ waitState \in {"Unused", "Pending", "Committed", "Completed", "Aborted"}
    /\ timerState \in {"Unused", "Pending", "Committed", "Completed", "Aborted"}
    /\ winner \in {NoWinner, "Ready", "Timeout", "Revoke"}
    /\ recoveryCohort \subseteq Effects
    /\ freeSubCredits \in 0..1
    /\ freeWaitCredits \in 0..1
    /\ freeTimerCredits \in 0..2

BudgetConservation ==
    /\ freeSubCredits + (IF subState \in LiveSubStates THEN 1 ELSE 0) = 1
    /\ freeWaitCredits + (IF waitState \in LiveWaitStates THEN 1 ELSE 0) = 1
    /\ freeTimerCredits
         + (IF timerState \in LiveTimerStates THEN 1 ELSE 0)
         + (IF watchdogHeld THEN 1 ELSE 0) = 2

SingleWinner ==
    /\ commitCount \in 0..1
    /\ publicationCount \in 0..1
    /\ publicationCount <= commitCount
    /\ (commitCount = 1 => winner \in {"Ready", "Timeout"})
    /\ (winner = "Revoke" => commitCount = 0)

FrozenReceipt ==
    /\ (winner = "Ready" =>
          /\ frozenReady
          /\ frozenCount = 1
          /\ frozenSourceGeneration \in 0..1
          /\ frozenSourceSequence \in Nat)
    /\ (winner = "Timeout" => /\ ~frozenReady /\ frozenCount = 0)
    /\ (commitCount = 0 => frozenCount = -1)

TriggerDiscipline ==
    /\ (subState = "Disabled" => subMode = "OneShot")
    /\ (subState = "Disabled" => ~queued)
    /\ (queued => /\ subState = "Armed" /\ sourceReady)

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} => commitCount = commitAtClose

SnapshotDiscipline ==
    replacementState = "Ready" =>
      /\ snapshotBinding = bindingEpoch
      /\ snapshotRevision = recoveryRevision
      /\ snapshotSourceGeneration = sourceGeneration
      /\ snapshotSourceSequence = sourceSequence
      /\ snapshotSourceReady = sourceReady
      /\ snapshotSubState = subState
      /\ snapshotSubGeneration = subGeneration
      /\ snapshotQueued = queued
      /\ snapshotWaitState = waitState
      /\ snapshotTimerState = timerState
      /\ snapshotWinner = winner

QuiescentClosure ==
    scopeState = "Revoked" =>
      /\ subState \in {"Unused", "Aborted"}
      /\ waitState \in {"Unused", "Completed", "Aborted"}
      /\ timerState \in {"Unused", "Completed", "Aborted"}
      /\ ~queued
      /\ ~watchdogHeld
      /\ recoveryCohort = {}
      /\ freeSubCredits = 1
      /\ freeWaitCredits = 1
      /\ freeTimerCredits = 2

RejectSideEffectFreedom ==
    [][rejectCount' # rejectCount => UNCHANGED <<
        scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch,
        fallbackState, replacementState, recoveryRevision, sourceGeneration,
        sourceSequence, sourceReady, subState, subMode, subGeneration,
        subBinding, queued, waitState, waitBinding, timerState, timerBinding,
        winner, frozenReady, frozenSourceGeneration, frozenSourceSequence,
        frozenCount, commitCount, publicationCount, terminalCount,
        freeSubCredits, freeWaitCredits, freeTimerCredits, watchdogHeld,
        recoveryCohort, snapshotState, snapshotBinding, snapshotRevision,
        snapshotSourceGeneration, snapshotSourceSequence, snapshotSourceReady,
        snapshotSubState, snapshotSubGeneration, snapshotQueued,
        snapshotWaitState, snapshotTimerState, snapshotWinner, commitAtClose
    >>]_vars

ReadyCommitUsesCurrentBinding ==
    [][(/\ commitCount' = commitCount + 1
        /\ winner' = "Ready") =>
          /\ subBinding = bindingEpoch
          /\ waitBinding = bindingEpoch
          /\ timerBinding = bindingEpoch]_vars

FallbackProgress == [](fallbackState = "Required" ~> fallbackState # "Required")
PublicationProgress == [](waitState = "Committed" ~> waitState = "Completed")
RevocationProgress == [](scopeState = "Closing" ~> scopeState = "Revoked")

ReadyObserved == /\ winner = "Ready" /\ frozenCount = 1
TimeoutObserved == /\ winner = "Timeout" /\ frozenCount = 0
RevokeObserved == /\ winner = "Revoke" /\ scopeState = "Revoked"
CrashAdoptObserved ==
    /\ bindingEpoch = 1
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ snapshotBinding = 1
    /\ snapshotSubState = "Armed"
    /\ snapshotWaitState = "Pending"
    /\ snapshotTimerState = "Pending"
    /\ recoveryCohort = {}
    /\ commitCount = 1
LTRequeueObserved ==
    /\ winner = "Ready"
    /\ subMode = "Level"
    /\ queued
OneShotDisabledObserved ==
    /\ winner = "Ready"
    /\ subMode = "OneShot"
    /\ subState = "Disabled"
SourceFenceObserved == /\ sourceGeneration = 1 /\ rejectCount = 1
CurrentBindingFenceObserved ==
    /\ bindingEpoch = 1
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ subState = "Armed"
    /\ subBinding = 0
    /\ queued
    /\ sourceReady
    /\ waitState = "Pending"
    /\ timerState = "Pending"
    /\ waitBinding = 1
    /\ timerBinding = 1
    /\ commitCount = 0

ReadyAbsent == ~ReadyObserved
TimeoutAbsent == ~TimeoutObserved
RevokeAbsent == ~RevokeObserved
CrashAdoptAbsent == ~CrashAdoptObserved
LTRequeueAbsent == ~LTRequeueObserved
OneShotDisabledAbsent == ~OneShotDisabledObserved
SourceFenceAbsent == ~SourceFenceObserved
CurrentBindingFenceAbsent == ~CurrentBindingFenceObserved

=============================================================================

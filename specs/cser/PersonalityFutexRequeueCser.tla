------------------ MODULE PersonalityFutexRequeueCser ------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Stage 6B.2 bounded successor for two private keys and two waiters.       *)
(* RequeueCommit atomically freezes a disjoint woken/moved partition.       *)
(* Moved waits retain identity, continuation, binding, and wait credit.      *)
(* KernelPublish later terminalizes only the controller and woken waiter.    *)
(* The PlusCal algorithm is the sole source of Init and Next.                *)
(***************************************************************************)

CONSTANTS
    Scope,
    Wait1,
    Wait2,
    RequeueCall,
    WakeCall,
    WaitTask1,
    WaitTask2,
    RequeueTask,
    WakeTask,
    KeyA,
    KeyB,
    MaxBinding,
    EnableRejects

WaitCalls == {Wait1, Wait2}
ControlCalls == {RequeueCall, WakeCall}
Calls == WaitCalls \cup ControlCalls
Tasks == {WaitTask1, WaitTask2, RequeueTask, WakeTask}
Keys == {KeyA, KeyB}

ASSUME /\ Cardinality(Calls) = 4
       /\ Cardinality(Tasks) = 4
       /\ KeyA # KeyB
       /\ MaxBinding = 1
       /\ EnableRejects \in BOOLEAN

ScopeStates == {"Active", "Closing", "Revoked"}
CallStates == {
    "Unused", "WaitQueued", "WaitClaimed", "ControlCaptured",
    "RequeueCommitted", "WakeCommitted", "Completed", "Aborted"
}
LiveCallStates == {
    "WaitQueued", "WaitClaimed", "ControlCaptured",
    "RequeueCommitted", "WakeCommitted"
}
CommittedCallStates == {"WaitClaimed", "RequeueCommitted", "WakeCommitted"}
TerminalCallStates == {"Completed", "Aborted"}
Operations == {"None", "Wait", "Requeue", "Wake"}
ContinuationStates == {"Absent", "Pending", "Delivered", "Aborted"}
ReplacementStates == {"None", "Ready", "Bound", "Closed"}
FallbackStates == {"Standby", "Required", "Running", "Closed"}
SnapshotStates == {"Absent", "Captured"}
RequeueModes == {"None", "WakeMove", "MoveOnly"}

NoEpoch == -1
NoBinding == -1
NoRevision == -1
NoResult == -1
NoCall == "NoCall"
NoTask == "NoTask"
NoKey == "NoKey"

HeadEligible(waiters, currentBinding, bindings) ==
    IF Wait1 \in waiters
       THEN IF bindings[Wait1] = currentBinding THEN {Wait1} ELSE {}
       ELSE IF Wait2 \in waiters
               THEN IF bindings[Wait2] = currentBinding THEN {Wait2} ELSE {}
               ELSE {}

RequeueWokenFor(mode, waiters, currentBinding, bindings) ==
    IF mode = "WakeMove"
       THEN HeadEligible(waiters, currentBinding, bindings)
       ELSE {}

RequeueMovedFor(mode, waiters, currentBinding, bindings) ==
    HeadEligible(
        waiters \ RequeueWokenFor(mode, waiters, currentBinding, bindings),
        currentBinding,
        bindings)

(* --algorithm PersonalityFutexRequeueCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = NoEpoch,

    serviceAlive = TRUE,
    bindingEpoch = 0,
    recoveryRevision = 0,
    replacementState = "Bound",
    fallbackState = "Standby",

    callState = [c \in Calls |-> "Unused"],
    operation = [c \in Calls |-> "None"],
    callTask = [c \in Calls |-> NoTask],
    originKey = [c \in Calls |-> NoKey],
    callAuthority = [c \in Calls |-> NoEpoch],
    callBinding = [c \in Calls |-> NoBinding],
    continuationState = [c \in Calls |-> "Absent"],
    blockedBy = [t \in Tasks |-> NoCall],

    queuedOn = [w \in WaitCalls |-> NoKey],
    queueA = {},
    queueB = {},
    selectedBy = [w \in WaitCalls |-> NoCall],
    migrationCount = [w \in WaitCalls |-> 0],

    requeueMode = "None",
    requeueWoken = {},
    requeueMoved = {},
    requeueResult = NoResult,
    wakeSelected = {},
    wakeResult = NoResult,
    requeueCommitCount = 0,
    wakeCommitCount = 0,

    waitCreditHeld = [w \in WaitCalls |-> FALSE],
    controlCreditHeld = [c \in ControlCalls |-> FALSE],
    freeWaitCredits = 2,
    freeControlCredits = 2,
    timerCreditHeld = FALSE,
    freeTimerCredits = 1,

    terminalCount = [c \in Calls |-> 0],
    publicationCount = [c \in Calls |-> 0],
    abortCount = [c \in Calls |-> 0],
    adoptCount = [c \in Calls |-> 0],
    rejectCount = [c \in Calls |-> 0],

    recoveryCohort = {},
    watchdogExpiredSeen = FALSE,

    snapshotState = "Absent",
    snapshotAuthority = NoEpoch,
    snapshotBinding = NoBinding,
    snapshotRevision = NoRevision,
    snapshotCallState = [c \in Calls |-> "Unused"],
    snapshotQueuedOn = [w \in WaitCalls |-> NoKey],
    snapshotQueueA = {},
    snapshotQueueB = {},
    snapshotRequeueWoken = {},
    snapshotRequeueMoved = {},
    snapshotRequeueResult = NoResult,
    snapshotWakeSelected = {},
    snapshotWakeResult = NoResult,
    snapshotMigrationCount = [w \in WaitCalls |-> 0],

    liveAtClose = {},
    committedAtClose = {},
    requeueCommitAtClose = 0,
    wakeCommitAtClose = 0,
    migrationAtClose = [w \in WaitCalls |-> 0],
    adoptAtClose = [c \in Calls |-> 0],
    closureTargetCount = 0,
    closureSteps = 0;

process PersonalityEnvironment = "personality-environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            with w \in WaitCalls do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ callState[w] = "Unused"
                      /\ freeWaitCredits > 0
                      /\ (w = Wait1 \/ callState[Wait1] # "Unused");
                callState[w] := "WaitQueued";
                operation[w] := "Wait";
                callTask[w] := IF w = Wait1 THEN WaitTask1 ELSE WaitTask2;
                originKey[w] := KeyA;
                callAuthority[w] := authorityEpoch;
                callBinding[w] := bindingEpoch;
                continuationState[w] := "Pending";
                blockedBy[IF w = Wait1 THEN WaitTask1 ELSE WaitTask2] := w;
                queuedOn[w] := KeyA;
                queueA := queueA \cup {w};
                waitCreditHeld[w] := TRUE;
                freeWaitCredits := freeWaitCredits - 1;
            end with;
        or
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[RequeueCall] = "Unused"
                  /\ freeControlCredits > 0;
            callState[RequeueCall] := "ControlCaptured";
            operation[RequeueCall] := "Requeue";
            callTask[RequeueCall] := RequeueTask;
            originKey[RequeueCall] := KeyA;
            callAuthority[RequeueCall] := authorityEpoch;
            callBinding[RequeueCall] := bindingEpoch;
            continuationState[RequeueCall] := "Pending";
            blockedBy[RequeueTask] := RequeueCall;
            controlCreditHeld[RequeueCall] := TRUE;
            freeControlCredits := freeControlCredits - 1;
            either requeueMode := "WakeMove"
            or requeueMode := "MoveOnly"
            end either;
        or
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WakeCall] = "Unused"
                  /\ freeControlCredits > 0;
            callState[WakeCall] := "ControlCaptured";
            operation[WakeCall] := "Wake";
            callTask[WakeCall] := WakeTask;
            originKey[WakeCall] := KeyB;
            callAuthority[WakeCall] := authorityEpoch;
            callBinding[WakeCall] := bindingEpoch;
            continuationState[WakeCall] := "Pending";
            blockedBy[WakeTask] := WakeCall;
            controlCreditHeld[WakeCall] := TRUE;
            freeControlCredits := freeControlCredits - 1;
        or
            \* RequeueCommit is atomic with RevokeBegin.  It selects only
            \* current-binding waits and never commits the moved waiter.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[RequeueCall] = "ControlCaptured"
                  /\ callAuthority[RequeueCall] = authorityEpoch
                  /\ callBinding[RequeueCall] = bindingEpoch;
            with woken = RequeueWokenFor(
                              requeueMode, queueA, bindingEpoch, callBinding),
                 moved = RequeueMovedFor(
                              requeueMode, queueA, bindingEpoch, callBinding) do
                callState := [c \in Calls |->
                    IF c = RequeueCall THEN "RequeueCommitted"
                    ELSE IF c \in woken THEN "WaitClaimed"
                    ELSE callState[c]];
                queuedOn := [w \in WaitCalls |->
                    IF w \in woken THEN NoKey
                    ELSE IF w \in moved THEN KeyB
                    ELSE queuedOn[w]];
                queueA := queueA \ (woken \cup moved);
                queueB := queueB \cup moved;
                selectedBy := [w \in WaitCalls |->
                    IF w \in woken THEN RequeueCall ELSE selectedBy[w]];
                migrationCount := [w \in WaitCalls |->
                    IF w \in moved THEN migrationCount[w] + 1
                    ELSE migrationCount[w]];
                requeueWoken := woken;
                requeueMoved := moved;
                requeueResult := Cardinality(woken) + Cardinality(moved);
                requeueCommitCount := requeueCommitCount + 1;
            end with;
        or
            \* Target wake selects only a current-binding B waiter.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WakeCall] = "ControlCaptured"
                  /\ callAuthority[WakeCall] = authorityEpoch
                  /\ callBinding[WakeCall] = bindingEpoch;
            with selected = HeadEligible(
                                queueB, bindingEpoch, callBinding) do
                callState := [c \in Calls |->
                    IF c = WakeCall THEN "WakeCommitted"
                    ELSE IF c \in selected THEN "WaitClaimed"
                    ELSE callState[c]];
                queuedOn := [w \in WaitCalls |->
                    IF w \in selected THEN NoKey ELSE queuedOn[w]];
                queueB := queueB \ selected;
                selectedBy := [w \in WaitCalls |->
                    IF w \in selected THEN WakeCall ELSE selectedBy[w]];
                wakeSelected := selected;
                wakeResult := Cardinality(selected);
                wakeCommitCount := wakeCommitCount + 1;
            end with;
        or
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ bindingEpoch < MaxBinding;
            bindingEpoch := bindingEpoch + 1;
            recoveryRevision := recoveryRevision + 1;
            serviceAlive := FALSE;
            replacementState := "None";
            fallbackState := "Required";
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotRevision := NoRevision;
            recoveryCohort := {c \in Calls : callState[c] \in LiveCallStates};
            if {c \in Calls : callState[c] \in LiveCallStates} # {} then
                timerCreditHeld := TRUE;
                freeTimerCredits := freeTimerCredits - 1;
            end if;
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None";
            snapshotState := "Captured";
            snapshotAuthority := authorityEpoch;
            snapshotBinding := bindingEpoch;
            snapshotRevision := recoveryRevision;
            snapshotCallState := callState;
            snapshotQueuedOn := queuedOn;
            snapshotQueueA := queueA;
            snapshotQueueB := queueB;
            snapshotRequeueWoken := requeueWoken;
            snapshotRequeueMoved := requeueMoved;
            snapshotRequeueResult := requeueResult;
            snapshotWakeSelected := wakeSelected;
            snapshotWakeResult := wakeResult;
            snapshotMigrationCount := migrationCount;
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ snapshotState = "Captured"
                  /\ snapshotAuthority = authorityEpoch
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotRevision = recoveryRevision
                  /\ snapshotCallState = callState
                  /\ snapshotQueuedOn = queuedOn
                  /\ snapshotQueueA = queueA
                  /\ snapshotQueueB = queueB
                  /\ snapshotRequeueWoken = requeueWoken
                  /\ snapshotRequeueMoved = requeueMoved
                  /\ snapshotRequeueResult = requeueResult
                  /\ snapshotWakeSelected = wakeSelected
                  /\ snapshotWakeResult = wakeResult
                  /\ snapshotMigrationCount = migrationCount;
            replacementState := "Ready";
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready"
                  /\ snapshotState = "Captured"
                  /\ snapshotRevision = recoveryRevision
                  /\ snapshotCallState = callState
                  /\ snapshotQueuedOn = queuedOn
                  /\ snapshotQueueA = queueA
                  /\ snapshotQueueB = queueB
                  /\ snapshotRequeueWoken = requeueWoken
                  /\ snapshotRequeueMoved = requeueMoved
                  /\ snapshotRequeueResult = requeueResult
                  /\ snapshotWakeSelected = wakeSelected
                  /\ snapshotWakeResult = wakeResult
                  /\ snapshotMigrationCount = migrationCount;
            serviceAlive := TRUE;
            replacementState := "Bound";
            fallbackState := "Standby";
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotRevision := NoRevision;
        or
            with c \in Calls do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ callState[c] \in LiveCallStates
                      /\ callAuthority[c] = authorityEpoch
                      /\ callBinding[c] # bindingEpoch;
                callBinding[c] := bindingEpoch;
                adoptCount[c] := adoptCount[c] + 1;
                recoveryCohort := recoveryCohort \ {c};
            end with;
        or
            with c \in Calls,
                 presentedBinding \in 0..MaxBinding do
                await /\ EnableRejects
                      /\ callState[c] \in LiveCallStates
                      /\ rejectCount[c] = 0
                      /\ presentedBinding # callBinding[c];
                rejectCount[c] := 1;
            end with;
        or
            await scopeState = "Active";
            liveAtClose := {c \in Calls : callState[c] \in LiveCallStates};
            committedAtClose := {c \in Calls : callState[c] \in CommittedCallStates};
            requeueCommitAtClose := requeueCommitCount;
            wakeCommitAtClose := wakeCommitCount;
            migrationAtClose := migrationCount;
            adoptAtClose := adoptCount;
            closureTargetCount := Cardinality({c \in Calls : callState[c] \in LiveCallStates});
            closureSteps := 0;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "Closed";
            fallbackState := "Closed";
            snapshotState := "Absent";
        end either;
    end while;
end process;

fair process KernelFallback = "kernel-fallback"
begin
FallbackLoop:
    while TRUE do
        await fallbackState = "Required";
        fallbackState := "Running";
    end while;
end process;

fair process KernelPublish = "kernel-publish"
begin
PublishLoop:
    while TRUE do
        with c \in ControlCalls do
            await /\ callState[c] \in {"RequeueCommitted", "WakeCommitted"}
                  /\ scopeState \in {"Active", "Closing"};
            if c = RequeueCall then
                if requeueWoken # {} then
                    with w \in requeueWoken do
                        callState := [callState EXCEPT
                            ![RequeueCall] = "Completed", ![w] = "Completed"];
                        continuationState := [continuationState EXCEPT
                            ![RequeueCall] = "Delivered", ![w] = "Delivered"];
                        terminalCount := [terminalCount EXCEPT
                            ![RequeueCall] = @ + 1, ![w] = @ + 1];
                        publicationCount := [publicationCount EXCEPT
                            ![RequeueCall] = @ + 1, ![w] = @ + 1];
                        blockedBy := [blockedBy EXCEPT
                            ![RequeueTask] = NoCall, ![callTask[w]] = NoCall];
                        controlCreditHeld[RequeueCall] := FALSE;
                        waitCreditHeld[w] := FALSE;
                        freeControlCredits := freeControlCredits + 1;
                        freeWaitCredits := freeWaitCredits + 1;
                        recoveryCohort := recoveryCohort \ {RequeueCall, w};
                    end with;
                else
                    callState[RequeueCall] := "Completed";
                    continuationState[RequeueCall] := "Delivered";
                    terminalCount[RequeueCall] := terminalCount[RequeueCall] + 1;
                    publicationCount[RequeueCall] := publicationCount[RequeueCall] + 1;
                    blockedBy[RequeueTask] := NoCall;
                    controlCreditHeld[RequeueCall] := FALSE;
                    freeControlCredits := freeControlCredits + 1;
                    recoveryCohort := recoveryCohort \ {RequeueCall};
                end if;
                if scopeState = "Closing" then
                    closureSteps := closureSteps + 1 + Cardinality(requeueWoken);
                end if;
            else
                if wakeSelected # {} then
                    with w \in wakeSelected do
                        callState := [callState EXCEPT
                            ![WakeCall] = "Completed", ![w] = "Completed"];
                        continuationState := [continuationState EXCEPT
                            ![WakeCall] = "Delivered", ![w] = "Delivered"];
                        terminalCount := [terminalCount EXCEPT
                            ![WakeCall] = @ + 1, ![w] = @ + 1];
                        publicationCount := [publicationCount EXCEPT
                            ![WakeCall] = @ + 1, ![w] = @ + 1];
                        blockedBy := [blockedBy EXCEPT
                            ![WakeTask] = NoCall, ![callTask[w]] = NoCall];
                        controlCreditHeld[WakeCall] := FALSE;
                        waitCreditHeld[w] := FALSE;
                        freeControlCredits := freeControlCredits + 1;
                        freeWaitCredits := freeWaitCredits + 1;
                        recoveryCohort := recoveryCohort \ {WakeCall, w};
                    end with;
                else
                    callState[WakeCall] := "Completed";
                    continuationState[WakeCall] := "Delivered";
                    terminalCount[WakeCall] := terminalCount[WakeCall] + 1;
                    publicationCount[WakeCall] := publicationCount[WakeCall] + 1;
                    blockedBy[WakeTask] := NoCall;
                    controlCreditHeld[WakeCall] := FALSE;
                    freeControlCredits := freeControlCredits + 1;
                    recoveryCohort := recoveryCohort \ {WakeCall};
                end if;
                if scopeState = "Closing" then
                    closureSteps := closureSteps + 1 + Cardinality(wakeSelected);
                end if;
            end if;
            if ~serviceAlive /\ scopeState = "Active" then
                recoveryRevision := recoveryRevision + 1;
                if replacementState = "Ready" then
                    replacementState := "None";
                end if;
            end if;
        end with;
    end while;
end process;

fair process KernelClosure = "kernel-closure"
begin
ClosureLoop:
    while TRUE do
        either
            await /\ scopeState = "Active"
                  /\ timerCreditHeld
                  /\ recoveryCohort = {};
            timerCreditHeld := FALSE;
            freeTimerCredits := freeTimerCredits + 1;
        or
            \* Recovery-watchdog expiry is a revoke, never Linux ETIMEDOUT.
            await /\ scopeState = "Active"
                  /\ timerCreditHeld
                  /\ recoveryCohort # {};
            liveAtClose := {c \in Calls : callState[c] \in LiveCallStates};
            committedAtClose := {c \in Calls : callState[c] \in CommittedCallStates};
            requeueCommitAtClose := requeueCommitCount;
            wakeCommitAtClose := wakeCommitCount;
            migrationAtClose := migrationCount;
            adoptAtClose := adoptCount;
            closureTargetCount := Cardinality({c \in Calls : callState[c] \in LiveCallStates});
            closureSteps := 0;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "Closed";
            fallbackState := "Closed";
            snapshotState := "Absent";
            watchdogExpiredSeen := TRUE;
        or
            with c \in Calls do
                await /\ scopeState = "Closing"
                      /\ callAuthority[c] = closingEpoch
                      /\ callState[c] \in LiveCallStates
                      /\ callState[c] \notin {"WaitClaimed", "RequeueCommitted", "WakeCommitted"};
                if c \in WaitCalls then
                    if queuedOn[c] = KeyA then queueA := queueA \ {c} end if;
                    if queuedOn[c] = KeyB then queueB := queueB \ {c} end if;
                    queuedOn[c] := NoKey;
                    waitCreditHeld[c] := FALSE;
                    freeWaitCredits := freeWaitCredits + 1;
                else
                    controlCreditHeld[c] := FALSE;
                    freeControlCredits := freeControlCredits + 1;
                end if;
                callState[c] := "Aborted";
                continuationState[c] := "Aborted";
                terminalCount[c] := terminalCount[c] + 1;
                abortCount[c] := abortCount[c] + 1;
                blockedBy[callTask[c]] := NoCall;
                recoveryCohort := recoveryCohort \ {c};
                closureSteps := closureSteps + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ timerCreditHeld
                  /\ recoveryCohort = {};
            timerCreditHeld := FALSE;
            freeTimerCredits := freeTimerCredits + 1;
        or
            await /\ scopeState = "Closing"
                  /\ {c \in Calls : callState[c] \in LiveCallStates} = {}
                  /\ ~timerCreditHeld
                  /\ closureSteps = closureTargetCount;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION
VARIABLES scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, terminalCount, publicationCount, abortCount, adoptCount, rejectCount, recoveryCohort, watchdogExpiredSeen, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps

vars == << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, terminalCount, publicationCount, abortCount, adoptCount, rejectCount, recoveryCohort, watchdogExpiredSeen, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps >>

ProcSet == {"personality-environment"} \cup {"kernel-fallback"} \cup {"kernel-publish"} \cup {"kernel-closure"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ serviceAlive = TRUE
        /\ bindingEpoch = 0
        /\ recoveryRevision = 0
        /\ replacementState = "Bound"
        /\ fallbackState = "Standby"
        /\ callState = [c \in Calls |-> "Unused"]
        /\ operation = [c \in Calls |-> "None"]
        /\ callTask = [c \in Calls |-> NoTask]
        /\ originKey = [c \in Calls |-> NoKey]
        /\ callAuthority = [c \in Calls |-> NoEpoch]
        /\ callBinding = [c \in Calls |-> NoBinding]
        /\ continuationState = [c \in Calls |-> "Absent"]
        /\ blockedBy = [t \in Tasks |-> NoCall]
        /\ queuedOn = [w \in WaitCalls |-> NoKey]
        /\ queueA = {}
        /\ queueB = {}
        /\ selectedBy = [w \in WaitCalls |-> NoCall]
        /\ migrationCount = [w \in WaitCalls |-> 0]
        /\ requeueMode = "None"
        /\ requeueWoken = {}
        /\ requeueMoved = {}
        /\ requeueResult = NoResult
        /\ wakeSelected = {}
        /\ wakeResult = NoResult
        /\ requeueCommitCount = 0
        /\ wakeCommitCount = 0
        /\ waitCreditHeld = [w \in WaitCalls |-> FALSE]
        /\ controlCreditHeld = [c \in ControlCalls |-> FALSE]
        /\ freeWaitCredits = 2
        /\ freeControlCredits = 2
        /\ timerCreditHeld = FALSE
        /\ freeTimerCredits = 1
        /\ terminalCount = [c \in Calls |-> 0]
        /\ publicationCount = [c \in Calls |-> 0]
        /\ abortCount = [c \in Calls |-> 0]
        /\ adoptCount = [c \in Calls |-> 0]
        /\ rejectCount = [c \in Calls |-> 0]
        /\ recoveryCohort = {}
        /\ watchdogExpiredSeen = FALSE
        /\ snapshotState = "Absent"
        /\ snapshotAuthority = NoEpoch
        /\ snapshotBinding = NoBinding
        /\ snapshotRevision = NoRevision
        /\ snapshotCallState = [c \in Calls |-> "Unused"]
        /\ snapshotQueuedOn = [w \in WaitCalls |-> NoKey]
        /\ snapshotQueueA = {}
        /\ snapshotQueueB = {}
        /\ snapshotRequeueWoken = {}
        /\ snapshotRequeueMoved = {}
        /\ snapshotRequeueResult = NoResult
        /\ snapshotWakeSelected = {}
        /\ snapshotWakeResult = NoResult
        /\ snapshotMigrationCount = [w \in WaitCalls |-> 0]
        /\ liveAtClose = {}
        /\ committedAtClose = {}
        /\ requeueCommitAtClose = 0
        /\ wakeCommitAtClose = 0
        /\ migrationAtClose = [w \in WaitCalls |-> 0]
        /\ adoptAtClose = [c \in Calls |-> 0]
        /\ closureTargetCount = 0
        /\ closureSteps = 0

PersonalityEnvironment == /\ \/ /\ \E w \in WaitCalls:
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ callState[w] = "Unused"
                                        /\ freeWaitCredits > 0
                                        /\ (w = Wait1 \/ callState[Wait1] # "Unused")
                                     /\ callState' = [callState EXCEPT ![w] = "WaitQueued"]
                                     /\ operation' = [operation EXCEPT ![w] = "Wait"]
                                     /\ callTask' = [callTask EXCEPT ![w] = IF w = Wait1 THEN WaitTask1 ELSE WaitTask2]
                                     /\ originKey' = [originKey EXCEPT ![w] = KeyA]
                                     /\ callAuthority' = [callAuthority EXCEPT ![w] = authorityEpoch]
                                     /\ callBinding' = [callBinding EXCEPT ![w] = bindingEpoch]
                                     /\ continuationState' = [continuationState EXCEPT ![w] = "Pending"]
                                     /\ blockedBy' = [blockedBy EXCEPT ![IF w = Wait1 THEN WaitTask1 ELSE WaitTask2] = w]
                                     /\ queuedOn' = [queuedOn EXCEPT ![w] = KeyA]
                                     /\ queueA' = (queueA \cup {w})
                                     /\ waitCreditHeld' = [waitCreditHeld EXCEPT ![w] = TRUE]
                                     /\ freeWaitCredits' = freeWaitCredits - 1
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, controlCreditHeld, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[RequeueCall] = "Unused"
                                   /\ freeControlCredits > 0
                                /\ callState' = [callState EXCEPT ![RequeueCall] = "ControlCaptured"]
                                /\ operation' = [operation EXCEPT ![RequeueCall] = "Requeue"]
                                /\ callTask' = [callTask EXCEPT ![RequeueCall] = RequeueTask]
                                /\ originKey' = [originKey EXCEPT ![RequeueCall] = KeyA]
                                /\ callAuthority' = [callAuthority EXCEPT ![RequeueCall] = authorityEpoch]
                                /\ callBinding' = [callBinding EXCEPT ![RequeueCall] = bindingEpoch]
                                /\ continuationState' = [continuationState EXCEPT ![RequeueCall] = "Pending"]
                                /\ blockedBy' = [blockedBy EXCEPT ![RequeueTask] = RequeueCall]
                                /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![RequeueCall] = TRUE]
                                /\ freeControlCredits' = freeControlCredits - 1
                                /\ \/ /\ requeueMode' = "WakeMove"
                                   \/ /\ requeueMode' = "MoveOnly"
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, freeWaitCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WakeCall] = "Unused"
                                   /\ freeControlCredits > 0
                                /\ callState' = [callState EXCEPT ![WakeCall] = "ControlCaptured"]
                                /\ operation' = [operation EXCEPT ![WakeCall] = "Wake"]
                                /\ callTask' = [callTask EXCEPT ![WakeCall] = WakeTask]
                                /\ originKey' = [originKey EXCEPT ![WakeCall] = KeyB]
                                /\ callAuthority' = [callAuthority EXCEPT ![WakeCall] = authorityEpoch]
                                /\ callBinding' = [callBinding EXCEPT ![WakeCall] = bindingEpoch]
                                /\ continuationState' = [continuationState EXCEPT ![WakeCall] = "Pending"]
                                /\ blockedBy' = [blockedBy EXCEPT ![WakeTask] = WakeCall]
                                /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![WakeCall] = TRUE]
                                /\ freeControlCredits' = freeControlCredits - 1
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, freeWaitCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[RequeueCall] = "ControlCaptured"
                                   /\ callAuthority[RequeueCall] = authorityEpoch
                                   /\ callBinding[RequeueCall] = bindingEpoch
                                /\ LET woken == RequeueWokenFor(
                                                     requeueMode, queueA, bindingEpoch, callBinding) IN
                                     LET moved == RequeueMovedFor(
                                                       requeueMode, queueA, bindingEpoch, callBinding) IN
                                       /\ callState' =          [c \in Calls |->
                                                       IF c = RequeueCall THEN "RequeueCommitted"
                                                       ELSE IF c \in woken THEN "WaitClaimed"
                                                       ELSE callState[c]]
                                       /\ queuedOn' =         [w \in WaitCalls |->
                                                      IF w \in woken THEN NoKey
                                                      ELSE IF w \in moved THEN KeyB
                                                      ELSE queuedOn[w]]
                                       /\ queueA' = queueA \ (woken \cup moved)
                                       /\ queueB' = (queueB \cup moved)
                                       /\ selectedBy' =           [w \in WaitCalls |->
                                                        IF w \in woken THEN RequeueCall ELSE selectedBy[w]]
                                       /\ migrationCount' =               [w \in WaitCalls |->
                                                            IF w \in moved THEN migrationCount[w] + 1
                                                            ELSE migrationCount[w]]
                                       /\ requeueWoken' = woken
                                       /\ requeueMoved' = moved
                                       /\ requeueResult' = Cardinality(woken) + Cardinality(moved)
                                       /\ requeueCommitCount' = requeueCommitCount + 1
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, requeueMode, wakeSelected, wakeResult, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WakeCall] = "ControlCaptured"
                                   /\ callAuthority[WakeCall] = authorityEpoch
                                   /\ callBinding[WakeCall] = bindingEpoch
                                /\ LET selected == HeadEligible(
                                                       queueB, bindingEpoch, callBinding) IN
                                     /\ callState' =          [c \in Calls |->
                                                     IF c = WakeCall THEN "WakeCommitted"
                                                     ELSE IF c \in selected THEN "WaitClaimed"
                                                     ELSE callState[c]]
                                     /\ queuedOn' =         [w \in WaitCalls |->
                                                    IF w \in selected THEN NoKey ELSE queuedOn[w]]
                                     /\ queueB' = queueB \ selected
                                     /\ selectedBy' =           [w \in WaitCalls |->
                                                      IF w \in selected THEN WakeCall ELSE selectedBy[w]]
                                     /\ wakeSelected' = selected
                                     /\ wakeResult' = Cardinality(selected)
                                     /\ wakeCommitCount' = wakeCommitCount + 1
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queueA, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, requeueCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ bindingEpoch < MaxBinding
                                /\ bindingEpoch' = bindingEpoch + 1
                                /\ recoveryRevision' = recoveryRevision + 1
                                /\ serviceAlive' = FALSE
                                /\ replacementState' = "None"
                                /\ fallbackState' = "Required"
                                /\ snapshotState' = "Absent"
                                /\ snapshotAuthority' = NoEpoch
                                /\ snapshotBinding' = NoBinding
                                /\ snapshotRevision' = NoRevision
                                /\ recoveryCohort' = {c \in Calls : callState[c] \in LiveCallStates}
                                /\ IF {c \in Calls : callState[c] \in LiveCallStates} # {}
                                      THEN /\ timerCreditHeld' = TRUE
                                           /\ freeTimerCredits' = freeTimerCredits - 1
                                      ELSE /\ TRUE
                                           /\ UNCHANGED << timerCreditHeld, freeTimerCredits >>
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, adoptCount, rejectCount, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "None"
                                /\ snapshotState' = "Captured"
                                /\ snapshotAuthority' = authorityEpoch
                                /\ snapshotBinding' = bindingEpoch
                                /\ snapshotRevision' = recoveryRevision
                                /\ snapshotCallState' = callState
                                /\ snapshotQueuedOn' = queuedOn
                                /\ snapshotQueueA' = queueA
                                /\ snapshotQueueB' = queueB
                                /\ snapshotRequeueWoken' = requeueWoken
                                /\ snapshotRequeueMoved' = requeueMoved
                                /\ snapshotRequeueResult' = requeueResult
                                /\ snapshotWakeSelected' = wakeSelected
                                /\ snapshotWakeResult' = wakeResult
                                /\ snapshotMigrationCount' = migrationCount
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "None"
                                   /\ snapshotState = "Captured"
                                   /\ snapshotAuthority = authorityEpoch
                                   /\ snapshotBinding = bindingEpoch
                                   /\ snapshotRevision = recoveryRevision
                                   /\ snapshotCallState = callState
                                   /\ snapshotQueuedOn = queuedOn
                                   /\ snapshotQueueA = queueA
                                   /\ snapshotQueueB = queueB
                                   /\ snapshotRequeueWoken = requeueWoken
                                   /\ snapshotRequeueMoved = requeueMoved
                                   /\ snapshotRequeueResult = requeueResult
                                   /\ snapshotWakeSelected = wakeSelected
                                   /\ snapshotWakeResult = wakeResult
                                   /\ snapshotMigrationCount = migrationCount
                                /\ replacementState' = "Ready"
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, fallbackState, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "Ready"
                                   /\ snapshotState = "Captured"
                                   /\ snapshotRevision = recoveryRevision
                                   /\ snapshotCallState = callState
                                   /\ snapshotQueuedOn = queuedOn
                                   /\ snapshotQueueA = queueA
                                   /\ snapshotQueueB = queueB
                                   /\ snapshotRequeueWoken = requeueWoken
                                   /\ snapshotRequeueMoved = requeueMoved
                                   /\ snapshotRequeueResult = requeueResult
                                   /\ snapshotWakeSelected = wakeSelected
                                   /\ snapshotWakeResult = wakeResult
                                   /\ snapshotMigrationCount = migrationCount
                                /\ serviceAlive' = TRUE
                                /\ replacementState' = "Bound"
                                /\ fallbackState' = "Standby"
                                /\ snapshotState' = "Absent"
                                /\ snapshotAuthority' = NoEpoch
                                /\ snapshotBinding' = NoBinding
                                /\ snapshotRevision' = NoRevision
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, bindingEpoch, recoveryRevision, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ \E c \in Calls:
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ callState[c] \in LiveCallStates
                                        /\ callAuthority[c] = authorityEpoch
                                        /\ callBinding[c] # bindingEpoch
                                     /\ callBinding' = [callBinding EXCEPT ![c] = bindingEpoch]
                                     /\ adoptCount' = [adoptCount EXCEPT ![c] = adoptCount[c] + 1]
                                     /\ recoveryCohort' = recoveryCohort \ {c}
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, callState, operation, callTask, originKey, callAuthority, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, rejectCount, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ \E c \in Calls:
                                     \E presentedBinding \in 0..MaxBinding:
                                       /\ /\ EnableRejects
                                          /\ callState[c] \in LiveCallStates
                                          /\ rejectCount[c] = 0
                                          /\ presentedBinding # callBinding[c]
                                       /\ rejectCount' = [rejectCount EXCEPT ![c] = 1]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, recoveryCohort, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                             \/ /\ scopeState = "Active"
                                /\ liveAtClose' = {c \in Calls : callState[c] \in LiveCallStates}
                                /\ committedAtClose' = {c \in Calls : callState[c] \in CommittedCallStates}
                                /\ requeueCommitAtClose' = requeueCommitCount
                                /\ wakeCommitAtClose' = wakeCommitCount
                                /\ migrationAtClose' = migrationCount
                                /\ adoptAtClose' = adoptCount
                                /\ closureTargetCount' = Cardinality({c \in Calls : callState[c] \in LiveCallStates})
                                /\ closureSteps' = 0
                                /\ closingEpoch' = authorityEpoch
                                /\ authorityEpoch' = authorityEpoch + 1
                                /\ scopeState' = "Closing"
                                /\ serviceAlive' = FALSE
                                /\ replacementState' = "Closed"
                                /\ fallbackState' = "Closed"
                                /\ snapshotState' = "Absent"
                                /\ UNCHANGED <<bindingEpoch, recoveryRevision, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, adoptCount, rejectCount, recoveryCohort, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount>>
                          /\ UNCHANGED << terminalCount, publicationCount, abortCount, watchdogExpiredSeen >>

KernelFallback == /\ fallbackState = "Required"
                  /\ fallbackState' = "Running"
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, callState, operation, callTask, originKey, callAuthority, callBinding, continuationState, blockedBy, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, terminalCount, publicationCount, abortCount, adoptCount, rejectCount, recoveryCohort, watchdogExpiredSeen, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps >>

KernelPublish == /\ \E c \in ControlCalls:
                      /\ /\ callState[c] \in {"RequeueCommitted", "WakeCommitted"}
                         /\ scopeState \in {"Active", "Closing"}
                      /\ IF c = RequeueCall
                            THEN /\ IF requeueWoken # {}
                                       THEN /\ \E w \in requeueWoken:
                                                 /\ callState' =          [callState EXCEPT
                                                                 ![RequeueCall] = "Completed", ![w] = "Completed"]
                                                 /\ continuationState' =                  [continuationState EXCEPT
                                                                         ![RequeueCall] = "Delivered", ![w] = "Delivered"]
                                                 /\ terminalCount' =              [terminalCount EXCEPT
                                                                     ![RequeueCall] = @ + 1, ![w] = @ + 1]
                                                 /\ publicationCount' =                 [publicationCount EXCEPT
                                                                        ![RequeueCall] = @ + 1, ![w] = @ + 1]
                                                 /\ blockedBy' =          [blockedBy EXCEPT
                                                                 ![RequeueTask] = NoCall, ![callTask[w]] = NoCall]
                                                 /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![RequeueCall] = FALSE]
                                                 /\ waitCreditHeld' = [waitCreditHeld EXCEPT ![w] = FALSE]
                                                 /\ freeControlCredits' = freeControlCredits + 1
                                                 /\ freeWaitCredits' = freeWaitCredits + 1
                                                 /\ recoveryCohort' = recoveryCohort \ {RequeueCall, w}
                                       ELSE /\ callState' = [callState EXCEPT ![RequeueCall] = "Completed"]
                                            /\ continuationState' = [continuationState EXCEPT ![RequeueCall] = "Delivered"]
                                            /\ terminalCount' = [terminalCount EXCEPT ![RequeueCall] = terminalCount[RequeueCall] + 1]
                                            /\ publicationCount' = [publicationCount EXCEPT ![RequeueCall] = publicationCount[RequeueCall] + 1]
                                            /\ blockedBy' = [blockedBy EXCEPT ![RequeueTask] = NoCall]
                                            /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![RequeueCall] = FALSE]
                                            /\ freeControlCredits' = freeControlCredits + 1
                                            /\ recoveryCohort' = recoveryCohort \ {RequeueCall}
                                            /\ UNCHANGED << waitCreditHeld, freeWaitCredits >>
                                 /\ IF scopeState = "Closing"
                                       THEN /\ closureSteps' = closureSteps + 1 + Cardinality(requeueWoken)
                                       ELSE /\ TRUE
                                            /\ UNCHANGED closureSteps
                            ELSE /\ IF wakeSelected # {}
                                       THEN /\ \E w \in wakeSelected:
                                                 /\ callState' =          [callState EXCEPT
                                                                 ![WakeCall] = "Completed", ![w] = "Completed"]
                                                 /\ continuationState' =                  [continuationState EXCEPT
                                                                         ![WakeCall] = "Delivered", ![w] = "Delivered"]
                                                 /\ terminalCount' =              [terminalCount EXCEPT
                                                                     ![WakeCall] = @ + 1, ![w] = @ + 1]
                                                 /\ publicationCount' =                 [publicationCount EXCEPT
                                                                        ![WakeCall] = @ + 1, ![w] = @ + 1]
                                                 /\ blockedBy' =          [blockedBy EXCEPT
                                                                 ![WakeTask] = NoCall, ![callTask[w]] = NoCall]
                                                 /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![WakeCall] = FALSE]
                                                 /\ waitCreditHeld' = [waitCreditHeld EXCEPT ![w] = FALSE]
                                                 /\ freeControlCredits' = freeControlCredits + 1
                                                 /\ freeWaitCredits' = freeWaitCredits + 1
                                                 /\ recoveryCohort' = recoveryCohort \ {WakeCall, w}
                                       ELSE /\ callState' = [callState EXCEPT ![WakeCall] = "Completed"]
                                            /\ continuationState' = [continuationState EXCEPT ![WakeCall] = "Delivered"]
                                            /\ terminalCount' = [terminalCount EXCEPT ![WakeCall] = terminalCount[WakeCall] + 1]
                                            /\ publicationCount' = [publicationCount EXCEPT ![WakeCall] = publicationCount[WakeCall] + 1]
                                            /\ blockedBy' = [blockedBy EXCEPT ![WakeTask] = NoCall]
                                            /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![WakeCall] = FALSE]
                                            /\ freeControlCredits' = freeControlCredits + 1
                                            /\ recoveryCohort' = recoveryCohort \ {WakeCall}
                                            /\ UNCHANGED << waitCreditHeld, freeWaitCredits >>
                                 /\ IF scopeState = "Closing"
                                       THEN /\ closureSteps' = closureSteps + 1 + Cardinality(wakeSelected)
                                       ELSE /\ TRUE
                                            /\ UNCHANGED closureSteps
                      /\ IF ~serviceAlive /\ scopeState = "Active"
                            THEN /\ recoveryRevision' = recoveryRevision + 1
                                 /\ IF replacementState = "Ready"
                                       THEN /\ replacementState' = "None"
                                       ELSE /\ TRUE
                                            /\ UNCHANGED replacementState
                            ELSE /\ TRUE
                                 /\ UNCHANGED << recoveryRevision, replacementState >>
                 /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, operation, callTask, originKey, callAuthority, callBinding, queuedOn, queueA, queueB, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, timerCreditHeld, freeTimerCredits, abortCount, adoptCount, rejectCount, watchdogExpiredSeen, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount >>

KernelClosure == /\ \/ /\ /\ scopeState = "Active"
                          /\ timerCreditHeld
                          /\ recoveryCohort = {}
                       /\ timerCreditHeld' = FALSE
                       /\ freeTimerCredits' = freeTimerCredits + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, callState, continuationState, blockedBy, queuedOn, queueA, queueB, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, terminalCount, abortCount, recoveryCohort, watchdogExpiredSeen, snapshotState, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                    \/ /\ /\ scopeState = "Active"
                          /\ timerCreditHeld
                          /\ recoveryCohort # {}
                       /\ liveAtClose' = {c \in Calls : callState[c] \in LiveCallStates}
                       /\ committedAtClose' = {c \in Calls : callState[c] \in CommittedCallStates}
                       /\ requeueCommitAtClose' = requeueCommitCount
                       /\ wakeCommitAtClose' = wakeCommitCount
                       /\ migrationAtClose' = migrationCount
                       /\ adoptAtClose' = adoptCount
                       /\ closureTargetCount' = Cardinality({c \in Calls : callState[c] \in LiveCallStates})
                       /\ closureSteps' = 0
                       /\ closingEpoch' = authorityEpoch
                       /\ authorityEpoch' = authorityEpoch + 1
                       /\ scopeState' = "Closing"
                       /\ serviceAlive' = FALSE
                       /\ replacementState' = "Closed"
                       /\ fallbackState' = "Closed"
                       /\ snapshotState' = "Absent"
                       /\ watchdogExpiredSeen' = TRUE
                       /\ UNCHANGED <<callState, continuationState, blockedBy, queuedOn, queueA, queueB, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, terminalCount, abortCount, recoveryCohort>>
                    \/ /\ \E c \in Calls:
                            /\ /\ scopeState = "Closing"
                               /\ callAuthority[c] = closingEpoch
                               /\ callState[c] \in LiveCallStates
                               /\ callState[c] \notin {"WaitClaimed", "RequeueCommitted", "WakeCommitted"}
                            /\ IF c \in WaitCalls
                                  THEN /\ IF queuedOn[c] = KeyA
                                             THEN /\ queueA' = queueA \ {c}
                                             ELSE /\ TRUE
                                                  /\ UNCHANGED queueA
                                       /\ IF queuedOn[c] = KeyB
                                             THEN /\ queueB' = queueB \ {c}
                                             ELSE /\ TRUE
                                                  /\ UNCHANGED queueB
                                       /\ queuedOn' = [queuedOn EXCEPT ![c] = NoKey]
                                       /\ waitCreditHeld' = [waitCreditHeld EXCEPT ![c] = FALSE]
                                       /\ freeWaitCredits' = freeWaitCredits + 1
                                       /\ UNCHANGED << controlCreditHeld, freeControlCredits >>
                                  ELSE /\ controlCreditHeld' = [controlCreditHeld EXCEPT ![c] = FALSE]
                                       /\ freeControlCredits' = freeControlCredits + 1
                                       /\ UNCHANGED << queuedOn, queueA, queueB, waitCreditHeld, freeWaitCredits >>
                            /\ callState' = [callState EXCEPT ![c] = "Aborted"]
                            /\ continuationState' = [continuationState EXCEPT ![c] = "Aborted"]
                            /\ terminalCount' = [terminalCount EXCEPT ![c] = terminalCount[c] + 1]
                            /\ abortCount' = [abortCount EXCEPT ![c] = abortCount[c] + 1]
                            /\ blockedBy' = [blockedBy EXCEPT ![callTask[c]] = NoCall]
                            /\ recoveryCohort' = recoveryCohort \ {c}
                            /\ closureSteps' = closureSteps + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, timerCreditHeld, freeTimerCredits, watchdogExpiredSeen, snapshotState, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ timerCreditHeld
                          /\ recoveryCohort = {}
                       /\ timerCreditHeld' = FALSE
                       /\ freeTimerCredits' = freeTimerCredits + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, callState, continuationState, blockedBy, queuedOn, queueA, queueB, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, terminalCount, abortCount, recoveryCohort, watchdogExpiredSeen, snapshotState, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ {c \in Calls : callState[c] \in LiveCallStates} = {}
                          /\ ~timerCreditHeld
                          /\ closureSteps = closureTargetCount
                       /\ scopeState' = "Revoked"
                       /\ UNCHANGED <<authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, callState, continuationState, blockedBy, queuedOn, queueA, queueB, waitCreditHeld, controlCreditHeld, freeWaitCredits, freeControlCredits, timerCreditHeld, freeTimerCredits, terminalCount, abortCount, recoveryCohort, watchdogExpiredSeen, snapshotState, liveAtClose, committedAtClose, requeueCommitAtClose, wakeCommitAtClose, migrationAtClose, adoptAtClose, closureTargetCount, closureSteps>>
                 /\ UNCHANGED << bindingEpoch, recoveryRevision, operation, callTask, originKey, callAuthority, callBinding, selectedBy, migrationCount, requeueMode, requeueWoken, requeueMoved, requeueResult, wakeSelected, wakeResult, requeueCommitCount, wakeCommitCount, publicationCount, adoptCount, rejectCount, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotCallState, snapshotQueuedOn, snapshotQueueA, snapshotQueueB, snapshotRequeueWoken, snapshotRequeueMoved, snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult, snapshotMigrationCount >>

Next == PersonalityEnvironment \/ KernelFallback \/ KernelPublish \/ KernelClosure

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(KernelFallback)
        /\ WF_vars(KernelPublish)
        /\ WF_vars(KernelClosure)

\* END TRANSLATION

CurrentLiveCalls == {c \in Calls : callState[c] \in LiveCallStates}

TypeOK ==
    /\ scopeState \in ScopeStates
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ serviceAlive \in BOOLEAN
    /\ bindingEpoch \in 0..MaxBinding
    /\ recoveryRevision \in Nat
    /\ replacementState \in ReplacementStates
    /\ fallbackState \in FallbackStates
    /\ callState \in [Calls -> CallStates]
    /\ operation \in [Calls -> Operations]
    /\ callTask \in [Calls -> ({NoTask} \cup Tasks)]
    /\ originKey \in [Calls -> ({NoKey} \cup Keys)]
    /\ callAuthority \in [Calls -> {NoEpoch, 0}]
    /\ callBinding \in [Calls -> ({NoBinding} \cup (0..MaxBinding))]
    /\ continuationState \in [Calls -> ContinuationStates]
    /\ blockedBy \in [Tasks -> ({NoCall} \cup Calls)]
    /\ queuedOn \in [WaitCalls -> ({NoKey} \cup Keys)]
    /\ queueA \subseteq WaitCalls
    /\ queueB \subseteq WaitCalls
    /\ selectedBy \in [WaitCalls -> ({NoCall} \cup ControlCalls)]
    /\ migrationCount \in [WaitCalls -> 0..1]
    /\ requeueMode \in RequeueModes
    /\ requeueWoken \subseteq WaitCalls
    /\ requeueMoved \subseteq WaitCalls
    /\ requeueResult \in {NoResult, 0, 1, 2}
    /\ wakeSelected \subseteq WaitCalls
    /\ wakeResult \in {NoResult, 0, 1}
    /\ requeueCommitCount \in 0..1
    /\ wakeCommitCount \in 0..1
    /\ waitCreditHeld \in [WaitCalls -> BOOLEAN]
    /\ controlCreditHeld \in [ControlCalls -> BOOLEAN]
    /\ freeWaitCredits \in 0..2
    /\ freeControlCredits \in 0..2
    /\ timerCreditHeld \in BOOLEAN
    /\ freeTimerCredits \in 0..1
    /\ terminalCount \in [Calls -> 0..1]
    /\ publicationCount \in [Calls -> 0..1]
    /\ abortCount \in [Calls -> 0..1]
    /\ adoptCount \in [Calls -> 0..1]
    /\ rejectCount \in [Calls -> 0..1]
    /\ recoveryCohort \subseteq Calls
    /\ watchdogExpiredSeen \in BOOLEAN
    /\ snapshotState \in SnapshotStates
    /\ snapshotAuthority \in {NoEpoch, 0}
    /\ snapshotBinding \in {NoBinding, 0, 1}
    /\ snapshotRevision \in ({NoRevision} \cup Nat)
    /\ snapshotCallState \in [Calls -> CallStates]
    /\ snapshotQueuedOn \in [WaitCalls -> ({NoKey} \cup Keys)]
    /\ snapshotQueueA \subseteq WaitCalls
    /\ snapshotQueueB \subseteq WaitCalls
    /\ snapshotRequeueWoken \subseteq WaitCalls
    /\ snapshotRequeueMoved \subseteq WaitCalls
    /\ snapshotRequeueResult \in {NoResult, 0, 1, 2}
    /\ snapshotWakeSelected \subseteq WaitCalls
    /\ snapshotWakeResult \in {NoResult, 0, 1}
    /\ snapshotMigrationCount \in [WaitCalls -> 0..1]
    /\ liveAtClose \subseteq Calls
    /\ committedAtClose \subseteq liveAtClose
    /\ requeueCommitAtClose \in 0..1
    /\ wakeCommitAtClose \in 0..1
    /\ migrationAtClose \in [WaitCalls -> 0..1]
    /\ adoptAtClose \in [Calls -> 0..1]
    /\ closureTargetCount \in 0..Cardinality(Calls)
    /\ closureSteps \in 0..Cardinality(Calls)

IdentityConsistency ==
    /\ \A w \in WaitCalls :
           callState[w] # "Unused"
             => /\ operation[w] = "Wait"
                /\ originKey[w] = KeyA
                /\ callAuthority[w] = 0
                /\ callBinding[w] \in 0..MaxBinding
    /\ (callState[RequeueCall] # "Unused"
          => /\ operation[RequeueCall] = "Requeue"
             /\ originKey[RequeueCall] = KeyA)
    /\ (callState[WakeCall] # "Unused"
          => /\ operation[WakeCall] = "Wake"
             /\ originKey[WakeCall] = KeyB)

QueuePartitionExactness ==
    /\ queueA \cap queueB = {}
    /\ \A w \in WaitCalls :
           /\ (w \in queueA <=> /\ callState[w] = "WaitQueued"
                                  /\ queuedOn[w] = KeyA)
           /\ (w \in queueB <=> /\ callState[w] = "WaitQueued"
                                  /\ queuedOn[w] = KeyB)
           /\ (callState[w] = "WaitClaimed"
                 => /\ queuedOn[w] = NoKey
                    /\ selectedBy[w] \in ControlCalls)
           /\ (callState[w] \in TerminalCallStates => queuedOn[w] = NoKey)

FrozenRequeueReceipt ==
    /\ requeueWoken \cap requeueMoved = {}
    /\ (requeueCommitCount = 0
          => /\ requeueWoken = {}
             /\ requeueMoved = {}
             /\ requeueResult = NoResult)
    /\ (requeueCommitCount = 1
          => /\ requeueResult = Cardinality(requeueWoken) + Cardinality(requeueMoved)
             /\ Cardinality(requeueWoken) <= 1
             /\ Cardinality(requeueMoved) <= 1
             /\ \A w \in requeueWoken :
                    /\ selectedBy[w] = RequeueCall
                       \/ callState[w] = "Completed"
             /\ \A w \in requeueMoved : migrationCount[w] = 1)
    /\ (wakeCommitCount = 0 => /\ wakeSelected = {} /\ wakeResult = NoResult)
    /\ (wakeCommitCount = 1
          => /\ wakeResult = Cardinality(wakeSelected)
             /\ Cardinality(wakeSelected) <= 1
             /\ \A w \in wakeSelected : selectedBy[w] = WakeCall)

MigrationIdentityPreservation ==
    \A w \in requeueMoved :
        /\ operation[w] = "Wait"
        /\ originKey[w] = KeyA
        /\ waitCreditHeld[w] \/ callState[w] \in TerminalCallStates
        /\ (callState[w] = "WaitQueued" => /\ queuedOn[w] = KeyB /\ w \in queueB)

SingleTerminalization ==
    \A c \in Calls :
        /\ terminalCount[c] \in {0, 1}
        /\ (callState[c] \in TerminalCallStates <=> terminalCount[c] = 1)
        /\ (callState[c] = "Completed"
              => /\ continuationState[c] = "Delivered"
                 /\ publicationCount[c] = 1
                 /\ abortCount[c] = 0)
        /\ (callState[c] = "Aborted"
              => /\ continuationState[c] = "Aborted"
                 /\ publicationCount[c] = 0
                 /\ abortCount[c] = 1)

BudgetConservation ==
    /\ freeWaitCredits + Cardinality({w \in WaitCalls : waitCreditHeld[w]}) = 2
    /\ freeControlCredits
         + Cardinality({c \in ControlCalls : controlCreditHeld[c]}) = 2
    /\ freeTimerCredits + (IF timerCreditHeld THEN 1 ELSE 0) = 1

RecoveryCohortConsistency ==
    /\ recoveryCohort \subseteq CurrentLiveCalls
    /\ \A c \in recoveryCohort : callBinding[c] < bindingEpoch

SnapshotDiscipline ==
    /\ (serviceAlive <=> replacementState = "Bound")
    /\ (snapshotState = "Captured"
          => /\ scopeState = "Active"
             /\ ~serviceAlive
             /\ snapshotAuthority = authorityEpoch
             /\ snapshotBinding = bindingEpoch
             /\ snapshotRevision <= recoveryRevision
             /\ (snapshotRevision = recoveryRevision
                   => /\ snapshotCallState = callState
                      /\ snapshotQueuedOn = queuedOn
                      /\ snapshotQueueA = queueA
                      /\ snapshotQueueB = queueB
                      /\ snapshotRequeueWoken = requeueWoken
                      /\ snapshotRequeueMoved = requeueMoved
                      /\ snapshotRequeueResult = requeueResult
                      /\ snapshotWakeSelected = wakeSelected
                      /\ snapshotWakeResult = wakeResult
                      /\ snapshotMigrationCount = migrationCount))
    /\ (replacementState = "Ready" => snapshotRevision = recoveryRevision)

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"}
      => /\ requeueCommitCount = requeueCommitAtClose
         /\ wakeCommitCount = wakeCommitAtClose
         /\ migrationCount = migrationAtClose
         /\ adoptCount = adoptAtClose

ClosureAccounting ==
    /\ closureSteps <= closureTargetCount
    /\ (scopeState \in {"Closing", "Revoked"}
          => closureSteps + Cardinality(CurrentLiveCalls) = closureTargetCount)

RevokeRaceOutcome ==
    scopeState = "Revoked"
      => /\ \A c \in committedAtClose : callState[c] = "Completed"
         /\ \A c \in liveAtClose \ committedAtClose : callState[c] = "Aborted"

QuiescentClosure ==
    scopeState = "Revoked"
      => /\ CurrentLiveCalls = {}
         /\ queueA = {}
         /\ queueB = {}
         /\ freeWaitCredits = 2
         /\ freeControlCredits = 2
         /\ freeTimerCredits = 1
         /\ ~timerCreditHeld

RejectSideEffectFreedom ==
    [][rejectCount' # rejectCount
       => UNCHANGED <<
            scopeState, authorityEpoch, closingEpoch, serviceAlive,
            bindingEpoch, recoveryRevision, replacementState, fallbackState,
            callState, operation, callTask, originKey, callAuthority,
            callBinding, continuationState, blockedBy, queuedOn, queueA,
            queueB, selectedBy, migrationCount, requeueMode, requeueWoken,
            requeueMoved, requeueResult, wakeSelected, wakeResult,
            requeueCommitCount, wakeCommitCount, waitCreditHeld,
            controlCreditHeld, freeWaitCredits, freeControlCredits,
            timerCreditHeld, freeTimerCredits, terminalCount,
            publicationCount, abortCount, adoptCount, recoveryCohort,
            watchdogExpiredSeen, snapshotState, snapshotAuthority,
            snapshotBinding, snapshotRevision, snapshotCallState,
            snapshotQueuedOn, snapshotQueueA, snapshotQueueB,
            snapshotRequeueWoken, snapshotRequeueMoved,
            snapshotRequeueResult, snapshotWakeSelected, snapshotWakeResult,
            snapshotMigrationCount, liveAtClose, committedAtClose,
            requeueCommitAtClose, wakeCommitAtClose, migrationAtClose,
            adoptAtClose, closureTargetCount, closureSteps
          >>]_vars

CurrentBindingSelection ==
    [][
        /\ (requeueCommitCount' = requeueCommitCount + 1
              => \A w \in requeueWoken' \cup requeueMoved' :
                    callBinding[w] = bindingEpoch)
        /\ (wakeCommitCount' = wakeCommitCount + 1
              => \A w \in wakeSelected' : callBinding[w] = bindingEpoch)
    ]_vars

AdoptPreservesFutexState ==
    [][adoptCount' # adoptCount
       => UNCHANGED <<
            scopeState, authorityEpoch, closingEpoch, serviceAlive,
            bindingEpoch, recoveryRevision, replacementState, fallbackState,
            callState, operation, callTask, originKey, callAuthority,
            continuationState, blockedBy, queuedOn, queueA, queueB,
            selectedBy, migrationCount, requeueMode, requeueWoken,
            requeueMoved, requeueResult, wakeSelected, wakeResult,
            requeueCommitCount, wakeCommitCount, waitCreditHeld,
            controlCreditHeld, freeWaitCredits, freeControlCredits,
            timerCreditHeld, freeTimerCredits, terminalCount,
            publicationCount, abortCount
          >>]_vars

FallbackProgress ==
    (fallbackState = "Required")
      ~> (fallbackState = "Running" \/ fallbackState = "Closed")

CommittedPublicationProgress ==
    /\ (callState[RequeueCall] = "RequeueCommitted")
         ~> (callState[RequeueCall] = "Completed" \/ scopeState = "Revoked")
    /\ (callState[WakeCall] = "WakeCommitted")
         ~> (callState[WakeCall] = "Completed" \/ scopeState = "Revoked")

RevocationProgress ==
    (scopeState = "Closing") ~> (scopeState = "Revoked")

TwoAffectedObserved ==
    /\ requeueCommitCount = 1
    /\ requeueResult = 2
    /\ Cardinality(requeueWoken) = 1
    /\ Cardinality(requeueMoved) = 1

MoveOnlyObserved ==
    /\ requeueCommitCount = 1
    /\ requeueMode = "MoveOnly"
    /\ requeueResult = 1
    /\ requeueWoken = {}
    /\ Cardinality(requeueMoved) = 1

CurrentBindingFenceObserved ==
    /\ bindingEpoch = 1
    /\ requeueCommitCount = 1
    /\ requeueResult = 0
    /\ Wait1 \in queueA
    /\ callBinding[Wait1] = 0
    /\ Wait2 \in queueA
    /\ callBinding[Wait2] = bindingEpoch

CommitBeforeRevokeObserved ==
    /\ scopeState = "Revoked"
    /\ requeueCommitAtClose = 1
    /\ requeueResult = 2
    /\ \A w \in requeueWoken : callState[w] = "Completed"
    /\ \A w \in requeueMoved : callState[w] = "Aborted"

RevokeBeforeCommitObserved ==
    /\ scopeState = "Revoked"
    /\ requeueCommitAtClose = 0
    /\ callState[RequeueCall] = "Aborted"

TargetWakeObserved ==
    /\ wakeCommitCount = 1
    /\ wakeResult = 1
    /\ wakeSelected \subseteq requeueMoved

TwoAffectedAbsent == ~TwoAffectedObserved
MoveOnlyAbsent == ~MoveOnlyObserved
CurrentBindingFenceAbsent == ~CurrentBindingFenceObserved
CommitBeforeRevokeAbsent == ~CommitBeforeRevokeObserved
RevokeBeforeCommitAbsent == ~RevokeBeforeCommitObserved
TargetWakeAbsent == ~TargetWakeObserved

=============================================================================

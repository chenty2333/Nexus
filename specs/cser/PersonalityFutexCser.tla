--------------------- MODULE PersonalityFutexCser ---------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Stage 6B.1 successor refinement for one restartable Linux personality.  *)
(*                                                                         *)
(* The model has exactly one private futex key, one wait syscall, and one   *)
(* wake syscall with max_wake = 1.  A wait registration is the atomic       *)
(* compare-and-enqueue abstraction.  WakeCommit atomically fixes the        *)
(* selected waiter and return count; KernelWakePublish is the later         *)
(* one-shot task-state publication.                                         *)
(*                                                                         *)
(* The recovery watchdog protects only an orphaned personality-recovery     *)
(* cohort.  Explicit adoption may cancel it while a no-timeout futex wait   *)
(* remains registered.  Expiry closes authority and starts CSER closure; it *)
(* never produces Linux ETIMEDOUT.                                          *)
(*                                                                         *)
(* The PlusCal algorithm is the sole source of Init and Next.               *)
(***************************************************************************)

CONSTANTS
    Scope,
    WaitCall,
    WakeCall,
    WaitTask,
    WakeTask,
    PrivateKey,
    MaxBinding,
    MaxAttempts,
    InitialWaitCredits,
    InitialWakeCredits,
    InitialTimerCredits,
    EnableRejects

Calls == {WaitCall, WakeCall}
Tasks == {WaitTask, WakeTask}

ASSUME /\ WaitCall # WakeCall
       /\ WaitTask # WakeTask
       /\ MaxBinding \in Nat
       /\ MaxBinding > 0
       /\ MaxAttempts \in Nat
       /\ MaxAttempts > 1
       /\ InitialWaitCredits = 1
       /\ InitialWakeCredits = 1
       /\ InitialTimerCredits = 1
       /\ EnableRejects \in BOOLEAN

ScopeStates == {"Active", "Closing", "Revoked"}
CallStates == {
    "Unused", "Captured", "ReplyPrepared", "WaitRegistered",
    "WaitCommitted", "WakeCommitted", "Completed", "Aborted"
}
LiveCallStates == {
    "Captured", "ReplyPrepared", "WaitRegistered",
    "WaitCommitted", "WakeCommitted"
}
CommittedCallStates == {"WaitCommitted", "WakeCommitted"}
TerminalCallStates == {"Completed", "Aborted"}
Operations == {"None", "Wait", "Wake"}
ContinuationStates == {"Absent", "Pending", "Replied", "Aborted"}
PreparedReplies == {
    "None", "WaitEagain", "WaitWoken", "WakeCount0", "WakeCount1"
}
FallbackStates == {"Standby", "Required", "Running", "Closed"}
ReplacementStates == {"None", "Ready", "Bound", "Closed"}
SnapshotStates == {"Absent", "Captured"}
WatchdogStates == {"Idle", "Armed", "Expired", "Closing"}
WaitCreditStates == {"None", "Held", "Returned"}
CancelReasonStates == {"None", "ResolvedBeforeExpiry", "ResolvedAfterExpiry"}

NoEpoch == -1
NoBinding == -1
NoRevision == -1
NoResult == -1
NoCall == "NoCall"
NoTask == "NoTask"
NoKey == "NoKey"

(* --algorithm PersonalityFutexCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = NoEpoch,

    serviceAlive = TRUE,
    bindingEpoch = 0,
    recoveryRevision = 0,
    replacementState = "Bound",
    fallbackState = "Standby",

    snapshotState = "Absent",
    snapshotAuthority = NoEpoch,
    snapshotBinding = NoBinding,
    snapshotRevision = NoRevision,
    snapshotLive = {},
    snapshotCallState = [c \in Calls |-> "Unused"],
    snapshotAdoptCount = [c \in Calls |-> 0],
    snapshotQueue = {},
    snapshotSelected = {},
    snapshotResult = NoResult,

    callState = [c \in Calls |-> "Unused"],
    operation = [c \in Calls |-> "None"],
    callTask = [c \in Calls |-> NoTask],
    callKey = [c \in Calls |-> NoKey],
    callAuthority = [c \in Calls |-> NoEpoch],
    callBinding = [c \in Calls |-> NoBinding],
    continuationState = [c \in Calls |-> "Absent"],
    preparedReply = [c \in Calls |-> "None"],
    blockedBy = [t \in Tasks |-> NoCall],

    waitQueue = {},
    waitCreditState = [c \in Calls |-> "None"],
    freeWaitCredits = InitialWaitCredits,

    wakeCreditState = [c \in Calls |-> "None"],
    freeWakeCredits = InitialWakeCredits,

    wakeSelected = {},
    wakeResult = NoResult,
    wakeCommitCount = [c \in Calls |-> 0],
    wakePublicationCount = [c \in Calls |-> 0],
    replyPublicationCount = [c \in Calls |-> 0],
    continuationConsumptionCount = [c \in Calls |-> 0],
    terminalCount = [c \in Calls |-> 0],
    resumeCount = [c \in Calls |-> 0],
    eagainCount = [c \in Calls |-> 0],
    abortCount = [c \in Calls |-> 0],

    rejectCount = [c \in Calls |-> 0],
    lastRejectedPresentedCall = [c \in Calls |-> NoCall],
    adoptCount = [c \in Calls |-> 0],

    watchdogState = "Idle",
    recoveryCohort = {},
    deadlineCohort = {},
    deadlineAuthority = NoEpoch,
    deadlineCrashBinding = NoBinding,
    deadlineCancelReason = "None",
    cancelledCohort = {},
    cancelledCrashBinding = NoBinding,
    timerCreditHeld = FALSE,
    freeTimerCredits = InitialTimerCredits,
    watchdogExpiredSeen = FALSE,
    deadlineCancelledSeen = FALSE,
    timeoutRevokeSeen = FALSE,

    liveAtClose = {},
    committedAtClose = {},
    wakeCommitCountAtClose = [c \in Calls |-> 0],
    adoptCountAtClose = [c \in Calls |-> 0],
    closureTargetCount = 0,
    closureSteps = 0;

process PersonalityEnvironment = "personality-environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* CaptureWait installs the wait task's only live continuation.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WaitCall] = "Unused"
                  /\ blockedBy[WaitTask] = NoCall;
            callState[WaitCall] := "Captured";
            operation[WaitCall] := "Wait";
            callTask[WaitCall] := WaitTask;
            callKey[WaitCall] := PrivateKey;
            callAuthority[WaitCall] := authorityEpoch;
            callBinding[WaitCall] := bindingEpoch;
            continuationState[WaitCall] := "Pending";
            blockedBy[WaitTask] := WaitCall;
        or
            \* CaptureWake installs a distinct wake syscall continuation.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WakeCall] = "Unused"
                  /\ blockedBy[WakeTask] = NoCall
                  /\ freeWakeCredits > 0;
            callState[WakeCall] := "Captured";
            operation[WakeCall] := "Wake";
            callTask[WakeCall] := WakeTask;
            callKey[WakeCall] := PrivateKey;
            callAuthority[WakeCall] := authorityEpoch;
            callBinding[WakeCall] := bindingEpoch;
            continuationState[WakeCall] := "Pending";
            blockedBy[WakeTask] := WakeCall;
            wakeCreditState[WakeCall] := "Held";
            freeWakeCredits := freeWakeCredits - 1;
        or
            \* CompareMismatch is the EAGAIN path.  It neither enters the wait
            \* queue nor reserves the one wait-slot lease credit.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WaitCall] = "Captured"
                  /\ callAuthority[WaitCall] = authorityEpoch
                  /\ callBinding[WaitCall] = bindingEpoch;
            callState[WaitCall] := "ReplyPrepared";
            preparedReply[WaitCall] := "WaitEagain";
        or
            \* WaitRegister is one atomic compare-match + enqueue + credit-hold
            \* transition.  The concrete user-memory and bucket-lock refinement
            \* is outside this finite protocol model.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WaitCall] = "Captured"
                  /\ callAuthority[WaitCall] = authorityEpoch
                  /\ callBinding[WaitCall] = bindingEpoch
                  /\ freeWaitCredits > 0;
            callState[WaitCall] := "WaitRegistered";
            waitQueue := waitQueue \cup {WaitCall};
            waitCreditState[WaitCall] := "Held";
            freeWaitCredits := freeWaitCredits - 1;
        or
            \* WakeCommit is the wake linearization point.  It fixes both the
            \* selected set and the Linux return count.  It publishes no task
            \* state and is atomic with respect to RevokeBegin.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ callState[WakeCall] = "Captured"
                  /\ callAuthority[WakeCall] = authorityEpoch
                  /\ callBinding[WakeCall] = bindingEpoch;
            if /\ callState[WaitCall] = "WaitRegistered"
               /\ WaitCall \in waitQueue
               /\ callAuthority[WaitCall] = authorityEpoch
               /\ callBinding[WaitCall] = bindingEpoch then
                callState := [callState EXCEPT
                    ![WaitCall] = "WaitCommitted",
                    ![WakeCall] = "WakeCommitted"];
                preparedReply := [preparedReply EXCEPT
                    ![WaitCall] = "WaitWoken",
                    ![WakeCall] = "WakeCount1"];
                waitQueue := waitQueue \ {WaitCall};
                wakeSelected := {WaitCall};
                wakeResult := 1;
                wakeCommitCount := [wakeCommitCount EXCEPT
                    ![WaitCall] = @ + 1,
                    ![WakeCall] = @ + 1];
            else
                callState[WakeCall] := "WakeCommitted";
                wakeSelected := {};
                wakeResult := 0;
                preparedReply[WakeCall] := "WakeCount0";
                wakeCommitCount[WakeCall] :=
                    wakeCommitCount[WakeCall] + 1;
            end if;
        or
            \* Reply publishes only the mismatch EAGAIN result.  A committed
            \* wake caller and its selected waiter are terminalized together
            \* by the kernel-owned publication below.
            with c = WaitCall do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ callAuthority[c] = authorityEpoch
                      /\ callBinding[c] = bindingEpoch
                      /\ continuationState[c] = "Pending"
                      /\ callState[c] = "ReplyPrepared"
                      /\ preparedReply[c] = "WaitEagain";
                callState[c] := "Completed";
                continuationState[c] := "Replied";
                replyPublicationCount[c] :=
                    replyPublicationCount[c] + 1;
                continuationConsumptionCount[c] :=
                    continuationConsumptionCount[c] + 1;
                terminalCount[c] := terminalCount[c] + 1;
                resumeCount[c] := resumeCount[c] + 1;
                if c = WaitCall then
                    eagainCount[c] := eagainCount[c] + 1;
                end if;
                blockedBy[callTask[c]] := NoCall;
                recoveryCohort := recoveryCohort \ {c};
            end with;
        or
            \* A rejected full-identity token changes only bounded audit state.
            \* PrivateKey is the only valid key; NoKey is an invalid sentinel.
            with c \in Calls,
                 presentedCall \in Calls,
                 presentedTask \in Tasks,
                 presentedOperation \in {"Wait", "Wake"},
                 presentedKey \in {PrivateKey, NoKey},
                 presentedAuthority \in 0..1,
                 presentedBinding \in 0..MaxBinding do
                await /\ EnableRejects
                      /\ callState[c] \in LiveCallStates
                      /\ rejectCount[c] < MaxAttempts - 1
                      /\ ~( /\ scopeState = "Active"
                            /\ serviceAlive
                            /\ replacementState = "Bound"
                            /\ presentedCall = c
                            /\ presentedTask = callTask[c]
                            /\ presentedOperation = operation[c]
                            /\ presentedKey = callKey[c]
                            /\ presentedAuthority = callAuthority[c]
                            /\ callAuthority[c] = authorityEpoch
                            /\ presentedBinding = callBinding[c]
                            /\ callBinding[c] = bindingEpoch );
                rejectCount[c] := rejectCount[c] + 1;
                lastRejectedPresentedCall[c] := presentedCall;
            end with;
        or
            \* Crash advances only the service binding.  A nonempty orphan
            \* cohort reserves one timer credit and arms the recovery watchdog.
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
            snapshotLive := {};
            snapshotCallState := [c \in Calls |-> "Unused"];
            snapshotAdoptCount := [c \in Calls |-> 0];
            snapshotQueue := {};
            snapshotSelected := {};
            snapshotResult := NoResult;
            recoveryCohort :=
                {c \in Calls : callState[c] \in LiveCallStates};
            if /\ {c \in Calls : callState[c] \in LiveCallStates} # {}
               /\ watchdogState = "Idle" then
                watchdogState := "Armed";
                deadlineCohort :=
                    {c \in Calls : callState[c] \in LiveCallStates};
                deadlineAuthority := authorityEpoch;
                deadlineCrashBinding := bindingEpoch;
                deadlineCancelReason := "None";
                cancelledCohort := {};
                cancelledCrashBinding := NoBinding;
                deadlineCancelledSeen := FALSE;
                timerCreditHeld := TRUE;
                freeTimerCredits := freeTimerCredits - 1;
            end if;
        or
            \* Snapshot records exact futex phases and committed wake data.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ \/ snapshotState = "Absent"
                     \/ /\ snapshotState = "Captured"
                           /\ snapshotRevision < recoveryRevision
                  /\ watchdogState # "Expired";
            snapshotState := "Captured";
            snapshotAuthority := authorityEpoch;
            snapshotBinding := bindingEpoch;
            snapshotRevision := recoveryRevision;
            snapshotLive :=
                {c \in Calls : callState[c] \in LiveCallStates};
            snapshotCallState := callState;
            snapshotAdoptCount := adoptCount;
            snapshotQueue := waitQueue;
            snapshotSelected := wakeSelected;
            snapshotResult := wakeResult;
        or
            \* Ready is accepted only while the exact snapshot is current.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ snapshotState = "Captured"
                  /\ watchdogState # "Expired"
                  /\ snapshotAuthority = authorityEpoch
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotRevision = recoveryRevision
                  /\ snapshotLive =
                        {c \in Calls : callState[c] \in LiveCallStates}
                  /\ snapshotCallState = callState
                  /\ snapshotAdoptCount = adoptCount
                  /\ snapshotQueue = waitQueue
                  /\ snapshotSelected = wakeSelected
                  /\ snapshotResult = wakeResult;
            replacementState := "Ready";
        or
            \* Rebind installs a ready replacement without adopting any call.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready"
                  /\ snapshotState = "Captured"
                  /\ watchdogState # "Expired"
                  /\ snapshotAuthority = authorityEpoch
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotRevision = recoveryRevision
                  /\ snapshotLive =
                        {c \in Calls : callState[c] \in LiveCallStates}
                  /\ snapshotCallState = callState
                  /\ snapshotAdoptCount = adoptCount
                  /\ snapshotQueue = waitQueue
                  /\ snapshotSelected = wakeSelected
                  /\ snapshotResult = wakeResult;
            serviceAlive := TRUE;
            replacementState := "Bound";
            fallbackState := "Standby";
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotRevision := NoRevision;
            snapshotLive := {};
            snapshotCallState := [c \in Calls |-> "Unused"];
            snapshotAdoptCount := [c \in Calls |-> 0];
            snapshotQueue := {};
            snapshotSelected := {};
            snapshotResult := NoResult;
        or
            \* Adopt transfers only binding ownership.  Queue membership,
            \* selected/count data, and credits are preserved.
            with c \in Calls do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ watchdogState # "Expired"
                      /\ callState[c] \in LiveCallStates
                      /\ callAuthority[c] = authorityEpoch
                      /\ callBinding[c] # bindingEpoch;
                callBinding[c] := bindingEpoch;
                adoptCount[c] := adoptCount[c] + 1;
                recoveryCohort := recoveryCohort \ {c};
            end with;
        or
            \* Explicit RevokeBegin and WakeCommit serialize on Active.
            await scopeState = "Active";
            liveAtClose :=
                {c \in Calls : callState[c] \in LiveCallStates};
            committedAtClose :=
                {c \in Calls : callState[c] \in CommittedCallStates};
            wakeCommitCountAtClose := wakeCommitCount;
            adoptCountAtClose := adoptCount;
            closureTargetCount :=
                Cardinality({c \in Calls :
                    callState[c] \in LiveCallStates})
                + (IF timerCreditHeld THEN 1 ELSE 0);
            closureSteps := 0;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "Closed";
            fallbackState := "Closed";
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotRevision := NoRevision;
            snapshotLive := {};
            snapshotCallState := [c \in Calls |-> "Unused"];
            snapshotAdoptCount := [c \in Calls |-> 0];
            snapshotQueue := {};
            snapshotSelected := {};
            snapshotResult := NoResult;
            if timerCreditHeld then
                watchdogState := "Closing";
            else
                watchdogState := "Idle";
            end if;
        end either;
    end while;
end process;

\* Kernel fallback is weakly fair.  Recovery environment actions are not.
fair process KernelFallback = "kernel-fallback"
begin
FallbackLoop:
    while TRUE do
        await fallbackState = "Required";
        fallbackState := "Running";
    end while;
end process;

\* A committed wake result and its selected waiter are published together by
\* the kernel.  The reusable backend waker does not itself provide one-shot
\* authority; callState does.  A count-zero wake completes only WakeCall.
fair process KernelWake = "kernel-wake"
begin
WakeLoop:
    while TRUE do
        await /\ scopeState = "Active"
              /\ callState[WakeCall] = "WakeCommitted"
              /\ continuationState[WakeCall] = "Pending"
              /\ wakeCreditState[WakeCall] = "Held"
              /\ (wakeResult = 0
                    \/ /\ wakeResult = 1
                       /\ callState[WaitCall] = "WaitCommitted"
                       /\ continuationState[WaitCall] = "Pending"
                       /\ waitCreditState[WaitCall] = "Held");
        if wakeResult = 1 then
            callState := [callState EXCEPT
                ![WaitCall] = "Completed",
                ![WakeCall] = "Completed"];
            continuationState := [continuationState EXCEPT
                ![WaitCall] = "Replied",
                ![WakeCall] = "Replied"];
            wakePublicationCount[WaitCall] :=
                wakePublicationCount[WaitCall] + 1;
            replyPublicationCount := [replyPublicationCount EXCEPT
                ![WaitCall] = @ + 1,
                ![WakeCall] = @ + 1];
            continuationConsumptionCount :=
                [continuationConsumptionCount EXCEPT
                    ![WaitCall] = @ + 1,
                    ![WakeCall] = @ + 1];
            terminalCount := [terminalCount EXCEPT
                ![WaitCall] = @ + 1,
                ![WakeCall] = @ + 1];
            resumeCount := [resumeCount EXCEPT
                ![WaitCall] = @ + 1,
                ![WakeCall] = @ + 1];
            waitCreditState[WaitCall] := "Returned";
            freeWaitCredits := freeWaitCredits + 1;
            blockedBy := [blockedBy EXCEPT
                ![WaitTask] = NoCall,
                ![WakeTask] = NoCall];
            recoveryCohort :=
                recoveryCohort \ {WaitCall, WakeCall};
        else
            callState[WakeCall] := "Completed";
            continuationState[WakeCall] := "Replied";
            replyPublicationCount[WakeCall] :=
                replyPublicationCount[WakeCall] + 1;
            continuationConsumptionCount[WakeCall] :=
                continuationConsumptionCount[WakeCall] + 1;
            terminalCount[WakeCall] := terminalCount[WakeCall] + 1;
            resumeCount[WakeCall] := resumeCount[WakeCall] + 1;
            blockedBy[WakeTask] := NoCall;
            recoveryCohort := recoveryCohort \ {WakeCall};
        end if;
        wakeCreditState[WakeCall] := "Returned";
        freeWakeCredits := freeWakeCredits + 1;
        \* A kernel publication after crash makes the prior recovery image
        \* stale.  Preserve that immutable image for audit, advance the
        \* recovery revision, and invalidate Ready until a fresh capture.
        if ~serviceAlive then
            recoveryRevision := recoveryRevision + 1;
            if replacementState = "Ready" then
                replacementState := "None";
            end if;
        end if;
    end while;
end process;

\* This is an abstract CSER recovery edge, never a Linux futex timeout.
fair process KernelWatchdog = "kernel-watchdog"
begin
WatchdogLoop:
    while TRUE do
        await watchdogState = "Armed";
        watchdogState := "Expired";
        watchdogExpiredSeen := TRUE;
    end while;
end process;

\* Kernel closure cancels or expires the recovery deadline, and performs all
\* post-revoke terminalization.  Only this process advances closureSteps.
fair process KernelClosure = "kernel-closure"
begin
ClosureLoop:
    while TRUE do
        either
            \* Successful adoption/terminalization of the entire old-binding
            \* cohort cancels the watchdog even if a wait remains registered.
            await /\ scopeState = "Active"
                  /\ watchdogState = "Armed"
                  /\ recoveryCohort = {}
                  /\ timerCreditHeld;
            watchdogState := "Idle";
            deadlineCancelReason := "ResolvedBeforeExpiry";
            cancelledCohort := deadlineCohort;
            cancelledCrashBinding := deadlineCrashBinding;
            deadlineAuthority := NoEpoch;
            deadlineCrashBinding := NoBinding;
            timerCreditHeld := FALSE;
            freeTimerCredits := freeTimerCredits + 1;
            deadlineCancelledSeen := TRUE;
        or
            \* Expiry with no remaining orphan is completion, not timeout of a
            \* normal registered futex wait.
            await /\ scopeState = "Active"
                  /\ watchdogState = "Expired"
                  /\ recoveryCohort = {}
                  /\ timerCreditHeld;
            watchdogState := "Idle";
            deadlineCancelReason := "ResolvedAfterExpiry";
            cancelledCohort := deadlineCohort;
            cancelledCrashBinding := deadlineCrashBinding;
            deadlineAuthority := NoEpoch;
            deadlineCrashBinding := NoBinding;
            timerCreditHeld := FALSE;
            freeTimerCredits := freeTimerCredits + 1;
            deadlineCancelledSeen := TRUE;
        or
            \* An expired nonempty recovery cohort closes authority.  It does
            \* not prepare or publish an ETIMEDOUT result.
            await /\ scopeState = "Active"
                  /\ watchdogState = "Expired"
                  /\ recoveryCohort # {}
                  /\ timerCreditHeld;
            liveAtClose :=
                {c \in Calls : callState[c] \in LiveCallStates};
            committedAtClose :=
                {c \in Calls : callState[c] \in CommittedCallStates};
            wakeCommitCountAtClose := wakeCommitCount;
            adoptCountAtClose := adoptCount;
            closureTargetCount :=
                Cardinality({c \in Calls :
                    callState[c] \in LiveCallStates}) + 1;
            closureSteps := 0;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "Closed";
            fallbackState := "Closed";
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotRevision := NoRevision;
            snapshotLive := {};
            snapshotCallState := [c \in Calls |-> "Unused"];
            snapshotAdoptCount := [c \in Calls |-> 0];
            snapshotQueue := {};
            snapshotSelected := {};
            snapshotResult := NoResult;
            watchdogState := "Closing";
            timeoutRevokeSeen := TRUE;
        or
            \* A committed wake drains its frozen result and selected waiter
            \* together, accounting for one or two live effects.
            await /\ scopeState = "Closing"
                  /\ callAuthority[WakeCall] = closingEpoch
                  /\ callState[WakeCall] = "WakeCommitted"
                  /\ (wakeResult = 0
                        \/ /\ wakeResult = 1
                           /\ callState[WaitCall] = "WaitCommitted");
            if wakeResult = 1 then
                callState := [callState EXCEPT
                    ![WaitCall] = "Completed",
                    ![WakeCall] = "Completed"];
                continuationState := [continuationState EXCEPT
                    ![WaitCall] = "Replied",
                    ![WakeCall] = "Replied"];
                wakePublicationCount[WaitCall] :=
                    wakePublicationCount[WaitCall] + 1;
                replyPublicationCount := [replyPublicationCount EXCEPT
                    ![WaitCall] = @ + 1,
                    ![WakeCall] = @ + 1];
                continuationConsumptionCount :=
                    [continuationConsumptionCount EXCEPT
                        ![WaitCall] = @ + 1,
                        ![WakeCall] = @ + 1];
                terminalCount := [terminalCount EXCEPT
                    ![WaitCall] = @ + 1,
                    ![WakeCall] = @ + 1];
                resumeCount := [resumeCount EXCEPT
                    ![WaitCall] = @ + 1,
                    ![WakeCall] = @ + 1];
                waitCreditState[WaitCall] := "Returned";
                freeWaitCredits := freeWaitCredits + 1;
                blockedBy := [blockedBy EXCEPT
                    ![WaitTask] = NoCall,
                    ![WakeTask] = NoCall];
                recoveryCohort :=
                    recoveryCohort \ {WaitCall, WakeCall};
                closureSteps := closureSteps + 2;
            else
                callState[WakeCall] := "Completed";
                continuationState[WakeCall] := "Replied";
                replyPublicationCount[WakeCall] :=
                    replyPublicationCount[WakeCall] + 1;
                continuationConsumptionCount[WakeCall] :=
                    continuationConsumptionCount[WakeCall] + 1;
                terminalCount[WakeCall] := terminalCount[WakeCall] + 1;
                resumeCount[WakeCall] := resumeCount[WakeCall] + 1;
                blockedBy[WakeTask] := NoCall;
                recoveryCohort := recoveryCohort \ {WakeCall};
                closureSteps := closureSteps + 1;
            end if;
            wakeCreditState[WakeCall] := "Returned";
            freeWakeCredits := freeWakeCredits + 1;
        or
            \* Every other live call is uncommitted and aborts independently.
            with c \in Calls do
                await /\ scopeState = "Closing"
                      /\ callAuthority[c] = closingEpoch
                      /\ callState[c] \in LiveCallStates
                      /\ callState[c] # "WaitCommitted"
                      /\ callState[c] # "WakeCommitted";
                if /\ c = WaitCall
                   /\ waitCreditState[c] = "Held" then
                    waitQueue := waitQueue \ {c};
                    waitCreditState[c] := "Returned";
                    freeWaitCredits := freeWaitCredits + 1;
                end if;
                if /\ c = WakeCall
                   /\ wakeCreditState[c] = "Held" then
                    wakeCreditState[c] := "Returned";
                    freeWakeCredits := freeWakeCredits + 1;
                end if;
                callState[c] := "Aborted";
                continuationState[c] := "Aborted";
                continuationConsumptionCount[c] :=
                    continuationConsumptionCount[c] + 1;
                terminalCount[c] := terminalCount[c] + 1;
                abortCount[c] := abortCount[c] + 1;
                blockedBy[callTask[c]] := NoCall;
                recoveryCohort := recoveryCohort \ {c};
                closureSteps := closureSteps + 1;
            end with;
        or
            \* The watchdog is a separately budgeted live effect at closure.
            await /\ scopeState = "Closing"
                  /\ watchdogState = "Closing"
                  /\ timerCreditHeld;
            watchdogState := "Idle";
            recoveryCohort := {};
            deadlineAuthority := NoEpoch;
            deadlineCrashBinding := NoBinding;
            timerCreditHeld := FALSE;
            freeTimerCredits := freeTimerCredits + 1;
            closureSteps := closureSteps + 1;
        or
            await /\ scopeState = "Closing"
                  /\ \A c \in Calls :
                         callAuthority[c] = closingEpoch
                         => callState[c] \in TerminalCallStates
                  /\ ~timerCreditHeld
                  /\ closureSteps = closureTargetCount;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "626095a6" /\ chksum(tla) = "9b432aad")
VARIABLES scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, abortCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, watchdogExpiredSeen, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps

vars == << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, abortCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, watchdogExpiredSeen, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps >>

ProcSet == {"personality-environment"} \cup {"kernel-fallback"} \cup {"kernel-wake"} \cup {"kernel-watchdog"} \cup {"kernel-closure"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ serviceAlive = TRUE
        /\ bindingEpoch = 0
        /\ recoveryRevision = 0
        /\ replacementState = "Bound"
        /\ fallbackState = "Standby"
        /\ snapshotState = "Absent"
        /\ snapshotAuthority = NoEpoch
        /\ snapshotBinding = NoBinding
        /\ snapshotRevision = NoRevision
        /\ snapshotLive = {}
        /\ snapshotCallState = [c \in Calls |-> "Unused"]
        /\ snapshotAdoptCount = [c \in Calls |-> 0]
        /\ snapshotQueue = {}
        /\ snapshotSelected = {}
        /\ snapshotResult = NoResult
        /\ callState = [c \in Calls |-> "Unused"]
        /\ operation = [c \in Calls |-> "None"]
        /\ callTask = [c \in Calls |-> NoTask]
        /\ callKey = [c \in Calls |-> NoKey]
        /\ callAuthority = [c \in Calls |-> NoEpoch]
        /\ callBinding = [c \in Calls |-> NoBinding]
        /\ continuationState = [c \in Calls |-> "Absent"]
        /\ preparedReply = [c \in Calls |-> "None"]
        /\ blockedBy = [t \in Tasks |-> NoCall]
        /\ waitQueue = {}
        /\ waitCreditState = [c \in Calls |-> "None"]
        /\ freeWaitCredits = InitialWaitCredits
        /\ wakeCreditState = [c \in Calls |-> "None"]
        /\ freeWakeCredits = InitialWakeCredits
        /\ wakeSelected = {}
        /\ wakeResult = NoResult
        /\ wakeCommitCount = [c \in Calls |-> 0]
        /\ wakePublicationCount = [c \in Calls |-> 0]
        /\ replyPublicationCount = [c \in Calls |-> 0]
        /\ continuationConsumptionCount = [c \in Calls |-> 0]
        /\ terminalCount = [c \in Calls |-> 0]
        /\ resumeCount = [c \in Calls |-> 0]
        /\ eagainCount = [c \in Calls |-> 0]
        /\ abortCount = [c \in Calls |-> 0]
        /\ rejectCount = [c \in Calls |-> 0]
        /\ lastRejectedPresentedCall = [c \in Calls |-> NoCall]
        /\ adoptCount = [c \in Calls |-> 0]
        /\ watchdogState = "Idle"
        /\ recoveryCohort = {}
        /\ deadlineCohort = {}
        /\ deadlineAuthority = NoEpoch
        /\ deadlineCrashBinding = NoBinding
        /\ deadlineCancelReason = "None"
        /\ cancelledCohort = {}
        /\ cancelledCrashBinding = NoBinding
        /\ timerCreditHeld = FALSE
        /\ freeTimerCredits = InitialTimerCredits
        /\ watchdogExpiredSeen = FALSE
        /\ deadlineCancelledSeen = FALSE
        /\ timeoutRevokeSeen = FALSE
        /\ liveAtClose = {}
        /\ committedAtClose = {}
        /\ wakeCommitCountAtClose = [c \in Calls |-> 0]
        /\ adoptCountAtClose = [c \in Calls |-> 0]
        /\ closureTargetCount = 0
        /\ closureSteps = 0

PersonalityEnvironment == /\ \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WaitCall] = "Unused"
                                   /\ blockedBy[WaitTask] = NoCall
                                /\ callState' = [callState EXCEPT ![WaitCall] = "Captured"]
                                /\ operation' = [operation EXCEPT ![WaitCall] = "Wait"]
                                /\ callTask' = [callTask EXCEPT ![WaitCall] = WaitTask]
                                /\ callKey' = [callKey EXCEPT ![WaitCall] = PrivateKey]
                                /\ callAuthority' = [callAuthority EXCEPT ![WaitCall] = authorityEpoch]
                                /\ callBinding' = [callBinding EXCEPT ![WaitCall] = bindingEpoch]
                                /\ continuationState' = [continuationState EXCEPT ![WaitCall] = "Pending"]
                                /\ blockedBy' = [blockedBy EXCEPT ![WaitTask] = WaitCall]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, preparedReply, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WakeCall] = "Unused"
                                   /\ blockedBy[WakeTask] = NoCall
                                   /\ freeWakeCredits > 0
                                /\ callState' = [callState EXCEPT ![WakeCall] = "Captured"]
                                /\ operation' = [operation EXCEPT ![WakeCall] = "Wake"]
                                /\ callTask' = [callTask EXCEPT ![WakeCall] = WakeTask]
                                /\ callKey' = [callKey EXCEPT ![WakeCall] = PrivateKey]
                                /\ callAuthority' = [callAuthority EXCEPT ![WakeCall] = authorityEpoch]
                                /\ callBinding' = [callBinding EXCEPT ![WakeCall] = bindingEpoch]
                                /\ continuationState' = [continuationState EXCEPT ![WakeCall] = "Pending"]
                                /\ blockedBy' = [blockedBy EXCEPT ![WakeTask] = WakeCall]
                                /\ wakeCreditState' = [wakeCreditState EXCEPT ![WakeCall] = "Held"]
                                /\ freeWakeCredits' = freeWakeCredits - 1
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, preparedReply, waitQueue, waitCreditState, freeWaitCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WaitCall] = "Captured"
                                   /\ callAuthority[WaitCall] = authorityEpoch
                                   /\ callBinding[WaitCall] = bindingEpoch
                                /\ callState' = [callState EXCEPT ![WaitCall] = "ReplyPrepared"]
                                /\ preparedReply' = [preparedReply EXCEPT ![WaitCall] = "WaitEagain"]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, operation, callTask, callKey, callAuthority, callBinding, continuationState, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WaitCall] = "Captured"
                                   /\ callAuthority[WaitCall] = authorityEpoch
                                   /\ callBinding[WaitCall] = bindingEpoch
                                   /\ freeWaitCredits > 0
                                /\ callState' = [callState EXCEPT ![WaitCall] = "WaitRegistered"]
                                /\ waitQueue' = (waitQueue \cup {WaitCall})
                                /\ waitCreditState' = [waitCreditState EXCEPT ![WaitCall] = "Held"]
                                /\ freeWaitCredits' = freeWaitCredits - 1
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ replacementState = "Bound"
                                   /\ callState[WakeCall] = "Captured"
                                   /\ callAuthority[WakeCall] = authorityEpoch
                                   /\ callBinding[WakeCall] = bindingEpoch
                                /\ IF /\ callState[WaitCall] = "WaitRegistered"
                                      /\ WaitCall \in waitQueue
                                      /\ callAuthority[WaitCall] = authorityEpoch
                                      /\ callBinding[WaitCall] = bindingEpoch
                                      THEN /\ callState' =          [callState EXCEPT
                                                           ![WaitCall] = "WaitCommitted",
                                                           ![WakeCall] = "WakeCommitted"]
                                           /\ preparedReply' =              [preparedReply EXCEPT
                                                               ![WaitCall] = "WaitWoken",
                                                               ![WakeCall] = "WakeCount1"]
                                           /\ waitQueue' = waitQueue \ {WaitCall}
                                           /\ wakeSelected' = {WaitCall}
                                           /\ wakeResult' = 1
                                           /\ wakeCommitCount' =                [wakeCommitCount EXCEPT
                                                                 ![WaitCall] = @ + 1,
                                                                 ![WakeCall] = @ + 1]
                                      ELSE /\ callState' = [callState EXCEPT ![WakeCall] = "WakeCommitted"]
                                           /\ wakeSelected' = {}
                                           /\ wakeResult' = 0
                                           /\ preparedReply' = [preparedReply EXCEPT ![WakeCall] = "WakeCount0"]
                                           /\ wakeCommitCount' = [wakeCommitCount EXCEPT ![WakeCall] = wakeCommitCount[WakeCall] + 1]
                                           /\ UNCHANGED waitQueue
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, operation, callTask, callKey, callAuthority, callBinding, continuationState, blockedBy, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ LET c == WaitCall IN
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ callAuthority[c] = authorityEpoch
                                        /\ callBinding[c] = bindingEpoch
                                        /\ continuationState[c] = "Pending"
                                        /\ callState[c] = "ReplyPrepared"
                                        /\ preparedReply[c] = "WaitEagain"
                                     /\ callState' = [callState EXCEPT ![c] = "Completed"]
                                     /\ continuationState' = [continuationState EXCEPT ![c] = "Replied"]
                                     /\ replyPublicationCount' = [replyPublicationCount EXCEPT ![c] = replyPublicationCount[c] + 1]
                                     /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![c] = continuationConsumptionCount[c] + 1]
                                     /\ terminalCount' = [terminalCount EXCEPT ![c] = terminalCount[c] + 1]
                                     /\ resumeCount' = [resumeCount EXCEPT ![c] = resumeCount[c] + 1]
                                     /\ IF c = WaitCall
                                           THEN /\ eagainCount' = [eagainCount EXCEPT ![c] = eagainCount[c] + 1]
                                           ELSE /\ TRUE
                                                /\ UNCHANGED eagainCount
                                     /\ blockedBy' = [blockedBy EXCEPT ![callTask[c]] = NoCall]
                                     /\ recoveryCohort' = recoveryCohort \ {c}
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, operation, callTask, callKey, callAuthority, callBinding, preparedReply, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ \E c \in Calls:
                                     \E presentedCall \in Calls:
                                       \E presentedTask \in Tasks:
                                         \E presentedOperation \in {"Wait", "Wake"}:
                                           \E presentedKey \in {PrivateKey, NoKey}:
                                             \E presentedAuthority \in 0..1:
                                               \E presentedBinding \in 0..MaxBinding:
                                                 /\ /\ EnableRejects
                                                    /\ callState[c] \in LiveCallStates
                                                    /\ rejectCount[c] < MaxAttempts - 1
                                                    /\ ~( /\ scopeState = "Active"
                                                          /\ serviceAlive
                                                          /\ replacementState = "Bound"
                                                          /\ presentedCall = c
                                                          /\ presentedTask = callTask[c]
                                                          /\ presentedOperation = operation[c]
                                                          /\ presentedKey = callKey[c]
                                                          /\ presentedAuthority = callAuthority[c]
                                                          /\ callAuthority[c] = authorityEpoch
                                                          /\ presentedBinding = callBinding[c]
                                                          /\ callBinding[c] = bindingEpoch )
                                                 /\ rejectCount' = [rejectCount EXCEPT ![c] = rejectCount[c] + 1]
                                                 /\ lastRejectedPresentedCall' = [lastRejectedPresentedCall EXCEPT ![c] = presentedCall]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
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
                                /\ snapshotLive' = {}
                                /\ snapshotCallState' = [c \in Calls |-> "Unused"]
                                /\ snapshotAdoptCount' = [c \in Calls |-> 0]
                                /\ snapshotQueue' = {}
                                /\ snapshotSelected' = {}
                                /\ snapshotResult' = NoResult
                                /\ recoveryCohort' = {c \in Calls : callState[c] \in LiveCallStates}
                                /\ IF /\ {c \in Calls : callState[c] \in LiveCallStates} # {}
                                      /\ watchdogState = "Idle"
                                      THEN /\ watchdogState' = "Armed"
                                           /\ deadlineCohort' = {c \in Calls : callState[c] \in LiveCallStates}
                                           /\ deadlineAuthority' = authorityEpoch
                                           /\ deadlineCrashBinding' = bindingEpoch'
                                           /\ deadlineCancelReason' = "None"
                                           /\ cancelledCohort' = {}
                                           /\ cancelledCrashBinding' = NoBinding
                                           /\ deadlineCancelledSeen' = FALSE
                                           /\ timerCreditHeld' = TRUE
                                           /\ freeTimerCredits' = freeTimerCredits - 1
                                      ELSE /\ TRUE
                                           /\ UNCHANGED << watchdogState, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen >>
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "None"
                                   /\ \/ snapshotState = "Absent"
                                      \/ /\ snapshotState = "Captured"
                                            /\ snapshotRevision < recoveryRevision
                                   /\ watchdogState # "Expired"
                                /\ snapshotState' = "Captured"
                                /\ snapshotAuthority' = authorityEpoch
                                /\ snapshotBinding' = bindingEpoch
                                /\ snapshotRevision' = recoveryRevision
                                /\ snapshotLive' = {c \in Calls : callState[c] \in LiveCallStates}
                                /\ snapshotCallState' = callState
                                /\ snapshotAdoptCount' = adoptCount
                                /\ snapshotQueue' = waitQueue
                                /\ snapshotSelected' = wakeSelected
                                /\ snapshotResult' = wakeResult
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "None"
                                   /\ snapshotState = "Captured"
                                   /\ watchdogState # "Expired"
                                   /\ snapshotAuthority = authorityEpoch
                                   /\ snapshotBinding = bindingEpoch
                                   /\ snapshotRevision = recoveryRevision
                                   /\ snapshotLive =
                                         {c \in Calls : callState[c] \in LiveCallStates}
                                   /\ snapshotCallState = callState
                                   /\ snapshotAdoptCount = adoptCount
                                   /\ snapshotQueue = waitQueue
                                   /\ snapshotSelected = wakeSelected
                                   /\ snapshotResult = wakeResult
                                /\ replacementState' = "Ready"
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "Ready"
                                   /\ snapshotState = "Captured"
                                   /\ watchdogState # "Expired"
                                   /\ snapshotAuthority = authorityEpoch
                                   /\ snapshotBinding = bindingEpoch
                                   /\ snapshotRevision = recoveryRevision
                                   /\ snapshotLive =
                                         {c \in Calls : callState[c] \in LiveCallStates}
                                   /\ snapshotCallState = callState
                                   /\ snapshotAdoptCount = adoptCount
                                   /\ snapshotQueue = waitQueue
                                   /\ snapshotSelected = wakeSelected
                                   /\ snapshotResult = wakeResult
                                /\ serviceAlive' = TRUE
                                /\ replacementState' = "Bound"
                                /\ fallbackState' = "Standby"
                                /\ snapshotState' = "Absent"
                                /\ snapshotAuthority' = NoEpoch
                                /\ snapshotBinding' = NoBinding
                                /\ snapshotRevision' = NoRevision
                                /\ snapshotLive' = {}
                                /\ snapshotCallState' = [c \in Calls |-> "Unused"]
                                /\ snapshotAdoptCount' = [c \in Calls |-> 0]
                                /\ snapshotQueue' = {}
                                /\ snapshotSelected' = {}
                                /\ snapshotResult' = NoResult
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, bindingEpoch, recoveryRevision, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ \E c \in Calls:
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ watchdogState # "Expired"
                                        /\ callState[c] \in LiveCallStates
                                        /\ callAuthority[c] = authorityEpoch
                                        /\ callBinding[c] # bindingEpoch
                                     /\ callBinding' = [callBinding EXCEPT ![c] = bindingEpoch]
                                     /\ adoptCount' = [adoptCount EXCEPT ![c] = adoptCount[c] + 1]
                                     /\ recoveryCohort' = recoveryCohort \ {c}
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, watchdogState, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ scopeState = "Active"
                                /\ liveAtClose' = {c \in Calls : callState[c] \in LiveCallStates}
                                /\ committedAtClose' = {c \in Calls : callState[c] \in CommittedCallStates}
                                /\ wakeCommitCountAtClose' = wakeCommitCount
                                /\ adoptCountAtClose' = adoptCount
                                /\ closureTargetCount' = Cardinality({c \in Calls :
                                                             callState[c] \in LiveCallStates})
                                                         + (IF timerCreditHeld THEN 1 ELSE 0)
                                /\ closureSteps' = 0
                                /\ closingEpoch' = authorityEpoch
                                /\ authorityEpoch' = authorityEpoch + 1
                                /\ scopeState' = "Closing"
                                /\ serviceAlive' = FALSE
                                /\ replacementState' = "Closed"
                                /\ fallbackState' = "Closed"
                                /\ snapshotState' = "Absent"
                                /\ snapshotAuthority' = NoEpoch
                                /\ snapshotBinding' = NoBinding
                                /\ snapshotRevision' = NoRevision
                                /\ snapshotLive' = {}
                                /\ snapshotCallState' = [c \in Calls |-> "Unused"]
                                /\ snapshotAdoptCount' = [c \in Calls |-> 0]
                                /\ snapshotQueue' = {}
                                /\ snapshotSelected' = {}
                                /\ snapshotResult' = NoResult
                                /\ IF timerCreditHeld
                                      THEN /\ watchdogState' = "Closing"
                                      ELSE /\ watchdogState' = "Idle"
                                /\ UNCHANGED <<bindingEpoch, recoveryRevision, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen>>
                          /\ UNCHANGED << wakePublicationCount, abortCount, watchdogExpiredSeen, timeoutRevokeSeen >>

KernelFallback == /\ fallbackState = "Required"
                  /\ fallbackState' = "Running"
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, abortCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, watchdogExpiredSeen, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps >>

KernelWake == /\ /\ scopeState = "Active"
                 /\ callState[WakeCall] = "WakeCommitted"
                 /\ continuationState[WakeCall] = "Pending"
                 /\ wakeCreditState[WakeCall] = "Held"
                 /\ (wakeResult = 0
                       \/ /\ wakeResult = 1
                          /\ callState[WaitCall] = "WaitCommitted"
                          /\ continuationState[WaitCall] = "Pending"
                          /\ waitCreditState[WaitCall] = "Held")
              /\ IF wakeResult = 1
                    THEN /\ callState' =          [callState EXCEPT
                                         ![WaitCall] = "Completed",
                                         ![WakeCall] = "Completed"]
                         /\ continuationState' =                  [continuationState EXCEPT
                                                 ![WaitCall] = "Replied",
                                                 ![WakeCall] = "Replied"]
                         /\ wakePublicationCount' = [wakePublicationCount EXCEPT ![WaitCall] = wakePublicationCount[WaitCall] + 1]
                         /\ replyPublicationCount' =                      [replyPublicationCount EXCEPT
                                                     ![WaitCall] = @ + 1,
                                                     ![WakeCall] = @ + 1]
                         /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT
                                                                ![WaitCall] = @ + 1,
                                                                ![WakeCall] = @ + 1]
                         /\ terminalCount' =              [terminalCount EXCEPT
                                             ![WaitCall] = @ + 1,
                                             ![WakeCall] = @ + 1]
                         /\ resumeCount' =            [resumeCount EXCEPT
                                           ![WaitCall] = @ + 1,
                                           ![WakeCall] = @ + 1]
                         /\ waitCreditState' = [waitCreditState EXCEPT ![WaitCall] = "Returned"]
                         /\ freeWaitCredits' = freeWaitCredits + 1
                         /\ blockedBy' =          [blockedBy EXCEPT
                                         ![WaitTask] = NoCall,
                                         ![WakeTask] = NoCall]
                         /\ recoveryCohort' = recoveryCohort \ {WaitCall, WakeCall}
                    ELSE /\ callState' = [callState EXCEPT ![WakeCall] = "Completed"]
                         /\ continuationState' = [continuationState EXCEPT ![WakeCall] = "Replied"]
                         /\ replyPublicationCount' = [replyPublicationCount EXCEPT ![WakeCall] = replyPublicationCount[WakeCall] + 1]
                         /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![WakeCall] = continuationConsumptionCount[WakeCall] + 1]
                         /\ terminalCount' = [terminalCount EXCEPT ![WakeCall] = terminalCount[WakeCall] + 1]
                         /\ resumeCount' = [resumeCount EXCEPT ![WakeCall] = resumeCount[WakeCall] + 1]
                         /\ blockedBy' = [blockedBy EXCEPT ![WakeTask] = NoCall]
                         /\ recoveryCohort' = recoveryCohort \ {WakeCall}
                         /\ UNCHANGED << waitCreditState, freeWaitCredits, wakePublicationCount >>
              /\ wakeCreditState' = [wakeCreditState EXCEPT ![WakeCall] = "Returned"]
              /\ freeWakeCredits' = freeWakeCredits + 1
              /\ IF ~serviceAlive
                    THEN /\ recoveryRevision' = recoveryRevision + 1
                         /\ IF replacementState = "Ready"
                               THEN /\ replacementState' = "None"
                               ELSE /\ TRUE
                                    /\ UNCHANGED replacementState
                    ELSE /\ TRUE
                         /\ UNCHANGED << recoveryRevision, replacementState >>
              /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, operation, callTask, callKey, callAuthority, callBinding, preparedReply, waitQueue, wakeSelected, wakeResult, wakeCommitCount, eagainCount, abortCount, rejectCount, lastRejectedPresentedCall, adoptCount, watchdogState, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, watchdogExpiredSeen, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps >>

KernelWatchdog == /\ watchdogState = "Armed"
                  /\ watchdogState' = "Expired"
                  /\ watchdogExpiredSeen' = TRUE
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, recoveryRevision, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, operation, callTask, callKey, callAuthority, callBinding, continuationState, preparedReply, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakeSelected, wakeResult, wakeCommitCount, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, eagainCount, abortCount, rejectCount, lastRejectedPresentedCall, adoptCount, recoveryCohort, deadlineCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps >>

KernelClosure == /\ \/ /\ /\ scopeState = "Active"
                          /\ watchdogState = "Armed"
                          /\ recoveryCohort = {}
                          /\ timerCreditHeld
                       /\ watchdogState' = "Idle"
                       /\ deadlineCancelReason' = "ResolvedBeforeExpiry"
                       /\ cancelledCohort' = deadlineCohort
                       /\ cancelledCrashBinding' = deadlineCrashBinding
                       /\ deadlineAuthority' = NoEpoch
                       /\ deadlineCrashBinding' = NoBinding
                       /\ timerCreditHeld' = FALSE
                       /\ freeTimerCredits' = freeTimerCredits + 1
                       /\ deadlineCancelledSeen' = TRUE
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, continuationState, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, abortCount, recoveryCohort, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                    \/ /\ /\ scopeState = "Active"
                          /\ watchdogState = "Expired"
                          /\ recoveryCohort = {}
                          /\ timerCreditHeld
                       /\ watchdogState' = "Idle"
                       /\ deadlineCancelReason' = "ResolvedAfterExpiry"
                       /\ cancelledCohort' = deadlineCohort
                       /\ cancelledCrashBinding' = deadlineCrashBinding
                       /\ deadlineAuthority' = NoEpoch
                       /\ deadlineCrashBinding' = NoBinding
                       /\ timerCreditHeld' = FALSE
                       /\ freeTimerCredits' = freeTimerCredits + 1
                       /\ deadlineCancelledSeen' = TRUE
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, continuationState, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, abortCount, recoveryCohort, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                    \/ /\ /\ scopeState = "Active"
                          /\ watchdogState = "Expired"
                          /\ recoveryCohort # {}
                          /\ timerCreditHeld
                       /\ liveAtClose' = {c \in Calls : callState[c] \in LiveCallStates}
                       /\ committedAtClose' = {c \in Calls : callState[c] \in CommittedCallStates}
                       /\ wakeCommitCountAtClose' = wakeCommitCount
                       /\ adoptCountAtClose' = adoptCount
                       /\ closureTargetCount' = Cardinality({c \in Calls :
                                                    callState[c] \in LiveCallStates}) + 1
                       /\ closureSteps' = 0
                       /\ closingEpoch' = authorityEpoch
                       /\ authorityEpoch' = authorityEpoch + 1
                       /\ scopeState' = "Closing"
                       /\ serviceAlive' = FALSE
                       /\ replacementState' = "Closed"
                       /\ fallbackState' = "Closed"
                       /\ snapshotState' = "Absent"
                       /\ snapshotAuthority' = NoEpoch
                       /\ snapshotBinding' = NoBinding
                       /\ snapshotRevision' = NoRevision
                       /\ snapshotLive' = {}
                       /\ snapshotCallState' = [c \in Calls |-> "Unused"]
                       /\ snapshotAdoptCount' = [c \in Calls |-> 0]
                       /\ snapshotQueue' = {}
                       /\ snapshotSelected' = {}
                       /\ snapshotResult' = NoResult
                       /\ watchdogState' = "Closing"
                       /\ timeoutRevokeSeen' = TRUE
                       /\ UNCHANGED <<callState, continuationState, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, abortCount, recoveryCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ callAuthority[WakeCall] = closingEpoch
                          /\ callState[WakeCall] = "WakeCommitted"
                          /\ (wakeResult = 0
                                \/ /\ wakeResult = 1
                                   /\ callState[WaitCall] = "WaitCommitted")
                       /\ IF wakeResult = 1
                             THEN /\ callState' =          [callState EXCEPT
                                                  ![WaitCall] = "Completed",
                                                  ![WakeCall] = "Completed"]
                                  /\ continuationState' =                  [continuationState EXCEPT
                                                          ![WaitCall] = "Replied",
                                                          ![WakeCall] = "Replied"]
                                  /\ wakePublicationCount' = [wakePublicationCount EXCEPT ![WaitCall] = wakePublicationCount[WaitCall] + 1]
                                  /\ replyPublicationCount' =                      [replyPublicationCount EXCEPT
                                                              ![WaitCall] = @ + 1,
                                                              ![WakeCall] = @ + 1]
                                  /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT
                                                                         ![WaitCall] = @ + 1,
                                                                         ![WakeCall] = @ + 1]
                                  /\ terminalCount' =              [terminalCount EXCEPT
                                                      ![WaitCall] = @ + 1,
                                                      ![WakeCall] = @ + 1]
                                  /\ resumeCount' =            [resumeCount EXCEPT
                                                    ![WaitCall] = @ + 1,
                                                    ![WakeCall] = @ + 1]
                                  /\ waitCreditState' = [waitCreditState EXCEPT ![WaitCall] = "Returned"]
                                  /\ freeWaitCredits' = freeWaitCredits + 1
                                  /\ blockedBy' =          [blockedBy EXCEPT
                                                  ![WaitTask] = NoCall,
                                                  ![WakeTask] = NoCall]
                                  /\ recoveryCohort' = recoveryCohort \ {WaitCall, WakeCall}
                                  /\ closureSteps' = closureSteps + 2
                             ELSE /\ callState' = [callState EXCEPT ![WakeCall] = "Completed"]
                                  /\ continuationState' = [continuationState EXCEPT ![WakeCall] = "Replied"]
                                  /\ replyPublicationCount' = [replyPublicationCount EXCEPT ![WakeCall] = replyPublicationCount[WakeCall] + 1]
                                  /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![WakeCall] = continuationConsumptionCount[WakeCall] + 1]
                                  /\ terminalCount' = [terminalCount EXCEPT ![WakeCall] = terminalCount[WakeCall] + 1]
                                  /\ resumeCount' = [resumeCount EXCEPT ![WakeCall] = resumeCount[WakeCall] + 1]
                                  /\ blockedBy' = [blockedBy EXCEPT ![WakeTask] = NoCall]
                                  /\ recoveryCohort' = recoveryCohort \ {WakeCall}
                                  /\ closureSteps' = closureSteps + 1
                                  /\ UNCHANGED << waitCreditState, freeWaitCredits, wakePublicationCount >>
                       /\ wakeCreditState' = [wakeCreditState EXCEPT ![WakeCall] = "Returned"]
                       /\ freeWakeCredits' = freeWakeCredits + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, waitQueue, abortCount, watchdogState, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount>>
                    \/ /\ \E c \in Calls:
                            /\ /\ scopeState = "Closing"
                               /\ callAuthority[c] = closingEpoch
                               /\ callState[c] \in LiveCallStates
                               /\ callState[c] # "WaitCommitted"
                               /\ callState[c] # "WakeCommitted"
                            /\ IF /\ c = WaitCall
                                  /\ waitCreditState[c] = "Held"
                                  THEN /\ waitQueue' = waitQueue \ {c}
                                       /\ waitCreditState' = [waitCreditState EXCEPT ![c] = "Returned"]
                                       /\ freeWaitCredits' = freeWaitCredits + 1
                                  ELSE /\ TRUE
                                       /\ UNCHANGED << waitQueue, waitCreditState, freeWaitCredits >>
                            /\ IF /\ c = WakeCall
                                  /\ wakeCreditState[c] = "Held"
                                  THEN /\ wakeCreditState' = [wakeCreditState EXCEPT ![c] = "Returned"]
                                       /\ freeWakeCredits' = freeWakeCredits + 1
                                  ELSE /\ TRUE
                                       /\ UNCHANGED << wakeCreditState, freeWakeCredits >>
                            /\ callState' = [callState EXCEPT ![c] = "Aborted"]
                            /\ continuationState' = [continuationState EXCEPT ![c] = "Aborted"]
                            /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![c] = continuationConsumptionCount[c] + 1]
                            /\ terminalCount' = [terminalCount EXCEPT ![c] = terminalCount[c] + 1]
                            /\ abortCount' = [abortCount EXCEPT ![c] = abortCount[c] + 1]
                            /\ blockedBy' = [blockedBy EXCEPT ![callTask[c]] = NoCall]
                            /\ recoveryCohort' = recoveryCohort \ {c}
                            /\ closureSteps' = closureSteps + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, wakePublicationCount, replyPublicationCount, resumeCount, watchdogState, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ watchdogState = "Closing"
                          /\ timerCreditHeld
                       /\ watchdogState' = "Idle"
                       /\ recoveryCohort' = {}
                       /\ deadlineAuthority' = NoEpoch
                       /\ deadlineCrashBinding' = NoBinding
                       /\ timerCreditHeld' = FALSE
                       /\ freeTimerCredits' = freeTimerCredits + 1
                       /\ closureSteps' = closureSteps + 1
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, continuationState, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, abortCount, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ \A c \in Calls :
                                 callAuthority[c] = closingEpoch
                                 => callState[c] \in TerminalCallStates
                          /\ ~timerCreditHeld
                          /\ closureSteps = closureTargetCount
                       /\ scopeState' = "Revoked"
                       /\ UNCHANGED <<authorityEpoch, closingEpoch, serviceAlive, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotRevision, snapshotLive, snapshotCallState, snapshotAdoptCount, snapshotQueue, snapshotSelected, snapshotResult, callState, continuationState, blockedBy, waitQueue, waitCreditState, freeWaitCredits, wakeCreditState, freeWakeCredits, wakePublicationCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, abortCount, watchdogState, recoveryCohort, deadlineAuthority, deadlineCrashBinding, deadlineCancelReason, cancelledCohort, cancelledCrashBinding, timerCreditHeld, freeTimerCredits, deadlineCancelledSeen, timeoutRevokeSeen, liveAtClose, committedAtClose, wakeCommitCountAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                 /\ UNCHANGED << bindingEpoch, recoveryRevision, operation, callTask, callKey, callAuthority, callBinding, preparedReply, wakeSelected, wakeResult, wakeCommitCount, eagainCount, rejectCount, lastRejectedPresentedCall, adoptCount, deadlineCohort, watchdogExpiredSeen >>

Next == PersonalityEnvironment \/ KernelFallback \/ KernelWake \/ KernelWatchdog \/ KernelClosure

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(KernelFallback)
        /\ WF_vars(KernelWake)
        /\ WF_vars(KernelWatchdog)
        /\ WF_vars(KernelClosure)

\* END TRANSLATION

(***************************************************************************)
(* Safety predicates and action/liveness properties follow the generated    *)
(* translation.                                                             *)
(***************************************************************************)

CurrentLiveCalls == {c \in Calls : callState[c] \in LiveCallStates}

FutexToken(c) ==
    [scope |-> Scope,
     call |-> c,
     task |-> callTask[c],
     operation |-> operation[c],
     key |-> callKey[c],
     authority_epoch |-> callAuthority[c],
     binding_epoch |-> callBinding[c]]

TypeOK ==
    /\ scopeState \in ScopeStates
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ serviceAlive \in BOOLEAN
    /\ bindingEpoch \in 0..MaxBinding
    /\ recoveryRevision \in 0..(MaxBinding + 1)
    /\ replacementState \in ReplacementStates
    /\ fallbackState \in FallbackStates
    /\ snapshotState \in SnapshotStates
    /\ snapshotAuthority \in {NoEpoch, 0}
    /\ snapshotBinding \in ({NoBinding} \cup (0..MaxBinding))
    /\ snapshotRevision \in ({NoRevision} \cup (0..(MaxBinding + 1)))
    /\ snapshotLive \subseteq Calls
    /\ snapshotCallState \in [Calls -> CallStates]
    /\ snapshotAdoptCount \in [Calls -> (0..MaxBinding)]
    /\ snapshotQueue \subseteq {WaitCall}
    /\ snapshotSelected \subseteq {WaitCall}
    /\ snapshotResult \in {NoResult, 0, 1}
    /\ callState \in [Calls -> CallStates]
    /\ operation \in [Calls -> Operations]
    /\ callTask \in [Calls -> ({NoTask} \cup Tasks)]
    /\ callKey \in [Calls -> {NoKey, PrivateKey}]
    /\ callAuthority \in [Calls -> {NoEpoch, 0}]
    /\ callBinding \in [Calls -> ({NoBinding} \cup (0..MaxBinding))]
    /\ continuationState \in [Calls -> ContinuationStates]
    /\ preparedReply \in [Calls -> PreparedReplies]
    /\ blockedBy \in [Tasks -> ({NoCall} \cup Calls)]
    /\ waitQueue \subseteq {WaitCall}
    /\ waitCreditState \in [Calls -> WaitCreditStates]
    /\ freeWaitCredits \in 0..InitialWaitCredits
    /\ wakeCreditState \in [Calls -> WaitCreditStates]
    /\ freeWakeCredits \in 0..InitialWakeCredits
    /\ wakeSelected \subseteq {WaitCall}
    /\ wakeResult \in {NoResult, 0, 1}
    /\ wakeCommitCount \in [Calls -> {0, 1}]
    /\ wakePublicationCount \in [Calls -> {0, 1}]
    /\ replyPublicationCount \in [Calls -> {0, 1}]
    /\ continuationConsumptionCount \in [Calls -> {0, 1}]
    /\ terminalCount \in [Calls -> {0, 1}]
    /\ resumeCount \in [Calls -> {0, 1}]
    /\ eagainCount \in [Calls -> {0, 1}]
    /\ abortCount \in [Calls -> {0, 1}]
    /\ rejectCount \in [Calls -> (0..(MaxAttempts - 1))]
    /\ lastRejectedPresentedCall \in [Calls -> ({NoCall} \cup Calls)]
    /\ adoptCount \in [Calls -> (0..MaxBinding)]
    /\ watchdogState \in WatchdogStates
    /\ recoveryCohort \subseteq Calls
    /\ deadlineCohort \subseteq Calls
    /\ deadlineAuthority \in {NoEpoch, 0}
    /\ deadlineCrashBinding \in ({NoBinding} \cup (0..MaxBinding))
    /\ deadlineCancelReason \in CancelReasonStates
    /\ cancelledCohort \subseteq Calls
    /\ cancelledCrashBinding \in ({NoBinding} \cup (0..MaxBinding))
    /\ timerCreditHeld \in BOOLEAN
    /\ freeTimerCredits \in 0..InitialTimerCredits
    /\ watchdogExpiredSeen \in BOOLEAN
    /\ deadlineCancelledSeen \in BOOLEAN
    /\ timeoutRevokeSeen \in BOOLEAN
    /\ liveAtClose \subseteq Calls
    /\ committedAtClose \subseteq liveAtClose
    /\ wakeCommitCountAtClose \in [Calls -> {0, 1}]
    /\ adoptCountAtClose \in [Calls -> (0..MaxBinding)]
    /\ closureTargetCount \in 0..(Cardinality(Calls) + 1)
    /\ closureSteps \in 0..(Cardinality(Calls) + 1)

FutexTokensTypeOK ==
    \A c \in Calls :
        FutexToken(c)
          \in [scope : {Scope},
               call : Calls,
               task : ({NoTask} \cup Tasks),
               operation : Operations,
               key : {NoKey, PrivateKey},
               authority_epoch : {NoEpoch, 0},
               binding_epoch : ({NoBinding} \cup (0..MaxBinding))]

CallIdentityConsistency ==
    /\ operation[WaitCall] \in {"None", "Wait"}
    /\ operation[WakeCall] \in {"None", "Wake"}
    /\ (callState[WaitCall] # "Unused"
          => /\ operation[WaitCall] = "Wait"
             /\ callTask[WaitCall] = WaitTask
             /\ callKey[WaitCall] = PrivateKey
             /\ callAuthority[WaitCall] = 0
             /\ callBinding[WaitCall] \in 0..MaxBinding)
    /\ (callState[WakeCall] # "Unused"
          => /\ operation[WakeCall] = "Wake"
             /\ callTask[WakeCall] = WakeTask
             /\ callKey[WakeCall] = PrivateKey
             /\ callAuthority[WakeCall] = 0
             /\ callBinding[WakeCall] \in 0..MaxBinding)
    /\ \A c \in Calls :
           callState[c] = "Unused"
             => /\ operation[c] = "None"
                /\ callTask[c] = NoTask
                /\ callKey[c] = NoKey
                /\ callAuthority[c] = NoEpoch
                /\ callBinding[c] = NoBinding
                /\ continuationState[c] = "Absent"
                /\ preparedReply[c] = "None"

BlockedTaskConsistency ==
    /\ (blockedBy[WaitTask] = WaitCall
          <=> callState[WaitCall] \in LiveCallStates)
    /\ (blockedBy[WakeTask] = WakeCall
          <=> callState[WakeCall] \in LiveCallStates)
    /\ blockedBy[WaitTask] # WakeCall
    /\ blockedBy[WakeTask] # WaitCall

WaitQueueConsistency ==
    /\ (WaitCall \in waitQueue
          <=> callState[WaitCall] = "WaitRegistered")
    /\ (waitCreditState[WaitCall] = "Held"
          <=> callState[WaitCall]
                \in {"WaitRegistered", "WaitCommitted"})
    /\ waitCreditState[WakeCall] = "None"
    /\ (callState[WaitCall] = "ReplyPrepared"
          => /\ preparedReply[WaitCall] = "WaitEagain"
             /\ WaitCall \notin waitQueue
             /\ waitCreditState[WaitCall] = "None")

WakeCreditConsistency ==
    /\ wakeCreditState[WaitCall] = "None"
    /\ (wakeCreditState[WakeCall] = "None"
          <=> callState[WakeCall] = "Unused")
    /\ (wakeCreditState[WakeCall] = "Held"
          <=> callState[WakeCall] \in LiveCallStates)
    /\ (wakeCreditState[WakeCall] = "Returned"
          <=> callState[WakeCall] \in TerminalCallStates)

WakeCommitConsistency ==
    /\ (\/ /\ wakeResult \in {0, 1}
              /\ wakeResult = Cardinality(wakeSelected)
        \/ /\ wakeResult = NoResult
              /\ wakeSelected = {})
    /\ (WaitCall \in wakeSelected
          <=> /\ wakeCommitCount[WaitCall] = 1
              /\ callState[WaitCall] \in {"WaitCommitted", "Completed"})
    /\ (wakeCommitCount[WakeCall] = 1
          <=> callState[WakeCall] \in {"WakeCommitted", "Completed"})
    /\ (callState[WaitCall] = "WaitCommitted"
          => /\ preparedReply[WaitCall] = "WaitWoken"
             /\ wakePublicationCount[WaitCall] = 0)
    /\ (callState[WakeCall] = "WakeCommitted"
          => /\ preparedReply[WakeCall]
                   \in {"WakeCount0", "WakeCount1"}
             /\ (preparedReply[WakeCall] = "WakeCount1"
                   <=> wakeResult = 1))

SingleTerminalization ==
    \A c \in Calls :
        /\ continuationConsumptionCount[c] \in {0, 1}
        /\ terminalCount[c] = continuationConsumptionCount[c]
        /\ resumeCount[c] \in {0, 1}
        /\ abortCount[c] \in {0, 1}
        /\ eagainCount[c] \in {0, 1}
        /\ (callState[c] \in TerminalCallStates
              <=> terminalCount[c] = 1)
        /\ (callState[c] = "Completed"
              => /\ continuationState[c] = "Replied"
                 /\ replyPublicationCount[c] = 1
                 /\ resumeCount[c] = 1
                 /\ abortCount[c] = 0)
        /\ (callState[c] = "Aborted"
              => /\ continuationState[c] = "Aborted"
                 /\ replyPublicationCount[c] = 0
                 /\ resumeCount[c] = 0
                 /\ abortCount[c] = 1)
        /\ (callState[c] \in LiveCallStates
              => /\ continuationState[c] = "Pending"
                 /\ continuationConsumptionCount[c] = 0
                 /\ terminalCount[c] = 0
                 /\ resumeCount[c] = 0
                 /\ abortCount[c] = 0)

WakeCommitBeforePublication ==
    /\ (wakePublicationCount[WaitCall] = 1
          => /\ wakeCommitCount[WaitCall] = 1
             /\ preparedReply[WaitCall] = "WaitWoken")
    /\ (eagainCount[WaitCall] = 1
          => /\ wakeCommitCount[WaitCall] = 0
             /\ waitCreditState[WaitCall] = "None")

BudgetConservation ==
    /\ freeWaitCredits
         + (IF waitCreditState[WaitCall] = "Held" THEN 1 ELSE 0)
       = InitialWaitCredits
    /\ freeWakeCredits
         + (IF wakeCreditState[WakeCall] = "Held" THEN 1 ELSE 0)
       = InitialWakeCredits
    /\ freeTimerCredits + (IF timerCreditHeld THEN 1 ELSE 0)
       = InitialTimerCredits
    /\ (watchdogState = "Idle" <=> ~timerCreditHeld)
    /\ (watchdogState \in {"Armed", "Expired", "Closing"}
          => timerCreditHeld)

SnapshotImageWellFormed ==
    /\ snapshotLive =
          {c \in Calls : snapshotCallState[c] \in LiveCallStates}
    /\ (WaitCall \in snapshotQueue
          <=> snapshotCallState[WaitCall] = "WaitRegistered")
    /\ (\/ /\ snapshotResult = NoResult
              /\ snapshotSelected = {}
        \/ /\ snapshotResult \in {0, 1}
              /\ snapshotResult = Cardinality(snapshotSelected))
    /\ (WaitCall \in snapshotSelected
          => snapshotCallState[WaitCall] \in {"WaitCommitted", "Completed"})
    /\ (snapshotResult \in {0, 1}
          => snapshotCallState[WakeCall] \in {"WakeCommitted", "Completed"})

SnapshotMatchesCurrent ==
    /\ snapshotLive = CurrentLiveCalls
    /\ snapshotCallState = callState
    /\ snapshotAdoptCount = adoptCount
    /\ snapshotQueue = waitQueue
    /\ snapshotSelected = wakeSelected
    /\ snapshotResult = wakeResult

SnapshotDiscipline ==
    /\ (serviceAlive <=> replacementState = "Bound")
    /\ (snapshotState = "Absent"
          => /\ snapshotAuthority = NoEpoch
             /\ snapshotBinding = NoBinding
             /\ snapshotRevision = NoRevision
             /\ snapshotLive = {}
             /\ snapshotCallState = [c \in Calls |-> "Unused"]
             /\ snapshotAdoptCount = [c \in Calls |-> 0]
             /\ snapshotQueue = {}
             /\ snapshotSelected = {}
             /\ snapshotResult = NoResult)
    /\ (snapshotState = "Captured"
          => /\ scopeState = "Active"
             /\ ~serviceAlive
             /\ fallbackState = "Running"
             /\ replacementState \in {"None", "Ready"}
             /\ snapshotAuthority = authorityEpoch
             /\ snapshotBinding = bindingEpoch
             /\ snapshotRevision \in 0..recoveryRevision
             /\ SnapshotImageWellFormed
             /\ snapshotAdoptCount = adoptCount
             /\ (snapshotRevision = recoveryRevision
                   => SnapshotMatchesCurrent)
             /\ (snapshotRevision < recoveryRevision
                   => /\ replacementState = "None"
                      /\ CurrentLiveCalls \subseteq snapshotLive
                      /\ snapshotLive \ CurrentLiveCalls # {}
                      /\ snapshotQueue = waitQueue
                      /\ snapshotSelected = wakeSelected
                      /\ snapshotResult = wakeResult
                      /\ \A c \in snapshotLive \ CurrentLiveCalls :
                             /\ callState[c] \in TerminalCallStates
                             /\ callBinding[c] < snapshotBinding
                             /\ adoptCount[c] = snapshotAdoptCount[c]))
    /\ (replacementState = "Ready"
          => /\ snapshotState = "Captured"
             /\ snapshotRevision = recoveryRevision
             /\ SnapshotMatchesCurrent)
    /\ (scopeState \in {"Closing", "Revoked"}
          => /\ ~serviceAlive
             /\ replacementState = "Closed"
             /\ fallbackState = "Closed"
             /\ snapshotState = "Absent")

RecoveryCohortConsistency ==
    /\ recoveryCohort \subseteq CurrentLiveCalls
    /\ \A c \in recoveryCohort : callBinding[c] < bindingEpoch
    /\ (watchdogState = "Idle" => recoveryCohort = {})
    /\ (watchdogState \in {"Armed", "Expired"}
          => /\ deadlineCohort # {}
             /\ recoveryCohort \subseteq deadlineCohort
             /\ deadlineAuthority = authorityEpoch
             /\ deadlineCrashBinding = bindingEpoch
             /\ deadlineCancelReason = "None"
             /\ cancelledCohort = {}
             /\ cancelledCrashBinding = NoBinding)
    /\ (deadlineCancelledSeen <=> deadlineCancelReason # "None")
    /\ (deadlineCancelledSeen
          => /\ watchdogState = "Idle"
             /\ ~timerCreditHeld
             /\ freeTimerCredits = InitialTimerCredits
             /\ cancelledCohort = deadlineCohort
             /\ cancelledCohort # {}
             /\ cancelledCrashBinding \in 1..MaxBinding
             /\ \A c \in cancelledCohort :
                    \/ callState[c] \in TerminalCallStates
                    \/ callBinding[c] = cancelledCrashBinding)
    /\ (deadlineCancelReason = "ResolvedAfterExpiry"
          => watchdogExpiredSeen)

PostRevokeWakeExclusion ==
    scopeState \in {"Closing", "Revoked"}
      => /\ wakeCommitCount = wakeCommitCountAtClose
         /\ adoptCount = adoptCountAtClose

ClosureAccounting ==
    /\ closureSteps <= closureTargetCount
    /\ (scopeState \in {"Closing", "Revoked"}
          => closureSteps
               + Cardinality({c \in Calls :
                    /\ callAuthority[c] = closingEpoch
                    /\ callState[c] \in LiveCallStates})
               + (IF timerCreditHeld THEN 1 ELSE 0)
             = closureTargetCount)

RevokeRaceOutcome ==
    scopeState = "Revoked"
      => /\ \A c \in committedAtClose : callState[c] = "Completed"
         /\ \A c \in liveAtClose \ committedAtClose :
                callState[c] = "Aborted"

QuiescentClosure ==
    scopeState = "Revoked"
      => /\ CurrentLiveCalls = {}
         /\ waitQueue = {}
         /\ blockedBy = [t \in Tasks |-> NoCall]
         /\ waitCreditState[WaitCall] \in {"None", "Returned"}
         /\ freeWaitCredits = InitialWaitCredits
         /\ wakeCreditState[WakeCall] \in {"None", "Returned"}
         /\ freeWakeCredits = InitialWakeCredits
         /\ watchdogState = "Idle"
         /\ ~timerCreditHeld
         /\ freeTimerCredits = InitialTimerCredits
         /\ closureSteps = closureTargetCount

(***************************************************************************)
(* Reachability witnesses used during bounded validation.                    *)
(***************************************************************************)

MismatchObserved == eagainCount[WaitCall] = 1

CrashAdoptCancelObserved ==
    /\ adoptCount[WaitCall] = 1
    /\ deadlineCancelledSeen
    /\ watchdogState = "Idle"
    /\ callState[WaitCall] = "WaitRegistered"

WakeBeforeRevokeObserved ==
    /\ scopeState = "Revoked"
    /\ WaitCall \in committedAtClose
    /\ callState[WaitCall] = "Completed"
    /\ wakePublicationCount[WaitCall] = 1

RevokeBeforeWakeObserved ==
    /\ scopeState = "Revoked"
    /\ wakeCommitCountAtClose[WaitCall] = 0
    /\ callState[WaitCall] = "Aborted"

WatchdogRevokeObserved ==
    /\ timeoutRevokeSeen
    /\ scopeState = "Revoked"
    /\ callState[WaitCall] = "Aborted"
    /\ eagainCount[WaitCall] = 0

MismatchAbsent == ~MismatchObserved
CrashAdoptCancelAbsent == ~CrashAdoptCancelObserved
WakeBeforeRevokeAbsent == ~WakeBeforeRevokeObserved
RevokeBeforeWakeAbsent == ~RevokeBeforeWakeObserved
WatchdogRevokeAbsent == ~WatchdogRevokeObserved

(***************************************************************************)
(* Action properties and conditional liveness.  No environment action is    *)
(* fair, and no property says that an ordinary registered wait completes.    *)
(***************************************************************************)

RejectSideEffectFreedom ==
    [][
        rejectCount' # rejectCount
          => UNCHANGED <<
                 scopeState, authorityEpoch, closingEpoch,
                 serviceAlive, bindingEpoch, recoveryRevision,
                 replacementState,
                 fallbackState, snapshotState, snapshotAuthority,
                 snapshotBinding, snapshotRevision, snapshotLive,
                 snapshotCallState, snapshotAdoptCount,
                 snapshotQueue, snapshotSelected, snapshotResult,
                 callState, operation, callTask, callKey,
                 callAuthority, callBinding, continuationState,
                 preparedReply, blockedBy, waitQueue, waitCreditState,
                 freeWaitCredits, wakeCreditState, freeWakeCredits,
                 wakeSelected, wakeResult,
                 wakeCommitCount, wakePublicationCount,
                 replyPublicationCount, continuationConsumptionCount,
                 terminalCount, resumeCount, eagainCount, abortCount,
                 adoptCount, watchdogState, recoveryCohort, deadlineCohort,
                 deadlineAuthority, deadlineCrashBinding,
                 deadlineCancelReason, cancelledCohort,
                 cancelledCrashBinding,
                 timerCreditHeld, freeTimerCredits,
                 watchdogExpiredSeen, deadlineCancelledSeen,
                 timeoutRevokeSeen, liveAtClose, committedAtClose,
                 wakeCommitCountAtClose, adoptCountAtClose,
                 closureTargetCount, closureSteps
             >>
    ]_vars

AdoptPreservesFutexState ==
    [][
        adoptCount' # adoptCount
          => UNCHANGED <<
                 scopeState, authorityEpoch, closingEpoch,
                 serviceAlive, bindingEpoch, recoveryRevision,
                 replacementState, fallbackState,
                 snapshotState, snapshotAuthority, snapshotBinding,
                 snapshotRevision, snapshotLive, snapshotCallState,
                 snapshotAdoptCount, snapshotQueue, snapshotSelected,
                 snapshotResult,
                 callState, operation, callTask, callKey,
                 callAuthority, continuationState, preparedReply,
                 blockedBy, waitQueue, waitCreditState, freeWaitCredits,
                 wakeCreditState, freeWakeCredits,
                 wakeSelected, wakeResult, wakeCommitCount,
                 wakePublicationCount, replyPublicationCount,
                 continuationConsumptionCount, terminalCount,
                 resumeCount, eagainCount, abortCount,
                 rejectCount, lastRejectedPresentedCall,
                 watchdogState, deadlineCohort, deadlineAuthority,
                 deadlineCrashBinding, deadlineCancelReason,
                 cancelledCohort, cancelledCrashBinding,
                 timerCreditHeld, freeTimerCredits,
                 watchdogExpiredSeen, deadlineCancelledSeen,
                 timeoutRevokeSeen,
                 liveAtClose, committedAtClose, wakeCommitCountAtClose,
                 adoptCountAtClose, closureTargetCount, closureSteps
             >>
    ]_vars

GenerationSeparation ==
    [][
        /\ (authorityEpoch' # authorityEpoch
              => /\ scopeState = "Active"
                 /\ scopeState' = "Closing"
                 /\ bindingEpoch' = bindingEpoch)
        /\ (bindingEpoch' # bindingEpoch
              => /\ serviceAlive
                 /\ ~serviceAlive'
                 /\ authorityEpoch' = authorityEpoch
                 /\ recoveryRevision' = recoveryRevision + 1)
    ]_vars

RecoveryRevisionAdvance ==
    [][
        recoveryRevision' # recoveryRevision
          => /\ recoveryRevision' = recoveryRevision + 1
             /\ \/ bindingEpoch' = bindingEpoch + 1
                \/ replyPublicationCount'[WakeCall]
                     = replyPublicationCount[WakeCall] + 1
    ]_vars

SnapshotCaptureIntegrity ==
    [][
        (/\ snapshotRevision' # snapshotRevision
         /\ snapshotRevision' # NoRevision)
          => /\ snapshotState' = "Captured"
             /\ snapshotRevision' = recoveryRevision'
             /\ snapshotLive' =
                   {c \in Calls : callState'[c] \in LiveCallStates}
             /\ snapshotCallState' = callState'
             /\ snapshotAdoptCount' = adoptCount'
             /\ snapshotQueue' = waitQueue'
             /\ snapshotSelected' = wakeSelected'
             /\ snapshotResult' = wakeResult'
    ]_vars

KernelChangeInvalidatesReady ==
    [][
        (/\ replacementState = "Ready"
         /\ replyPublicationCount'[WakeCall]
              = replyPublicationCount[WakeCall] + 1)
          => /\ replacementState' = "None"
             /\ snapshotRevision < recoveryRevision'
    ]_vars

FallbackOrClosureProgress ==
    (fallbackState = "Required")
      ~> (fallbackState = "Running" \/ fallbackState = "Closed")

CommittedWakeProgress ==
    (/\ scopeState = "Active"
     /\ callState[WaitCall] = "WaitCommitted")
      ~> (callState[WaitCall] = "Completed" \/ scopeState # "Active")

WatchdogProgress ==
    (watchdogState = "Armed")
      ~> (watchdogState \in {"Idle", "Expired", "Closing"})

ExpiredDeadlineProgress ==
    (/\ scopeState = "Active"
     /\ watchdogState = "Expired")
      ~> (watchdogState = "Idle" \/ scopeState = "Closing")

RevocationProgress ==
    /\ \A c \in Calls :
           (/\ scopeState = "Closing"
            /\ callAuthority[c] = closingEpoch
            /\ callState[c] \in LiveCallStates)
             ~> (callState[c] \in TerminalCallStates)
    /\ (scopeState = "Closing") ~> (scopeState = "Revoked")

=============================================================================

------------------------- MODULE PersonalityCser -------------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* A finite-state Stage 6A refinement of CSER for one restartable Linux    *)
(* personality scope.  The model deliberately contains only two operation  *)
(* labels: write and exit_group.  It fixes crash/recovery and continuation  *)
(* semantics; it does not model Linux ABI decoding or file-descriptor state. *)
(*                                                                         *)
(* The PlusCal algorithm is the source of Init/Next.  BackendCommit is the  *)
(* external-output linearization point for write.  Reply is a separate      *)
(* task-state publication and one-shot continuation consumption point.      *)
(***************************************************************************)

CONSTANTS
    Syscalls,
    Scope,
    MaxBinding,
    MaxReplyAttempts

ASSUME /\ IsFiniteSet(Syscalls)
       /\ Syscalls # {}
       /\ MaxBinding \in Nat
       /\ MaxBinding > 0
       /\ MaxReplyAttempts \in Nat
       /\ MaxReplyAttempts > 1

ScopeStates == {"Active", "Closing", "Revoked"}
SyscallStates == {
    "Unused", "Captured", "ReplyPrepared", "BackendCommitted",
    "Completed", "Aborted"
}
LiveSyscallStates == {"Captured", "ReplyPrepared", "BackendCommitted"}
TerminalSyscallStates == {"Completed", "Aborted"}
OperationStates == {"None", "Write", "ExitGroup"}
PreparedReplyStates == {"None", "WriteReturned", "ExitGroupRequested"}
ContinuationStates == {"Absent", "Pending", "Replied", "Aborted"}
ReplacementStates == {"None", "Ready", "Bound", "Closed"}
FallbackStates == {"Standby", "Required", "Running", "Closed"}
SnapshotStates == {"Absent", "Captured"}
ReplyRejectReasons == {"None", "GateClosed", "Authority", "Binding"}

NoEpoch == -1
NoBinding == -1

SyscallSymmetry == Permutations(Syscalls)

(* --algorithm PersonalityCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = NoEpoch,

    serviceAlive = TRUE,
    bindingEpoch = 0,
    replacementState = "Bound",
    fallbackState = "Standby",
    snapshotState = "Absent",
    snapshotAuthority = NoEpoch,
    snapshotBinding = NoBinding,
    snapshotLive = {},
    snapshottedBindings = {0},
    readyBindings = {0},
    reboundBindings = {0},

    syscallState = [s \in Syscalls |-> "Unused"],
    operation = [s \in Syscalls |-> "None"],
    syscallAuthority = [s \in Syscalls |-> NoEpoch],
    syscallBinding = [s \in Syscalls |-> NoBinding],
    continuationState = [s \in Syscalls |-> "Absent"],
    preparedReply = [s \in Syscalls |-> "None"],

    backendCommitCount = [s \in Syscalls |-> 0],
    replyPublicationCount = [s \in Syscalls |-> 0],
    continuationConsumptionCount = [s \in Syscalls |-> 0],
    terminalCount = [s \in Syscalls |-> 0],
    resumeCount = [s \in Syscalls |-> 0],
    exitCount = [s \in Syscalls |-> 0],
    abortCount = [s \in Syscalls |-> 0],

    replyAttemptCount = [s \in Syscalls |-> 0],
    replyAcceptCount = [s \in Syscalls |-> 0],
    replyRejectCount = [s \in Syscalls |-> 0],
    replyAcceptedAuthority = [s \in Syscalls |-> NoEpoch],
    replyAcceptedBinding = [s \in Syscalls |-> NoBinding],
    lastReplyRejectReason = [s \in Syscalls |-> "None"],
    oldBindingOnlyRejectSeen = [s \in Syscalls |-> FALSE],
    adoptCount = [s \in Syscalls |-> 0],

    backendCommittedAtClose = {},
    serviceRepliedAtClose = {},
    adoptCountAtClose = [s \in Syscalls |-> 0],
    closureTargetCount = 0,
    closureSteps = 0,
    backendCommittedAtLastCrash = {},
    lastCrashBinding = 0;

process PersonalityEnvironment = "personality-environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* Capture(s, operation): the kernel blocks one task behind a
            \* one-shot continuation and captures both CSER generations.
            with s \in Syscalls,
                 selectedOperation \in {"Write", "ExitGroup"} do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ syscallState[s] = "Unused";
                syscallState[s] := "Captured";
                operation[s] := selectedOperation;
                syscallAuthority[s] := authorityEpoch;
                syscallBinding[s] := bindingEpoch;
                continuationState[s] := "Pending";
            end with;
        or
            \* PrepareReply(s): retain a type-matching reply in kernel-owned
            \* state without changing guest task state or external output.
            with s \in Syscalls do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ syscallState[s] = "Captured"
                      /\ syscallAuthority[s] = authorityEpoch
                      /\ syscallBinding[s] = bindingEpoch
                      /\ continuationState[s] = "Pending";
                syscallState[s] := "ReplyPrepared";
                if operation[s] = "Write" then
                    preparedReply[s] := "WriteReturned";
                else
                    preparedReply[s] := "ExitGroupRequested";
                end if;
            end with;
        or
            \* BackendCommit(s): THE external-output commit point.  Only a
            \* prepared write may create this kernel-owned obligation.  It
            \* neither publishes a guest return nor consumes the continuation.
            with s \in Syscalls do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ syscallState[s] = "ReplyPrepared"
                      /\ operation[s] = "Write"
                      /\ preparedReply[s] = "WriteReturned"
                      /\ syscallAuthority[s] = authorityEpoch
                      /\ syscallBinding[s] = bindingEpoch
                      /\ continuationState[s] = "Pending"
                      /\ backendCommitCount[s] = 0;
                syscallState[s] := "BackendCommitted";
                backendCommitCount[s] := backendCommitCount[s] + 1;
            end with;
        or
            \* ReplyAccept(s, token): atomically publish one guest result and
            \* consume the continuation.  A write must already have crossed
            \* BackendCommit; exit_group publishes one process exit and never
            \* resumes the trapped task.
            with s \in Syscalls,
                 presentedAuthority \in 0..1,
                 presentedBinding \in 0..MaxBinding do
                await /\ syscallState[s]
                            \in {"ReplyPrepared", "BackendCommitted"}
                      /\ (\/ /\ operation[s] = "Write"
                                /\ syscallState[s] = "BackendCommitted"
                                /\ preparedReply[s] = "WriteReturned"
                          \/ /\ operation[s] = "ExitGroup"
                                /\ syscallState[s] = "ReplyPrepared"
                                /\ preparedReply[s]
                                      = "ExitGroupRequested")
                      /\ replyAttemptCount[s] < MaxReplyAttempts
                      /\ replyAcceptCount[s] = 0
                      /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ continuationState[s] = "Pending"
                      /\ presentedAuthority = syscallAuthority[s]
                      /\ syscallAuthority[s] = authorityEpoch
                      /\ presentedBinding = syscallBinding[s]
                      /\ syscallBinding[s] = bindingEpoch;
                replyAttemptCount[s] := replyAttemptCount[s] + 1;
                replyAcceptCount[s] := replyAcceptCount[s] + 1;
                replyAcceptedAuthority[s] := presentedAuthority;
                replyAcceptedBinding[s] := presentedBinding;
                syscallState[s] := "Completed";
                continuationState[s] := "Replied";
                replyPublicationCount[s] :=
                    replyPublicationCount[s] + 1;
                continuationConsumptionCount[s] :=
                    continuationConsumptionCount[s] + 1;
                terminalCount[s] := terminalCount[s] + 1;
                if operation[s] = "Write" then
                    resumeCount[s] := resumeCount[s] + 1;
                else
                    exitCount[s] := exitCount[s] + 1;
                end if;
            end with;
        or
            \* ReplyReject(s, token): an invalid full-token attempt changes
            \* only bounded audit history.  In particular, a token retained
            \* from the pre-crash binding cannot resume or exit a task after
            \* explicit adoption into the replacement binding.
            with s \in Syscalls,
                 presentedAuthority \in 0..1,
                 presentedBinding \in 0..MaxBinding do
                await /\ syscallState[s]
                            \in {"ReplyPrepared", "BackendCommitted"}
                      /\ (\/ /\ operation[s] = "Write"
                                /\ syscallState[s] = "BackendCommitted"
                                /\ preparedReply[s] = "WriteReturned"
                          \/ /\ operation[s] = "ExitGroup"
                                /\ syscallState[s] = "ReplyPrepared"
                                /\ preparedReply[s]
                                      = "ExitGroupRequested")
                      /\ replyAttemptCount[s] < MaxReplyAttempts
                      /\ replyRejectCount[s] = 0
                      /\ ~( /\ scopeState = "Active"
                            /\ serviceAlive
                            /\ replacementState = "Bound"
                            /\ bindingEpoch \in reboundBindings
                            /\ continuationState[s] = "Pending"
                            /\ presentedAuthority = syscallAuthority[s]
                            /\ syscallAuthority[s] = authorityEpoch
                            /\ presentedBinding = syscallBinding[s]
                            /\ syscallBinding[s] = bindingEpoch );
                replyAttemptCount[s] := replyAttemptCount[s] + 1;
                replyRejectCount[s] := replyRejectCount[s] + 1;
                if /\ adoptCount[s] > 0
                   /\ scopeState = "Active"
                   /\ serviceAlive
                   /\ replacementState = "Bound"
                   /\ bindingEpoch \in reboundBindings
                   /\ continuationState[s] = "Pending"
                   /\ presentedAuthority = syscallAuthority[s]
                   /\ syscallAuthority[s] = authorityEpoch
                   /\ presentedBinding < syscallBinding[s]
                   /\ syscallBinding[s] = bindingEpoch then
                    oldBindingOnlyRejectSeen[s] := TRUE;
                end if;
                if \/ scopeState # "Active"
                   \/ ~serviceAlive
                   \/ replacementState # "Bound"
                   \/ bindingEpoch \notin reboundBindings
                   \/ continuationState[s] # "Pending" then
                    lastReplyRejectReason[s] := "GateClosed";
                elsif \/ presentedAuthority # syscallAuthority[s]
                      \/ syscallAuthority[s] # authorityEpoch then
                    lastReplyRejectReason[s] := "Authority";
                else
                    lastReplyRejectReason[s] := "Binding";
                end if;
            end with;
        or
            \* Crash advances only the service binding generation.  Prepared
            \* replies and committed write obligations remain kernel-owned.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ bindingEpoch < MaxBinding;
            backendCommittedAtLastCrash :=
                {s \in Syscalls : backendCommitCount[s] = 1};
            lastCrashBinding := bindingEpoch + 1;
            bindingEpoch := bindingEpoch + 1;
            serviceAlive := FALSE;
            replacementState := "None";
            fallbackState := "Required";
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotLive := {};
        or
            \* Snapshot records the exact orphan set after kernel fallback is
            \* active.  It is an explicit handshake step, not implicit rebind.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ snapshotState = "Absent";
            snapshotState := "Captured";
            snapshotAuthority := authorityEpoch;
            snapshotBinding := bindingEpoch;
            snapshotLive :=
                {s \in Syscalls : syscallState[s] \in LiveSyscallStates};
            snapshottedBindings :=
                snapshottedBindings \cup {bindingEpoch};
        or
            \* Ready accepts only the still-current snapshot generation and
            \* exact orphan set.  No environment action is assumed fair.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ snapshotState = "Captured"
                  /\ snapshotAuthority = authorityEpoch
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotLive =
                        {s \in Syscalls :
                            syscallState[s] \in LiveSyscallStates};
            replacementState := "Ready";
            readyBindings := readyBindings \cup {bindingEpoch};
        or
            \* Rebind installs the ready replacement without advancing either
            \* generation.  Every orphan still needs an explicit Adopt.
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready"
                  /\ snapshotState = "Captured"
                  /\ snapshotAuthority = authorityEpoch
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotLive =
                        {s \in Syscalls :
                            syscallState[s] \in LiveSyscallStates}
                  /\ bindingEpoch \in readyBindings;
            serviceAlive := TRUE;
            replacementState := "Bound";
            fallbackState := "Standby";
            reboundBindings := reboundBindings \cup {bindingEpoch};
            snapshotState := "Absent";
            snapshotAuthority := NoEpoch;
            snapshotBinding := NoBinding;
            snapshotLive := {};
        or
            \* Adopt transfers only reply authority.  It never recreates a
            \* committed write obligation and is forbidden after closure.
            with s \in Syscalls do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ syscallState[s] \in LiveSyscallStates
                      /\ syscallAuthority[s] = authorityEpoch
                      /\ syscallBinding[s] # bindingEpoch;
                syscallBinding[s] := bindingEpoch;
                adoptCount[s] := adoptCount[s] + 1;
            end with;
        or
            \* RevokeBegin closes the authority/reply gate atomically and
            \* snapshots the exact scope-local reverse-index work bound.
            await scopeState = "Active";
            backendCommittedAtClose :=
                {s \in Syscalls : backendCommitCount[s] = 1};
            serviceRepliedAtClose :=
                {s \in Syscalls : replyAcceptCount[s] = 1};
            adoptCountAtClose := adoptCount;
            closureTargetCount :=
                Cardinality({s \in Syscalls :
                    syscallState[s] \in LiveSyscallStates});
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
            snapshotLive := {};
        end either;
    end while;
end process;

\* A crashed personality cannot strand execution merely because user-space
\* scheduling policy disappeared.  Revocation may instead close the scope.
fair process KernelFallback = "kernel-fallback"
begin
FallbackLoop:
    while TRUE do
        await fallbackState = "Required";
        fallbackState := "Running";
    end while;
end process;

\* Kernel closure is monotone and finite.  Uncommitted work aborts.  A write
\* that already crossed BackendCommit completes its existing obligation and
\* publishes exactly one return; it is not relabeled as rolled back.
fair process KernelClosure = "kernel-closure"
begin
ClosureLoop:
    while TRUE do
        either
            with s \in Syscalls do
                await /\ scopeState = "Closing"
                      /\ syscallAuthority[s] = closingEpoch
                      /\ syscallState[s] \in LiveSyscallStates;
                if syscallState[s] = "BackendCommitted" then
                    syscallState[s] := "Completed";
                    continuationState[s] := "Replied";
                    replyPublicationCount[s] :=
                        replyPublicationCount[s] + 1;
                    continuationConsumptionCount[s] :=
                        continuationConsumptionCount[s] + 1;
                    terminalCount[s] := terminalCount[s] + 1;
                    resumeCount[s] := resumeCount[s] + 1;
                else
                    syscallState[s] := "Aborted";
                    continuationState[s] := "Aborted";
                    continuationConsumptionCount[s] :=
                        continuationConsumptionCount[s] + 1;
                    terminalCount[s] := terminalCount[s] + 1;
                    abortCount[s] := abortCount[s] + 1;
                end if;
                closureSteps := closureSteps + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ \A s \in Syscalls :
                         syscallAuthority[s] = closingEpoch
                         => syscallState[s] \in TerminalSyscallStates;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "b779836" /\ chksum(tla) = "c14f2179")
VARIABLES scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, abortCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding

vars == << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, abortCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding >>

ProcSet == {"personality-environment"} \cup {"kernel-fallback"} \cup {"kernel-closure"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ serviceAlive = TRUE
        /\ bindingEpoch = 0
        /\ replacementState = "Bound"
        /\ fallbackState = "Standby"
        /\ snapshotState = "Absent"
        /\ snapshotAuthority = NoEpoch
        /\ snapshotBinding = NoBinding
        /\ snapshotLive = {}
        /\ snapshottedBindings = {0}
        /\ readyBindings = {0}
        /\ reboundBindings = {0}
        /\ syscallState = [s \in Syscalls |-> "Unused"]
        /\ operation = [s \in Syscalls |-> "None"]
        /\ syscallAuthority = [s \in Syscalls |-> NoEpoch]
        /\ syscallBinding = [s \in Syscalls |-> NoBinding]
        /\ continuationState = [s \in Syscalls |-> "Absent"]
        /\ preparedReply = [s \in Syscalls |-> "None"]
        /\ backendCommitCount = [s \in Syscalls |-> 0]
        /\ replyPublicationCount = [s \in Syscalls |-> 0]
        /\ continuationConsumptionCount = [s \in Syscalls |-> 0]
        /\ terminalCount = [s \in Syscalls |-> 0]
        /\ resumeCount = [s \in Syscalls |-> 0]
        /\ exitCount = [s \in Syscalls |-> 0]
        /\ abortCount = [s \in Syscalls |-> 0]
        /\ replyAttemptCount = [s \in Syscalls |-> 0]
        /\ replyAcceptCount = [s \in Syscalls |-> 0]
        /\ replyRejectCount = [s \in Syscalls |-> 0]
        /\ replyAcceptedAuthority = [s \in Syscalls |-> NoEpoch]
        /\ replyAcceptedBinding = [s \in Syscalls |-> NoBinding]
        /\ lastReplyRejectReason = [s \in Syscalls |-> "None"]
        /\ oldBindingOnlyRejectSeen = [s \in Syscalls |-> FALSE]
        /\ adoptCount = [s \in Syscalls |-> 0]
        /\ backendCommittedAtClose = {}
        /\ serviceRepliedAtClose = {}
        /\ adoptCountAtClose = [s \in Syscalls |-> 0]
        /\ closureTargetCount = 0
        /\ closureSteps = 0
        /\ backendCommittedAtLastCrash = {}
        /\ lastCrashBinding = 0

PersonalityEnvironment == /\ \/ /\ \E s \in Syscalls:
                                     \E selectedOperation \in {"Write", "ExitGroup"}:
                                       /\ /\ scopeState = "Active"
                                          /\ serviceAlive
                                          /\ replacementState = "Bound"
                                          /\ bindingEpoch \in reboundBindings
                                          /\ syscallState[s] = "Unused"
                                       /\ syscallState' = [syscallState EXCEPT ![s] = "Captured"]
                                       /\ operation' = [operation EXCEPT ![s] = selectedOperation]
                                       /\ syscallAuthority' = [syscallAuthority EXCEPT ![s] = authorityEpoch]
                                       /\ syscallBinding' = [syscallBinding EXCEPT ![s] = bindingEpoch]
                                       /\ continuationState' = [continuationState EXCEPT ![s] = "Pending"]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ \E s \in Syscalls:
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ bindingEpoch \in reboundBindings
                                        /\ syscallState[s] = "Captured"
                                        /\ syscallAuthority[s] = authorityEpoch
                                        /\ syscallBinding[s] = bindingEpoch
                                        /\ continuationState[s] = "Pending"
                                     /\ syscallState' = [syscallState EXCEPT ![s] = "ReplyPrepared"]
                                     /\ IF operation[s] = "Write"
                                           THEN /\ preparedReply' = [preparedReply EXCEPT ![s] = "WriteReturned"]
                                           ELSE /\ preparedReply' = [preparedReply EXCEPT ![s] = "ExitGroupRequested"]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, operation, syscallAuthority, syscallBinding, continuationState, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ \E s \in Syscalls:
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ bindingEpoch \in reboundBindings
                                        /\ syscallState[s] = "ReplyPrepared"
                                        /\ operation[s] = "Write"
                                        /\ preparedReply[s] = "WriteReturned"
                                        /\ syscallAuthority[s] = authorityEpoch
                                        /\ syscallBinding[s] = bindingEpoch
                                        /\ continuationState[s] = "Pending"
                                        /\ backendCommitCount[s] = 0
                                     /\ syscallState' = [syscallState EXCEPT ![s] = "BackendCommitted"]
                                     /\ backendCommitCount' = [backendCommitCount EXCEPT ![s] = backendCommitCount[s] + 1]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ \E s \in Syscalls:
                                     \E presentedAuthority \in 0..1:
                                       \E presentedBinding \in 0..MaxBinding:
                                         /\ /\ syscallState[s]
                                                  \in {"ReplyPrepared", "BackendCommitted"}
                                            /\ (\/ /\ operation[s] = "Write"
                                                      /\ syscallState[s] = "BackendCommitted"
                                                      /\ preparedReply[s] = "WriteReturned"
                                                \/ /\ operation[s] = "ExitGroup"
                                                      /\ syscallState[s] = "ReplyPrepared"
                                                      /\ preparedReply[s]
                                                            = "ExitGroupRequested")
                                            /\ replyAttemptCount[s] < MaxReplyAttempts
                                            /\ replyAcceptCount[s] = 0
                                            /\ scopeState = "Active"
                                            /\ serviceAlive
                                            /\ replacementState = "Bound"
                                            /\ bindingEpoch \in reboundBindings
                                            /\ continuationState[s] = "Pending"
                                            /\ presentedAuthority = syscallAuthority[s]
                                            /\ syscallAuthority[s] = authorityEpoch
                                            /\ presentedBinding = syscallBinding[s]
                                            /\ syscallBinding[s] = bindingEpoch
                                         /\ replyAttemptCount' = [replyAttemptCount EXCEPT ![s] = replyAttemptCount[s] + 1]
                                         /\ replyAcceptCount' = [replyAcceptCount EXCEPT ![s] = replyAcceptCount[s] + 1]
                                         /\ replyAcceptedAuthority' = [replyAcceptedAuthority EXCEPT ![s] = presentedAuthority]
                                         /\ replyAcceptedBinding' = [replyAcceptedBinding EXCEPT ![s] = presentedBinding]
                                         /\ syscallState' = [syscallState EXCEPT ![s] = "Completed"]
                                         /\ continuationState' = [continuationState EXCEPT ![s] = "Replied"]
                                         /\ replyPublicationCount' = [replyPublicationCount EXCEPT ![s] = replyPublicationCount[s] + 1]
                                         /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![s] = continuationConsumptionCount[s] + 1]
                                         /\ terminalCount' = [terminalCount EXCEPT ![s] = terminalCount[s] + 1]
                                         /\ IF operation[s] = "Write"
                                               THEN /\ resumeCount' = [resumeCount EXCEPT ![s] = resumeCount[s] + 1]
                                                    /\ UNCHANGED exitCount
                                               ELSE /\ exitCount' = [exitCount EXCEPT ![s] = exitCount[s] + 1]
                                                    /\ UNCHANGED resumeCount
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, operation, syscallAuthority, syscallBinding, preparedReply, backendCommitCount, replyRejectCount, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ \E s \in Syscalls:
                                     \E presentedAuthority \in 0..1:
                                       \E presentedBinding \in 0..MaxBinding:
                                         /\ /\ syscallState[s]
                                                  \in {"ReplyPrepared", "BackendCommitted"}
                                            /\ (\/ /\ operation[s] = "Write"
                                                      /\ syscallState[s] = "BackendCommitted"
                                                      /\ preparedReply[s] = "WriteReturned"
                                                \/ /\ operation[s] = "ExitGroup"
                                                      /\ syscallState[s] = "ReplyPrepared"
                                                      /\ preparedReply[s]
                                                            = "ExitGroupRequested")
                                            /\ replyAttemptCount[s] < MaxReplyAttempts
                                            /\ replyRejectCount[s] = 0
                                            /\ ~( /\ scopeState = "Active"
                                                  /\ serviceAlive
                                                  /\ replacementState = "Bound"
                                                  /\ bindingEpoch \in reboundBindings
                                                  /\ continuationState[s] = "Pending"
                                                  /\ presentedAuthority = syscallAuthority[s]
                                                  /\ syscallAuthority[s] = authorityEpoch
                                                  /\ presentedBinding = syscallBinding[s]
                                                  /\ syscallBinding[s] = bindingEpoch )
                                         /\ replyAttemptCount' = [replyAttemptCount EXCEPT ![s] = replyAttemptCount[s] + 1]
                                         /\ replyRejectCount' = [replyRejectCount EXCEPT ![s] = replyRejectCount[s] + 1]
                                         /\ IF /\ adoptCount[s] > 0
                                               /\ scopeState = "Active"
                                               /\ serviceAlive
                                               /\ replacementState = "Bound"
                                               /\ bindingEpoch \in reboundBindings
                                               /\ continuationState[s] = "Pending"
                                               /\ presentedAuthority = syscallAuthority[s]
                                               /\ syscallAuthority[s] = authorityEpoch
                                               /\ presentedBinding < syscallBinding[s]
                                               /\ syscallBinding[s] = bindingEpoch
                                               THEN /\ oldBindingOnlyRejectSeen' = [oldBindingOnlyRejectSeen EXCEPT ![s] = TRUE]
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED oldBindingOnlyRejectSeen
                                         /\ IF \/ scopeState # "Active"
                                               \/ ~serviceAlive
                                               \/ replacementState # "Bound"
                                               \/ bindingEpoch \notin reboundBindings
                                               \/ continuationState[s] # "Pending"
                                               THEN /\ lastReplyRejectReason' = [lastReplyRejectReason EXCEPT ![s] = "GateClosed"]
                                               ELSE /\ IF \/ presentedAuthority # syscallAuthority[s]
                                                          \/ syscallAuthority[s] # authorityEpoch
                                                          THEN /\ lastReplyRejectReason' = [lastReplyRejectReason EXCEPT ![s] = "Authority"]
                                                          ELSE /\ lastReplyRejectReason' = [lastReplyRejectReason EXCEPT ![s] = "Binding"]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAcceptCount, replyAcceptedAuthority, replyAcceptedBinding, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ serviceAlive
                                   /\ bindingEpoch < MaxBinding
                                /\ backendCommittedAtLastCrash' = {s \in Syscalls : backendCommitCount[s] = 1}
                                /\ lastCrashBinding' = bindingEpoch + 1
                                /\ bindingEpoch' = bindingEpoch + 1
                                /\ serviceAlive' = FALSE
                                /\ replacementState' = "None"
                                /\ fallbackState' = "Required"
                                /\ snapshotState' = "Absent"
                                /\ snapshotAuthority' = NoEpoch
                                /\ snapshotBinding' = NoBinding
                                /\ snapshotLive' = {}
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "None"
                                   /\ snapshotState = "Absent"
                                /\ snapshotState' = "Captured"
                                /\ snapshotAuthority' = authorityEpoch
                                /\ snapshotBinding' = bindingEpoch
                                /\ snapshotLive' = {s \in Syscalls : syscallState[s] \in LiveSyscallStates}
                                /\ snapshottedBindings' = (snapshottedBindings \cup {bindingEpoch})
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "None"
                                   /\ snapshotState = "Captured"
                                   /\ snapshotAuthority = authorityEpoch
                                   /\ snapshotBinding = bindingEpoch
                                   /\ snapshotLive =
                                         {s \in Syscalls :
                                             syscallState[s] \in LiveSyscallStates}
                                /\ replacementState' = "Ready"
                                /\ readyBindings' = (readyBindings \cup {bindingEpoch})
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ /\ scopeState = "Active"
                                   /\ ~serviceAlive
                                   /\ fallbackState = "Running"
                                   /\ replacementState = "Ready"
                                   /\ snapshotState = "Captured"
                                   /\ snapshotAuthority = authorityEpoch
                                   /\ snapshotBinding = bindingEpoch
                                   /\ snapshotLive =
                                         {s \in Syscalls :
                                             syscallState[s] \in LiveSyscallStates}
                                   /\ bindingEpoch \in readyBindings
                                /\ serviceAlive' = TRUE
                                /\ replacementState' = "Bound"
                                /\ fallbackState' = "Standby"
                                /\ reboundBindings' = (reboundBindings \cup {bindingEpoch})
                                /\ snapshotState' = "Absent"
                                /\ snapshotAuthority' = NoEpoch
                                /\ snapshotBinding' = NoBinding
                                /\ snapshotLive' = {}
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, bindingEpoch, snapshottedBindings, readyBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ \E s \in Syscalls:
                                     /\ /\ scopeState = "Active"
                                        /\ serviceAlive
                                        /\ replacementState = "Bound"
                                        /\ bindingEpoch \in reboundBindings
                                        /\ syscallState[s] \in LiveSyscallStates
                                        /\ syscallAuthority[s] = authorityEpoch
                                        /\ syscallBinding[s] # bindingEpoch
                                     /\ syscallBinding' = [syscallBinding EXCEPT ![s] = bindingEpoch]
                                     /\ adoptCount' = [adoptCount EXCEPT ![s] = adoptCount[s] + 1]
                                /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding>>
                             \/ /\ scopeState = "Active"
                                /\ backendCommittedAtClose' = {s \in Syscalls : backendCommitCount[s] = 1}
                                /\ serviceRepliedAtClose' = {s \in Syscalls : replyAcceptCount[s] = 1}
                                /\ adoptCountAtClose' = adoptCount
                                /\ closureTargetCount' = Cardinality({s \in Syscalls :
                                                             syscallState[s] \in LiveSyscallStates})
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
                                /\ snapshotLive' = {}
                                /\ UNCHANGED <<bindingEpoch, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtLastCrash, lastCrashBinding>>
                          /\ UNCHANGED abortCount

KernelFallback == /\ fallbackState = "Required"
                  /\ fallbackState' = "Running"
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, syscallState, operation, syscallAuthority, syscallBinding, continuationState, preparedReply, backendCommitCount, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, exitCount, abortCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, closureSteps, backendCommittedAtLastCrash, lastCrashBinding >>

KernelClosure == /\ \/ /\ \E s \in Syscalls:
                            /\ /\ scopeState = "Closing"
                               /\ syscallAuthority[s] = closingEpoch
                               /\ syscallState[s] \in LiveSyscallStates
                            /\ IF syscallState[s] = "BackendCommitted"
                                  THEN /\ syscallState' = [syscallState EXCEPT ![s] = "Completed"]
                                       /\ continuationState' = [continuationState EXCEPT ![s] = "Replied"]
                                       /\ replyPublicationCount' = [replyPublicationCount EXCEPT ![s] = replyPublicationCount[s] + 1]
                                       /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![s] = continuationConsumptionCount[s] + 1]
                                       /\ terminalCount' = [terminalCount EXCEPT ![s] = terminalCount[s] + 1]
                                       /\ resumeCount' = [resumeCount EXCEPT ![s] = resumeCount[s] + 1]
                                       /\ UNCHANGED abortCount
                                  ELSE /\ syscallState' = [syscallState EXCEPT ![s] = "Aborted"]
                                       /\ continuationState' = [continuationState EXCEPT ![s] = "Aborted"]
                                       /\ continuationConsumptionCount' = [continuationConsumptionCount EXCEPT ![s] = continuationConsumptionCount[s] + 1]
                                       /\ terminalCount' = [terminalCount EXCEPT ![s] = terminalCount[s] + 1]
                                       /\ abortCount' = [abortCount EXCEPT ![s] = abortCount[s] + 1]
                                       /\ UNCHANGED << replyPublicationCount, resumeCount >>
                            /\ closureSteps' = closureSteps + 1
                       /\ UNCHANGED scopeState
                    \/ /\ /\ scopeState = "Closing"
                          /\ \A s \in Syscalls :
                                 syscallAuthority[s] = closingEpoch
                                 => syscallState[s] \in TerminalSyscallStates
                       /\ scopeState' = "Revoked"
                       /\ UNCHANGED <<syscallState, continuationState, replyPublicationCount, continuationConsumptionCount, terminalCount, resumeCount, abortCount, closureSteps>>
                 /\ UNCHANGED << authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, replacementState, fallbackState, snapshotState, snapshotAuthority, snapshotBinding, snapshotLive, snapshottedBindings, readyBindings, reboundBindings, operation, syscallAuthority, syscallBinding, preparedReply, backendCommitCount, exitCount, replyAttemptCount, replyAcceptCount, replyRejectCount, replyAcceptedAuthority, replyAcceptedBinding, lastReplyRejectReason, oldBindingOnlyRejectSeen, adoptCount, backendCommittedAtClose, serviceRepliedAtClose, adoptCountAtClose, closureTargetCount, backendCommittedAtLastCrash, lastCrashBinding >>

Next == PersonalityEnvironment \/ KernelFallback \/ KernelClosure

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(KernelFallback)
        /\ WF_vars(KernelClosure)

\* END TRANSLATION

(***************************************************************************)
(* Safety predicates checked by TLC.                                      *)
(***************************************************************************)

CurrentLiveSyscalls ==
    {s \in Syscalls : syscallState[s] \in LiveSyscallStates}

SyscallToken(s) ==
    [scope |-> Scope,
     syscall |-> s,
     operation |-> operation[s],
     authority_epoch |-> syscallAuthority[s],
     binding_epoch |-> syscallBinding[s]]

PresentedSyscallToken(s, authority, binding) ==
    [scope |-> Scope,
     syscall |-> s,
     operation |-> operation[s],
     authority_epoch |-> authority,
     binding_epoch |-> binding]

TypeOK ==
    /\ scopeState \in ScopeStates
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ serviceAlive \in BOOLEAN
    /\ bindingEpoch \in 0..MaxBinding
    /\ replacementState \in ReplacementStates
    /\ fallbackState \in FallbackStates
    /\ snapshotState \in SnapshotStates
    /\ snapshotAuthority \in ({NoEpoch} \cup {0})
    /\ snapshotBinding \in ({NoBinding} \cup (0..MaxBinding))
    /\ snapshotLive \subseteq Syscalls
    /\ snapshottedBindings \subseteq (0..MaxBinding)
    /\ readyBindings \subseteq (0..MaxBinding)
    /\ reboundBindings \subseteq (0..MaxBinding)
    /\ syscallState \in [Syscalls -> SyscallStates]
    /\ operation \in [Syscalls -> OperationStates]
    /\ syscallAuthority \in [Syscalls -> ({NoEpoch} \cup {0})]
    /\ syscallBinding
          \in [Syscalls -> ({NoBinding} \cup (0..MaxBinding))]
    /\ continuationState \in [Syscalls -> ContinuationStates]
    /\ preparedReply \in [Syscalls -> PreparedReplyStates]
    /\ backendCommitCount \in [Syscalls -> {0, 1}]
    /\ replyPublicationCount \in [Syscalls -> {0, 1}]
    /\ continuationConsumptionCount \in [Syscalls -> {0, 1}]
    /\ terminalCount \in [Syscalls -> {0, 1}]
    /\ resumeCount \in [Syscalls -> {0, 1}]
    /\ exitCount \in [Syscalls -> {0, 1}]
    /\ abortCount \in [Syscalls -> {0, 1}]
    /\ replyAttemptCount
          \in [Syscalls -> (0..MaxReplyAttempts)]
    /\ replyAcceptCount \in [Syscalls -> {0, 1}]
    /\ replyRejectCount \in [Syscalls -> {0, 1}]
    /\ replyAcceptedAuthority
          \in [Syscalls -> ({NoEpoch} \cup {0})]
    /\ replyAcceptedBinding
          \in [Syscalls -> ({NoBinding} \cup (0..MaxBinding))]
    /\ lastReplyRejectReason \in [Syscalls -> ReplyRejectReasons]
    /\ oldBindingOnlyRejectSeen \in [Syscalls -> BOOLEAN]
    /\ adoptCount \in [Syscalls -> (0..MaxBinding)]
    /\ backendCommittedAtClose \subseteq Syscalls
    /\ serviceRepliedAtClose \subseteq Syscalls
    /\ adoptCountAtClose \in [Syscalls -> (0..MaxBinding)]
    /\ closureTargetCount \in 0..Cardinality(Syscalls)
    /\ closureSteps \in 0..Cardinality(Syscalls)
    /\ backendCommittedAtLastCrash \subseteq Syscalls
    /\ lastCrashBinding \in 0..MaxBinding

SyscallTokensTypeOK ==
    /\ \A s \in Syscalls :
           SyscallToken(s)
             \in [scope : {Scope},
                  syscall : Syscalls,
                  operation : OperationStates,
                  authority_epoch : ({NoEpoch} \cup {0}),
                  binding_epoch :
                      ({NoBinding} \cup (0..MaxBinding))]
    /\ \A s \in Syscalls,
          authority \in 0..1,
          binding \in 0..MaxBinding :
           PresentedSyscallToken(s, authority, binding)
             \in [scope : {Scope},
                  syscall : Syscalls,
                  operation : OperationStates,
                  authority_epoch : (0..1),
                  binding_epoch : (0..MaxBinding)]

SyscallLifecycleConsistency ==
    \A s \in Syscalls :
        CASE syscallState[s] = "Unused" ->
                 /\ operation[s] = "None"
                 /\ syscallAuthority[s] = NoEpoch
                 /\ syscallBinding[s] = NoBinding
                 /\ continuationState[s] = "Absent"
                 /\ preparedReply[s] = "None"
                 /\ backendCommitCount[s] = 0
                 /\ replyPublicationCount[s] = 0
                 /\ continuationConsumptionCount[s] = 0
                 /\ terminalCount[s] = 0
                 /\ resumeCount[s] = 0
                 /\ exitCount[s] = 0
                 /\ abortCount[s] = 0
          [] syscallState[s] = "Captured" ->
                 /\ operation[s] \in {"Write", "ExitGroup"}
                 /\ syscallAuthority[s] = 0
                 /\ syscallBinding[s] \in 0..MaxBinding
                 /\ continuationState[s] = "Pending"
                 /\ preparedReply[s] = "None"
                 /\ backendCommitCount[s] = 0
                 /\ replyPublicationCount[s] = 0
                 /\ continuationConsumptionCount[s] = 0
                 /\ terminalCount[s] = 0
                 /\ resumeCount[s] = 0
                 /\ exitCount[s] = 0
                 /\ abortCount[s] = 0
          [] syscallState[s] = "ReplyPrepared" ->
                 /\ operation[s] \in {"Write", "ExitGroup"}
                 /\ continuationState[s] = "Pending"
                 /\ preparedReply[s] =
                       IF operation[s] = "Write"
                       THEN "WriteReturned"
                       ELSE "ExitGroupRequested"
                 /\ backendCommitCount[s] = 0
                 /\ replyPublicationCount[s] = 0
                 /\ continuationConsumptionCount[s] = 0
                 /\ terminalCount[s] = 0
                 /\ resumeCount[s] = 0
                 /\ exitCount[s] = 0
                 /\ abortCount[s] = 0
          [] syscallState[s] = "BackendCommitted" ->
                 /\ operation[s] = "Write"
                 /\ continuationState[s] = "Pending"
                 /\ preparedReply[s] = "WriteReturned"
                 /\ backendCommitCount[s] = 1
                 /\ replyPublicationCount[s] = 0
                 /\ continuationConsumptionCount[s] = 0
                 /\ terminalCount[s] = 0
                 /\ resumeCount[s] = 0
                 /\ exitCount[s] = 0
                 /\ abortCount[s] = 0
          [] syscallState[s] = "Completed" ->
                 /\ continuationState[s] = "Replied"
                 /\ replyPublicationCount[s] = 1
                 /\ continuationConsumptionCount[s] = 1
                 /\ terminalCount[s] = 1
                 /\ abortCount[s] = 0
                 /\ IF operation[s] = "Write"
                       THEN /\ preparedReply[s] = "WriteReturned"
                            /\ backendCommitCount[s] = 1
                            /\ resumeCount[s] = 1
                            /\ exitCount[s] = 0
                       ELSE /\ operation[s] = "ExitGroup"
                            /\ preparedReply[s]
                                  = "ExitGroupRequested"
                            /\ backendCommitCount[s] = 0
                            /\ resumeCount[s] = 0
                            /\ exitCount[s] = 1
          [] syscallState[s] = "Aborted" ->
                 /\ operation[s] \in {"Write", "ExitGroup"}
                 /\ continuationState[s] = "Aborted"
                 /\ preparedReply[s]
                       \in {"None", "WriteReturned",
                            "ExitGroupRequested"}
                 /\ (preparedReply[s] = "WriteReturned"
                       => operation[s] = "Write")
                 /\ (preparedReply[s] = "ExitGroupRequested"
                       => operation[s] = "ExitGroup")
                 /\ backendCommitCount[s] = 0
                 /\ replyPublicationCount[s] = 0
                 /\ continuationConsumptionCount[s] = 1
                 /\ terminalCount[s] = 1
                 /\ resumeCount[s] = 0
                 /\ exitCount[s] = 0
                 /\ abortCount[s] = 1

OneShotDelivery ==
    \A s \in Syscalls :
        /\ backendCommitCount[s] \in {0, 1}
        /\ replyPublicationCount[s] \in {0, 1}
        /\ continuationConsumptionCount[s] \in {0, 1}
        /\ terminalCount[s] \in {0, 1}
        /\ resumeCount[s] \in {0, 1}
        /\ exitCount[s] \in {0, 1}
        /\ abortCount[s] \in {0, 1}
        /\ (continuationConsumptionCount[s] = 1)
              <=> (syscallState[s] \in TerminalSyscallStates)
        /\ terminalCount[s] = continuationConsumptionCount[s]
        /\ (replyPublicationCount[s] = 1)
              <=> (syscallState[s] = "Completed")
        /\ (resumeCount[s] = 1)
              <=> /\ syscallState[s] = "Completed"
                  /\ operation[s] = "Write"
        /\ (exitCount[s] = 1)
              <=> /\ syscallState[s] = "Completed"
                  /\ operation[s] = "ExitGroup"
        /\ (abortCount[s] = 1)
              <=> (syscallState[s] = "Aborted")

BackendCommitBeforeWriteReply ==
    \A s \in Syscalls :
        /\ (backendCommitCount[s] = 1
              => /\ operation[s] = "Write"
                 /\ preparedReply[s] = "WriteReturned"
                 /\ syscallState[s]
                       \in {"BackendCommitted", "Completed"})
        /\ (operation[s] = "Write"
              /\ replyPublicationCount[s] = 1
              => backendCommitCount[s] = 1)
        /\ (syscallState[s] = "BackendCommitted"
              => /\ replyPublicationCount[s] = 0
                 /\ resumeCount[s] = 0
                 /\ continuationState[s] = "Pending")

ExitGroupNeverResumes ==
    \A s \in Syscalls :
        operation[s] = "ExitGroup"
        => /\ backendCommitCount[s] = 0
           /\ resumeCount[s] = 0
           /\ exitCount[s] \in {0, 1}
           /\ (exitCount[s] = 1
                 => /\ syscallState[s] = "Completed"
                    /\ replyPublicationCount[s] = 1)

ReplyReady(s) ==
    /\ continuationState[s] = "Pending"
    /\ (\/ /\ operation[s] = "Write"
              /\ syscallState[s] = "BackendCommitted"
              /\ preparedReply[s] = "WriteReturned"
        \/ /\ operation[s] = "ExitGroup"
              /\ syscallState[s] = "ReplyPrepared"
              /\ preparedReply[s] = "ExitGroupRequested")

ReplyTokenMatchesCurrentGate(s, authority, binding) ==
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ ReplyReady(s)
    /\ authority = syscallAuthority[s]
    /\ syscallAuthority[s] = authorityEpoch
    /\ binding = syscallBinding[s]
    /\ syscallBinding[s] = bindingEpoch

ReplyAttemptEnabled(s, authority, binding) ==
    /\ ReplyReady(s)
    /\ replyAttemptCount[s] < MaxReplyAttempts
    /\ authority \in 0..1
    /\ binding \in 0..MaxBinding
    /\ IF ReplyTokenMatchesCurrentGate(s, authority, binding)
          THEN replyAcceptCount[s] = 0
          ELSE replyRejectCount[s] = 0

ReplyTokenCanPublish(s, authority, binding) ==
    /\ ReplyAttemptEnabled(s, authority, binding)
    /\ ReplyTokenMatchesCurrentGate(s, authority, binding)

ReplyTokenFencing ==
    /\ \A s \in Syscalls :
           /\ replyAttemptCount[s]
                 = replyAcceptCount[s] + replyRejectCount[s]
           /\ replyAcceptCount[s] \in {0, 1}
           /\ replyRejectCount[s] \in {0, 1}
           /\ (replyRejectCount[s] = 0)
                 <=> (lastReplyRejectReason[s] = "None")
           /\ (oldBindingOnlyRejectSeen[s]
                 => /\ replyRejectCount[s] = 1
                    /\ adoptCount[s] > 0
                    /\ lastReplyRejectReason[s] = "Binding")
           /\ (replyAcceptCount[s] = 1
                 => /\ syscallState[s] = "Completed"
                    /\ replyPublicationCount[s] = 1
                    /\ replyAcceptedAuthority[s]
                          = syscallAuthority[s]
                    /\ replyAcceptedBinding[s] = syscallBinding[s]
                    /\ replyAcceptedBinding[s] \in reboundBindings)
           /\ (replyAcceptCount[s] = 0
                 => /\ replyAcceptedAuthority[s] = NoEpoch
                    /\ replyAcceptedBinding[s] = NoBinding)
    /\ \A s \in Syscalls,
          authority \in 0..1,
          binding \in 0..MaxBinding :
           /\ (ReplyTokenCanPublish(s, authority, binding)
                 => /\ authority = syscallAuthority[s]
                    /\ binding = syscallBinding[s])
           /\ (\/ scopeState # "Active"
                \/ ~serviceAlive
                \/ ~ReplyReady(s)
                \/ authority # syscallAuthority[s]
                \/ syscallAuthority[s] # authorityEpoch
                \/ binding # syscallBinding[s]
                \/ syscallBinding[s] # bindingEpoch)
                 => ~ReplyTokenCanPublish(s, authority, binding)

PrepareReplyEnabled(s) ==
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ syscallState[s] = "Captured"
    /\ syscallAuthority[s] = authorityEpoch
    /\ syscallBinding[s] = bindingEpoch
    /\ continuationState[s] = "Pending"

BackendCommitEnabled(s) ==
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ syscallState[s] = "ReplyPrepared"
    /\ operation[s] = "Write"
    /\ preparedReply[s] = "WriteReturned"
    /\ syscallAuthority[s] = authorityEpoch
    /\ syscallBinding[s] = bindingEpoch
    /\ continuationState[s] = "Pending"
    /\ backendCommitCount[s] = 0

AdoptEnabled(s) ==
    /\ scopeState = "Active"
    /\ serviceAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ syscallState[s] \in LiveSyscallStates
    /\ syscallAuthority[s] = authorityEpoch
    /\ syscallBinding[s] # bindingEpoch

SnapshotAndRebindDiscipline ==
    /\ reboundBindings \subseteq readyBindings
    /\ readyBindings \subseteq snapshottedBindings
    /\ (serviceAlive <=> replacementState = "Bound")
    /\ (snapshotState = "Captured"
          => /\ scopeState = "Active"
             /\ ~serviceAlive
             /\ fallbackState = "Running"
             /\ replacementState \in {"None", "Ready"}
             /\ snapshotAuthority = authorityEpoch
             /\ snapshotBinding = bindingEpoch
             /\ snapshotBinding \in snapshottedBindings
             /\ snapshotLive = CurrentLiveSyscalls)
    /\ (snapshotState = "Absent"
          => /\ snapshotAuthority = NoEpoch
             /\ snapshotBinding = NoBinding
             /\ snapshotLive = {})
    /\ (replacementState = "Ready"
          => /\ snapshotState = "Captured"
             /\ bindingEpoch \in readyBindings)
    /\ (scopeState \in {"Closing", "Revoked"}
          => /\ ~serviceAlive
             /\ replacementState = "Closed"
             /\ fallbackState = "Closed"
             /\ snapshotState = "Absent")

CrashRebindAdoptFencing ==
    /\ \A s \in Syscalls :
           /\ syscallState[s] \in LiveSyscallStates
           /\ syscallBinding[s] < bindingEpoch
           => /\ ~PrepareReplyEnabled(s)
              /\ ~BackendCommitEnabled(s)
              /\ \A authority \in 0..1,
                    oldBinding \in 0..MaxBinding :
                     ~ReplyTokenCanPublish(
                         s, authority, oldBinding)
    /\ \A s \in Syscalls :
           /\ backendCommitCount[s] = 1
           /\ s \notin backendCommittedAtLastCrash
           => syscallBinding[s] >= lastCrashBinding
    /\ (scopeState \in {"Closing", "Revoked"}
          => /\ adoptCount = adoptCountAtClose
             /\ \A s \in Syscalls : ~AdoptEnabled(s))

PostRevokeCommitAndReplyExclusion ==
    scopeState \in {"Closing", "Revoked"}
    => /\ \A s \in Syscalls :
              backendCommitCount[s] = 1
              => s \in backendCommittedAtClose
       /\ \A s \in Syscalls :
              replyAcceptCount[s] = 1
              => s \in serviceRepliedAtClose
       /\ \A s \in Syscalls : ~BackendCommitEnabled(s)
       /\ \A s \in Syscalls,
             authority \in 0..1,
             binding \in 0..MaxBinding :
              ~ReplyTokenCanPublish(s, authority, binding)

ClosureAccounting ==
    /\ closureSteps <= closureTargetCount
    /\ (scopeState \in {"Closing", "Revoked"}
          => closureSteps
               + Cardinality({s \in Syscalls :
                    /\ syscallAuthority[s] = closingEpoch
                    /\ syscallState[s] \in LiveSyscallStates})
               = closureTargetCount)

QuiescentClosure ==
    scopeState = "Revoked"
    => /\ closingEpoch # NoEpoch
       /\ ~serviceAlive
       /\ closureSteps = closureTargetCount
       /\ \A s \in Syscalls :
              syscallAuthority[s] = closingEpoch
              => syscallState[s] \in TerminalSyscallStates

(***************************************************************************)
(* Coverage witnesses.  check.sh deliberately asks TLC to falsify each    *)
(* corresponding *Absent invariant.                                      *)
(***************************************************************************)

OldBindingRecoveryObserved ==
    \E s \in Syscalls :
        /\ syscallState[s] = "Completed"
        /\ operation[s] = "Write"
        /\ s \in backendCommittedAtLastCrash
        /\ oldBindingOnlyRejectSeen[s]
        /\ adoptCount[s] > 0
        /\ backendCommitCount[s] = 1
        /\ replyAcceptCount[s] = 1
        /\ replyPublicationCount[s] = 1
        /\ resumeCount[s] = 1

ExitGroupDeliveryObserved ==
    \E s \in Syscalls :
        /\ syscallState[s] = "Completed"
        /\ operation[s] = "ExitGroup"
        /\ backendCommitCount[s] = 0
        /\ replyPublicationCount[s] = 1
        /\ resumeCount[s] = 0
        /\ exitCount[s] = 1

RevocationSplitObserved ==
    /\ scopeState = "Revoked"
    /\ \E committed \in Syscalls,
          uncommitted \in Syscalls :
           /\ committed # uncommitted
           /\ committed \in backendCommittedAtClose
           /\ operation[committed] = "Write"
           /\ syscallState[committed] = "Completed"
           /\ backendCommitCount[committed] = 1
           /\ replyAcceptCount[committed] = 0
           /\ replyPublicationCount[committed] = 1
           /\ resumeCount[committed] = 1
           /\ syscallState[uncommitted] = "Aborted"
           /\ abortCount[uncommitted] = 1

OldBindingRecoveryAbsent == ~OldBindingRecoveryObserved
ExitGroupDeliveryAbsent == ~ExitGroupDeliveryObserved
RevocationSplitAbsent == ~RevocationSplitObserved

(***************************************************************************)
(* Action properties and conditional liveness.  Only kernel processes are *)
(* weakly fair; snapshot, ready, rebind, adopt, and reply remain unfair.   *)
(***************************************************************************)

ReplyRejectSideEffectFreedom ==
    [][
        replyRejectCount' # replyRejectCount
        => UNCHANGED <<
               scopeState, authorityEpoch, closingEpoch,
               serviceAlive, bindingEpoch, replacementState,
               fallbackState, snapshotState, snapshotAuthority,
               snapshotBinding, snapshotLive, snapshottedBindings,
               readyBindings, reboundBindings, syscallState,
               operation, syscallAuthority, syscallBinding,
               continuationState, preparedReply, backendCommitCount,
               replyPublicationCount, continuationConsumptionCount,
               terminalCount, resumeCount, exitCount, abortCount,
               replyAcceptCount, replyAcceptedAuthority,
               replyAcceptedBinding, adoptCount,
               backendCommittedAtClose, serviceRepliedAtClose,
               adoptCountAtClose, closureTargetCount, closureSteps,
               backendCommittedAtLastCrash, lastCrashBinding
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
                 /\ authorityEpoch' = authorityEpoch)
    ]_vars

FallbackOrClosureProgress ==
    (fallbackState = "Required")
      ~> (fallbackState = "Running" \/ fallbackState = "Closed")

RevocationProgress ==
    /\ \A s \in Syscalls :
           (/\ scopeState = "Closing"
            /\ syscallAuthority[s] = closingEpoch
            /\ syscallState[s] \in LiveSyscallStates)
             ~> (syscallState[s] \in TerminalSyscallStates)
    /\ (scopeState = "Closing") ~> (scopeState = "Revoked")

ReadyForRevokeComplete ==
    /\ scopeState = "Closing"
    /\ \A s \in Syscalls :
           syscallAuthority[s] = closingEpoch
           => syscallState[s] \in TerminalSyscallStates

ReadyClosureProgress ==
    ReadyForRevokeComplete ~> (scopeState = "Revoked")

=============================================================================

---------------------------- MODULE PagerCser ----------------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* A finite-state refinement of CSER for one user-space pager scope.       *)
(*                                                                         *)
(* The scope is one address space.  Each fault token carries independent   *)
(* authority, pager-binding, and address-space generations.  The PlusCal   *)
(* algorithm is the source of Init/Next.  Each branch is one atomic portal *)
(* or kernel operation, so Commit is the mapping-publication and reply-     *)
(* consumption linearization point.                                       *)
(***************************************************************************)

CONSTANTS
    Faults,
    Frames,
    AddressSpace,
    Page,
    MaxBinding,
    MaxAddressSpaceGeneration

ASSUME /\ IsFiniteSet(Faults)
       /\ Faults # {}
       /\ IsFiniteSet(Frames)
       /\ Cardinality(Frames) = Cardinality(Faults)
       /\ Faults \cap Frames = {}
       /\ MaxBinding \in Nat
       /\ MaxBinding > 0
       /\ MaxAddressSpaceGeneration \in Nat
       /\ MaxAddressSpaceGeneration > 0

ScopeStates == {"Active", "Closing", "Revoked"}
FaultStates == {
    "Unused", "Registered", "Prepared", "Committed", "Completed", "Aborted"
}
UncommittedFaultStates == {"Registered", "Prepared"}
TerminalFaultStates == {"Completed", "Aborted"}
FrameStates == {"Free", "Prepared", "Mapped"}
ContinuationStates == {"Absent", "Pending", "Consumed", "Failed"}
Outcomes == {"None", "Success", "Failure"}
FallbackStates == {"Standby", "Required", "Running"}
ReplacementStates == {"None", "Ready", "Bound"}
WatchdogStates == {"Idle", "Armed", "Expired"}

NoEpoch == -1
NoBinding == -1
NoFrame == "NoFrame"
NoOwner == "NoOwner"

Pages == {Page}

(* --algorithm PagerCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = NoEpoch,

    pagerAlive = TRUE,
    bindingEpoch = 0,
    replacementState = "Bound",
    readyBindings = {0},
    reboundBindings = {0},
    fallbackState = "Standby",
    watchdogState = "Idle",
    deadlineFaults = {},

    addressSpaceGeneration = 0,

    faultState = [f \in Faults |-> "Unused"],
    faultAuthority = [f \in Faults |-> NoEpoch],
    faultBinding = [f \in Faults |-> NoBinding],
    faultAsGeneration = [f \in Faults |-> NoEpoch],
    faultFrame = [f \in Faults |-> NoFrame],

    frameState = [fr \in Frames |-> "Free"],
    frameOwner = [fr \in Frames |-> NoOwner],
    pageFrame = [p \in Pages |-> NoFrame],
    pageOwner = [p \in Pages |-> NoOwner],

    continuationState = [f \in Faults |-> "Absent"],
    outcome = [f \in Faults |-> "None"],
    consumeCount = [f \in Faults |-> 0],
    wakeCount = [f \in Faults |-> 0],
    terminalCount = [f \in Faults |-> 0],

    commitSeen = [f \in Faults |-> FALSE],
    commitBinding = [f \in Faults |-> NoBinding],
    commitAsGeneration = [f \in Faults |-> NoEpoch],
    mappingPublicationCount = [f \in Faults |-> 0],
    generationPublicationCount =
        [generation \in 0..MaxAddressSpaceGeneration |-> 0],
    adoptCount = [f \in Faults |-> 0],

    committedAtClose = {},
    adoptCountAtClose = [f \in Faults |-> 0],
    committedAtLastCrash = {},
    lastCrashBinding = 0,
    committedAtLastAsChange = {},
    lastAsGeneration = 0;

process PagerEnvironment = "pager-environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* Register(f): the kernel creates a blocked, one-shot fault
            \* continuation only while a pager is bound.  Faults arriving
            \* during pager outage fail outside this first-slice scope model.
            with f \in Faults do
                await /\ scopeState = "Active"
                      /\ pagerAlive
                      /\ watchdogState # "Expired"
                      /\ faultState[f] = "Unused";
                faultState[f] := "Registered";
                faultAuthority[f] := authorityEpoch;
                faultBinding[f] := bindingEpoch;
                faultAsGeneration[f] := addressSpaceGeneration;
                continuationState[f] := "Pending";
                deadlineFaults := deadlineFaults \cup {f};
                if watchdogState = "Idle" then
                    watchdogState := "Armed";
                end if;
            end with;
        or
            \* PrepareZero(f, fr): a live, rebound pager reserves and zeros
            \* one frame.  The frame belongs to the fault effect, not to the
            \* pager process, and therefore survives a pager crash.
            with f \in Faults, fr \in Frames do
                await /\ scopeState = "Active"
                      /\ pagerAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ faultState[f] = "Registered"
                      /\ faultAuthority[f] = authorityEpoch
                      /\ faultBinding[f] = bindingEpoch
                      /\ faultAsGeneration[f] = addressSpaceGeneration
                      /\ continuationState[f] = "Pending"
                      /\ frameState[fr] = "Free";
                faultState[f] := "Prepared";
                faultFrame[f] := fr;
                frameState[fr] := "Prepared";
                frameOwner[fr] := f;
            end with;
        or
            \* Crash: only the pager binding generation advances.  Existing
            \* authority and address-space generations are unchanged.  A
            \* nonempty fault batch keeps its recovery deadline; an empty
            \* crash cohort does not create a service-liveness deadline.
            await /\ scopeState = "Active"
                  /\ pagerAlive
                  /\ bindingEpoch < MaxBinding;
            committedAtLastCrash := {f \in Faults : commitSeen[f]};
            lastCrashBinding := bindingEpoch + 1;
            bindingEpoch := bindingEpoch + 1;
            pagerAlive := FALSE;
            replacementState := "None";
            fallbackState := "Required";
            if /\ deadlineFaults # {}
               /\ watchdogState = "Idle" then
                watchdogState := "Armed";
            end if;
        or
            \* Ready: a fresh replacement reports that its recovery snapshot
            \* is installed.  This user-space action deliberately has no
            \* fairness assumption.
            await /\ scopeState = "Active"
                  /\ ~pagerAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None";
            replacementState := "Ready";
            readyBindings := readyBindings \cup {bindingEpoch};
        or
            \* Rebind: the ready replacement becomes the only live reply
            \* endpoint.  Rebind does not advance any generation.
            await /\ scopeState = "Active"
                  /\ ~pagerAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready"
                  /\ bindingEpoch \in readyBindings;
            pagerAlive := TRUE;
            replacementState := "Bound";
            reboundBindings := reboundBindings \cup {bindingEpoch};
            fallbackState := "Standby";
        or
            \* Adopt(f): only an uncommitted, current-authority and current-AS
            \* continuation can move from an old pager binding to the new one.
            with f \in Faults do
                await /\ scopeState = "Active"
                      /\ pagerAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ faultState[f] \in UncommittedFaultStates
                      /\ faultAuthority[f] = authorityEpoch
                      /\ faultAsGeneration[f] = addressSpaceGeneration
                      /\ faultBinding[f] # bindingEpoch;
                faultBinding[f] := bindingEpoch;
                adoptCount[f] := adoptCount[f] + 1;
            end with;
        or
            \* Commit(f): THE pager reply and PTE-publication linearization
            \* point.  All three generations and the empty target slot are
            \* revalidated atomically before the continuation is consumed.
            with f \in Faults do
                await /\ scopeState = "Active"
                      /\ pagerAlive
                      /\ replacementState = "Bound"
                      /\ bindingEpoch \in reboundBindings
                      /\ faultState[f] = "Prepared"
                      /\ faultAuthority[f] = authorityEpoch
                      /\ faultBinding[f] = bindingEpoch
                      /\ faultAsGeneration[f] = addressSpaceGeneration
                      /\ continuationState[f] = "Pending"
                      /\ faultFrame[f] \in Frames
                      /\ frameState[faultFrame[f]] = "Prepared"
                      /\ frameOwner[faultFrame[f]] = f
                      /\ pageFrame[Page] = NoFrame;
                faultState[f] := "Committed";
                continuationState[f] := "Consumed";
                consumeCount[f] := consumeCount[f] + 1;
                commitSeen[f] := TRUE;
                commitBinding[f] := bindingEpoch;
                commitAsGeneration[f] := addressSpaceGeneration;
                mappingPublicationCount[f] := mappingPublicationCount[f] + 1;
                generationPublicationCount[addressSpaceGeneration] :=
                    generationPublicationCount[addressSpaceGeneration] + 1;
                frameState[faultFrame[f]] := "Mapped";
                pageFrame[Page] := faultFrame[f];
                pageOwner[Page] := f;
            end with;
        or
            \* AddressSpaceChange: an unmap/remap/protect/exec-like change
            \* advances the address-space generation and clears the current
            \* slot after any committed continuation has been completed.  Its
            \* publication generation remains in the history counters.
            await /\ scopeState = "Active"
                  /\ addressSpaceGeneration < MaxAddressSpaceGeneration
                  /\ \A f \in Faults : faultState[f] # "Committed";
            if pageFrame[Page] # NoFrame then
                with fr = pageFrame[Page], owner = pageOwner[Page] do
                    frameState[fr] := "Free";
                    frameOwner[fr] := NoOwner;
                    faultFrame[owner] := NoFrame;
                end with;
                pageFrame[Page] := NoFrame;
                pageOwner[Page] := NoOwner;
            end if;
            committedAtLastAsChange := {f \in Faults : commitSeen[f]};
            lastAsGeneration := addressSpaceGeneration + 1;
            addressSpaceGeneration := addressSpaceGeneration + 1;
        end either;
    end while;
end process;

\* Kernel fallback is fair: a pager crash cannot leave the client dependent
\* on the failed user-space service merely for continued scheduling.
fair process KernelFallback = "kernel-fallback"
begin
FallbackLoop:
    while TRUE do
        await fallbackState = "Required";
        fallbackState := "Running";
    end while;
end process;

\* This is an abstract deadline edge, not a production timer.  Rebind does
\* not disarm it: a recovered pager must still resolve each blocked fault or
\* lose the atomic Commit-versus-timeout race to kernel-owned abort.
fair process KernelWatchdog = "kernel-watchdog"
begin
WatchdogLoop:
    while TRUE do
        await watchdogState = "Armed";
        watchdogState := "Expired";
    end while;
end process;

\* All actions in this process are kernel-owned.  The transition graph is
\* monotone and finite, so weak fairness of the process suffices to finish
\* every enabled Complete/Abort and the timeout revocation closure.
fair process KernelClosure = "kernel-closure"
begin
ClosureLoop:
    while TRUE do
        either
            \* Complete(f): after Commit published the mapping, wake the
            \* blocked thread exactly once for a same-RIP retry.
            with f \in Faults do
                await faultState[f] = "Committed";
                faultState[f] := "Completed";
                outcome[f] := "Success";
                wakeCount[f] := wakeCount[f] + 1;
                terminalCount[f] := terminalCount[f] + 1;
            end with;
        or
            \* SatisfyMapped(f): concurrent same-page faults share the first
            \* committed publication.  The losing continuation is consumed
            \* once without publishing the slot again; an unused prepared
            \* candidate frame is returned before the client is woken.
            with f \in Faults do
                await /\ scopeState = "Active"
                      /\ faultState[f] \in UncommittedFaultStates
                      /\ faultAuthority[f] = authorityEpoch
                      /\ faultAsGeneration[f] = addressSpaceGeneration
                      /\ continuationState[f] = "Pending"
                      /\ pageFrame[Page] \in Frames
                      /\ pageOwner[Page] # f
                      /\ commitAsGeneration[pageOwner[Page]] =
                            addressSpaceGeneration;
                if faultState[f] = "Prepared" then
                    with fr = faultFrame[f] do
                        frameState[fr] := "Free";
                        frameOwner[fr] := NoOwner;
                    end with;
                end if;
                faultState[f] := "Completed";
                faultFrame[f] := NoFrame;
                continuationState[f] := "Consumed";
                outcome[f] := "Success";
                consumeCount[f] := consumeCount[f] + 1;
                wakeCount[f] := wakeCount[f] + 1;
                terminalCount[f] := terminalCount[f] + 1;
            end with;
        or
            \* TimeoutRevoke: an expired recovery batch still contains an
            \* uncommitted blocked fault.  Advancing authority closes every
            \* old reply gate.  A final Commit and this action therefore race
            \* atomically on the same Active scope gate.  Pager death alone is
            \* not a service-liveness lease and does not revoke a batch whose
            \* remaining faults have all committed or terminalized.
            await /\ scopeState = "Active"
                  /\ watchdogState = "Expired"
                  /\ \E f \in deadlineFaults :
                         faultState[f] \in UncommittedFaultStates;
            committedAtClose := {f \in Faults : commitSeen[f]};
            adoptCountAtClose := adoptCount;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            pagerAlive := FALSE;
            replacementState := "None";
            watchdogState := "Idle";
            deadlineFaults := {};
        or
            \* Abort(f): closure releases an uncommitted prepared frame and
            \* wakes the client once with a terminal failure.  The same action
            \* also terminalizes a token fenced by an AS-generation change.
            with f \in Faults do
                await /\ faultState[f] \in UncommittedFaultStates
                      /\ (\/ /\ scopeState = "Closing"
                                /\ faultAuthority[f] = closingEpoch
                          \/ /\ scopeState = "Active"
                                /\ faultAsGeneration[f]
                                      # addressSpaceGeneration);
                if faultState[f] = "Prepared" then
                    with fr = faultFrame[f] do
                        frameState[fr] := "Free";
                        frameOwner[fr] := NoOwner;
                    end with;
                end if;
                faultState[f] := "Aborted";
                faultFrame[f] := NoFrame;
                continuationState[f] := "Failed";
                outcome[f] := "Failure";
                consumeCount[f] := consumeCount[f] + 1;
                wakeCount[f] := wakeCount[f] + 1;
                terminalCount[f] := terminalCount[f] + 1;
            end with;
        or
            \* DeadlineCancel: all members terminalized before expiry.  This
            \* kernel-owned action races WatchdogExpire atomically and models
            \* the implementation folding early cancellation into the final
            \* terminalization path.
            await /\ scopeState = "Active"
                  /\ watchdogState = "Armed"
                  /\ deadlineFaults # {}
                  /\ \A f \in deadlineFaults :
                         faultState[f] \in TerminalFaultStates;
            watchdogState := "Idle";
            deadlineFaults := {};
        or
            \* DeadlineComplete: a fresh deadline batch may start only after
            \* every fault in the expired batch is terminal.  The kernel owns
            \* completion of an already committed fault, so a later pager crash
            \* does not turn the deadline into a service lease.  No Ready/Rebind
            \* action clears this obligation; an uncommitted fault instead
            \* enables TimeoutRevoke.
            await /\ scopeState = "Active"
                  /\ watchdogState = "Expired"
                  /\ \A f \in deadlineFaults :
                         faultState[f] \in TerminalFaultStates;
            watchdogState := "Idle";
            deadlineFaults := {};
        or
            \* RevokeComplete is legal only after every fault in the closing
            \* authority epoch is terminal and no prepared frame remains.
            await /\ scopeState = "Closing"
                  /\ \A f \in Faults :
                         faultAuthority[f] = closingEpoch
                         => /\ faultState[f] \in TerminalFaultStates
                            /\ ~(faultFrame[f] \in Frames
                                 /\ frameState[faultFrame[f]] = "Prepared");
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)

\* BEGIN TRANSLATION
VARIABLES scopeState, authorityEpoch, closingEpoch, pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, watchdogState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtClose, adoptCountAtClose, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration

vars == << scopeState, authorityEpoch, closingEpoch, pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, watchdogState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtClose, adoptCountAtClose, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration >>

ProcSet == {"pager-environment"} \cup {"kernel-fallback"} \cup {"kernel-watchdog"} \cup {"kernel-closure"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ pagerAlive = TRUE
        /\ bindingEpoch = 0
        /\ replacementState = "Bound"
        /\ readyBindings = {0}
        /\ reboundBindings = {0}
        /\ fallbackState = "Standby"
        /\ watchdogState = "Idle"
        /\ deadlineFaults = {}
        /\ addressSpaceGeneration = 0
        /\ faultState = [f \in Faults |-> "Unused"]
        /\ faultAuthority = [f \in Faults |-> NoEpoch]
        /\ faultBinding = [f \in Faults |-> NoBinding]
        /\ faultAsGeneration = [f \in Faults |-> NoEpoch]
        /\ faultFrame = [f \in Faults |-> NoFrame]
        /\ frameState = [fr \in Frames |-> "Free"]
        /\ frameOwner = [fr \in Frames |-> NoOwner]
        /\ pageFrame = [p \in Pages |-> NoFrame]
        /\ pageOwner = [p \in Pages |-> NoOwner]
        /\ continuationState = [f \in Faults |-> "Absent"]
        /\ outcome = [f \in Faults |-> "None"]
        /\ consumeCount = [f \in Faults |-> 0]
        /\ wakeCount = [f \in Faults |-> 0]
        /\ terminalCount = [f \in Faults |-> 0]
        /\ commitSeen = [f \in Faults |-> FALSE]
        /\ commitBinding = [f \in Faults |-> NoBinding]
        /\ commitAsGeneration = [f \in Faults |-> NoEpoch]
        /\ mappingPublicationCount = [f \in Faults |-> 0]
        /\ generationPublicationCount = [generation \in 0..MaxAddressSpaceGeneration |-> 0]
        /\ adoptCount = [f \in Faults |-> 0]
        /\ committedAtClose = {}
        /\ adoptCountAtClose = [f \in Faults |-> 0]
        /\ committedAtLastCrash = {}
        /\ lastCrashBinding = 0
        /\ committedAtLastAsChange = {}
        /\ lastAsGeneration = 0

PagerEnvironment == /\ \/ /\ \E f \in Faults:
                               /\ /\ scopeState = "Active"
                                  /\ pagerAlive
                                  /\ watchdogState # "Expired"
                                  /\ faultState[f] = "Unused"
                               /\ faultState' = [faultState EXCEPT ![f] = "Registered"]
                               /\ faultAuthority' = [faultAuthority EXCEPT ![f] = authorityEpoch]
                               /\ faultBinding' = [faultBinding EXCEPT ![f] = bindingEpoch]
                               /\ faultAsGeneration' = [faultAsGeneration EXCEPT ![f] = addressSpaceGeneration]
                               /\ continuationState' = [continuationState EXCEPT ![f] = "Pending"]
                               /\ deadlineFaults' = (deadlineFaults \cup {f})
                               /\ IF watchdogState = "Idle"
                                     THEN /\ watchdogState' = "Armed"
                                     ELSE /\ TRUE
                                          /\ UNCHANGED watchdogState
                          /\ UNCHANGED <<pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, addressSpaceGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ \E f \in Faults:
                               \E fr \in Frames:
                                 /\ /\ scopeState = "Active"
                                    /\ pagerAlive
                                    /\ replacementState = "Bound"
                                    /\ bindingEpoch \in reboundBindings
                                    /\ faultState[f] = "Registered"
                                    /\ faultAuthority[f] = authorityEpoch
                                    /\ faultBinding[f] = bindingEpoch
                                    /\ faultAsGeneration[f] = addressSpaceGeneration
                                    /\ continuationState[f] = "Pending"
                                    /\ frameState[fr] = "Free"
                                 /\ faultState' = [faultState EXCEPT ![f] = "Prepared"]
                                 /\ faultFrame' = [faultFrame EXCEPT ![f] = fr]
                                 /\ frameState' = [frameState EXCEPT ![fr] = "Prepared"]
                                 /\ frameOwner' = [frameOwner EXCEPT ![fr] = f]
                          /\ UNCHANGED <<pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, watchdogState, deadlineFaults, addressSpaceGeneration, faultAuthority, faultBinding, faultAsGeneration, pageFrame, pageOwner, continuationState, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ /\ scopeState = "Active"
                             /\ pagerAlive
                             /\ bindingEpoch < MaxBinding
                          /\ committedAtLastCrash' = {f \in Faults : commitSeen[f]}
                          /\ lastCrashBinding' = bindingEpoch + 1
                          /\ bindingEpoch' = bindingEpoch + 1
                          /\ pagerAlive' = FALSE
                          /\ replacementState' = "None"
                          /\ fallbackState' = "Required"
                          /\ IF /\ deadlineFaults # {}
                                /\ watchdogState = "Idle"
                                THEN /\ watchdogState' = "Armed"
                                ELSE /\ TRUE
                                     /\ UNCHANGED watchdogState
                          /\ UNCHANGED <<readyBindings, reboundBindings, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ /\ scopeState = "Active"
                             /\ ~pagerAlive
                             /\ fallbackState = "Running"
                             /\ replacementState = "None"
                          /\ replacementState' = "Ready"
                          /\ readyBindings' = (readyBindings \cup {bindingEpoch})
                          /\ UNCHANGED <<pagerAlive, bindingEpoch, reboundBindings, fallbackState, watchdogState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ /\ scopeState = "Active"
                             /\ ~pagerAlive
                             /\ fallbackState = "Running"
                             /\ replacementState = "Ready"
                             /\ bindingEpoch \in readyBindings
                          /\ pagerAlive' = TRUE
                          /\ replacementState' = "Bound"
                          /\ reboundBindings' = (reboundBindings \cup {bindingEpoch})
                          /\ fallbackState' = "Standby"
                          /\ UNCHANGED <<bindingEpoch, readyBindings, watchdogState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ \E f \in Faults:
                               /\ /\ scopeState = "Active"
                                  /\ pagerAlive
                                  /\ replacementState = "Bound"
                                  /\ bindingEpoch \in reboundBindings
                                  /\ faultState[f] \in UncommittedFaultStates
                                  /\ faultAuthority[f] = authorityEpoch
                                  /\ faultAsGeneration[f] = addressSpaceGeneration
                                  /\ faultBinding[f] # bindingEpoch
                               /\ faultBinding' = [faultBinding EXCEPT ![f] = bindingEpoch]
                               /\ adoptCount' = [adoptCount EXCEPT ![f] = adoptCount[f] + 1]
                          /\ UNCHANGED <<pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, watchdogState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ \E f \in Faults:
                               /\ /\ scopeState = "Active"
                                  /\ pagerAlive
                                  /\ replacementState = "Bound"
                                  /\ bindingEpoch \in reboundBindings
                                  /\ faultState[f] = "Prepared"
                                  /\ faultAuthority[f] = authorityEpoch
                                  /\ faultBinding[f] = bindingEpoch
                                  /\ faultAsGeneration[f] = addressSpaceGeneration
                                  /\ continuationState[f] = "Pending"
                                  /\ faultFrame[f] \in Frames
                                  /\ frameState[faultFrame[f]] = "Prepared"
                                  /\ frameOwner[faultFrame[f]] = f
                                  /\ pageFrame[Page] = NoFrame
                               /\ faultState' = [faultState EXCEPT ![f] = "Committed"]
                               /\ continuationState' = [continuationState EXCEPT ![f] = "Consumed"]
                               /\ consumeCount' = [consumeCount EXCEPT ![f] = consumeCount[f] + 1]
                               /\ commitSeen' = [commitSeen EXCEPT ![f] = TRUE]
                               /\ commitBinding' = [commitBinding EXCEPT ![f] = bindingEpoch]
                               /\ commitAsGeneration' = [commitAsGeneration EXCEPT ![f] = addressSpaceGeneration]
                               /\ mappingPublicationCount' = [mappingPublicationCount EXCEPT ![f] = mappingPublicationCount[f] + 1]
                               /\ generationPublicationCount' = [generationPublicationCount EXCEPT ![addressSpaceGeneration] = generationPublicationCount[addressSpaceGeneration] + 1]
                               /\ frameState' = [frameState EXCEPT ![faultFrame[f]] = "Mapped"]
                               /\ pageFrame' = [pageFrame EXCEPT ![Page] = faultFrame[f]]
                               /\ pageOwner' = [pageOwner EXCEPT ![Page] = f]
                          /\ UNCHANGED <<pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, watchdogState, deadlineFaults, addressSpaceGeneration, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameOwner, adoptCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration>>
                       \/ /\ /\ scopeState = "Active"
                             /\ addressSpaceGeneration < MaxAddressSpaceGeneration
                             /\ \A f \in Faults : faultState[f] # "Committed"
                          /\ IF pageFrame[Page] # NoFrame
                                THEN /\ LET fr == pageFrame[Page] IN
                                          LET owner == pageOwner[Page] IN
                                            /\ frameState' = [frameState EXCEPT ![fr] = "Free"]
                                            /\ frameOwner' = [frameOwner EXCEPT ![fr] = NoOwner]
                                            /\ faultFrame' = [faultFrame EXCEPT ![owner] = NoFrame]
                                     /\ pageFrame' = [pageFrame EXCEPT ![Page] = NoFrame]
                                     /\ pageOwner' = [pageOwner EXCEPT ![Page] = NoOwner]
                                ELSE /\ TRUE
                                     /\ UNCHANGED << faultFrame, frameState, frameOwner, pageFrame, pageOwner >>
                          /\ committedAtLastAsChange' = {f \in Faults : commitSeen[f]}
                          /\ lastAsGeneration' = addressSpaceGeneration + 1
                          /\ addressSpaceGeneration' = addressSpaceGeneration + 1
                          /\ UNCHANGED <<pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, watchdogState, deadlineFaults, faultState, faultAuthority, faultBinding, faultAsGeneration, continuationState, consumeCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastCrash, lastCrashBinding>>
                    /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, outcome, wakeCount, terminalCount, committedAtClose, adoptCountAtClose >>

KernelFallback == /\ fallbackState = "Required"
                  /\ fallbackState' = "Running"
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, watchdogState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtClose, adoptCountAtClose, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration >>

KernelWatchdog == /\ watchdogState = "Armed"
                  /\ watchdogState' = "Expired"
                  /\ UNCHANGED << scopeState, authorityEpoch, closingEpoch, pagerAlive, bindingEpoch, replacementState, readyBindings, reboundBindings, fallbackState, deadlineFaults, addressSpaceGeneration, faultState, faultAuthority, faultBinding, faultAsGeneration, faultFrame, frameState, frameOwner, pageFrame, pageOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtClose, adoptCountAtClose, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration >>

KernelClosure == /\ \/ /\ \E f \in Faults:
                            /\ faultState[f] = "Committed"
                            /\ faultState' = [faultState EXCEPT ![f] = "Completed"]
                            /\ outcome' = [outcome EXCEPT ![f] = "Success"]
                            /\ wakeCount' = [wakeCount EXCEPT ![f] = wakeCount[f] + 1]
                            /\ terminalCount' = [terminalCount EXCEPT ![f] = terminalCount[f] + 1]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, pagerAlive, replacementState, watchdogState, deadlineFaults, faultFrame, frameState, frameOwner, continuationState, consumeCount, committedAtClose, adoptCountAtClose>>
                    \/ /\ \E f \in Faults:
                            /\ /\ scopeState = "Active"
                               /\ faultState[f] \in UncommittedFaultStates
                               /\ faultAuthority[f] = authorityEpoch
                               /\ faultAsGeneration[f] = addressSpaceGeneration
                               /\ continuationState[f] = "Pending"
                               /\ pageFrame[Page] \in Frames
                               /\ pageOwner[Page] # f
                               /\ commitAsGeneration[pageOwner[Page]] =
                                     addressSpaceGeneration
                            /\ IF faultState[f] = "Prepared"
                                  THEN /\ LET fr == faultFrame[f] IN
                                            /\ frameState' = [frameState EXCEPT ![fr] = "Free"]
                                            /\ frameOwner' = [frameOwner EXCEPT ![fr] = NoOwner]
                                  ELSE /\ TRUE
                                       /\ UNCHANGED << frameState, frameOwner >>
                            /\ faultState' = [faultState EXCEPT ![f] = "Completed"]
                            /\ faultFrame' = [faultFrame EXCEPT ![f] = NoFrame]
                            /\ continuationState' = [continuationState EXCEPT ![f] = "Consumed"]
                            /\ outcome' = [outcome EXCEPT ![f] = "Success"]
                            /\ consumeCount' = [consumeCount EXCEPT ![f] = consumeCount[f] + 1]
                            /\ wakeCount' = [wakeCount EXCEPT ![f] = wakeCount[f] + 1]
                            /\ terminalCount' = [terminalCount EXCEPT ![f] = terminalCount[f] + 1]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, pagerAlive, replacementState, watchdogState, deadlineFaults, committedAtClose, adoptCountAtClose>>
                    \/ /\ /\ scopeState = "Active"
                          /\ watchdogState = "Expired"
                          /\ \E f \in deadlineFaults :
                                 faultState[f] \in UncommittedFaultStates
                       /\ committedAtClose' = {f \in Faults : commitSeen[f]}
                       /\ adoptCountAtClose' = adoptCount
                       /\ closingEpoch' = authorityEpoch
                       /\ authorityEpoch' = authorityEpoch + 1
                       /\ scopeState' = "Closing"
                       /\ pagerAlive' = FALSE
                       /\ replacementState' = "None"
                       /\ watchdogState' = "Idle"
                       /\ deadlineFaults' = {}
                       /\ UNCHANGED <<faultState, faultFrame, frameState, frameOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount>>
                    \/ /\ \E f \in Faults:
                            /\ /\ faultState[f] \in UncommittedFaultStates
                               /\ (\/ /\ scopeState = "Closing"
                                         /\ faultAuthority[f] = closingEpoch
                                   \/ /\ scopeState = "Active"
                                         /\ faultAsGeneration[f]
                                               # addressSpaceGeneration)
                            /\ IF faultState[f] = "Prepared"
                                  THEN /\ LET fr == faultFrame[f] IN
                                            /\ frameState' = [frameState EXCEPT ![fr] = "Free"]
                                            /\ frameOwner' = [frameOwner EXCEPT ![fr] = NoOwner]
                                  ELSE /\ TRUE
                                       /\ UNCHANGED << frameState, frameOwner >>
                            /\ faultState' = [faultState EXCEPT ![f] = "Aborted"]
                            /\ faultFrame' = [faultFrame EXCEPT ![f] = NoFrame]
                            /\ continuationState' = [continuationState EXCEPT ![f] = "Failed"]
                            /\ outcome' = [outcome EXCEPT ![f] = "Failure"]
                            /\ consumeCount' = [consumeCount EXCEPT ![f] = consumeCount[f] + 1]
                            /\ wakeCount' = [wakeCount EXCEPT ![f] = wakeCount[f] + 1]
                            /\ terminalCount' = [terminalCount EXCEPT ![f] = terminalCount[f] + 1]
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, pagerAlive, replacementState, watchdogState, deadlineFaults, committedAtClose, adoptCountAtClose>>
                    \/ /\ /\ scopeState = "Active"
                          /\ watchdogState = "Armed"
                          /\ deadlineFaults # {}
                          /\ \A f \in deadlineFaults :
                                 faultState[f] \in TerminalFaultStates
                       /\ watchdogState' = "Idle"
                       /\ deadlineFaults' = {}
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, pagerAlive, replacementState, faultState, faultFrame, frameState, frameOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, committedAtClose, adoptCountAtClose>>
                    \/ /\ /\ scopeState = "Active"
                          /\ watchdogState = "Expired"
                          /\ \A f \in deadlineFaults :
                                 faultState[f] \in TerminalFaultStates
                       /\ watchdogState' = "Idle"
                       /\ deadlineFaults' = {}
                       /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, pagerAlive, replacementState, faultState, faultFrame, frameState, frameOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, committedAtClose, adoptCountAtClose>>
                    \/ /\ /\ scopeState = "Closing"
                          /\ \A f \in Faults :
                                 faultAuthority[f] = closingEpoch
                                 => /\ faultState[f] \in TerminalFaultStates
                                    /\ ~(faultFrame[f] \in Frames
                                         /\ frameState[faultFrame[f]] = "Prepared")
                       /\ scopeState' = "Revoked"
                       /\ UNCHANGED <<authorityEpoch, closingEpoch, pagerAlive, replacementState, watchdogState, deadlineFaults, faultState, faultFrame, frameState, frameOwner, continuationState, outcome, consumeCount, wakeCount, terminalCount, committedAtClose, adoptCountAtClose>>
                 /\ UNCHANGED << bindingEpoch, readyBindings, reboundBindings, fallbackState, addressSpaceGeneration, faultAuthority, faultBinding, faultAsGeneration, pageFrame, pageOwner, commitSeen, commitBinding, commitAsGeneration, mappingPublicationCount, generationPublicationCount, adoptCount, committedAtLastCrash, lastCrashBinding, committedAtLastAsChange, lastAsGeneration >>

Next == PagerEnvironment \/ KernelFallback \/ KernelWatchdog \/ KernelClosure

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(KernelFallback)
        /\ WF_vars(KernelWatchdog)
        /\ WF_vars(KernelClosure)

\* END TRANSLATION

(***************************************************************************)
(* Safety predicates checked by TLC.                                       *)
(***************************************************************************)

(* A fault identifier also names its blocked client thread in this bounded  *)
(* model.  All faults target the same page, deliberately exercising the     *)
(* rule that a PTE slot can be published at most once per AS generation.     *)
FaultToken(f) ==
    [scope |-> AddressSpace,
     fault |-> f,
     authority_epoch |-> faultAuthority[f],
     binding_epoch |-> faultBinding[f],
     address_space |-> AddressSpace,
     address_space_generation |-> faultAsGeneration[f],
     thread |-> f,
     page |-> Page,
     access |-> "Write"]

TypeOK ==
    /\ scopeState \in ScopeStates
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ pagerAlive \in BOOLEAN
    /\ bindingEpoch \in 0..MaxBinding
    /\ replacementState \in ReplacementStates
    /\ readyBindings \subseteq (0..MaxBinding)
    /\ reboundBindings \subseteq (0..MaxBinding)
    /\ fallbackState \in FallbackStates
    /\ watchdogState \in WatchdogStates
    /\ deadlineFaults \subseteq Faults
    /\ addressSpaceGeneration \in 0..MaxAddressSpaceGeneration
    /\ faultState \in [Faults -> FaultStates]
    /\ faultAuthority \in [Faults -> ({NoEpoch} \cup {0})]
    /\ faultBinding \in [Faults -> ({NoBinding} \cup (0..MaxBinding))]
    /\ faultAsGeneration
          \in [Faults -> ({NoEpoch} \cup (0..MaxAddressSpaceGeneration))]
    /\ faultFrame \in [Faults -> ({NoFrame} \cup Frames)]
    /\ frameState \in [Frames -> FrameStates]
    /\ frameOwner \in [Frames -> ({NoOwner} \cup Faults)]
    /\ pageFrame \in [Pages -> ({NoFrame} \cup Frames)]
    /\ pageOwner \in [Pages -> ({NoOwner} \cup Faults)]
    /\ continuationState \in [Faults -> ContinuationStates]
    /\ outcome \in [Faults -> Outcomes]
    /\ consumeCount \in [Faults -> {0, 1}]
    /\ wakeCount \in [Faults -> {0, 1}]
    /\ terminalCount \in [Faults -> {0, 1}]
    /\ commitSeen \in [Faults -> BOOLEAN]
    /\ commitBinding \in [Faults -> ({NoBinding} \cup (0..MaxBinding))]
    /\ commitAsGeneration
          \in [Faults -> ({NoEpoch} \cup (0..MaxAddressSpaceGeneration))]
    /\ mappingPublicationCount \in [Faults -> {0, 1}]
    /\ generationPublicationCount
          \in [(0..MaxAddressSpaceGeneration) -> {0, 1}]
    /\ adoptCount \in [Faults -> (0..MaxBinding)]
    /\ committedAtClose \subseteq Faults
    /\ adoptCountAtClose \in [Faults -> (0..MaxBinding)]
    /\ committedAtLastCrash \subseteq Faults
    /\ lastCrashBinding \in 0..MaxBinding
    /\ committedAtLastAsChange \subseteq Faults
    /\ lastAsGeneration \in 0..MaxAddressSpaceGeneration

FaultTokensTypeOK ==
    \A f \in Faults :
        FaultToken(f)
          \in [scope : {AddressSpace},
               fault : Faults,
               authority_epoch : ({NoEpoch} \cup {0}),
               binding_epoch : ({NoBinding} \cup (0..MaxBinding)),
               address_space : {AddressSpace},
               address_space_generation :
                   ({NoEpoch} \cup (0..MaxAddressSpaceGeneration)),
               thread : Faults,
               page : Pages,
               access : {"Write"}]

ContinuationStateConsistency ==
    \A f \in Faults :
        CASE faultState[f] = "Unused" ->
                 /\ continuationState[f] = "Absent"
                 /\ outcome[f] = "None"
          [] faultState[f] \in UncommittedFaultStates ->
                 /\ continuationState[f] = "Pending"
                 /\ outcome[f] = "None"
          [] faultState[f] = "Committed" ->
                 /\ continuationState[f] = "Consumed"
                 /\ outcome[f] = "None"
          [] faultState[f] = "Completed" ->
                 /\ continuationState[f] = "Consumed"
                 /\ outcome[f] = "Success"
          [] faultState[f] = "Aborted" ->
                 /\ continuationState[f] = "Failed"
                 /\ outcome[f] = "Failure"

OneShotContinuation ==
    \A f \in Faults :
        /\ consumeCount[f] \in {0, 1}
        /\ wakeCount[f] \in {0, 1}
        /\ terminalCount[f] \in {0, 1}
        /\ (consumeCount[f] = 1)
              <=> (faultState[f]
                     \in {"Committed", "Completed", "Aborted"})
        /\ (wakeCount[f] = 1) <=> (faultState[f] \in TerminalFaultStates)
        /\ terminalCount[f] = wakeCount[f]

PendingFaultHasDeadline ==
    /\ (watchdogState = "Idle" => deadlineFaults = {})
    /\ (watchdogState \in {"Armed", "Expired"} => deadlineFaults # {})
    /\ \A f \in Faults :
           /\ scopeState = "Active"
           /\ faultState[f]
                 \in (UncommittedFaultStates \cup {"Committed"})
           => /\ f \in deadlineFaults
              /\ watchdogState # "Idle"

FrameOwnershipConsistency ==
    /\ \A fr \in Frames :
           CASE frameState[fr] = "Free" ->
                    /\ frameOwner[fr] = NoOwner
                    /\ ~\E f \in Faults : faultFrame[f] = fr
             [] frameState[fr] = "Prepared" ->
                    /\ frameOwner[fr] \in Faults
                    /\ faultFrame[frameOwner[fr]] = fr
                    /\ faultState[frameOwner[fr]] = "Prepared"
             [] frameState[fr] = "Mapped" ->
                    /\ frameOwner[fr] \in Faults
                    /\ faultFrame[frameOwner[fr]] = fr
                    /\ faultState[frameOwner[fr]] \in {"Committed", "Completed"}
    /\ \A f \in Faults :
           CASE faultState[f] \in {"Unused", "Registered", "Aborted"} ->
                    faultFrame[f] = NoFrame
             [] faultState[f] = "Prepared" ->
                    /\ faultFrame[f] \in Frames
                    /\ frameState[faultFrame[f]] = "Prepared"
                    /\ frameOwner[faultFrame[f]] = f
             [] faultState[f] = "Committed" ->
                    /\ faultFrame[f] \in Frames
                    /\ frameState[faultFrame[f]] = "Mapped"
                    /\ frameOwner[faultFrame[f]] = f
             [] faultState[f] = "Completed" ->
                    \/ /\ faultFrame[f] \in Frames
                          /\ frameState[faultFrame[f]] = "Mapped"
                          /\ frameOwner[faultFrame[f]] = f
                       \/ /\ faultFrame[f] = NoFrame
                          /\ (\/ /\ commitSeen[f]
                                    /\ commitAsGeneration[f]
                                          < addressSpaceGeneration
                              \/ /\ ~commitSeen[f]
                                    /\ generationPublicationCount[
                                           faultAsGeneration[f]] = 1)

PreparedFrameOwnedExactlyOnce ==
    \A fr \in Frames :
        frameState[fr] = "Prepared"
        => Cardinality({f \in Faults :
                            /\ faultState[f] = "Prepared"
                            /\ faultFrame[f] = fr
                            /\ frameOwner[fr] = f}) = 1

NoTerminalFaultRetainsPreparedFrame ==
    \A f \in Faults :
        faultState[f] \in TerminalFaultStates
        => /\ (faultFrame[f] \in Frames
                => frameState[faultFrame[f]] # "Prepared")
           /\ (faultState[f] = "Aborted" => faultFrame[f] = NoFrame)

MappingConsistency ==
    \A p \in Pages :
        CASE pageFrame[p] = NoFrame ->
                 pageOwner[p] = NoOwner
          [] pageFrame[p] \in Frames ->
                 /\ pageOwner[p] \in Faults
                 /\ frameState[pageFrame[p]] = "Mapped"
                 /\ frameOwner[pageFrame[p]] = pageOwner[p]
                 /\ faultFrame[pageOwner[p]] = pageFrame[p]
                 /\ faultState[pageOwner[p]] \in {"Committed", "Completed"}
                 /\ commitAsGeneration[pageOwner[p]] =
                       addressSpaceGeneration

NoDoubleMappingPublication ==
    /\ \A f \in Faults :
           /\ mappingPublicationCount[f] \in {0, 1}
           /\ (mappingPublicationCount[f] = 1) <=> commitSeen[f]
    /\ \A generation \in 0..MaxAddressSpaceGeneration :
           /\ generationPublicationCount[generation] \in {0, 1}
           /\ generationPublicationCount[generation]
                 = Cardinality({f \in Faults :
                                   /\ commitSeen[f]
                                   /\ commitAsGeneration[f] = generation})

ResumeRequiresCommittedMapping ==
    \A f \in Faults :
        outcome[f] = "Success"
        => /\ faultState[f] = "Completed"
           /\ continuationState[f] = "Consumed"
           /\ consumeCount[f] = 1
           /\ generationPublicationCount[faultAsGeneration[f]] = 1
           /\ (commitSeen[f]
                 => /\ mappingPublicationCount[f] = 1
                    /\ commitAsGeneration[f] = faultAsGeneration[f])
           /\ (~commitSeen[f] => mappingPublicationCount[f] = 0)
           /\ (\/ /\ faultAsGeneration[f] = addressSpaceGeneration
                      /\ pageFrame[Page] \in Frames
                      /\ pageOwner[Page] \in Faults
                      /\ commitAsGeneration[pageOwner[Page]] =
                            faultAsGeneration[f]
                \/ faultAsGeneration[f] < addressSpaceGeneration)

PrepareZeroEnabled(f) ==
    /\ scopeState = "Active"
    /\ pagerAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ faultState[f] = "Registered"
    /\ faultAuthority[f] = authorityEpoch
    /\ faultBinding[f] = bindingEpoch
    /\ faultAsGeneration[f] = addressSpaceGeneration
    /\ continuationState[f] = "Pending"
    /\ \E fr \in Frames : frameState[fr] = "Free"

CommitEnabled(f) ==
    /\ scopeState = "Active"
    /\ pagerAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ faultState[f] = "Prepared"
    /\ faultAuthority[f] = authorityEpoch
    /\ faultBinding[f] = bindingEpoch
    /\ faultAsGeneration[f] = addressSpaceGeneration
    /\ continuationState[f] = "Pending"
    /\ faultFrame[f] \in Frames
    /\ frameState[faultFrame[f]] = "Prepared"
    /\ frameOwner[faultFrame[f]] = f
    /\ pageFrame[Page] = NoFrame

AdoptEnabled(f) ==
    /\ scopeState = "Active"
    /\ pagerAlive
    /\ replacementState = "Bound"
    /\ bindingEpoch \in reboundBindings
    /\ faultState[f] \in UncommittedFaultStates
    /\ faultAuthority[f] = authorityEpoch
    /\ faultAsGeneration[f] = addressSpaceGeneration
    /\ faultBinding[f] # bindingEpoch

OldBindingCannotCommit ==
    /\ \A f \in Faults :
           /\ faultState[f] \in UncommittedFaultStates
           /\ faultBinding[f] < bindingEpoch
           => ~CommitEnabled(f)
    /\ \A f \in Faults :
           /\ commitSeen[f]
           /\ f \notin committedAtLastCrash
           => commitBinding[f] >= lastCrashBinding

OldAddressSpaceGenerationCannotCommit ==
    /\ \A f \in Faults :
           /\ faultState[f] \in UncommittedFaultStates
           /\ faultAsGeneration[f] < addressSpaceGeneration
           => ~CommitEnabled(f)
    /\ \A f \in Faults :
           /\ commitSeen[f]
           /\ f \notin committedAtLastAsChange
           => commitAsGeneration[f] >= lastAsGeneration

ReadyBeforeRebind ==
    /\ reboundBindings \subseteq readyBindings
    /\ (replacementState = "Ready"
          => /\ ~pagerAlive /\ bindingEpoch \in readyBindings)
    /\ (pagerAlive <=> replacementState = "Bound")

NoReplyBeforeRebind ==
    /\ \A f \in Faults :
           commitSeen[f] => commitBinding[f] \in reboundBindings
    /\ (bindingEpoch \notin reboundBindings
          => /\ ~pagerAlive
             /\ \A f \in Faults :
                    /\ ~PrepareZeroEnabled(f)
                    /\ ~CommitEnabled(f))

NoAdoptAfterClosing ==
    scopeState \in {"Closing", "Revoked"}
    => /\ adoptCount = adoptCountAtClose
       /\ \A f \in Faults : ~AdoptEnabled(f)

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"}
    => \A f \in Faults : commitSeen[f] => f \in committedAtClose

QuiescentClosure ==
    scopeState = "Revoked"
    => /\ closingEpoch # NoEpoch
       /\ deadlineFaults = {}
       /\ \A f \in Faults :
              faultAuthority[f] = closingEpoch
              => /\ faultState[f] \in TerminalFaultStates
                 /\ ~(faultFrame[f] \in Frames
                      /\ frameState[faultFrame[f]] = "Prepared")

(***************************************************************************)
(* Liveness predicates.  Only the three kernel processes are weakly fair.  *)
(***************************************************************************)

SchedulerFallbackProgress ==
    (fallbackState = "Required") ~> (fallbackState = "Running")

WatchdogProgress ==
    (watchdogState = "Armed")
      ~> (watchdogState = "Expired" \/ watchdogState = "Idle")

DeadlineBatchProgress ==
    (/\ scopeState = "Active"
     /\ watchdogState = "Expired")
      ~> (scopeState = "Closing" \/ watchdogState = "Idle")

FaultClosureProgress ==
    /\ \A f \in Faults :
           (faultState[f] = "Committed") ~> (faultState[f] = "Completed")
    /\ \A f \in Faults :
           (/\ scopeState = "Closing"
            /\ faultAuthority[f] = closingEpoch
            /\ faultState[f] \notin TerminalFaultStates)
             ~> (faultState[f] \in TerminalFaultStates)
    /\ (scopeState = "Closing") ~> (scopeState = "Revoked")

BlockedFaultProgress ==
    \A f \in Faults :
        (faultState[f]
           \in (UncommittedFaultStates \cup {"Committed"}))
          ~> (faultState[f] \in TerminalFaultStates)

=============================================================================

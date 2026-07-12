-------------------- MODULE CompositionCser --------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Bounded system-wide CSER composition over five existing Nexus domains.  *)
(* The fixed topology keeps exhaustive checking tractable while preserving *)
(* cross-domain derivation, independent bindings, typed credit ownership,  *)
(* crash/adopt, authority closure receipts, and an honest I/O tombstone.    *)
(* The PlusCal algorithm is the sole source of Init and Next.               *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableCrash, EnableTimeout

ASSUME /\ MaxBinding = 1
       /\ EnableCrash \in BOOLEAN
       /\ EnableTimeout \in BOOLEAN

Domains == {"Scheduler", "Pager", "Personality", "Readiness", "VirtIo"}
Effects == {"EScheduler", "EPager", "EPersonality", "EReadiness", "EVirtIo"}
CreditTypes == {"Cpu", "Memory", "Control", "Wait", "Dma"}
MaxReceiptSequence == Cardinality(Domains) + 1

Root == "Root"
NoParent == "NoParent"
NoEpoch == -1
NoBinding == -1

EffectDomain(e) ==
    CASE e = "EScheduler" -> "Scheduler"
      [] e = "EPager" -> "Pager"
      [] e = "EPersonality" -> "Personality"
      [] e = "EReadiness" -> "Readiness"
      [] e = "EVirtIo" -> "VirtIo"

EffectCredit(e) ==
    CASE e = "EScheduler" -> "Cpu"
      [] e = "EPager" -> "Memory"
      [] e = "EPersonality" -> "Control"
      [] e = "EReadiness" -> "Wait"
      [] e = "EVirtIo" -> "Dma"

(***************************************************************************)
(* The bounded graph contains a fork and two cross-domain chains:           *)
(*                                                                           *)
(* Root -> Personality -> Pager -> Scheduler                                *)
(*                     \-> Readiness -> VirtIo                               *)
(*                                                                           *)
(* Parent fields are assigned only by DeriveEffect and are retained through *)
(* terminalization, so a descendant never outlives its causal identity.      *)
(***************************************************************************)
AllowedParent(e) ==
    CASE e = "EPersonality" -> Root
      [] e = "EPager" -> "EPersonality"
      [] e = "EScheduler" -> "EPager"
      [] e = "EReadiness" -> "EPersonality"
      [] e = "EVirtIo" -> "EReadiness"

LiveStates == {"Registered", "Committed", "Tombstoned"}
TerminalStates == {"Completed", "Aborted"}

ParentCanDerive(e, effectState, effectBinding, bindingEpoch, domainPhase) ==
    IF AllowedParent(e) = Root
    THEN TRUE
    ELSE /\ effectState[AllowedParent(e)] \in {"Registered", "Committed"}
         /\ domainPhase[EffectDomain(AllowedParent(e))] = "Bound"
         /\ effectBinding[AllowedParent(e)] =
                bindingEpoch[EffectDomain(AllowedParent(e))]

ChildrenTerminal(e, effectState, effectParent) ==
    \A child \in Effects :
        (effectParent[child] = e /\ effectState[child] # "Unused")
        => effectState[child] \in TerminalStates

DomainClosingTerminal(d, closingEffects, effectState) ==
    \A e \in closingEffects :
        EffectDomain(e) = d => effectState[e] \in TerminalStates

(* --algorithm CompositionCSER
variables
    scopeState = "Active",
    scopeGate = "Open",
    authorityEpoch = 0,
    closingEpoch = NoEpoch,

    effectState = [e \in Effects |-> "Unused"],
    effectParent = [e \in Effects |-> NoParent],
    effectAuthority = [e \in Effects |-> NoEpoch],
    effectBinding = [e \in Effects |-> NoBinding],
    commitCount = [e \in Effects |-> 0],
    terminalCount = [e \in Effects |-> 0],
    effectDeviceGeneration = [e \in Effects |-> NoEpoch],

    freeCredits = [t \in CreditTypes |-> 1],
    creditSource = [e \in Effects |-> NoParent],
    creditKind = [e \in Effects |-> "None"],

    bindingEpoch = [d \in Domains |-> 0],
    domainPhase = [d \in Domains |-> "Bound"],
    recoveryCohort = [d \in Domains |-> {}],
    snapshotBinding = [d \in Domains |-> NoBinding],
    snapshotCohort = [d \in Domains |-> {}],
    adoptCount = [d \in Domains |-> 0],
    crashCount = 0,
    deviceGeneration = 0,

    effectsAtClose = {},
    closingEffects = {},
    closingDomains = {},
    committedAtClose = {},
    commitAtClose = [e \in Effects |-> 0],
    domainReceipt = [d \in Domains |-> "Open"],
    receiptCount = [d \in Domains |-> 0],
    nextReceiptSequence = 1,
    receiptSequence = [d \in Domains |-> 0],
    receiptClosingEpoch = [d \in Domains |-> NoEpoch],
    receiptBindingEpoch = [d \in Domains |-> NoBinding],
    receiptDeviceGeneration = [d \in Domains |-> NoEpoch],
    timeoutReceiptSequence = 0,
    timeoutReceiptClosingEpoch = NoEpoch,
    timeoutReceiptBindingEpoch = NoBinding,
    timeoutReceiptDeviceGeneration = NoEpoch,
    closedReceiptSequence = [d \in Domains |-> 0],
    staleReceiptPresentedSequence = 0,
    staleReceiptRejectCount = 0,
    closureTargetCount = 0,
    closureSteps = 0,

    tombstoneHeld = FALSE,
    timeoutCount = 0,
    retryCount = 0,
    timeoutSeen = FALSE,
    retrySeen = FALSE;

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* DeriveEffect atomically installs the immutable causal record
            \* and transfers one typed scope credit to its owning domain.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Unused"
                      /\ ParentCanDerive(e, effectState, effectBinding,
                            bindingEpoch, domainPhase)
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ freeCredits[EffectCredit(e)] = 1;
                effectState[e] := "Registered";
                effectParent[e] := AllowedParent(e);
                effectAuthority[e] := authorityEpoch;
                effectBinding[e] := bindingEpoch[EffectDomain(e)];
                if e = "EVirtIo" then
                    effectDeviceGeneration[e] := deviceGeneration;
                end if;
                creditSource[e] := AllowedParent(e);
                creditKind[e] := EffectCredit(e);
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] - 1;
            end with;
        or
            with e \in Effects do
                \* Commit is fenced by all three local facts: the root
                \* authority gate, this domain's binding, and a live service.
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Registered"
                      /\ effectAuthority[e] = authorityEpoch
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ effectBinding[e] = bindingEpoch[EffectDomain(e)];
                effectState[e] := "Committed";
                commitCount[e] := commitCount[e] + 1;
            end with;
        or
            with d \in Domains do
                \* The bound permits one domain crash.  Only that binding
                \* advances; committed effects stay kernel-owned and only
                \* uncommitted work enters the explicit adoption cohort.
                await /\ EnableCrash
                      /\ scopeState = "Active"
                      /\ domainPhase[d] = "Bound"
                      /\ crashCount = 0
                      /\ \E e \in Effects :
                            EffectDomain(e) = d
                            /\ effectState[e] \in {"Registered", "Committed"};
                bindingEpoch[d] := bindingEpoch[d] + 1;
                domainPhase[d] := "Down";
                recoveryCohort[d] :=
                    {e \in Effects : EffectDomain(e) = d
                        /\ effectState[e] = "Registered"};
                snapshotBinding[d] := NoBinding;
                snapshotCohort[d] := {};
                crashCount := crashCount + 1;
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Down";
                snapshotBinding[d] := bindingEpoch[d];
                snapshotCohort[d] := recoveryCohort[d];
                domainPhase[d] := "Snapshotted";
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Snapshotted"
                      /\ snapshotBinding[d] = bindingEpoch[d]
                      /\ snapshotCohort[d] = recoveryCohort[d];
                domainPhase[d] := "Ready";
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Ready";
                domainPhase[d] := "Bound";
            end with;
        or
            with d \in Domains, e \in recoveryCohort[d] do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Bound"
                      /\ EffectDomain(e) = d
                      /\ effectState[e] = "Registered"
                      /\ effectBinding[e] # bindingEpoch[d];
                effectBinding[e] := bindingEpoch[d];
                recoveryCohort[d] := recoveryCohort[d] \ {e};
                adoptCount[d] := adoptCount[d] + 1;
            end with;
        or
            \* RevokeBegin is the single root linearization point.  It closes
            \* child derivation and commit, advances authority, and freezes
            \* both the exact live-effect cohort and its participating domains.
            await scopeState = "Active";
            effectsAtClose :=
                {e \in Effects : effectState[e] # "Unused"};
            closingEffects :=
                {e \in Effects : effectState[e] \in LiveStates};
            closingDomains :=
                {d \in Domains : \E e \in Effects :
                    EffectDomain(e) = d /\ effectState[e] \in LiveStates};
            committedAtClose :=
                {e \in Effects : effectState[e] = "Committed"};
            commitAtClose := commitCount;
            closureTargetCount :=
                Cardinality({e \in Effects : effectState[e] \in LiveStates});
            closureSteps := 0;
            domainReceipt := [d \in Domains |->
                IF \E e \in Effects :
                    EffectDomain(e) = d /\ effectState[e] \in LiveStates
                THEN "Pending" ELSE "NotRequired"];
            receiptCount := [d \in Domains |-> 0];
            staleReceiptPresentedSequence := 0;
            staleReceiptRejectCount := 0;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeGate := "Closed";
            scopeState := "Closing";
            domainPhase := [d \in Domains |-> "Closed"];
            recoveryCohort := [d \in Domains |-> {}];
        or
            \* A committed external effect may fail to quiesce.  Timeout is
            \* evidence retention, not a terminal outcome or closure receipt.
            await /\ EnableTimeout
                  /\ scopeState = "Closing"
                  /\ "EVirtIo" \in closingEffects
                  /\ effectState["EVirtIo"] = "Committed"
                  /\ domainReceipt["VirtIo"] = "Pending"
                  /\ timeoutCount = 0;
            effectState["EVirtIo"] := "Tombstoned";
            domainReceipt["VirtIo"] := "TimedOut";
            receiptSequence["VirtIo"] := nextReceiptSequence;
            receiptClosingEpoch["VirtIo"] := closingEpoch;
            receiptBindingEpoch["VirtIo"] := bindingEpoch["VirtIo"];
            receiptDeviceGeneration["VirtIo"] := deviceGeneration;
            timeoutReceiptSequence := nextReceiptSequence;
            timeoutReceiptClosingEpoch := closingEpoch;
            timeoutReceiptBindingEpoch := bindingEpoch["VirtIo"];
            timeoutReceiptDeviceGeneration := deviceGeneration;
            nextReceiptSequence := nextReceiptSequence + 1;
            tombstoneHeld := TRUE;
            timeoutCount := timeoutCount + 1;
            timeoutSeen := TRUE;
        or
            \* Retry retains the same effect identity and DMA credit.  It
            \* merely reopens the pending domain closure path once.
            await /\ scopeState = "Closing"
                  /\ effectState["EVirtIo"] = "Tombstoned"
                  /\ domainReceipt["VirtIo"] = "TimedOut"
                  /\ tombstoneHeld
                  /\ retryCount = 0;
            effectState["EVirtIo"] := "Committed";
            domainReceipt["VirtIo"] := "Pending";
            tombstoneHeld := FALSE;
            deviceGeneration := deviceGeneration + 1;
            retryCount := retryCount + 1;
            retrySeen := TRUE;
        or
            \* A retained old timeout receipt cannot be replayed as
            \* closure after retry.  The reject changes audit state only.
            await /\ scopeState = "Closing"
                  /\ retrySeen
                  /\ timeoutReceiptSequence # 0
                  /\ receiptSequence["VirtIo"] = timeoutReceiptSequence
                  /\ timeoutReceiptClosingEpoch = closingEpoch
                  /\ timeoutReceiptBindingEpoch = bindingEpoch["VirtIo"]
                  /\ timeoutReceiptDeviceGeneration # deviceGeneration
                  /\ domainReceipt["VirtIo"] = "Pending"
                  /\ staleReceiptRejectCount = 0;
            staleReceiptPresentedSequence := timeoutReceiptSequence;
            staleReceiptRejectCount := staleReceiptRejectCount + 1;
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            \* Active completion is kernel-owned.  A parent cannot discard its
            \* record or credit while an already-derived child remains live.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ effectState[e] = "Committed"
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Completed";
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
            end with;
        or
            \* Closing is child-first.  Uncommitted work aborts; committed
            \* work completes its existing obligation and is never relabeled.
            with e \in closingEffects do
                await /\ scopeState = "Closing"
                      /\ effectState[e] \in {"Registered", "Committed"}
                      /\ ChildrenTerminal(e, effectState, effectParent);
                if effectState[e] = "Registered" then
                    effectState[e] := "Aborted";
                else
                    effectState[e] := "Completed";
                end if;
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
                closureSteps := closureSteps + 1;
            end with;
        or
            \* A receipt is issued exactly once and only after that frozen
            \* domain cohort is terminal.  Closed domains are never revisited.
            with d \in closingDomains do
                await /\ scopeState = "Closing"
                      /\ domainReceipt[d] = "Pending"
                      /\ DomainClosingTerminal(d, closingEffects, effectState)
                      /\ ~(d = "VirtIo" /\ tombstoneHeld);
                domainReceipt[d] := "Closed";
                receiptCount[d] := receiptCount[d] + 1;
                receiptSequence[d] := nextReceiptSequence;
                receiptClosingEpoch[d] := closingEpoch;
                receiptBindingEpoch[d] := bindingEpoch[d];
                if d = "VirtIo" then
                    receiptDeviceGeneration[d] := deviceGeneration;
                else
                    receiptDeviceGeneration[d] := NoEpoch;
                end if;
                closedReceiptSequence[d] := nextReceiptSequence;
                nextReceiptSequence := nextReceiptSequence + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ closureSteps = closureTargetCount
                  /\ \A e \in closingEffects :
                        effectState[e] \in TerminalStates
                  /\ \A d \in closingDomains :
                        domainReceipt[d] = "Closed"
                  /\ \A t \in CreditTypes : freeCredits[t] = 1
                  /\ ~tombstoneHeld;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)

\* BEGIN TRANSLATION
VARIABLES scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, closedReceiptSequence, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen

vars == << scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, closedReceiptSequence, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ effectState = [e \in Effects |-> "Unused"]
        /\ effectParent = [e \in Effects |-> NoParent]
        /\ effectAuthority = [e \in Effects |-> NoEpoch]
        /\ effectBinding = [e \in Effects |-> NoBinding]
        /\ commitCount = [e \in Effects |-> 0]
        /\ terminalCount = [e \in Effects |-> 0]
        /\ effectDeviceGeneration = [e \in Effects |-> NoEpoch]
        /\ freeCredits = [t \in CreditTypes |-> 1]
        /\ creditSource = [e \in Effects |-> NoParent]
        /\ creditKind = [e \in Effects |-> "None"]
        /\ bindingEpoch = [d \in Domains |-> 0]
        /\ domainPhase = [d \in Domains |-> "Bound"]
        /\ recoveryCohort = [d \in Domains |-> {}]
        /\ snapshotBinding = [d \in Domains |-> NoBinding]
        /\ snapshotCohort = [d \in Domains |-> {}]
        /\ adoptCount = [d \in Domains |-> 0]
        /\ crashCount = 0
        /\ deviceGeneration = 0
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ closingDomains = {}
        /\ committedAtClose = {}
        /\ commitAtClose = [e \in Effects |-> 0]
        /\ domainReceipt = [d \in Domains |-> "Open"]
        /\ receiptCount = [d \in Domains |-> 0]
        /\ nextReceiptSequence = 1
        /\ receiptSequence = [d \in Domains |-> 0]
        /\ receiptClosingEpoch = [d \in Domains |-> NoEpoch]
        /\ receiptBindingEpoch = [d \in Domains |-> NoBinding]
        /\ receiptDeviceGeneration = [d \in Domains |-> NoEpoch]
        /\ timeoutReceiptSequence = 0
        /\ timeoutReceiptClosingEpoch = NoEpoch
        /\ timeoutReceiptBindingEpoch = NoBinding
        /\ timeoutReceiptDeviceGeneration = NoEpoch
        /\ closedReceiptSequence = [d \in Domains |-> 0]
        /\ staleReceiptPresentedSequence = 0
        /\ staleReceiptRejectCount = 0
        /\ closureTargetCount = 0
        /\ closureSteps = 0
        /\ tombstoneHeld = FALSE
        /\ timeoutCount = 0
        /\ retryCount = 0
        /\ timeoutSeen = FALSE
        /\ retrySeen = FALSE

Environment == /\ \/ /\ \E e \in Effects:
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Unused"
                             /\ ParentCanDerive(e, effectState, effectBinding,
                                   bindingEpoch, domainPhase)
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ freeCredits[EffectCredit(e)] = 1
                          /\ effectState' = [effectState EXCEPT ![e] = "Registered"]
                          /\ effectParent' = [effectParent EXCEPT ![e] = AllowedParent(e)]
                          /\ effectAuthority' = [effectAuthority EXCEPT ![e] = authorityEpoch]
                          /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[EffectDomain(e)]]
                          /\ IF e = "EVirtIo"
                                THEN /\ effectDeviceGeneration' = [effectDeviceGeneration EXCEPT ![e] = deviceGeneration]
                                ELSE /\ TRUE
                                     /\ UNCHANGED effectDeviceGeneration
                          /\ creditSource' = [creditSource EXCEPT ![e] = AllowedParent(e)]
                          /\ creditKind' = [creditKind EXCEPT ![e] = EffectCredit(e)]
                          /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] - 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, commitCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ \E e \in Effects:
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Registered"
                             /\ effectAuthority[e] = authorityEpoch
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                          /\ effectState' = [effectState EXCEPT ![e] = "Committed"]
                          /\ commitCount' = [commitCount EXCEPT ![e] = commitCount[e] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ \E d \in Domains:
                          /\ /\ EnableCrash
                             /\ scopeState = "Active"
                             /\ domainPhase[d] = "Bound"
                             /\ crashCount = 0
                             /\ \E e \in Effects :
                                   EffectDomain(e) = d
                                   /\ effectState[e] \in {"Registered", "Committed"}
                          /\ bindingEpoch' = [bindingEpoch EXCEPT ![d] = bindingEpoch[d] + 1]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Down"]
                          /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = {e \in Effects : EffectDomain(e) = d
                                                                                 /\ effectState[e] = "Registered"}]
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = NoBinding]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = {}]
                          /\ crashCount' = crashCount + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, adoptCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Down"
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = bindingEpoch[d]]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = recoveryCohort[d]]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Snapshotted"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, recoveryCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Snapshotted"
                             /\ snapshotBinding[d] = bindingEpoch[d]
                             /\ snapshotCohort[d] = recoveryCohort[d]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Ready"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Ready"
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Bound"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ \E d \in Domains:
                          \E e \in recoveryCohort[d]:
                            /\ /\ scopeState = "Active"
                               /\ domainPhase[d] = "Bound"
                               /\ EffectDomain(e) = d
                               /\ effectState[e] = "Registered"
                               /\ effectBinding[e] # bindingEpoch[d]
                            /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[d]]
                            /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = recoveryCohort[d] \ {e}]
                            /\ adoptCount' = [adoptCount EXCEPT ![d] = adoptCount[d] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, snapshotBinding, snapshotCohort, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ scopeState = "Active"
                     /\ effectsAtClose' = {e \in Effects : effectState[e] # "Unused"}
                     /\ closingEffects' = {e \in Effects : effectState[e] \in LiveStates}
                     /\ closingDomains' = {d \in Domains : \E e \in Effects :
                                              EffectDomain(e) = d /\ effectState[e] \in LiveStates}
                     /\ committedAtClose' = {e \in Effects : effectState[e] = "Committed"}
                     /\ commitAtClose' = commitCount
                     /\ closureTargetCount' = Cardinality({e \in Effects : effectState[e] \in LiveStates})
                     /\ closureSteps' = 0
                     /\ domainReceipt' =              [d \in Domains |->
                                         IF \E e \in Effects :
                                             EffectDomain(e) = d /\ effectState[e] \in LiveStates
                                         THEN "Pending" ELSE "NotRequired"]
                     /\ receiptCount' = [d \in Domains |-> 0]
                     /\ staleReceiptPresentedSequence' = 0
                     /\ staleReceiptRejectCount' = 0
                     /\ closingEpoch' = authorityEpoch
                     /\ authorityEpoch' = authorityEpoch + 1
                     /\ scopeGate' = "Closed"
                     /\ scopeState' = "Closing"
                     /\ domainPhase' = [d \in Domains |-> "Closed"]
                     /\ recoveryCohort' = [d \in Domains |-> {}]
                     /\ UNCHANGED <<effectState, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
                  \/ /\ /\ EnableTimeout
                        /\ scopeState = "Closing"
                        /\ "EVirtIo" \in closingEffects
                        /\ effectState["EVirtIo"] = "Committed"
                        /\ domainReceipt["VirtIo"] = "Pending"
                        /\ timeoutCount = 0
                     /\ effectState' = [effectState EXCEPT !["EVirtIo"] = "Tombstoned"]
                     /\ domainReceipt' = [domainReceipt EXCEPT !["VirtIo"] = "TimedOut"]
                     /\ receiptSequence' = [receiptSequence EXCEPT !["VirtIo"] = nextReceiptSequence]
                     /\ receiptClosingEpoch' = [receiptClosingEpoch EXCEPT !["VirtIo"] = closingEpoch]
                     /\ receiptBindingEpoch' = [receiptBindingEpoch EXCEPT !["VirtIo"] = bindingEpoch["VirtIo"]]
                     /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT !["VirtIo"] = deviceGeneration]
                     /\ timeoutReceiptSequence' = nextReceiptSequence
                     /\ timeoutReceiptClosingEpoch' = closingEpoch
                     /\ timeoutReceiptBindingEpoch' = bindingEpoch["VirtIo"]
                     /\ timeoutReceiptDeviceGeneration' = deviceGeneration
                     /\ nextReceiptSequence' = nextReceiptSequence + 1
                     /\ tombstoneHeld' = TRUE
                     /\ timeoutCount' = timeoutCount + 1
                     /\ timeoutSeen' = TRUE
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, receiptCount, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, retryCount, retrySeen>>
                  \/ /\ /\ scopeState = "Closing"
                        /\ effectState["EVirtIo"] = "Tombstoned"
                        /\ domainReceipt["VirtIo"] = "TimedOut"
                        /\ tombstoneHeld
                        /\ retryCount = 0
                     /\ effectState' = [effectState EXCEPT !["EVirtIo"] = "Committed"]
                     /\ domainReceipt' = [domainReceipt EXCEPT !["VirtIo"] = "Pending"]
                     /\ tombstoneHeld' = FALSE
                     /\ deviceGeneration' = deviceGeneration + 1
                     /\ retryCount' = retryCount + 1
                     /\ retrySeen' = TRUE
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, closureSteps, timeoutCount, timeoutSeen>>
                  \/ /\ /\ scopeState = "Closing"
                        /\ retrySeen
                        /\ timeoutReceiptSequence # 0
                        /\ receiptSequence["VirtIo"] = timeoutReceiptSequence
                        /\ timeoutReceiptClosingEpoch = closingEpoch
                        /\ timeoutReceiptBindingEpoch = bindingEpoch["VirtIo"]
                        /\ timeoutReceiptDeviceGeneration # deviceGeneration
                        /\ domainReceipt["VirtIo"] = "Pending"
                        /\ staleReceiptRejectCount = 0
                     /\ staleReceiptPresentedSequence' = timeoutReceiptSequence
                     /\ staleReceiptRejectCount' = staleReceiptRejectCount + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, freeCredits, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, closureTargetCount, closureSteps, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen>>
               /\ UNCHANGED << terminalCount, closedReceiptSequence >>

Kernel == /\ \/ /\ \E e \in Effects:
                     /\ /\ scopeState = "Active"
                        /\ effectState[e] = "Committed"
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                /\ UNCHANGED <<scopeState, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, closureSteps>>
             \/ /\ \E e \in closingEffects:
                     /\ /\ scopeState = "Closing"
                        /\ effectState[e] \in {"Registered", "Committed"}
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ IF effectState[e] = "Registered"
                           THEN /\ effectState' = [effectState EXCEPT ![e] = "Aborted"]
                           ELSE /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                     /\ closureSteps' = closureSteps + 1
                /\ UNCHANGED <<scopeState, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence>>
             \/ /\ \E d \in closingDomains:
                     /\ /\ scopeState = "Closing"
                        /\ domainReceipt[d] = "Pending"
                        /\ DomainClosingTerminal(d, closingEffects, effectState)
                        /\ ~(d = "VirtIo" /\ tombstoneHeld)
                     /\ domainReceipt' = [domainReceipt EXCEPT ![d] = "Closed"]
                     /\ receiptCount' = [receiptCount EXCEPT ![d] = receiptCount[d] + 1]
                     /\ receiptSequence' = [receiptSequence EXCEPT ![d] = nextReceiptSequence]
                     /\ receiptClosingEpoch' = [receiptClosingEpoch EXCEPT ![d] = closingEpoch]
                     /\ receiptBindingEpoch' = [receiptBindingEpoch EXCEPT ![d] = bindingEpoch[d]]
                     /\ IF d = "VirtIo"
                           THEN /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT ![d] = deviceGeneration]
                           ELSE /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT ![d] = NoEpoch]
                     /\ closedReceiptSequence' = [closedReceiptSequence EXCEPT ![d] = nextReceiptSequence]
                     /\ nextReceiptSequence' = nextReceiptSequence + 1
                /\ UNCHANGED <<scopeState, effectState, terminalCount, freeCredits, closureSteps>>
             \/ /\ /\ scopeState = "Closing"
                   /\ closureSteps = closureTargetCount
                   /\ \A e \in closingEffects :
                         effectState[e] \in TerminalStates
                   /\ \A d \in closingDomains :
                         domainReceipt[d] = "Closed"
                   /\ \A t \in CreditTypes : freeCredits[t] = 1
                   /\ ~tombstoneHeld
                /\ scopeState' = "Revoked"
                /\ UNCHANGED <<effectState, terminalCount, freeCredits, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, closureSteps>>
          /\ UNCHANGED << scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, effectDeviceGeneration, creditSource, creditKind, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, timeoutReceiptSequence, timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration, staleReceiptPresentedSequence, staleReceiptRejectCount, closureTargetCount, tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

TypeOK ==
    /\ scopeState \in {"Active", "Closing", "Revoked"}
    /\ scopeGate \in {"Open", "Closed"}
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ effectState \in [Effects ->
        {"Unused", "Registered", "Committed", "Tombstoned",
         "Completed", "Aborted"}]
    /\ effectParent \in [Effects -> Effects \cup {Root, NoParent}]
    /\ effectAuthority \in [Effects -> {NoEpoch, 0}]
    /\ effectBinding \in [Effects -> {NoBinding} \cup (0..MaxBinding)]
    /\ commitCount \in [Effects -> 0..1]
    /\ terminalCount \in [Effects -> 0..1]
    /\ effectDeviceGeneration \in [Effects -> {NoEpoch, 0}]
    /\ freeCredits \in [CreditTypes -> 0..1]
    /\ creditSource \in [Effects -> Effects \cup {Root, NoParent}]
    /\ creditKind \in [Effects -> CreditTypes \cup {"None"}]
    /\ bindingEpoch \in [Domains -> 0..MaxBinding]
    /\ domainPhase \in [Domains ->
        {"Bound", "Down", "Snapshotted", "Ready", "Closed"}]
    /\ recoveryCohort \in [Domains -> SUBSET Effects]
    /\ snapshotBinding \in [Domains -> {NoBinding} \cup (0..MaxBinding)]
    /\ snapshotCohort \in [Domains -> SUBSET Effects]
    /\ adoptCount \in [Domains -> 0..1]
    /\ crashCount \in 0..1
    /\ deviceGeneration \in 0..1
    /\ effectsAtClose \subseteq Effects
    /\ closingEffects \subseteq Effects
    /\ closingDomains \subseteq Domains
    /\ committedAtClose \subseteq Effects
    /\ commitAtClose \in [Effects -> 0..1]
    /\ domainReceipt \in [Domains ->
        {"Open", "Pending", "TimedOut", "Closed", "NotRequired"}]
    /\ receiptCount \in [Domains -> 0..1]
    /\ nextReceiptSequence \in 1..(MaxReceiptSequence + 1)
    /\ receiptSequence \in [Domains -> 0..MaxReceiptSequence]
    /\ receiptClosingEpoch \in [Domains -> {NoEpoch, 0}]
    /\ receiptBindingEpoch \in
        [Domains -> {NoBinding} \cup (0..MaxBinding)]
    /\ receiptDeviceGeneration \in [Domains -> {NoEpoch, 0, 1}]
    /\ timeoutReceiptSequence \in 0..MaxReceiptSequence
    /\ timeoutReceiptClosingEpoch \in {NoEpoch, 0}
    /\ timeoutReceiptBindingEpoch \in
        {NoBinding} \cup (0..MaxBinding)
    /\ timeoutReceiptDeviceGeneration \in {NoEpoch, 0, 1}
    /\ closedReceiptSequence \in [Domains -> 0..MaxReceiptSequence]
    /\ staleReceiptPresentedSequence \in 0..MaxReceiptSequence
    /\ staleReceiptRejectCount \in 0..1
    /\ closureTargetCount \in 0..Cardinality(Effects)
    /\ closureSteps \in 0..Cardinality(Effects)
    /\ tombstoneHeld \in BOOLEAN
    /\ timeoutCount \in 0..1
    /\ retryCount \in 0..1
    /\ timeoutSeen \in BOOLEAN
    /\ retrySeen \in BOOLEAN
    /\ \A d \in Domains :
        /\ recoveryCohort[d] \subseteq
            {e \in Effects : EffectDomain(e) = d}
        /\ snapshotCohort[d] \subseteq
            {e \in Effects : EffectDomain(e) = d}

ScopeGateDiscipline ==
    /\ (scopeState = "Active" <=>
        /\ scopeGate = "Open"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoEpoch)
    /\ (scopeState \in {"Closing", "Revoked"} <=>
        /\ scopeGate = "Closed"
        /\ authorityEpoch = 1
        /\ closingEpoch = 0)

CausalIdentity ==
    /\ \A e \in Effects :
        /\ (effectState[e] = "Unused" =>
            /\ effectParent[e] = NoParent
            /\ effectAuthority[e] = NoEpoch
            /\ effectBinding[e] = NoBinding
            /\ effectDeviceGeneration[e] = NoEpoch
            /\ creditSource[e] = NoParent
            /\ creditKind[e] = "None")
        /\ (effectState[e] # "Unused" =>
            /\ effectParent[e] = AllowedParent(e)
            /\ effectAuthority[e] = 0
            /\ effectBinding[e] \in 0..MaxBinding
            /\ effectDeviceGeneration[e] =
                IF e = "EVirtIo" THEN 0 ELSE NoEpoch
            /\ creditSource[e] = AllowedParent(e)
            /\ creditKind[e] = EffectCredit(e))
    /\ \A child \in Effects :
        effectState[child] # "Unused" =>
            IF effectParent[child] = Root
            THEN TRUE
            ELSE effectState[effectParent[child]] # "Unused"

NoOrphanDescendants ==
    \A parent \in Effects :
        effectState[parent] \in TerminalStates =>
            \A child \in Effects :
                (effectParent[child] = parent
                    /\ effectState[child] # "Unused")
                => effectState[child] \in TerminalStates

EffectLifecycle ==
    \A e \in Effects :
        /\ (effectState[e] = "Unused" =>
            /\ commitCount[e] = 0 /\ terminalCount[e] = 0)
        /\ (effectState[e] = "Registered" =>
            /\ commitCount[e] = 0 /\ terminalCount[e] = 0)
        /\ (effectState[e] \in {"Committed", "Tombstoned"} =>
            /\ commitCount[e] = 1 /\ terminalCount[e] = 0)
        /\ (effectState[e] = "Completed" =>
            /\ commitCount[e] = 1 /\ terminalCount[e] = 1)
        /\ (effectState[e] = "Aborted" =>
            /\ commitCount[e] = 0 /\ terminalCount[e] = 1)

TypedCreditConservation ==
    \A t \in CreditTypes :
        freeCredits[t]
        + Cardinality({e \in Effects :
            EffectCredit(e) = t /\ effectState[e] \in LiveStates}) = 1

CrashIsolation ==
    /\ Cardinality({d \in Domains : bindingEpoch[d] = 1}) = crashCount
    /\ \A d \in Domains : adoptCount[d] <= bindingEpoch[d]
    /\ \A d \in Domains :
        domainPhase[d] \in {"Down", "Snapshotted", "Ready"}
        => bindingEpoch[d] = 1

RecoveryDiscipline ==
    \A d \in Domains :
        /\ \A e \in recoveryCohort[d] :
            /\ EffectDomain(e) = d
            /\ effectState[e] = "Registered"
            /\ effectBinding[e] # bindingEpoch[d]
        /\ (domainPhase[d] = "Ready" =>
            /\ snapshotBinding[d] = bindingEpoch[d]
            /\ snapshotCohort[d] = recoveryCohort[d])

FrozenClosureCohort ==
    /\ (scopeState = "Active" =>
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ closingDomains = {}
        /\ committedAtClose = {}
        /\ domainReceipt = [d \in Domains |-> "Open"])
    /\ (scopeState \in {"Closing", "Revoked"} =>
        /\ effectsAtClose = {e \in Effects : effectState[e] # "Unused"}
        /\ closingDomains =
            {d \in Domains : \E e \in closingEffects :
                EffectDomain(e) = d}
        /\ committedAtClose \subseteq closingEffects
        /\ closureTargetCount = Cardinality(closingEffects)
        /\ \A d \in Domains \ closingDomains :
            domainReceipt[d] = "NotRequired")

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} => commitCount = commitAtClose

NoPostRevokeDerivation ==
    scopeState \in {"Closing", "Revoked"} =>
        effectsAtClose = {e \in Effects : effectState[e] # "Unused"}

IssuedReceiptSequences ==
    {closedReceiptSequence[d] :
        d \in {candidate \in Domains :
            closedReceiptSequence[candidate] # 0}}
    \cup IF timeoutSeen THEN {timeoutReceiptSequence} ELSE {}

ExactClosureReceipts ==
    /\ \A d \in Domains :
        /\ (domainReceipt[d] = "Closed" =>
            /\ d \in closingDomains
            /\ DomainClosingTerminal(d, closingEffects, effectState)
            /\ ~(d = "VirtIo" /\ tombstoneHeld)
            /\ receiptCount[d] = 1
            /\ closedReceiptSequence[d] = receiptSequence[d]
            /\ closedReceiptSequence[d] # 0
            /\ receiptClosingEpoch[d] = closingEpoch
            /\ receiptBindingEpoch[d] = bindingEpoch[d]
            /\ receiptDeviceGeneration[d] =
                IF d = "VirtIo" THEN deviceGeneration ELSE NoEpoch)
        /\ (receiptCount[d] = 1 <=> domainReceipt[d] = "Closed")
        /\ (closedReceiptSequence[d] # 0 <=>
            domainReceipt[d] = "Closed")
        /\ (domainReceipt[d] \in {"Open", "NotRequired"} =>
            /\ receiptSequence[d] = 0
            /\ receiptClosingEpoch[d] = NoEpoch
            /\ receiptBindingEpoch[d] = NoBinding
            /\ receiptDeviceGeneration[d] = NoEpoch)
        /\ (domainReceipt[d] = "Pending" =>
            IF d = "VirtIo" /\ retrySeen
            THEN /\ receiptSequence[d] = timeoutReceiptSequence
                 /\ receiptClosingEpoch[d] = timeoutReceiptClosingEpoch
                 /\ receiptBindingEpoch[d] = timeoutReceiptBindingEpoch
                 /\ receiptDeviceGeneration[d] =
                        timeoutReceiptDeviceGeneration
            ELSE /\ receiptSequence[d] = 0
                 /\ receiptClosingEpoch[d] = NoEpoch
                 /\ receiptBindingEpoch[d] = NoBinding
                 /\ receiptDeviceGeneration[d] = NoEpoch)
    /\ (domainReceipt["VirtIo"] = "TimedOut" <=>
        /\ scopeState = "Closing"
        /\ effectState["EVirtIo"] = "Tombstoned"
        /\ tombstoneHeld)
    /\ (domainReceipt["VirtIo"] = "TimedOut" =>
        /\ receiptSequence["VirtIo"] = timeoutReceiptSequence
        /\ receiptClosingEpoch["VirtIo"] = timeoutReceiptClosingEpoch
        /\ receiptBindingEpoch["VirtIo"] = timeoutReceiptBindingEpoch
        /\ receiptDeviceGeneration["VirtIo"] =
            timeoutReceiptDeviceGeneration)
    /\ (timeoutSeen =>
        /\ timeoutReceiptSequence # 0
        /\ timeoutReceiptSequence < nextReceiptSequence
        /\ timeoutReceiptClosingEpoch = closingEpoch
        /\ timeoutReceiptBindingEpoch = bindingEpoch["VirtIo"]
        /\ timeoutReceiptDeviceGeneration = 0)
    /\ (~timeoutSeen =>
        /\ timeoutReceiptSequence = 0
        /\ timeoutReceiptClosingEpoch = NoEpoch
        /\ timeoutReceiptBindingEpoch = NoBinding
        /\ timeoutReceiptDeviceGeneration = NoEpoch)
    /\ nextReceiptSequence =
        1 + Cardinality({d \in Domains : receiptCount[d] = 1})
          + IF timeoutSeen THEN 1 ELSE 0
    /\ IssuedReceiptSequences = 1..(nextReceiptSequence - 1)
    /\ \A d \in Domains :
        receiptSequence[d] < nextReceiptSequence
    /\ \A d1, d2 \in Domains :
        closedReceiptSequence[d1] # 0
            /\ closedReceiptSequence[d1] = closedReceiptSequence[d2]
        => d1 = d2
    /\ (timeoutSeen => \A d \in Domains :
        closedReceiptSequence[d] # timeoutReceiptSequence)
    /\ (timeoutSeen /\ domainReceipt["VirtIo"] = "Closed" =>
        /\ closedReceiptSequence["VirtIo"] > timeoutReceiptSequence)
    /\ (staleReceiptRejectCount = 1 =>
        /\ retrySeen
        /\ staleReceiptPresentedSequence = timeoutReceiptSequence
        /\ timeoutReceiptSequence # 0
        /\ timeoutReceiptDeviceGeneration < deviceGeneration)

TimeoutHonesty ==
    /\ (tombstoneHeld =>
        /\ scopeState = "Closing"
        /\ effectState["EVirtIo"] = "Tombstoned"
        /\ effectDeviceGeneration["EVirtIo"] = 0
        /\ deviceGeneration = 0
        /\ freeCredits["Dma"] = 0
        /\ terminalCount["EVirtIo"] = 0
        /\ domainReceipt["VirtIo"] = "TimedOut")
    /\ timeoutSeen = (timeoutCount = 1)
    /\ retrySeen = (retryCount = 1)
    /\ retryCount <= timeoutCount
    /\ (retrySeen => deviceGeneration = 1)
    /\ (~retrySeen => deviceGeneration = 0)

SingleTerminalization ==
    \A e \in Effects : terminalCount[e] <= 1

QuiescentClosure ==
    scopeState = "Revoked" =>
        /\ \A e \in effectsAtClose : effectState[e] \in TerminalStates
        /\ \A d \in closingDomains : domainReceipt[d] = "Closed"
        /\ \A t \in CreditTypes : freeCredits[t] = 1
        /\ closureSteps = closureTargetCount
        /\ ~tombstoneHeld

CausalEdgeImmutability ==
    [][\A e \in Effects :
        effectParent[e] # NoParent => effectParent'[e] = effectParent[e]]_vars

DeriveGateAction ==
    [][\A e \in Effects :
        effectState[e] = "Unused" /\ effectState'[e] = "Registered" =>
            /\ scopeState = "Active"
            /\ scopeGate = "Open"
            /\ domainPhase[EffectDomain(e)] = "Bound"
            /\ ParentCanDerive(e, effectState, effectBinding,
                bindingEpoch, domainPhase)]_vars

CommitGateAction ==
    [][\A e \in Effects :
        commitCount'[e] > commitCount[e] =>
            /\ scopeState = "Active"
            /\ scopeGate = "Open"
            /\ effectAuthority[e] = authorityEpoch
            /\ domainPhase[EffectDomain(e)] = "Bound"
            /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]]_vars

DomainBindingIsolation ==
    [][(\E d \in Domains : bindingEpoch'[d] # bindingEpoch[d]) =>
        /\ Cardinality({d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d]}) = 1
        /\ \A d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d]
            => bindingEpoch'[d] = bindingEpoch[d] + 1]_vars

GlobalReceiptSequenceDiscipline ==
    [][/\ nextReceiptSequence' >= nextReceiptSequence
        /\ nextReceiptSequence' <= nextReceiptSequence + 1
        /\ (nextReceiptSequence' = nextReceiptSequence => UNCHANGED <<
            receiptSequence, receiptClosingEpoch, receiptBindingEpoch,
            receiptDeviceGeneration, timeoutReceiptSequence,
            timeoutReceiptClosingEpoch, timeoutReceiptBindingEpoch,
            timeoutReceiptDeviceGeneration, closedReceiptSequence
        >>)
        /\ (nextReceiptSequence' = nextReceiptSequence + 1 =>
            /\ scopeState = "Closing"
            /\ Cardinality({d \in Domains :
                    closedReceiptSequence[d] = 0
                    /\ closedReceiptSequence'[d] = nextReceiptSequence})
                + (IF timeoutReceiptSequence = 0
                        /\ timeoutReceiptSequence' = nextReceiptSequence
                   THEN 1 ELSE 0) = 1
            /\ \A d \in Domains :
                receiptSequence'[d] # receiptSequence[d]
                => receiptSequence'[d] = nextReceiptSequence
            /\ \A d \in Domains :
                closedReceiptSequence'[d] # closedReceiptSequence[d]
                => closedReceiptSequence'[d] = nextReceiptSequence
            /\ (timeoutReceiptSequence' # timeoutReceiptSequence =>
                timeoutReceiptSequence' = nextReceiptSequence))]_vars

StaleReceiptRejectSideEffectFreedom ==
    [][staleReceiptRejectCount' # staleReceiptRejectCount => UNCHANGED <<
        scopeState, scopeGate, authorityEpoch, closingEpoch, effectState,
        effectParent, effectAuthority, effectBinding, commitCount,
        terminalCount, effectDeviceGeneration, freeCredits, creditSource,
        creditKind, bindingEpoch, domainPhase, recoveryCohort,
        snapshotBinding, snapshotCohort, adoptCount, crashCount,
        deviceGeneration, effectsAtClose, closingEffects, closingDomains,
        committedAtClose, commitAtClose, domainReceipt, receiptCount,
        nextReceiptSequence, receiptSequence, receiptClosingEpoch,
        receiptBindingEpoch, receiptDeviceGeneration,
        timeoutReceiptSequence, timeoutReceiptClosingEpoch,
        timeoutReceiptBindingEpoch, timeoutReceiptDeviceGeneration,
        closedReceiptSequence, closureTargetCount, closureSteps,
        tombstoneHeld, timeoutCount, retryCount, timeoutSeen, retrySeen
    >>]_vars

ReadyForRevokeComplete ==
    /\ scopeState = "Closing"
    /\ closureSteps = closureTargetCount
    /\ \A e \in closingEffects : effectState[e] \in TerminalStates
    /\ \A d \in closingDomains : domainReceipt[d] = "Closed"
    /\ \A t \in CreditTypes : freeCredits[t] = 1
    /\ ~tombstoneHeld

ReceiptReady(d) ==
    /\ scopeState = "Closing"
    /\ d \in closingDomains
    /\ domainReceipt[d] = "Pending"
    /\ DomainClosingTerminal(d, closingEffects, effectState)
    /\ ~(d = "VirtIo" /\ tombstoneHeld)

ConditionalRevocationProgress ==
    [](ReadyForRevokeComplete ~> scopeState = "Revoked")

DomainReceiptProgress ==
    \A d \in Domains : [](ReceiptReady(d) ~> domainReceipt[d] = "Closed")

FiveDomainClosureObserved ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ closingEffects = Effects
    /\ closingDomains = Domains
    /\ \A d \in Domains : domainReceipt[d] = "Closed"
    /\ Cardinality({receiptSequence[d] : d \in Domains}) =
        Cardinality(Domains)
    /\ nextReceiptSequence = Cardinality(Domains) + 1
    /\ closureSteps = Cardinality(Effects)

CrashAdoptIsolationObserved ==
    /\ bindingEpoch["Pager"] = 1
    /\ \A d \in Domains \ {"Pager"} : bindingEpoch[d] = 0
    /\ adoptCount["Pager"] = 1
    /\ effectBinding["EPager"] = 1
    /\ recoveryCohort["Pager"] = {}
    /\ domainPhase["Pager"] = "Bound"

CommitAbortSplitObserved ==
    /\ scopeState = "Revoked"
    /\ committedAtClose # {}
    /\ closingEffects \ committedAtClose # {}
    /\ \E e \in committedAtClose : effectState[e] = "Completed"
    /\ \E e \in closingEffects \ committedAtClose :
        effectState[e] = "Aborted"

TimeoutRetryClosureObserved ==
    /\ scopeState = "Revoked"
    /\ timeoutSeen
    /\ retrySeen
    /\ timeoutCount = 1
    /\ retryCount = 1
    /\ deviceGeneration = 1
    /\ receiptSequence["VirtIo"] = 2
    /\ timeoutReceiptSequence = 1
    /\ timeoutReceiptClosingEpoch = closingEpoch
    /\ timeoutReceiptBindingEpoch = bindingEpoch["VirtIo"]
    /\ timeoutReceiptDeviceGeneration = 0
    /\ closedReceiptSequence["VirtIo"] = 2
    /\ receiptClosingEpoch["VirtIo"] = closingEpoch
    /\ receiptBindingEpoch["VirtIo"] = bindingEpoch["VirtIo"]
    /\ receiptDeviceGeneration["VirtIo"] = 1
    /\ staleReceiptPresentedSequence = 1
    /\ staleReceiptRejectCount = 1
    /\ domainReceipt["VirtIo"] = "Closed"

FiveDomainClosureAbsent == ~FiveDomainClosureObserved
CrashAdoptIsolationAbsent == ~CrashAdoptIsolationObserved
CommitAbortSplitAbsent == ~CommitAbortSplitObserved
TimeoutRetryClosureAbsent == ~TimeoutRetryClosureObserved

=============================================================================

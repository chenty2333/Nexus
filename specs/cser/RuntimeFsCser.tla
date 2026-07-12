-------------------- MODULE RuntimeFsCser --------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Bounded runtime-filesystem CSER successor.  The fixed causal graph is:   *)
(*                                                                         *)
(* Root -> Syscall -> PagerMap                                             *)
(*                 \-> FsOp -> BlockReq                                   *)
(*                                                                         *)
(* The model fixes four independently rebound service domains, four typed   *)
(* credits, failure-atomic pager and inode publication, and one mediated     *)
(* block request whose DMA owner survives reset/IOTLB timeout tombstones.   *)
(* It deliberately does not encode the complete Linux syscall or VFS ABI.   *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableCrash, EnableTimeout, EnableRejects

ASSUME /\ MaxBinding = 1
       /\ EnableCrash \in BOOLEAN
       /\ EnableTimeout \in BOOLEAN
       /\ EnableRejects \in BOOLEAN

Domains == {"Personality", "Pager", "Filesystem", "Block"}
Effects == {"Syscall", "PagerMap", "FsOp", "BlockReq"}
NonBlockEffects == Effects \ {"BlockReq"}
CreditTypes == {"Control", "Memory", "FilesystemCredit", "Dma"}
RejectKinds == {"Authority", "Binding", "AddressSpace", "Inode", "Device",
                "TimeoutReceipt"}
TimeoutTargets == {"Reset", "Iotlb"}

Root == "Root"
NoParent == "NoParent"
NoGeneration == -1
NoBinding == -1

EffectDomain(e) ==
    CASE e = "Syscall" -> "Personality"
      [] e = "PagerMap" -> "Pager"
      [] e = "FsOp" -> "Filesystem"
      [] e = "BlockReq" -> "Block"

EffectCredit(e) ==
    CASE e = "Syscall" -> "Control"
      [] e = "PagerMap" -> "Memory"
      [] e = "FsOp" -> "FilesystemCredit"
      [] e = "BlockReq" -> "Dma"

AllowedParent(e) ==
    CASE e = "Syscall" -> Root
      [] e = "PagerMap" -> "Syscall"
      [] e = "FsOp" -> "Syscall"
      [] e = "BlockReq" -> "FsOp"

LiveStates == {"Registered", "Prepared", "Committed", "Cancelling",
                "DeviceCompleted", "ResetIndeterminate", "Tombstoned"}
TerminalStates == {"Completed", "Aborted"}
UncommittedStates == {"Registered", "Prepared"}

ParentCanDerive(e, effectState, effectBinding, bindingEpoch, domainPhase) ==
    IF AllowedParent(e) = Root
    THEN TRUE
    ELSE /\ effectState[AllowedParent(e)] \in LiveStates
         /\ domainPhase[EffectDomain(AllowedParent(e))] = "Bound"
         /\ effectBinding[AllowedParent(e)] =
                bindingEpoch[EffectDomain(AllowedParent(e))]

ChildrenTerminal(e, effectState, effectParent) ==
    \A child \in Effects :
        (effectParent[child] = e /\ effectState[child] # "Unused")
        => effectState[child] \in TerminalStates

GenerationMatches(e, pagerAsGeneration, addressSpaceGeneration,
        fsInodeGeneration, inodeGeneration, blockDeviceGeneration,
        deviceGeneration) ==
    CASE e = "PagerMap" -> pagerAsGeneration = addressSpaceGeneration
      [] e = "FsOp" -> fsInodeGeneration = inodeGeneration
      [] e = "BlockReq" -> blockDeviceGeneration = deviceGeneration
      [] OTHER -> TRUE

StaleEnabled(kind, scopeState, bindingEpoch, pagerAsGeneration,
        addressSpaceGeneration, fsInodeGeneration, inodeGeneration,
        blockDeviceGeneration, deviceGeneration, retryKinds) ==
    CASE kind = "Authority" -> scopeState # "Active"
      [] kind = "Binding" -> \E d \in Domains : bindingEpoch[d] > 0
      [] kind = "AddressSpace" ->
            pagerAsGeneration # NoGeneration
                /\ pagerAsGeneration # addressSpaceGeneration
      [] kind = "Inode" ->
            fsInodeGeneration # NoGeneration
                /\ fsInodeGeneration # inodeGeneration
      [] kind = "Device" ->
            blockDeviceGeneration # NoGeneration
                /\ blockDeviceGeneration # deviceGeneration
      [] kind = "TimeoutReceipt" -> retryKinds # {}

(* --algorithm RuntimeFsCSER
variables
    scopeState = "Active",
    scopeGate = "Open",
    authorityEpoch = 0,
    closingEpoch = NoGeneration,

    effectState = [e \in Effects |-> "Unused"],
    effectParent = [e \in Effects |-> NoParent],
    effectAuthority = [e \in Effects |-> NoGeneration],
    effectBinding = [e \in Effects |-> NoBinding],
    commitCount = [e \in Effects |-> 0],
    terminalCount = [e \in Effects |-> 0],

    freeCredits = [t \in CreditTypes |-> 1],

    bindingEpoch = [d \in Domains |-> 0],
    domainPhase = [d \in Domains |-> "Bound"],
    recoveryCohort = [d \in Domains |-> {}],
    snapshotBinding = [d \in Domains |-> NoBinding],
    snapshotCohort = [d \in Domains |-> {}],
    adoptCount = [d \in Domains |-> 0],
    crashCount = 0,

    addressSpaceGeneration = 0,
    pagerAsGeneration = NoGeneration,
    ptePublished = FALSE,
    tlbSynced = FALSE,
    mapPublicationCount = 0,

    inodeGeneration = 0,
    fsInodeGeneration = NoGeneration,
    inodeBytes = "Zeros",
    inodePublicationCount = 0,

    deviceGeneration = 0,
    blockDeviceGeneration = NoGeneration,
    dmaState = "Absent",
    blockOutcome = "None",
    blockPublicationCount = 0,
    tombstoneKind = "None",
    tombstoneResume = "None",
    timeoutKinds = {},
    retryKinds = {},

    replyPublicationCount = 0,

    effectsAtClose = {},
    closingEffects = {},
    committedAtClose = {},
    commitAtClose = [e \in Effects |-> 0],

    rejectKinds = {};

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* Register captures authority, binding, and every applicable
            \* resource generation before any preparation is allowed.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Unused"
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ ParentCanDerive(e, effectState, effectBinding,
                            bindingEpoch, domainPhase)
                      /\ freeCredits[EffectCredit(e)] = 1;
                effectState[e] := "Registered";
                effectParent[e] := AllowedParent(e);
                effectAuthority[e] := authorityEpoch;
                effectBinding[e] := bindingEpoch[EffectDomain(e)];
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] - 1;
                if e = "PagerMap" then
                    pagerAsGeneration := addressSpaceGeneration;
                elsif e = "FsOp" then
                    fsInodeGeneration := inodeGeneration;
                elsif e = "BlockReq" then
                    blockDeviceGeneration := deviceGeneration;
                end if;
            end with;
        or
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Registered"
                      /\ effectAuthority[e] = authorityEpoch
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                      /\ GenerationMatches(e, pagerAsGeneration,
                            addressSpaceGeneration, fsInodeGeneration,
                            inodeGeneration, blockDeviceGeneration,
                            deviceGeneration);
                effectState[e] := "Prepared";
                if e = "BlockReq" then
                    dmaState := "Mapped";
                end if;
            end with;
        or
            \* Each accepted commit crosses exactly one domain publication
            \* point.  Syscall commit freezes the backend result; its guest
            \* reply remains a separate kernel publication below.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Prepared"
                      /\ effectAuthority[e] = authorityEpoch
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                      /\ GenerationMatches(e, pagerAsGeneration,
                            addressSpaceGeneration, fsInodeGeneration,
                            inodeGeneration, blockDeviceGeneration,
                            deviceGeneration)
                      /\ (e # "BlockReq" \/ dmaState = "Mapped");
                effectState[e] := "Committed";
                commitCount[e] := commitCount[e] + 1;
                if e = "PagerMap" then
                    ptePublished := TRUE;
                    tlbSynced := TRUE;
                    mapPublicationCount := mapPublicationCount + 1;
                    addressSpaceGeneration := addressSpaceGeneration + 1;
                elsif e = "FsOp" then
                    inodeBytes := "HoleXY";
                    inodeGeneration := inodeGeneration + 1;
                    inodePublicationCount := inodePublicationCount + 1;
                elsif e = "BlockReq" then
                    blockPublicationCount := blockPublicationCount + 1;
                end if;
            end with;
        or
            \* One bounded crash advances only the selected service binding.
            \* Committed work remains kernel/device owned and is never adopted.
            with d \in Domains do
                await /\ EnableCrash
                      /\ scopeState = "Active"
                      /\ domainPhase[d] = "Bound"
                      /\ bindingEpoch[d] < MaxBinding
                      /\ crashCount = 0
                      /\ \E e \in Effects :
                            EffectDomain(e) = d
                                /\ effectState[e] \in LiveStates;
                bindingEpoch[d] := bindingEpoch[d] + 1;
                domainPhase[d] := "Down";
                recoveryCohort[d] :=
                    {e \in Effects : EffectDomain(e) = d
                        /\ effectState[e] \in UncommittedStates};
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
                      /\ effectState[e] \in UncommittedStates
                      /\ effectBinding[e] # bindingEpoch[d];
                effectBinding[e] := bindingEpoch[d];
                recoveryCohort[d] := recoveryCohort[d] \ {e};
                adoptCount[d] := adoptCount[d] + 1;
            end with;
        or
            \* RevokeBegin is the root linearization point.  It closes every
            \* old-authority commit gate and freezes the exact live cohort.
            await scopeState = "Active";
            effectsAtClose :=
                {e \in Effects : effectState[e] # "Unused"};
            closingEffects :=
                {e \in Effects : effectState[e] \in LiveStates};
            committedAtClose :=
                {e \in Effects : commitCount[e] = 1
                    /\ effectState[e] \in LiveStates};
            commitAtClose := commitCount;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeGate := "Closed";
            scopeState := "Closing";
            domainPhase := [d \in Domains |-> "Closed"];
            recoveryCohort := [d \in Domains |-> {}];
        or
            \* A committed request may time out before reset acknowledgement.
            \* The same mapped DMA owner and Dma credit stay retained.
            await /\ EnableTimeout
                  /\ scopeState = "Closing"
                  /\ effectState["BlockReq"] = "Committed"
                  /\ tombstoneKind = "None"
                  /\ "Reset" \notin timeoutKinds;
            effectState["BlockReq"] := "Tombstoned";
            tombstoneKind := "Reset";
            tombstoneResume := "Committed";
            timeoutKinds := timeoutKinds \cup {"Reset"};
        or
            \* Reset acknowledgement is the only device-generation advance.
            await /\ scopeState = "Closing"
                  /\ effectState["BlockReq"] = "Committed"
                  /\ tombstoneKind = "None"
                  /\ blockDeviceGeneration = deviceGeneration;
            effectState["BlockReq"] := "ResetIndeterminate";
            blockOutcome := "IndeterminateAfterReset";
            terminalCount["BlockReq"] :=
                terminalCount["BlockReq"] + 1;
            deviceGeneration := deviceGeneration + 1;
            dmaState := "Invalidating";
        or
            \* Device completion is kernel/device owned and remains valid after
            \* a block-service binding crash, provided the device token is fresh.
            await /\ scopeState \in {"Active", "Closing"}
                  /\ effectState["BlockReq"] = "Committed"
                  /\ tombstoneKind = "None"
                  /\ blockDeviceGeneration = deviceGeneration;
            effectState["BlockReq"] := "DeviceCompleted";
            blockOutcome := "Completed";
            terminalCount["BlockReq"] :=
                terminalCount["BlockReq"] + 1;
            dmaState := "Invalidating";
        or
            \* Request invalidation timeout retains the exact terminal outcome,
            \* DMA owner, IOVA identity, and Dma credit.
            await /\ EnableTimeout
                  /\ scopeState = "Closing"
                  /\ dmaState = "Invalidating"
                  /\ effectState["BlockReq"] \in
                        {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
                  /\ tombstoneKind = "None"
                  /\ "Iotlb" \notin timeoutKinds;
            tombstoneResume := effectState["BlockReq"];
            effectState["BlockReq"] := "Tombstoned";
            tombstoneKind := "Iotlb";
            timeoutKinds := timeoutKinds \cup {"Iotlb"};
        or
            with kind \in TimeoutTargets do
                await /\ tombstoneKind = kind
                      /\ kind \in timeoutKinds
                      /\ kind \notin retryKinds;
                effectState["BlockReq"] := tombstoneResume;
                retryKinds := retryKinds \cup {kind};
                tombstoneKind := "None";
                tombstoneResume := "None";
            end with;
        or
            \* IOTLB Ack, not reset acknowledgement, makes the retained owner
            \* and its Dma credit reusable.
            await /\ dmaState = "Invalidating"
                  /\ tombstoneKind = "None"
                  /\ effectState["BlockReq"] \in
                        {"Cancelling", "DeviceCompleted", "ResetIndeterminate"};
            if effectState["BlockReq"] = "Cancelling" then
                effectState["BlockReq"] := "Aborted";
            else
                effectState["BlockReq"] := "Completed";
            end if;
            dmaState := "Released";
            freeCredits["Dma"] := freeCredits["Dma"] + 1;
        or
            \* Present one stale full token or timeout receipt.  Rejection may
            \* change only the bounded audit set.
            with kind \in RejectKinds \ rejectKinds do
                await /\ EnableRejects
                      /\ StaleEnabled(kind, scopeState, bindingEpoch,
                            pagerAsGeneration, addressSpaceGeneration,
                            fsInodeGeneration, inodeGeneration,
                            blockDeviceGeneration, deviceGeneration,
                            retryKinds);
                rejectKinds := rejectKinds \cup {kind};
            end with;
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            \* Completed non-block effects retire child-first.  Completing a
            \* committed Syscall is the separate one-shot guest reply publish.
            with e \in NonBlockEffects do
                await /\ effectState[e] = "Committed"
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Completed";
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
                if e = "Syscall" then
                    replyPublicationCount := replyPublicationCount + 1;
                end if;
            end with;
        or
            \* Revocation aborts only work that never crossed its own commit.
            \* A committed FsOp remains visible even if Syscall later aborts.
            with e \in NonBlockEffects do
                await /\ scopeState = "Closing"
                      /\ effectState[e] \in UncommittedStates
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Aborted";
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ effectState["BlockReq"] = "Registered";
            effectState["BlockReq"] := "Aborted";
            blockOutcome := "AbortedBeforeCommit";
            terminalCount["BlockReq"] :=
                terminalCount["BlockReq"] + 1;
            freeCredits["Dma"] := freeCredits["Dma"] + 1;
        or
            \* Prepared block work is invisible to the device but its DMA map
            \* cannot be freed until IOTLB acknowledgement.
            await /\ scopeState = "Closing"
                  /\ effectState["BlockReq"] = "Prepared"
                  /\ dmaState = "Mapped";
            effectState["BlockReq"] := "Cancelling";
            blockOutcome := "AbortedBeforeCommit";
            terminalCount["BlockReq"] :=
                terminalCount["BlockReq"] + 1;
            dmaState := "Invalidating";
        or
            await /\ scopeState = "Closing"
                  /\ \A e \in closingEffects :
                        effectState[e] \in TerminalStates
                  /\ \A t \in CreditTypes : freeCredits[t] = 1
                  /\ tombstoneKind = "None";
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "bde149c9" /\ chksum(tla) = "92e8ad0e")
VARIABLES scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, replyPublicationCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds

vars == << scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, replyPublicationCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectState = [e \in Effects |-> "Unused"]
        /\ effectParent = [e \in Effects |-> NoParent]
        /\ effectAuthority = [e \in Effects |-> NoGeneration]
        /\ effectBinding = [e \in Effects |-> NoBinding]
        /\ commitCount = [e \in Effects |-> 0]
        /\ terminalCount = [e \in Effects |-> 0]
        /\ freeCredits = [t \in CreditTypes |-> 1]
        /\ bindingEpoch = [d \in Domains |-> 0]
        /\ domainPhase = [d \in Domains |-> "Bound"]
        /\ recoveryCohort = [d \in Domains |-> {}]
        /\ snapshotBinding = [d \in Domains |-> NoBinding]
        /\ snapshotCohort = [d \in Domains |-> {}]
        /\ adoptCount = [d \in Domains |-> 0]
        /\ crashCount = 0
        /\ addressSpaceGeneration = 0
        /\ pagerAsGeneration = NoGeneration
        /\ ptePublished = FALSE
        /\ tlbSynced = FALSE
        /\ mapPublicationCount = 0
        /\ inodeGeneration = 0
        /\ fsInodeGeneration = NoGeneration
        /\ inodeBytes = "Zeros"
        /\ inodePublicationCount = 0
        /\ deviceGeneration = 0
        /\ blockDeviceGeneration = NoGeneration
        /\ dmaState = "Absent"
        /\ blockOutcome = "None"
        /\ blockPublicationCount = 0
        /\ tombstoneKind = "None"
        /\ tombstoneResume = "None"
        /\ timeoutKinds = {}
        /\ retryKinds = {}
        /\ replyPublicationCount = 0
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ committedAtClose = {}
        /\ commitAtClose = [e \in Effects |-> 0]
        /\ rejectKinds = {}

Environment == /\ \/ /\ \E e \in Effects:
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Unused"
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ ParentCanDerive(e, effectState, effectBinding,
                                   bindingEpoch, domainPhase)
                             /\ freeCredits[EffectCredit(e)] = 1
                          /\ effectState' = [effectState EXCEPT ![e] = "Registered"]
                          /\ effectParent' = [effectParent EXCEPT ![e] = AllowedParent(e)]
                          /\ effectAuthority' = [effectAuthority EXCEPT ![e] = authorityEpoch]
                          /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[EffectDomain(e)]]
                          /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] - 1]
                          /\ IF e = "PagerMap"
                                THEN /\ pagerAsGeneration' = addressSpaceGeneration
                                     /\ UNCHANGED << fsInodeGeneration, blockDeviceGeneration >>
                                ELSE /\ IF e = "FsOp"
                                           THEN /\ fsInodeGeneration' = inodeGeneration
                                                /\ UNCHANGED blockDeviceGeneration
                                           ELSE /\ IF e = "BlockReq"
                                                      THEN /\ blockDeviceGeneration' = deviceGeneration
                                                      ELSE /\ TRUE
                                                           /\ UNCHANGED blockDeviceGeneration
                                                /\ UNCHANGED fsInodeGeneration
                                     /\ UNCHANGED pagerAsGeneration
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, commitCount, terminalCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E e \in Effects:
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Registered"
                             /\ effectAuthority[e] = authorityEpoch
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                             /\ GenerationMatches(e, pagerAsGeneration,
                                   addressSpaceGeneration, fsInodeGeneration,
                                   inodeGeneration, blockDeviceGeneration,
                                   deviceGeneration)
                          /\ effectState' = [effectState EXCEPT ![e] = "Prepared"]
                          /\ IF e = "BlockReq"
                                THEN /\ dmaState' = "Mapped"
                                ELSE /\ TRUE
                                     /\ UNCHANGED dmaState
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E e \in Effects:
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Prepared"
                             /\ effectAuthority[e] = authorityEpoch
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                             /\ GenerationMatches(e, pagerAsGeneration,
                                   addressSpaceGeneration, fsInodeGeneration,
                                   inodeGeneration, blockDeviceGeneration,
                                   deviceGeneration)
                             /\ (e # "BlockReq" \/ dmaState = "Mapped")
                          /\ effectState' = [effectState EXCEPT ![e] = "Committed"]
                          /\ commitCount' = [commitCount EXCEPT ![e] = commitCount[e] + 1]
                          /\ IF e = "PagerMap"
                                THEN /\ ptePublished' = TRUE
                                     /\ tlbSynced' = TRUE
                                     /\ mapPublicationCount' = mapPublicationCount + 1
                                     /\ addressSpaceGeneration' = addressSpaceGeneration + 1
                                     /\ UNCHANGED << inodeGeneration, inodeBytes, inodePublicationCount, blockPublicationCount >>
                                ELSE /\ IF e = "FsOp"
                                           THEN /\ inodeBytes' = "HoleXY"
                                                /\ inodeGeneration' = inodeGeneration + 1
                                                /\ inodePublicationCount' = inodePublicationCount + 1
                                                /\ UNCHANGED blockPublicationCount
                                           ELSE /\ IF e = "BlockReq"
                                                      THEN /\ blockPublicationCount' = blockPublicationCount + 1
                                                      ELSE /\ TRUE
                                                           /\ UNCHANGED blockPublicationCount
                                                /\ UNCHANGED << inodeGeneration, inodeBytes, inodePublicationCount >>
                                     /\ UNCHANGED << addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount >>
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, pagerAsGeneration, fsInodeGeneration, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ EnableCrash
                             /\ scopeState = "Active"
                             /\ domainPhase[d] = "Bound"
                             /\ bindingEpoch[d] < MaxBinding
                             /\ crashCount = 0
                             /\ \E e \in Effects :
                                   EffectDomain(e) = d
                                       /\ effectState[e] \in LiveStates
                          /\ bindingEpoch' = [bindingEpoch EXCEPT ![d] = bindingEpoch[d] + 1]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Down"]
                          /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = {e \in Effects : EffectDomain(e) = d
                                                                                 /\ effectState[e] \in UncommittedStates}]
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = NoBinding]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = {}]
                          /\ crashCount' = crashCount + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, adoptCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Down"
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = bindingEpoch[d]]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = recoveryCohort[d]]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Snapshotted"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Snapshotted"
                             /\ snapshotBinding[d] = bindingEpoch[d]
                             /\ snapshotCohort[d] = recoveryCohort[d]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Ready"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Ready"
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Bound"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          \E e \in recoveryCohort[d]:
                            /\ /\ scopeState = "Active"
                               /\ domainPhase[d] = "Bound"
                               /\ effectState[e] \in UncommittedStates
                               /\ effectBinding[e] # bindingEpoch[d]
                            /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[d]]
                            /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = recoveryCohort[d] \ {e}]
                            /\ adoptCount' = [adoptCount EXCEPT ![d] = adoptCount[d] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, snapshotBinding, snapshotCohort, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ scopeState = "Active"
                     /\ effectsAtClose' = {e \in Effects : effectState[e] # "Unused"}
                     /\ closingEffects' = {e \in Effects : effectState[e] \in LiveStates}
                     /\ committedAtClose' = {e \in Effects : commitCount[e] = 1
                                                /\ effectState[e] \in LiveStates}
                     /\ commitAtClose' = commitCount
                     /\ closingEpoch' = authorityEpoch
                     /\ authorityEpoch' = authorityEpoch + 1
                     /\ scopeGate' = "Closed"
                     /\ scopeState' = "Closing"
                     /\ domainPhase' = [d \in Domains |-> "Closed"]
                     /\ recoveryCohort' = [d \in Domains |-> {}]
                     /\ UNCHANGED <<effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, rejectKinds>>
                  \/ /\ /\ EnableTimeout
                        /\ scopeState = "Closing"
                        /\ effectState["BlockReq"] = "Committed"
                        /\ tombstoneKind = "None"
                        /\ "Reset" \notin timeoutKinds
                     /\ effectState' = [effectState EXCEPT !["BlockReq"] = "Tombstoned"]
                     /\ tombstoneKind' = "Reset"
                     /\ tombstoneResume' = "Committed"
                     /\ timeoutKinds' = (timeoutKinds \cup {"Reset"})
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ scopeState = "Closing"
                        /\ effectState["BlockReq"] = "Committed"
                        /\ tombstoneKind = "None"
                        /\ blockDeviceGeneration = deviceGeneration
                     /\ effectState' = [effectState EXCEPT !["BlockReq"] = "ResetIndeterminate"]
                     /\ blockOutcome' = "IndeterminateAfterReset"
                     /\ terminalCount' = [terminalCount EXCEPT !["BlockReq"] = terminalCount["BlockReq"] + 1]
                     /\ deviceGeneration' = deviceGeneration + 1
                     /\ dmaState' = "Invalidating"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, blockDeviceGeneration, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ scopeState \in {"Active", "Closing"}
                        /\ effectState["BlockReq"] = "Committed"
                        /\ tombstoneKind = "None"
                        /\ blockDeviceGeneration = deviceGeneration
                     /\ effectState' = [effectState EXCEPT !["BlockReq"] = "DeviceCompleted"]
                     /\ blockOutcome' = "Completed"
                     /\ terminalCount' = [terminalCount EXCEPT !["BlockReq"] = terminalCount["BlockReq"] + 1]
                     /\ dmaState' = "Invalidating"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ EnableTimeout
                        /\ scopeState = "Closing"
                        /\ dmaState = "Invalidating"
                        /\ effectState["BlockReq"] \in
                              {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
                        /\ tombstoneKind = "None"
                        /\ "Iotlb" \notin timeoutKinds
                     /\ tombstoneResume' = effectState["BlockReq"]
                     /\ effectState' = [effectState EXCEPT !["BlockReq"] = "Tombstoned"]
                     /\ tombstoneKind' = "Iotlb"
                     /\ timeoutKinds' = (timeoutKinds \cup {"Iotlb"})
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E kind \in TimeoutTargets:
                          /\ /\ tombstoneKind = kind
                             /\ kind \in timeoutKinds
                             /\ kind \notin retryKinds
                          /\ effectState' = [effectState EXCEPT !["BlockReq"] = tombstoneResume]
                          /\ retryKinds' = (retryKinds \cup {kind})
                          /\ tombstoneKind' = "None"
                          /\ tombstoneResume' = "None"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, timeoutKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ dmaState = "Invalidating"
                        /\ tombstoneKind = "None"
                        /\ effectState["BlockReq"] \in
                              {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
                     /\ IF effectState["BlockReq"] = "Cancelling"
                           THEN /\ effectState' = [effectState EXCEPT !["BlockReq"] = "Aborted"]
                           ELSE /\ effectState' = [effectState EXCEPT !["BlockReq"] = "Completed"]
                     /\ dmaState' = "Released"
                     /\ freeCredits' = [freeCredits EXCEPT !["Dma"] = freeCredits["Dma"] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E kind \in RejectKinds \ rejectKinds:
                          /\ /\ EnableRejects
                             /\ StaleEnabled(kind, scopeState, bindingEpoch,
                                   pagerAsGeneration, addressSpaceGeneration,
                                   fsInodeGeneration, inodeGeneration,
                                   blockDeviceGeneration, deviceGeneration,
                                   retryKinds)
                          /\ rejectKinds' = (rejectKinds \cup {kind})
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose>>
               /\ UNCHANGED replyPublicationCount

Kernel == /\ \/ /\ \E e \in NonBlockEffects:
                     /\ /\ effectState[e] = "Committed"
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                     /\ IF e = "Syscall"
                           THEN /\ replyPublicationCount' = replyPublicationCount + 1
                           ELSE /\ TRUE
                                /\ UNCHANGED replyPublicationCount
                /\ UNCHANGED <<scopeState, dmaState, blockOutcome>>
             \/ /\ \E e \in NonBlockEffects:
                     /\ /\ scopeState = "Closing"
                        /\ effectState[e] \in UncommittedStates
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Aborted"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                /\ UNCHANGED <<scopeState, dmaState, blockOutcome, replyPublicationCount>>
             \/ /\ /\ scopeState = "Closing"
                   /\ effectState["BlockReq"] = "Registered"
                /\ effectState' = [effectState EXCEPT !["BlockReq"] = "Aborted"]
                /\ blockOutcome' = "AbortedBeforeCommit"
                /\ terminalCount' = [terminalCount EXCEPT !["BlockReq"] = terminalCount["BlockReq"] + 1]
                /\ freeCredits' = [freeCredits EXCEPT !["Dma"] = freeCredits["Dma"] + 1]
                /\ UNCHANGED <<scopeState, dmaState, replyPublicationCount>>
             \/ /\ /\ scopeState = "Closing"
                   /\ effectState["BlockReq"] = "Prepared"
                   /\ dmaState = "Mapped"
                /\ effectState' = [effectState EXCEPT !["BlockReq"] = "Cancelling"]
                /\ blockOutcome' = "AbortedBeforeCommit"
                /\ terminalCount' = [terminalCount EXCEPT !["BlockReq"] = terminalCount["BlockReq"] + 1]
                /\ dmaState' = "Invalidating"
                /\ UNCHANGED <<scopeState, freeCredits, replyPublicationCount>>
             \/ /\ /\ scopeState = "Closing"
                   /\ \A e \in closingEffects :
                         effectState[e] \in TerminalStates
                   /\ \A t \in CreditTypes : freeCredits[t] = 1
                   /\ tombstoneKind = "None"
                /\ scopeState' = "Revoked"
                /\ UNCHANGED <<effectState, terminalCount, freeCredits, dmaState, blockOutcome, replyPublicationCount>>
          /\ UNCHANGED << scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, commitCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockDeviceGeneration, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

TypeOK ==
    /\ scopeState \in {"Active", "Closing", "Revoked"}
    /\ scopeGate \in {"Open", "Closed"}
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoGeneration, 0}
    /\ effectState \in [Effects ->
        {"Unused", "Registered", "Prepared", "Committed", "Cancelling",
         "DeviceCompleted", "ResetIndeterminate", "Tombstoned",
         "Completed", "Aborted"}]
    /\ effectParent \in [Effects -> Effects \cup {Root, NoParent}]
    /\ effectAuthority \in [Effects -> {NoGeneration, 0}]
    /\ effectBinding \in [Effects -> NoBinding..MaxBinding]
    /\ commitCount \in [Effects -> 0..1]
    /\ terminalCount \in [Effects -> 0..1]
    /\ freeCredits \in [CreditTypes -> 0..1]
    /\ bindingEpoch \in [Domains -> 0..MaxBinding]
    /\ domainPhase \in [Domains ->
        {"Bound", "Down", "Snapshotted", "Ready", "Closed"}]
    /\ \A d \in Domains : recoveryCohort[d] \subseteq Effects
    /\ \A d \in Domains : snapshotCohort[d] \subseteq Effects
    /\ snapshotBinding \in [Domains -> NoBinding..MaxBinding]
    /\ adoptCount \in [Domains -> 0..1]
    /\ crashCount \in 0..1
    /\ addressSpaceGeneration \in 0..1
    /\ pagerAsGeneration \in {NoGeneration, 0}
    /\ ptePublished \in BOOLEAN
    /\ tlbSynced \in BOOLEAN
    /\ mapPublicationCount \in 0..1
    /\ inodeGeneration \in 0..1
    /\ fsInodeGeneration \in {NoGeneration, 0}
    /\ inodeBytes \in {"Zeros", "HoleXY"}
    /\ inodePublicationCount \in 0..1
    /\ deviceGeneration \in 0..1
    /\ blockDeviceGeneration \in {NoGeneration, 0}
    /\ dmaState \in {"Absent", "Mapped", "Invalidating", "Released"}
    /\ blockOutcome \in
        {"None", "Completed", "IndeterminateAfterReset",
         "AbortedBeforeCommit"}
    /\ blockPublicationCount \in 0..1
    /\ tombstoneKind \in TimeoutTargets \cup {"None"}
    /\ tombstoneResume \in
        {"None", "Committed", "Cancelling", "DeviceCompleted",
         "ResetIndeterminate"}
    /\ timeoutKinds \subseteq TimeoutTargets
    /\ retryKinds \subseteq TimeoutTargets
    /\ replyPublicationCount \in 0..1
    /\ effectsAtClose \subseteq Effects
    /\ closingEffects \subseteq Effects
    /\ committedAtClose \subseteq Effects
    /\ commitAtClose \in [Effects -> 0..1]
    /\ rejectKinds \subseteq RejectKinds

ScopeGateDiscipline ==
    /\ (scopeState = "Active" <=> scopeGate = "Open")
    /\ (scopeState \in {"Closing", "Revoked"} <=> scopeGate = "Closed")
    /\ (scopeState = "Active" =>
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ committedAtClose = {})
    /\ (scopeState \in {"Closing", "Revoked"} =>
        /\ authorityEpoch = 1
        /\ closingEpoch = 0)

CausalIdentity ==
    /\ \A e \in Effects :
        /\ (effectState[e] = "Unused" =>
            /\ effectParent[e] = NoParent
            /\ effectAuthority[e] = NoGeneration
            /\ effectBinding[e] = NoBinding)
        /\ (effectState[e] # "Unused" =>
            /\ effectParent[e] = AllowedParent(e)
            /\ effectAuthority[e] = 0
            /\ effectBinding[e] \in 0..bindingEpoch[EffectDomain(e)])
    /\ \A e \in Effects \ {"Syscall"} :
        effectState[e] # "Unused" =>
            effectState[AllowedParent(e)] # "Unused"

EffectLifecycle ==
    /\ \A e \in NonBlockEffects :
        /\ (effectState[e] \in {"Unused", "Registered", "Prepared"} =>
            /\ commitCount[e] = 0
            /\ terminalCount[e] = 0)
        /\ (effectState[e] = "Committed" =>
            /\ commitCount[e] = 1
            /\ terminalCount[e] = 0)
        /\ (effectState[e] = "Completed" =>
            /\ commitCount[e] = 1
            /\ terminalCount[e] = 1)
        /\ (effectState[e] = "Aborted" =>
            /\ commitCount[e] = 0
            /\ terminalCount[e] = 1)
    /\ (blockOutcome = "None" <=> terminalCount["BlockReq"] = 0)
    /\ (blockOutcome # "None" <=> terminalCount["BlockReq"] = 1)
    /\ (effectState["BlockReq"] = "Completed" =>
        blockOutcome \in {"Completed", "IndeterminateAfterReset"})
    /\ (effectState["BlockReq"] = "Aborted" =>
        blockOutcome = "AbortedBeforeCommit")
    /\ (effectState["BlockReq"] = "Committed" =>
        /\ commitCount["BlockReq"] = 1
        /\ terminalCount["BlockReq"] = 0)
    /\ (effectState["BlockReq"] \in
            {"DeviceCompleted", "ResetIndeterminate", "Cancelling"} =>
        terminalCount["BlockReq"] = 1)

TypedCreditConservation ==
    \A t \in CreditTypes :
        freeCredits[t]
        + Cardinality({e \in Effects :
            EffectCredit(e) = t /\ effectState[e] \in LiveStates}) = 1

PagerPublicationDiscipline ==
    /\ mapPublicationCount = commitCount["PagerMap"]
    /\ (mapPublicationCount = 0 =>
        /\ ~ptePublished
        /\ ~tlbSynced
        /\ addressSpaceGeneration = 0)
    /\ (mapPublicationCount = 1 =>
        /\ ptePublished
        /\ tlbSynced
        /\ addressSpaceGeneration = 1
        /\ pagerAsGeneration = 0)

PwriteAtomicity ==
    /\ inodePublicationCount = commitCount["FsOp"]
    /\ (inodePublicationCount = 0 <=>
        /\ inodeBytes = "Zeros"
        /\ inodeGeneration = 0)
    /\ (inodePublicationCount = 1 <=>
        /\ inodeBytes = "HoleXY"
        /\ inodeGeneration = 1
        /\ fsInodeGeneration = 0)

BlockPublicationDiscipline ==
    /\ blockPublicationCount = commitCount["BlockReq"]
    /\ replyPublicationCount <= commitCount["Syscall"]
    /\ (replyPublicationCount = 1 =>
        effectState["Syscall"] = "Completed")
    /\ (effectState["BlockReq"] = "Prepared" => dmaState = "Mapped")
    /\ (effectState["BlockReq"] = "Registered" => dmaState = "Absent")
    /\ (effectState["BlockReq"] \in
            {"Cancelling", "DeviceCompleted", "ResetIndeterminate"} =>
        dmaState = "Invalidating")
    /\ (effectState["BlockReq"] \in TerminalStates =>
        dmaState \in {"Absent", "Released"})

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
            /\ effectState[e] \in UncommittedStates
            /\ effectBinding[e] # bindingEpoch[d]
        /\ (domainPhase[d] = "Ready" =>
            /\ snapshotBinding[d] = bindingEpoch[d]
            /\ snapshotCohort[d] = recoveryCohort[d])

FrozenClosureCohort ==
    scopeState \in {"Closing", "Revoked"} =>
        /\ effectsAtClose =
            {e \in Effects : effectState[e] # "Unused"}
        /\ closingEffects \subseteq effectsAtClose
        /\ committedAtClose \subseteq closingEffects

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} => commitCount = commitAtClose

NoPostRevokeDerivation ==
    scopeState \in {"Closing", "Revoked"} =>
        effectsAtClose = {e \in Effects : effectState[e] # "Unused"}

TimeoutHonesty ==
    /\ retryKinds \subseteq timeoutKinds
    /\ (tombstoneKind # "None" =>
        /\ scopeState = "Closing"
        /\ effectState["BlockReq"] = "Tombstoned"
        /\ freeCredits["Dma"] = 0
        /\ dmaState \in {"Mapped", "Invalidating"}
        /\ tombstoneKind \in timeoutKinds
        /\ tombstoneKind \notin retryKinds)
    /\ (tombstoneKind = "Reset" =>
        /\ tombstoneResume = "Committed"
        /\ blockOutcome = "None"
        /\ deviceGeneration = blockDeviceGeneration)
    /\ (tombstoneKind = "Iotlb" =>
        /\ tombstoneResume \in
            {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
        /\ blockOutcome # "None")
    /\ (tombstoneKind = "None" => tombstoneResume = "None")

SingleTerminalization ==
    \A e \in Effects : terminalCount[e] <= 1

QuiescentClosure ==
    scopeState = "Revoked" =>
        /\ \A e \in closingEffects : effectState[e] \in TerminalStates
        /\ \A t \in CreditTypes : freeCredits[t] = 1
        /\ tombstoneKind = "None"
        /\ dmaState \in {"Absent", "Released"}

CausalEdgeImmutability ==
    [][\A e \in Effects :
        effectParent[e] # NoParent => effectParent'[e] = effectParent[e]]_vars

CommitGateAction ==
    [][\A e \in Effects : commitCount'[e] > commitCount[e] =>
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ effectAuthority[e] = authorityEpoch
        /\ domainPhase[EffectDomain(e)] = "Bound"
        /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
        /\ GenerationMatches(e, pagerAsGeneration,
            addressSpaceGeneration, fsInodeGeneration, inodeGeneration,
            blockDeviceGeneration, deviceGeneration)]_vars

DomainBindingIsolation ==
    [][(\E d \in Domains : bindingEpoch'[d] # bindingEpoch[d]) =>
        /\ Cardinality({d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d]}) = 1
        /\ \A d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d] =>
                bindingEpoch'[d] = bindingEpoch[d] + 1]_vars

RejectSideEffectFreedom ==
    [][rejectKinds' # rejectKinds => UNCHANGED <<
        scopeState, scopeGate, authorityEpoch, closingEpoch,
        effectState, effectParent, effectAuthority, effectBinding,
        commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase,
        recoveryCohort, snapshotBinding, snapshotCohort, adoptCount,
        crashCount, addressSpaceGeneration, pagerAsGeneration, ptePublished,
        tlbSynced, mapPublicationCount, inodeGeneration, fsInodeGeneration,
        inodeBytes, inodePublicationCount, deviceGeneration,
        blockDeviceGeneration, dmaState, blockOutcome,
        blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds,
        retryKinds, replyPublicationCount, effectsAtClose, closingEffects,
        committedAtClose, commitAtClose
    >>]_vars

ReadyForRevokeComplete ==
    /\ scopeState = "Closing"
    /\ \A e \in closingEffects : effectState[e] \in TerminalStates
    /\ \A t \in CreditTypes : freeCredits[t] = 1
    /\ tombstoneKind = "None"

ConditionalRevocationProgress ==
    [](ReadyForRevokeComplete ~> scopeState = "Revoked")

FourDomainPwriteClosureObserved ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ closingEffects = Effects
    /\ committedAtClose = Effects
    /\ ptePublished
    /\ tlbSynced
    /\ inodeBytes = "HoleXY"
    /\ inodeGeneration = 1
    /\ replyPublicationCount = 1
    /\ blockOutcome \in {"Completed", "IndeterminateAfterReset"}
    /\ \A t \in CreditTypes : freeCredits[t] = 1

RevokeBeforePwriteObserved ==
    /\ scopeState = "Revoked"
    /\ "FsOp" \in closingEffects
    /\ commitAtClose["FsOp"] = 0
    /\ effectState["FsOp"] = "Aborted"
    /\ inodeBytes = "Zeros"
    /\ inodeGeneration = 0
    /\ inodePublicationCount = 0
    /\ replyPublicationCount = 0

PagerCrashAdoptMapObserved ==
    /\ bindingEpoch["Pager"] = 1
    /\ adoptCount["Pager"] = 1
    /\ effectBinding["PagerMap"] = 1
    /\ recoveryCohort["Pager"] = {}
    /\ snapshotBinding["Pager"] = 1
    /\ mapPublicationCount = 1
    /\ ptePublished
    /\ tlbSynced

FsCrashAdoptWriteObserved ==
    /\ bindingEpoch["Filesystem"] = 1
    /\ adoptCount["Filesystem"] = 1
    /\ effectBinding["FsOp"] = 1
    /\ recoveryCohort["Filesystem"] = {}
    /\ snapshotBinding["Filesystem"] = 1
    /\ inodePublicationCount = 1
    /\ inodeBytes = "HoleXY"

BlockCrashDeviceDrainObserved ==
    /\ bindingEpoch["Block"] = 1
    /\ adoptCount["Block"] = 0
    /\ effectBinding["BlockReq"] = 0
    /\ blockOutcome = "Completed"
    /\ effectState["BlockReq"] = "Completed"
    /\ deviceGeneration = 0
    /\ dmaState = "Released"

ResetTimeoutRetryClosureObserved ==
    /\ scopeState = "Revoked"
    /\ "Reset" \in timeoutKinds
    /\ "Reset" \in retryKinds
    /\ deviceGeneration = 1
    /\ blockOutcome = "IndeterminateAfterReset"
    /\ effectState["BlockReq"] = "Completed"
    /\ dmaState = "Released"

IotlbTimeoutRetryClosureObserved ==
    /\ scopeState = "Revoked"
    /\ "Iotlb" \in timeoutKinds
    /\ "Iotlb" \in retryKinds
    /\ blockOutcome # "None"
    /\ effectState["BlockReq"] \in TerminalStates
    /\ dmaState = "Released"

StaleTokenFencesObserved == rejectKinds = RejectKinds

FourDomainPwriteClosureAbsent == ~FourDomainPwriteClosureObserved
RevokeBeforePwriteAbsent == ~RevokeBeforePwriteObserved
PagerCrashAdoptMapAbsent == ~PagerCrashAdoptMapObserved
FsCrashAdoptWriteAbsent == ~FsCrashAdoptWriteObserved
BlockCrashDeviceDrainAbsent == ~BlockCrashDeviceDrainObserved
ResetTimeoutRetryClosureAbsent == ~ResetTimeoutRetryClosureObserved
IotlbTimeoutRetryClosureAbsent == ~IotlbTimeoutRetryClosureObserved
StaleTokenFencesAbsent == ~StaleTokenFencesObserved

=============================================================================

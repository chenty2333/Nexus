-------------------- MODULE LinuxIoCompositionCser --------------------
EXTENDS FiniteSets, Integers, Sequences, TLC

(***************************************************************************)
(* Bounded seven-domain Linux-I/O composition successor.  This module is   *)
(* additive: CompositionCser, RuntimeFsCser, and RuntimeNetCser remain      *)
(* frozen predecessors.  The fixed graph is:                               *)
(*                                                                         *)
(* Root                                                                    *)
(* |-- FsSyscall -> PagerMap -> SchedulerAction                            *)
(* |             \-> FsOperation -> BlockRequest                           *)
(* \-- NetSyscall -> NetOperation -> ReadinessWait                         *)
(*                                 \-> BufferLease                          *)
(*                                                                         *)
(* Nine effects span seven independently rebound domains.  Control has     *)
(* capacity two; the other seven credit classes have capacity one.  The    *)
(* PlusCal algorithm is the sole source of Init and Next.                   *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableCrash, EnableTimeout, EnableRejects

ASSUME /\ MaxBinding = 1
       /\ EnableCrash \in BOOLEAN
       /\ EnableTimeout \in BOOLEAN
       /\ EnableRejects \in BOOLEAN

Domains == {"Scheduler", "Pager", "Personality", "Filesystem",
            "VirtIo", "Network", "Readiness"}
Effects == {"FsSyscall", "NetSyscall", "PagerMap", "SchedulerAction",
            "FsOperation", "BlockRequest", "NetOperation",
            "ReadinessWait", "BufferLease"}
NonBlockEffects == Effects \ {"BlockRequest"}
SimpleKernelEffects == {"SchedulerAction", "PagerMap", "FsOperation"}
CreditTypes == {"Control", "Scheduling", "Memory", "Filesystem", "Dma",
                 "Network", "Readiness", "Buffer"}
TimeoutTargets == {"Reset", "Iotlb"}
RejectKinds == {"Authority", "Binding", "AddressSpace", "Inode", "Device",
                 "Socket", "Source", "TimeoutReceipt", "ClosureReceipt",
                 "CompletionReplay"}
ScenarioModes == {"DeriveRace", "Core", "NewDomainCrash", "DmaTimeout",
                   "RejectProbe"}
CrashTargets == {"Filesystem", "Network"}

Root == "Root"
NoParent == "NoParent"
NoGeneration == -1
NoBinding == -1

DeriveOrder == <<"FsSyscall", "NetSyscall", "PagerMap", "SchedulerAction",
                 "FsOperation", "BlockRequest", "NetOperation",
                 "ReadinessWait", "BufferLease">>
ReceiptOrder == <<"Scheduler", "Pager", "VirtIo", "Filesystem",
                  "Readiness", "Network", "Personality">>
RejectOrder == <<"AddressSpace", "Inode", "Socket", "Source", "Device",
                 "Binding", "Authority", "TimeoutReceipt", "ClosureReceipt",
                 "CompletionReplay">>

MaxReceiptSequence == Cardinality(Domains) + Cardinality(TimeoutTargets)

EffectDomain(e) ==
    CASE e \in {"FsSyscall", "NetSyscall"} -> "Personality"
      [] e = "PagerMap" -> "Pager"
      [] e = "SchedulerAction" -> "Scheduler"
      [] e = "FsOperation" -> "Filesystem"
      [] e = "BlockRequest" -> "VirtIo"
      [] e \in {"NetOperation", "BufferLease"} -> "Network"
      [] e = "ReadinessWait" -> "Readiness"

EffectCredit(e) ==
    CASE e \in {"FsSyscall", "NetSyscall"} -> "Control"
      [] e = "PagerMap" -> "Memory"
      [] e = "SchedulerAction" -> "Scheduling"
      [] e = "FsOperation" -> "Filesystem"
      [] e = "BlockRequest" -> "Dma"
      [] e = "NetOperation" -> "Network"
      [] e = "ReadinessWait" -> "Readiness"
      [] e = "BufferLease" -> "Buffer"

CreditCapacity(t) == IF t = "Control" THEN 2 ELSE 1

ModeAllowsEffect(mode, crashTarget, rejectIndex, e) ==
    CASE mode = "Core" -> TRUE
      [] mode = "NewDomainCrash" ->
            IF crashTarget = "Filesystem"
            THEN e = "FsOperation"
            ELSE e \in {"NetOperation", "BufferLease"}
      [] mode = "DmaTimeout" -> e = "BlockRequest"
      [] mode = "RejectProbe" ->
            CASE rejectIndex = 1 -> e = "PagerMap"
              [] rejectIndex = 2 -> e = "FsOperation"
              [] rejectIndex = 3 -> e \in {"NetOperation", "BufferLease"}
              [] rejectIndex = 4 -> e = "ReadinessWait"
              [] rejectIndex = 5 -> e = "BlockRequest"
              [] OTHER -> FALSE
      [] OTHER -> FALSE

AllowedParent(e) ==
    CASE e \in {"FsSyscall", "NetSyscall"} -> Root
      [] e = "PagerMap" -> "FsSyscall"
      [] e = "SchedulerAction" -> "PagerMap"
      [] e = "FsOperation" -> "FsSyscall"
      [] e = "BlockRequest" -> "FsOperation"
      [] e = "NetOperation" -> "NetSyscall"
      [] e \in {"ReadinessWait", "BufferLease"} -> "NetOperation"

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

DomainClosingTerminal(d, effectsAtClose, effectState) ==
    \A e \in effectsAtClose :
        EffectDomain(e) = d => effectState[e] \in TerminalStates

GenerationMatches(e, effectAddressSpaceGeneration, addressSpaceGeneration,
        effectInodeGeneration, inodeGeneration, effectDeviceGeneration,
        deviceGeneration, effectSocketGeneration, socketGeneration,
        effectSourceGeneration, sourceGeneration) ==
    CASE e = "PagerMap" ->
            effectAddressSpaceGeneration[e] = addressSpaceGeneration
      [] e = "FsOperation" ->
            effectInodeGeneration[e] = inodeGeneration
      [] e = "BlockRequest" ->
            effectDeviceGeneration[e] = deviceGeneration
      [] e \in {"NetOperation", "BufferLease"} ->
            effectSocketGeneration[e] = socketGeneration
      [] e = "ReadinessWait" ->
            effectSourceGeneration[e] = sourceGeneration
      [] OTHER -> TRUE

StaleEnabled(kind, scopeState, crashCount, addressSpaceGeneration,
        inodeGeneration, deviceGeneration, socketGeneration, sourceGeneration,
        retryKinds, closedReceiptSequence, terminalCount) ==
    CASE kind = "Authority" -> scopeState \in {"Closing", "Revoked"}
      [] kind = "Binding" -> crashCount = 1
      [] kind = "AddressSpace" -> addressSpaceGeneration = 1
      [] kind = "Inode" -> inodeGeneration = 1
      [] kind = "Device" -> deviceGeneration = 1
      [] kind = "Socket" -> socketGeneration = 1
      [] kind = "Source" -> sourceGeneration = 1
      [] kind = "TimeoutReceipt" -> retryKinds # {}
      [] kind = "ClosureReceipt" ->
            \E d \in Domains : closedReceiptSequence[d] # 0
      [] kind = "CompletionReplay" ->
            \E e \in Effects : terminalCount[e] = 1

(* --algorithm LinuxIoCompositionCSER
variables
    scenarioMode \in ScenarioModes,
    crashTarget \in CrashTargets,

    scopeState = "Active",
    scopeGate = "Open",
    authorityEpoch = 0,
    closingEpoch = NoGeneration,

    effectState = [e \in Effects |-> "Unused"],
    effectParent = [e \in Effects |-> NoParent],
    effectAuthority = [e \in Effects |-> NoGeneration],
    effectBinding = [e \in Effects |-> NoBinding],
    effectAddressSpaceGeneration = [e \in Effects |-> NoGeneration],
    effectInodeGeneration = [e \in Effects |-> NoGeneration],
    effectDeviceGeneration = [e \in Effects |-> NoGeneration],
    effectSocketGeneration = [e \in Effects |-> NoGeneration],
    effectSourceGeneration = [e \in Effects |-> NoGeneration],
    commitCount = [e \in Effects |-> 0],
    terminalCount = [e \in Effects |-> 0],
    nextDeriveIndex = 1,

    freeCredits = [t \in CreditTypes |-> CreditCapacity(t)],

    bindingEpoch = [d \in Domains |-> 0],
    domainPhase = [d \in Domains |-> "Bound"],
    recoveryCohort = [d \in Domains |-> {}],
    snapshotBinding = [d \in Domains |-> NoBinding],
    snapshotCohort = [d \in Domains |-> {}],
    snapshotAddressSpaceGeneration = [d \in Domains |-> NoGeneration],
    snapshotInodeGeneration = [d \in Domains |-> NoGeneration],
    snapshotDeviceGeneration = [d \in Domains |-> NoGeneration],
    snapshotSocketGeneration = [d \in Domains |-> NoGeneration],
    snapshotSourceGeneration = [d \in Domains |-> NoGeneration],
    adoptCount = [d \in Domains |-> 0],
    adoptedEffects = {},
    crashCount = 0,

    addressSpaceGeneration = 0,
    ptePublished = FALSE,
    tlbSynced = FALSE,
    mapPublicationCount = 0,

    inodeGeneration = 0,
    inodeBytes = "Zeros",
    inodePublicationCount = 0,

    deviceGeneration = 0,
    dmaState = "Absent",
    blockOutcome = "None",
    blockPublicationCount = 0,
    tombstoneKind = "None",
    tombstoneResume = "None",
    timeoutKinds = {},
    retryKinds = {},

    socketGeneration = 0,
    socketState = "Closed",
    sourceGeneration = 0,
    sourceReady = FALSE,
    bufferState = "Empty",
    bufferPayload = "None",
    netReceiptSocketGeneration = NoGeneration,
    netReceiptPayload = "None",
    frozenReady = FALSE,
    frozenSocketGeneration = NoGeneration,
    frozenSourceGeneration = NoGeneration,
    frozenPayload = "None",

    netPublicationCount = 0,
    readyPublicationCount = 0,
    readyDeliveryCount = 0,
    bufferConsumptionCount = 0,
    bufferClosureCount = 0,

    fsGuestCommitCount = 0,
    fsGuestPublicationCount = 0,
    fsGuestResult = "None",
    netGuestCommitCount = 0,
    netGuestPublicationCount = 0,
    netGuestResult = "None",

    effectsAtClose = {},
    closingEffects = {},
    closingDomains = {},
    committedAtClose = {},
    commitAtClose = [e \in Effects |-> 0],

    domainReceipt = [d \in Domains |-> "Open"],
    domainRevision = [d \in Domains |-> 0],
    receiptCount = [d \in Domains |-> 0],
    nextReceiptSequence = 1,
    receiptSequence = [d \in Domains |-> 0],
    receiptRevision = [d \in Domains |-> 0],
    receiptClosingEpoch = [d \in Domains |-> NoGeneration],
    receiptBindingEpoch = [d \in Domains |-> NoBinding],
    receiptDeviceGeneration = [d \in Domains |-> NoGeneration],
    closedReceiptSequence = [d \in Domains |-> 0],
    timeoutReceiptSequence = [kind \in TimeoutTargets |-> 0],
    timeoutReceiptRevision = [kind \in TimeoutTargets |-> 0],
    timeoutReceiptDeviceGeneration = [kind \in TimeoutTargets |-> NoGeneration],
    receiptCursor = 1,

    rejectKinds = {},
    rejectIndex = 1;

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* The fixed order is only a state-space quotient.  Revoke may
            \* still win between any two failure-atomic derivations.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ nextDeriveIndex \in 1..Len(DeriveOrder);
            with e = DeriveOrder[nextDeriveIndex] do
                await /\ effectState[e] = "Unused"
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ ParentCanDerive(e, effectState, effectBinding,
                            bindingEpoch, domainPhase)
                      /\ freeCredits[EffectCredit(e)] > 0;
                effectState[e] := "Registered";
                effectParent[e] := AllowedParent(e);
                effectAuthority[e] := authorityEpoch;
                effectBinding[e] := bindingEpoch[EffectDomain(e)];
                effectAddressSpaceGeneration[e] := addressSpaceGeneration;
                effectInodeGeneration[e] := inodeGeneration;
                effectDeviceGeneration[e] := deviceGeneration;
                effectSocketGeneration[e] := socketGeneration;
                effectSourceGeneration[e] := sourceGeneration;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] - 1;
                nextDeriveIndex := nextDeriveIndex + 1;
            end with;
        or
            with e \in Effects do
                await /\ ModeAllowsEffect(scenarioMode, crashTarget,
                            rejectIndex, e)
                      /\ nextDeriveIndex = Len(DeriveOrder) + 1
                      /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Registered"
                      /\ effectAuthority[e] = authorityEpoch
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                      /\ GenerationMatches(e,
                            effectAddressSpaceGeneration,
                            addressSpaceGeneration, effectInodeGeneration,
                            inodeGeneration, effectDeviceGeneration,
                            deviceGeneration, effectSocketGeneration,
                            socketGeneration, effectSourceGeneration,
                            sourceGeneration)
                      /\ (e # "NetOperation" \/ socketState = "Closed")
                      /\ (e # "BufferLease" \/
                            /\ effectState["NetOperation"] = "Prepared"
                            /\ socketState = "Listening");
                effectState[e] := "Prepared";
                if e = "BlockRequest" then
                    dmaState := "Mapped";
                elsif e = "NetOperation" then
                    socketState := "Listening";
                elsif e = "BufferLease" then
                    socketState := "Pending";
                end if;
            end with;
        or
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["SchedulerAction"] = "Prepared"
                  /\ effectAuthority["SchedulerAction"] = authorityEpoch
                  /\ domainPhase["Scheduler"] = "Bound"
                  /\ effectBinding["SchedulerAction"] =
                        bindingEpoch["Scheduler"];
            effectState["SchedulerAction"] := "Committed";
            commitCount["SchedulerAction"] :=
                commitCount["SchedulerAction"] + 1;
        or
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["PagerMap"] = "Prepared"
                  /\ effectAuthority["PagerMap"] = authorityEpoch
                  /\ domainPhase["Pager"] = "Bound"
                  /\ effectBinding["PagerMap"] = bindingEpoch["Pager"]
                  /\ effectAddressSpaceGeneration["PagerMap"] =
                        addressSpaceGeneration;
            effectState["PagerMap"] := "Committed";
            commitCount["PagerMap"] := commitCount["PagerMap"] + 1;
            ptePublished := TRUE;
            tlbSynced := TRUE;
            mapPublicationCount := mapPublicationCount + 1;
            addressSpaceGeneration := addressSpaceGeneration + 1;
            domainPhase := [d \in Domains |->
                IF domainPhase[d] = "Ready" THEN "Fallback"
                ELSE domainPhase[d]];
        or
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["FsOperation"] = "Prepared"
                  /\ effectAuthority["FsOperation"] = authorityEpoch
                  /\ domainPhase["Filesystem"] = "Bound"
                  /\ effectBinding["FsOperation"] =
                        bindingEpoch["Filesystem"]
                  /\ effectInodeGeneration["FsOperation"] = inodeGeneration;
            effectState["FsOperation"] := "Committed";
            commitCount["FsOperation"] := commitCount["FsOperation"] + 1;
            inodeBytes := "HoleXY";
            inodeGeneration := inodeGeneration + 1;
            inodePublicationCount := inodePublicationCount + 1;
            domainPhase := [d \in Domains |->
                IF domainPhase[d] = "Ready" THEN "Fallback"
                ELSE domainPhase[d]];
        or
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["BlockRequest"] = "Prepared"
                  /\ effectAuthority["BlockRequest"] = authorityEpoch
                  /\ domainPhase["VirtIo"] = "Bound"
                  /\ effectBinding["BlockRequest"] = bindingEpoch["VirtIo"]
                  /\ effectDeviceGeneration["BlockRequest"] = deviceGeneration
                  /\ dmaState = "Mapped";
            effectState["BlockRequest"] := "Committed";
            commitCount["BlockRequest"] :=
                commitCount["BlockRequest"] + 1;
            blockPublicationCount := blockPublicationCount + 1;
        or
            \* NetCommit atomically publishes the socket, payload, and lease.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["NetOperation"] = "Prepared"
                  /\ effectState["BufferLease"] = "Prepared"
                  /\ socketState = "Pending"
                  /\ bufferState = "Empty"
                  /\ ~sourceReady
                  /\ netPublicationCount = 0
                  /\ \A e \in {"NetOperation", "BufferLease"} :
                        /\ effectAuthority[e] = authorityEpoch
                        /\ domainPhase["Network"] = "Bound"
                        /\ effectBinding[e] = bindingEpoch["Network"]
                        /\ effectSocketGeneration[e] = socketGeneration;
            effectState := [effectState EXCEPT
                !["NetOperation"] = "Committed",
                !["BufferLease"] = "Committed"];
            commitCount := [commitCount EXCEPT
                !["NetOperation"] = @ + 1,
                !["BufferLease"] = @ + 1];
            netReceiptSocketGeneration := socketGeneration + 1;
            netReceiptPayload := "Ping4";
            socketGeneration := socketGeneration + 1;
            socketState := "Connected";
            bufferState := "Queued";
            bufferPayload := "Ping4";
            sourceReady := TRUE;
            netPublicationCount := netPublicationCount + 1;
            domainPhase := [d \in Domains |->
                IF domainPhase[d] = "Ready" THEN "Fallback"
                ELSE domainPhase[d]];
        or
            \* ReadyCommit consumes the exact immutable NetCommit envelope.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["ReadinessWait"] = "Prepared"
                  /\ effectState["NetOperation"] = "Committed"
                  /\ effectAuthority["ReadinessWait"] = authorityEpoch
                  /\ domainPhase["Readiness"] = "Bound"
                  /\ effectBinding["ReadinessWait"] =
                        bindingEpoch["Readiness"]
                  /\ effectSourceGeneration["ReadinessWait"] =
                        sourceGeneration
                  /\ netPublicationCount = 1
                  /\ netReceiptSocketGeneration = socketGeneration
                  /\ netReceiptPayload = "Ping4"
                  /\ bufferState = "Queued"
                  /\ sourceReady
                  /\ readyPublicationCount = 0;
            effectState["ReadinessWait"] := "Committed";
            commitCount["ReadinessWait"] :=
                commitCount["ReadinessWait"] + 1;
            frozenReady := TRUE;
            frozenSocketGeneration := socketGeneration;
            frozenSourceGeneration := sourceGeneration + 1;
            frozenPayload := "Ping4";
            sourceGeneration := sourceGeneration + 1;
            readyPublicationCount := readyPublicationCount + 1;
            domainPhase := [d \in Domains |->
                IF domainPhase[d] = "Ready" THEN "Fallback"
                ELSE domainPhase[d]];
        or
            \* Syscall commit freezes a backend result.  Publication remains
            \* a separate fair kernel transition.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["FsSyscall"] = "Prepared"
                  /\ effectAuthority["FsSyscall"] = authorityEpoch
                  /\ domainPhase["Personality"] = "Bound"
                  /\ effectBinding["FsSyscall"] = bindingEpoch["Personality"]
                  /\ effectState["PagerMap"] = "Completed"
                  /\ effectState["FsOperation"] = "Completed"
                  /\ fsGuestCommitCount = 0;
            effectState["FsSyscall"] := "Committed";
            commitCount["FsSyscall"] := commitCount["FsSyscall"] + 1;
            fsGuestCommitCount := fsGuestCommitCount + 1;
            fsGuestResult := "PwriteOK";
        or
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["NetSyscall"] = "Prepared"
                  /\ effectAuthority["NetSyscall"] = authorityEpoch
                  /\ domainPhase["Personality"] = "Bound"
                  /\ effectBinding["NetSyscall"] =
                        bindingEpoch["Personality"]
                  /\ effectState["NetOperation"] = "Completed"
                  /\ effectState["ReadinessWait"] = "Completed"
                  /\ readyDeliveryCount = 1
                  /\ netGuestCommitCount = 0;
            effectState["NetSyscall"] := "Committed";
            commitCount["NetSyscall"] := commitCount["NetSyscall"] + 1;
            netGuestCommitCount := netGuestCommitCount + 1;
            netGuestResult := "LoopbackOK";
        or
            \* The bound permits one crashed domain in each trace.  The two
            \* new-domain witnesses select Filesystem and Network separately.
            with d \in Domains do
                await /\ EnableCrash
                      /\ scenarioMode \in {"NewDomainCrash", "RejectProbe"}
                      /\ d = crashTarget
                      /\ (scenarioMode = "NewDomainCrash" \/ rejectIndex = 6)
                      /\ scopeState = "Active"
                      /\ domainPhase[d] = "Bound"
                      /\ bindingEpoch[d] < MaxBinding
                      /\ crashCount = 0
                      /\ \E e \in Effects :
                            /\ EffectDomain(e) = d
                            /\ effectState[e] \in LiveStates;
                bindingEpoch[d] := bindingEpoch[d] + 1;
                domainPhase[d] := "Down";
                recoveryCohort[d] :=
                    {e \in Effects :
                        /\ EffectDomain(e) = d
                        /\ effectState[e] \in UncommittedStates};
                snapshotBinding[d] := NoBinding;
                snapshotCohort[d] := {};
                snapshotAddressSpaceGeneration[d] := NoGeneration;
                snapshotInodeGeneration[d] := NoGeneration;
                snapshotDeviceGeneration[d] := NoGeneration;
                snapshotSocketGeneration[d] := NoGeneration;
                snapshotSourceGeneration[d] := NoGeneration;
                crashCount := crashCount + 1;
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Fallback";
                snapshotBinding[d] := bindingEpoch[d];
                snapshotCohort[d] := recoveryCohort[d];
                snapshotAddressSpaceGeneration[d] := addressSpaceGeneration;
                snapshotInodeGeneration[d] := inodeGeneration;
                snapshotDeviceGeneration[d] := deviceGeneration;
                snapshotSocketGeneration[d] := socketGeneration;
                snapshotSourceGeneration[d] := sourceGeneration;
                domainPhase[d] := "Snapshotted";
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Snapshotted"
                      /\ snapshotBinding[d] = bindingEpoch[d]
                      /\ snapshotCohort[d] = recoveryCohort[d]
                      /\ snapshotAddressSpaceGeneration[d] =
                            addressSpaceGeneration
                      /\ snapshotInodeGeneration[d] = inodeGeneration
                      /\ snapshotDeviceGeneration[d] = deviceGeneration
                      /\ snapshotSocketGeneration[d] = socketGeneration
                      /\ snapshotSourceGeneration[d] = sourceGeneration;
                domainPhase[d] := "Ready";
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Ready"
                      /\ snapshotBinding[d] = bindingEpoch[d]
                      /\ snapshotCohort[d] = recoveryCohort[d]
                      /\ snapshotAddressSpaceGeneration[d] =
                            addressSpaceGeneration
                      /\ snapshotInodeGeneration[d] = inodeGeneration
                      /\ snapshotDeviceGeneration[d] = deviceGeneration
                      /\ snapshotSocketGeneration[d] = socketGeneration
                      /\ snapshotSourceGeneration[d] = sourceGeneration;
                domainPhase[d] := "Bound";
            end with;
        or
            with d \in Domains, e \in recoveryCohort[d] do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Bound"
                      /\ EffectDomain(e) = d
                      /\ effectState[e] \in UncommittedStates
                      /\ effectBinding[e] # bindingEpoch[d];
                effectBinding[e] := bindingEpoch[d];
                recoveryCohort[d] := recoveryCohort[d] \ {e};
                adoptedEffects := adoptedEffects \cup {e};
                adoptCount[d] := adoptCount[d] + 1;
            end with;
        or
            \* Active peer consumption is distinct from root-owned closure.
            await /\ scopeState = "Active"
                  /\ scenarioMode \in {"Core", "NewDomainCrash"}
                  /\ domainPhase["Network"] = "Bound"
                  /\ effectBinding["BufferLease"] = bindingEpoch["Network"]
                  /\ effectState["BufferLease"] = "Committed"
                  /\ bufferState = "Queued"
                  /\ bufferPayload = "Ping4";
            effectState["BufferLease"] := "Completed";
            terminalCount["BufferLease"] :=
                terminalCount["BufferLease"] + 1;
            bufferState := "Consumed";
            sourceReady := FALSE;
            bufferConsumptionCount := bufferConsumptionCount + 1;
            freeCredits["Buffer"] := freeCredits["Buffer"] + 1;
        or
            \* RevokeBegin is the single seven-domain root linearization point.
            await /\ scopeState = "Active"
                  /\ scenarioMode \in
                        {"DeriveRace", "Core", "DmaTimeout", "RejectProbe"}
                  /\ (scenarioMode # "RejectProbe" \/ rejectIndex = 7)
                  /\ (scenarioMode = "DeriveRace" \/
                        nextDeriveIndex = Len(DeriveOrder) + 1);
            effectsAtClose :=
                {e \in Effects : effectState[e] # "Unused"};
            closingEffects :=
                {e \in Effects : effectState[e] \in LiveStates};
            closingDomains :=
                {d \in Domains : \E e \in Effects :
                    EffectDomain(e) = d /\ effectState[e] # "Unused"};
            committedAtClose :=
                {e \in Effects :
                    commitCount[e] = 1 /\ effectState[e] \in LiveStates};
            commitAtClose := commitCount;
            domainReceipt := [d \in Domains |->
                IF \E e \in Effects :
                    EffectDomain(e) = d /\ effectState[e] # "Unused"
                THEN "Pending" ELSE "NotRequired"];
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeGate := "Closed";
            scopeState := "Closing";
            domainPhase := [d \in Domains |-> "Closed"];
            recoveryCohort := [d \in Domains |-> {}];
            receiptCursor := 1;
        or
            \* A reset timeout retains the exact block identity and Dma credit.
            await /\ EnableTimeout
                  /\ scenarioMode = "DmaTimeout"
                  /\ scopeState = "Closing"
                  /\ effectState["BlockRequest"] = "Committed"
                  /\ tombstoneKind = "None"
                  /\ "Reset" \notin timeoutKinds
                  /\ domainReceipt["VirtIo"] = "Pending";
            effectState["BlockRequest"] := "Tombstoned";
            tombstoneKind := "Reset";
            tombstoneResume := "Committed";
            timeoutKinds := timeoutKinds \cup {"Reset"};
            domainReceipt["VirtIo"] := "TimedOut";
            receiptSequence["VirtIo"] := nextReceiptSequence;
            receiptRevision["VirtIo"] := domainRevision["VirtIo"];
            receiptClosingEpoch["VirtIo"] := closingEpoch;
            receiptBindingEpoch["VirtIo"] := bindingEpoch["VirtIo"];
            receiptDeviceGeneration["VirtIo"] := deviceGeneration;
            timeoutReceiptSequence["Reset"] := nextReceiptSequence;
            timeoutReceiptRevision["Reset"] := domainRevision["VirtIo"];
            timeoutReceiptDeviceGeneration["Reset"] := deviceGeneration;
            nextReceiptSequence := nextReceiptSequence + 1;
        or
            \* ResetAck, not retry, advances the device generation.
            await /\ scopeState \in {"Active", "Closing"}
                  /\ scenarioMode \in {"Core", "DmaTimeout", "RejectProbe"}
                  /\ effectState["BlockRequest"] = "Committed"
                  /\ tombstoneKind = "None"
                  /\ effectDeviceGeneration["BlockRequest"] = deviceGeneration;
            effectState["BlockRequest"] := "ResetIndeterminate";
            blockOutcome := "IndeterminateAfterReset";
            terminalCount["BlockRequest"] :=
                terminalCount["BlockRequest"] + 1;
            deviceGeneration := deviceGeneration + 1;
            dmaState := "Invalidating";
            domainPhase := [d \in Domains |->
                IF domainPhase[d] = "Ready" THEN "Fallback"
                ELSE domainPhase[d]];
        or
            await /\ scopeState \in {"Active", "Closing"}
                  /\ scenarioMode = "Core"
                  /\ effectState["BlockRequest"] = "Committed"
                  /\ tombstoneKind = "None"
                  /\ effectDeviceGeneration["BlockRequest"] = deviceGeneration;
            effectState["BlockRequest"] := "DeviceCompleted";
            blockOutcome := "Completed";
            terminalCount["BlockRequest"] :=
                terminalCount["BlockRequest"] + 1;
            dmaState := "Invalidating";
        or
            await /\ EnableTimeout
                  /\ scenarioMode \in {"DmaTimeout", "RejectProbe"}
                  /\ scopeState = "Closing"
                  /\ dmaState = "Invalidating"
                  /\ effectState["BlockRequest"] \in
                        {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
                  /\ tombstoneKind = "None"
                  /\ "Iotlb" \notin timeoutKinds
                  /\ domainReceipt["VirtIo"] = "Pending";
            tombstoneResume := effectState["BlockRequest"];
            effectState["BlockRequest"] := "Tombstoned";
            tombstoneKind := "Iotlb";
            timeoutKinds := timeoutKinds \cup {"Iotlb"};
            domainReceipt["VirtIo"] := "TimedOut";
            receiptSequence["VirtIo"] := nextReceiptSequence;
            receiptRevision["VirtIo"] := domainRevision["VirtIo"];
            receiptClosingEpoch["VirtIo"] := closingEpoch;
            receiptBindingEpoch["VirtIo"] := bindingEpoch["VirtIo"];
            receiptDeviceGeneration["VirtIo"] := deviceGeneration;
            timeoutReceiptSequence["Iotlb"] := nextReceiptSequence;
            timeoutReceiptRevision["Iotlb"] := domainRevision["VirtIo"];
            timeoutReceiptDeviceGeneration["Iotlb"] := deviceGeneration;
            nextReceiptSequence := nextReceiptSequence + 1;
        or
            with kind \in TimeoutTargets do
                await /\ scenarioMode \in {"DmaTimeout", "RejectProbe"}
                      /\ tombstoneKind = kind
                      /\ kind \in timeoutKinds
                      /\ kind \notin retryKinds;
                effectState["BlockRequest"] := tombstoneResume;
                retryKinds := retryKinds \cup {kind};
                tombstoneKind := "None";
                tombstoneResume := "None";
                domainRevision["VirtIo"] :=
                    domainRevision["VirtIo"] + 1;
                domainReceipt["VirtIo"] := "Pending";
            end with;
        or
            \* IOTLB Ack is the sole Dma-credit release point.
            await /\ dmaState = "Invalidating"
                  /\ scenarioMode \in {"Core", "DmaTimeout", "RejectProbe"}
                  /\ tombstoneKind = "None"
                  /\ effectState["BlockRequest"] \in
                        {"Cancelling", "DeviceCompleted", "ResetIndeterminate"};
            if effectState["BlockRequest"] = "Cancelling" then
                effectState["BlockRequest"] := "Aborted";
            else
                effectState["BlockRequest"] := "Completed";
            end if;
            dmaState := "Released";
            freeCredits["Dma"] := freeCredits["Dma"] + 1;
        or
            \* Fixed reject order avoids a 2^N audit-set state multiplier.
            await /\ EnableRejects
                  /\ scenarioMode = "RejectProbe"
                  /\ rejectIndex \in 1..Len(RejectOrder);
            with kind = RejectOrder[rejectIndex] do
                await StaleEnabled(kind, scopeState, crashCount,
                    addressSpaceGeneration, inodeGeneration, deviceGeneration,
                    socketGeneration, sourceGeneration, retryKinds,
                    closedReceiptSequence, terminalCount);
                rejectKinds := rejectKinds \cup {kind};
                rejectIndex := rejectIndex + 1;
            end with;
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Down";
                domainPhase[d] := "Fallback";
            end with;
        or
            await /\ scopeState \in {"Active", "Closing"}
                  /\ effectState["ReadinessWait"] = "Committed";
            effectState["ReadinessWait"] := "Completed";
            terminalCount["ReadinessWait"] :=
                terminalCount["ReadinessWait"] + 1;
            readyDeliveryCount := readyDeliveryCount + 1;
            freeCredits["Readiness"] := freeCredits["Readiness"] + 1;
        or
            await /\ scopeState \in {"Active", "Closing"}
                  /\ effectState["FsSyscall"] = "Committed";
            effectState["FsSyscall"] := "Completed";
            terminalCount["FsSyscall"] := terminalCount["FsSyscall"] + 1;
            fsGuestPublicationCount := fsGuestPublicationCount + 1;
            freeCredits["Control"] := freeCredits["Control"] + 1;
        or
            await /\ scopeState \in {"Active", "Closing"}
                  /\ effectState["NetSyscall"] = "Committed";
            effectState["NetSyscall"] := "Completed";
            terminalCount["NetSyscall"] := terminalCount["NetSyscall"] + 1;
            netGuestPublicationCount := netGuestPublicationCount + 1;
            freeCredits["Control"] := freeCredits["Control"] + 1;
        or
            await /\ scopeState = "Closing"
                  /\ effectState["BufferLease"] = "Committed"
                  /\ bufferState = "Queued"
                  /\ bufferPayload = "Ping4";
            effectState["BufferLease"] := "Completed";
            terminalCount["BufferLease"] :=
                terminalCount["BufferLease"] + 1;
            bufferState := "Consumed";
            sourceReady := FALSE;
            bufferClosureCount := bufferClosureCount + 1;
            freeCredits["Buffer"] := freeCredits["Buffer"] + 1;
        or
            with e \in SimpleKernelEffects do
                await /\ effectState[e] = "Committed"
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Completed";
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
            end with;
        or
            await /\ effectState["NetOperation"] = "Committed"
                  /\ ChildrenTerminal("NetOperation", effectState,
                        effectParent);
            effectState["NetOperation"] := "Completed";
            terminalCount["NetOperation"] :=
                terminalCount["NetOperation"] + 1;
            socketState := "HalfClosed";
            freeCredits["Network"] := freeCredits["Network"] + 1;
        or
            with e \in NonBlockEffects do
                await /\ scopeState = "Closing"
                      /\ effectState[e] \in UncommittedStates
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Aborted";
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
                if e = "BufferLease" /\ socketState = "Pending" then
                    socketState := "Listening";
                elsif e = "NetOperation" /\ socketState = "Listening" then
                    socketState := "Closed";
                end if;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ effectState["BlockRequest"] = "Registered";
            effectState["BlockRequest"] := "Aborted";
            blockOutcome := "AbortedBeforeCommit";
            terminalCount["BlockRequest"] :=
                terminalCount["BlockRequest"] + 1;
            freeCredits["Dma"] := freeCredits["Dma"] + 1;
        or
            await /\ scopeState = "Closing"
                  /\ effectState["BlockRequest"] = "Prepared"
                  /\ dmaState = "Mapped";
            effectState["BlockRequest"] := "Cancelling";
            blockOutcome := "AbortedBeforeCommit";
            terminalCount["BlockRequest"] :=
                terminalCount["BlockRequest"] + 1;
            dmaState := "Invalidating";
        or
            \* Receipt publication is deterministic in this finite quotient.
            await /\ scopeState = "Closing"
                  /\ receiptCursor \in 1..Len(ReceiptOrder);
            with d = ReceiptOrder[receiptCursor] do
                await /\ domainReceipt[d] = "Pending"
                      /\ DomainClosingTerminal(d, effectsAtClose, effectState)
                      /\ ~(d = "VirtIo" /\ tombstoneKind # "None");
                domainReceipt[d] := "Closed";
                receiptCount[d] := receiptCount[d] + 1;
                receiptSequence[d] := nextReceiptSequence;
                receiptRevision[d] := domainRevision[d];
                receiptClosingEpoch[d] := closingEpoch;
                receiptBindingEpoch[d] := bindingEpoch[d];
                if d = "VirtIo" then
                    receiptDeviceGeneration[d] := deviceGeneration;
                else
                    receiptDeviceGeneration[d] := NoGeneration;
                end if;
                closedReceiptSequence[d] := nextReceiptSequence;
                nextReceiptSequence := nextReceiptSequence + 1;
                receiptCursor := receiptCursor + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ receiptCursor \in 1..Len(ReceiptOrder);
            with d = ReceiptOrder[receiptCursor] do
                await domainReceipt[d] = "NotRequired";
                receiptCursor := receiptCursor + 1;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ receiptCursor = Len(ReceiptOrder) + 1
                  /\ \A e \in effectsAtClose :
                        effectState[e] \in TerminalStates
                  /\ \A d \in closingDomains :
                        domainReceipt[d] = "Closed"
                  /\ \A t \in CreditTypes :
                        freeCredits[t] = CreditCapacity(t)
                  /\ tombstoneKind = "None"
                  /\ dmaState \in {"Absent", "Released"}
                  /\ bufferState \in {"Empty", "Consumed"}
                  /\ ~sourceReady;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "ef4b11c2" /\ chksum(tla) = "77512aa2")
VARIABLES scenarioMode, crashTarget, scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, readyDeliveryCount, bufferConsumptionCount, bufferClosureCount, fsGuestCommitCount, fsGuestPublicationCount, fsGuestResult, netGuestCommitCount, netGuestPublicationCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex

vars == << scenarioMode, crashTarget, scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, readyDeliveryCount, bufferConsumptionCount, bufferClosureCount, fsGuestCommitCount, fsGuestPublicationCount, fsGuestResult, netGuestCommitCount, netGuestPublicationCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scenarioMode \in ScenarioModes
        /\ crashTarget \in CrashTargets
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectState = [e \in Effects |-> "Unused"]
        /\ effectParent = [e \in Effects |-> NoParent]
        /\ effectAuthority = [e \in Effects |-> NoGeneration]
        /\ effectBinding = [e \in Effects |-> NoBinding]
        /\ effectAddressSpaceGeneration = [e \in Effects |-> NoGeneration]
        /\ effectInodeGeneration = [e \in Effects |-> NoGeneration]
        /\ effectDeviceGeneration = [e \in Effects |-> NoGeneration]
        /\ effectSocketGeneration = [e \in Effects |-> NoGeneration]
        /\ effectSourceGeneration = [e \in Effects |-> NoGeneration]
        /\ commitCount = [e \in Effects |-> 0]
        /\ terminalCount = [e \in Effects |-> 0]
        /\ nextDeriveIndex = 1
        /\ freeCredits = [t \in CreditTypes |-> CreditCapacity(t)]
        /\ bindingEpoch = [d \in Domains |-> 0]
        /\ domainPhase = [d \in Domains |-> "Bound"]
        /\ recoveryCohort = [d \in Domains |-> {}]
        /\ snapshotBinding = [d \in Domains |-> NoBinding]
        /\ snapshotCohort = [d \in Domains |-> {}]
        /\ snapshotAddressSpaceGeneration = [d \in Domains |-> NoGeneration]
        /\ snapshotInodeGeneration = [d \in Domains |-> NoGeneration]
        /\ snapshotDeviceGeneration = [d \in Domains |-> NoGeneration]
        /\ snapshotSocketGeneration = [d \in Domains |-> NoGeneration]
        /\ snapshotSourceGeneration = [d \in Domains |-> NoGeneration]
        /\ adoptCount = [d \in Domains |-> 0]
        /\ adoptedEffects = {}
        /\ crashCount = 0
        /\ addressSpaceGeneration = 0
        /\ ptePublished = FALSE
        /\ tlbSynced = FALSE
        /\ mapPublicationCount = 0
        /\ inodeGeneration = 0
        /\ inodeBytes = "Zeros"
        /\ inodePublicationCount = 0
        /\ deviceGeneration = 0
        /\ dmaState = "Absent"
        /\ blockOutcome = "None"
        /\ blockPublicationCount = 0
        /\ tombstoneKind = "None"
        /\ tombstoneResume = "None"
        /\ timeoutKinds = {}
        /\ retryKinds = {}
        /\ socketGeneration = 0
        /\ socketState = "Closed"
        /\ sourceGeneration = 0
        /\ sourceReady = FALSE
        /\ bufferState = "Empty"
        /\ bufferPayload = "None"
        /\ netReceiptSocketGeneration = NoGeneration
        /\ netReceiptPayload = "None"
        /\ frozenReady = FALSE
        /\ frozenSocketGeneration = NoGeneration
        /\ frozenSourceGeneration = NoGeneration
        /\ frozenPayload = "None"
        /\ netPublicationCount = 0
        /\ readyPublicationCount = 0
        /\ readyDeliveryCount = 0
        /\ bufferConsumptionCount = 0
        /\ bufferClosureCount = 0
        /\ fsGuestCommitCount = 0
        /\ fsGuestPublicationCount = 0
        /\ fsGuestResult = "None"
        /\ netGuestCommitCount = 0
        /\ netGuestPublicationCount = 0
        /\ netGuestResult = "None"
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ closingDomains = {}
        /\ committedAtClose = {}
        /\ commitAtClose = [e \in Effects |-> 0]
        /\ domainReceipt = [d \in Domains |-> "Open"]
        /\ domainRevision = [d \in Domains |-> 0]
        /\ receiptCount = [d \in Domains |-> 0]
        /\ nextReceiptSequence = 1
        /\ receiptSequence = [d \in Domains |-> 0]
        /\ receiptRevision = [d \in Domains |-> 0]
        /\ receiptClosingEpoch = [d \in Domains |-> NoGeneration]
        /\ receiptBindingEpoch = [d \in Domains |-> NoBinding]
        /\ receiptDeviceGeneration = [d \in Domains |-> NoGeneration]
        /\ closedReceiptSequence = [d \in Domains |-> 0]
        /\ timeoutReceiptSequence = [kind \in TimeoutTargets |-> 0]
        /\ timeoutReceiptRevision = [kind \in TimeoutTargets |-> 0]
        /\ timeoutReceiptDeviceGeneration = [kind \in TimeoutTargets |-> NoGeneration]
        /\ receiptCursor = 1
        /\ rejectKinds = {}
        /\ rejectIndex = 1

Environment == /\ \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ nextDeriveIndex \in 1..Len(DeriveOrder)
                     /\ LET e == DeriveOrder[nextDeriveIndex] IN
                          /\ /\ effectState[e] = "Unused"
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ ParentCanDerive(e, effectState, effectBinding,
                                   bindingEpoch, domainPhase)
                             /\ freeCredits[EffectCredit(e)] > 0
                          /\ effectState' = [effectState EXCEPT ![e] = "Registered"]
                          /\ effectParent' = [effectParent EXCEPT ![e] = AllowedParent(e)]
                          /\ effectAuthority' = [effectAuthority EXCEPT ![e] = authorityEpoch]
                          /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[EffectDomain(e)]]
                          /\ effectAddressSpaceGeneration' = [effectAddressSpaceGeneration EXCEPT ![e] = addressSpaceGeneration]
                          /\ effectInodeGeneration' = [effectInodeGeneration EXCEPT ![e] = inodeGeneration]
                          /\ effectDeviceGeneration' = [effectDeviceGeneration EXCEPT ![e] = deviceGeneration]
                          /\ effectSocketGeneration' = [effectSocketGeneration EXCEPT ![e] = socketGeneration]
                          /\ effectSourceGeneration' = [effectSourceGeneration EXCEPT ![e] = sourceGeneration]
                          /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] - 1]
                          /\ nextDeriveIndex' = nextDeriveIndex + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, commitCount, terminalCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E e \in Effects:
                          /\ /\ ModeAllowsEffect(scenarioMode, crashTarget,
                                   rejectIndex, e)
                             /\ nextDeriveIndex = Len(DeriveOrder) + 1
                             /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Registered"
                             /\ effectAuthority[e] = authorityEpoch
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                             /\ GenerationMatches(e,
                                   effectAddressSpaceGeneration,
                                   addressSpaceGeneration, effectInodeGeneration,
                                   inodeGeneration, effectDeviceGeneration,
                                   deviceGeneration, effectSocketGeneration,
                                   socketGeneration, effectSourceGeneration,
                                   sourceGeneration)
                             /\ (e # "NetOperation" \/ socketState = "Closed")
                             /\ (e # "BufferLease" \/
                                   /\ effectState["NetOperation"] = "Prepared"
                                   /\ socketState = "Listening")
                          /\ effectState' = [effectState EXCEPT ![e] = "Prepared"]
                          /\ IF e = "BlockRequest"
                                THEN /\ dmaState' = "Mapped"
                                     /\ UNCHANGED socketState
                                ELSE /\ IF e = "NetOperation"
                                           THEN /\ socketState' = "Listening"
                                           ELSE /\ IF e = "BufferLease"
                                                      THEN /\ socketState' = "Pending"
                                                      ELSE /\ TRUE
                                                           /\ UNCHANGED socketState
                                     /\ UNCHANGED dmaState
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["SchedulerAction"] = "Prepared"
                        /\ effectAuthority["SchedulerAction"] = authorityEpoch
                        /\ domainPhase["Scheduler"] = "Bound"
                        /\ effectBinding["SchedulerAction"] =
                              bindingEpoch["Scheduler"]
                     /\ effectState' = [effectState EXCEPT !["SchedulerAction"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["SchedulerAction"] = commitCount["SchedulerAction"] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["PagerMap"] = "Prepared"
                        /\ effectAuthority["PagerMap"] = authorityEpoch
                        /\ domainPhase["Pager"] = "Bound"
                        /\ effectBinding["PagerMap"] = bindingEpoch["Pager"]
                        /\ effectAddressSpaceGeneration["PagerMap"] =
                              addressSpaceGeneration
                     /\ effectState' = [effectState EXCEPT !["PagerMap"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["PagerMap"] = commitCount["PagerMap"] + 1]
                     /\ ptePublished' = TRUE
                     /\ tlbSynced' = TRUE
                     /\ mapPublicationCount' = mapPublicationCount + 1
                     /\ addressSpaceGeneration' = addressSpaceGeneration + 1
                     /\ domainPhase' =            [d \in Domains |->
                                       IF domainPhase[d] = "Ready" THEN "Fallback"
                                       ELSE domainPhase[d]]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["FsOperation"] = "Prepared"
                        /\ effectAuthority["FsOperation"] = authorityEpoch
                        /\ domainPhase["Filesystem"] = "Bound"
                        /\ effectBinding["FsOperation"] =
                              bindingEpoch["Filesystem"]
                        /\ effectInodeGeneration["FsOperation"] = inodeGeneration
                     /\ effectState' = [effectState EXCEPT !["FsOperation"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["FsOperation"] = commitCount["FsOperation"] + 1]
                     /\ inodeBytes' = "HoleXY"
                     /\ inodeGeneration' = inodeGeneration + 1
                     /\ inodePublicationCount' = inodePublicationCount + 1
                     /\ domainPhase' =            [d \in Domains |->
                                       IF domainPhase[d] = "Ready" THEN "Fallback"
                                       ELSE domainPhase[d]]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["BlockRequest"] = "Prepared"
                        /\ effectAuthority["BlockRequest"] = authorityEpoch
                        /\ domainPhase["VirtIo"] = "Bound"
                        /\ effectBinding["BlockRequest"] = bindingEpoch["VirtIo"]
                        /\ effectDeviceGeneration["BlockRequest"] = deviceGeneration
                        /\ dmaState = "Mapped"
                     /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["BlockRequest"] = commitCount["BlockRequest"] + 1]
                     /\ blockPublicationCount' = blockPublicationCount + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["NetOperation"] = "Prepared"
                        /\ effectState["BufferLease"] = "Prepared"
                        /\ socketState = "Pending"
                        /\ bufferState = "Empty"
                        /\ ~sourceReady
                        /\ netPublicationCount = 0
                        /\ \A e \in {"NetOperation", "BufferLease"} :
                              /\ effectAuthority[e] = authorityEpoch
                              /\ domainPhase["Network"] = "Bound"
                              /\ effectBinding[e] = bindingEpoch["Network"]
                              /\ effectSocketGeneration[e] = socketGeneration
                     /\ effectState' =            [effectState EXCEPT
                                       !["NetOperation"] = "Committed",
                                       !["BufferLease"] = "Committed"]
                     /\ commitCount' =            [commitCount EXCEPT
                                       !["NetOperation"] = @ + 1,
                                       !["BufferLease"] = @ + 1]
                     /\ netReceiptSocketGeneration' = socketGeneration + 1
                     /\ netReceiptPayload' = "Ping4"
                     /\ socketGeneration' = socketGeneration + 1
                     /\ socketState' = "Connected"
                     /\ bufferState' = "Queued"
                     /\ bufferPayload' = "Ping4"
                     /\ sourceReady' = TRUE
                     /\ netPublicationCount' = netPublicationCount + 1
                     /\ domainPhase' =            [d \in Domains |->
                                       IF domainPhase[d] = "Ready" THEN "Fallback"
                                       ELSE domainPhase[d]]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, sourceGeneration, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["ReadinessWait"] = "Prepared"
                        /\ effectState["NetOperation"] = "Committed"
                        /\ effectAuthority["ReadinessWait"] = authorityEpoch
                        /\ domainPhase["Readiness"] = "Bound"
                        /\ effectBinding["ReadinessWait"] =
                              bindingEpoch["Readiness"]
                        /\ effectSourceGeneration["ReadinessWait"] =
                              sourceGeneration
                        /\ netPublicationCount = 1
                        /\ netReceiptSocketGeneration = socketGeneration
                        /\ netReceiptPayload = "Ping4"
                        /\ bufferState = "Queued"
                        /\ sourceReady
                        /\ readyPublicationCount = 0
                     /\ effectState' = [effectState EXCEPT !["ReadinessWait"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["ReadinessWait"] = commitCount["ReadinessWait"] + 1]
                     /\ frozenReady' = TRUE
                     /\ frozenSocketGeneration' = socketGeneration
                     /\ frozenSourceGeneration' = sourceGeneration + 1
                     /\ frozenPayload' = "Ping4"
                     /\ sourceGeneration' = sourceGeneration + 1
                     /\ readyPublicationCount' = readyPublicationCount + 1
                     /\ domainPhase' =            [d \in Domains |->
                                       IF domainPhase[d] = "Ready" THEN "Fallback"
                                       ELSE domainPhase[d]]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, netPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["FsSyscall"] = "Prepared"
                        /\ effectAuthority["FsSyscall"] = authorityEpoch
                        /\ domainPhase["Personality"] = "Bound"
                        /\ effectBinding["FsSyscall"] = bindingEpoch["Personality"]
                        /\ effectState["PagerMap"] = "Completed"
                        /\ effectState["FsOperation"] = "Completed"
                        /\ fsGuestCommitCount = 0
                     /\ effectState' = [effectState EXCEPT !["FsSyscall"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["FsSyscall"] = commitCount["FsSyscall"] + 1]
                     /\ fsGuestCommitCount' = fsGuestCommitCount + 1
                     /\ fsGuestResult' = "PwriteOK"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["NetSyscall"] = "Prepared"
                        /\ effectAuthority["NetSyscall"] = authorityEpoch
                        /\ domainPhase["Personality"] = "Bound"
                        /\ effectBinding["NetSyscall"] =
                              bindingEpoch["Personality"]
                        /\ effectState["NetOperation"] = "Completed"
                        /\ effectState["ReadinessWait"] = "Completed"
                        /\ readyDeliveryCount = 1
                        /\ netGuestCommitCount = 0
                     /\ effectState' = [effectState EXCEPT !["NetSyscall"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["NetSyscall"] = commitCount["NetSyscall"] + 1]
                     /\ netGuestCommitCount' = netGuestCommitCount + 1
                     /\ netGuestResult' = "LoopbackOK"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E d \in Domains:
                          /\ /\ EnableCrash
                             /\ scenarioMode \in {"NewDomainCrash", "RejectProbe"}
                             /\ d = crashTarget
                             /\ (scenarioMode = "NewDomainCrash" \/ rejectIndex = 6)
                             /\ scopeState = "Active"
                             /\ domainPhase[d] = "Bound"
                             /\ bindingEpoch[d] < MaxBinding
                             /\ crashCount = 0
                             /\ \E e \in Effects :
                                   /\ EffectDomain(e) = d
                                   /\ effectState[e] \in LiveStates
                          /\ bindingEpoch' = [bindingEpoch EXCEPT ![d] = bindingEpoch[d] + 1]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Down"]
                          /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = {e \in Effects :
                                                                                 /\ EffectDomain(e) = d
                                                                                 /\ effectState[e] \in UncommittedStates}]
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = NoBinding]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = {}]
                          /\ snapshotAddressSpaceGeneration' = [snapshotAddressSpaceGeneration EXCEPT ![d] = NoGeneration]
                          /\ snapshotInodeGeneration' = [snapshotInodeGeneration EXCEPT ![d] = NoGeneration]
                          /\ snapshotDeviceGeneration' = [snapshotDeviceGeneration EXCEPT ![d] = NoGeneration]
                          /\ snapshotSocketGeneration' = [snapshotSocketGeneration EXCEPT ![d] = NoGeneration]
                          /\ snapshotSourceGeneration' = [snapshotSourceGeneration EXCEPT ![d] = NoGeneration]
                          /\ crashCount' = crashCount + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, adoptCount, adoptedEffects, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Fallback"
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = bindingEpoch[d]]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = recoveryCohort[d]]
                          /\ snapshotAddressSpaceGeneration' = [snapshotAddressSpaceGeneration EXCEPT ![d] = addressSpaceGeneration]
                          /\ snapshotInodeGeneration' = [snapshotInodeGeneration EXCEPT ![d] = inodeGeneration]
                          /\ snapshotDeviceGeneration' = [snapshotDeviceGeneration EXCEPT ![d] = deviceGeneration]
                          /\ snapshotSocketGeneration' = [snapshotSocketGeneration EXCEPT ![d] = socketGeneration]
                          /\ snapshotSourceGeneration' = [snapshotSourceGeneration EXCEPT ![d] = sourceGeneration]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Snapshotted"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Snapshotted"
                             /\ snapshotBinding[d] = bindingEpoch[d]
                             /\ snapshotCohort[d] = recoveryCohort[d]
                             /\ snapshotAddressSpaceGeneration[d] =
                                   addressSpaceGeneration
                             /\ snapshotInodeGeneration[d] = inodeGeneration
                             /\ snapshotDeviceGeneration[d] = deviceGeneration
                             /\ snapshotSocketGeneration[d] = socketGeneration
                             /\ snapshotSourceGeneration[d] = sourceGeneration
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Ready"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Ready"
                             /\ snapshotBinding[d] = bindingEpoch[d]
                             /\ snapshotCohort[d] = recoveryCohort[d]
                             /\ snapshotAddressSpaceGeneration[d] =
                                   addressSpaceGeneration
                             /\ snapshotInodeGeneration[d] = inodeGeneration
                             /\ snapshotDeviceGeneration[d] = deviceGeneration
                             /\ snapshotSocketGeneration[d] = socketGeneration
                             /\ snapshotSourceGeneration[d] = sourceGeneration
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Bound"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E d \in Domains:
                          \E e \in recoveryCohort[d]:
                            /\ /\ scopeState = "Active"
                               /\ domainPhase[d] = "Bound"
                               /\ EffectDomain(e) = d
                               /\ effectState[e] \in UncommittedStates
                               /\ effectBinding[e] # bindingEpoch[d]
                            /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[d]]
                            /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = recoveryCohort[d] \ {e}]
                            /\ adoptedEffects' = (adoptedEffects \cup {e})
                            /\ adoptCount' = [adoptCount EXCEPT ![d] = adoptCount[d] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scenarioMode \in {"Core", "NewDomainCrash"}
                        /\ domainPhase["Network"] = "Bound"
                        /\ effectBinding["BufferLease"] = bindingEpoch["Network"]
                        /\ effectState["BufferLease"] = "Committed"
                        /\ bufferState = "Queued"
                        /\ bufferPayload = "Ping4"
                     /\ effectState' = [effectState EXCEPT !["BufferLease"] = "Completed"]
                     /\ terminalCount' = [terminalCount EXCEPT !["BufferLease"] = terminalCount["BufferLease"] + 1]
                     /\ bufferState' = "Consumed"
                     /\ sourceReady' = FALSE
                     /\ bufferConsumptionCount' = bufferConsumptionCount + 1
                     /\ freeCredits' = [freeCredits EXCEPT !["Buffer"] = freeCredits["Buffer"] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, nextDeriveIndex, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scenarioMode \in
                              {"DeriveRace", "Core", "DmaTimeout", "RejectProbe"}
                        /\ (scenarioMode # "RejectProbe" \/ rejectIndex = 7)
                        /\ (scenarioMode = "DeriveRace" \/
                              nextDeriveIndex = Len(DeriveOrder) + 1)
                     /\ effectsAtClose' = {e \in Effects : effectState[e] # "Unused"}
                     /\ closingEffects' = {e \in Effects : effectState[e] \in LiveStates}
                     /\ closingDomains' = {d \in Domains : \E e \in Effects :
                                              EffectDomain(e) = d /\ effectState[e] # "Unused"}
                     /\ committedAtClose' = {e \in Effects :
                                                commitCount[e] = 1 /\ effectState[e] \in LiveStates}
                     /\ commitAtClose' = commitCount
                     /\ domainReceipt' =              [d \in Domains |->
                                         IF \E e \in Effects :
                                             EffectDomain(e) = d /\ effectState[e] # "Unused"
                                         THEN "Pending" ELSE "NotRequired"]
                     /\ closingEpoch' = authorityEpoch
                     /\ authorityEpoch' = authorityEpoch + 1
                     /\ scopeGate' = "Closed"
                     /\ scopeState' = "Closing"
                     /\ domainPhase' = [d \in Domains |-> "Closed"]
                     /\ recoveryCohort' = [d \in Domains |-> {}]
                     /\ receiptCursor' = 1
                     /\ UNCHANGED <<effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, rejectKinds, rejectIndex>>
                  \/ /\ /\ EnableTimeout
                        /\ scenarioMode = "DmaTimeout"
                        /\ scopeState = "Closing"
                        /\ effectState["BlockRequest"] = "Committed"
                        /\ tombstoneKind = "None"
                        /\ "Reset" \notin timeoutKinds
                        /\ domainReceipt["VirtIo"] = "Pending"
                     /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Tombstoned"]
                     /\ tombstoneKind' = "Reset"
                     /\ tombstoneResume' = "Committed"
                     /\ timeoutKinds' = (timeoutKinds \cup {"Reset"})
                     /\ domainReceipt' = [domainReceipt EXCEPT !["VirtIo"] = "TimedOut"]
                     /\ receiptSequence' = [receiptSequence EXCEPT !["VirtIo"] = nextReceiptSequence]
                     /\ receiptRevision' = [receiptRevision EXCEPT !["VirtIo"] = domainRevision["VirtIo"]]
                     /\ receiptClosingEpoch' = [receiptClosingEpoch EXCEPT !["VirtIo"] = closingEpoch]
                     /\ receiptBindingEpoch' = [receiptBindingEpoch EXCEPT !["VirtIo"] = bindingEpoch["VirtIo"]]
                     /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT !["VirtIo"] = deviceGeneration]
                     /\ timeoutReceiptSequence' = [timeoutReceiptSequence EXCEPT !["Reset"] = nextReceiptSequence]
                     /\ timeoutReceiptRevision' = [timeoutReceiptRevision EXCEPT !["Reset"] = domainRevision["VirtIo"]]
                     /\ timeoutReceiptDeviceGeneration' = [timeoutReceiptDeviceGeneration EXCEPT !["Reset"] = deviceGeneration]
                     /\ nextReceiptSequence' = nextReceiptSequence + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainRevision, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState \in {"Active", "Closing"}
                        /\ scenarioMode \in {"Core", "DmaTimeout", "RejectProbe"}
                        /\ effectState["BlockRequest"] = "Committed"
                        /\ tombstoneKind = "None"
                        /\ effectDeviceGeneration["BlockRequest"] = deviceGeneration
                     /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "ResetIndeterminate"]
                     /\ blockOutcome' = "IndeterminateAfterReset"
                     /\ terminalCount' = [terminalCount EXCEPT !["BlockRequest"] = terminalCount["BlockRequest"] + 1]
                     /\ deviceGeneration' = deviceGeneration + 1
                     /\ dmaState' = "Invalidating"
                     /\ domainPhase' =            [d \in Domains |->
                                       IF domainPhase[d] = "Ready" THEN "Fallback"
                                       ELSE domainPhase[d]]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, nextDeriveIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ scopeState \in {"Active", "Closing"}
                        /\ scenarioMode = "Core"
                        /\ effectState["BlockRequest"] = "Committed"
                        /\ tombstoneKind = "None"
                        /\ effectDeviceGeneration["BlockRequest"] = deviceGeneration
                     /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "DeviceCompleted"]
                     /\ blockOutcome' = "Completed"
                     /\ terminalCount' = [terminalCount EXCEPT !["BlockRequest"] = terminalCount["BlockRequest"] + 1]
                     /\ dmaState' = "Invalidating"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ EnableTimeout
                        /\ scenarioMode \in {"DmaTimeout", "RejectProbe"}
                        /\ scopeState = "Closing"
                        /\ dmaState = "Invalidating"
                        /\ effectState["BlockRequest"] \in
                              {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
                        /\ tombstoneKind = "None"
                        /\ "Iotlb" \notin timeoutKinds
                        /\ domainReceipt["VirtIo"] = "Pending"
                     /\ tombstoneResume' = effectState["BlockRequest"]
                     /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Tombstoned"]
                     /\ tombstoneKind' = "Iotlb"
                     /\ timeoutKinds' = (timeoutKinds \cup {"Iotlb"})
                     /\ domainReceipt' = [domainReceipt EXCEPT !["VirtIo"] = "TimedOut"]
                     /\ receiptSequence' = [receiptSequence EXCEPT !["VirtIo"] = nextReceiptSequence]
                     /\ receiptRevision' = [receiptRevision EXCEPT !["VirtIo"] = domainRevision["VirtIo"]]
                     /\ receiptClosingEpoch' = [receiptClosingEpoch EXCEPT !["VirtIo"] = closingEpoch]
                     /\ receiptBindingEpoch' = [receiptBindingEpoch EXCEPT !["VirtIo"] = bindingEpoch["VirtIo"]]
                     /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT !["VirtIo"] = deviceGeneration]
                     /\ timeoutReceiptSequence' = [timeoutReceiptSequence EXCEPT !["Iotlb"] = nextReceiptSequence]
                     /\ timeoutReceiptRevision' = [timeoutReceiptRevision EXCEPT !["Iotlb"] = domainRevision["VirtIo"]]
                     /\ timeoutReceiptDeviceGeneration' = [timeoutReceiptDeviceGeneration EXCEPT !["Iotlb"] = deviceGeneration]
                     /\ nextReceiptSequence' = nextReceiptSequence + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainRevision, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ \E kind \in TimeoutTargets:
                          /\ /\ scenarioMode \in {"DmaTimeout", "RejectProbe"}
                             /\ tombstoneKind = kind
                             /\ kind \in timeoutKinds
                             /\ kind \notin retryKinds
                          /\ effectState' = [effectState EXCEPT !["BlockRequest"] = tombstoneResume]
                          /\ retryKinds' = (retryKinds \cup {kind})
                          /\ tombstoneKind' = "None"
                          /\ tombstoneResume' = "None"
                          /\ domainRevision' = [domainRevision EXCEPT !["VirtIo"] = domainRevision["VirtIo"] + 1]
                          /\ domainReceipt' = [domainReceipt EXCEPT !["VirtIo"] = "Pending"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, timeoutKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ dmaState = "Invalidating"
                        /\ scenarioMode \in {"Core", "DmaTimeout", "RejectProbe"}
                        /\ tombstoneKind = "None"
                        /\ effectState["BlockRequest"] \in
                              {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
                     /\ IF effectState["BlockRequest"] = "Cancelling"
                           THEN /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Aborted"]
                           ELSE /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Completed"]
                     /\ dmaState' = "Released"
                     /\ freeCredits' = [freeCredits EXCEPT !["Dma"] = freeCredits["Dma"] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor, rejectKinds, rejectIndex>>
                  \/ /\ /\ EnableRejects
                        /\ scenarioMode = "RejectProbe"
                        /\ rejectIndex \in 1..Len(RejectOrder)
                     /\ LET kind == RejectOrder[rejectIndex] IN
                          /\   StaleEnabled(kind, scopeState, crashCount,
                             addressSpaceGeneration, inodeGeneration, deviceGeneration,
                             socketGeneration, sourceGeneration, retryKinds,
                             closedReceiptSequence, terminalCount)
                          /\ rejectKinds' = (rejectKinds \cup {kind})
                          /\ rejectIndex' = rejectIndex + 1
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, dmaState, blockOutcome, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainReceipt, domainRevision, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor>>
               /\ UNCHANGED << scenarioMode, crashTarget, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, receiptCount, closedReceiptSequence >>

Kernel == /\ \/ /\ \E d \in Domains:
                     /\ /\ scopeState = "Active"
                        /\ domainPhase[d] = "Down"
                     /\ domainPhase' = [domainPhase EXCEPT ![d] = "Fallback"]
                /\ UNCHANGED <<scopeState, effectState, terminalCount, freeCredits, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState \in {"Active", "Closing"}
                   /\ effectState["ReadinessWait"] = "Committed"
                /\ effectState' = [effectState EXCEPT !["ReadinessWait"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["ReadinessWait"] = terminalCount["ReadinessWait"] + 1]
                /\ readyDeliveryCount' = readyDeliveryCount + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Readiness"] = freeCredits["Readiness"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState \in {"Active", "Closing"}
                   /\ effectState["FsSyscall"] = "Committed"
                /\ effectState' = [effectState EXCEPT !["FsSyscall"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["FsSyscall"] = terminalCount["FsSyscall"] + 1]
                /\ fsGuestPublicationCount' = fsGuestPublicationCount + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Control"] = freeCredits["Control"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState \in {"Active", "Closing"}
                   /\ effectState["NetSyscall"] = "Committed"
                /\ effectState' = [effectState EXCEPT !["NetSyscall"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["NetSyscall"] = terminalCount["NetSyscall"] + 1]
                /\ netGuestPublicationCount' = netGuestPublicationCount + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Control"] = freeCredits["Control"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState = "Closing"
                   /\ effectState["BufferLease"] = "Committed"
                   /\ bufferState = "Queued"
                   /\ bufferPayload = "Ping4"
                /\ effectState' = [effectState EXCEPT !["BufferLease"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["BufferLease"] = terminalCount["BufferLease"] + 1]
                /\ bufferState' = "Consumed"
                /\ sourceReady' = FALSE
                /\ bufferClosureCount' = bufferClosureCount + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Buffer"] = freeCredits["Buffer"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, socketState, readyDeliveryCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ \E e \in SimpleKernelEffects:
                     /\ /\ effectState[e] = "Committed"
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ effectState["NetOperation"] = "Committed"
                   /\ ChildrenTerminal("NetOperation", effectState,
                         effectParent)
                /\ effectState' = [effectState EXCEPT !["NetOperation"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["NetOperation"] = terminalCount["NetOperation"] + 1]
                /\ socketState' = "HalfClosed"
                /\ freeCredits' = [freeCredits EXCEPT !["Network"] = freeCredits["Network"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ \E e \in NonBlockEffects:
                     /\ /\ scopeState = "Closing"
                        /\ effectState[e] \in UncommittedStates
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Aborted"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                     /\ IF e = "BufferLease" /\ socketState = "Pending"
                           THEN /\ socketState' = "Listening"
                           ELSE /\ IF e = "NetOperation" /\ socketState = "Listening"
                                      THEN /\ socketState' = "Closed"
                                      ELSE /\ TRUE
                                           /\ UNCHANGED socketState
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, blockOutcome, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState = "Closing"
                   /\ effectState["BlockRequest"] = "Registered"
                /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Aborted"]
                /\ blockOutcome' = "AbortedBeforeCommit"
                /\ terminalCount' = [terminalCount EXCEPT !["BlockRequest"] = terminalCount["BlockRequest"] + 1]
                /\ freeCredits' = [freeCredits EXCEPT !["Dma"] = freeCredits["Dma"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, dmaState, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState = "Closing"
                   /\ effectState["BlockRequest"] = "Prepared"
                   /\ dmaState = "Mapped"
                /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Cancelling"]
                /\ blockOutcome' = "AbortedBeforeCommit"
                /\ terminalCount' = [terminalCount EXCEPT !["BlockRequest"] = terminalCount["BlockRequest"] + 1]
                /\ dmaState' = "Invalidating"
                /\ UNCHANGED <<scopeState, freeCredits, domainPhase, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
             \/ /\ /\ scopeState = "Closing"
                   /\ receiptCursor \in 1..Len(ReceiptOrder)
                /\ LET d == ReceiptOrder[receiptCursor] IN
                     /\ /\ domainReceipt[d] = "Pending"
                        /\ DomainClosingTerminal(d, effectsAtClose, effectState)
                        /\ ~(d = "VirtIo" /\ tombstoneKind # "None")
                     /\ domainReceipt' = [domainReceipt EXCEPT ![d] = "Closed"]
                     /\ receiptCount' = [receiptCount EXCEPT ![d] = receiptCount[d] + 1]
                     /\ receiptSequence' = [receiptSequence EXCEPT ![d] = nextReceiptSequence]
                     /\ receiptRevision' = [receiptRevision EXCEPT ![d] = domainRevision[d]]
                     /\ receiptClosingEpoch' = [receiptClosingEpoch EXCEPT ![d] = closingEpoch]
                     /\ receiptBindingEpoch' = [receiptBindingEpoch EXCEPT ![d] = bindingEpoch[d]]
                     /\ IF d = "VirtIo"
                           THEN /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT ![d] = deviceGeneration]
                           ELSE /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT ![d] = NoGeneration]
                     /\ closedReceiptSequence' = [closedReceiptSequence EXCEPT ![d] = nextReceiptSequence]
                     /\ nextReceiptSequence' = nextReceiptSequence + 1
                     /\ receiptCursor' = receiptCursor + 1
                /\ UNCHANGED <<scopeState, effectState, terminalCount, freeCredits, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount>>
             \/ /\ /\ scopeState = "Closing"
                   /\ receiptCursor \in 1..Len(ReceiptOrder)
                /\ LET d == ReceiptOrder[receiptCursor] IN
                     /\ domainReceipt[d] = "NotRequired"
                     /\ receiptCursor' = receiptCursor + 1
                /\ UNCHANGED <<scopeState, effectState, terminalCount, freeCredits, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence>>
             \/ /\ /\ scopeState = "Closing"
                   /\ receiptCursor = Len(ReceiptOrder) + 1
                   /\ \A e \in effectsAtClose :
                         effectState[e] \in TerminalStates
                   /\ \A d \in closingDomains :
                         domainReceipt[d] = "Closed"
                   /\ \A t \in CreditTypes :
                         freeCredits[t] = CreditCapacity(t)
                   /\ tombstoneKind = "None"
                   /\ dmaState \in {"Absent", "Released"}
                   /\ bufferState \in {"Empty", "Consumed"}
                   /\ ~sourceReady
                /\ scopeState' = "Revoked"
                /\ UNCHANGED <<effectState, terminalCount, freeCredits, domainPhase, dmaState, blockOutcome, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount, fsGuestPublicationCount, netGuestPublicationCount, domainReceipt, receiptCount, nextReceiptSequence, receiptSequence, receiptRevision, receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration, closedReceiptSequence, receiptCursor>>
          /\ UNCHANGED << scenarioMode, crashTarget, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectAddressSpaceGeneration, effectInodeGeneration, effectDeviceGeneration, effectSocketGeneration, effectSourceGeneration, commitCount, nextDeriveIndex, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration, snapshotInodeGeneration, snapshotDeviceGeneration, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, crashCount, addressSpaceGeneration, ptePublished, tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes, inodePublicationCount, deviceGeneration, blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds, retryKinds, socketGeneration, sourceGeneration, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, fsGuestCommitCount, fsGuestResult, netGuestCommitCount, netGuestResult, effectsAtClose, closingEffects, closingDomains, committedAtClose, commitAtClose, domainRevision, timeoutReceiptSequence, timeoutReceiptRevision, timeoutReceiptDeviceGeneration, rejectKinds, rejectIndex >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

TypeOK ==
    /\ scenarioMode \in ScenarioModes
    /\ crashTarget \in CrashTargets
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
    /\ effectBinding \in [Effects -> {NoBinding} \cup (0..MaxBinding)]
    /\ effectAddressSpaceGeneration \in [Effects -> {NoGeneration, 0, 1}]
    /\ effectInodeGeneration \in [Effects -> {NoGeneration, 0, 1}]
    /\ effectDeviceGeneration \in [Effects -> {NoGeneration, 0, 1}]
    /\ effectSocketGeneration \in [Effects -> {NoGeneration, 0, 1}]
    /\ effectSourceGeneration \in [Effects -> {NoGeneration, 0, 1}]
    /\ commitCount \in [Effects -> 0..1]
    /\ terminalCount \in [Effects -> 0..1]
    /\ nextDeriveIndex \in 1..(Len(DeriveOrder) + 1)
    /\ freeCredits \in [CreditTypes -> 0..2]
    /\ bindingEpoch \in [Domains -> 0..MaxBinding]
    /\ domainPhase \in [Domains ->
        {"Bound", "Down", "Fallback", "Snapshotted", "Ready", "Closed"}]
    /\ recoveryCohort \in [Domains -> SUBSET Effects]
    /\ snapshotBinding \in [Domains -> {NoBinding} \cup (0..MaxBinding)]
    /\ snapshotCohort \in [Domains -> SUBSET Effects]
    /\ snapshotAddressSpaceGeneration \in [Domains -> {NoGeneration, 0, 1}]
    /\ snapshotInodeGeneration \in [Domains -> {NoGeneration, 0, 1}]
    /\ snapshotDeviceGeneration \in [Domains -> {NoGeneration, 0, 1}]
    /\ snapshotSocketGeneration \in [Domains -> {NoGeneration, 0, 1}]
    /\ snapshotSourceGeneration \in [Domains -> {NoGeneration, 0, 1}]
    /\ adoptCount \in [Domains -> 0..2]
    /\ adoptedEffects \subseteq Effects
    /\ crashCount \in 0..1
    /\ addressSpaceGeneration \in 0..1
    /\ ptePublished \in BOOLEAN
    /\ tlbSynced \in BOOLEAN
    /\ mapPublicationCount \in 0..1
    /\ inodeGeneration \in 0..1
    /\ inodeBytes \in {"Zeros", "HoleXY"}
    /\ inodePublicationCount \in 0..1
    /\ deviceGeneration \in 0..1
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
    /\ socketGeneration \in 0..1
    /\ socketState \in
        {"Closed", "Listening", "Pending", "Connected", "HalfClosed"}
    /\ sourceGeneration \in 0..1
    /\ sourceReady \in BOOLEAN
    /\ bufferState \in {"Empty", "Queued", "Consumed"}
    /\ bufferPayload \in {"None", "Ping4"}
    /\ netReceiptSocketGeneration \in {NoGeneration, 1}
    /\ netReceiptPayload \in {"None", "Ping4"}
    /\ frozenReady \in BOOLEAN
    /\ frozenSocketGeneration \in {NoGeneration, 1}
    /\ frozenSourceGeneration \in {NoGeneration, 1}
    /\ frozenPayload \in {"None", "Ping4"}
    /\ netPublicationCount \in 0..1
    /\ readyPublicationCount \in 0..1
    /\ readyDeliveryCount \in 0..1
    /\ bufferConsumptionCount \in 0..1
    /\ bufferClosureCount \in 0..1
    /\ fsGuestCommitCount \in 0..1
    /\ fsGuestPublicationCount \in 0..1
    /\ fsGuestResult \in {"None", "PwriteOK"}
    /\ netGuestCommitCount \in 0..1
    /\ netGuestPublicationCount \in 0..1
    /\ netGuestResult \in {"None", "LoopbackOK"}
    /\ effectsAtClose \subseteq Effects
    /\ closingEffects \subseteq Effects
    /\ closingDomains \subseteq Domains
    /\ committedAtClose \subseteq Effects
    /\ commitAtClose \in [Effects -> 0..1]
    /\ domainReceipt \in [Domains ->
        {"Open", "Pending", "TimedOut", "Closed", "NotRequired"}]
    /\ domainRevision \in [Domains -> 0..2]
    /\ receiptCount \in [Domains -> 0..1]
    /\ nextReceiptSequence \in 1..(MaxReceiptSequence + 1)
    /\ receiptSequence \in [Domains -> 0..MaxReceiptSequence]
    /\ receiptRevision \in [Domains -> 0..2]
    /\ receiptClosingEpoch \in [Domains -> {NoGeneration, 0}]
    /\ receiptBindingEpoch \in
        [Domains -> {NoBinding} \cup (0..MaxBinding)]
    /\ receiptDeviceGeneration \in [Domains -> {NoGeneration, 0, 1}]
    /\ closedReceiptSequence \in [Domains -> 0..MaxReceiptSequence]
    /\ timeoutReceiptSequence \in
        [TimeoutTargets -> 0..MaxReceiptSequence]
    /\ timeoutReceiptRevision \in [TimeoutTargets -> 0..2]
    /\ timeoutReceiptDeviceGeneration \in
        [TimeoutTargets -> {NoGeneration, 0, 1}]
    /\ receiptCursor \in 1..(Len(ReceiptOrder) + 1)
    /\ rejectKinds \subseteq RejectKinds
    /\ rejectIndex \in 1..(Len(RejectOrder) + 1)

ScopeGateDiscipline ==
    /\ (scopeState = "Active" <=> scopeGate = "Open")
    /\ (scopeState \in {"Closing", "Revoked"} <=> scopeGate = "Closed")
    /\ (scopeState = "Active" =>
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ closingDomains = {})
    /\ (scopeState \in {"Closing", "Revoked"} =>
        /\ authorityEpoch = 1
        /\ closingEpoch = 0
        /\ \A d \in Domains : domainPhase[d] = "Closed")

FixedLinuxIoGraph ==
    /\ \A i, j \in 1..Len(DeriveOrder) :
        i < j =>
            (effectState[DeriveOrder[j]] # "Unused" =>
                effectState[DeriveOrder[i]] # "Unused")
    /\ \A e \in Effects :
        /\ (effectState[e] = "Unused" =>
            /\ effectParent[e] = NoParent
            /\ effectAuthority[e] = NoGeneration
            /\ effectBinding[e] = NoBinding)
        /\ (effectState[e] # "Unused" =>
            /\ effectParent[e] = AllowedParent(e)
            /\ effectAuthority[e] = 0
            /\ effectBinding[e] \in 0..bindingEpoch[EffectDomain(e)])
    /\ \A e \in Effects \ {"FsSyscall", "NetSyscall"} :
        effectState[e] # "Unused" =>
            effectState[AllowedParent(e)] # "Unused"

CausalIdentity ==
    /\ \A e \in Effects :
        effectState[e] # "Unused" =>
            /\ effectParent[e] = AllowedParent(e)
            /\ effectAuthority[e] = 0
    /\ \A child \in Effects :
        effectState[child] # "Unused" /\ AllowedParent(child) # Root =>
            effectState[AllowedParent(child)] # "Unused"

NoOrphanDescendants ==
    \A parent \in Effects :
        effectState[parent] \in TerminalStates =>
            \A child \in Effects :
                (effectParent[child] = parent /\ effectState[child] # "Unused")
                    => effectState[child] \in TerminalStates

EffectLifecycle ==
    /\ \A e \in NonBlockEffects :
        /\ (effectState[e] \in {"Unused", "Registered", "Prepared"} =>
            /\ commitCount[e] = 0 /\ terminalCount[e] = 0)
        /\ (effectState[e] = "Committed" =>
            /\ commitCount[e] = 1 /\ terminalCount[e] = 0)
        /\ (effectState[e] = "Completed" =>
            /\ commitCount[e] = 1 /\ terminalCount[e] = 1)
        /\ (effectState[e] = "Aborted" =>
            /\ commitCount[e] = 0 /\ terminalCount[e] = 1)
    /\ (effectState["BlockRequest"] = "Committed" =>
        /\ commitCount["BlockRequest"] = 1
        /\ terminalCount["BlockRequest"] = 0)
    /\ (effectState["BlockRequest"] \in
            {"DeviceCompleted", "ResetIndeterminate"} =>
        /\ commitCount["BlockRequest"] = 1
        /\ terminalCount["BlockRequest"] = 1)
    /\ (effectState["BlockRequest"] = "Cancelling" =>
        /\ commitCount["BlockRequest"] = 0
        /\ terminalCount["BlockRequest"] = 1)
    /\ (effectState["BlockRequest"] = "Completed" =>
        /\ commitCount["BlockRequest"] = 1
        /\ terminalCount["BlockRequest"] = 1)
    /\ (effectState["BlockRequest"] = "Aborted" =>
        /\ commitCount["BlockRequest"] = 0
        /\ terminalCount["BlockRequest"] = 1)

TypedCreditConservation ==
    \A t \in CreditTypes :
        freeCredits[t]
        + Cardinality({e \in Effects :
            EffectCredit(e) = t /\ effectState[e] \in LiveStates})
        = CreditCapacity(t)

FilesystemPublicationDiscipline ==
    /\ mapPublicationCount = commitCount["PagerMap"]
    /\ inodePublicationCount = commitCount["FsOperation"]
    /\ blockPublicationCount = commitCount["BlockRequest"]
    /\ addressSpaceGeneration = mapPublicationCount
    /\ inodeGeneration = inodePublicationCount
    /\ (mapPublicationCount = 0 <=> /\ ~ptePublished /\ ~tlbSynced)
    /\ (mapPublicationCount = 1 => /\ ptePublished /\ tlbSynced)
    /\ (inodePublicationCount = 0 <=> inodeBytes = "Zeros")
    /\ (inodePublicationCount = 1 <=> inodeBytes = "HoleXY")
    /\ fsGuestCommitCount = commitCount["FsSyscall"]
    /\ fsGuestPublicationCount <= fsGuestCommitCount
    /\ (fsGuestCommitCount = 0 <=> fsGuestResult = "None")
    /\ (fsGuestCommitCount = 1 <=> fsGuestResult = "PwriteOK")
    /\ (fsGuestPublicationCount = 1 <=>
        effectState["FsSyscall"] = "Completed")

NetworkPublicationDiscipline ==
    /\ netPublicationCount = commitCount["NetOperation"]
    /\ netPublicationCount = commitCount["BufferLease"]
    /\ socketGeneration = netPublicationCount
    /\ bufferConsumptionCount + bufferClosureCount <= netPublicationCount
    /\ (netPublicationCount = 0 =>
        /\ netReceiptSocketGeneration = NoGeneration
        /\ netReceiptPayload = "None"
        /\ bufferPayload = "None"
        /\ bufferState = "Empty"
        /\ socketState \in {"Closed", "Listening", "Pending"})
    /\ (netPublicationCount = 1 =>
        /\ netReceiptSocketGeneration = 1
        /\ netReceiptPayload = "Ping4"
        /\ bufferPayload = "Ping4"
        /\ bufferState \in {"Queued", "Consumed"}
        /\ socketState \in {"Connected", "HalfClosed"})
    /\ (bufferState = "Queued" <=>
        effectState["BufferLease"] = "Committed")
    /\ (bufferState = "Consumed" <=>
        effectState["BufferLease"] = "Completed")
    /\ (sourceReady <=> bufferState = "Queued")
    /\ (socketState = "HalfClosed" <=>
        effectState["NetOperation"] = "Completed")

ReadinessPublicationDiscipline ==
    /\ readyPublicationCount = commitCount["ReadinessWait"]
    /\ sourceGeneration = readyPublicationCount
    /\ readyDeliveryCount <= readyPublicationCount
    /\ (readyPublicationCount = 0 =>
        /\ ~frozenReady
        /\ frozenSocketGeneration = NoGeneration
        /\ frozenSourceGeneration = NoGeneration
        /\ frozenPayload = "None")
    /\ (readyPublicationCount = 1 =>
        /\ frozenReady
        /\ frozenSocketGeneration = 1
        /\ frozenSourceGeneration = 1
        /\ frozenPayload = "Ping4"
        /\ netPublicationCount = 1)
    /\ (readyDeliveryCount = 1 <=>
        effectState["ReadinessWait"] = "Completed")

GuestPublicationDiscipline ==
    /\ netGuestCommitCount = commitCount["NetSyscall"]
    /\ netGuestPublicationCount <= netGuestCommitCount
    /\ (netGuestCommitCount = 0 <=> netGuestResult = "None")
    /\ (netGuestCommitCount = 1 <=> netGuestResult = "LoopbackOK")
    /\ (netGuestPublicationCount = 1 <=>
        effectState["NetSyscall"] = "Completed")
    /\ fsGuestPublicationCount <= fsGuestCommitCount

CrashIsolation ==
    /\ Cardinality({d \in Domains : bindingEpoch[d] = 1}) = crashCount
    /\ \A d \in Domains : adoptCount[d] <= 2 * bindingEpoch[d]
    /\ \A d \in Domains :
        domainPhase[d] \in {"Down", "Fallback", "Snapshotted", "Ready"}
            => /\ scopeState = "Active"
               /\ bindingEpoch[d] = 1
    /\ \A e \in adoptedEffects :
        /\ bindingEpoch[EffectDomain(e)] = 1
        /\ effectBinding[e] = 1

RecoveryDiscipline ==
    \A d \in Domains :
        /\ \A e \in recoveryCohort[d] :
            /\ EffectDomain(e) = d
            /\ effectState[e] \in UncommittedStates
            /\ effectBinding[e] # bindingEpoch[d]
        /\ (bindingEpoch[d] = 0 => recoveryCohort[d] = {})
        /\ (domainPhase[d] = "Ready" =>
            /\ snapshotBinding[d] = bindingEpoch[d]
            /\ snapshotCohort[d] = recoveryCohort[d]
            /\ snapshotAddressSpaceGeneration[d] = addressSpaceGeneration
            /\ snapshotInodeGeneration[d] = inodeGeneration
            /\ snapshotDeviceGeneration[d] = deviceGeneration
            /\ snapshotSocketGeneration[d] = socketGeneration
            /\ snapshotSourceGeneration[d] = sourceGeneration)

FrozenClosureCohort ==
    scopeState \in {"Closing", "Revoked"} =>
        /\ effectsAtClose = {e \in Effects : effectState[e] # "Unused"}
        /\ closingEffects \subseteq effectsAtClose
        /\ closingDomains =
            {d \in Domains : \E e \in effectsAtClose : EffectDomain(e) = d}
        /\ committedAtClose \subseteq closingEffects
        /\ \A d \in Domains \ closingDomains :
            domainReceipt[d] = "NotRequired"

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} => commitCount = commitAtClose

NoPostRevokeDerivation ==
    scopeState \in {"Closing", "Revoked"} =>
        effectsAtClose = {e \in Effects : effectState[e] # "Unused"}

IssuedReceiptSequences ==
    {closedReceiptSequence[d] :
        d \in {candidate \in Domains :
            closedReceiptSequence[candidate] # 0}}
    \cup {timeoutReceiptSequence[k] : k \in timeoutKinds}

ExactClosureReceipts ==
    /\ \A d \in Domains :
        /\ (domainReceipt[d] = "Closed" =>
            /\ d \in closingDomains
            /\ DomainClosingTerminal(d, effectsAtClose, effectState)
            /\ receiptCount[d] = 1
            /\ closedReceiptSequence[d] = receiptSequence[d]
            /\ receiptSequence[d] # 0
            /\ receiptRevision[d] = domainRevision[d]
            /\ receiptClosingEpoch[d] = closingEpoch
            /\ receiptBindingEpoch[d] = bindingEpoch[d]
            /\ receiptDeviceGeneration[d] =
                IF d = "VirtIo" THEN deviceGeneration ELSE NoGeneration)
        /\ (receiptCount[d] = 1 <=> domainReceipt[d] = "Closed")
        /\ (closedReceiptSequence[d] # 0 <=> domainReceipt[d] = "Closed")
        /\ (domainReceipt[d] \in {"Open", "NotRequired"} =>
            /\ receiptSequence[d] = 0
            /\ receiptClosingEpoch[d] = NoGeneration
            /\ receiptBindingEpoch[d] = NoBinding
            /\ receiptDeviceGeneration[d] = NoGeneration)
    /\ \A k \in TimeoutTargets :
        /\ (k \in timeoutKinds =>
            /\ timeoutReceiptSequence[k] # 0
            /\ timeoutReceiptSequence[k] < nextReceiptSequence)
        /\ (k \notin timeoutKinds =>
            /\ timeoutReceiptSequence[k] = 0
            /\ timeoutReceiptRevision[k] = 0
            /\ timeoutReceiptDeviceGeneration[k] = NoGeneration)
    /\ nextReceiptSequence =
        1 + Cardinality({d \in Domains : receiptCount[d] = 1})
          + Cardinality(timeoutKinds)
    /\ IssuedReceiptSequences = 1..(nextReceiptSequence - 1)
    /\ \A d1, d2 \in Domains :
        closedReceiptSequence[d1] # 0
            /\ closedReceiptSequence[d1] = closedReceiptSequence[d2]
        => d1 = d2
    /\ \A d \in Domains, k \in timeoutKinds :
        closedReceiptSequence[d] # timeoutReceiptSequence[k]
    /\ \A k1, k2 \in timeoutKinds :
        timeoutReceiptSequence[k1] = timeoutReceiptSequence[k2] => k1 = k2

TimeoutHonesty ==
    /\ retryKinds \subseteq timeoutKinds
    /\ (tombstoneKind # "None" =>
        /\ scopeState = "Closing"
        /\ effectState["BlockRequest"] = "Tombstoned"
        /\ freeCredits["Dma"] = 0
        /\ dmaState \in {"Mapped", "Invalidating"}
        /\ tombstoneKind \in timeoutKinds
        /\ tombstoneKind \notin retryKinds)
    /\ (tombstoneKind = "Reset" =>
        /\ tombstoneResume = "Committed"
        /\ blockOutcome = "None"
        /\ deviceGeneration = 0)
    /\ (tombstoneKind = "Iotlb" =>
        /\ tombstoneResume \in
            {"Cancelling", "DeviceCompleted", "ResetIndeterminate"}
        /\ blockOutcome # "None")
    /\ (tombstoneKind = "None" => tombstoneResume = "None")
    /\ (deviceGeneration = 1 => blockOutcome = "IndeterminateAfterReset")
    /\ \A kind \in retryKinds :
        timeoutReceiptRevision[kind] < domainRevision["VirtIo"]

SingleTerminalization ==
    \A e \in Effects : terminalCount[e] <= 1

QuiescentClosure ==
    scopeState = "Revoked" =>
        /\ \A e \in effectsAtClose : effectState[e] \in TerminalStates
        /\ \A d \in closingDomains : domainReceipt[d] = "Closed"
        /\ \A t \in CreditTypes : freeCredits[t] = CreditCapacity(t)
        /\ tombstoneKind = "None"
        /\ dmaState \in {"Absent", "Released"}
        /\ bufferState \in {"Empty", "Consumed"}
        /\ ~sourceReady

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
    [][\A e \in Effects : commitCount'[e] > commitCount[e] =>
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ effectAuthority[e] = authorityEpoch
        /\ domainPhase[EffectDomain(e)] = "Bound"
        /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
        /\ GenerationMatches(e, effectAddressSpaceGeneration,
            addressSpaceGeneration, effectInodeGeneration, inodeGeneration,
            effectDeviceGeneration, deviceGeneration,
            effectSocketGeneration, socketGeneration,
            effectSourceGeneration, sourceGeneration)]_vars

DomainBindingIsolation ==
    [][bindingEpoch' # bindingEpoch =>
        /\ Cardinality({d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d]}) = 1
        /\ \A d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d] =>
                bindingEpoch'[d] = bindingEpoch[d] + 1
        /\ UNCHANGED <<authorityEpoch, addressSpaceGeneration,
            inodeGeneration, deviceGeneration, socketGeneration,
            sourceGeneration>>]_vars

GenerationIsolation ==
    [][/\ (authorityEpoch' # authorityEpoch =>
            /\ scopeState = "Active" /\ scopeState' = "Closing"
            /\ authorityEpoch' = authorityEpoch + 1
            /\ UNCHANGED <<bindingEpoch, addressSpaceGeneration,
                inodeGeneration, deviceGeneration, socketGeneration,
                sourceGeneration>>)
        /\ (addressSpaceGeneration' # addressSpaceGeneration =>
            /\ mapPublicationCount' = mapPublicationCount + 1
            /\ UNCHANGED <<authorityEpoch, bindingEpoch, inodeGeneration,
                deviceGeneration, socketGeneration, sourceGeneration>>)
        /\ (inodeGeneration' # inodeGeneration =>
            /\ inodePublicationCount' = inodePublicationCount + 1
            /\ UNCHANGED <<authorityEpoch, bindingEpoch,
                addressSpaceGeneration, deviceGeneration, socketGeneration,
                sourceGeneration>>)
        /\ (deviceGeneration' # deviceGeneration =>
            /\ blockOutcome' = "IndeterminateAfterReset"
            /\ UNCHANGED <<authorityEpoch, bindingEpoch,
                addressSpaceGeneration, inodeGeneration, socketGeneration,
                sourceGeneration>>)
        /\ (socketGeneration' # socketGeneration =>
            /\ netPublicationCount' = netPublicationCount + 1
            /\ UNCHANGED <<authorityEpoch, bindingEpoch,
                addressSpaceGeneration, inodeGeneration, deviceGeneration,
                sourceGeneration>>)
        /\ (sourceGeneration' # sourceGeneration =>
            /\ readyPublicationCount' = readyPublicationCount + 1
            /\ UNCHANGED <<authorityEpoch, bindingEpoch,
                addressSpaceGeneration, inodeGeneration, deviceGeneration,
                socketGeneration>>)]_vars

TimeoutReceiptRevisionDiscipline ==
    [][domainRevision' # domainRevision =>
        /\ scopeState = "Closing"
        /\ tombstoneKind \in TimeoutTargets
        /\ Cardinality({d \in Domains :
            domainRevision'[d] # domainRevision[d]}) = 1
        /\ \A d \in Domains :
            domainRevision'[d] # domainRevision[d] =>
                /\ d = "VirtIo"
                /\ domainRevision'[d] = domainRevision[d] + 1]_vars

ExplicitAdoptionAction ==
    [][(\E changed \in Effects :
            /\ effectState[changed] # "Unused"
            /\ effectBinding'[changed] # effectBinding[changed]) =>
        \/ /\ bindingEpoch' # bindingEpoch
           /\ UNCHANGED effectBinding
        \/ /\ bindingEpoch' = bindingEpoch
           /\ Cardinality({e \in Effects :
                effectBinding'[e] # effectBinding[e]}) = 1
           /\ \A e \in Effects :
                effectBinding'[e] # effectBinding[e] =>
                    /\ effectState[e] \in UncommittedStates
                    /\ effectBinding'[e] = bindingEpoch[EffectDomain(e)]
                    /\ e \notin adoptedEffects
                    /\ e \in adoptedEffects']_vars

RejectSideEffectFreedom ==
    [][rejectKinds' # rejectKinds => UNCHANGED <<
        scopeState, scopeGate, authorityEpoch, closingEpoch,
        effectState, effectParent, effectAuthority, effectBinding,
        effectAddressSpaceGeneration, effectInodeGeneration,
        effectDeviceGeneration, effectSocketGeneration,
        effectSourceGeneration, commitCount, terminalCount, nextDeriveIndex,
        freeCredits, bindingEpoch, domainPhase, recoveryCohort,
        snapshotBinding, snapshotCohort, snapshotAddressSpaceGeneration,
        snapshotInodeGeneration, snapshotDeviceGeneration,
        snapshotSocketGeneration, snapshotSourceGeneration, adoptCount,
        adoptedEffects, crashCount, addressSpaceGeneration, ptePublished,
        tlbSynced, mapPublicationCount, inodeGeneration, inodeBytes,
        inodePublicationCount, deviceGeneration, dmaState, blockOutcome,
        blockPublicationCount, tombstoneKind, tombstoneResume, timeoutKinds,
        retryKinds, socketGeneration, socketState, sourceGeneration,
        sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration,
        netReceiptPayload, frozenReady, frozenSocketGeneration,
        frozenSourceGeneration, frozenPayload, netPublicationCount,
        readyPublicationCount, readyDeliveryCount, bufferConsumptionCount,
        bufferClosureCount, fsGuestCommitCount, fsGuestPublicationCount,
        fsGuestResult, netGuestCommitCount, netGuestPublicationCount,
        netGuestResult, effectsAtClose, closingEffects, closingDomains,
        committedAtClose, commitAtClose, domainReceipt, domainRevision,
        receiptCount, nextReceiptSequence, receiptSequence, receiptRevision,
        receiptClosingEpoch, receiptBindingEpoch, receiptDeviceGeneration,
        closedReceiptSequence, timeoutReceiptSequence,
        timeoutReceiptRevision, timeoutReceiptDeviceGeneration, receiptCursor
    >>]_vars

PublicationReceiptImmutability ==
    [][/\ (netPublicationCount = 1 => UNCHANGED <<
            netReceiptSocketGeneration, netReceiptPayload, bufferPayload>>)
        /\ (readyPublicationCount = 1 => UNCHANGED <<
            frozenReady, frozenSocketGeneration,
            frozenSourceGeneration, frozenPayload>>)
        /\ (fsGuestCommitCount = 1 => UNCHANGED fsGuestResult)
        /\ (netGuestCommitCount = 1 => UNCHANGED netGuestResult)]_vars

GlobalReceiptSequenceDiscipline ==
    [][/\ nextReceiptSequence' >= nextReceiptSequence
        /\ nextReceiptSequence' <= nextReceiptSequence + 1
        /\ (nextReceiptSequence' = nextReceiptSequence + 1 =>
            /\ scopeState = "Closing"
            /\ Cardinality({d \in Domains :
                    closedReceiptSequence[d] = 0
                    /\ closedReceiptSequence'[d] = nextReceiptSequence})
                + Cardinality({k \in TimeoutTargets :
                    timeoutReceiptSequence[k] = 0
                    /\ timeoutReceiptSequence'[k] = nextReceiptSequence}) = 1)]_vars

ConditionalFallbackProgress ==
    \A d \in CrashTargets :
        [](domainPhase[d] = "Down" ~> domainPhase[d] # "Down")

ReadyForKernelClosure ==
    /\ scopeState = "Closing"
    /\ ("BlockRequest" \notin effectsAtClose \/
        effectState["BlockRequest"] \in TerminalStates)
    /\ tombstoneKind = "None"
    /\ dmaState \in {"Absent", "Released"}

ConditionalKernelClosureProgress ==
    [](ReadyForKernelClosure ~> scopeState = "Revoked")

SevenDomainLinuxIoClosureObserved ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ closingDomains = Domains
    /\ \A e \in Effects : effectState[e] = "Completed"
    /\ mapPublicationCount = 1
    /\ inodePublicationCount = 1
    /\ blockPublicationCount = 1
    /\ netPublicationCount = 1
    /\ readyPublicationCount = 1
    /\ readyDeliveryCount = 1
    /\ fsGuestPublicationCount = 1
    /\ netGuestPublicationCount = 1
    /\ \A d \in Domains : domainReceipt[d] = "Closed"
    /\ Cardinality({closedReceiptSequence[d] : d \in Domains}) =
        Cardinality(Domains)
    /\ \A t \in CreditTypes : freeCredits[t] = CreditCapacity(t)

RevokeBeforeIoPublicationObserved ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ inodePublicationCount = 0
    /\ blockPublicationCount = 0
    /\ netPublicationCount = 0
    /\ readyPublicationCount = 0
    /\ fsGuestPublicationCount = 0
    /\ netGuestPublicationCount = 0
    /\ inodeGeneration = 0
    /\ socketGeneration = 0
    /\ sourceGeneration = 0

FsVisibleNetSuppressedObserved ==
    /\ scopeState = "Revoked"
    /\ inodePublicationCount = 1
    /\ inodeBytes = "HoleXY"
    /\ netPublicationCount = 0
    /\ readyPublicationCount = 0
    /\ netGuestPublicationCount = 0
    /\ effectState["NetOperation"] = "Aborted"

NetVisibleFsSuppressedObserved ==
    /\ scopeState = "Revoked"
    /\ netPublicationCount = 1
    /\ bufferClosureCount = 1
    /\ bufferConsumptionCount = 0
    /\ inodePublicationCount = 0
    /\ fsGuestPublicationCount = 0
    /\ effectState["FsOperation"] = "Aborted"

FilesystemCrashAdoptIsolationObserved ==
    /\ scopeState = "Active"
    /\ bindingEpoch["Filesystem"] = 1
    /\ \A d \in Domains \ {"Filesystem"} : bindingEpoch[d] = 0
    /\ adoptCount["Filesystem"] = 1
    /\ effectBinding["FsOperation"] = 1
    /\ recoveryCohort["Filesystem"] = {}
    /\ inodePublicationCount = 1

NetworkCrashAdoptIsolationObserved ==
    /\ scopeState = "Active"
    /\ bindingEpoch["Network"] = 1
    /\ \A d \in Domains \ {"Network"} : bindingEpoch[d] = 0
    /\ adoptCount["Network"] = 2
    /\ {"NetOperation", "BufferLease"} \subseteq adoptedEffects
    /\ effectBinding["NetOperation"] = 1
    /\ effectBinding["BufferLease"] = 1
    /\ netPublicationCount = 1

ReadinessBeforeRevokeObserved ==
    /\ scopeState = "Revoked"
    /\ commitAtClose["ReadinessWait"] = 1
    /\ readyPublicationCount = 1
    /\ readyDeliveryCount = 1
    /\ netGuestCommitCount = 0
    /\ netGuestPublicationCount = 0
    /\ bufferClosureCount = 1
    /\ bufferConsumptionCount = 0

RevokeBeforeReadinessObserved ==
    /\ scopeState = "Revoked"
    /\ commitAtClose["NetOperation"] = 1
    /\ commitAtClose["ReadinessWait"] = 0
    /\ netPublicationCount = 1
    /\ readyPublicationCount = 0
    /\ readyDeliveryCount = 0
    /\ netGuestPublicationCount = 0
    /\ effectState["ReadinessWait"] = "Aborted"
    /\ bufferClosureCount = 1

VirtIoResetIotlbTombstoneClosureObserved ==
    /\ scopeState = "Revoked"
    /\ timeoutKinds = TimeoutTargets
    /\ retryKinds = TimeoutTargets
    /\ deviceGeneration = 1
    /\ blockOutcome = "IndeterminateAfterReset"
    /\ effectState["BlockRequest"] = "Completed"
    /\ dmaState = "Released"
    /\ timeoutReceiptSequence["Reset"] # 0
    /\ timeoutReceiptSequence["Iotlb"] >
        timeoutReceiptSequence["Reset"]
    /\ closedReceiptSequence["VirtIo"] >
        timeoutReceiptSequence["Iotlb"]

StaleEnvelopeAndReceiptFencesObserved == rejectKinds = RejectKinds

SevenDomainLinuxIoClosureAbsent == ~SevenDomainLinuxIoClosureObserved
RevokeBeforeIoPublicationAbsent == ~RevokeBeforeIoPublicationObserved
FsVisibleNetSuppressedAbsent == ~FsVisibleNetSuppressedObserved
NetVisibleFsSuppressedAbsent == ~NetVisibleFsSuppressedObserved
FilesystemCrashAdoptIsolationAbsent == ~FilesystemCrashAdoptIsolationObserved
NetworkCrashAdoptIsolationAbsent == ~NetworkCrashAdoptIsolationObserved
ReadinessBeforeRevokeAbsent == ~ReadinessBeforeRevokeObserved
RevokeBeforeReadinessAbsent == ~RevokeBeforeReadinessObserved
VirtIoResetIotlbTombstoneClosureAbsent ==
    ~VirtIoResetIotlbTombstoneClosureObserved
StaleEnvelopeAndReceiptFencesAbsent ==
    ~StaleEnvelopeAndReceiptFencesObserved

=============================================================================

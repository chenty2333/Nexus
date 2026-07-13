---------------- MODULE ProductionIdentityCser ----------------
EXTENDS FiniteSets, Integers, Sequences, TLC

(***************************************************************************)
(* Prospective RFC-0001 successor for identity-preserving production-path   *)
(* composition.  One workload dynamically instantiates this fixed tree:    *)
(*                                                                         *)
(* Root                                                                    *)
(* `-- PersonalitySyscall                                                  *)
(*     `-- FilesystemRead                                                   *)
(*         `-- BlockRequest                                                 *)
(*             |-- DmaQueueOwnerA                                           *)
(*             |-- DmaQueueOwnerB                                           *)
(*             `-- DmaRequestOwner                                          *)
(*                                                                         *)
(* The model has one registry-native binding table and one typed root       *)
(* ledger.  CpuCount and actor fields state bounded 2/4-CPU obligations;    *)
(* they do not model OSTD locks, interrupts, or a hardware memory model.     *)
(* The PlusCal algorithm is the sole source of Init and Next.               *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableCrash, EnableTimeout, EnableRejects, CpuCount

ASSUME /\ MaxBinding = 1
       /\ EnableCrash \in BOOLEAN
       /\ EnableTimeout \in BOOLEAN
       /\ EnableRejects \in BOOLEAN
       /\ CpuCount \in {2, 4}

Domains == {"Personality", "Filesystem", "VirtIo"}
Effects == {"PersonalitySyscall", "FilesystemRead", "BlockRequest",
             "DmaQueueOwnerA", "DmaQueueOwnerB", "DmaRequestOwner"}
DmaEffects == {"DmaQueueOwnerA", "DmaQueueOwnerB", "DmaRequestOwner"}
DeviceEffects == {"BlockRequest"} \cup DmaEffects
CreditTypes == {"Control", "FilesystemCredit", "QueueSlot", "DmaOwner"}
TimeoutTargets == {"Reset", "Iotlb"}
RejectKinds == {"ForeignRegistry", "StaleDeviceGeneration"}
ScenarioModes == {"Normal", "CrashRecovery", "CommitRevokeRace",
                   "DeviceTimeout", "RejectProbe", "ActorRace"}

Root == "Root"
RegistryA == "RegistryA"
RegistryB == "RegistryB"
SessionA == "SessionA"
NoParent == "NoParent"
NoRegistry == "NoRegistry"
NoSession == "NoSession"
NoEffect == "NoEffect"
NoGeneration == -1
NoBinding == -1
NoCpu == -1

DeriveOrder == <<"PersonalitySyscall", "FilesystemRead", "BlockRequest",
                 "DmaQueueOwnerA", "DmaQueueOwnerB", "DmaRequestOwner">>

CpuIds == 0..(CpuCount - 1)
ServiceCpu == 0
KernelCpu == 1
IrqCpu == CpuCount - 1

ServiceEvents == {"Derive", "Prepare", "Ready", "Adopt", "DeviceCommit"}
KernelEvents == {"Crash", "Snapshot", "Rebind", "RevokeBegin",
                 "ResetTimeout", "ResetRetry", "IotlbTimeout",
                 "IotlbRetry", "CompleteDma", "CompleteBlock",
                 "CompleteFilesystem", "GuestReply", "AbortLeaf",
                 "DomainReceipt", "RevokeComplete", "RejectForeign"}
IrqEvents == {"DeviceComplete", "ResetAck", "IotlbAck",
              "RejectStaleGeneration"}
AllEvents == {"Init"} \cup ServiceEvents \cup KernelEvents \cup IrqEvents
ActorKinds == {"None", "Service", "Kernel", "Irq"}

EffectDomain(e) ==
    CASE e = "PersonalitySyscall" -> "Personality"
      [] e = "FilesystemRead" -> "Filesystem"
      [] e \in DeviceEffects -> "VirtIo"

EffectCredit(e) ==
    CASE e = "PersonalitySyscall" -> "Control"
      [] e = "FilesystemRead" -> "FilesystemCredit"
      [] e = "BlockRequest" -> "QueueSlot"
      [] e \in DmaEffects -> "DmaOwner"

CreditCapacity(t) == IF t = "DmaOwner" THEN 3 ELSE 1

AllowedParent(e) ==
    CASE e = "PersonalitySyscall" -> Root
      [] e = "FilesystemRead" -> "PersonalitySyscall"
      [] e = "BlockRequest" -> "FilesystemRead"
      [] e \in DmaEffects -> "BlockRequest"

DomainParent(d) ==
    CASE d = "Personality" -> "NoDomain"
      [] d = "Filesystem" -> "Personality"
      [] d = "VirtIo" -> "Filesystem"

LiveStates == {"Registered", "Prepared", "Committed"}
TerminalStates == {"Completed", "Aborted"}
UncommittedStates == {"Registered", "Prepared"}
CreditLiveStates == {"Held", "Committed", "Retained"}

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

DomainTerminal(d, effectsAtClose, effectState) ==
    \A e \in effectsAtClose :
        EffectDomain(e) = d => effectState[e] \in TerminalStates

ChildDomainReceiptsClosed(d, domainReceipt) ==
    \A child \in Domains :
        DomainParent(child) = d => domainReceipt[child] = "Closed"

AllDerived(nextDeriveIndex) == nextDeriveIndex = Len(DeriveOrder) + 1
AllPrepared(nextPrepareIndex) == nextPrepareIndex = Len(DeriveOrder) + 1

(* --algorithm ProductionIdentityCSER
variables
    scenarioMode \in ScenarioModes,

    scopeState = "Active",
    scopeGate = "Open",
    authorityEpoch = 0,
    closingEpoch = NoGeneration,

    effectState = [e \in Effects |-> "Unused"],
    effectParent = [e \in Effects |-> NoParent],
    effectRegistry = [e \in Effects |-> NoRegistry],
    effectGeneration = [e \in Effects |-> 0],
    effectAuthority = [e \in Effects |-> NoGeneration],
    effectOriginBinding = [e \in Effects |-> NoBinding],
    effectBinding = [e \in Effects |-> NoBinding],
    effectDeviceGeneration = [e \in Effects |-> NoGeneration],
    effectDeviceSession = [e \in Effects |-> NoSession],
    createdByWorkload = [e \in Effects |-> FALSE],
    creditState = [e \in Effects |-> "None"],
    commitCount = [e \in Effects |-> 0],
    terminalCount = [e \in Effects |-> 0],
    terminalSequence = [e \in Effects |-> 0],
    nextTerminalSequence = 1,
    nextDeriveIndex = 1,
    nextPrepareIndex = 1,

    freeCredits = [t \in CreditTypes |-> CreditCapacity(t)],

    bindingEpoch = [d \in Domains |-> 0],
    domainPhase = [d \in Domains |-> "Bound"],
    recoveryCohort = [d \in Domains |-> {}],
    snapshotBinding = [d \in Domains |-> NoBinding],
    snapshotCohort = [d \in Domains |-> {}],
    adoptCount = [d \in Domains |-> 0],
    crashCount = 0,

    deviceSession = SessionA,
    deviceGeneration = 0,
    commitDeviceGeneration = NoGeneration,
    devicePublished = FALSE,
    deviceOutcome = "None",
    dmaPhase = "Absent",
    resetPhase = "None",
    tombstoneKind = "None",
    tombstoneEffect = NoEffect,
    timeoutKinds = {},
    retryKinds = {},
    backendDataVisible = FALSE,

    guestReplyCount = 0,
    guestReplyResult = "None",

    effectsAtClose = {},
    closingEffects = {},
    committedAtClose = {},
    commitAtClose = [e \in Effects |-> 0],
    closureTargetCount = 0,
    closureSteps = 0,
    closingDomains = {},
    domainReceipt = [d \in Domains |-> "Open"],
    receiptSequence = [d \in Domains |-> 0],
    receiptBindingEpoch = [d \in Domains |-> NoBinding],
    receiptDeviceGeneration = [d \in Domains |-> NoGeneration],
    nextReceiptSequence = 1,

    rejectKinds = {},
    presentedRegistry = NoRegistry,
    presentedDeviceGeneration = NoGeneration,

    lastEvent = "Init",
    lastActorKind = "None",
    lastActorCpu = NoCpu,
    commitCpu = NoCpu,
    revokeCpu = NoCpu,
    completionCpu = NoCpu,
    irqCount = 0;

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* Workload derivation is ordered only to keep the finite graph
            \* tractable.  Each effect is still absent until this transition.
            with e = DeriveOrder[nextDeriveIndex] do
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ nextDeriveIndex <= Len(DeriveOrder)
                      /\ effectState[e] = "Unused"
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ ParentCanDerive(e, effectState, effectBinding,
                            bindingEpoch, domainPhase)
                      /\ freeCredits[EffectCredit(e)] > 0;
                effectState[e] := "Registered";
                effectParent[e] := AllowedParent(e);
                effectRegistry[e] := RegistryA;
                effectGeneration[e] := 1;
                effectAuthority[e] := authorityEpoch;
                effectOriginBinding[e] := bindingEpoch[EffectDomain(e)];
                effectBinding[e] := bindingEpoch[EffectDomain(e)];
                createdByWorkload[e] := TRUE;
                creditState[e] := "Held";
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] - 1;
                if e \in DeviceEffects then
                    effectDeviceGeneration[e] := deviceGeneration;
                    effectDeviceSession[e] := deviceSession;
                end if;
                nextDeriveIndex := nextDeriveIndex + 1;
                lastEvent := "Derive";
                lastActorKind := "Service";
                lastActorCpu := ServiceCpu;
            end with;
        or
            with e = DeriveOrder[nextPrepareIndex] do
                await /\ AllDerived(nextDeriveIndex)
                      /\ nextPrepareIndex <= Len(DeriveOrder)
                      /\ effectState[e] = "Registered"
                      /\ effectAuthority[e] = authorityEpoch
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                      /\ (scenarioMode # "CrashRecovery"
                            \/ crashCount = 1
                            \/ nextPrepareIndex <= 2);
                effectState[e] := "Prepared";
                nextPrepareIndex := nextPrepareIndex + 1;
                lastEvent := "Prepare";
                lastActorKind := "Service";
                lastActorCpu := ServiceCpu;
            end with;
        or
            \* The crash point is after FilesystemRead is prepared and before
            \* BlockRequest preparation.  Only the Filesystem binding moves.
            await /\ EnableCrash
                  /\ scenarioMode = "CrashRecovery"
                  /\ scopeState = "Active"
                  /\ crashCount = 0
                  /\ nextPrepareIndex = 3
                  /\ effectState["FilesystemRead"] = "Prepared"
                  /\ domainPhase["Filesystem"] = "Bound"
                  /\ bindingEpoch["Filesystem"] < MaxBinding;
            bindingEpoch["Filesystem"] :=
                bindingEpoch["Filesystem"] + 1;
            domainPhase["Filesystem"] := "Down";
            recoveryCohort["Filesystem"] := {"FilesystemRead"};
            snapshotBinding["Filesystem"] := NoBinding;
            snapshotCohort["Filesystem"] := {};
            crashCount := crashCount + 1;
            lastEvent := "Crash";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ scopeState = "Active"
                  /\ domainPhase["Filesystem"] = "Down";
            snapshotBinding["Filesystem"] := bindingEpoch["Filesystem"];
            snapshotCohort["Filesystem"] := recoveryCohort["Filesystem"];
            domainPhase["Filesystem"] := "Snapshotted";
            lastEvent := "Snapshot";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ scopeState = "Active"
                  /\ domainPhase["Filesystem"] = "Snapshotted"
                  /\ snapshotBinding["Filesystem"] =
                        bindingEpoch["Filesystem"]
                  /\ snapshotCohort["Filesystem"] =
                        recoveryCohort["Filesystem"];
            domainPhase["Filesystem"] := "Ready";
            lastEvent := "Ready";
            lastActorKind := "Service";
            lastActorCpu := ServiceCpu;
        or
            await /\ scopeState = "Active"
                  /\ domainPhase["Filesystem"] = "Ready";
            domainPhase["Filesystem"] := "Bound";
            lastEvent := "Rebind";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ scopeState = "Active"
                  /\ domainPhase["Filesystem"] = "Bound"
                  /\ "FilesystemRead" \in recoveryCohort["Filesystem"]
                  /\ effectState["FilesystemRead"] \in UncommittedStates
                  /\ effectBinding["FilesystemRead"] #
                        bindingEpoch["Filesystem"];
            effectBinding["FilesystemRead"] := bindingEpoch["Filesystem"];
            recoveryCohort["Filesystem"] := {};
            adoptCount["Filesystem"] := adoptCount["Filesystem"] + 1;
            lastEvent := "Adopt";
            lastActorKind := "Service";
            lastActorCpu := ServiceCpu;
        or
            \* avail.idx Release is the one bounded batch commit.  Parent
            \* obligations and the three DMA owners share the root gate.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ AllPrepared(nextPrepareIndex)
                  /\ ~devicePublished
                  /\ \A e \in Effects :
                        /\ effectState[e] = "Prepared"
                        /\ effectAuthority[e] = authorityEpoch
                        /\ effectBinding[e] =
                            bindingEpoch[EffectDomain(e)]
                        /\ domainPhase[EffectDomain(e)] = "Bound"
                  /\ \A e \in DeviceEffects :
                        /\ effectDeviceGeneration[e] = deviceGeneration
                        /\ effectDeviceSession[e] = deviceSession;
            effectState := [e \in Effects |-> "Committed"];
            creditState := [e \in Effects |-> "Committed"];
            commitCount := [e \in Effects |-> 1];
            devicePublished := TRUE;
            commitDeviceGeneration := deviceGeneration;
            dmaPhase := "Mapped";
            commitCpu := ServiceCpu;
            lastEvent := "DeviceCommit";
            lastActorKind := "Service";
            lastActorCpu := ServiceCpu;
        or
            \* The abstract IRQ actor validates the current device envelope.
            \* This is not a model of a real interrupt controller or SpinLock.
            await /\ devicePublished
                  /\ deviceOutcome = "None"
                  /\ dmaPhase = "Mapped"
                  /\ resetPhase = "None"
                  /\ scenarioMode \in
                        {"Normal", "CrashRecovery", "CommitRevokeRace",
                         "ActorRace"}
                  /\ effectDeviceGeneration["BlockRequest"] =
                        deviceGeneration;
            deviceOutcome := "Data";
            backendDataVisible := TRUE;
            dmaPhase := "IotlbPending";
            completionCpu := IrqCpu;
            irqCount := irqCount + 1;
            lastEvent := "DeviceComplete";
            lastActorKind := "Irq";
            lastActorCpu := IrqCpu;
        or
            \* A reset deadline never authorizes release.  The same committed
            \* effects and credits remain visible through the tombstone.
            await /\ EnableTimeout
                  /\ scopeState = "Closing"
                  /\ devicePublished
                  /\ deviceOutcome = "None"
                  /\ dmaPhase = "Mapped"
                  /\ resetPhase = "None"
                  /\ scenarioMode \in
                        {"DeviceTimeout", "RejectProbe", "ActorRace"};
            resetPhase := "TimedOut";
            tombstoneKind := "Reset";
            tombstoneEffect := "BlockRequest";
            timeoutKinds := timeoutKinds \cup {"Reset"};
            creditState := [e \in Effects |->
                IF e \in DeviceEffects THEN "Retained" ELSE creditState[e]];
            lastEvent := "ResetTimeout";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ resetPhase = "TimedOut"
                  /\ tombstoneKind = "Reset"
                  /\ "Reset" \notin retryKinds;
            resetPhase := "Retrying";
            retryKinds := retryKinds \cup {"Reset"};
            lastEvent := "ResetRetry";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            \* Reset acknowledgement advances only the device generation.  The
            \* root and effect identities remain unchanged.
            await /\ resetPhase = "Retrying"
                  /\ deviceOutcome = "None"
                  /\ tombstoneKind = "Reset";
            resetPhase := "Acknowledged";
            deviceGeneration := deviceGeneration + 1;
            effectDeviceGeneration := [e \in Effects |->
                IF e \in DeviceEffects
                THEN deviceGeneration
                ELSE effectDeviceGeneration[e]];
            deviceOutcome := "Eio";
            dmaPhase := "IotlbPending";
            tombstoneKind := "None";
            tombstoneEffect := NoEffect;
            completionCpu := IrqCpu;
            irqCount := irqCount + 1;
            lastEvent := "ResetAck";
            lastActorKind := "Irq";
            lastActorCpu := IrqCpu;
        or
            await /\ EnableTimeout
                  /\ scopeState = "Closing"
                  /\ dmaPhase = "IotlbPending"
                  /\ deviceOutcome \in {"Data", "Eio"}
                  /\ "Iotlb" \notin timeoutKinds
                  /\ scenarioMode \in {"DeviceTimeout", "RejectProbe"};
            dmaPhase := "IotlbTimedOut";
            tombstoneKind := "Iotlb";
            tombstoneEffect := "BlockRequest";
            timeoutKinds := timeoutKinds \cup {"Iotlb"};
            creditState := [e \in Effects |->
                IF e \in DeviceEffects THEN "Retained" ELSE creditState[e]];
            lastEvent := "IotlbTimeout";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ dmaPhase = "IotlbTimedOut"
                  /\ tombstoneKind = "Iotlb"
                  /\ "Iotlb" \notin retryKinds;
            dmaPhase := "IotlbPending";
            retryKinds := retryKinds \cup {"Iotlb"};
            lastEvent := "IotlbRetry";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ dmaPhase = "IotlbPending"
                  /\ deviceOutcome \in {"Data", "Eio"}
                  /\ (scenarioMode \notin {"DeviceTimeout", "RejectProbe"}
                        \/ "Iotlb" \in retryKinds);
            dmaPhase := "Released";
            tombstoneKind := "None";
            tombstoneEffect := NoEffect;
            irqCount := irqCount + 1;
            lastEvent := "IotlbAck";
            lastActorKind := "Irq";
            lastActorCpu := IrqCpu;
        or
            \* Presenting RegistryB cannot mutate RegistryA's semantic state.
            await /\ EnableRejects
                  /\ scenarioMode = "RejectProbe"
                  /\ devicePublished
                  /\ "ForeignRegistry" \notin rejectKinds;
            rejectKinds := rejectKinds \cup {"ForeignRegistry"};
            presentedRegistry := RegistryB;
            lastEvent := "RejectForeign";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            \* The original generation-zero completion is stale after the same
            \* effect advances to generation one through reset acknowledgement.
            await /\ EnableRejects
                  /\ scenarioMode = "RejectProbe"
                  /\ deviceGeneration = 1
                  /\ commitDeviceGeneration = 0
                  /\ "StaleDeviceGeneration" \notin rejectKinds;
            rejectKinds := rejectKinds \cup {"StaleDeviceGeneration"};
            presentedDeviceGeneration := commitDeviceGeneration;
            lastEvent := "RejectStaleGeneration";
            lastActorKind := "Irq";
            lastActorCpu := IrqCpu;
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            \* In CommitRevokeRace this action and DeviceCommit are enabled
            \* together after preparation.  The shared gate chooses one winner.
            await /\ scopeState = "Active"
                  /\ AllPrepared(nextPrepareIndex)
                  /\ (scenarioMode = "CommitRevokeRace" \/ devicePublished);
            effectsAtClose :=
                {e \in Effects : effectState[e] # "Unused"};
            closingEffects :=
                {e \in Effects : effectState[e] \in
                    (LiveStates \cup UncommittedStates)};
            committedAtClose :=
                {e \in Effects : commitCount[e] = 1
                    /\ effectState[e] \in LiveStates};
            commitAtClose := commitCount;
            closureTargetCount := Cardinality(
                {e \in Effects : effectState[e] \in
                    (LiveStates \cup UncommittedStates)});
            closureSteps := 0;
            closingDomains := Domains;
            domainReceipt := [d \in Domains |-> "Pending"];
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeGate := "Closed";
            scopeState := "Closing";
            domainPhase := [d \in Domains |-> "Closed"];
            recoveryCohort := [d \in Domains |-> {}];
            revokeCpu := KernelCpu;
            lastEvent := "RevokeBegin";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            with e \in DmaEffects do
                await /\ effectState[e] = "Committed"
                      /\ dmaPhase = "Released"
                      /\ deviceOutcome \in {"Data", "Eio"}
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Completed";
                creditState[e] := "Returned";
                terminalCount[e] := terminalCount[e] + 1;
                terminalSequence[e] := nextTerminalSequence;
                nextTerminalSequence := nextTerminalSequence + 1;
                freeCredits["DmaOwner"] := freeCredits["DmaOwner"] + 1;
                if e \in closingEffects then
                    closureSteps := closureSteps + 1;
                end if;
                lastEvent := "CompleteDma";
                lastActorKind := "Kernel";
                lastActorCpu := KernelCpu;
            end with;
        or
            await /\ effectState["BlockRequest"] = "Committed"
                  /\ deviceOutcome \in {"Data", "Eio"}
                  /\ dmaPhase = "Released"
                  /\ ChildrenTerminal("BlockRequest", effectState,
                        effectParent);
            effectState["BlockRequest"] := "Completed";
            creditState["BlockRequest"] := "Returned";
            terminalCount["BlockRequest"] :=
                terminalCount["BlockRequest"] + 1;
            terminalSequence["BlockRequest"] := nextTerminalSequence;
            nextTerminalSequence := nextTerminalSequence + 1;
            freeCredits["QueueSlot"] := freeCredits["QueueSlot"] + 1;
            if "BlockRequest" \in closingEffects then
                closureSteps := closureSteps + 1;
            end if;
            lastEvent := "CompleteBlock";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            await /\ effectState["FilesystemRead"] = "Committed"
                  /\ effectState["BlockRequest"] = "Completed"
                  /\ ChildrenTerminal("FilesystemRead", effectState,
                        effectParent);
            effectState["FilesystemRead"] := "Completed";
            creditState["FilesystemRead"] := "Returned";
            terminalCount["FilesystemRead"] :=
                terminalCount["FilesystemRead"] + 1;
            terminalSequence["FilesystemRead"] := nextTerminalSequence;
            nextTerminalSequence := nextTerminalSequence + 1;
            freeCredits["FilesystemCredit"] :=
                freeCredits["FilesystemCredit"] + 1;
            if "FilesystemRead" \in closingEffects then
                closureSteps := closureSteps + 1;
            end if;
            lastEvent := "CompleteFilesystem";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            \* Guest reply is distinct from device commit and backend result.
            await /\ effectState["PersonalitySyscall"] = "Committed"
                  /\ effectState["FilesystemRead"] = "Completed"
                  /\ guestReplyCount = 0
                  /\ deviceOutcome \in {"Data", "Eio"};
            effectState["PersonalitySyscall"] := "Completed";
            creditState["PersonalitySyscall"] := "Returned";
            terminalCount["PersonalitySyscall"] :=
                terminalCount["PersonalitySyscall"] + 1;
            terminalSequence["PersonalitySyscall"] := nextTerminalSequence;
            nextTerminalSequence := nextTerminalSequence + 1;
            freeCredits["Control"] := freeCredits["Control"] + 1;
            guestReplyCount := guestReplyCount + 1;
            if deviceOutcome = "Data" then
                guestReplyResult := "Data";
            else
                guestReplyResult := "Eio";
            end if;
            if "PersonalitySyscall" \in closingEffects then
                closureSteps := closureSteps + 1;
            end if;
            lastEvent := "GuestReply";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        or
            \* Uncommitted closure is leaf-first.  It never fabricates a guest
            \* reply or a device completion.
            with e \in Effects do
                await /\ scopeState = "Closing"
                      /\ e \in closingEffects
                      /\ effectState[e] \in UncommittedStates
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Aborted";
                creditState[e] := "Returned";
                terminalCount[e] := terminalCount[e] + 1;
                terminalSequence[e] := nextTerminalSequence;
                nextTerminalSequence := nextTerminalSequence + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
                closureSteps := closureSteps + 1;
                lastEvent := "AbortLeaf";
                lastActorKind := "Kernel";
                lastActorCpu := KernelCpu;
            end with;
        or
            with d \in Domains do
                await /\ scopeState = "Closing"
                      /\ d \in closingDomains
                      /\ domainReceipt[d] = "Pending"
                      /\ DomainTerminal(d, effectsAtClose, effectState)
                      /\ ChildDomainReceiptsClosed(d, domainReceipt);
                domainReceipt[d] := "Closed";
                receiptSequence[d] := nextReceiptSequence;
                receiptBindingEpoch[d] := bindingEpoch[d];
                if d = "VirtIo" then
                    receiptDeviceGeneration[d] := deviceGeneration;
                end if;
                nextReceiptSequence := nextReceiptSequence + 1;
                lastEvent := "DomainReceipt";
                lastActorKind := "Kernel";
                lastActorCpu := KernelCpu;
            end with;
        or
            await /\ scopeState = "Closing"
                  /\ closureSteps = closureTargetCount
                  /\ \A e \in effectsAtClose :
                        effectState[e] \in TerminalStates
                  /\ \A d \in closingDomains :
                        domainReceipt[d] = "Closed"
                  /\ \A t \in CreditTypes :
                        freeCredits[t] = CreditCapacity(t)
                  /\ tombstoneKind = "None"
                  /\ dmaPhase \in {"Absent", "Released"}
                  /\ (~devicePublished \/ guestReplyCount = 1);
            scopeState := "Revoked";
            lastEvent := "RevokeComplete";
            lastActorKind := "Kernel";
            lastActorCpu := KernelCpu;
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "b972eaf" /\ chksum(tla) = "89252716")
VARIABLES scenarioMode, scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, terminalCount, terminalSequence, nextTerminalSequence, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceSession, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closureSteps, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, rejectKinds, presentedRegistry, presentedDeviceGeneration, lastEvent, lastActorKind, lastActorCpu, commitCpu, revokeCpu, completionCpu, irqCount

vars == << scenarioMode, scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, terminalCount, terminalSequence, nextTerminalSequence, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceSession, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closureSteps, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, rejectKinds, presentedRegistry, presentedDeviceGeneration, lastEvent, lastActorKind, lastActorCpu, commitCpu, revokeCpu, completionCpu, irqCount >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scenarioMode \in ScenarioModes
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectState = [e \in Effects |-> "Unused"]
        /\ effectParent = [e \in Effects |-> NoParent]
        /\ effectRegistry = [e \in Effects |-> NoRegistry]
        /\ effectGeneration = [e \in Effects |-> 0]
        /\ effectAuthority = [e \in Effects |-> NoGeneration]
        /\ effectOriginBinding = [e \in Effects |-> NoBinding]
        /\ effectBinding = [e \in Effects |-> NoBinding]
        /\ effectDeviceGeneration = [e \in Effects |-> NoGeneration]
        /\ effectDeviceSession = [e \in Effects |-> NoSession]
        /\ createdByWorkload = [e \in Effects |-> FALSE]
        /\ creditState = [e \in Effects |-> "None"]
        /\ commitCount = [e \in Effects |-> 0]
        /\ terminalCount = [e \in Effects |-> 0]
        /\ terminalSequence = [e \in Effects |-> 0]
        /\ nextTerminalSequence = 1
        /\ nextDeriveIndex = 1
        /\ nextPrepareIndex = 1
        /\ freeCredits = [t \in CreditTypes |-> CreditCapacity(t)]
        /\ bindingEpoch = [d \in Domains |-> 0]
        /\ domainPhase = [d \in Domains |-> "Bound"]
        /\ recoveryCohort = [d \in Domains |-> {}]
        /\ snapshotBinding = [d \in Domains |-> NoBinding]
        /\ snapshotCohort = [d \in Domains |-> {}]
        /\ adoptCount = [d \in Domains |-> 0]
        /\ crashCount = 0
        /\ deviceSession = SessionA
        /\ deviceGeneration = 0
        /\ commitDeviceGeneration = NoGeneration
        /\ devicePublished = FALSE
        /\ deviceOutcome = "None"
        /\ dmaPhase = "Absent"
        /\ resetPhase = "None"
        /\ tombstoneKind = "None"
        /\ tombstoneEffect = NoEffect
        /\ timeoutKinds = {}
        /\ retryKinds = {}
        /\ backendDataVisible = FALSE
        /\ guestReplyCount = 0
        /\ guestReplyResult = "None"
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ committedAtClose = {}
        /\ commitAtClose = [e \in Effects |-> 0]
        /\ closureTargetCount = 0
        /\ closureSteps = 0
        /\ closingDomains = {}
        /\ domainReceipt = [d \in Domains |-> "Open"]
        /\ receiptSequence = [d \in Domains |-> 0]
        /\ receiptBindingEpoch = [d \in Domains |-> NoBinding]
        /\ receiptDeviceGeneration = [d \in Domains |-> NoGeneration]
        /\ nextReceiptSequence = 1
        /\ rejectKinds = {}
        /\ presentedRegistry = NoRegistry
        /\ presentedDeviceGeneration = NoGeneration
        /\ lastEvent = "Init"
        /\ lastActorKind = "None"
        /\ lastActorCpu = NoCpu
        /\ commitCpu = NoCpu
        /\ revokeCpu = NoCpu
        /\ completionCpu = NoCpu
        /\ irqCount = 0

Environment == /\ \/ /\ LET e == DeriveOrder[nextDeriveIndex] IN
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ nextDeriveIndex <= Len(DeriveOrder)
                             /\ effectState[e] = "Unused"
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ ParentCanDerive(e, effectState, effectBinding,
                                   bindingEpoch, domainPhase)
                             /\ freeCredits[EffectCredit(e)] > 0
                          /\ effectState' = [effectState EXCEPT ![e] = "Registered"]
                          /\ effectParent' = [effectParent EXCEPT ![e] = AllowedParent(e)]
                          /\ effectRegistry' = [effectRegistry EXCEPT ![e] = RegistryA]
                          /\ effectGeneration' = [effectGeneration EXCEPT ![e] = 1]
                          /\ effectAuthority' = [effectAuthority EXCEPT ![e] = authorityEpoch]
                          /\ effectOriginBinding' = [effectOriginBinding EXCEPT ![e] = bindingEpoch[EffectDomain(e)]]
                          /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[EffectDomain(e)]]
                          /\ createdByWorkload' = [createdByWorkload EXCEPT ![e] = TRUE]
                          /\ creditState' = [creditState EXCEPT ![e] = "Held"]
                          /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] - 1]
                          /\ IF e \in DeviceEffects
                                THEN /\ effectDeviceGeneration' = [effectDeviceGeneration EXCEPT ![e] = deviceGeneration]
                                     /\ effectDeviceSession' = [effectDeviceSession EXCEPT ![e] = deviceSession]
                                ELSE /\ TRUE
                                     /\ UNCHANGED << effectDeviceGeneration, effectDeviceSession >>
                          /\ nextDeriveIndex' = nextDeriveIndex + 1
                          /\ lastEvent' = "Derive"
                          /\ lastActorKind' = "Service"
                          /\ lastActorCpu' = ServiceCpu
                     /\ UNCHANGED <<commitCount, nextPrepareIndex, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ LET e == DeriveOrder[nextPrepareIndex] IN
                          /\ /\ AllDerived(nextDeriveIndex)
                             /\ nextPrepareIndex <= Len(DeriveOrder)
                             /\ effectState[e] = "Registered"
                             /\ effectAuthority[e] = authorityEpoch
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
                             /\ (scenarioMode # "CrashRecovery"
                                   \/ crashCount = 1
                                   \/ nextPrepareIndex <= 2)
                          /\ effectState' = [effectState EXCEPT ![e] = "Prepared"]
                          /\ nextPrepareIndex' = nextPrepareIndex + 1
                          /\ lastEvent' = "Prepare"
                          /\ lastActorKind' = "Service"
                          /\ lastActorCpu' = ServiceCpu
                     /\ UNCHANGED <<effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ EnableCrash
                        /\ scenarioMode = "CrashRecovery"
                        /\ scopeState = "Active"
                        /\ crashCount = 0
                        /\ nextPrepareIndex = 3
                        /\ effectState["FilesystemRead"] = "Prepared"
                        /\ domainPhase["Filesystem"] = "Bound"
                        /\ bindingEpoch["Filesystem"] < MaxBinding
                     /\ bindingEpoch' = [bindingEpoch EXCEPT !["Filesystem"] = bindingEpoch["Filesystem"] + 1]
                     /\ domainPhase' = [domainPhase EXCEPT !["Filesystem"] = "Down"]
                     /\ recoveryCohort' = [recoveryCohort EXCEPT !["Filesystem"] = {"FilesystemRead"}]
                     /\ snapshotBinding' = [snapshotBinding EXCEPT !["Filesystem"] = NoBinding]
                     /\ snapshotCohort' = [snapshotCohort EXCEPT !["Filesystem"] = {}]
                     /\ crashCount' = crashCount + 1
                     /\ lastEvent' = "Crash"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, adoptCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ scopeState = "Active"
                        /\ domainPhase["Filesystem"] = "Down"
                     /\ snapshotBinding' = [snapshotBinding EXCEPT !["Filesystem"] = bindingEpoch["Filesystem"]]
                     /\ snapshotCohort' = [snapshotCohort EXCEPT !["Filesystem"] = recoveryCohort["Filesystem"]]
                     /\ domainPhase' = [domainPhase EXCEPT !["Filesystem"] = "Snapshotted"]
                     /\ lastEvent' = "Snapshot"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, recoveryCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ scopeState = "Active"
                        /\ domainPhase["Filesystem"] = "Snapshotted"
                        /\ snapshotBinding["Filesystem"] =
                              bindingEpoch["Filesystem"]
                        /\ snapshotCohort["Filesystem"] =
                              recoveryCohort["Filesystem"]
                     /\ domainPhase' = [domainPhase EXCEPT !["Filesystem"] = "Ready"]
                     /\ lastEvent' = "Ready"
                     /\ lastActorKind' = "Service"
                     /\ lastActorCpu' = ServiceCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ scopeState = "Active"
                        /\ domainPhase["Filesystem"] = "Ready"
                     /\ domainPhase' = [domainPhase EXCEPT !["Filesystem"] = "Bound"]
                     /\ lastEvent' = "Rebind"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ scopeState = "Active"
                        /\ domainPhase["Filesystem"] = "Bound"
                        /\ "FilesystemRead" \in recoveryCohort["Filesystem"]
                        /\ effectState["FilesystemRead"] \in UncommittedStates
                        /\ effectBinding["FilesystemRead"] #
                              bindingEpoch["Filesystem"]
                     /\ effectBinding' = [effectBinding EXCEPT !["FilesystemRead"] = bindingEpoch["Filesystem"]]
                     /\ recoveryCohort' = [recoveryCohort EXCEPT !["Filesystem"] = {}]
                     /\ adoptCount' = [adoptCount EXCEPT !["Filesystem"] = adoptCount["Filesystem"] + 1]
                     /\ lastEvent' = "Adopt"
                     /\ lastActorKind' = "Service"
                     /\ lastActorCpu' = ServiceCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, snapshotBinding, snapshotCohort, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ AllPrepared(nextPrepareIndex)
                        /\ ~devicePublished
                        /\ \A e \in Effects :
                              /\ effectState[e] = "Prepared"
                              /\ effectAuthority[e] = authorityEpoch
                              /\ effectBinding[e] =
                                  bindingEpoch[EffectDomain(e)]
                              /\ domainPhase[EffectDomain(e)] = "Bound"
                        /\ \A e \in DeviceEffects :
                              /\ effectDeviceGeneration[e] = deviceGeneration
                              /\ effectDeviceSession[e] = deviceSession
                     /\ effectState' = [e \in Effects |-> "Committed"]
                     /\ creditState' = [e \in Effects |-> "Committed"]
                     /\ commitCount' = [e \in Effects |-> 1]
                     /\ devicePublished' = TRUE
                     /\ commitDeviceGeneration' = deviceGeneration
                     /\ dmaPhase' = "Mapped"
                     /\ commitCpu' = ServiceCpu
                     /\ lastEvent' = "DeviceCommit"
                     /\ lastActorKind' = "Service"
                     /\ lastActorCpu' = ServiceCpu
                     /\ UNCHANGED <<effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, deviceOutcome, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, completionCpu, irqCount>>
                  \/ /\ /\ devicePublished
                        /\ deviceOutcome = "None"
                        /\ dmaPhase = "Mapped"
                        /\ resetPhase = "None"
                        /\ scenarioMode \in
                              {"Normal", "CrashRecovery", "CommitRevokeRace",
                               "ActorRace"}
                        /\ effectDeviceGeneration["BlockRequest"] =
                              deviceGeneration
                     /\ deviceOutcome' = "Data"
                     /\ backendDataVisible' = TRUE
                     /\ dmaPhase' = "IotlbPending"
                     /\ completionCpu' = IrqCpu
                     /\ irqCount' = irqCount + 1
                     /\ lastEvent' = "DeviceComplete"
                     /\ lastActorKind' = "Irq"
                     /\ lastActorCpu' = IrqCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu>>
                  \/ /\ /\ EnableTimeout
                        /\ scopeState = "Closing"
                        /\ devicePublished
                        /\ deviceOutcome = "None"
                        /\ dmaPhase = "Mapped"
                        /\ resetPhase = "None"
                        /\ scenarioMode \in
                              {"DeviceTimeout", "RejectProbe", "ActorRace"}
                     /\ resetPhase' = "TimedOut"
                     /\ tombstoneKind' = "Reset"
                     /\ tombstoneEffect' = "BlockRequest"
                     /\ timeoutKinds' = (timeoutKinds \cup {"Reset"})
                     /\ creditState' =            [e \in Effects |->
                                       IF e \in DeviceEffects THEN "Retained" ELSE creditState[e]]
                     /\ lastEvent' = "ResetTimeout"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ resetPhase = "TimedOut"
                        /\ tombstoneKind = "Reset"
                        /\ "Reset" \notin retryKinds
                     /\ resetPhase' = "Retrying"
                     /\ retryKinds' = (retryKinds \cup {"Reset"})
                     /\ lastEvent' = "ResetRetry"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, tombstoneKind, tombstoneEffect, timeoutKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ resetPhase = "Retrying"
                        /\ deviceOutcome = "None"
                        /\ tombstoneKind = "Reset"
                     /\ resetPhase' = "Acknowledged"
                     /\ deviceGeneration' = deviceGeneration + 1
                     /\ effectDeviceGeneration' =                       [e \in Effects |->
                                                  IF e \in DeviceEffects
                                                  THEN deviceGeneration'
                                                  ELSE effectDeviceGeneration[e]]
                     /\ deviceOutcome' = "Eio"
                     /\ dmaPhase' = "IotlbPending"
                     /\ tombstoneKind' = "None"
                     /\ tombstoneEffect' = NoEffect
                     /\ completionCpu' = IrqCpu
                     /\ irqCount' = irqCount + 1
                     /\ lastEvent' = "ResetAck"
                     /\ lastActorKind' = "Irq"
                     /\ lastActorCpu' = IrqCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, commitDeviceGeneration, devicePublished, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu>>
                  \/ /\ /\ EnableTimeout
                        /\ scopeState = "Closing"
                        /\ dmaPhase = "IotlbPending"
                        /\ deviceOutcome \in {"Data", "Eio"}
                        /\ "Iotlb" \notin timeoutKinds
                        /\ scenarioMode \in {"DeviceTimeout", "RejectProbe"}
                     /\ dmaPhase' = "IotlbTimedOut"
                     /\ tombstoneKind' = "Iotlb"
                     /\ tombstoneEffect' = "BlockRequest"
                     /\ timeoutKinds' = (timeoutKinds \cup {"Iotlb"})
                     /\ creditState' =            [e \in Effects |->
                                       IF e \in DeviceEffects THEN "Retained" ELSE creditState[e]]
                     /\ lastEvent' = "IotlbTimeout"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, resetPhase, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ dmaPhase = "IotlbTimedOut"
                        /\ tombstoneKind = "Iotlb"
                        /\ "Iotlb" \notin retryKinds
                     /\ dmaPhase' = "IotlbPending"
                     /\ retryKinds' = (retryKinds \cup {"Iotlb"})
                     /\ lastEvent' = "IotlbRetry"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ dmaPhase = "IotlbPending"
                        /\ deviceOutcome \in {"Data", "Eio"}
                        /\ (scenarioMode \notin {"DeviceTimeout", "RejectProbe"}
                              \/ "Iotlb" \in retryKinds)
                     /\ dmaPhase' = "Released"
                     /\ tombstoneKind' = "None"
                     /\ tombstoneEffect' = NoEffect
                     /\ irqCount' = irqCount + 1
                     /\ lastEvent' = "IotlbAck"
                     /\ lastActorKind' = "Irq"
                     /\ lastActorCpu' = IrqCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, resetPhase, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu>>
                  \/ /\ /\ EnableRejects
                        /\ scenarioMode = "RejectProbe"
                        /\ devicePublished
                        /\ "ForeignRegistry" \notin rejectKinds
                     /\ rejectKinds' = (rejectKinds \cup {"ForeignRegistry"})
                     /\ presentedRegistry' = RegistryB
                     /\ lastEvent' = "RejectForeign"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, presentedDeviceGeneration, commitCpu, completionCpu, irqCount>>
                  \/ /\ /\ EnableRejects
                        /\ scenarioMode = "RejectProbe"
                        /\ deviceGeneration = 1
                        /\ commitDeviceGeneration = 0
                        /\ "StaleDeviceGeneration" \notin rejectKinds
                     /\ rejectKinds' = (rejectKinds \cup {"StaleDeviceGeneration"})
                     /\ presentedDeviceGeneration' = commitDeviceGeneration
                     /\ lastEvent' = "RejectStaleGeneration"
                     /\ lastActorKind' = "Irq"
                     /\ lastActorCpu' = IrqCpu
                     /\ UNCHANGED <<effectState, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, creditState, commitCount, nextDeriveIndex, nextPrepareIndex, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, presentedRegistry, commitCpu, completionCpu, irqCount>>
               /\ UNCHANGED << scenarioMode, scopeState, scopeGate, authorityEpoch, closingEpoch, terminalCount, terminalSequence, nextTerminalSequence, deviceSession, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closureSteps, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu >>

Kernel == /\ \/ /\ /\ scopeState = "Active"
                   /\ AllPrepared(nextPrepareIndex)
                   /\ (scenarioMode = "CommitRevokeRace" \/ devicePublished)
                /\ effectsAtClose' = {e \in Effects : effectState[e] # "Unused"}
                /\ closingEffects' = {e \in Effects : effectState[e] \in
                                         (LiveStates \cup UncommittedStates)}
                /\ committedAtClose' = {e \in Effects : commitCount[e] = 1
                                           /\ effectState[e] \in LiveStates}
                /\ commitAtClose' = commitCount
                /\ closureTargetCount' =                   Cardinality(
                                         {e \in Effects : effectState[e] \in
                                             (LiveStates \cup UncommittedStates)})
                /\ closureSteps' = 0
                /\ closingDomains' = Domains
                /\ domainReceipt' = [d \in Domains |-> "Pending"]
                /\ closingEpoch' = authorityEpoch
                /\ authorityEpoch' = authorityEpoch + 1
                /\ scopeGate' = "Closed"
                /\ scopeState' = "Closing"
                /\ domainPhase' = [d \in Domains |-> "Closed"]
                /\ recoveryCohort' = [d \in Domains |-> {}]
                /\ revokeCpu' = KernelCpu
                /\ lastEvent' = "RevokeBegin"
                /\ lastActorKind' = "Kernel"
                /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<effectState, creditState, terminalCount, terminalSequence, nextTerminalSequence, freeCredits, guestReplyCount, guestReplyResult, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence>>
             \/ /\ \E e \in DmaEffects:
                     /\ /\ effectState[e] = "Committed"
                        /\ dmaPhase = "Released"
                        /\ deviceOutcome \in {"Data", "Eio"}
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                     /\ creditState' = [creditState EXCEPT ![e] = "Returned"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ terminalSequence' = [terminalSequence EXCEPT ![e] = nextTerminalSequence]
                     /\ nextTerminalSequence' = nextTerminalSequence + 1
                     /\ freeCredits' = [freeCredits EXCEPT !["DmaOwner"] = freeCredits["DmaOwner"] + 1]
                     /\ IF e \in closingEffects
                           THEN /\ closureSteps' = closureSteps + 1
                           ELSE /\ TRUE
                                /\ UNCHANGED closureSteps
                     /\ lastEvent' = "CompleteDma"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, domainPhase, recoveryCohort, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu>>
             \/ /\ /\ effectState["BlockRequest"] = "Committed"
                   /\ deviceOutcome \in {"Data", "Eio"}
                   /\ dmaPhase = "Released"
                   /\ ChildrenTerminal("BlockRequest", effectState,
                         effectParent)
                /\ effectState' = [effectState EXCEPT !["BlockRequest"] = "Completed"]
                /\ creditState' = [creditState EXCEPT !["BlockRequest"] = "Returned"]
                /\ terminalCount' = [terminalCount EXCEPT !["BlockRequest"] = terminalCount["BlockRequest"] + 1]
                /\ terminalSequence' = [terminalSequence EXCEPT !["BlockRequest"] = nextTerminalSequence]
                /\ nextTerminalSequence' = nextTerminalSequence + 1
                /\ freeCredits' = [freeCredits EXCEPT !["QueueSlot"] = freeCredits["QueueSlot"] + 1]
                /\ IF "BlockRequest" \in closingEffects
                      THEN /\ closureSteps' = closureSteps + 1
                      ELSE /\ TRUE
                           /\ UNCHANGED closureSteps
                /\ lastEvent' = "CompleteBlock"
                /\ lastActorKind' = "Kernel"
                /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, domainPhase, recoveryCohort, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu>>
             \/ /\ /\ effectState["FilesystemRead"] = "Committed"
                   /\ effectState["BlockRequest"] = "Completed"
                   /\ ChildrenTerminal("FilesystemRead", effectState,
                         effectParent)
                /\ effectState' = [effectState EXCEPT !["FilesystemRead"] = "Completed"]
                /\ creditState' = [creditState EXCEPT !["FilesystemRead"] = "Returned"]
                /\ terminalCount' = [terminalCount EXCEPT !["FilesystemRead"] = terminalCount["FilesystemRead"] + 1]
                /\ terminalSequence' = [terminalSequence EXCEPT !["FilesystemRead"] = nextTerminalSequence]
                /\ nextTerminalSequence' = nextTerminalSequence + 1
                /\ freeCredits' = [freeCredits EXCEPT !["FilesystemCredit"] = freeCredits["FilesystemCredit"] + 1]
                /\ IF "FilesystemRead" \in closingEffects
                      THEN /\ closureSteps' = closureSteps + 1
                      ELSE /\ TRUE
                           /\ UNCHANGED closureSteps
                /\ lastEvent' = "CompleteFilesystem"
                /\ lastActorKind' = "Kernel"
                /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, domainPhase, recoveryCohort, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu>>
             \/ /\ /\ effectState["PersonalitySyscall"] = "Committed"
                   /\ effectState["FilesystemRead"] = "Completed"
                   /\ guestReplyCount = 0
                   /\ deviceOutcome \in {"Data", "Eio"}
                /\ effectState' = [effectState EXCEPT !["PersonalitySyscall"] = "Completed"]
                /\ creditState' = [creditState EXCEPT !["PersonalitySyscall"] = "Returned"]
                /\ terminalCount' = [terminalCount EXCEPT !["PersonalitySyscall"] = terminalCount["PersonalitySyscall"] + 1]
                /\ terminalSequence' = [terminalSequence EXCEPT !["PersonalitySyscall"] = nextTerminalSequence]
                /\ nextTerminalSequence' = nextTerminalSequence + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Control"] = freeCredits["Control"] + 1]
                /\ guestReplyCount' = guestReplyCount + 1
                /\ IF deviceOutcome = "Data"
                      THEN /\ guestReplyResult' = "Data"
                      ELSE /\ guestReplyResult' = "Eio"
                /\ IF "PersonalitySyscall" \in closingEffects
                      THEN /\ closureSteps' = closureSteps + 1
                      ELSE /\ TRUE
                           /\ UNCHANGED closureSteps
                /\ lastEvent' = "GuestReply"
                /\ lastActorKind' = "Kernel"
                /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, domainPhase, recoveryCohort, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu>>
             \/ /\ \E e \in Effects:
                     /\ /\ scopeState = "Closing"
                        /\ e \in closingEffects
                        /\ effectState[e] \in UncommittedStates
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Aborted"]
                     /\ creditState' = [creditState EXCEPT ![e] = "Returned"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ terminalSequence' = [terminalSequence EXCEPT ![e] = nextTerminalSequence]
                     /\ nextTerminalSequence' = nextTerminalSequence + 1
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                     /\ closureSteps' = closureSteps + 1
                     /\ lastEvent' = "AbortLeaf"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, domainPhase, recoveryCohort, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu>>
             \/ /\ \E d \in Domains:
                     /\ /\ scopeState = "Closing"
                        /\ d \in closingDomains
                        /\ domainReceipt[d] = "Pending"
                        /\ DomainTerminal(d, effectsAtClose, effectState)
                        /\ ChildDomainReceiptsClosed(d, domainReceipt)
                     /\ domainReceipt' = [domainReceipt EXCEPT ![d] = "Closed"]
                     /\ receiptSequence' = [receiptSequence EXCEPT ![d] = nextReceiptSequence]
                     /\ receiptBindingEpoch' = [receiptBindingEpoch EXCEPT ![d] = bindingEpoch[d]]
                     /\ IF d = "VirtIo"
                           THEN /\ receiptDeviceGeneration' = [receiptDeviceGeneration EXCEPT ![d] = deviceGeneration]
                           ELSE /\ TRUE
                                /\ UNCHANGED receiptDeviceGeneration
                     /\ nextReceiptSequence' = nextReceiptSequence + 1
                     /\ lastEvent' = "DomainReceipt"
                     /\ lastActorKind' = "Kernel"
                     /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, creditState, terminalCount, terminalSequence, nextTerminalSequence, freeCredits, domainPhase, recoveryCohort, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closureSteps, closingDomains, revokeCpu>>
             \/ /\ /\ scopeState = "Closing"
                   /\ closureSteps = closureTargetCount
                   /\ \A e \in effectsAtClose :
                         effectState[e] \in TerminalStates
                   /\ \A d \in closingDomains :
                         domainReceipt[d] = "Closed"
                   /\ \A t \in CreditTypes :
                         freeCredits[t] = CreditCapacity(t)
                   /\ tombstoneKind = "None"
                   /\ dmaPhase \in {"Absent", "Released"}
                   /\ (~devicePublished \/ guestReplyCount = 1)
                /\ scopeState' = "Revoked"
                /\ lastEvent' = "RevokeComplete"
                /\ lastActorKind' = "Kernel"
                /\ lastActorCpu' = KernelCpu
                /\ UNCHANGED <<scopeGate, authorityEpoch, closingEpoch, effectState, creditState, terminalCount, terminalSequence, nextTerminalSequence, freeCredits, domainPhase, recoveryCohort, guestReplyCount, guestReplyResult, effectsAtClose, closingEffects, committedAtClose, commitAtClose, closureTargetCount, closureSteps, closingDomains, domainReceipt, receiptSequence, receiptBindingEpoch, receiptDeviceGeneration, nextReceiptSequence, revokeCpu>>
          /\ UNCHANGED << scenarioMode, effectParent, effectRegistry, effectGeneration, effectAuthority, effectOriginBinding, effectBinding, effectDeviceGeneration, effectDeviceSession, createdByWorkload, commitCount, nextDeriveIndex, nextPrepareIndex, bindingEpoch, snapshotBinding, snapshotCohort, adoptCount, crashCount, deviceSession, deviceGeneration, commitDeviceGeneration, devicePublished, deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect, timeoutKinds, retryKinds, backendDataVisible, rejectKinds, presentedRegistry, presentedDeviceGeneration, commitCpu, completionCpu, irqCount >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

(***************************************************************************)
(* State invariants                                                         *)
(***************************************************************************)

TypeOK ==
    /\ scenarioMode \in ScenarioModes
    /\ scopeState \in {"Active", "Closing", "Revoked"}
    /\ scopeGate \in {"Open", "Closed"}
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoGeneration, 0}
    /\ effectState \in [Effects ->
        ({"Unused"} \cup LiveStates \cup TerminalStates)]
    /\ effectParent \in [Effects -> (Effects \cup {Root, NoParent})]
    /\ effectRegistry \in [Effects -> {RegistryA, NoRegistry}]
    /\ effectGeneration \in [Effects -> 0..1]
    /\ effectAuthority \in [Effects -> {NoGeneration, 0}]
    /\ effectOriginBinding \in [Effects -> {NoBinding, 0}]
    /\ effectBinding \in [Effects -> {NoBinding, 0, 1}]
    /\ effectDeviceGeneration \in
        [Effects -> {NoGeneration, 0, 1}]
    /\ effectDeviceSession \in [Effects -> {NoSession, SessionA}]
    /\ createdByWorkload \in [Effects -> BOOLEAN]
    /\ creditState \in [Effects ->
        {"None", "Held", "Committed", "Retained", "Returned"}]
    /\ commitCount \in [Effects -> 0..1]
    /\ terminalCount \in [Effects -> 0..1]
    /\ terminalSequence \in [Effects -> 0..Cardinality(Effects)]
    /\ nextTerminalSequence \in 1..(Cardinality(Effects) + 1)
    /\ nextDeriveIndex \in 1..(Len(DeriveOrder) + 1)
    /\ nextPrepareIndex \in 1..(Len(DeriveOrder) + 1)
    /\ freeCredits \in [CreditTypes -> 0..3]
    /\ bindingEpoch \in [Domains -> 0..1]
    /\ domainPhase \in
        [Domains -> {"Bound", "Down", "Snapshotted", "Ready", "Closed"}]
    /\ recoveryCohort \in [Domains -> SUBSET Effects]
    /\ snapshotBinding \in [Domains -> {NoBinding, 0, 1}]
    /\ snapshotCohort \in [Domains -> SUBSET Effects]
    /\ adoptCount \in [Domains -> 0..1]
    /\ crashCount \in 0..1
    /\ deviceSession = SessionA
    /\ deviceGeneration \in 0..1
    /\ commitDeviceGeneration \in {NoGeneration, 0}
    /\ devicePublished \in BOOLEAN
    /\ deviceOutcome \in {"None", "Data", "Eio"}
    /\ dmaPhase \in
        {"Absent", "Mapped", "IotlbPending", "IotlbTimedOut", "Released"}
    /\ resetPhase \in {"None", "TimedOut", "Retrying", "Acknowledged"}
    /\ tombstoneKind \in {"None", "Reset", "Iotlb"}
    /\ tombstoneEffect \in {NoEffect, "BlockRequest"}
    /\ timeoutKinds \subseteq TimeoutTargets
    /\ retryKinds \subseteq TimeoutTargets
    /\ backendDataVisible \in BOOLEAN
    /\ guestReplyCount \in 0..1
    /\ guestReplyResult \in {"None", "Data", "Eio"}
    /\ effectsAtClose \subseteq Effects
    /\ closingEffects \subseteq Effects
    /\ committedAtClose \subseteq Effects
    /\ commitAtClose \in [Effects -> 0..1]
    /\ closureTargetCount \in 0..Cardinality(Effects)
    /\ closureSteps \in 0..Cardinality(Effects)
    /\ closingDomains \subseteq Domains
    /\ domainReceipt \in [Domains -> {"Open", "Pending", "Closed"}]
    /\ receiptSequence \in [Domains -> 0..Cardinality(Domains)]
    /\ receiptBindingEpoch \in [Domains -> {NoBinding, 0, 1}]
    /\ receiptDeviceGeneration \in
        [Domains -> {NoGeneration, 0, 1}]
    /\ nextReceiptSequence \in 1..(Cardinality(Domains) + 1)
    /\ rejectKinds \subseteq RejectKinds
    /\ presentedRegistry \in {NoRegistry, RegistryB}
    /\ presentedDeviceGeneration \in {NoGeneration, 0}
    /\ lastEvent \in AllEvents
    /\ lastActorKind \in ActorKinds
    /\ lastActorCpu \in CpuIds \cup {NoCpu}
    /\ commitCpu \in CpuIds \cup {NoCpu}
    /\ revokeCpu \in CpuIds \cup {NoCpu}
    /\ completionCpu \in CpuIds \cup {NoCpu}
    /\ irqCount \in 0..2

ScopeGateDiscipline ==
    /\ (scopeState = "Active") = (scopeGate = "Open")
    /\ (scopeState \in {"Closing", "Revoked"}) = (scopeGate = "Closed")
    /\ (scopeState = "Active" => authorityEpoch = 0)
    /\ (scopeState \in {"Closing", "Revoked"} =>
        /\ authorityEpoch = 1
        /\ closingEpoch = 0)

WorkloadRegistryIdentity ==
    /\ \A e \in Effects :
        /\ (effectState[e] = "Unused") =
            /\ effectParent[e] = NoParent
            /\ effectRegistry[e] = NoRegistry
            /\ effectGeneration[e] = 0
            /\ ~createdByWorkload[e]
            /\ creditState[e] = "None"
        /\ (effectState[e] # "Unused") =>
            /\ effectParent[e] = AllowedParent(e)
            /\ effectRegistry[e] = RegistryA
            /\ effectGeneration[e] = 1
            /\ effectAuthority[e] = 0
            /\ createdByWorkload[e]
            /\ effectOriginBinding[e] = 0
            /\ effectBinding[e] \in 0..bindingEpoch[EffectDomain(e)]
    /\ effectsAtClose \subseteq
        {e \in Effects : createdByWorkload[e]}

ImmutableAncestry ==
    /\ \A e \in Effects :
        effectState[e] # "Unused" =>
            IF effectParent[e] = Root
            THEN e = "PersonalitySyscall"
            ELSE /\ effectParent[e] \in Effects
                 /\ effectState[effectParent[e]] # "Unused"
                 /\ effectRegistry[effectParent[e]] = effectRegistry[e]
                 /\ effectAuthority[effectParent[e]] = effectAuthority[e]
    /\ \A e \in DeviceEffects :
        effectState[e] # "Unused" =>
            /\ effectDeviceSession[e] = deviceSession
            /\ effectDeviceGeneration[e] \in 0..deviceGeneration
    /\ \A e \in Effects \ DeviceEffects :
        /\ effectDeviceSession[e] = NoSession
        /\ effectDeviceGeneration[e] = NoGeneration

RegistryNativeBindings ==
    /\ \A e \in Effects :
        effectState[e] # "Unused" =>
            /\ effectBinding[e] <= bindingEpoch[EffectDomain(e)]
            /\ effectOriginBinding[e] = 0
    /\ bindingEpoch["Personality"] = 0
    /\ bindingEpoch["VirtIo"] = 0
    /\ bindingEpoch["Filesystem"] = crashCount
    /\ \A d \in Domains \ {"Filesystem"} :
        /\ recoveryCohort[d] = {}
        /\ snapshotCohort[d] = {}
        /\ adoptCount[d] = 0

EffectLifecycle ==
    \A e \in Effects :
        /\ commitCount[e] <= 1
        /\ terminalCount[e] <= 1
        /\ (commitCount[e] = 1 =>
            effectState[e] \in ({"Committed"} \cup TerminalStates))
        /\ (effectState[e] \in TerminalStates => terminalCount[e] = 1)
        /\ (terminalCount[e] = 1 => terminalSequence[e] # 0)
        /\ (effectState[e] \in UncommittedStates => commitCount[e] = 0)

CreditLifecycle ==
    \A e \in Effects :
        CASE effectState[e] = "Unused" -> creditState[e] = "None"
          [] effectState[e] \in UncommittedStates -> creditState[e] = "Held"
          [] effectState[e] = "Committed" ->
                creditState[e] \in {"Committed", "Retained"}
          [] effectState[e] \in TerminalStates -> creditState[e] = "Returned"

TypedCreditConservation ==
    \A t \in CreditTypes :
        freeCredits[t]
            + Cardinality({e \in Effects :
                EffectCredit(e) = t /\ creditState[e] \in CreditLiveStates})
        = CreditCapacity(t)

RecoveryDiscipline ==
    /\ recoveryCohort["Filesystem"] \subseteq {"FilesystemRead"}
    /\ snapshotCohort["Filesystem"] \subseteq {"FilesystemRead"}
    /\ ("FilesystemRead" \in recoveryCohort["Filesystem"] =>
        /\ effectState["FilesystemRead"] \in UncommittedStates
        /\ effectBinding["FilesystemRead"] = 0
        /\ bindingEpoch["Filesystem"] = 1)
    /\ (adoptCount["Filesystem"] = 1 =>
        /\ effectBinding["FilesystemRead"] = 1
        /\ recoveryCohort["Filesystem"] = {}
        /\ effectGeneration["FilesystemRead"] = 1
        /\ effectParent["FilesystemRead"] = "PersonalitySyscall")

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} =>
        \A e \in closingEffects :
            commitAtClose[e] = 0 => commitCount[e] = 0

GuestReplyDiscipline ==
    /\ guestReplyCount <= 1
    /\ (guestReplyCount = 0 => guestReplyResult = "None")
    /\ (guestReplyCount = 1 =>
        /\ effectState["PersonalitySyscall"] = "Completed"
        /\ effectState["FilesystemRead"] = "Completed"
        /\ deviceOutcome \in {"Data", "Eio"}
        /\ guestReplyResult = deviceOutcome)
    /\ backendDataVisible = (deviceOutcome = "Data")

DeviceIdentityAndHonesty ==
    /\ (devicePublished =>
        /\ commitDeviceGeneration = 0
        /\ \A e \in DeviceEffects :
            /\ effectRegistry[e] = RegistryA
            /\ effectGeneration[e] = 1
            /\ effectDeviceSession[e] = SessionA
            /\ commitCount[e] = 1)
    /\ (deviceGeneration = 1 =>
        /\ resetPhase = "Acknowledged"
        /\ deviceOutcome = "Eio"
        /\ \A e \in DeviceEffects : effectDeviceGeneration[e] = 1)
    /\ (tombstoneKind # "None" =>
        /\ scopeState = "Closing"
        /\ tombstoneEffect = "BlockRequest"
        /\ devicePublished
        /\ dmaPhase # "Released"
        /\ \A e \in DeviceEffects : creditState[e] = "Retained")
    /\ (tombstoneKind = "None" => tombstoneEffect = NoEffect)
    /\ retryKinds \subseteq timeoutKinds
    /\ (dmaPhase = "Released" => tombstoneKind = "None")

LeafFirstTerminalization ==
    \A parent \in Effects :
        effectState[parent] \in TerminalStates =>
            \A child \in Effects :
                effectParent[child] = parent =>
                    /\ effectState[child] \in TerminalStates
                    /\ terminalSequence[child] < terminalSequence[parent]

ClosureReceiptDiscipline ==
    /\ (scopeState = "Active" =>
        /\ closingDomains = {}
        /\ \A d \in Domains : domainReceipt[d] = "Open")
    /\ (scopeState \in {"Closing", "Revoked"} =>
        /\ closingDomains = Domains
        /\ \A d \in Domains : domainReceipt[d] \in {"Pending", "Closed"})
    /\ \A d \in Domains :
        domainReceipt[d] = "Closed" =>
            /\ DomainTerminal(d, effectsAtClose, effectState)
            /\ ChildDomainReceiptsClosed(d, domainReceipt)
            /\ receiptSequence[d] # 0
            /\ receiptBindingEpoch[d] = bindingEpoch[d]
            /\ (d = "VirtIo" =>
                receiptDeviceGeneration[d] = deviceGeneration)
    /\ Cardinality({receiptSequence[d] :
        d \in {closed \in Domains : receiptSequence[closed] # 0}})
       = Cardinality({d \in Domains : domainReceipt[d] = "Closed"})

RejectAuditDiscipline ==
    /\ ("StaleDeviceGeneration" \in rejectKinds =>
        /\ deviceGeneration = 1
        /\ commitDeviceGeneration = 0
        /\ presentedDeviceGeneration = 0)
    /\ ("ForeignRegistry" \in rejectKinds =>
        /\ devicePublished
        /\ presentedRegistry = RegistryB)

ActorBoundarySafety ==
    /\ (lastEvent = "Init" =>
        /\ lastActorKind = "None"
        /\ lastActorCpu = NoCpu)
    /\ (lastEvent \in ServiceEvents =>
        /\ lastActorKind = "Service"
        /\ lastActorCpu = ServiceCpu)
    /\ (lastEvent \in KernelEvents =>
        /\ lastActorKind = "Kernel"
        /\ lastActorCpu = KernelCpu)
    /\ (lastEvent \in IrqEvents =>
        /\ lastActorKind = "Irq"
        /\ lastActorCpu = IrqCpu)
    /\ (commitCpu # NoCpu => commitCpu = ServiceCpu)
    /\ (revokeCpu # NoCpu => revokeCpu = KernelCpu)
    /\ (completionCpu # NoCpu => completionCpu = IrqCpu)
    /\ ServiceCpu \in CpuIds
    /\ KernelCpu \in CpuIds
    /\ IrqCpu \in CpuIds

SingleTerminalization == \A e \in Effects : terminalCount[e] <= 1

QuiescentClosure ==
    scopeState = "Revoked" =>
        /\ \A e \in effectsAtClose : effectState[e] \in TerminalStates
        /\ \A d \in closingDomains : domainReceipt[d] = "Closed"
        /\ \A t \in CreditTypes : freeCredits[t] = CreditCapacity(t)
        /\ closureSteps = closureTargetCount
        /\ tombstoneKind = "None"
        /\ dmaPhase \in {"Absent", "Released"}
        /\ (~devicePublished \/ guestReplyCount = 1)

(***************************************************************************)
(* Action properties                                                        *)
(***************************************************************************)

CausalIdentityImmutability ==
    [][\A e \in Effects :
        effectState[e] # "Unused" => UNCHANGED <<
            effectParent[e], effectRegistry[e], effectGeneration[e],
            effectAuthority[e], effectOriginBinding[e],
            effectDeviceSession[e], createdByWorkload[e]
        >>]_vars

DeriveRegistryAction ==
    [][\A e \in Effects :
        effectState[e] = "Unused" /\ effectState'[e] = "Registered" =>
            /\ scopeState = "Active"
            /\ scopeGate = "Open"
            /\ effectRegistry'[e] = RegistryA
            /\ effectGeneration'[e] = 1
            /\ createdByWorkload'[e]
            /\ effectParent'[e] = AllowedParent(e)]_vars

CommitGateAction ==
    [][(\E e \in Effects : commitCount'[e] > commitCount[e]) =>
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ \A e \in Effects :
            /\ effectState[e] = "Prepared"
            /\ effectAuthority[e] = authorityEpoch
            /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
            /\ domainPhase[EffectDomain(e)] = "Bound"]_vars

DomainBindingIsolation ==
    [][bindingEpoch' # bindingEpoch =>
        /\ bindingEpoch'["Filesystem"] =
            bindingEpoch["Filesystem"] + 1
        /\ UNCHANGED <<bindingEpoch["Personality"],
            bindingEpoch["VirtIo"], authorityEpoch, deviceGeneration>>]_vars

ExplicitAdoptionAction ==
    [][effectState["FilesystemRead"] # "Unused"
        /\ effectBinding'["FilesystemRead"] #
            effectBinding["FilesystemRead"] =>
        /\ "FilesystemRead" \in recoveryCohort["Filesystem"]
        /\ effectState["FilesystemRead"] \in UncommittedStates
        /\ effectBinding'["FilesystemRead"] = bindingEpoch["Filesystem"]
        /\ UNCHANGED <<effectParent["FilesystemRead"],
            effectRegistry["FilesystemRead"],
            effectGeneration["FilesystemRead"],
            effectAuthority["FilesystemRead"],
            effectOriginBinding["FilesystemRead"]>>]_vars

DeviceGenerationIsolation ==
    [][deviceGeneration' # deviceGeneration =>
        /\ scopeState = "Closing"
        /\ resetPhase = "Retrying"
        /\ deviceOutcome = "None"
        /\ deviceGeneration' = deviceGeneration + 1
        /\ UNCHANGED <<authorityEpoch, bindingEpoch, deviceSession,
            effectParent, effectRegistry, effectGeneration>>]_vars

TerminalLeafAction ==
    [][\A e \in Effects : terminalCount'[e] > terminalCount[e] =>
        ChildrenTerminal(e, effectState, effectParent)]_vars

CoreProjection == <<
    scopeState, scopeGate, authorityEpoch, closingEpoch,
    effectState, effectParent, effectRegistry, effectGeneration,
    effectAuthority, effectOriginBinding, effectBinding,
    effectDeviceGeneration, effectDeviceSession, createdByWorkload,
    creditState, commitCount, terminalCount, terminalSequence,
    nextTerminalSequence, nextDeriveIndex, nextPrepareIndex, freeCredits,
    bindingEpoch, domainPhase, recoveryCohort, snapshotBinding,
    snapshotCohort, adoptCount, crashCount, deviceSession,
    deviceGeneration, commitDeviceGeneration, devicePublished,
    deviceOutcome, dmaPhase, resetPhase, tombstoneKind, tombstoneEffect,
    timeoutKinds, retryKinds, backendDataVisible, guestReplyCount,
    guestReplyResult, effectsAtClose, closingEffects, committedAtClose,
    commitAtClose, closureTargetCount, closureSteps, closingDomains,
    domainReceipt, receiptSequence, receiptBindingEpoch,
    receiptDeviceGeneration, nextReceiptSequence, commitCpu, revokeCpu,
    completionCpu, irqCount
>>

RejectSideEffectFreedom ==
    [][rejectKinds' # rejectKinds => UNCHANGED CoreProjection]_vars

ReadyForDomainReceipt(d) ==
    /\ scopeState = "Closing"
    /\ d \in closingDomains
    /\ domainReceipt[d] = "Pending"
    /\ DomainTerminal(d, effectsAtClose, effectState)
    /\ ChildDomainReceiptsClosed(d, domainReceipt)

ReadyForRevokeComplete ==
    /\ scopeState = "Closing"
    /\ closureSteps = closureTargetCount
    /\ \A e \in effectsAtClose : effectState[e] \in TerminalStates
    /\ \A d \in closingDomains : domainReceipt[d] = "Closed"
    /\ \A t \in CreditTypes : freeCredits[t] = CreditCapacity(t)
    /\ tombstoneKind = "None"
    /\ dmaPhase \in {"Absent", "Released"}
    /\ (~devicePublished \/ guestReplyCount = 1)

ReadyForKernelClosure ==
    /\ scopeState = "Closing"
    /\ tombstoneKind = "None"
    /\ \/ ~devicePublished
       \/ /\ deviceOutcome \in {"Data", "Eio"}
          /\ dmaPhase = "Released"

ConditionalKernelClosureProgress ==
    [](ReadyForKernelClosure ~> scopeState = "Revoked")

ConditionalRevokeCompletion ==
    [](ReadyForRevokeComplete ~> scopeState = "Revoked")

ConditionalDomainReceiptProgress ==
    \A d \in Domains :
        [](ReadyForDomainReceipt(d) ~> domainReceipt[d] = "Closed")

(***************************************************************************)
(* Reachability witnesses                                                   *)
(***************************************************************************)

IdentityPreservingReadObserved ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ \A e \in Effects :
        /\ effectState[e] = "Completed"
        /\ effectRegistry[e] = RegistryA
        /\ effectGeneration[e] = 1
        /\ createdByWorkload[e]
    /\ deviceOutcome = "Data"
    /\ backendDataVisible
    /\ guestReplyCount = 1
    /\ guestReplyResult = "Data"
    /\ dmaPhase = "Released"
    /\ \A d \in Domains : domainReceipt[d] = "Closed"
    /\ \A t \in CreditTypes : freeCredits[t] = CreditCapacity(t)

FilesystemCrashAdoptObserved ==
    /\ bindingEpoch["Filesystem"] = 1
    /\ bindingEpoch["Personality"] = 0
    /\ bindingEpoch["VirtIo"] = 0
    /\ adoptCount["Filesystem"] = 1
    /\ effectBinding["FilesystemRead"] = 1
    /\ effectOriginBinding["FilesystemRead"] = 0
    /\ effectGeneration["FilesystemRead"] = 1
    /\ effectParent["FilesystemRead"] = "PersonalitySyscall"
    /\ recoveryCohort["Filesystem"] = {}

CommitWinsRevokeRaceObserved ==
    /\ scopeState = "Revoked"
    /\ devicePublished
    /\ committedAtClose = Effects
    /\ \A e \in Effects : effectState[e] = "Completed"
    /\ guestReplyCount = 1

RevokeWinsCommitRaceObserved ==
    /\ scopeState = "Revoked"
    /\ ~devicePublished
    /\ committedAtClose = {}
    /\ \A e \in Effects : effectState[e] = "Aborted"
    /\ guestReplyCount = 0

ResetIotlbSameEffectObserved ==
    /\ scopeState = "Revoked"
    /\ timeoutKinds = TimeoutTargets
    /\ retryKinds = TimeoutTargets
    /\ deviceGeneration = 1
    /\ commitDeviceGeneration = 0
    /\ \A e \in DeviceEffects :
        /\ effectRegistry[e] = RegistryA
        /\ effectGeneration[e] = 1
        /\ effectDeviceSession[e] = SessionA
        /\ effectDeviceGeneration[e] = 1
    /\ deviceOutcome = "Eio"
    /\ dmaPhase = "Released"
    /\ guestReplyCount = 1
    /\ guestReplyResult = "Eio"

CrossRegistryGenerationRejectObserved == rejectKinds = RejectKinds

ActorSeparationObserved ==
    /\ scopeState = "Revoked"
    /\ commitCpu = ServiceCpu
    /\ revokeCpu = KernelCpu
    /\ completionCpu = IrqCpu
    /\ Cardinality({commitCpu, revokeCpu, completionCpu}) =
        IF CpuCount = 4 THEN 3 ELSE 2
    /\ irqCount >= 1

IdentityPreservingReadAbsent == ~IdentityPreservingReadObserved
FilesystemCrashAdoptAbsent == ~FilesystemCrashAdoptObserved
CommitWinsRevokeRaceAbsent == ~CommitWinsRevokeRaceObserved
RevokeWinsCommitRaceAbsent == ~RevokeWinsCommitRaceObserved
ResetIotlbSameEffectAbsent == ~ResetIotlbSameEffectObserved
CrossRegistryGenerationRejectAbsent ==
    ~CrossRegistryGenerationRejectObserved
ActorSeparationAbsent == ~ActorSeparationObserved

NormalWitnessScenario == scenarioMode = "Normal"
CrashWitnessScenario == scenarioMode = "CrashRecovery"
CommitRaceWitnessScenario == scenarioMode = "CommitRevokeRace"
TimeoutWitnessScenario == scenarioMode = "DeviceTimeout"
RejectWitnessScenario == scenarioMode = "RejectProbe"
ActorWitnessScenario == scenarioMode = "ActorRace"

ActionScenarios == scenarioMode \in ScenarioModes
ProgressScenarios ==
    scenarioMode \in {"Normal", "CrashRecovery", "CommitRevokeRace",
                       "DeviceTimeout", "ActorRace"}

=============================================================================

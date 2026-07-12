-------------------- MODULE RuntimeNetCser --------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Bounded runtime-network CSER successor.  The fixed causal graph is:     *)
(*                                                                         *)
(* Root -> Syscall -> NetOperation -> ReadinessWait                        *)
(*                                \-> BufferLease                           *)
(*                                                                         *)
(* NetCommit, ReadyCommit, and GuestReply are distinct publication points. *)
(* The model fixes three independently rebound domains and four typed       *)
(* credits around one four-byte in-memory loopback transaction.  It is not  *)
(* a TCP/IP, VirtIO-net, external-packet, or complete Linux ABI model.       *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableCrash, EnableRejects

ASSUME /\ MaxBinding = 1
       /\ EnableCrash \in BOOLEAN
       /\ EnableRejects \in BOOLEAN

Domains == {"Personality", "Network", "Readiness"}
Effects == {"Syscall", "NetOperation", "ReadinessWait", "BufferLease"}
CreditTypes == {"Control", "Network", "Readiness", "Buffer"}
SocketEffects == {"NetOperation", "BufferLease"}
RejectKinds == {"Authority", "PersonalityBinding", "NetworkBinding",
                "ReadinessBinding", "SocketGeneration",
                "SourceGeneration", "CompletionReplay"}

Root == "Root"
NoParent == "NoParent"
NoGeneration == -1
NoBinding == -1

EffectDomain(e) ==
    CASE e = "Syscall" -> "Personality"
      [] e = "NetOperation" -> "Network"
      [] e = "ReadinessWait" -> "Readiness"
      [] e = "BufferLease" -> "Network"

EffectCredit(e) ==
    CASE e = "Syscall" -> "Control"
      [] e = "NetOperation" -> "Network"
      [] e = "ReadinessWait" -> "Readiness"
      [] e = "BufferLease" -> "Buffer"

AllowedParent(e) ==
    CASE e = "Syscall" -> Root
      [] e = "NetOperation" -> "Syscall"
      [] e = "ReadinessWait" -> "NetOperation"
      [] e = "BufferLease" -> "NetOperation"

LiveStates == {"Registered", "Prepared", "Committed"}
TerminalStates == {"Completed", "Aborted"}
UncommittedStates == {"Registered", "Prepared"}

ChildrenTerminal(e, effectState, effectParent) ==
    \A child \in Effects :
        (effectParent[child] = e /\ effectState[child] # "Unused")
            => effectState[child] \in TerminalStates

GenerationMatches(e, effectSocketGeneration, socketGeneration,
        effectSourceGeneration, sourceGeneration) ==
    CASE e \in SocketEffects ->
            effectSocketGeneration[e] = socketGeneration
      [] e = "ReadinessWait" ->
            effectSourceGeneration[e] = sourceGeneration
      [] OTHER -> TRUE

StaleEnabled(kind, scopeState, bindingEpoch, socketGeneration,
        sourceGeneration, terminalCount) ==
    CASE kind = "Authority" -> scopeState \in {"Closing", "Revoked"}
      [] kind = "PersonalityBinding" -> bindingEpoch["Personality"] > 0
      [] kind = "NetworkBinding" -> bindingEpoch["Network"] > 0
      [] kind = "ReadinessBinding" -> bindingEpoch["Readiness"] > 0
      [] kind = "SocketGeneration" -> socketGeneration > 0
      [] kind = "SourceGeneration" -> sourceGeneration > 0
      [] kind = "CompletionReplay" ->
            \E e \in Effects : terminalCount[e] = 1

(* --algorithm RuntimeNetCSER
variables
    scopeState = "Absent",
    scopeGate = "Closed",
    authorityEpoch = 0,
    closingEpoch = NoGeneration,

    effectState = [e \in Effects |-> "Unused"],
    effectParent = [e \in Effects |-> NoParent],
    effectAuthority = [e \in Effects |-> NoGeneration],
    effectBinding = [e \in Effects |-> NoBinding],
    effectSocketGeneration = [e \in Effects |-> NoGeneration],
    effectSourceGeneration = [e \in Effects |-> NoGeneration],
    commitCount = [e \in Effects |-> 0],
    terminalCount = [e \in Effects |-> 0],

    freeCredits = [t \in CreditTypes |-> 1],

    bindingEpoch = [d \in Domains |-> 0],
    domainPhase = [d \in Domains |-> "Absent"],
    recoveryCohort = [d \in Domains |-> {}],
    snapshotBinding = [d \in Domains |-> NoBinding],
    snapshotCohort = [d \in Domains |-> {}],
    snapshotSocketGeneration = [d \in Domains |-> NoGeneration],
    snapshotSourceGeneration = [d \in Domains |-> NoGeneration],
    adoptCount = [d \in Domains |-> 0],
    adoptedEffects = {},

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
    guestResult = "None",

    netPublicationCount = 0,
    readyPublicationCount = 0,
    readyDeliveryCount = 0,
    guestCommitCount = 0,
    guestPublicationCount = 0,
    bufferConsumptionCount = 0,
    bufferClosureCount = 0,

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
            \* Create one root scope and install the three initial bindings.
            await scopeState = "Absent";
            scopeState := "Active";
            scopeGate := "Open";
            domainPhase := [d \in Domains |-> "Bound"];
        or
            \* Register the complete fixed graph failure-atomically.  Every
            \* effect captures authority, local binding, and applicable
            \* resource generations while taking exactly one typed credit.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ \A e \in Effects : effectState[e] = "Unused"
                  /\ \A d \in Domains : domainPhase[d] = "Bound"
                  /\ \A t \in CreditTypes : freeCredits[t] = 1;
            effectState := [e \in Effects |-> "Registered"];
            effectParent := [e \in Effects |-> AllowedParent(e)];
            effectAuthority := [e \in Effects |-> authorityEpoch];
            effectBinding :=
                [e \in Effects |-> bindingEpoch[EffectDomain(e)]];
            effectSocketGeneration :=
                [e \in Effects |-> socketGeneration];
            effectSourceGeneration :=
                [e \in Effects |-> sourceGeneration];
            freeCredits := [t \in CreditTypes |-> 0];
        or
            \* Listening and Pending are private setup states.  They are
            \* returned to Closed if revocation wins before NetCommit.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ scopeGate = "Open"
                      /\ effectState[e] = "Registered"
                      /\ effectAuthority[e] = authorityEpoch
                      /\ domainPhase[EffectDomain(e)] = "Bound"
                      /\ effectBinding[e] =
                            bindingEpoch[EffectDomain(e)]
                      /\ GenerationMatches(e, effectSocketGeneration,
                            socketGeneration, effectSourceGeneration,
                            sourceGeneration)
                      /\ (e # "NetOperation" \/ socketState = "Closed")
                      /\ (e # "BufferLease" \/
                            /\ effectState["NetOperation"] = "Prepared"
                            /\ socketState = "Listening");
                effectState[e] := "Prepared";
                if e = "NetOperation" then
                    socketState := "Listening";
                elsif e = "BufferLease" then
                    socketState := "Pending";
                end if;
            end with;
        or
            \* NetCommit is the first publication point.  It atomically
            \* publishes connected socket state, one four-byte payload, the
            \* BufferLease, and the successor socket generation.
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
                        /\ domainPhase[EffectDomain(e)] = "Bound"
                        /\ effectBinding[e] =
                            bindingEpoch[EffectDomain(e)]
                        /\ GenerationMatches(e,
                            effectSocketGeneration, socketGeneration,
                            effectSourceGeneration, sourceGeneration);
            effectState := [effectState EXCEPT
                !["NetOperation"] = "Committed",
                !["BufferLease"] = "Committed"];
            commitCount := [commitCount EXCEPT
                !["NetOperation"] = commitCount["NetOperation"] + 1,
                !["BufferLease"] = commitCount["BufferLease"] + 1];
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
            \* ReadyCommit consumes the exact NetCommit receipt and freezes a
            \* kernel-owned readiness receipt under its independent source
            \* generation.  Publication/drain remains a separate kernel step.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["ReadinessWait"] = "Prepared"
                  /\ effectState["NetOperation"] = "Committed"
                  /\ effectAuthority["ReadinessWait"] = authorityEpoch
                  /\ domainPhase["Readiness"] = "Bound"
                  /\ effectBinding["ReadinessWait"] =
                        bindingEpoch["Readiness"]
                  /\ GenerationMatches("ReadinessWait",
                        effectSocketGeneration, socketGeneration,
                        effectSourceGeneration, sourceGeneration)
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
            \* GuestReplyCommit is the third commit gate.  The ticket is
            \* immutable and the fair kernel publishes it exactly once.
            await /\ scopeState = "Active"
                  /\ scopeGate = "Open"
                  /\ effectState["Syscall"] = "Prepared"
                  /\ effectAuthority["Syscall"] = authorityEpoch
                  /\ domainPhase["Personality"] = "Bound"
                  /\ effectBinding["Syscall"] =
                        bindingEpoch["Personality"]
                  /\ effectState["NetOperation"] = "Completed"
                  /\ effectState["ReadinessWait"] = "Completed"
                  /\ readyDeliveryCount = 1
                  /\ guestCommitCount = 0;
            effectState["Syscall"] := "Committed";
            commitCount["Syscall"] := commitCount["Syscall"] + 1;
            guestCommitCount := guestCommitCount + 1;
            guestResult := "LoopbackOK";
        or
            \* Each domain may crash once, but recovery handshakes are kept
            \* sequential so the bounded graph stays tractable.  Only
            \* uncommitted old-binding work enters the adoption cohort.
            with d \in Domains do
                await /\ EnableCrash
                      /\ scopeState = "Active"
                      /\ domainPhase[d] = "Bound"
                      /\ bindingEpoch[d] < MaxBinding
                      /\ \A other \in Domains :
                            domainPhase[other] = "Bound"
                      /\ \A other \in Domains :
                            recoveryCohort[other] = {}
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
                snapshotSocketGeneration[d] := NoGeneration;
                snapshotSourceGeneration[d] := NoGeneration;
            end with;
        or
            \* Capture or refresh the exact generation/cohort snapshot after
            \* kernel fallback is running.  A stale ready proof can therefore
            \* return to this step rather than being silently accepted.
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] \in
                            {"Fallback", "Snapshotted", "Ready"};
                snapshotBinding[d] := bindingEpoch[d];
                snapshotCohort[d] := recoveryCohort[d];
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
                      /\ snapshotSocketGeneration[d] = socketGeneration
                      /\ snapshotSourceGeneration[d] = sourceGeneration;
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
                adoptedEffects := adoptedEffects \cup {e};
                adoptCount[d] := adoptCount[d] + 1;
            end with;
        or
            \* The peer consumes the retained payload.  This is deliberately
            \* an unfair service/environment action; root closure has a
            \* separate kernel-owned drain below and assumes no peer fairness.
            await /\ scopeState = "Active"
                  /\ domainPhase["Network"] = "Bound"
                  /\ effectBinding["BufferLease"] =
                        bindingEpoch["Network"]
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
            \* Present one stale full token or duplicate completion.  The
            \* bounded audit set is the only state allowed to change.
            with kind \in RejectKinds \ rejectKinds do
                await /\ EnableRejects
                      /\ StaleEnabled(kind, scopeState, bindingEpoch,
                            socketGeneration, sourceGeneration,
                            terminalCount);
                rejectKinds := rejectKinds \cup {kind};
            end with;
        or
            \* RevokeBegin closes all three old-authority commit gates and
            \* freezes the exact live cohort in one root-owned step.
            await scopeState = "Active";
            effectsAtClose :=
                {e \in Effects : effectState[e] # "Unused"};
            closingEffects :=
                {e \in Effects : effectState[e] \in LiveStates};
            committedAtClose :=
                {e \in Effects :
                    /\ commitCount[e] = 1
                    /\ effectState[e] \in LiveStates};
            commitAtClose := commitCount;
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeGate := "Closed";
            scopeState := "Closing";
            domainPhase := [d \in Domains |-> "Closed"];
            recoveryCohort := [d \in Domains |-> {}];
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            \* Kernel fallback is fair; snapshot, Ready, Rebind, and Adopt are
            \* user-service actions and intentionally receive no fairness.
            with d \in Domains do
                await /\ scopeState = "Active"
                      /\ domainPhase[d] = "Down";
                domainPhase[d] := "Fallback";
            end with;
        or
            \* A committed readiness receipt is kernel-owned and drains even
            \* across readiness-service crash or root closure.
            await /\ scopeState \in {"Active", "Closing"}
                  /\ effectState["ReadinessWait"] = "Committed";
            effectState["ReadinessWait"] := "Completed";
            terminalCount["ReadinessWait"] :=
                terminalCount["ReadinessWait"] + 1;
            readyDeliveryCount := readyDeliveryCount + 1;
            freeCredits["Readiness"] :=
                freeCredits["Readiness"] + 1;
        or
            \* A committed guest ticket is likewise kernel-owned.
            await /\ scopeState \in {"Active", "Closing"}
                  /\ effectState["Syscall"] = "Committed";
            effectState["Syscall"] := "Completed";
            terminalCount["Syscall"] :=
                terminalCount["Syscall"] + 1;
            guestPublicationCount := guestPublicationCount + 1;
            freeCredits["Control"] := freeCredits["Control"] + 1;
        or
            \* Root closure may drain an already committed lease without
            \* pretending the peer consumed it.  The immutable NetCommit
            \* receipt and payload history remain; only queue ownership and
            \* the retained Buffer credit are released.
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
            \* Revocation aborts only work that did not cross its own commit
            \* point, and it does so child-first.  Private socket staging is
            \* discarded without publishing socket state or payload bytes.
            with e \in Effects do
                await /\ scopeState = "Closing"
                      /\ effectState[e] \in UncommittedStates
                      /\ ChildrenTerminal(e, effectState, effectParent);
                effectState[e] := "Aborted";
                terminalCount[e] := terminalCount[e] + 1;
                freeCredits[EffectCredit(e)] :=
                    freeCredits[EffectCredit(e)] + 1;
                if e = "BufferLease" /\ socketState = "Pending" then
                    socketState := "Listening";
                elsif e = "NetOperation" /\
                        socketState = "Listening" then
                    socketState := "Closed";
                end if;
            end with;
        or
            \* The committed network operation drains only after both fixed
            \* children are terminal.  Its already published payload/history
            \* is not rolled back.
            await /\ effectState["NetOperation"] = "Committed"
                  /\ ChildrenTerminal("NetOperation", effectState,
                        effectParent);
            effectState["NetOperation"] := "Completed";
            terminalCount["NetOperation"] :=
                terminalCount["NetOperation"] + 1;
            socketState := "HalfClosed";
            freeCredits["Network"] := freeCredits["Network"] + 1;
        or
            await /\ scopeState = "Closing"
                  /\ \A e \in closingEffects :
                        effectState[e] \in TerminalStates
                  /\ \A t \in CreditTypes : freeCredits[t] = 1
                  /\ bufferState # "Queued"
                  /\ ~sourceReady;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "1652dc89" /\ chksum(tla) = "f571fc53")
VARIABLES scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, readyDeliveryCount, guestCommitCount, guestPublicationCount, bufferConsumptionCount, bufferClosureCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds

vars == << scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, readyDeliveryCount, guestCommitCount, guestPublicationCount, bufferConsumptionCount, bufferClosureCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scopeState = "Absent"
        /\ scopeGate = "Closed"
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectState = [e \in Effects |-> "Unused"]
        /\ effectParent = [e \in Effects |-> NoParent]
        /\ effectAuthority = [e \in Effects |-> NoGeneration]
        /\ effectBinding = [e \in Effects |-> NoBinding]
        /\ effectSocketGeneration = [e \in Effects |-> NoGeneration]
        /\ effectSourceGeneration = [e \in Effects |-> NoGeneration]
        /\ commitCount = [e \in Effects |-> 0]
        /\ terminalCount = [e \in Effects |-> 0]
        /\ freeCredits = [t \in CreditTypes |-> 1]
        /\ bindingEpoch = [d \in Domains |-> 0]
        /\ domainPhase = [d \in Domains |-> "Absent"]
        /\ recoveryCohort = [d \in Domains |-> {}]
        /\ snapshotBinding = [d \in Domains |-> NoBinding]
        /\ snapshotCohort = [d \in Domains |-> {}]
        /\ snapshotSocketGeneration = [d \in Domains |-> NoGeneration]
        /\ snapshotSourceGeneration = [d \in Domains |-> NoGeneration]
        /\ adoptCount = [d \in Domains |-> 0]
        /\ adoptedEffects = {}
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
        /\ guestResult = "None"
        /\ netPublicationCount = 0
        /\ readyPublicationCount = 0
        /\ readyDeliveryCount = 0
        /\ guestCommitCount = 0
        /\ guestPublicationCount = 0
        /\ bufferConsumptionCount = 0
        /\ bufferClosureCount = 0
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ committedAtClose = {}
        /\ commitAtClose = [e \in Effects |-> 0]
        /\ rejectKinds = {}

Environment == /\ \/ /\ scopeState = "Absent"
                     /\ scopeState' = "Active"
                     /\ scopeGate' = "Open"
                     /\ domainPhase' = [d \in Domains |-> "Bound"]
                     /\ UNCHANGED <<authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ \A e \in Effects : effectState[e] = "Unused"
                        /\ \A d \in Domains : domainPhase[d] = "Bound"
                        /\ \A t \in CreditTypes : freeCredits[t] = 1
                     /\ effectState' = [e \in Effects |-> "Registered"]
                     /\ effectParent' = [e \in Effects |-> AllowedParent(e)]
                     /\ effectAuthority' = [e \in Effects |-> authorityEpoch]
                     /\ effectBinding' = [e \in Effects |-> bindingEpoch[EffectDomain(e)]]
                     /\ effectSocketGeneration' = [e \in Effects |-> socketGeneration]
                     /\ effectSourceGeneration' = [e \in Effects |-> sourceGeneration]
                     /\ freeCredits' = [t \in CreditTypes |-> 0]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, commitCount, terminalCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E e \in Effects:
                          /\ /\ scopeState = "Active"
                             /\ scopeGate = "Open"
                             /\ effectState[e] = "Registered"
                             /\ effectAuthority[e] = authorityEpoch
                             /\ domainPhase[EffectDomain(e)] = "Bound"
                             /\ effectBinding[e] =
                                   bindingEpoch[EffectDomain(e)]
                             /\ GenerationMatches(e, effectSocketGeneration,
                                   socketGeneration, effectSourceGeneration,
                                   sourceGeneration)
                             /\ (e # "NetOperation" \/ socketState = "Closed")
                             /\ (e # "BufferLease" \/
                                   /\ effectState["NetOperation"] = "Prepared"
                                   /\ socketState = "Listening")
                          /\ effectState' = [effectState EXCEPT ![e] = "Prepared"]
                          /\ IF e = "NetOperation"
                                THEN /\ socketState' = "Listening"
                                ELSE /\ IF e = "BufferLease"
                                           THEN /\ socketState' = "Pending"
                                           ELSE /\ TRUE
                                                /\ UNCHANGED socketState
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
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
                              /\ domainPhase[EffectDomain(e)] = "Bound"
                              /\ effectBinding[e] =
                                  bindingEpoch[EffectDomain(e)]
                              /\ GenerationMatches(e,
                                  effectSocketGeneration, socketGeneration,
                                  effectSourceGeneration, sourceGeneration)
                     /\ effectState' =            [effectState EXCEPT
                                       !["NetOperation"] = "Committed",
                                       !["BufferLease"] = "Committed"]
                     /\ commitCount' =            [commitCount EXCEPT
                                       !["NetOperation"] = commitCount["NetOperation"] + 1,
                                       !["BufferLease"] = commitCount["BufferLease"] + 1]
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
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, sourceGeneration, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["ReadinessWait"] = "Prepared"
                        /\ effectState["NetOperation"] = "Committed"
                        /\ effectAuthority["ReadinessWait"] = authorityEpoch
                        /\ domainPhase["Readiness"] = "Bound"
                        /\ effectBinding["ReadinessWait"] =
                              bindingEpoch["Readiness"]
                        /\ GenerationMatches("ReadinessWait",
                              effectSocketGeneration, socketGeneration,
                              effectSourceGeneration, sourceGeneration)
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
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, guestResult, netPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ scopeState = "Active"
                        /\ scopeGate = "Open"
                        /\ effectState["Syscall"] = "Prepared"
                        /\ effectAuthority["Syscall"] = authorityEpoch
                        /\ domainPhase["Personality"] = "Bound"
                        /\ effectBinding["Syscall"] =
                              bindingEpoch["Personality"]
                        /\ effectState["NetOperation"] = "Completed"
                        /\ effectState["ReadinessWait"] = "Completed"
                        /\ readyDeliveryCount = 1
                        /\ guestCommitCount = 0
                     /\ effectState' = [effectState EXCEPT !["Syscall"] = "Committed"]
                     /\ commitCount' = [commitCount EXCEPT !["Syscall"] = commitCount["Syscall"] + 1]
                     /\ guestCommitCount' = guestCommitCount + 1
                     /\ guestResult' = "LoopbackOK"
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, netPublicationCount, readyPublicationCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ EnableCrash
                             /\ scopeState = "Active"
                             /\ domainPhase[d] = "Bound"
                             /\ bindingEpoch[d] < MaxBinding
                             /\ \A other \in Domains :
                                   domainPhase[other] = "Bound"
                             /\ \A other \in Domains :
                                   recoveryCohort[other] = {}
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
                          /\ snapshotSocketGeneration' = [snapshotSocketGeneration EXCEPT ![d] = NoGeneration]
                          /\ snapshotSourceGeneration' = [snapshotSourceGeneration EXCEPT ![d] = NoGeneration]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] \in
                                   {"Fallback", "Snapshotted", "Ready"}
                          /\ snapshotBinding' = [snapshotBinding EXCEPT ![d] = bindingEpoch[d]]
                          /\ snapshotCohort' = [snapshotCohort EXCEPT ![d] = recoveryCohort[d]]
                          /\ snapshotSocketGeneration' = [snapshotSocketGeneration EXCEPT ![d] = socketGeneration]
                          /\ snapshotSourceGeneration' = [snapshotSourceGeneration EXCEPT ![d] = sourceGeneration]
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Snapshotted"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Snapshotted"
                             /\ snapshotBinding[d] = bindingEpoch[d]
                             /\ snapshotCohort[d] = recoveryCohort[d]
                             /\ snapshotSocketGeneration[d] = socketGeneration
                             /\ snapshotSourceGeneration[d] = sourceGeneration
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Ready"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          /\ /\ scopeState = "Active"
                             /\ domainPhase[d] = "Ready"
                             /\ snapshotBinding[d] = bindingEpoch[d]
                             /\ snapshotCohort[d] = recoveryCohort[d]
                             /\ snapshotSocketGeneration[d] = socketGeneration
                             /\ snapshotSourceGeneration[d] = sourceGeneration
                          /\ domainPhase' = [domainPhase EXCEPT ![d] = "Bound"]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E d \in Domains:
                          \E e \in recoveryCohort[d]:
                            /\ /\ scopeState = "Active"
                               /\ domainPhase[d] = "Bound"
                               /\ effectState[e] \in UncommittedStates
                               /\ effectBinding[e] # bindingEpoch[d]
                            /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch[d]]
                            /\ recoveryCohort' = [recoveryCohort EXCEPT ![d] = recoveryCohort[d] \ {e}]
                            /\ adoptedEffects' = (adoptedEffects \cup {e})
                            /\ adoptCount' = [adoptCount EXCEPT ![d] = adoptCount[d] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ /\ scopeState = "Active"
                        /\ domainPhase["Network"] = "Bound"
                        /\ effectBinding["BufferLease"] =
                              bindingEpoch["Network"]
                        /\ effectState["BufferLease"] = "Committed"
                        /\ bufferState = "Queued"
                        /\ bufferPayload = "Ping4"
                     /\ effectState' = [effectState EXCEPT !["BufferLease"] = "Completed"]
                     /\ terminalCount' = [terminalCount EXCEPT !["BufferLease"] = terminalCount["BufferLease"] + 1]
                     /\ bufferState' = "Consumed"
                     /\ sourceReady' = FALSE
                     /\ bufferConsumptionCount' = bufferConsumptionCount + 1
                     /\ freeCredits' = [freeCredits EXCEPT !["Buffer"] = freeCredits["Buffer"] + 1]
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds>>
                  \/ /\ \E kind \in RejectKinds \ rejectKinds:
                          /\ /\ EnableRejects
                             /\ StaleEnabled(kind, scopeState, bindingEpoch,
                                   socketGeneration, sourceGeneration,
                                   terminalCount)
                          /\ rejectKinds' = (rejectKinds \cup {kind})
                     /\ UNCHANGED <<scopeState, scopeGate, authorityEpoch, closingEpoch, effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose>>
                  \/ /\ scopeState = "Active"
                     /\ effectsAtClose' = {e \in Effects : effectState[e] # "Unused"}
                     /\ closingEffects' = {e \in Effects : effectState[e] \in LiveStates}
                     /\ committedAtClose' = {e \in Effects :
                                                /\ commitCount[e] = 1
                                                /\ effectState[e] \in LiveStates}
                     /\ commitAtClose' = commitCount
                     /\ closingEpoch' = authorityEpoch
                     /\ authorityEpoch' = authorityEpoch + 1
                     /\ scopeGate' = "Closed"
                     /\ scopeState' = "Closing"
                     /\ domainPhase' = [d \in Domains |-> "Closed"]
                     /\ recoveryCohort' = [d \in Domains |-> {}]
                     /\ UNCHANGED <<effectState, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, terminalCount, freeCredits, bindingEpoch, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, socketState, sourceGeneration, sourceReady, bufferState, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, rejectKinds>>
               /\ UNCHANGED << readyDeliveryCount, guestPublicationCount, bufferClosureCount >>

Kernel == /\ \/ /\ \E d \in Domains:
                     /\ /\ scopeState = "Active"
                        /\ domainPhase[d] = "Down"
                     /\ domainPhase' = [domainPhase EXCEPT ![d] = "Fallback"]
                /\ UNCHANGED <<scopeState, effectState, terminalCount, freeCredits, socketState, sourceReady, bufferState, readyDeliveryCount, guestPublicationCount, bufferClosureCount>>
             \/ /\ /\ scopeState \in {"Active", "Closing"}
                   /\ effectState["ReadinessWait"] = "Committed"
                /\ effectState' = [effectState EXCEPT !["ReadinessWait"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["ReadinessWait"] = terminalCount["ReadinessWait"] + 1]
                /\ readyDeliveryCount' = readyDeliveryCount + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Readiness"] = freeCredits["Readiness"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, socketState, sourceReady, bufferState, guestPublicationCount, bufferClosureCount>>
             \/ /\ /\ scopeState \in {"Active", "Closing"}
                   /\ effectState["Syscall"] = "Committed"
                /\ effectState' = [effectState EXCEPT !["Syscall"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["Syscall"] = terminalCount["Syscall"] + 1]
                /\ guestPublicationCount' = guestPublicationCount + 1
                /\ freeCredits' = [freeCredits EXCEPT !["Control"] = freeCredits["Control"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, socketState, sourceReady, bufferState, readyDeliveryCount, bufferClosureCount>>
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
                /\ UNCHANGED <<scopeState, domainPhase, socketState, readyDeliveryCount, guestPublicationCount>>
             \/ /\ \E e \in Effects:
                     /\ /\ scopeState = "Closing"
                        /\ effectState[e] \in UncommittedStates
                        /\ ChildrenTerminal(e, effectState, effectParent)
                     /\ effectState' = [effectState EXCEPT ![e] = "Aborted"]
                     /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                     /\ freeCredits' = [freeCredits EXCEPT ![EffectCredit(e)] = freeCredits[EffectCredit(e)] + 1]
                     /\ IF e = "BufferLease" /\ socketState = "Pending"
                           THEN /\ socketState' = "Listening"
                           ELSE /\ IF e = "NetOperation" /\
                                        socketState = "Listening"
                                      THEN /\ socketState' = "Closed"
                                      ELSE /\ TRUE
                                           /\ UNCHANGED socketState
                /\ UNCHANGED <<scopeState, domainPhase, sourceReady, bufferState, readyDeliveryCount, guestPublicationCount, bufferClosureCount>>
             \/ /\ /\ effectState["NetOperation"] = "Committed"
                   /\ ChildrenTerminal("NetOperation", effectState,
                         effectParent)
                /\ effectState' = [effectState EXCEPT !["NetOperation"] = "Completed"]
                /\ terminalCount' = [terminalCount EXCEPT !["NetOperation"] = terminalCount["NetOperation"] + 1]
                /\ socketState' = "HalfClosed"
                /\ freeCredits' = [freeCredits EXCEPT !["Network"] = freeCredits["Network"] + 1]
                /\ UNCHANGED <<scopeState, domainPhase, sourceReady, bufferState, readyDeliveryCount, guestPublicationCount, bufferClosureCount>>
             \/ /\ /\ scopeState = "Closing"
                   /\ \A e \in closingEffects :
                         effectState[e] \in TerminalStates
                   /\ \A t \in CreditTypes : freeCredits[t] = 1
                   /\ bufferState # "Queued"
                   /\ ~sourceReady
                /\ scopeState' = "Revoked"
                /\ UNCHANGED <<effectState, terminalCount, freeCredits, domainPhase, socketState, sourceReady, bufferState, readyDeliveryCount, guestPublicationCount, bufferClosureCount>>
          /\ UNCHANGED << scopeGate, authorityEpoch, closingEpoch, effectParent, effectAuthority, effectBinding, effectSocketGeneration, effectSourceGeneration, commitCount, bindingEpoch, recoveryCohort, snapshotBinding, snapshotCohort, snapshotSocketGeneration, snapshotSourceGeneration, adoptCount, adoptedEffects, socketGeneration, sourceGeneration, bufferPayload, netReceiptSocketGeneration, netReceiptPayload, frozenReady, frozenSocketGeneration, frozenSourceGeneration, frozenPayload, guestResult, netPublicationCount, readyPublicationCount, guestCommitCount, bufferConsumptionCount, effectsAtClose, closingEffects, committedAtClose, commitAtClose, rejectKinds >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

TypeOK ==
    /\ scopeState \in {"Absent", "Active", "Closing", "Revoked"}
    /\ scopeGate \in {"Open", "Closed"}
    /\ authorityEpoch \in 0..1
    /\ closingEpoch \in {NoGeneration, 0}
    /\ effectState \in [Effects ->
        {"Unused", "Registered", "Prepared", "Committed",
         "Completed", "Aborted"}]
    /\ effectParent \in [Effects -> Effects \cup {Root, NoParent}]
    /\ effectAuthority \in [Effects -> {NoGeneration, 0}]
    /\ effectBinding \in [Effects -> NoBinding..MaxBinding]
    /\ effectSocketGeneration \in [Effects -> {NoGeneration, 0}]
    /\ effectSourceGeneration \in [Effects -> {NoGeneration, 0}]
    /\ commitCount \in [Effects -> 0..1]
    /\ terminalCount \in [Effects -> 0..1]
    /\ freeCredits \in [CreditTypes -> 0..1]
    /\ bindingEpoch \in [Domains -> 0..MaxBinding]
    /\ domainPhase \in [Domains ->
        {"Absent", "Bound", "Down", "Fallback", "Snapshotted",
         "Ready", "Closed"}]
    /\ \A d \in Domains : recoveryCohort[d] \subseteq Effects
    /\ \A d \in Domains : snapshotCohort[d] \subseteq Effects
    /\ snapshotBinding \in [Domains -> NoBinding..MaxBinding]
    /\ snapshotSocketGeneration \in [Domains -> NoGeneration..1]
    /\ snapshotSourceGeneration \in [Domains -> NoGeneration..1]
    /\ adoptCount \in [Domains -> 0..2]
    /\ adoptedEffects \subseteq Effects
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
    /\ guestResult \in {"None", "LoopbackOK"}
    /\ netPublicationCount \in 0..1
    /\ readyPublicationCount \in 0..1
    /\ readyDeliveryCount \in 0..1
    /\ guestCommitCount \in 0..1
    /\ guestPublicationCount \in 0..1
    /\ bufferConsumptionCount \in 0..1
    /\ bufferClosureCount \in 0..1
    /\ effectsAtClose \subseteq Effects
    /\ closingEffects \subseteq Effects
    /\ committedAtClose \subseteq Effects
    /\ commitAtClose \in [Effects -> 0..1]
    /\ rejectKinds \subseteq RejectKinds

ScopeGateDiscipline ==
    /\ (scopeState = "Active" <=> scopeGate = "Open")
    /\ (scopeState \in {"Absent", "Closing", "Revoked"} <=>
        scopeGate = "Closed")
    /\ (scopeState = "Absent" =>
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ \A d \in Domains : domainPhase[d] = "Absent"
        /\ \A e \in Effects : effectState[e] = "Unused")
    /\ (scopeState = "Active" =>
        /\ authorityEpoch = 0
        /\ closingEpoch = NoGeneration
        /\ effectsAtClose = {}
        /\ closingEffects = {}
        /\ committedAtClose = {})
    /\ (scopeState \in {"Closing", "Revoked"} =>
        /\ authorityEpoch = 1
        /\ closingEpoch = 0
        /\ \A d \in Domains : domainPhase[d] = "Closed")

FixedCausalGraph ==
    /\ ((\A e \in Effects : effectState[e] = "Unused") \/
        (\A e \in Effects : effectState[e] # "Unused"))
    /\ \A e \in Effects :
        /\ (effectState[e] = "Unused" =>
            /\ effectParent[e] = NoParent
            /\ effectAuthority[e] = NoGeneration
            /\ effectBinding[e] = NoBinding
            /\ effectSocketGeneration[e] = NoGeneration
            /\ effectSourceGeneration[e] = NoGeneration)
        /\ (effectState[e] # "Unused" =>
            /\ effectParent[e] = AllowedParent(e)
            /\ effectAuthority[e] = 0
            /\ effectBinding[e] \in 0..bindingEpoch[EffectDomain(e)]
            /\ effectSocketGeneration[e] = 0
            /\ effectSourceGeneration[e] = 0)
    /\ \A e \in Effects \ {"Syscall"} :
        effectState[e] # "Unused" =>
            effectState[AllowedParent(e)] # "Unused"

EffectLifecycle ==
    \A e \in Effects :
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

TypedCreditConservation ==
    \A t \in CreditTypes :
        freeCredits[t]
        + Cardinality({e \in Effects :
            EffectCredit(e) = t /\ effectState[e] \in LiveStates}) = 1

NetworkPublicationDiscipline ==
    /\ netPublicationCount = commitCount["NetOperation"]
    /\ netPublicationCount = commitCount["BufferLease"]
    /\ socketGeneration = netPublicationCount
    /\ bufferConsumptionCount + bufferClosureCount <=
        netPublicationCount
    /\ (netPublicationCount = 0 =>
        /\ netReceiptSocketGeneration = NoGeneration
        /\ netReceiptPayload = "None"
        /\ bufferPayload = "None"
        /\ bufferState = "Empty"
        /\ socketState \in {"Closed", "Listening", "Pending"}
        /\ ~sourceReady)
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
    /\ (bufferConsumptionCount + bufferClosureCount = 1 <=>
        bufferState = "Consumed")
    /\ (sourceReady <=> bufferState = "Queued")
    /\ (socketState = "Listening" =>
        effectState["NetOperation"] = "Prepared")
    /\ (socketState = "Pending" =>
        /\ effectState["NetOperation"] = "Prepared"
        /\ effectState["BufferLease"] = "Prepared")
    /\ (socketState = "Connected" =>
        effectState["NetOperation"] = "Committed")
    /\ (socketState = "HalfClosed" <=>
        effectState["NetOperation"] = "Completed")
    /\ (effectState["NetOperation"] = "Aborted" =>
        socketState = "Closed")

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
        /\ netPublicationCount = 1
        /\ effectState["ReadinessWait"] \in
            {"Committed", "Completed"})
    /\ (readyDeliveryCount = 1 <=>
        effectState["ReadinessWait"] = "Completed")

GuestPublicationDiscipline ==
    /\ guestCommitCount = commitCount["Syscall"]
    /\ guestPublicationCount <= guestCommitCount
    /\ (guestCommitCount = 0 <=> guestResult = "None")
    /\ (guestCommitCount = 1 <=> guestResult = "LoopbackOK")
    /\ (guestCommitCount = 1 =>
        /\ effectState["NetOperation"] = "Completed"
        /\ effectState["ReadinessWait"] = "Completed"
        /\ readyDeliveryCount = 1)
    /\ (guestPublicationCount = 1 <=>
        effectState["Syscall"] = "Completed")

CrashIsolation ==
    /\ \A d \in Domains :
        domainPhase[d] \in {"Down", "Fallback", "Snapshotted", "Ready"}
            => /\ scopeState = "Active"
               /\ bindingEpoch[d] = 1
    /\ \A d \in Domains :
        adoptCount[d] = Cardinality({e \in adoptedEffects :
            EffectDomain(e) = d})
    /\ \A e \in adoptedEffects :
        /\ effectState[e] # "Unused"
        /\ bindingEpoch[EffectDomain(e)] = 1
        /\ effectBinding[e] = 1
    /\ \A e \in Effects :
        effectBinding[e] = 1 => e \in adoptedEffects

RecoveryDiscipline ==
    \A d \in Domains :
        /\ \A e \in recoveryCohort[d] :
            /\ EffectDomain(e) = d
            /\ effectState[e] \in UncommittedStates
            /\ effectBinding[e] # bindingEpoch[d]
        /\ (bindingEpoch[d] = 0 => recoveryCohort[d] = {})
        /\ (scopeState = "Active" /\ bindingEpoch[d] = 1 =>
            recoveryCohort[d] =
                {e \in Effects :
                    /\ EffectDomain(e) = d
                    /\ effectState[e] \in UncommittedStates
                    /\ effectBinding[e] # bindingEpoch[d]})
        /\ (domainPhase[d] = "Ready" =>
            /\ snapshotBinding[d] = bindingEpoch[d]
            /\ snapshotCohort[d] = recoveryCohort[d]
            /\ snapshotSocketGeneration[d] = socketGeneration
            /\ snapshotSourceGeneration[d] = sourceGeneration)
        /\ (domainPhase[d] = "Closed" => recoveryCohort[d] = {})

FrozenClosureCohort ==
    scopeState \in {"Closing", "Revoked"} =>
        /\ effectsAtClose =
            {e \in Effects : effectState[e] # "Unused"}
        /\ closingEffects \subseteq effectsAtClose
        /\ committedAtClose =
            {e \in closingEffects : commitAtClose[e] = 1}

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} => commitCount = commitAtClose

NoPostRevokeDerivation ==
    scopeState \in {"Closing", "Revoked"} =>
        effectsAtClose = {e \in Effects : effectState[e] # "Unused"}

SingleTerminalization ==
    \A e \in Effects : terminalCount[e] <= 1

QuiescentClosure ==
    scopeState = "Revoked" =>
        /\ \A e \in Effects :
            effectState[e] = "Unused" \/ effectState[e] \in TerminalStates
        /\ \A e \in closingEffects : effectState[e] \in TerminalStates
        /\ \A t \in CreditTypes : freeCredits[t] = 1
        /\ bufferState \in {"Empty", "Consumed"}
        /\ ~sourceReady
        /\ \A d \in Domains : recoveryCohort[d] = {}

CausalEdgeImmutability ==
    [][\A e \in Effects :
        effectParent[e] # NoParent =>
            effectParent'[e] = effectParent[e]]_vars

CommitGateAction ==
    [][\A e \in Effects : commitCount'[e] > commitCount[e] =>
        /\ scopeState = "Active"
        /\ scopeGate = "Open"
        /\ effectAuthority[e] = authorityEpoch
        /\ domainPhase[EffectDomain(e)] = "Bound"
        /\ effectBinding[e] = bindingEpoch[EffectDomain(e)]
        /\ GenerationMatches(e, effectSocketGeneration,
            socketGeneration, effectSourceGeneration, sourceGeneration)]_vars

DomainBindingIsolation ==
    [][bindingEpoch' # bindingEpoch =>
        /\ Cardinality({d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d]}) = 1
        /\ \A d \in Domains :
            bindingEpoch'[d] # bindingEpoch[d] =>
                bindingEpoch'[d] = bindingEpoch[d] + 1
        /\ UNCHANGED <<authorityEpoch, socketGeneration,
            sourceGeneration>>]_vars

GenerationIsolation ==
    [][/\ (authorityEpoch' # authorityEpoch =>
            /\ scopeState = "Active"
            /\ scopeState' = "Closing"
            /\ authorityEpoch' = authorityEpoch + 1
            /\ UNCHANGED <<bindingEpoch, socketGeneration,
                sourceGeneration>>)
        /\ (socketGeneration' # socketGeneration =>
            /\ socketGeneration' = socketGeneration + 1
            /\ netPublicationCount' = netPublicationCount + 1
            /\ UNCHANGED <<authorityEpoch, bindingEpoch,
                sourceGeneration>>)
        /\ (sourceGeneration' # sourceGeneration =>
            /\ sourceGeneration' = sourceGeneration + 1
            /\ readyPublicationCount' = readyPublicationCount + 1
            /\ UNCHANGED <<authorityEpoch, bindingEpoch,
                socketGeneration>>)]_vars

ExplicitAdoptionAction ==
    [][(\E changed \in Effects :
            /\ effectState[changed] # "Unused"
            /\ effectBinding'[changed] # effectBinding[changed]) =>
        /\ Cardinality({e \in Effects :
            effectBinding'[e] # effectBinding[e]}) = 1
        /\ \A e \in Effects :
            effectBinding'[e] # effectBinding[e] =>
                /\ effectState[e] \in UncommittedStates
                /\ effectBinding'[e] =
                    bindingEpoch[EffectDomain(e)]
                /\ e \notin adoptedEffects
                /\ e \in adoptedEffects']_vars

RejectSideEffectFreedom ==
    [][rejectKinds' # rejectKinds => UNCHANGED <<
        scopeState, scopeGate, authorityEpoch, closingEpoch,
        effectState, effectParent, effectAuthority, effectBinding,
        effectSocketGeneration, effectSourceGeneration,
        commitCount, terminalCount, freeCredits, bindingEpoch, domainPhase,
        recoveryCohort, snapshotBinding, snapshotCohort,
        snapshotSocketGeneration, snapshotSourceGeneration,
        adoptCount, adoptedEffects, socketGeneration, socketState,
        sourceGeneration, sourceReady, bufferState, bufferPayload,
        netReceiptSocketGeneration, netReceiptPayload, frozenReady,
        frozenSocketGeneration, frozenSourceGeneration, frozenPayload,
        guestResult, netPublicationCount, readyPublicationCount,
        readyDeliveryCount, guestCommitCount, guestPublicationCount,
        bufferConsumptionCount, bufferClosureCount,
        effectsAtClose, closingEffects,
        committedAtClose, commitAtClose
    >>]_vars

ReceiptImmutability ==
    [][/\ (netPublicationCount = 1 => UNCHANGED <<
            netReceiptSocketGeneration, netReceiptPayload, bufferPayload>>)
        /\ (readyPublicationCount = 1 => UNCHANGED <<
            frozenReady, frozenSocketGeneration,
            frozenSourceGeneration, frozenPayload>>)
        /\ (guestCommitCount = 1 => UNCHANGED guestResult)]_vars

ReadyForNetworkDrain ==
    /\ effectState["NetOperation"] = "Committed"
    /\ ChildrenTerminal("NetOperation", effectState, effectParent)

ReadyForRevokeComplete ==
    /\ scopeState = "Closing"
    /\ \A e \in closingEffects : effectState[e] \in TerminalStates
    /\ \A t \in CreditTypes : freeCredits[t] = 1
    /\ bufferState # "Queued"
    /\ ~sourceReady

ConditionalFallbackProgress ==
    \A d \in Domains :
        [](domainPhase[d] = "Down" ~> domainPhase[d] # "Down")

CommittedReadinessDrainProgress ==
    [](effectState["ReadinessWait"] = "Committed" ~>
        effectState["ReadinessWait"] = "Completed")

CommittedGuestReplyProgress ==
    [](effectState["Syscall"] = "Committed" ~>
        effectState["Syscall"] = "Completed")

CommittedBufferClosureProgress ==
    []((scopeState = "Closing" /\
        effectState["BufferLease"] = "Committed") ~>
        effectState["BufferLease"] = "Completed")

ConditionalNetworkDrainProgress ==
    [](ReadyForNetworkDrain ~>
        effectState["NetOperation"] = "Completed")

ConditionalRevocationProgress ==
    [](ReadyForRevokeComplete ~> scopeState = "Revoked")

LoopbackClosure ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ \A e \in Effects : effectState[e] = "Completed"
    /\ netPublicationCount = 1
    /\ readyPublicationCount = 1
    /\ readyDeliveryCount = 1
    /\ guestCommitCount = 1
    /\ guestPublicationCount = 1
    /\ bufferConsumptionCount = 1
    /\ bufferClosureCount = 0
    /\ socketState = "HalfClosed"
    /\ bufferState = "Consumed"
    /\ bufferPayload = "Ping4"
    /\ \A t \in CreditTypes : freeCredits[t] = 1

RevokeBeforeNetCommit ==
    /\ scopeState = "Revoked"
    /\ effectsAtClose = Effects
    /\ \A e \in Effects : effectState[e] = "Aborted"
    /\ commitAtClose["NetOperation"] = 0
    /\ netPublicationCount = 0
    /\ readyPublicationCount = 0
    /\ guestPublicationCount = 0
    /\ socketGeneration = 0
    /\ socketState = "Closed"
    /\ bufferState = "Empty"
    /\ bufferPayload = "None"

NetdCrashAdoptAccept ==
    /\ scopeState = "Active"
    /\ bindingEpoch["Network"] = 1
    /\ domainPhase["Network"] = "Bound"
    /\ snapshotBinding["Network"] = 1
    /\ recoveryCohort["Network"] = {}
    /\ adoptCount["Network"] = 2
    /\ {"NetOperation", "BufferLease"} \subseteq adoptedEffects
    /\ effectBinding["NetOperation"] = 1
    /\ effectBinding["BufferLease"] = 1
    /\ netPublicationCount = 1
    /\ socketState = "Connected"
    /\ bufferState = "Queued"

ReadinessBeforeRevoke ==
    /\ scopeState = "Revoked"
    /\ commitAtClose["ReadinessWait"] = 1
    /\ readyPublicationCount = 1
    /\ readyDeliveryCount = 1
    /\ guestCommitCount = 0
    /\ guestPublicationCount = 0
    /\ effectState["ReadinessWait"] = "Completed"
    /\ effectState["BufferLease"] = "Completed"
    /\ effectState["NetOperation"] = "Completed"
    /\ effectState["Syscall"] = "Aborted"
    /\ bufferState = "Consumed"
    /\ bufferConsumptionCount = 0
    /\ bufferClosureCount = 1
    /\ socketState = "HalfClosed"

RevokeBeforeReadiness ==
    /\ scopeState = "Revoked"
    /\ commitAtClose["NetOperation"] = 1
    /\ commitAtClose["ReadinessWait"] = 0
    /\ netPublicationCount = 1
    /\ readyPublicationCount = 0
    /\ readyDeliveryCount = 0
    /\ guestPublicationCount = 0
    /\ effectState["ReadinessWait"] = "Aborted"
    /\ effectState["BufferLease"] = "Completed"
    /\ effectState["NetOperation"] = "Completed"
    /\ effectState["Syscall"] = "Aborted"
    /\ bufferState = "Consumed"
    /\ bufferConsumptionCount = 0
    /\ bufferClosureCount = 1
    /\ socketState = "HalfClosed"

PersonalityCrashDrainAbort ==
    /\ scopeState = "Revoked"
    /\ bindingEpoch["Personality"] = 1
    /\ effectBinding["Syscall"] = 0
    /\ "Syscall" \notin adoptedEffects
    /\ netPublicationCount = 1
    /\ readyPublicationCount = 1
    /\ readyDeliveryCount = 1
    /\ guestCommitCount = 0
    /\ guestPublicationCount = 0
    /\ effectState["ReadinessWait"] = "Completed"
    /\ effectState["NetOperation"] = "Completed"
    /\ effectState["Syscall"] = "Aborted"

BufferVisibleReplyAbsent ==
    /\ scopeState = "Active"
    /\ netPublicationCount = 1
    /\ readyPublicationCount = 0
    /\ bufferState = "Queued"
    /\ bufferPayload = "Ping4"
    /\ effectState["BufferLease"] = "Committed"
    /\ freeCredits["Buffer"] = 0
    /\ bufferConsumptionCount = 0
    /\ bufferClosureCount = 0
    /\ guestCommitCount = 0
    /\ guestPublicationCount = 0

StaleTokenFences == rejectKinds = RejectKinds

LoopbackClosureAbsent == ~LoopbackClosure
RevokeBeforeNetCommitAbsent == ~RevokeBeforeNetCommit
NetdCrashAdoptAcceptAbsent == ~NetdCrashAdoptAccept
ReadinessBeforeRevokeAbsent == ~ReadinessBeforeRevoke
RevokeBeforeReadinessAbsent == ~RevokeBeforeReadiness
PersonalityCrashDrainAbortAbsent == ~PersonalityCrashDrainAbort
BufferVisibleReplyAbsentAbsent == ~BufferVisibleReplyAbsent
StaleTokenFencesAbsent == ~StaleTokenFences

=============================================================================

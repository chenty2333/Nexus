---------------- MODULE HandoffAdmissionCser ----------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Prospective RFC-0002 local successor. Scope authority and the reversible  *)
(* handoff admission gate are orthogonal. The ownership log is abstracted as *)
(* a non-equivocating, rollback-free decision source in the first-round TCB. *)
(* This is declarative TLA+, not a production Registry or distributed log.   *)
(***************************************************************************)

CONSTANTS MaxBinding, EnablePostCommitRetain

ASSUME /\ MaxBinding = 2
       /\ EnablePostCommitRetain \in BOOLEAN

Effects == {"Precommit", "Committed", "Late"}
EffectStates == {"Absent", "Registered", "Prepared", "Committed",
                  "Completed", "Aborted", "Retained"}
TerminalStates == {"Completed", "Aborted"}
ScopePhases == {"Active", "Closing", "Revoked"}
GateStates == {"Open", "Frozen"}
SourceStates == {"Active", "Frozen", "Fenced", "RecoveryRequired"}
DestinationStates == {"Inactive", "Active", "RecoveryRequired"}
Decisions == {"None", "Abort", "Commit"}
RejectKinds == {"CommitAfterFreeze", "RetainedCommit", "UntypedAbort",
                 "StaleBinding", "ConflictingDecision", "ActivationBeforeClosure"}

VARIABLES intentRecorded,
          intentRecovered,
          coordinatorCrashed,
          gate,
          freezeGeneration,
          scopePhase,
          source,
          destination,
          decision,
          authorityEpoch,
          bindingEpoch,
          effectState,
          frozenCohort,
          committedAtFreeze,
          pendingPublications,
          abortReceipt,
          commitReceipt,
          closureReceipt,
          sourceCrashed,
          lostCommitAck,
          commitReplayObserved,
          closeReplayObserved,
          rejects

vars == <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
          freezeGeneration, scopePhase, source, destination, decision,
          authorityEpoch, bindingEpoch, effectState, frozenCohort,
          committedAtFreeze, pendingPublications, abortReceipt, commitReceipt,
          closureReceipt, sourceCrashed, lostCommitAck, commitReplayObserved,
          closeReplayObserved, rejects>>

LiveEffects == {e \in Effects : effectState[e] \notin TerminalStates \cup {"Absent"}}
UncommittedFrozen ==
    {e \in frozenCohort : effectState[e] \in {"Registered", "Prepared"}}
RetainedFrozen == {e \in frozenCohort : effectState[e] = "Retained"}
ReadyToCommit ==
    /\ gate = "Frozen"
    /\ UncommittedFrozen = {}
    /\ RetainedFrozen = {}
    /\ pendingPublications = {}

Init ==
    /\ intentRecorded = FALSE
    /\ intentRecovered = FALSE
    /\ coordinatorCrashed = FALSE
    /\ gate = "Open"
    /\ freezeGeneration = 0
    /\ scopePhase = "Active"
    /\ source = "Active"
    /\ destination = "Inactive"
    /\ decision = "None"
    /\ authorityEpoch = 1
    /\ bindingEpoch = 1
    /\ effectState = [e \in Effects |->
         IF e = "Precommit" THEN "Prepared"
         ELSE IF e = "Committed" THEN "Committed"
         ELSE "Absent"]
    /\ frozenCohort = {}
    /\ committedAtFreeze = {}
    /\ pendingPublications = {}
    /\ abortReceipt = FALSE
    /\ commitReceipt = FALSE
    /\ closureReceipt = FALSE
    /\ sourceCrashed = FALSE
    /\ lostCommitAck = FALSE
    /\ commitReplayObserved = FALSE
    /\ closeReplayObserved = FALSE
    /\ rejects = {}

PrepareIntent ==
    /\ ~intentRecorded
    /\ gate = "Open"
    /\ scopePhase = "Active"
    /\ source = "Active"
    /\ intentRecorded' = TRUE
    /\ UNCHANGED <<intentRecovered, coordinatorCrashed, gate, freezeGeneration,
                    scopePhase, source, destination, decision, authorityEpoch,
                    bindingEpoch, effectState, frozenCohort, committedAtFreeze,
                    pendingPublications, abortReceipt, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

CoordinatorCrash ==
    /\ intentRecorded
    /\ gate = "Open"
    /\ ~coordinatorCrashed
    /\ coordinatorCrashed' = TRUE
    /\ UNCHANGED <<intentRecorded, intentRecovered, gate, freezeGeneration,
                    scopePhase, source, destination, decision, authorityEpoch,
                    bindingEpoch, effectState, frozenCohort, committedAtFreeze,
                    pendingPublications, abortReceipt, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

RecoverIntent ==
    /\ coordinatorCrashed
    /\ ~intentRecovered
    /\ gate = "Open"
    /\ intentRecovered' = TRUE
    /\ UNCHANGED <<intentRecorded, coordinatorCrashed, gate, freezeGeneration,
                    scopePhase, source, destination, decision, authorityEpoch,
                    bindingEpoch, effectState, frozenCohort, committedAtFreeze,
                    pendingPublications, abortReceipt, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

RegisterLate ==
    /\ gate = "Open"
    /\ scopePhase = "Active"
    /\ source = "Active"
    /\ effectState["Late"] = "Absent"
    /\ effectState' = [effectState EXCEPT !["Late"] = "Registered"]
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

FirstCommit ==
    /\ gate = "Open"
    /\ scopePhase = "Active"
    /\ source = "Active"
    /\ effectState["Precommit"] = "Prepared"
    /\ effectState' = [effectState EXCEPT !["Precommit"] = "Committed"]
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

RetainBeforeFreeze ==
    /\ gate = "Open"
    /\ decision = "None"
    /\ effectState["Committed"] = "Committed"
    /\ effectState' = [effectState EXCEPT !["Committed"] = "Retained"]
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

FreezeAdmission ==
    /\ intentRecorded
    /\ gate = "Open"
    /\ scopePhase = "Active"
    /\ source = "Active"
    /\ freezeGeneration = 0
    /\ gate' = "Frozen"
    /\ freezeGeneration' = 1
    /\ source' = "Frozen"
    /\ frozenCohort' = LiveEffects
    /\ committedAtFreeze' =
         {e \in LiveEffects : effectState[e] \in {"Committed", "Retained"}}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed,
                    scopePhase, destination, decision, authorityEpoch,
                    bindingEpoch, effectState, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ProbeCommitAfterFreeze ==
    /\ gate = "Frozen"
    /\ decision = "None"
    /\ effectState["Precommit"] = "Prepared"
    /\ "CommitAfterFreeze" \notin rejects
    /\ rejects' = rejects \cup {"CommitAfterFreeze"}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved>>

AbortUncommitted ==
    /\ gate = "Frozen"
    /\ decision = "None"
    /\ UncommittedFrozen /= {}
    /\ effectState' = [e \in Effects |->
         IF e \in UncommittedFrozen THEN "Aborted" ELSE effectState[e]]
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ProbeUntypedAbort ==
    /\ gate = "Frozen"
    /\ decision = "None"
    /\ "UntypedAbort" \notin rejects
    /\ rejects' = rejects \cup {"UntypedAbort"}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved>>

TypedAbort ==
    /\ gate = "Frozen"
    /\ decision = "None"
    /\ decision' = "Abort"
    /\ abortReceipt' = TRUE
    /\ gate' = "Open"
    /\ source' = IF sourceCrashed THEN "RecoveryRequired" ELSE "Active"
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed,
                    freezeGeneration, scopePhase, destination, authorityEpoch,
                    bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

RecoverSourceAfterAbort ==
    /\ decision = "Abort"
    /\ source = "RecoveryRequired"
    /\ source' = "Active"
    /\ sourceCrashed' = FALSE
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ProbeRetainedCommit ==
    /\ gate = "Frozen"
    /\ decision = "None"
    /\ RetainedFrozen /= {}
    /\ "RetainedCommit" \notin rejects
    /\ rejects' = rejects \cup {"RetainedCommit"}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved>>

CommitDecision ==
    /\ decision = "None"
    /\ ReadyToCommit
    /\ decision' = "Commit"
    /\ commitReceipt' = TRUE
    /\ scopePhase' = "Closing"
    /\ source' = "Fenced"
    /\ authorityEpoch' = 2
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, destination, bindingEpoch, effectState,
                    frozenCohort, committedAtFreeze, pendingPublications,
                    abortReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

LoseCommitAck ==
    /\ decision = "Commit"
    /\ commitReceipt
    /\ ~lostCommitAck
    /\ lostCommitAck' = TRUE
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed,
                    commitReplayObserved, closeReplayObserved, rejects>>

ReplayCommit ==
    /\ decision = "Commit"
    /\ commitReceipt
    /\ lostCommitAck
    /\ ~commitReplayObserved
    /\ commitReplayObserved' = TRUE
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    closeReplayObserved, rejects>>

SourceCrash ==
    /\ gate = "Frozen"
    /\ decision = "None"
    /\ ~sourceCrashed
    /\ bindingEpoch < MaxBinding
    /\ sourceCrashed' = TRUE
    /\ bindingEpoch' = bindingEpoch + 1
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ProbeOldBindingReply ==
    /\ sourceCrashed
    /\ gate = "Frozen"
    /\ "StaleBinding" \notin rejects
    /\ rejects' = rejects \cup {"StaleBinding"}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved>>

CompleteCommitted ==
    /\ gate = "Frozen"
    /\ \E e \in committedAtFreeze : effectState[e] = "Committed"
    /\ \E e \in committedAtFreeze :
         /\ effectState[e] = "Committed"
         /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
         /\ pendingPublications' = pendingPublications \cup {e}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, abortReceipt, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

AckPublication ==
    /\ pendingPublications /= {}
    /\ \E e \in pendingPublications :
         pendingPublications' = pendingPublications \ {e}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, abortReceipt, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

RetainAfterCommit ==
    /\ EnablePostCommitRetain
    /\ decision = "Commit"
    /\ \E e \in committedAtFreeze : effectState[e] = "Committed"
    /\ \E e \in committedAtFreeze :
         /\ effectState[e] = "Committed"
         /\ effectState' = [effectState EXCEPT ![e] = "Retained"]
    /\ destination' = "RecoveryRequired"
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ReconcileRetained ==
    /\ gate = "Frozen"
    /\ \E e \in committedAtFreeze : effectState[e] = "Retained"
    /\ \E e \in committedAtFreeze :
         /\ effectState[e] = "Retained"
         /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
         /\ pendingPublications' = pendingPublications \cup {e}
    /\ destination' = "Inactive"
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, decision,
                    authorityEpoch, bindingEpoch, frozenCohort,
                    committedAtFreeze, abortReceipt, commitReceipt,
                    closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

RevokeComplete ==
    /\ decision = "Commit"
    /\ scopePhase = "Closing"
    /\ \A e \in frozenCohort : effectState[e] \in TerminalStates
    /\ pendingPublications = {}
    /\ closureReceipt' = TRUE
    /\ scopePhase' = "Revoked"
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ActivateDestination ==
    /\ closureReceipt
    /\ scopePhase = "Revoked"
    /\ destination /= "Active"
    /\ destination' = "Active"
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved, rejects>>

ProbeActivationBeforeClosure ==
    /\ decision = "Commit"
    /\ ~closureReceipt
    /\ "ActivationBeforeClosure" \notin rejects
    /\ rejects' = rejects \cup {"ActivationBeforeClosure"}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved>>

ReplayClose ==
    /\ closureReceipt
    /\ ~closeReplayObserved
    /\ closeReplayObserved' = TRUE
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, rejects>>

ProbeConflictingAbort ==
    /\ decision = "Commit"
    /\ "ConflictingDecision" \notin rejects
    /\ rejects' = rejects \cup {"ConflictingDecision"}
    /\ UNCHANGED <<intentRecorded, intentRecovered, coordinatorCrashed, gate,
                    freezeGeneration, scopePhase, source, destination, decision,
                    authorityEpoch, bindingEpoch, effectState, frozenCohort,
                    committedAtFreeze, pendingPublications, abortReceipt,
                    commitReceipt, closureReceipt, sourceCrashed, lostCommitAck,
                    commitReplayObserved, closeReplayObserved>>

Next ==
    \/ PrepareIntent
    \/ CoordinatorCrash
    \/ RecoverIntent
    \/ RegisterLate
    \/ FirstCommit
    \/ RetainBeforeFreeze
    \/ FreezeAdmission
    \/ ProbeCommitAfterFreeze
    \/ AbortUncommitted
    \/ ProbeUntypedAbort
    \/ TypedAbort
    \/ RecoverSourceAfterAbort
    \/ ProbeRetainedCommit
    \/ CommitDecision
    \/ LoseCommitAck
    \/ ReplayCommit
    \/ SourceCrash
    \/ ProbeOldBindingReply
    \/ CompleteCommitted
    \/ AckPublication
    \/ RetainAfterCommit
    \/ ReconcileRetained
    \/ RevokeComplete
    \/ ActivateDestination
    \/ ProbeActivationBeforeClosure
    \/ ReplayClose
    \/ ProbeConflictingAbort

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(CompleteCommitted)
    /\ WF_vars(AckPublication)
    /\ WF_vars(RevokeComplete)
    /\ WF_vars(RecoverSourceAfterAbort)

TypeOK ==
    /\ intentRecorded \in BOOLEAN
    /\ intentRecovered \in BOOLEAN
    /\ coordinatorCrashed \in BOOLEAN
    /\ gate \in GateStates
    /\ freezeGeneration \in 0..1
    /\ scopePhase \in ScopePhases
    /\ source \in SourceStates
    /\ destination \in DestinationStates
    /\ decision \in Decisions
    /\ authorityEpoch \in 1..2
    /\ bindingEpoch \in 1..MaxBinding
    /\ effectState \in [Effects -> EffectStates]
    /\ frozenCohort \subseteq Effects
    /\ committedAtFreeze \subseteq frozenCohort
    /\ pendingPublications \subseteq Effects
    /\ abortReceipt \in BOOLEAN
    /\ commitReceipt \in BOOLEAN
    /\ closureReceipt \in BOOLEAN
    /\ sourceCrashed \in BOOLEAN
    /\ lostCommitAck \in BOOLEAN
    /\ commitReplayObserved \in BOOLEAN
    /\ closeReplayObserved \in BOOLEAN
    /\ rejects \subseteq RejectKinds

AtMostOneExecutionAuthority ==
    /\ source = "Active" => destination /= "Active"
    /\ destination = "Active" => source = "Fenced"

NoPostFreezeUntrackedEffect ==
    gate = "Frozen" =>
        /\ LiveEffects \subseteq frozenCohort
        /\ {e \in Effects : effectState[e] \in {"Committed", "Retained"}}
              \subseteq committedAtFreeze

AbortImpliesNoDestinationAuthority ==
    decision = "Abort" =>
        /\ abortReceipt
        /\ ~commitReceipt
        /\ gate = "Open"
        /\ destination = "Inactive"

CommitDecisionImpliesSourcePrincipalFenced ==
    decision = "Commit" =>
        /\ commitReceipt
        /\ ~abortReceipt
        /\ source = "Fenced"
        /\ scopePhase \in {"Closing", "Revoked"}
        /\ authorityEpoch = 2

PostCommitPublicationImpliesPreFreezeCommittedAndClosureOwned ==
    pendingPublications \subseteq committedAtFreeze

UnknownDecisionImpliesRemainFrozen ==
    (freezeGeneration = 1 /\ decision = "None") =>
        /\ gate = "Frozen"
        /\ source = "Frozen"
        /\ destination = "Inactive"

DestinationActivationRequiresSourceClosure ==
    destination = "Active" =>
        /\ closureReceipt
        /\ scopePhase = "Revoked"
        /\ pendingPublications = {}
        /\ RetainedFrozen = {}

EveryReceiptBindsOneDecisionAndOneCohort ==
    /\ abortReceipt => decision = "Abort" /\ freezeGeneration = 1
    /\ commitReceipt => decision = "Commit" /\ freezeGeneration = 1
    /\ ~(abortReceipt /\ commitReceipt)

StaleBindingCannotPublish ==
    (sourceCrashed /\ gate = "Frozen") => source /= "Active"

TombstoneCannotBeInterpretedAsClosure ==
    RetainedFrozen /= {} => ~closureReceipt

FreezeDoesNotAdvanceAuthority ==
    (gate = "Frozen" /\ decision = "None") => authorityEpoch = 1

CloseReplayIsIdempotent ==
    closeReplayObserved => closureReceipt /\ scopePhase = "Revoked"

ConditionalCommitClosure ==
    [](decision = "Commit" => <> (closureReceipt \/ RetainedFrozen /= {}))

ConditionalAbortRecovery ==
    [](decision = "Abort" => <> (source = "Active"))

IntentCrashBeforeFreezeAbsent ==
    ~(coordinatorCrashed /\ intentRecovered /\ gate = "Open" /\ source = "Active")
FreezeBeforeCommitAbsent == ~("CommitAfterFreeze" \in rejects)
CommitBeforeFreezeAbsent ==
    ~(gate = "Frozen" /\ "Precommit" \in committedAtFreeze)
PredecisionTombstoneBlockedAbsent == ~("RetainedCommit" \in rejects)
TypedAbortRequiredAbsent ==
    ~("UntypedAbort" \in rejects /\ decision = "Abort" /\ abortReceipt)
CommitAckLossReplayAbsent == ~(lostCommitAck /\ commitReplayObserved)
SourceCrashStaleBindingAbsent ==
    ~(sourceCrashed /\ "StaleBinding" \in rejects)
DuplicateCommitCloseAbsent == ~(closureReceipt /\ closeReplayObserved)
ConflictingDecisionRejectedAbsent == ~("ConflictingDecision" \in rejects)
PostcommitRetainedRecoveryAbsent ==
    ~(decision = "Commit" /\ RetainedFrozen /= {}
      /\ destination = "RecoveryRequired" /\ ~closureReceipt)

=============================================================================

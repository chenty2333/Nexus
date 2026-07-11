------------------------------ MODULE Cser ------------------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* A finite-state model of Causally Scoped Effect Revocation (CSER).       *)
(*                                                                         *)
(* The PlusCal algorithm below is the source of the Init/Next relation.     *)
(* Every branch of EnvironmentLoop is one atomic protocol operation.       *)
(* Consequently Commit and RevokeBegin are their respective linearization  *)
(* points; TLC cannot observe a partially-applied operation.                *)
(***************************************************************************)

CONSTANTS Effects, TotalBudget, MaxBinding

ASSUME /\ IsFiniteSet(Effects)
       /\ Effects # {}
       /\ TotalBudget \in Nat
       /\ TotalBudget <= Cardinality(Effects)
       /\ MaxBinding \in Nat
       /\ MaxBinding > 0

ScopeStates == {"Active", "Closing", "Revoked"}
EffectStates == {
    "Unregistered",
    "Registered",
    "Prepared",
    "Committed",
    "Draining",
    "Completed",
    "Cancelling",
    "Aborted"
}
TerminalStates == {"Completed", "Aborted"}
UncommittedStates == {"Registered", "Prepared"}
CommittedPathStates == {"Committed", "Draining", "Completed"}
FallbackStates == {"Standby", "Required", "Running"}

NoEpoch == -1
NoBinding == -1

(* --algorithm CSER
variables
    scopeState = "Active",
    scopeEpoch = 0,
    closingEpoch = NoEpoch,

    supervisorAlive = TRUE,
    bindingEpoch = 0,
    fallbackState = "Standby",

    effectState = [e \in Effects |-> "Unregistered"],
    effectEpoch = [e \in Effects |-> NoEpoch],
    effectBinding = [e \in Effects |-> NoBinding],

    freeBudget = TotalBudget,
    held = [e \in Effects |-> 0],
    spent = [e \in Effects |-> 0],

    commitSeen = [e \in Effects |-> FALSE],
    commitBinding = [e \in Effects |-> NoBinding],
    terminalCount = [e \in Effects |-> 0],

    committedAtClose = {},
    committedAtLastCrash = {},
    lastCrashBinding = 0;

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* register(e): reserve one credit and bind the effect to the
            \* currently active scope and supervisor generation.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ supervisorAlive
                      /\ effectState[e] = "Unregistered"
                      /\ freeBudget > 0;
                effectState[e] := "Registered";
                effectEpoch[e] := scopeEpoch;
                effectBinding[e] := bindingEpoch;
                freeBudget := freeBudget - 1;
                held[e] := 1;
            end with;
        or
            \* prepare(e): construction is complete but no externally
            \* visible effect has crossed its commit point.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ supervisorAlive
                      /\ effectState[e] = "Registered"
                      /\ effectEpoch[e] = scopeEpoch
                      /\ effectBinding[e] = bindingEpoch;
                effectState[e] := "Prepared";
            end with;
        or
            \* commit(e): THE effect commit linearization point.  Its guards
            \* are the epoch and binding fences.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ supervisorAlive
                      /\ effectState[e] = "Prepared"
                      /\ effectEpoch[e] = scopeEpoch
                      /\ effectBinding[e] = bindingEpoch;
                effectState[e] := "Committed";
                held[e] := 0;
                spent[e] := 1;
                commitSeen[e] := TRUE;
                commitBinding[e] := bindingEpoch;
            end with;
        or
            \* complete(e): normal completion after an irreversible commit.
            with e \in Effects do
                await effectState[e] = "Committed";
                effectState[e] := "Completed";
                terminalCount[e] := terminalCount[e] + 1;
            end with;
        or
            \* revoke_begin(): THE revocation linearization point.  Moving to
            \* Closing and advancing scopeEpoch closes the old commit gate.
            await scopeState = "Active";
            committedAtClose := {e \in Effects : commitSeen[e]};
            closingEpoch := scopeEpoch;
            scopeEpoch := scopeEpoch + 1;
            scopeState := "Closing";
        or
            \* revoke_step(e): bounded work over the closing scope's reverse
            \* index.  Uncommitted work cancels; committed work drains.
            with e \in Effects do
                await /\ scopeState = "Closing"
                      /\ effectEpoch[e] = closingEpoch
                      /\ effectState[e] \in {
                             "Registered", "Prepared", "Committed",
                             "Cancelling", "Draining"
                         };
                if effectState[e] \in {"Registered", "Prepared"} then
                    effectState[e] := "Cancelling";
                elsif effectState[e] = "Cancelling" then
                    effectState[e] := "Aborted";
                    held[e] := 0;
                    freeBudget := freeBudget + 1;
                    terminalCount[e] := terminalCount[e] + 1;
                elsif effectState[e] = "Committed" then
                    effectState[e] := "Draining";
                else
                    effectState[e] := "Completed";
                    terminalCount[e] := terminalCount[e] + 1;
                end if;
            end with;
        or
            \* revoke_complete(): acknowledgement is legal only after every
            \* old-epoch effect is terminal.
            await /\ scopeState = "Closing"
                  /\ \A e \in Effects :
                         effectEpoch[e] = closingEpoch
                         => effectState[e] \in TerminalStates;
            scopeState := "Revoked";
        or
            \* crash(): advancing bindingEpoch fences every old reply.  It
            \* also requests the in-kernel scheduler fallback.
            await /\ scopeState = "Active"
                  /\ supervisorAlive
                  /\ bindingEpoch < MaxBinding;
            committedAtLastCrash := {e \in Effects : commitSeen[e]};
            lastCrashBinding := bindingEpoch + 1;
            bindingEpoch := bindingEpoch + 1;
            supervisorAlive := FALSE;
            fallbackState := "Required";
        or
            \* rebind(): a replacement may bind only after fallback has made
            \* scheduling independent of the failed policy service.
            await /\ scopeState = "Active"
                  /\ ~supervisorAlive
                  /\ fallbackState = "Running";
            supervisorAlive := TRUE;
            fallbackState := "Standby";
        or
            \* adopt(e): explicit transfer of an uncommitted continuation to
            \* the replacement binding.  Committed effects are never adopted.
            with e \in Effects do
                await /\ scopeState = "Active"
                      /\ supervisorAlive
                      /\ effectState[e] \in {"Registered", "Prepared"}
                      /\ effectEpoch[e] = scopeEpoch
                      /\ effectBinding[e] # bindingEpoch;
                effectBinding[e] := bindingEpoch;
            end with;
        end either;
    end while;
end process;

\* This process represents the kernel-owned scheduler fallback.  Fairness is
\* intentionally attached only here; no environment operation is assumed to
\* happen eventually.
fair process FallbackPick = "scheduler-fallback"
begin
FallbackLoop:
    while TRUE do
        await fallbackState = "Required";
        fallbackState := "Running";
    end while;
end process;
end algorithm; *)

\* BEGIN TRANSLATION
VARIABLES scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding

vars == << scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding >>

ProcSet == {"environment"} \cup {"scheduler-fallback"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ scopeEpoch = 0
        /\ closingEpoch = NoEpoch
        /\ supervisorAlive = TRUE
        /\ bindingEpoch = 0
        /\ fallbackState = "Standby"
        /\ effectState = [e \in Effects |-> "Unregistered"]
        /\ effectEpoch = [e \in Effects |-> NoEpoch]
        /\ effectBinding = [e \in Effects |-> NoBinding]
        /\ freeBudget = TotalBudget
        /\ held = [e \in Effects |-> 0]
        /\ spent = [e \in Effects |-> 0]
        /\ commitSeen = [e \in Effects |-> FALSE]
        /\ commitBinding = [e \in Effects |-> NoBinding]
        /\ terminalCount = [e \in Effects |-> 0]
        /\ committedAtClose = {}
        /\ committedAtLastCrash = {}
        /\ lastCrashBinding = 0

Environment == \/ /\ \E e \in Effects:
                       /\ /\ scopeState = "Active"
                          /\ supervisorAlive
                          /\ effectState[e] = "Unregistered"
                          /\ freeBudget > 0
                       /\ effectState' = [effectState EXCEPT ![e] = "Registered"]
                       /\ effectEpoch' = [effectEpoch EXCEPT ![e] = scopeEpoch]
                       /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch]
                       /\ freeBudget' = freeBudget - 1
                       /\ held' = [held EXCEPT ![e] = 1]
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ \E e \in Effects:
                       /\ /\ scopeState = "Active"
                          /\ supervisorAlive
                          /\ effectState[e] = "Registered"
                          /\ effectEpoch[e] = scopeEpoch
                          /\ effectBinding[e] = bindingEpoch
                       /\ effectState' = [effectState EXCEPT ![e] = "Prepared"]
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ \E e \in Effects:
                       /\ /\ scopeState = "Active"
                          /\ supervisorAlive
                          /\ effectState[e] = "Prepared"
                          /\ effectEpoch[e] = scopeEpoch
                          /\ effectBinding[e] = bindingEpoch
                       /\ effectState' = [effectState EXCEPT ![e] = "Committed"]
                       /\ held' = [held EXCEPT ![e] = 0]
                       /\ spent' = [spent EXCEPT ![e] = 1]
                       /\ commitSeen' = [commitSeen EXCEPT ![e] = TRUE]
                       /\ commitBinding' = [commitBinding EXCEPT ![e] = bindingEpoch]
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectEpoch, effectBinding, freeBudget, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ \E e \in Effects:
                       /\ effectState[e] = "Committed"
                       /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                       /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ scopeState = "Active"
                  /\ committedAtClose' = {e \in Effects : commitSeen[e]}
                  /\ closingEpoch' = scopeEpoch
                  /\ scopeEpoch' = scopeEpoch + 1
                  /\ scopeState' = "Closing"
                  /\ UNCHANGED <<supervisorAlive, bindingEpoch, fallbackState, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtLastCrash, lastCrashBinding>>
               \/ /\ \E e \in Effects:
                       /\ /\ scopeState = "Closing"
                          /\ effectEpoch[e] = closingEpoch
                          /\ effectState[e] \in {
                                 "Registered", "Prepared", "Committed",
                                 "Cancelling", "Draining"
                             }
                       /\ IF effectState[e] \in {"Registered", "Prepared"}
                             THEN /\ effectState' = [effectState EXCEPT ![e] = "Cancelling"]
                                  /\ UNCHANGED << freeBudget, held, terminalCount >>
                             ELSE /\ IF effectState[e] = "Cancelling"
                                        THEN /\ effectState' = [effectState EXCEPT ![e] = "Aborted"]
                                             /\ held' = [held EXCEPT ![e] = 0]
                                             /\ freeBudget' = freeBudget + 1
                                             /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                                        ELSE /\ IF effectState[e] = "Committed"
                                                   THEN /\ effectState' = [effectState EXCEPT ![e] = "Draining"]
                                                        /\ UNCHANGED terminalCount
                                                   ELSE /\ effectState' = [effectState EXCEPT ![e] = "Completed"]
                                                        /\ terminalCount' = [terminalCount EXCEPT ![e] = terminalCount[e] + 1]
                                             /\ UNCHANGED << freeBudget, held >>
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectEpoch, effectBinding, spent, commitSeen, commitBinding, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ /\ scopeState = "Closing"
                     /\ \A e \in Effects :
                            effectEpoch[e] = closingEpoch
                            => effectState[e] \in TerminalStates
                  /\ scopeState' = "Revoked"
                  /\ UNCHANGED <<scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ /\ scopeState = "Active"
                     /\ supervisorAlive
                     /\ bindingEpoch < MaxBinding
                  /\ committedAtLastCrash' = {e \in Effects : commitSeen[e]}
                  /\ lastCrashBinding' = bindingEpoch + 1
                  /\ bindingEpoch' = bindingEpoch + 1
                  /\ supervisorAlive' = FALSE
                  /\ fallbackState' = "Required"
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose>>
               \/ /\ /\ scopeState = "Active"
                     /\ ~supervisorAlive
                     /\ fallbackState = "Running"
                  /\ supervisorAlive' = TRUE
                  /\ fallbackState' = "Standby"
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, bindingEpoch, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding>>
               \/ /\ \E e \in Effects:
                       /\ /\ scopeState = "Active"
                          /\ supervisorAlive
                          /\ effectState[e] \in {"Registered", "Prepared"}
                          /\ effectEpoch[e] = scopeEpoch
                          /\ effectBinding[e] # bindingEpoch
                       /\ effectBinding' = [effectBinding EXCEPT ![e] = bindingEpoch]
                  /\ UNCHANGED <<scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, fallbackState, effectState, effectEpoch, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding>>

FallbackPick == /\ fallbackState = "Required"
                /\ fallbackState' = "Running"
                /\ UNCHANGED << scopeState, scopeEpoch, closingEpoch, supervisorAlive, bindingEpoch, effectState, effectEpoch, effectBinding, freeBudget, held, spent, commitSeen, commitBinding, terminalCount, committedAtClose, committedAtLastCrash, lastCrashBinding >>

Next == Environment \/ FallbackPick

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(FallbackPick)

\* END TRANSLATION

(***************************************************************************)
(* Safety predicates checked by TLC.                                       *)
(***************************************************************************)

TypeOK ==
    /\ scopeState \in ScopeStates
    /\ scopeEpoch \in 0..1
    /\ closingEpoch \in {NoEpoch, 0}
    /\ supervisorAlive \in BOOLEAN
    /\ bindingEpoch \in 0..MaxBinding
    /\ fallbackState \in FallbackStates
    /\ effectState \in [Effects -> EffectStates]
    /\ effectEpoch \in [Effects -> {NoEpoch, 0}]
    /\ effectBinding \in [Effects -> ({NoBinding} \cup (0..MaxBinding))]
    /\ freeBudget \in 0..TotalBudget
    /\ held \in [Effects -> {0, 1}]
    /\ spent \in [Effects -> {0, 1}]
    /\ commitSeen \in [Effects -> BOOLEAN]
    /\ commitBinding \in [Effects -> ({NoBinding} \cup (0..MaxBinding))]
    /\ terminalCount \in [Effects -> {0, 1}]
    /\ committedAtClose \subseteq Effects
    /\ committedAtLastCrash \subseteq Effects
    /\ lastCrashBinding \in 0..MaxBinding

BudgetStateConsistency ==
    \A e \in Effects :
        CASE effectState[e] = "Unregistered" ->
                 /\ held[e] = 0 /\ spent[e] = 0
          [] effectState[e] \in {"Registered", "Prepared", "Cancelling"} ->
                 /\ held[e] = 1 /\ spent[e] = 0
          [] effectState[e] \in CommittedPathStates ->
                 /\ held[e] = 0 /\ spent[e] = 1
          [] effectState[e] = "Aborted" ->
                 /\ held[e] = 0 /\ spent[e] = 0

BudgetConservation ==
    freeBudget
      + Cardinality({e \in Effects : held[e] = 1})
      + Cardinality({e \in Effects : spent[e] = 1})
      = TotalBudget

SingleTerminalization ==
    \A e \in Effects :
        /\ terminalCount[e] \in {0, 1}
        /\ (terminalCount[e] = 1) <=> (effectState[e] \in TerminalStates)

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"}
    => \A e \in Effects :
           /\ effectEpoch[e] = closingEpoch
           /\ commitSeen[e]
           => e \in committedAtClose

QuiescentClosure ==
    scopeState = "Revoked"
    => /\ closingEpoch # NoEpoch
       /\ \A e \in Effects :
              effectEpoch[e] = closingEpoch
              => /\ effectState[e] \in TerminalStates
                 /\ held[e] = 0

CommitEnabled(e) ==
    /\ scopeState = "Active"
    /\ supervisorAlive
    /\ effectState[e] = "Prepared"
    /\ effectEpoch[e] = scopeEpoch
    /\ effectBinding[e] = bindingEpoch

OldBindingCannotCommit ==
    /\ \A e \in Effects :
           /\ effectState[e] \in UncommittedStates
           /\ effectBinding[e] < bindingEpoch
           => ~CommitEnabled(e)
    /\ \A e \in Effects :
           /\ commitSeen[e]
           /\ e \notin committedAtLastCrash
           => commitBinding[e] >= lastCrashBinding

(* Under the fair FallbackPick process generated above, every crash's        *)
(* Required state eventually reaches Running.  Rebind cannot erase Required. *)
SchedulerFallbackProgress ==
    (fallbackState = "Required") ~> (fallbackState = "Running")

=============================================================================

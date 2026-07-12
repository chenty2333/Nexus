------------------ MODULE PersonalityExecCser ------------------
EXTENDS FiniteSets, Integers, TLC

(***************************************************************************)
(* Bounded failure-atomic exec successor with one transaction, two segments,*)
(* TLS, stack, crash/rebind/adopt, and authority closure.                    *)
(* The PlusCal algorithm is the sole source of Init and Next.                *)
(***************************************************************************)

CONSTANTS MaxBinding, EnableRejects

ASSUME /\ MaxBinding = 1
       /\ EnableRejects \in BOOLEAN

Effects == {"Tx", "Seg1", "Seg2"}
LiveStates == {"Staged", "Committed"}
NoBinding == -1

(* --algorithm PersonalityExecCSER
variables
    scopeState = "Active",
    authorityEpoch = 0,
    closingEpoch = -1,
    serviceAlive = TRUE,
    bindingEpoch = 0,
    fallbackState = "Standby",
    replacementState = "Bound",
    recoveryRevision = 0,

    currentImage = "Old",
    currentTls = "OldTls",
    currentStack = "OldStack",

    txState = "Unused",
    seg1State = "Unused",
    seg2State = "Unused",
    txBinding = NoBinding,
    seg1Binding = NoBinding,
    seg2Binding = NoBinding,

    commitCount = 0,
    publicationCount = 0,
    terminalCount = 0,
    receiptPrevious = "None",
    receiptImage = "None",
    receiptSegments = {},
    receiptTls = "None",
    receiptStack = "None",
    readyInvalidatedSeen = FALSE,

    freeControlCredits = 1,
    freeSegmentCredits = 2,
    freeTimerCredits = 1,
    watchdogHeld = FALSE,
    recoveryCohort = {},

    snapshotState = "Absent",
    snapshotBinding = NoBinding,
    snapshotRevision = -1,
    snapshotCurrentImage = "None",
    snapshotTxState = "Unused",
    snapshotSeg1State = "Unused",
    snapshotSeg2State = "Unused",

    rejectCount = 0,
    commitAtClose = 0;

process Environment = "environment"
begin
EnvironmentLoop:
    while TRUE do
        either
            \* Segment, TLS, and stack staging is invisible to currentImage.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ txState = "Unused"
                  /\ freeControlCredits = 1
                  /\ freeSegmentCredits = 2;
            txState := "Staged";
            seg1State := "Staged";
            seg2State := "Staged";
            txBinding := bindingEpoch;
            seg1Binding := bindingEpoch;
            seg2Binding := bindingEpoch;
            freeControlCredits := 0;
            freeSegmentCredits := 0;
            recoveryRevision := recoveryRevision + 1;
        or
            \* One atomic ExecCommit publishes the entire new image.
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ replacementState = "Bound"
                  /\ txState = "Staged"
                  /\ seg1State = "Staged"
                  /\ seg2State = "Staged"
                  /\ txBinding = bindingEpoch
                  /\ seg1Binding = bindingEpoch
                  /\ seg2Binding = bindingEpoch;
            txState := "Committed";
            seg1State := "Committed";
            seg2State := "Committed";
            receiptPrevious := currentImage;
            receiptImage := "New";
            receiptSegments := {"Seg1", "Seg2"};
            receiptTls := "NewTls";
            receiptStack := "NewStack";
            currentImage := "New";
            currentTls := "NewTls";
            currentStack := "NewStack";
            commitCount := commitCount + 1;
            recoveryRevision := recoveryRevision + 1;
        or
            await /\ scopeState = "Active"
                  /\ serviceAlive
                  /\ bindingEpoch < MaxBinding;
            with cohort =
                (IF txState \in LiveStates THEN {"Tx"} ELSE {}) \cup
                (IF seg1State \in LiveStates THEN {"Seg1"} ELSE {}) \cup
                (IF seg2State \in LiveStates THEN {"Seg2"} ELSE {}) do
                bindingEpoch := bindingEpoch + 1;
                recoveryRevision := recoveryRevision + 1;
                serviceAlive := FALSE;
                replacementState := "None";
                fallbackState := "Required";
                recoveryCohort := cohort;
                snapshotState := "Absent";
                if cohort # {} then
                    watchdogHeld := TRUE;
                    freeTimerCredits := freeTimerCredits - 1;
                end if;
            end with;
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None";
            snapshotState := "Captured";
            snapshotBinding := bindingEpoch;
            snapshotRevision := recoveryRevision;
            snapshotCurrentImage := currentImage;
            snapshotTxState := txState;
            snapshotSeg1State := seg1State;
            snapshotSeg2State := seg2State;
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "None"
                  /\ snapshotState = "Captured"
                  /\ snapshotBinding = bindingEpoch
                  /\ snapshotRevision = recoveryRevision
                  /\ snapshotCurrentImage = currentImage
                  /\ snapshotTxState = txState
                  /\ snapshotSeg1State = seg1State
                  /\ snapshotSeg2State = seg2State;
            replacementState := "Ready";
        or
            await /\ scopeState = "Active"
                  /\ ~serviceAlive
                  /\ fallbackState = "Running"
                  /\ replacementState = "Ready";
            replacementState := "Bound";
            serviceAlive := TRUE;
        or
            with e \in recoveryCohort do
                await /\ scopeState = "Active"
                      /\ serviceAlive
                      /\ replacementState = "Bound"
                      /\ ((e = "Tx" /\ txBinding # bindingEpoch)
                           \/ (e = "Seg1" /\ seg1Binding # bindingEpoch)
                           \/ (e = "Seg2" /\ seg2Binding # bindingEpoch));
                if e = "Tx" then txBinding := bindingEpoch end if;
                if e = "Seg1" then seg1Binding := bindingEpoch end if;
                if e = "Seg2" then seg2Binding := bindingEpoch end if;
                recoveryCohort := recoveryCohort \ {e};
                recoveryRevision := recoveryRevision + 1;
                if recoveryCohort \ {e} = {} then
                    watchdogHeld := FALSE;
                    freeTimerCredits := freeTimerCredits + 1;
                end if;
            end with;
        or
            \* A stale binding operation is failure-atomic.
            await /\ EnableRejects
                  /\ scopeState = "Active"
                  /\ bindingEpoch = 1
                  /\ txState \in LiveStates
                  /\ rejectCount = 0;
            rejectCount := 1;
        or
            await scopeState = "Active";
            closingEpoch := authorityEpoch;
            authorityEpoch := authorityEpoch + 1;
            scopeState := "Closing";
            serviceAlive := FALSE;
            replacementState := "Closed";
            fallbackState := "Closed";
            snapshotState := "Absent";
            commitAtClose := commitCount;
        end either;
    end while;
end process;

fair process Kernel = "kernel"
begin
KernelLoop:
    while TRUE do
        either
            await fallbackState = "Required";
            fallbackState := "Running";
        or
            await /\ txState = "Committed"
                  /\ seg1State = "Committed"
                  /\ seg2State = "Committed"
                  /\ scopeState \in {"Active", "Closing"};
            txState := "Completed";
            seg1State := "Completed";
            seg2State := "Completed";
            publicationCount := publicationCount + 1;
            terminalCount := terminalCount + 3;
            freeControlCredits := freeControlCredits + 1;
            freeSegmentCredits := freeSegmentCredits + 2;
            recoveryRevision := recoveryRevision + 1;
            with remaining = recoveryCohort \ Effects do
                freeTimerCredits := freeTimerCredits
                    + IF watchdogHeld /\ remaining = {} THEN 1 ELSE 0;
                recoveryCohort := remaining;
                if watchdogHeld /\ remaining = {} then watchdogHeld := FALSE end if;
            end with;
            if replacementState = "Ready" then
                replacementState := "None";
                snapshotState := "Absent";
                readyInvalidatedSeen := TRUE;
            end if;
        or
            await /\ scopeState = "Closing"
                  /\ txState = "Staged"
                  /\ seg1State = "Staged"
                  /\ seg2State = "Staged";
            txState := "Aborted";
            seg1State := "Aborted";
            seg2State := "Aborted";
            terminalCount := terminalCount + 3;
            freeControlCredits := freeControlCredits + 1;
            freeSegmentCredits := freeSegmentCredits + 2;
            freeTimerCredits := freeTimerCredits
                + IF watchdogHeld THEN 1 ELSE 0;
            watchdogHeld := FALSE;
            recoveryCohort := {};
        or
            await /\ scopeState = "Closing"
                  /\ txState \in {"Unused", "Completed", "Aborted"}
                  /\ seg1State \in {"Unused", "Completed", "Aborted"}
                  /\ seg2State \in {"Unused", "Completed", "Aborted"}
                  /\ ~watchdogHeld
                  /\ recoveryCohort = {}
                  /\ freeControlCredits = 1
                  /\ freeSegmentCredits = 2
                  /\ freeTimerCredits = 1;
            scopeState := "Revoked";
        end either;
    end while;
end process;
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "9fee9ef4" /\ chksum(tla) = "f1a91288")
VARIABLES scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, publicationCount, terminalCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, readyInvalidatedSeen, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose

vars == << scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, publicationCount, terminalCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, readyInvalidatedSeen, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose >>

ProcSet == {"environment"} \cup {"kernel"}

Init == (* Global variables *)
        /\ scopeState = "Active"
        /\ authorityEpoch = 0
        /\ closingEpoch = -1
        /\ serviceAlive = TRUE
        /\ bindingEpoch = 0
        /\ fallbackState = "Standby"
        /\ replacementState = "Bound"
        /\ recoveryRevision = 0
        /\ currentImage = "Old"
        /\ currentTls = "OldTls"
        /\ currentStack = "OldStack"
        /\ txState = "Unused"
        /\ seg1State = "Unused"
        /\ seg2State = "Unused"
        /\ txBinding = NoBinding
        /\ seg1Binding = NoBinding
        /\ seg2Binding = NoBinding
        /\ commitCount = 0
        /\ publicationCount = 0
        /\ terminalCount = 0
        /\ receiptPrevious = "None"
        /\ receiptImage = "None"
        /\ receiptSegments = {}
        /\ receiptTls = "None"
        /\ receiptStack = "None"
        /\ readyInvalidatedSeen = FALSE
        /\ freeControlCredits = 1
        /\ freeSegmentCredits = 2
        /\ freeTimerCredits = 1
        /\ watchdogHeld = FALSE
        /\ recoveryCohort = {}
        /\ snapshotState = "Absent"
        /\ snapshotBinding = NoBinding
        /\ snapshotRevision = -1
        /\ snapshotCurrentImage = "None"
        /\ snapshotTxState = "Unused"
        /\ snapshotSeg1State = "Unused"
        /\ snapshotSeg2State = "Unused"
        /\ rejectCount = 0
        /\ commitAtClose = 0

Environment == /\ \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ replacementState = "Bound"
                        /\ txState = "Unused"
                        /\ freeControlCredits = 1
                        /\ freeSegmentCredits = 2
                     /\ txState' = "Staged"
                     /\ seg1State' = "Staged"
                     /\ seg2State' = "Staged"
                     /\ txBinding' = bindingEpoch
                     /\ seg1Binding' = bindingEpoch
                     /\ seg2Binding' = bindingEpoch
                     /\ freeControlCredits' = 0
                     /\ freeSegmentCredits' = 0
                     /\ recoveryRevision' = recoveryRevision + 1
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, currentImage, currentTls, currentStack, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ replacementState = "Bound"
                        /\ txState = "Staged"
                        /\ seg1State = "Staged"
                        /\ seg2State = "Staged"
                        /\ txBinding = bindingEpoch
                        /\ seg1Binding = bindingEpoch
                        /\ seg2Binding = bindingEpoch
                     /\ txState' = "Committed"
                     /\ seg1State' = "Committed"
                     /\ seg2State' = "Committed"
                     /\ receiptPrevious' = currentImage
                     /\ receiptImage' = "New"
                     /\ receiptSegments' = {"Seg1", "Seg2"}
                     /\ receiptTls' = "NewTls"
                     /\ receiptStack' = "NewStack"
                     /\ currentImage' = "New"
                     /\ currentTls' = "NewTls"
                     /\ currentStack' = "NewStack"
                     /\ commitCount' = commitCount + 1
                     /\ recoveryRevision' = recoveryRevision + 1
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, txBinding, seg1Binding, seg2Binding, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ serviceAlive
                        /\ bindingEpoch < MaxBinding
                     /\ LET cohort == (IF txState \in LiveStates THEN {"Tx"} ELSE {}) \cup
                                      (IF seg1State \in LiveStates THEN {"Seg1"} ELSE {}) \cup
                                      (IF seg2State \in LiveStates THEN {"Seg2"} ELSE {}) IN
                          /\ bindingEpoch' = bindingEpoch + 1
                          /\ recoveryRevision' = recoveryRevision + 1
                          /\ serviceAlive' = FALSE
                          /\ replacementState' = "None"
                          /\ fallbackState' = "Required"
                          /\ recoveryCohort' = cohort
                          /\ snapshotState' = "Absent"
                          /\ IF cohort # {}
                                THEN /\ watchdogHeld' = TRUE
                                     /\ freeTimerCredits' = freeTimerCredits - 1
                                ELSE /\ TRUE
                                     /\ UNCHANGED << freeTimerCredits, watchdogHeld >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ ~serviceAlive
                        /\ fallbackState = "Running"
                        /\ replacementState = "None"
                     /\ snapshotState' = "Captured"
                     /\ snapshotBinding' = bindingEpoch
                     /\ snapshotRevision' = recoveryRevision
                     /\ snapshotCurrentImage' = currentImage
                     /\ snapshotTxState' = txState
                     /\ snapshotSeg1State' = seg1State
                     /\ snapshotSeg2State' = seg2State
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ ~serviceAlive
                        /\ fallbackState = "Running"
                        /\ replacementState = "None"
                        /\ snapshotState = "Captured"
                        /\ snapshotBinding = bindingEpoch
                        /\ snapshotRevision = recoveryRevision
                        /\ snapshotCurrentImage = currentImage
                        /\ snapshotTxState = txState
                        /\ snapshotSeg1State = seg1State
                        /\ snapshotSeg2State = seg2State
                     /\ replacementState' = "Ready"
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose>>
                  \/ /\ /\ scopeState = "Active"
                        /\ ~serviceAlive
                        /\ fallbackState = "Running"
                        /\ replacementState = "Ready"
                     /\ replacementState' = "Bound"
                     /\ serviceAlive' = TRUE
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, bindingEpoch, fallbackState, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose>>
                  \/ /\ \E e \in recoveryCohort:
                          /\ /\ scopeState = "Active"
                             /\ serviceAlive
                             /\ replacementState = "Bound"
                             /\ ((e = "Tx" /\ txBinding # bindingEpoch)
                                  \/ (e = "Seg1" /\ seg1Binding # bindingEpoch)
                                  \/ (e = "Seg2" /\ seg2Binding # bindingEpoch))
                          /\ IF e = "Tx"
                                THEN /\ txBinding' = bindingEpoch
                                ELSE /\ TRUE
                                     /\ UNCHANGED txBinding
                          /\ IF e = "Seg1"
                                THEN /\ seg1Binding' = bindingEpoch
                                ELSE /\ TRUE
                                     /\ UNCHANGED seg1Binding
                          /\ IF e = "Seg2"
                                THEN /\ seg2Binding' = bindingEpoch
                                ELSE /\ TRUE
                                     /\ UNCHANGED seg2Binding
                          /\ recoveryCohort' = recoveryCohort \ {e}
                          /\ recoveryRevision' = recoveryRevision + 1
                          /\ IF recoveryCohort' \ {e} = {}
                                THEN /\ watchdogHeld' = FALSE
                                     /\ freeTimerCredits' = freeTimerCredits + 1
                                ELSE /\ TRUE
                                     /\ UNCHANGED << freeTimerCredits, watchdogHeld >>
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, currentImage, currentTls, currentStack, txState, seg1State, seg2State, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose>>
                  \/ /\ /\ EnableRejects
                        /\ scopeState = "Active"
                        /\ bindingEpoch = 1
                        /\ txState \in LiveStates
                        /\ rejectCount = 0
                     /\ rejectCount' = 1
                     /\ UNCHANGED <<scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, fallbackState, replacementState, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, commitAtClose>>
                  \/ /\ scopeState = "Active"
                     /\ closingEpoch' = authorityEpoch
                     /\ authorityEpoch' = authorityEpoch + 1
                     /\ scopeState' = "Closing"
                     /\ serviceAlive' = FALSE
                     /\ replacementState' = "Closed"
                     /\ fallbackState' = "Closed"
                     /\ snapshotState' = "Absent"
                     /\ commitAtClose' = commitCount
                     /\ UNCHANGED <<bindingEpoch, recoveryRevision, currentImage, currentTls, currentStack, txState, seg1State, seg2State, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount>>
               /\ UNCHANGED << publicationCount, terminalCount, readyInvalidatedSeen >>

Kernel == /\ \/ /\ fallbackState = "Required"
                /\ fallbackState' = "Running"
                /\ UNCHANGED <<scopeState, replacementState, recoveryRevision, txState, seg1State, seg2State, publicationCount, terminalCount, readyInvalidatedSeen, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState>>
             \/ /\ /\ txState = "Committed"
                   /\ seg1State = "Committed"
                   /\ seg2State = "Committed"
                   /\ scopeState \in {"Active", "Closing"}
                /\ txState' = "Completed"
                /\ seg1State' = "Completed"
                /\ seg2State' = "Completed"
                /\ publicationCount' = publicationCount + 1
                /\ terminalCount' = terminalCount + 3
                /\ freeControlCredits' = freeControlCredits + 1
                /\ freeSegmentCredits' = freeSegmentCredits + 2
                /\ recoveryRevision' = recoveryRevision + 1
                /\ LET remaining == recoveryCohort \ Effects IN
                     /\ freeTimerCredits' =                 freeTimerCredits
                                            + IF watchdogHeld /\ remaining = {} THEN 1 ELSE 0
                     /\ recoveryCohort' = remaining
                     /\ IF watchdogHeld /\ remaining = {}
                           THEN /\ watchdogHeld' = FALSE
                           ELSE /\ TRUE
                                /\ UNCHANGED watchdogHeld
                /\ IF replacementState = "Ready"
                      THEN /\ replacementState' = "None"
                           /\ snapshotState' = "Absent"
                           /\ readyInvalidatedSeen' = TRUE
                      ELSE /\ TRUE
                           /\ UNCHANGED << replacementState, readyInvalidatedSeen, snapshotState >>
                /\ UNCHANGED <<scopeState, fallbackState>>
             \/ /\ /\ scopeState = "Closing"
                   /\ txState = "Staged"
                   /\ seg1State = "Staged"
                   /\ seg2State = "Staged"
                /\ txState' = "Aborted"
                /\ seg1State' = "Aborted"
                /\ seg2State' = "Aborted"
                /\ terminalCount' = terminalCount + 3
                /\ freeControlCredits' = freeControlCredits + 1
                /\ freeSegmentCredits' = freeSegmentCredits + 2
                /\ freeTimerCredits' =                 freeTimerCredits
                                       + IF watchdogHeld THEN 1 ELSE 0
                /\ watchdogHeld' = FALSE
                /\ recoveryCohort' = {}
                /\ UNCHANGED <<scopeState, fallbackState, replacementState, recoveryRevision, publicationCount, readyInvalidatedSeen, snapshotState>>
             \/ /\ /\ scopeState = "Closing"
                   /\ txState \in {"Unused", "Completed", "Aborted"}
                   /\ seg1State \in {"Unused", "Completed", "Aborted"}
                   /\ seg2State \in {"Unused", "Completed", "Aborted"}
                   /\ ~watchdogHeld
                   /\ recoveryCohort = {}
                   /\ freeControlCredits = 1
                   /\ freeSegmentCredits = 2
                   /\ freeTimerCredits = 1
                /\ scopeState' = "Revoked"
                /\ UNCHANGED <<fallbackState, replacementState, recoveryRevision, txState, seg1State, seg2State, publicationCount, terminalCount, readyInvalidatedSeen, freeControlCredits, freeSegmentCredits, freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState>>
          /\ UNCHANGED << authorityEpoch, closingEpoch, serviceAlive, bindingEpoch, currentImage, currentTls, currentStack, txBinding, seg1Binding, seg2Binding, commitCount, receiptPrevious, receiptImage, receiptSegments, receiptTls, receiptStack, snapshotBinding, snapshotRevision, snapshotCurrentImage, snapshotTxState, snapshotSeg1State, snapshotSeg2State, rejectCount, commitAtClose >>

Next == Environment \/ Kernel

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(Kernel)

\* END TRANSLATION

TypeOK ==
    /\ scopeState \in {"Active", "Closing", "Revoked"}
    /\ authorityEpoch \in 0..1
    /\ bindingEpoch \in 0..MaxBinding
    /\ fallbackState \in {"Standby", "Required", "Running", "Closed"}
    /\ replacementState \in {"None", "Ready", "Bound", "Closed"}
    /\ currentImage \in {"Old", "New"}
    /\ currentTls \in {"OldTls", "NewTls"}
    /\ currentStack \in {"OldStack", "NewStack"}
    /\ txState \in {"Unused", "Staged", "Committed", "Completed", "Aborted"}
    /\ seg1State \in {"Unused", "Staged", "Committed", "Completed", "Aborted"}
    /\ seg2State \in {"Unused", "Staged", "Committed", "Completed", "Aborted"}
    /\ receiptSegments \subseteq {"Seg1", "Seg2"}
    /\ readyInvalidatedSeen \in BOOLEAN
    /\ recoveryCohort \subseteq Effects
    /\ freeControlCredits \in 0..1
    /\ freeSegmentCredits \in 0..2
    /\ freeTimerCredits \in 0..1

AtomicImageVisibility ==
    /\ (commitCount = 0 =>
          /\ currentImage = "Old"
          /\ currentTls = "OldTls"
          /\ currentStack = "OldStack")
    /\ (commitCount = 1 =>
          /\ currentImage = "New"
          /\ currentTls = "NewTls"
          /\ currentStack = "NewStack")
    /\ (txState = "Staged" => currentImage = "Old")

FrozenCommitReceipt ==
    /\ commitCount \in 0..1
    /\ publicationCount \in 0..1
    /\ publicationCount <= commitCount
    /\ (commitCount = 0 =>
          /\ receiptPrevious = "None"
          /\ receiptImage = "None"
          /\ receiptSegments = {}
          /\ receiptTls = "None"
          /\ receiptStack = "None")
    /\ (commitCount = 1 =>
          /\ receiptPrevious = "Old"
          /\ receiptImage = "New"
          /\ receiptSegments = {"Seg1", "Seg2"}
          /\ receiptTls = "NewTls"
          /\ receiptStack = "NewStack")

StateCohesion ==
    /\ ((txState = seg1State) /\ (seg1State = seg2State))
    /\ terminalCount \in {0, 3}

BudgetConservation ==
    /\ freeControlCredits + (IF txState \in LiveStates THEN 1 ELSE 0) = 1
    /\ freeSegmentCredits
         + (IF seg1State \in LiveStates THEN 1 ELSE 0)
         + (IF seg2State \in LiveStates THEN 1 ELSE 0) = 2
    /\ freeTimerCredits + (IF watchdogHeld THEN 1 ELSE 0) = 1

PostRevokeCommitExclusion ==
    scopeState \in {"Closing", "Revoked"} => commitCount = commitAtClose

SnapshotDiscipline ==
    replacementState = "Ready" =>
      /\ snapshotBinding = bindingEpoch
      /\ snapshotRevision = recoveryRevision
      /\ snapshotCurrentImage = currentImage
      /\ snapshotTxState = txState
      /\ snapshotSeg1State = seg1State
      /\ snapshotSeg2State = seg2State

QuiescentClosure ==
    scopeState = "Revoked" =>
      /\ txState \in {"Unused", "Completed", "Aborted"}
      /\ seg1State \in {"Unused", "Completed", "Aborted"}
      /\ seg2State \in {"Unused", "Completed", "Aborted"}
      /\ ~watchdogHeld
      /\ recoveryCohort = {}
      /\ freeControlCredits = 1
      /\ freeSegmentCredits = 2
      /\ freeTimerCredits = 1

ReadyInvalidationDiscipline ==
    readyInvalidatedSeen => /\ publicationCount = 1 /\ bindingEpoch = 1

RejectSideEffectFreedom ==
    [][rejectCount' # rejectCount => UNCHANGED <<
        scopeState, authorityEpoch, closingEpoch, serviceAlive, bindingEpoch,
        fallbackState, replacementState, recoveryRevision, currentImage,
        currentTls, currentStack, txState, seg1State, seg2State, txBinding,
        seg1Binding, seg2Binding, commitCount, publicationCount, terminalCount,
        receiptPrevious, receiptImage, receiptSegments, receiptTls,
        receiptStack, readyInvalidatedSeen, freeControlCredits, freeSegmentCredits,
        freeTimerCredits, watchdogHeld, recoveryCohort, snapshotState,
        snapshotBinding, snapshotRevision, snapshotCurrentImage,
        snapshotTxState, snapshotSeg1State, snapshotSeg2State, commitAtClose
    >>]_vars

FallbackProgress == [](fallbackState = "Required" ~> fallbackState # "Required")
PublicationProgress == [](txState = "Committed" ~> txState = "Completed")
RevocationProgress == [](scopeState = "Closing" ~> scopeState = "Revoked")

CommitObserved == /\ commitCount = 1 /\ currentImage = "New"
RevokeBeforeCommitObserved ==
    /\ scopeState = "Revoked"
    /\ commitAtClose = 0
    /\ txState = "Aborted"
    /\ currentImage = "Old"
CrashAdoptCommitObserved ==
    /\ bindingEpoch = 1
    /\ snapshotBinding = 1
    /\ snapshotTxState = "Staged"
    /\ snapshotSeg1State = "Staged"
    /\ snapshotSeg2State = "Staged"
    /\ commitCount = 1
    /\ recoveryCohort = {}
    /\ txBinding = 1
    /\ seg1Binding = 1
    /\ seg2Binding = 1
CommitBeforeRevokeObserved ==
    /\ scopeState = "Revoked"
    /\ commitAtClose = 1
    /\ txState = "Completed"
    /\ currentImage = "New"
ReadyInvalidatedObserved == readyInvalidatedSeen
StaleBindingFenceObserved == /\ bindingEpoch = 1 /\ rejectCount = 1

CommitAbsent == ~CommitObserved
RevokeBeforeCommitAbsent == ~RevokeBeforeCommitObserved
CrashAdoptCommitAbsent == ~CrashAdoptCommitObserved
CommitBeforeRevokeAbsent == ~CommitBeforeRevokeObserved
ReadyInvalidatedAbsent == ~ReadyInvalidatedObserved
StaleBindingFenceAbsent == ~StaleBindingFenceObserved

=============================================================================

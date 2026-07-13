#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TLC_WORKERS=${TLC_WORKERS:-auto}
COVERAGE_CONFIG=
COVERAGE_LOG=

if [ -n "${TLA2TOOLS_JAR:-}" ]; then
    JAR=$TLA2TOOLS_JAR
elif [ -f "$SCRIPT_DIR/tla2tools.jar" ]; then
    JAR=$SCRIPT_DIR/tla2tools.jar
else
    echo "set TLA2TOOLS_JAR to a tla2tools.jar path" >&2
    exit 2
fi

cleanup() {
    rm -rf "$SCRIPT_DIR/states"
    rm -f "$SCRIPT_DIR"/*_TTrace_*.bin
    rm -f "$SCRIPT_DIR"/*_TTrace_*.tla
    if [ -n "$COVERAGE_CONFIG" ]; then
        rm -f "$COVERAGE_CONFIG"
    fi
    if [ -n "$COVERAGE_LOG" ]; then
        rm -f "$COVERAGE_LOG"
    fi
}
trap cleanup EXIT HUP INT TERM

run_tlc() {
    title=$1
    spec=$2
    config=$3
    echo "==> $title"
    cleanup

    java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -cleanup \
        -workers "$TLC_WORKERS" \
        -config "$SCRIPT_DIR/$config" \
        "$SCRIPT_DIR/${spec}.tla"
    cleanup
}

expect_reachable() {
    spec=$1
    base_config=$2
    invariant=$3
    description=$4
    state_constraint=${5:-}
    cleanup
    COVERAGE_CONFIG=
    COVERAGE_LOG=
    COVERAGE_CONFIG=$(mktemp \
        "${TMPDIR:-/tmp}/nexus-cser-coverage.XXXXXX.cfg")
    COVERAGE_LOG=$(mktemp \
        "${TMPDIR:-/tmp}/nexus-cser-coverage.XXXXXX.log")
    cp "$SCRIPT_DIR/$base_config" "$COVERAGE_CONFIG"
    printf '\nINVARIANT %s\n' "$invariant" >>"$COVERAGE_CONFIG"
    if [ -n "$state_constraint" ]; then
        printf 'CONSTRAINT %s\n' "$state_constraint" >>"$COVERAGE_CONFIG"
    fi
    echo "==> $spec reachability: $description"

    if java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -cleanup \
        -workers "$TLC_WORKERS" \
        -config "$COVERAGE_CONFIG" \
        "$SCRIPT_DIR/${spec}.tla" >"$COVERAGE_LOG" 2>&1; then
        cat "$COVERAGE_LOG"
        cleanup
        echo "expected reachability witness was not found: $description" >&2
        exit 1
    fi
    if ! grep -F "Invariant $invariant is violated" \
        "$COVERAGE_LOG" >/dev/null; then
        cat "$COVERAGE_LOG"
        cleanup
        echo "TLC failed without the expected witness: $description" >&2
        exit 1
    fi
    cat "$COVERAGE_LOG"
    echo "COVERAGE_RESULT PASS $description"
    cleanup
    COVERAGE_CONFIG=
    COVERAGE_LOG=
}

expect_core_reachable() {
    spec=LinuxIoCompositionCser
    base_config=LinuxIoCompositionCserSafetyMC.cfg
    cleanup
    COVERAGE_CONFIG=
    COVERAGE_CONFIG=$(mktemp \
        "${TMPDIR:-/tmp}/nexus-cser-core-coverage.XXXXXX.cfg")
    cp "$SCRIPT_DIR/$base_config" "$COVERAGE_CONFIG"
    for invariant in \
        SevenDomainLinuxIoClosureAbsent \
        FsVisibleNetSuppressedAbsent \
        NetVisibleFsSuppressedAbsent \
        ReadinessBeforeRevokeAbsent \
        RevokeBeforeReadinessAbsent; do
        printf '\nINVARIANT %s\n' "$invariant" >>"$COVERAGE_CONFIG"
    done
    printf 'CONSTRAINT CoreWitnessScenario\n' >>"$COVERAGE_CONFIG"
    echo "==> $spec reachability: five Core witnesses in one complete graph"

    if ! java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -cleanup \
        -continue \
        -workers "$TLC_WORKERS" \
        -config "$COVERAGE_CONFIG" \
        "$SCRIPT_DIR/${spec}.tla" 2>&1 | awk '
            BEGIN {
                order[1] = "SevenDomainLinuxIoClosureAbsent"
                order[2] = "FsVisibleNetSuppressedAbsent"
                order[3] = "NetVisibleFsSuppressedAbsent"
                order[4] = "ReadinessBeforeRevokeAbsent"
                order[5] = "RevokeBeforeReadinessAbsent"
                for (i = 1; i <= 5; i++) expected[order[i]] = 1
            }
            /^Error: Invariant .* is violated\.$/ {
                name = $0
                sub(/^Error: Invariant /, "", name)
                sub(/ is violated\.$/, "", name)
                if (!(name in expected)) {
                    print "unexpected invariant violation: " name > "/dev/stderr"
                    failed = 1
                } else {
                    if (!(name in seen)) {
                        print "COVERAGE_INVARIANT " name
                    }
                    seen[name] = 1
                }
                next
            }
            /^Error: The behavior up to this point is:$/ { next }
            /^Error:/ {
                print > "/dev/stderr"
                failed = 1
                next
            }
            /^Model checking completed\. No error has been found\.$/ {
                complete = 1
                print
                next
            }
            /states generated, .* distinct states found,/ { print; next }
            /^The depth of the complete state graph search is / { print; next }
            /^Finished in / { print; next }
            END {
                for (i = 1; i <= 5; i++) {
                    name = order[i]
                    if (!(name in seen)) {
                        print "expected reachability witness was not found: " \
                            name > "/dev/stderr"
                        failed = 1
                    }
                }
                if (!complete) {
                    print "grouped Core reachability did not complete" > "/dev/stderr"
                    failed = 1
                }
                exit failed
            }
        '; then
        cleanup
        echo "grouped Core reachability failed" >&2
        exit 1
    fi
    echo "COVERAGE_RESULT PASS seven domains close the fixed nine-effect graph with exact publications and receipts"
    echo "COVERAGE_RESULT PASS filesystem publication remains visible while the network branch aborts"
    echo "COVERAGE_RESULT PASS network publication remains visible while the filesystem branch aborts"
    echo "COVERAGE_RESULT PASS readiness commit can win before root revocation without a fabricated reply"
    echo "COVERAGE_RESULT PASS root revocation can fence readiness after an immutable network publication"
    cleanup
    COVERAGE_CONFIG=
}

run_spec() {
    case "$1" in
        Cser)
            run_tlc "Cser baseline safety and liveness" Cser CserMC.cfg
            ;;
        PagerCser)
            run_tlc "PagerCser safety and liveness" \
                PagerCser PagerCserMC.cfg
            ;;
        IoCser)
            run_tlc "IoCser 3-ID safety graph (symmetry, no liveness)" \
                IoCser IoCserSafetyMC.cfg
            expect_reachable IoCser IoCserSafetyMC.cfg \
                CoverageWitnessAbsent \
                "budget-only RegisterReject and binding-only PublishReject"
            expect_reachable IoCser IoCserSafetyMC.cfg \
                MixedResetOutcomesAbsent \
                "mixed Completed and IndeterminateAfterReset outcomes"
            run_tlc "IoCser action properties and weak-fair liveness (no symmetry)" \
                IoCser IoCserMC.cfg
            ;;
        PersonalityCser)
            run_tlc "PersonalityCser 2-ID safety graph (symmetry, no liveness)" \
                PersonalityCser PersonalityCserSafetyMC.cfg
            expect_reachable PersonalityCser \
                PersonalityCserSafetyMC.cfg \
                OldBindingRecoveryAbsent \
                "write commit/crash/adopt with old-binding rejection"
            expect_reachable PersonalityCser \
                PersonalityCserSafetyMC.cfg \
                ExitGroupDeliveryAbsent \
                "exit_group exits once without resuming"
            expect_reachable PersonalityCser \
                PersonalityCserSafetyMC.cfg \
                RevocationSplitAbsent \
                "committed write drain plus uncommitted abort"
            run_tlc "PersonalityCser action properties and weak-fair liveness (no symmetry)" \
                PersonalityCser PersonalityCserMC.cfg
            ;;
        PersonalityFutexCser)
            run_tlc "PersonalityFutexCser reject-enabled safety graph" \
                PersonalityFutexCser PersonalityFutexCserSafetyMC.cfg
            expect_reachable PersonalityFutexCser \
                PersonalityFutexCserSafetyMC.cfg \
                MismatchAbsent \
                "compare mismatch returns EAGAIN without queue or credit ownership"
            expect_reachable PersonalityFutexCser \
                PersonalityFutexCserSafetyMC.cfg \
                CrashAdoptCancelAbsent \
                "crash/rebind/adopt cancels the recovery watchdog while wait remains queued"
            expect_reachable PersonalityFutexCser \
                PersonalityFutexCserSafetyMC.cfg \
                WakeBeforeRevokeAbsent \
                "wake commit wins and closure preserves the selected waiter"
            expect_reachable PersonalityFutexCser \
                PersonalityFutexCserSafetyMC.cfg \
                RevokeBeforeWakeAbsent \
                "revocation wins and the unselected wait aborts"
            expect_reachable PersonalityFutexCser \
                PersonalityFutexCserSafetyMC.cfg \
                WatchdogRevokeAbsent \
                "orphan recovery watchdog drives quiescent authority closure"
            run_tlc "PersonalityFutexCser action properties and weak-fair kernel liveness" \
                PersonalityFutexCser PersonalityFutexCserMC.cfg
            ;;
        PersonalityFutexRequeueCser)
            run_tlc "PersonalityFutexRequeueCser reject-enabled safety graph" \
                PersonalityFutexRequeueCser PersonalityFutexRequeueCserSafetyMC.cfg
            expect_reachable PersonalityFutexRequeueCser \
                PersonalityFutexRequeueCserSafetyMC.cfg \
                TwoAffectedAbsent \
                "wake one and move one freezes Linux affected count two"
            expect_reachable PersonalityFutexRequeueCser \
                PersonalityFutexRequeueCserSafetyMC.cfg \
                MoveOnlyAbsent \
                "move-only requeue retains the waiter and returns one"
            expect_reachable PersonalityFutexRequeueCser \
                PersonalityFutexRequeueCserSafetyMC.cfg \
                CurrentBindingFenceAbsent \
                "fresh replacement cannot skip an old-binding head to migrate a current tail"
            expect_reachable PersonalityFutexRequeueCser \
                PersonalityFutexRequeueCserSafetyMC.cfg \
                CommitBeforeRevokeAbsent \
                "committed requeue drains woken and aborts moved wait at closure"
            expect_reachable PersonalityFutexRequeueCser \
                PersonalityFutexRequeueCserSafetyMC.cfg \
                RevokeBeforeCommitAbsent \
                "revocation fences requeue before any queue movement"
            expect_reachable PersonalityFutexRequeueCser \
                PersonalityFutexRequeueCserSafetyMC.cfg \
                TargetWakeAbsent \
                "target wake selects a waiter migrated from the source key"
            run_tlc "PersonalityFutexRequeueCser action properties and weak-fair kernel liveness" \
                PersonalityFutexRequeueCser PersonalityFutexRequeueCserMC.cfg
            ;;
        PersonalityReadinessCser)
            run_tlc "PersonalityReadinessCser reject-enabled safety graph" \
                PersonalityReadinessCser PersonalityReadinessCserSafetyMC.cfg
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg ReadyAbsent \
                "readiness wins with one immutable event"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg TimeoutAbsent \
                "positive timeout wins without fabricating readiness"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg RevokeAbsent \
                "revocation wins before ready or timeout commit"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg CrashAdoptAbsent \
                "replacement adopts the exact crash cohort before commit"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg LTRequeueAbsent \
                "level-triggered readiness remains queued after selection"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg OneShotDisabledAbsent \
                "one-shot subscription disables at frozen delivery"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg SourceFenceAbsent \
                "old source generation is rejected without side effects"
            expect_reachable PersonalityReadinessCser \
                PersonalityReadinessCserSafetyMC.cfg CurrentBindingFenceAbsent \
                "replacement cannot select an unadopted old-binding subscription"
            run_tlc "PersonalityReadinessCser action properties and weak-fair kernel liveness" \
                PersonalityReadinessCser PersonalityReadinessCserMC.cfg
            ;;
        PersonalityExecCser)
            run_tlc "PersonalityExecCser reject-enabled safety graph" \
                PersonalityExecCser PersonalityExecCserSafetyMC.cfg
            expect_reachable PersonalityExecCser \
                PersonalityExecCserSafetyMC.cfg CommitAbsent \
                "one atomic exec commit publishes the complete image"
            expect_reachable PersonalityExecCser \
                PersonalityExecCserSafetyMC.cfg RevokeBeforeCommitAbsent \
                "precommit revocation preserves the old image"
            expect_reachable PersonalityExecCser \
                PersonalityExecCserSafetyMC.cfg CrashAdoptCommitAbsent \
                "replacement adopts transaction and segments before commit"
            expect_reachable PersonalityExecCser \
                PersonalityExecCserSafetyMC.cfg CommitBeforeRevokeAbsent \
                "postcommit revocation drains without image rollback"
            expect_reachable PersonalityExecCser \
                PersonalityExecCserSafetyMC.cfg ReadyInvalidatedAbsent \
                "kernel publication invalidates a stale ready proof"
            expect_reachable PersonalityExecCser \
                PersonalityExecCserSafetyMC.cfg StaleBindingFenceAbsent \
                "old exec binding is rejected without side effects"
            run_tlc "PersonalityExecCser action properties and weak-fair kernel liveness" \
                PersonalityExecCser PersonalityExecCserMC.cfg
            ;;
        RuntimeFsCser)
            run_tlc "RuntimeFsCser four-domain reject-enabled safety graph" \
                RuntimeFsCser RuntimeFsCserSafetyMC.cfg
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                FourDomainPwriteClosureAbsent \
                "four-domain pwrite workload closes child-first and returns all credits"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                RevokeBeforePwriteAbsent \
                "revocation before pwrite preserves zero bytes and publishes no reply"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                PagerCrashAdoptMapAbsent \
                "pager crash requires explicit adoption before one PTE and TLB publication"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                FsCrashAdoptWriteAbsent \
                "filesystem crash requires explicit adoption before one inode publication"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                BlockCrashDeviceDrainAbsent \
                "committed block request drains through the device without adoption"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                ResetTimeoutRetryClosureAbsent \
                "reset timeout retains DMA through retry and fresh closure"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                IotlbTimeoutRetryClosureAbsent \
                "IOTLB timeout retains owner and outcome through retry"
            expect_reachable RuntimeFsCser \
                RuntimeFsCserSafetyMC.cfg \
                StaleTokenFencesAbsent \
                "all generation classes and stale timeout receipt reject without mutation"
            run_tlc "RuntimeFsCser action properties and conditional revocation progress" \
                RuntimeFsCser RuntimeFsCserMC.cfg
            ;;
        RuntimeNetCser)
            run_tlc "RuntimeNetCser three-domain reject-enabled safety graph" \
                RuntimeNetCser RuntimeNetCserSafetyMC.cfg
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                LoopbackClosureAbsent \
                "bounded loopback reaches ordered net, readiness, and guest publication before quiescent closure"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                RevokeBeforeNetCommitAbsent \
                "precommit revocation aborts the fixed graph without publication"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                NetdCrashAdoptAcceptAbsent \
                "network-service crash requires exact snapshot, ready, rebind, and explicit cohort adoption"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                ReadinessBeforeRevokeAbsent \
                "readiness commit can win before revocation while guest reply stays absent"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                RevokeBeforeReadinessAbsent \
                "revocation can fence readiness publication after the network commit"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                PersonalityCrashDrainAbortAbsent \
                "personality crash drains a committed reply and aborts an uncommitted sibling"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                BufferVisibleReplyAbsentAbsent \
                "network-visible buffer can remain live while guest reply is absent"
            expect_reachable RuntimeNetCser \
                RuntimeNetCserSafetyMC.cfg \
                StaleTokenFencesAbsent \
                "authority, binding, socket, and source generations reject without mutation"
            run_tlc "RuntimeNetCser action properties and conditional revocation progress" \
                RuntimeNetCser RuntimeNetCserMC.cfg
            ;;
        CompositionCser)
            run_tlc "CompositionCser five-domain safety graph" \
                CompositionCser CompositionCserSafetyMC.cfg
            expect_reachable CompositionCser \
                CompositionCserSafetyMC.cfg \
                FiveDomainClosureAbsent \
                "five-domain cohort closes with five globally sequenced receipts"
            expect_reachable CompositionCser \
                CompositionCserSafetyMC.cfg \
                CrashAdoptIsolationAbsent \
                "one domain crashes and adopts without advancing peer bindings"
            expect_reachable CompositionCser \
                CompositionCserSafetyMC.cfg \
                CommitAbortSplitAbsent \
                "committed descendants complete while uncommitted descendants abort"
            expect_reachable CompositionCser \
                CompositionCserSafetyMC.cfg \
                TimeoutRetryClosureAbsent \
                "VirtIo timeout tombstone, stale receipt reject, retry, and fresh closure receipt"
            run_tlc "CompositionCser action properties and conditional kernel liveness" \
                CompositionCser CompositionCserMC.cfg
            ;;
        LinuxIoCompositionCser)
            run_tlc "LinuxIoCompositionCser seven-domain reject-enabled safety and action graph" \
                LinuxIoCompositionCser LinuxIoCompositionCserSafetyMC.cfg
            expect_reachable LinuxIoCompositionCser \
                LinuxIoCompositionCserSafetyMC.cfg \
                RevokeBeforeIoPublicationAbsent \
                "root revocation can suppress both filesystem and network publication" \
                DeriveRaceWitnessScenario
            expect_core_reachable
            expect_reachable LinuxIoCompositionCser \
                LinuxIoCompositionCserSafetyMC.cfg \
                FilesystemCrashAdoptIsolationAbsent \
                "filesystem crash requires explicit adoption without advancing peer bindings" \
                FilesystemCrashWitnessScenario
            expect_reachable LinuxIoCompositionCser \
                LinuxIoCompositionCserSafetyMC.cfg \
                NetworkCrashAdoptIsolationAbsent \
                "network crash adopts operation and buffer without advancing peer bindings" \
                NetworkCrashWitnessScenario
            expect_reachable LinuxIoCompositionCser \
                LinuxIoCompositionCserSafetyMC.cfg \
                VirtIoResetIotlbTombstoneClosureAbsent \
                "reset and IOTLB tombstones retain DMA through fresh-receipt closure" \
                DmaTimeoutWitnessScenario
            expect_reachable LinuxIoCompositionCser \
                LinuxIoCompositionCserSafetyMC.cfg \
                StaleEnvelopeAndReceiptFencesAbsent \
                "all authority, generation, receipt, and replay rejects are side-effect free" \
                RejectProbeWitnessScenario
            run_tlc "LinuxIoCompositionCser conditional kernel-closure liveness" \
                LinuxIoCompositionCser LinuxIoCompositionCserMC.cfg
            run_tlc "LinuxIoCompositionCser conditional crash-fallback liveness" \
                LinuxIoCompositionCser LinuxIoCompositionCserFallbackMC.cfg
            ;;
        *)
            echo "unknown CSER specification: $1" >&2
            exit 2
            ;;
    esac
}

case $# in
    0)
        run_spec Cser
        run_spec PagerCser
        run_spec IoCser
        run_spec PersonalityCser
        run_spec PersonalityFutexCser
        run_spec PersonalityFutexRequeueCser
        run_spec PersonalityReadinessCser
        run_spec PersonalityExecCser
        run_spec RuntimeFsCser
        run_spec RuntimeNetCser
        run_spec CompositionCser
        run_spec LinuxIoCompositionCser
        ;;
    1) run_spec "$1" ;;
    *)
        echo "usage: $0 [Cser|PagerCser|IoCser|PersonalityCser|PersonalityFutexCser|PersonalityFutexRequeueCser|PersonalityReadinessCser|PersonalityExecCser|RuntimeFsCser|RuntimeNetCser|CompositionCser|LinuxIoCompositionCser]" >&2
        exit 2
        ;;
esac

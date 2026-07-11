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
    cleanup
    COVERAGE_CONFIG=
    COVERAGE_LOG=
    COVERAGE_CONFIG=$(mktemp \
        "${TMPDIR:-/tmp}/nexus-cser-coverage.XXXXXX.cfg")
    COVERAGE_LOG=$(mktemp \
        "${TMPDIR:-/tmp}/nexus-cser-coverage.XXXXXX.log")
    cp "$SCRIPT_DIR/$base_config" "$COVERAGE_CONFIG"
    printf '\nINVARIANT %s\n' "$invariant" >>"$COVERAGE_CONFIG"
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
        ;;
    1) run_spec "$1" ;;
    *)
        echo "usage: $0 [Cser|PagerCser|IoCser|PersonalityCser|PersonalityFutexCser]" >&2
        exit 2
        ;;
esac

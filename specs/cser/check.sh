#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -n "${TLA2TOOLS_JAR:-}" ]; then
    JAR=$TLA2TOOLS_JAR
elif [ -f "$SCRIPT_DIR/tla2tools.jar" ]; then
    JAR=$SCRIPT_DIR/tla2tools.jar
else
    echo "set TLA2TOOLS_JAR to a tla2tools.jar path" >&2
    exit 2
fi

cleanup() {
    rmdir "$SCRIPT_DIR/states" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

run_spec() {
    case "$1" in
        Cser|PagerCser) spec=$1 ;;
        *)
            echo "unknown CSER specification: $1" >&2
            exit 2
            ;;
    esac

    java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -cleanup \
        -config "$SCRIPT_DIR/${spec}MC.cfg" \
        "$SCRIPT_DIR/${spec}.tla"
}

case $# in
    0)
        run_spec Cser
        run_spec PagerCser
        ;;
    1) run_spec "$1" ;;
    *)
        echo "usage: $0 [Cser|PagerCser]" >&2
        exit 2
        ;;
esac

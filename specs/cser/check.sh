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

java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
    -cleanup \
    -config "$SCRIPT_DIR/CserMC.cfg" \
    "$SCRIPT_DIR/Cser.tla"

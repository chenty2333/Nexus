#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cc -c guest/probe.S -o "$tmp/probe.o"
objcopy -O binary -j .text "$tmp/probe.o" guest/probe.bin


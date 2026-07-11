#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for guest in probe pager-client pager-v1 pager-v2; do
    cc -c "guest/$guest.S" -o "$tmp/$guest.o"
    objcopy -O binary -j .text "$tmp/$guest.o" "guest/$guest.bin"
done

#!/usr/bin/env bash
# Create the blank, fixed-size media contract used by every real tool-plus-DMA
# matrix row.  The matrix copies these files before each initial boot; this
# helper is deliberately not invoked by recovery and never mutates a trial.
set -euo pipefail

if (($# != 1)); then
  echo "usage: $0 BASE_MEDIA_DIRECTORY" >&2
  exit 2
fi

base=$1
mkdir -p -- "$base"
base=$(cd "$base" && pwd -P)

declare -A sizes=(
  [journal.raw]=$((4 * 1024 * 1024))
  [outbox.raw]=$((4 * 1024 * 1024))
  [ram.raw]=$((1024 * 1024 * 1024))
)

for name in journal.raw outbox.raw ram.raw; do
  path="$base/$name"
  if [[ -e $path && ! -f $path ]]; then
    echo "base medium is not a regular file: $path" >&2
    exit 1
  fi
  # A preexisting image is accepted only if it has the exact QEMU contract.
  # This avoids silently turning a reused experiment snapshot into a new base.
  if [[ -e $path ]]; then
    [[ $(stat -c %s -- "$path") == "${sizes[$name]}" ]] || {
      echo "base medium has wrong size: $path" >&2
      exit 1
    }
  else
    truncate -s "${sizes[$name]}" -- "$path"
  fi
done

echo "TOOL_DMA_BASE_MEDIA PASS directory=$base journal_bytes=${sizes[journal.raw]} outbox_bytes=${sizes[outbox.raw]} ram_bytes=${sizes[ram.raw]}"

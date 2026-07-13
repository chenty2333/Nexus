#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

die() {
    echo "runtime fs block-image build: FAIL: $*" >&2
    exit 1
}

if (( $# != 2 )); then
    die "usage: $0 RUNTIME_FS_ELF OUTPUT_RAW_IMAGE"
fi

elf=$1
output=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
oracle=${NEXUS_RUNTIME_FS_BLOCK_IMAGE_ORACLE:-$script_dir/assert-runtime-fs-block-image.sh}

for command_name in bash chmod cmp cp dirname mkdir mktemp mv rm truncate; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done
[[ -f "$elf" && ! -L "$elf" ]] || die "missing regular non-symlink ELF: $elf"
[[ -f "$oracle" && ! -L "$oracle" ]] || die "missing regular non-symlink oracle: $oracle"
[[ ! -L "$output" ]] || die "refusing to replace symlink output: $output"

output_parent=$(dirname -- "$output")
mkdir -p "$output_parent"
tmp=$(mktemp "$output_parent/.runtime-fs-block.XXXXXX")
trap 'rm -f "$tmp"' EXIT

cp "$elf" "$tmp"
cmp -s "$elf" "$tmp" || die "temporary image prefix copy differs from ELF"
truncate -s 10240 "$tmp"
chmod 0444 "$tmp"
bash "$oracle" "$elf" "$tmp" >/dev/null

mv -f "$tmp" "$output"
trap - EXIT
bash "$oracle" "$elf" "$output"

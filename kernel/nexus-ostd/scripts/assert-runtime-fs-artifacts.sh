#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=c5a4014d88794ddccd1c5239957a43500a6637a433640c2293e699fea72b870f
readonly pinned_artifact_sha=0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef
readonly first_pread_payload_sha=3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359

die() {
    echo "runtime fs artifact assertion: FAIL: $*" >&2
    exit 1
}

sha_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

require_regular_file() {
    local label=$1
    local path=$2

    [[ -f "$path" && ! -L "$path" ]] || die "$label is not a regular non-symlink file: $path"
}

require_sha256() {
    local label=$1
    local path=$2
    local expected=$3
    local actual

    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "$label expected SHA is not 64 lowercase hex: ${expected:-unset}"
    actual=$(sha_file "$path")
    [[ "$actual" == "$expected" ]] ||
        die "$label SHA mismatch expected=$expected actual=$actual file=$path"
}

if (( $# < 2 || $# > 3 )); then
    die "usage: $0 RETAINED_SOURCE ELF [EXPECTED_ARTIFACT_SHA]"
fi

source_file=$1
elf_file=$2
expected_artifact_sha=${3-$pinned_artifact_sha}

for command_name in awk cut grep head nm readelf sha256sum strings; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done

require_regular_file retained-source "$source_file"
require_regular_file artifact "$elf_file"
require_sha256 retained-source "$source_file" "$expected_source_sha"

header=$(readelf -hW "$elf_file")
programs=$(readelf -lW "$elf_file")
sections=$(readelf -SW "$elf_file")

for pattern in \
    'Class:.*ELF64' \
    'Data:.*little endian' \
    'Type:.*EXEC' \
    'Machine:.*X86-64' \
    'Entry point address:.*0x401000'; do
    grep -Eq "$pattern" <<<"$header" || die "ELF header assertion failed: $pattern"
done

if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' <<<"$programs"; then
    die 'artifact must be static and must not contain PT_INTERP or PT_DYNAMIC'
fi

if ! awk '
    $1 == "LOAD" {
        flags = ""
        for (field = 7; field < NF; field++) flags = flags $field
        loads++
        if (flags ~ /E/) executable++
        if (flags ~ /W/ && flags ~ /E/) wx++
    }
    END {
        exit loads >= 3 && executable == 1 && wx == 0 ? 0 : 1
    }
' <<<"$programs"; then
    die 'PT_LOAD layout must separate code/read-only data, contain one executable segment, and satisfy W^X'
fi

if awk '
    $1 == "GNU_STACK" && $0 ~ / E / { executable = 1 }
    END { exit executable ? 0 : 1 }
' <<<"$programs"; then
    die 'artifact requests an executable stack'
fi

grep -Eq '[[:space:]]\.text[[:space:]]+PROGBITS.*[[:space:]]AX[[:space:]]' <<<"$sections" ||
    die 'artifact is missing executable .text'
grep -Eq '[[:space:]]\.rodata[[:space:]]+PROGBITS.*[[:space:]]A[[:space:]]' <<<"$sections" ||
    die 'artifact is missing read-only .rodata'
if ! grep -Fq 'There are no relocations in this file.' < <(readelf -rW "$elf_file"); then
    die 'artifact contains runtime relocations'
fi
undefined=$(nm -u "$elf_file")
[[ -z "$undefined" ]] || die "artifact contains undefined symbols: $undefined"
if grep -Eq '\((NEEDED|RPATH|RUNPATH|REL|RELA|RELSZ|RELASZ|JMPREL|PLTGOT|TEXTREL)\)' \
    < <(readelf -dW "$elf_file"); then
    die 'artifact contains a runtime-link dependency or relocation table'
fi

strings -a "$elf_file" | grep -Fxq 'runtime fs ok' ||
    die 'artifact lost the retained success marker'
strings -a "$elf_file" | grep -Fxq '/tmp/runtime-fs.bin' ||
    die 'artifact lost the bounded writable-file path'
strings -a "$elf_file" | grep -Fxq '/proc/self' ||
    die 'artifact lost the relative procfs lookup path'

artifact_sha=$(sha_file "$elf_file")
if [[ -z "$expected_artifact_sha" ]]; then
    die "expected artifact SHA is unset; candidate_artifact_sha=$artifact_sha"
fi
require_sha256 artifact "$elf_file" "$expected_artifact_sha"
actual_first_pread_payload_sha=$(head -c 4 "$elf_file" | sha256sum | cut -d ' ' -f1)
[[ $actual_first_pread_payload_sha == "$first_pread_payload_sha" ]] ||
    die "first pread payload SHA mismatch expected=$first_pread_payload_sha actual=$actual_first_pread_payload_sha"

entry=$(awk -F: '/Entry point address:/ { gsub(/[[:space:]]/, "", $2); print $2 }' <<<"$header")
load_count=$(awk '$1 == "LOAD" { count++ } END { print count + 0 }' <<<"$programs")
echo "runtime fs artifact assertions: PASS source_sha=$expected_source_sha artifact_sha=$artifact_sha first_pread_payload_sha=$first_pread_payload_sha elf=ELF64 machine=x86_64 type=ET_EXEC entry=$entry static=true pt_interp=false load_segments=$load_count wx=false exec_stack=false runtime_dependencies=none"

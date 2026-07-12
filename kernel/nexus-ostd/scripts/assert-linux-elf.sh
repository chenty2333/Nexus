#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

source_file=${1:?usage: assert-linux-elf.sh SOURCE ELF}
elf_file=${2:?usage: assert-linux-elf.sh SOURCE ELF}
expected_source_sha=50690500a3cfac0f412da66d3d5d7f32b9b4da2a96a38d6d21c3ef12ea141490
expected_artifact_sha=1dae72e6d4a5c9144e94580a8e2a8280cb36f725d66046baed77562051b2f1a4

actual_source_sha=$(sha256sum "$source_file" | cut -d ' ' -f1)
if [[ "$actual_source_sha" != "$expected_source_sha" ]]; then
    echo "linux-hello retained source SHA mismatch: $actual_source_sha" >&2
    exit 1
fi

header=$(readelf -hW "$elf_file")
programs=$(readelf -lW "$elf_file")

for pattern in \
    'Class:.*ELF64' \
    'Data:.*little endian' \
    'Type:.*EXEC' \
    'Machine:.*X86-64'; do
    if ! grep -Eq "$pattern" <<<"$header"; then
        echo "linux-hello ELF header assertion failed: $pattern" >&2
        exit 1
    fi
done

if grep -Eq '^[[:space:]]*INTERP[[:space:]]' <<<"$programs"; then
    echo "linux-hello must not contain PT_INTERP" >&2
    exit 1
fi
if grep -Eq '^[[:space:]]*LOAD.*RWE' <<<"$programs"; then
    echo "linux-hello must not contain a writable executable PT_LOAD" >&2
    exit 1
fi
if [[ $(grep -Ec '^[[:space:]]*LOAD[[:space:]]' <<<"$programs") -lt 1 ]]; then
    echo "linux-hello must contain at least one PT_LOAD" >&2
    exit 1
fi

actual_artifact_sha=$(sha256sum "$elf_file" | cut -d ' ' -f1)
if [[ "$actual_artifact_sha" != "$expected_artifact_sha" ]]; then
    echo "linux-hello reproducible artifact SHA mismatch: $actual_artifact_sha" >&2
    exit 1
fi

echo "linux ELF assertions: PASS source_sha=$actual_source_sha artifact_sha=$actual_artifact_sha"

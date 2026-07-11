#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=f435e87ea3ded433ba330b48222ece776b72d77ae9dcba4dc348bb5e37d20c56
readonly expected_patch_sha=4269a03e573b3c23fbeb1570238b2ba30ec9e1e95e3b8f5d43b206a027490a3b
readonly expected_adapted_source_sha=9c1efb1dbe4db7f87d8eebf80f289dea8b71f896636362a34f27320424e4e8de
readonly run_timeout=5s

die() {
    echo "round4 futex adaptation oracle: FAIL: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

sha256_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

check_sha() {
    local label=$1
    local path=$2
    local expected=$3
    local actual

    actual=$(sha256_file "$path")
    [[ "$actual" == "$expected" ]] ||
        die "$label SHA-256 mismatch: expected=$expected actual=$actual path=$path"
}

if [[ $# -ne 0 ]]; then
    die "usage: $0"
fi

for command_name in awk clang cmp cp cut dirname grep mktemp patch readelf rm sha256sum timeout wc; do
    require_command "$command_name"
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../../../.." && pwd)
source_file="$repo_root/tests/guest/linux/sources/linux-round4-futex-smoke/round4_futex_smoke.S"
patch_file="$script_dir/round4-futex-modern-requeue.patch"

[[ -f "$source_file" ]] || die "missing retained source: $source_file"
[[ -f "$patch_file" ]] || die "missing adaptation patch: $patch_file"
check_sha "retained source" "$source_file" "$expected_source_sha"
check_sha "adaptation patch" "$patch_file" "$expected_patch_sha"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

adapted_source="$tmp/round4_futex_smoke.S"
object_file="$tmp/round4_futex_smoke.o"
elf_file="$tmp/round4_futex_smoke.elf"
expected_stdout="$tmp/expected.stdout"
actual_stdout="$tmp/actual.stdout"
actual_stderr="$tmp/actual.stderr"

cp -- "$source_file" "$adapted_source"
(
    cd -- "$tmp"
    patch \
        --batch \
        --forward \
        --fuzz=0 \
        --no-backup-if-mismatch \
        --reject-file=- \
        --silent \
        -p1 \
        <"$patch_file"
)
check_sha "adapted source" "$adapted_source" "$expected_adapted_source_sha"

clang \
    --target=x86_64-unknown-linux-gnu \
    -c \
    "$adapted_source" \
    -o "$object_file"
clang \
    --target=x86_64-unknown-linux-gnu \
    -nostdlib \
    -static \
    -Wl,--build-id=none \
    -Wl,-z,max-page-size=4096 \
    "$object_file" \
    -o "$elf_file"

header=$(readelf -hW "$elf_file")
programs=$(readelf -lW "$elf_file")

for pattern in \
    'Class:.*ELF64' \
    'Data:.*little endian' \
    'Type:.*EXEC' \
    'Machine:.*X86-64'; do
    grep -Eq "$pattern" <<<"$header" || die "ELF header assertion failed: $pattern"
done

if grep -Eq '^[[:space:]]*INTERP[[:space:]]' <<<"$programs"; then
    die "adapted artifact must be static and contain no PT_INTERP"
fi
if grep -Eq '^[[:space:]]*DYNAMIC[[:space:]]' <<<"$programs"; then
    die "adapted artifact must contain no PT_DYNAMIC"
fi
if [[ $(grep -Ec '^[[:space:]]*LOAD[[:space:]]' <<<"$programs") -lt 1 ]]; then
    die "adapted artifact must contain at least one PT_LOAD"
fi
if awk '
    $1 == "LOAD" {
        flags = ""
        for (field = 7; field < NF; field++) {
            flags = flags $field
        }
        if (flags ~ /W/ && flags ~ /E/) {
            writable_executable = 1
        }
    }
    END { exit writable_executable ? 0 : 1 }
' <<<"$programs"; then
    die "adapted artifact contains a writable executable PT_LOAD"
fi

printf 'round4 futex ok\n' >"$expected_stdout"
set +e
timeout \
    --foreground \
    --kill-after=1s \
    "$run_timeout" \
    "$elf_file" \
    >"$actual_stdout" \
    2>"$actual_stderr"
run_status=$?
set -e

if [[ $run_status -ne 0 ]]; then
    die "host execution failed: status=$run_status timeout=$run_timeout stderr_bytes=$(wc -c <"$actual_stderr")"
fi
cmp -s "$expected_stdout" "$actual_stdout" ||
    die "stdout mismatch: expected_bytes=$(wc -c <"$expected_stdout") actual_bytes=$(wc -c <"$actual_stdout")"
[[ ! -s "$actual_stderr" ]] ||
    die "host execution wrote stderr: bytes=$(wc -c <"$actual_stderr")"

artifact_sha=$(sha256_file "$elf_file")
echo "round4 futex adaptation oracle: PASS source_sha=$expected_source_sha patch_sha=$expected_patch_sha adapted_source_sha=$expected_adapted_source_sha artifact_sha=$artifact_sha"

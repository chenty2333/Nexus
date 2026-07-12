#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=f435e87ea3ded433ba330b48222ece776b72d77ae9dcba4dc348bb5e37d20c56
readonly expected_patch_sha=4269a03e573b3c23fbeb1570238b2ba30ec9e1e95e3b8f5d43b206a027490a3b
readonly expected_adapted_sha=9c1efb1dbe4db7f87d8eebf80f289dea8b71f896636362a34f27320424e4e8de
readonly expected_artifact_sha=c31cfc57e562e5be0e9558e5017a579b4353a016898113b07cbb467d31a2b7ca
readonly run_timeout=5s

die() {
    echo "round4 futex build: FAIL: $*" >&2
    exit 1
}

sha_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

check_sha() {
    local label=$1
    local file=$2
    local expected=$3
    local actual
    actual=$(sha_file "$file")
    [[ "$actual" == "$expected" ]] ||
        die "$label SHA mismatch expected=$expected actual=$actual file=$file"
}

if [[ $# -ne 1 ]]; then
    die "usage: $0 OUTPUT_ELF"
fi

output=$1
source_file=${NEXUS_ROUND4_FUTEX_SOURCE:-/repo/tests/guest/linux/sources/linux-round4-futex-smoke/round4_futex_smoke.S}
patch_file=${NEXUS_ROUND4_FUTEX_PATCH:-/repo/tests/guest/linux/adaptations/round4-futex-modern-requeue.patch}

for command_name in awk clang cmp cp cut dirname grep mktemp patch readelf rm sha256sum timeout wc; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done
[[ -f "$source_file" ]] || die "missing retained source: $source_file"
[[ -f "$patch_file" ]] || die "missing visible adaptation: $patch_file"
check_sha source "$source_file" "$expected_source_sha"
check_sha patch "$patch_file" "$expected_patch_sha"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
adapted="$tmp/round4_futex_smoke.S"
object="$tmp/round4_futex_smoke.o"
elf="$tmp/round4_futex_smoke.elf"
expected_stdout="$tmp/expected.stdout"
actual_stdout="$tmp/actual.stdout"
actual_stderr="$tmp/actual.stderr"

cp "$source_file" "$adapted"
(
    cd "$tmp"
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
check_sha adapted-source "$adapted" "$expected_adapted_sha"

clang \
    --target=x86_64-unknown-linux-gnu \
    -c \
    "$adapted" \
    -o "$object"
clang \
    --target=x86_64-unknown-linux-gnu \
    -nostdlib \
    -static \
    -Wl,--build-id=none \
    -Wl,-z,max-page-size=4096 \
    "$object" \
    -o "$elf"

header=$(readelf -hW "$elf")
programs=$(readelf -lW "$elf")
sections=$(readelf -SW "$elf")
for pattern in \
    'Class:.*ELF64' \
    'Data:.*little endian' \
    'Type:.*EXEC' \
    'Machine:.*X86-64' \
    'Entry point address:.*0x401000'; do
    grep -Eq "$pattern" <<<"$header" || die "ELF header assertion failed: $pattern"
done
if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' <<<"$programs"; then
    die "adapted Round 4 artifact must be static"
fi
if ! awk '
    $1 == "LOAD" {
        flags = ""
        for (field = 7; field < NF; field++) flags = flags $field
        loads++
        if (flags ~ /E/) executable++
        if (flags ~ /W/) writable++
        if (flags ~ /W/ && flags ~ /E/) wx++
    }
    END { exit loads >= 3 && executable == 1 && writable == 1 && wx == 0 ? 0 : 1 }
' <<<"$programs"; then
    die "adapted Round 4 load plan must have code/data separation and satisfy W^X"
fi
grep -Eq '[[:space:]]\.text[[:space:]]+PROGBITS.*[[:space:]]AX[[:space:]]' <<<"$sections" ||
    die "adapted Round 4 artifact is missing executable .text"
grep -Eq '[[:space:]]\.rodata[[:space:]]+PROGBITS.*[[:space:]]A[[:space:]]' <<<"$sections" ||
    die "adapted Round 4 artifact is missing read-only .rodata"
grep -Eq '[[:space:]]\.bss[[:space:]]+NOBITS.*[[:space:]]WA[[:space:]]' <<<"$sections" ||
    die "adapted Round 4 artifact is missing zero-fill writable .bss"

printf 'round4 futex ok\n' >"$expected_stdout"
set +e
timeout --foreground --kill-after=1s "$run_timeout" "$elf" \
    >"$actual_stdout" 2>"$actual_stderr"
run_status=$?
set -e
[[ $run_status -eq 0 ]] ||
    die "host Linux oracle failed status=$run_status stderr_bytes=$(wc -c <"$actual_stderr")"
cmp -s "$expected_stdout" "$actual_stdout" ||
    die "host Linux stdout mismatch expected_bytes=16 actual_bytes=$(wc -c <"$actual_stdout")"
[[ ! -s "$actual_stderr" ]] ||
    die "host Linux wrote stderr bytes=$(wc -c <"$actual_stderr")"

artifact_sha=$(sha_file "$elf")
[[ "$artifact_sha" == "$expected_artifact_sha" ]] ||
    die "pinned artifact SHA mismatch expected=$expected_artifact_sha actual=$artifact_sha"
mkdir -p "$(dirname "$output")"
cp "$elf" "$output"
echo "round4 futex build: PASS source_sha=$expected_source_sha patch_sha=$expected_patch_sha adapted_sha=$expected_adapted_sha artifact_sha=$artifact_sha host_oracle=true stdout_bytes=16"

#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=21d322d582465c939367977e6b7f23474ccedebacfa6d5f27ec97d979a9bb13c
readonly expected_patch_sha=cf19e05067a79fec35f0a5ed57e5f302129707a7b0dd57affc93bed56903026b
readonly expected_adapted_sha=1aad9899aceb23cd2e21c067a96bffed92543fa7bbd92e91f4d807a0e4843205
readonly expected_artifact_sha=1ff6f21480064d8ec84a8e58bef60c54733707fd13b1b2e46ab856daad8fc3f7

die() {
    echo "round5 epoll build: FAIL: $*" >&2
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
source_file=${NEXUS_ROUND5_EPOLL_SOURCE:-/repo/tests/guest/linux/sources/linux-round5-epoll-smoke/round5_epoll_smoke.S}
patch_file=${NEXUS_ROUND5_EPOLL_PATCH:-/repo/tests/guest/linux/adaptations/round5-epoll-linux-regular-file.patch}
oracle=${NEXUS_ROUND5_EPOLL_ORACLE:-/repo/tests/guest/linux/adaptations/verify-round5-epoll-adaptation.sh}

for command_name in awk clang cp cut dirname grep mktemp patch readelf rm sha256sum strings; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done
[[ -f "$source_file" ]] || die "missing retained source: $source_file"
[[ -f "$patch_file" ]] || die "missing visible adaptation: $patch_file"
[[ -f "$oracle" ]] || die "missing host semantic oracle: $oracle"
check_sha source "$source_file" "$expected_source_sha"
check_sha patch "$patch_file" "$expected_patch_sha"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
adapted="$tmp/round5_epoll_smoke.S"
object="$tmp/round5_epoll_smoke.o"
elf="$tmp/round5_epoll_smoke.elf"

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
    -Wl,-z,noexecstack \
    -Wl,-z,max-page-size=4096 \
    "$object" \
    -o "$elf"

header=$(readelf -hW "$elf")
programs=$(readelf -lW "$elf")
for pattern in \
    'Class:.*ELF64' \
    'Data:.*little endian' \
    'Type:.*EXEC' \
    'Machine:.*X86-64'; do
    grep -Eq "$pattern" <<<"$header" || die "ELF header assertion failed: $pattern"
done
if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' <<<"$programs"; then
    die "adapted Round 5 artifact must be static"
fi
load_count=$(grep -Ec '^[[:space:]]*LOAD[[:space:]]' <<<"$programs")
(( load_count >= 2 )) ||
    die "adapted Round 5 artifact must contain code and read-only PT_LOAD segments"
[[ $(awk '$1 == "LOAD" && $0 ~ / E / { count++ } END { print count + 0 }' <<<"$programs") -eq 1 ]] ||
    die "adapted Round 5 artifact must contain exactly one executable PT_LOAD"
if awk '
    $1 == "LOAD" {
        flags = ""
        for (field = 7; field < NF; field++) flags = flags $field
        if (flags ~ /W/ && flags ~ /E/) bad = 1
    }
    END { exit bad ? 0 : 1 }
' <<<"$programs"; then
    die "adapted Round 5 artifact violates W^X"
fi
if awk '$1 == "GNU_STACK" && $0 ~ / E / { executable = 1 } END { exit executable ? 0 : 1 }' <<<"$programs"; then
    die "adapted Round 5 artifact requests an executable stack"
fi
strings -a "$elf" | grep -Fxq '/bin/linux-hello' ||
    die "adapted Round 5 artifact lost fixed artifact lookup"
strings -a "$elf" | grep -Fxq 'round5 epoll ok' ||
    die "adapted Round 5 artifact lost success marker"

# The companion validates why the visible regular-file expectation changed.
# Full execution belongs to the Nexus guest because /bin/linux-hello is an
# intentionally bounded guest artifact, not a host installation.
bash "$oracle" >/dev/null

mkdir -p "$(dirname "$output")"
cp "$elf" "$output"
artifact_sha=$(sha_file "$output")
[[ "$artifact_sha" == "$expected_artifact_sha" ]] ||
    die "artifact SHA mismatch expected=$expected_artifact_sha actual=$artifact_sha"
echo "round5 epoll build: PASS source_sha=$expected_source_sha patch_sha=$expected_patch_sha adapted_sha=$expected_adapted_sha artifact_sha=$artifact_sha regular_file_epoll=EPERM host_full_run=false qemu_required=true"

#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=65ba020b526fe1cbf05feef0739791a3ae6274b2ffa2b39d385ce88e1a086ecf

die() {
    echo "runtime net build: FAIL: $*" >&2
    exit 1
}

sha_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

if (( $# < 1 || $# > 2 )); then
    die "usage: $0 OUTPUT_ELF [EXPECTED_ARTIFACT_SHA]"
fi

output=$1
expected_artifact_sha=${2-}
source_file=${NEXUS_RUNTIME_NET_SOURCE:-/repo/tests/guest/linux/sources/linux-runtime-net-smoke/runtime_net_smoke.S}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
oracle=${NEXUS_RUNTIME_NET_ARTIFACT_ORACLE:-$script_dir/assert-runtime-net-artifacts.sh}
publish_tmp=

for command_name in bash chmod clang cmp cp cut dirname mkdir mktemp mv rm sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done
[[ -f "$source_file" && ! -L "$source_file" ]] ||
    die "missing retained regular source: $source_file"
[[ -f "$oracle" && ! -L "$oracle" ]] || die "missing artifact oracle: $oracle"

assert_artifact() {
    local artifact=$1

    if (( $# == 2 )); then
        bash "$oracle" "$source_file" "$artifact" "$2"
    elif (( $# == 1 )); then
        bash "$oracle" "$source_file" "$artifact"
    else
        die 'internal artifact assertion argument mismatch'
    fi
}

actual_source_sha=$(sha_file "$source_file")
[[ "$actual_source_sha" == "$expected_source_sha" ]] ||
    die "retained source SHA mismatch expected=$expected_source_sha actual=$actual_source_sha file=$source_file"

tmp=$(mktemp -d)
cleanup() {
    rm -rf "$tmp"
    if [[ -n $publish_tmp ]]; then
        rm -f -- "$publish_tmp"
    fi
}
trap cleanup EXIT
fixed_source="$tmp/linux-runtime-net-smoke.S"
elf="$tmp/linux-runtime-net-smoke.elf"

# A fixed basename prevents STT_FILE metadata from depending on whether the
# immutable input arrived through /repo or a Docker COPY location.
cp "$source_file" "$fixed_source"
cmp -s "$source_file" "$fixed_source" || die 'fixed-name source copy differs from retained input'
[[ $(sha_file "$fixed_source") == "$expected_source_sha" ]] ||
    die 'fixed-name source copy failed its immutable digest gate'

(
    cd "$tmp"
    clang \
        --target=x86_64-unknown-linux-gnu \
        -c \
        -fno-pie \
        linux-runtime-net-smoke.S \
        -o linux-runtime-net-smoke.o
    clang \
        --target=x86_64-unknown-linux-gnu \
        -nostdlib \
        -static \
        -fno-pie \
        -Wl,-no-pie \
        -Wl,--entry=_start \
        -Wl,--build-id=none \
        -Wl,-z,noexecstack \
        -Wl,-z,max-page-size=4096 \
        linux-runtime-net-smoke.o \
        -o linux-runtime-net-smoke.elf
)

# Omitting the expected digest uses the oracle's checked-in pin. Passing an
# explicitly empty digest deliberately fails after printing the reproducible
# candidate. No output path is touched until the independent oracle accepts.
if (( $# == 2 )); then
    assert_artifact "$elf" "$expected_artifact_sha"
else
    assert_artifact "$elf"
fi

output_parent=$(dirname -- "$output")
mkdir -p "$output_parent"
if [[ -e $output || -L $output ]]; then
    [[ -f $output && ! -L $output ]] ||
        die "refusing to replace non-regular output: $output"
fi

# Validate a same-directory temporary first, then atomically rename it into
# place. Digest or structural failure therefore preserves any prior artifact.
publish_tmp=$(mktemp "$output_parent/.linux-runtime-net.XXXXXX")
cp "$elf" "$publish_tmp"
chmod 0755 "$publish_tmp"
if (( $# == 2 )); then
    assert_artifact "$publish_tmp" "$expected_artifact_sha" >/dev/null
else
    assert_artifact "$publish_tmp" >/dev/null
fi
mv -f -- "$publish_tmp" "$output"
publish_tmp=

if (( $# == 2 )); then
    assert_artifact "$output" "$expected_artifact_sha" >/dev/null
else
    assert_artifact "$output" >/dev/null
fi

artifact_sha=$(sha_file "$output")
echo "runtime net build: PASS source_sha=$expected_source_sha artifact_sha=$artifact_sha fixed_source=linux-runtime-net-smoke.S artifact=static-et-exec oracle=structural+digest publish=atomic-rename output=$output"

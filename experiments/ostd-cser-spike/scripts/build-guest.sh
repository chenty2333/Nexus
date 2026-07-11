#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

raw_guests=(
    probe
    pager-client
    pager-v1
    pager-v2
    linux-code-pager-v1
    linux-code-pager-v2
    linux-scheduler-policy
    linux-futex-shared
    linux-futex-personality-v1
    linux-futex-personality-v2
)

for guest in "${raw_guests[@]}"; do
    cc -c "guest/$guest.S" -o "$tmp/$guest.o"
    objcopy -O binary -j .text "$tmp/$guest.o" "guest/$guest.bin"
done

assert_symbol_offset() {
    local object=$1
    local symbol=$2
    local expected=$3
    local actual

    actual=$(nm --defined-only -P "$object" | awk -v symbol="$symbol" '$1 == symbol { print $3 }')
    if [[ -z "$actual" ]] || (( 16#$actual != expected )); then
        echo "unexpected $symbol offset in $object: got ${actual:-missing}, expected $expected" >&2
        exit 1
    fi
}

assert_raw_binary() {
    local object=$1
    local binary=$2
    local max_bytes=$3
    local size

    if ! readelf -rW "$object" | grep -Fq 'There are no relocations in this file.'; then
        echo "raw guest contains unresolved relocations: $object" >&2
        exit 1
    fi
    size=$(wc -c <"$binary")
    if (( size > max_bytes )); then
        echo "raw guest exceeds its mapping: $binary is $size bytes, limit $max_bytes" >&2
        exit 1
    fi
}

assert_symbol_offset "$tmp/linux-futex-shared.o" _start 0
assert_symbol_offset "$tmp/linux-futex-shared.o" _waker_start 0x200
assert_symbol_offset "$tmp/linux-futex-personality-v1.o" _start 0
assert_symbol_offset "$tmp/linux-futex-personality-v1.o" _expire_start 0x200
assert_raw_binary \
    "$tmp/linux-futex-shared.o" guest/linux-futex-shared.bin 4096
assert_raw_binary \
    "$tmp/linux-futex-personality-v1.o" guest/linux-futex-personality-v1.bin 4096
assert_raw_binary \
    "$tmp/linux-futex-personality-v2.o" guest/linux-futex-personality-v2.bin 4096

personality_manifest=userspace/personality/Cargo.toml
cargo build \
    --manifest-path "$personality_manifest" \
    --target x86_64-unknown-none \
    --release \
    --locked \
    --offline
for personality in linuxd-v1 linuxd-v2; do
    objcopy \
        -O binary \
        -j .text \
        "userspace/personality/target/x86_64-unknown-none/release/$personality" \
        "guest/linux-personality-${personality#linuxd-}.bin"
done

linux_hello_source=${NEXUS_LINUX_HELLO_SOURCE:-/repo/tests/guest/linux/sources/linux-hello/hello.S}
if [[ ! -f "$linux_hello_source" ]]; then
    echo "missing retained linux-hello source: $linux_hello_source" >&2
    exit 1
fi

cp "$linux_hello_source" "$tmp/linux-hello.S"
(
    cd "$tmp"
    clang \
        --target=x86_64-unknown-linux-gnu \
        -c \
        linux-hello.S \
        -o linux-hello.o
    clang \
        --target=x86_64-unknown-linux-gnu \
        -nostdlib \
        -static \
        -Wl,--build-id=none \
        -Wl,-z,max-page-size=4096 \
        linux-hello.o \
        -o linux-hello.elf
)
cp "$tmp/linux-hello.elf" guest/linux-hello.elf

bash scripts/assert-linux-elf.sh "$linux_hello_source" guest/linux-hello.elf

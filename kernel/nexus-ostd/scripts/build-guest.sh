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
    linux-futex-core-personality-v1
    linux-futex-core-personality-v2
    linux-dynamic-personality-v1
    linux-dynamic-personality-v2
    linux-netd-v1
    linux-netd-v2
    linux-fsd-v1
    linux-fsd-v2
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
assert_symbol_offset "$tmp/linux-fsd-v1.o" _start 0
assert_symbol_offset "$tmp/linux-fsd-v2.o" _start 0
assert_raw_binary \
    "$tmp/linux-futex-shared.o" guest/linux-futex-shared.bin 4096
assert_raw_binary \
    "$tmp/linux-futex-personality-v1.o" guest/linux-futex-personality-v1.bin 4096
assert_raw_binary \
    "$tmp/linux-futex-personality-v2.o" guest/linux-futex-personality-v2.bin 4096
assert_raw_binary \
    "$tmp/linux-futex-core-personality-v1.o" guest/linux-futex-core-personality-v1.bin 4096
assert_raw_binary \
    "$tmp/linux-futex-core-personality-v2.o" guest/linux-futex-core-personality-v2.bin 4096
assert_raw_binary \
    "$tmp/linux-dynamic-personality-v1.o" guest/linux-dynamic-personality-v1.bin 4096
assert_raw_binary \
    "$tmp/linux-dynamic-personality-v2.o" guest/linux-dynamic-personality-v2.bin 4096
assert_raw_binary \
    "$tmp/linux-netd-v1.o" guest/linux-netd-v1.bin 4096
assert_raw_binary \
    "$tmp/linux-netd-v2.o" guest/linux-netd-v2.bin 4096
assert_raw_binary \
    "$tmp/linux-fsd-v1.o" guest/linux-fsd-v1.bin 4096
assert_raw_binary \
    "$tmp/linux-fsd-v2.o" guest/linux-fsd-v2.bin 4096

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

bash scripts/build-round4.sh guest/linux-round4-futex.elf

dynamic_pie_launcher_source=${NEXUS_DYNAMIC_PIE_LAUNCHER_SOURCE:-/repo/tests/guest/linux/sources/linux-dynamic-pie-smoke/dynamic_pie_smoke.S}
dynamic_pie_main_source=${NEXUS_DYNAMIC_PIE_MAIN_SOURCE:-/repo/tests/guest/linux/sources/linux-dynamic-pie-main/dynamic_pie_main.c}
dynamic_pie_interp_source=${NEXUS_DYNAMIC_PIE_INTERP_SOURCE:-/repo/tests/guest/linux/sources/linux-dynamic-runtime-interp/dynamic_runtime_interp.c}

for source in \
    "$dynamic_pie_launcher_source" \
    "$dynamic_pie_main_source" \
    "$dynamic_pie_interp_source"; do
    if [[ ! -f "$source" ]]; then
        echo "missing retained dynamic PIE source: $source" >&2
        exit 1
    fi
done

# Compile from fixed temporary filenames so STT_FILE metadata is independent
# of whether the read-only source arrived through /repo or Docker COPY.
cp "$dynamic_pie_launcher_source" "$tmp/linux-dynamic-pie-smoke.S"
cp "$dynamic_pie_main_source" "$tmp/linux-dynamic-pie-main.c"
cp "$dynamic_pie_interp_source" "$tmp/linux-dynamic-runtime-interp.c"
(
    cd "$tmp"
    clang \
        --target=x86_64-unknown-linux-gnu \
        -c \
        -fno-pie \
        -o linux-dynamic-pie-smoke.o \
        linux-dynamic-pie-smoke.S
    clang \
        --target=x86_64-unknown-linux-gnu \
        -nostdlib \
        -static \
        -fno-pie \
        -Wl,-no-pie \
        -Wl,--entry=_start \
        -Wl,-z,noexecstack \
        -Wl,-z,max-page-size=4096 \
        -Wl,--build-id=none \
        -Wl,-Ttext-segment=0x100000000 \
        -o linux-dynamic-pie-smoke.elf \
        linux-dynamic-pie-smoke.o
    clang \
        --target=x86_64-unknown-linux-gnu \
        -c \
        -nostdlib \
        -fPIE \
        -o linux-dynamic-pie-main.o \
        linux-dynamic-pie-main.c
    clang \
        --target=x86_64-unknown-linux-gnu \
        -nostdlib \
        -fPIE \
        -pie \
        -Wl,--entry=_start \
        -Wl,-z,noexecstack \
        -Wl,-z,max-page-size=4096 \
        -Wl,--build-id=none \
        -Wl,--dynamic-linker=/lib/ld-nexus-dynamic-runtime.so \
        -o linux-dynamic-pie-main.elf \
        linux-dynamic-pie-main.o
    clang \
        --target=x86_64-unknown-linux-gnu \
        -c \
        -nostdlib \
        -fPIC \
        -o linux-dynamic-runtime-interp.o \
        linux-dynamic-runtime-interp.c
    clang \
        --target=x86_64-unknown-linux-gnu \
        -nostdlib \
        -shared \
        -fPIC \
        -Wl,--entry=_start \
        -Wl,-z,noexecstack \
        -Wl,-z,max-page-size=4096 \
        -Wl,--build-id=none \
        -Wl,-soname,ld-nexus-dynamic-runtime.so \
        -o linux-dynamic-runtime-interp.elf \
        linux-dynamic-runtime-interp.o
)

cp "$tmp/linux-dynamic-pie-smoke.elf" guest/linux-dynamic-pie-smoke.elf
cp "$tmp/linux-dynamic-pie-main.elf" guest/linux-dynamic-pie-main.elf
cp "$tmp/linux-dynamic-runtime-interp.elf" guest/linux-dynamic-runtime-interp.elf

bash scripts/assert-dynamic-pie-artifacts.sh \
    "$dynamic_pie_launcher_source" \
    "$dynamic_pie_main_source" \
    "$dynamic_pie_interp_source" \
    guest/linux-dynamic-pie-smoke.elf \
    guest/linux-dynamic-pie-main.elf \
    guest/linux-dynamic-runtime-interp.elf

bash scripts/build-round5.sh guest/linux-round5-epoll.elf

bash scripts/build-runtime-fs.sh guest/linux-runtime-fs.elf

bash scripts/build-runtime-net.sh guest/linux-runtime-net.elf

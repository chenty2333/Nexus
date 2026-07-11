#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for guest in probe pager-client pager-v1 pager-v2 linux-code-pager-v1 linux-code-pager-v2 linux-scheduler-policy; do
    cc -c "guest/$guest.S" -o "$tmp/$guest.o"
    objcopy -O binary -j .text "$tmp/$guest.o" "guest/$guest.bin"
done

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

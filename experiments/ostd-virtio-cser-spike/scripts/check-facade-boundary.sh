#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
experiment_root=$(cd "$script_dir/.." && pwd)
repo_root=$(cd "$experiment_root/../.." && pwd)
facade_root=${NEXUS_OSTD_VIRTIO_FACADE_ROOT:-$repo_root/crates/nexus-ostd-virtio}
kernel_manifest=${NEXUS_KERNEL_MANIFEST:-$repo_root/kernel/nexus-ostd/Cargo.toml}

fail() {
    echo "VirtIO facade boundary check failed: $*" >&2
    exit 1
}

for source in pci dma portal; do
    [[ ! -e $experiment_root/src/$source.rs ]] \
        || fail "experiment still owns src/$source.rs"
    [[ -f $facade_root/src/$source.rs ]] \
        || fail "facade lacks private src/$source.rs"
done

grep -Fqx '#![deny(unsafe_code)]' "$experiment_root/src/lib.rs" \
    || fail 'experiment client does not deny unsafe code'
grep -Fq 'use nexus_ostd_virtio::{' "$experiment_root/src/lib.rs" \
    || fail 'experiment is not a facade client'
if grep -Eq '^[[:space:]]*(mod (pci|dma|portal)|unsafe[[:space:]])' \
    "$experiment_root/src/lib.rs"; then
    fail 'experiment client regained a local substrate or unsafe block'
fi

grep -Fqx '#![deny(unsafe_code)]' "$facade_root/src/lib.rs" \
    || fail 'facade crate root does not deny unsafe code'
[[ $(grep -Fc '#[allow(unsafe_code)]' "$facade_root/src/lib.rs") -eq 3 ]] \
    || fail 'unsafe allowance is not confined to exactly three private modules'
for module in dma pci portal; do
    grep -Fqx "mod $module;" "$facade_root/src/lib.rs" \
        || fail "$module substrate is not private"
    if grep -Fqx "pub mod $module;" "$facade_root/src/lib.rs"; then
        fail "$module substrate became public"
    fi
done
if grep -REn '^[[:space:]]*pub[[:space:]]+unsafe[[:space:]]+fn|^[[:space:]]*pub[[:space:]]+mod[[:space:]]+(pci|dma|portal)' \
    "$facade_root/src" >/dev/null; then
    fail 'public API exposes unsafe operations or raw substrate modules'
fi
grep -Fq 'pub struct Root {' "$facade_root/src/pci.rs" \
    || fail 'opaque PCI root owner is missing'
grep -Fq 'type RawRoot = PciRoot<PioConfigurationAccess>;' "$facade_root/src/pci.rs" \
    || fail 'raw PCI root is no longer hidden behind the owner'
grep -Fq 'pub fn for_owned_device(root: &mut Root) -> Self {' "$facade_root/src/portal.rs" \
    || fail 'portal cannot be constructed from the opaque owner'
grep -Fq 'assert!(!self.portal_claimed, "PCI device portal claimed twice");' \
    "$facade_root/src/pci.rs" \
    || fail 'opaque PCI owner does not enforce one portal claim'
grep -Fq 'if root.device_function() != self.device_function {' "$facade_root/src/portal.rs" \
    || fail 'session open no longer checks the exact PCI owner'

for pin in \
    'ostd = { version = "=0.18.0" }' \
    'virtio-drivers = { version = "=0.13.0", default-features = false }'; do
    grep -Fq "$pin" "$facade_root/Cargo.toml" \
        || fail "facade dependency pin drifted: $pin"
done
for lock in \
    "$facade_root/Cargo.lock" \
    "$experiment_root/Cargo.lock" \
    "$experiment_root/osdk-runner-base/Cargo.lock" \
    "$repo_root/kernel/nexus-ostd/Cargo.lock"; do
    [[ -f $lock ]] || fail "missing lockfile: $lock"
done
grep -Fq 'name = "nexus-ostd-virtio"' "$facade_root/Cargo.lock" \
    || fail 'standalone facade lock lacks the facade package'
for lock in \
    "$experiment_root/Cargo.lock" \
    "$experiment_root/osdk-runner-base/Cargo.lock" \
    "$repo_root/kernel/nexus-ostd/Cargo.lock"; do
    grep -Fq 'name = "nexus-ostd-virtio"' "$lock" \
        || fail "consumer lock lacks the facade package: $lock"
done
grep -Fq 'nexus-ostd-virtio = { path = "../../crates/nexus-ostd-virtio" }' \
    "$experiment_root/Cargo.toml" \
    || fail 'experiment dependency is not the shared facade'
grep -Fq 'virtio-cser-facade = ["dep:nexus-ostd-virtio"]' "$kernel_manifest" \
    || fail 'kernel lacks an explicit opt-in facade feature'
grep -Fq 'nexus-ostd-virtio = { path = "../../crates/nexus-ostd-virtio", optional = true }' \
    "$kernel_manifest" \
    || fail 'kernel facade dependency is not optional'

echo 'OSTD VirtIO facade boundary: PASS client_unsafe=false raw_api=false opaque_root=true substrate_modules=3 experiment_equivalence=runtime_oracle kernel_default=disabled'

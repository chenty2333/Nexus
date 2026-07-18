// SPDX-License-Identifier: MPL-2.0

extern crate alloc;

#[path = "../../../kernel/nexus-ostd/src/cser/effect_registry.rs"]
mod effect_registry;

#[allow(dead_code)]
#[path = "../../../kernel/nexus-ostd/src/cser/portal_v2.rs"]
mod portal_v2;

#[allow(dead_code)]
#[path = "../../../kernel/nexus-ostd/src/cser/device_flight.rs"]
mod device_flight;

/// Host-side implementation gate for the registry-native successor.  The
/// independent semantic oracle lives in `cser-model`; this test exercises the
/// exact OSTD production source that will later be wired into the real
/// filesystem and device workload.
#[test]
fn production_identity_chain_uses_one_registry_and_shared_ledger() {
    effect_registry::production_identity_registry_self_test();
    device_flight::retained_semantic_self_test();
    portal_v2::production_portal_v2_self_test();
}

// SPDX-License-Identifier: MPL-2.0

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE,
    CSER_CORE_API_PROFILE_VERSION, DEVICE_CLAIM_PINNED_PAGE, DEVICE_DOMAIN,
    DMA_ARENA_REUSE_COMPOSITE, EvidenceCapability, EvidenceRecovery, JOURNAL_CORE_API_PROFILE,
    JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION, NORMALIZED_TRACE_VERSION, PROJECTION_VERSION,
    RECOVERY_SNAPSHOT_VERSION, REPLY_CLAIM_PUBLICATION_SLOT, REPLY_DOMAIN,
    STANDARD_CATALOG_VERSION, standard_catalog,
};

#[test]
fn semantic_api_profile_two_freezes_journal_and_domain_catalog() {
    assert_eq!(CSER_CORE_API_PROFILE_VERSION, 2);
    assert_eq!(JOURNAL_MAGIC, *b"CSERJR6\0");
    assert_eq!(JOURNAL_SCHEMA_VERSION, 6);
    assert_eq!(JOURNAL_CORE_API_PROFILE, 2);
    assert_eq!(STANDARD_CATALOG_VERSION, 6);
    assert_eq!(PROJECTION_VERSION, 6);
    assert_eq!(RECOVERY_SNAPSHOT_VERSION, 2);
    assert_eq!(NORMALIZED_TRACE_VERSION, 2);
    let catalog = standard_catalog();
    let agent_operation = catalog
        .composite_rule(AGENT_OPERATION_COMPOSITE)
        .expect("the standard agent operation must remain catalog-bound");
    assert_eq!(agent_operation.components().len(), 2);
    assert_eq!(
        agent_operation.components()[0].component(),
        AGENT_COMPONENT_REPLY
    );
    assert_eq!(
        agent_operation.components()[1].component(),
        AGENT_COMPONENT_DMA
    );
    let arena_reuse = catalog
        .composite_rule(DMA_ARENA_REUSE_COMPOSITE)
        .expect("the DMA arena reuse operation must remain catalog-bound");
    assert_eq!(arena_reuse.components().len(), 1);
    assert_eq!(arena_reuse.components()[0].component(), AGENT_COMPONENT_DMA);
    assert_eq!(
        catalog.digest().bytes(),
        [
            0x5d, 0xb1, 0xd6, 0x89, 0x66, 0xf8, 0x22, 0x7e, 0x26, 0xaf, 0x6a, 0xbc, 0x06, 0x98,
            0x43, 0xfd, 0xe3, 0x58, 0x2b, 0x12, 0x9a, 0x0f, 0xec, 0x67, 0x22, 0x81, 0xf8, 0x8d,
            0x72, 0x8f, 0x53, 0xd8,
        ]
    );
}

/// The evidence capability classification is part of the frozen catalog contract,
/// not an internal detail. Profile 2 must keep exactly one outcome-bearing claim
/// class and one quiescence-bearing class, because the whole point of the
/// separation is that an escaped effect can reach physical quiescence while its
/// externally visible outcome is still unresolved.
#[test]
fn semantic_api_profile_two_freezes_evidence_capability_classification() {
    let catalog = standard_catalog();

    let reply = catalog
        .claim_rule(REPLY_DOMAIN, REPLY_CLAIM_PUBLICATION_SLOT)
        .expect("the reply publication slot must remain catalog-bound");
    for rule in reply.evidence() {
        assert_eq!(
            rule.capability(),
            EvidenceCapability::Outcome,
            "reply publication evidence resolves the visible outcome"
        );
        assert_eq!(
            rule.recovery(),
            EvidenceRecovery::Recoverable,
            "a publication acknowledgement is queryable by durable effect identity"
        );
    }

    let pinned = catalog
        .claim_rule(DEVICE_DOMAIN, DEVICE_CLAIM_PINNED_PAGE)
        .expect("the pinned page claim must remain catalog-bound");
    assert!(
        !pinned.evidence().is_empty(),
        "a physical claim must declare retirement evidence"
    );
    for rule in pinned.evidence() {
        assert_eq!(
            rule.capability(),
            EvidenceCapability::Quiescence,
            "device retirement evidence proves the device stopped touching the resource"
        );
        assert_eq!(
            rule.recovery(),
            EvidenceRecovery::Recoverable,
            "a successor incarnation must be able to re-observe device quiescence"
        );
    }
}

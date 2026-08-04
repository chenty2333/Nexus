// SPDX-License-Identifier: MPL-2.0

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE, ConflictMode,
    CSER_CORE_API_PROFILE_VERSION, DEVICE_CLAIM_IOVA, DEVICE_CLAIM_PINNED_PAGE,
    DEVICE_CLAIM_QUEUE_SLOT, DEVICE_DOMAIN, DMA_ARENA_REUSE_COMPOSITE, EvidenceCapability,
    EvidenceRecovery, JOURNAL_CORE_API_PROFILE, JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION,
    NORMALIZED_TRACE_VERSION, PROJECTION_VERSION, RECOVERY_SNAPSHOT_VERSION,
    REPLY_CLAIM_PUBLICATION_SLOT, REPLY_DOMAIN, STANDARD_CATALOG_VERSION, standard_catalog,
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
            0x20, 0x32, 0x90, 0xd2, 0x13, 0x54, 0xb4, 0x1c, 0x40, 0xe6, 0x78, 0x15, 0x9d, 0x97,
            0x7e, 0xe7, 0xbc, 0x81, 0x17, 0x5b, 0xd2, 0x72, 0x64, 0x85, 0x04, 0x92, 0x53, 0x8e,
            0xc9, 0xa9, 0x4b, 0x5c,
        ]
    );
}

/// Every standard claim class must declare exclusive conflict, because each one
/// names a coordinate a single custodian may hold: a reply publication slot, one
/// queue slot, one pinned page, one IOVA mapping. Shared custody exists in the
/// admission algebra for domains that need it, but silence in the standard
/// profile must continue to mean exclusion.
#[test]
fn semantic_api_profile_two_freezes_exclusive_conflict_for_every_standard_class() {
    let catalog = standard_catalog();
    for (domain, kind) in [
        (REPLY_DOMAIN, REPLY_CLAIM_PUBLICATION_SLOT),
        (DEVICE_DOMAIN, DEVICE_CLAIM_QUEUE_SLOT),
        (DEVICE_DOMAIN, DEVICE_CLAIM_PINNED_PAGE),
        (DEVICE_DOMAIN, DEVICE_CLAIM_IOVA),
    ] {
        assert_eq!(
            catalog
                .claim_rule(domain, kind)
                .expect("every standard claim class must remain catalog-bound")
                .conflict(),
            ConflictMode::Exclusive,
        );
    }
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

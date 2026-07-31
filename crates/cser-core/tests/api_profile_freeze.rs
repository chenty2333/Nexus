// SPDX-License-Identifier: MPL-2.0

use cser_core::{
    AGENT_COMPONENT_DMA, AGENT_COMPONENT_REPLY, AGENT_OPERATION_COMPOSITE,
    CSER_CORE_API_PROFILE_VERSION, DMA_ARENA_REUSE_COMPOSITE, JOURNAL_CORE_API_PROFILE,
    JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION, NORMALIZED_TRACE_VERSION, PROJECTION_VERSION,
    RECOVERY_SNAPSHOT_VERSION, STANDARD_CATALOG_VERSION, standard_catalog,
};

#[test]
fn semantic_api_profile_two_freezes_journal_and_domain_catalog() {
    assert_eq!(CSER_CORE_API_PROFILE_VERSION, 2);
    assert_eq!(JOURNAL_MAGIC, *b"CSERJR6\0");
    assert_eq!(JOURNAL_SCHEMA_VERSION, 6);
    assert_eq!(JOURNAL_CORE_API_PROFILE, 2);
    assert_eq!(STANDARD_CATALOG_VERSION, 5);
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
            0xf6, 0xa4, 0xb0, 0x7c, 0x1e, 0x17, 0x36, 0x1a, 0xa6, 0x2b, 0xbc, 0xa2, 0xc6, 0x57,
            0x9b, 0x38, 0x0f, 0xde, 0x43, 0xbe, 0x44, 0xf3, 0x88, 0x24, 0xa3, 0xdb, 0x42, 0xe8,
            0x28, 0x55, 0xc1, 0x73,
        ]
    );
}

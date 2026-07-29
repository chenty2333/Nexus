// SPDX-License-Identifier: MPL-2.0

use cser_core::{
    CSER_CORE_API_PROFILE_VERSION, JOURNAL_MAGIC, JOURNAL_SCHEMA_VERSION, standard_catalog,
};

#[test]
fn semantic_api_profile_one_freezes_journal_and_domain_catalog() {
    assert_eq!(CSER_CORE_API_PROFILE_VERSION, 1);
    assert_eq!(JOURNAL_MAGIC, *b"CSERJR5\0");
    assert_eq!(JOURNAL_SCHEMA_VERSION, 5);
    assert_eq!(
        standard_catalog().digest().bytes(),
        [
            0xf5, 0x8a, 0xd9, 0xf2, 0xc9, 0x73, 0xe6, 0x55, 0x32, 0xb1, 0x0d, 0x63, 0x92, 0xf0,
            0x52, 0x88, 0x38, 0xbf, 0x95, 0xc0, 0x96, 0x68, 0xf3, 0x03, 0x95, 0x74, 0x38, 0x16,
            0xa5, 0x8d, 0xdf, 0x25,
        ]
    );
}

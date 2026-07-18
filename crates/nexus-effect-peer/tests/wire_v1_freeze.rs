// SPDX-License-Identifier: MPL-2.0

//! Compatibility gate for the process crate's native-v1 re-export.
//!
//! The producer-owned corpus and exhaustive wire-shape tests live in
//! `nexus-effect-peer-wire`; this test prevents the process facade from
//! silently dropping or replacing that public contract.

use nexus_effect_peer::{
    PeerRequest, REQUEST_SCHEMA,
    frozen_v1::{
        CONTRACT_JSON, SNAPSHOT_SHA256, canonical_snapshot_sha256, request_corpus, response_corpus,
    },
};

const REPOSITORY_CONTRACT: &str = include_str!("../../../status/effect-peer-native-v1.json");

#[test]
fn process_crate_reexports_the_frozen_wire_contract() {
    assert_eq!(CONTRACT_JSON, REPOSITORY_CONTRACT);
    assert_eq!(canonical_snapshot_sha256().unwrap(), SNAPSHOT_SHA256);
    assert_eq!(request_corpus().len(), 14);
    assert_eq!(response_corpus().unwrap().len(), 14);

    let request: PeerRequest = request_corpus().remove(0);
    assert_eq!(request.schema, REQUEST_SCHEMA);
}

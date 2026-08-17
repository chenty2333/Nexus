use std::collections::BTreeSet;

use cser_core::{
    DEVICE_COMMIT_RECEIPT_SCHEMA, DEVICE_RECEIPT_SCHEMA, DEVICE_VERIFIER, Digest,
    HARNESS_APPLY_RECEIPT_SCHEMA, HARNESS_COMMIT_RECEIPT_SCHEMA, HARNESS_RECEIPT_SCHEMA,
    HARNESS_SETTLEMENT_RECEIPT_SCHEMA, HARNESS_VERIFIER, REPLY_APPLY_RECEIPT_SCHEMA,
    REPLY_COMMIT_RECEIPT_SCHEMA, REPLY_RECEIPT_SCHEMA, REPLY_SETTLEMENT_RECEIPT_SCHEMA,
    REPLY_VERIFIER, ReceiptSchemaId, VerifierBinding, VerifierClassBinding, VerifierGeneration,
    VerifierId, VerifierSetError, canonical_verifier_set_digest, harness_catalog, standard_catalog,
    validate_verifier_set,
};

fn binding(
    verifier: u32,
    generation: u64,
    receipt_schema: u32,
    implementation: u8,
) -> VerifierBinding {
    VerifierBinding::new(
        VerifierId::new(verifier).unwrap(),
        VerifierGeneration::new(generation).unwrap(),
        ReceiptSchemaId::new(receipt_schema).unwrap(),
        Digest::new([implementation; 32]),
    )
    .unwrap()
}

#[test]
fn verifier_set_digest_is_canonical_and_generation_bound() {
    let first = binding(7, 1, 11, 0x11);
    let second = binding(8, 3, 12, 0x22);
    let forward = canonical_verifier_set_digest(&[first, second]).unwrap();
    let reverse = canonical_verifier_set_digest(&[second, first]).unwrap();
    assert_eq!(forward, reverse);

    let next_generation = binding(7, 2, 11, 0x11);
    assert_ne!(
        forward,
        canonical_verifier_set_digest(&[next_generation, second]).unwrap()
    );

    let next_implementation = binding(7, 1, 11, 0x33);
    assert_ne!(
        forward,
        canonical_verifier_set_digest(&[next_implementation, second]).unwrap()
    );
}

#[test]
fn verifier_set_rejects_empty_and_duplicate_coordinates() {
    assert_eq!(
        canonical_verifier_set_digest(&[]),
        Err(VerifierSetError::Empty)
    );

    let original = binding(7, 1, 11, 0x11);
    assert_eq!(
        canonical_verifier_set_digest(&[original, original]),
        Err(VerifierSetError::DuplicateExactIdentity)
    );

    let conflict = binding(7, 2, 11, 0x22);
    assert_eq!(
        canonical_verifier_set_digest(&[original, conflict]),
        Err(VerifierSetError::DuplicateClassSchema)
    );

    // The intervening class proves validation keys duplicates by
    // class/schema, rather than relying on the full binding's field order.
    let class_a_old = binding(7, 1, 99, 0x11);
    let class_b = binding(7, 2, 1, 0x22);
    let class_a_new = binding(7, 3, 99, 0x33);
    assert_eq!(
        canonical_verifier_set_digest(&[class_a_old, class_b, class_a_new]),
        Err(VerifierSetError::DuplicateClassSchema)
    );

    assert_eq!(
        VerifierBinding::new(
            VerifierId::new(7).unwrap(),
            VerifierGeneration::new(1).unwrap(),
            ReceiptSchemaId::new(11).unwrap(),
            Digest::ZERO,
        ),
        Err(VerifierSetError::ZeroImplementationDigest)
    );
}

#[test]
fn verifier_set_matches_catalog_class_schema_requirements() {
    let first = binding(7, 1, 11, 0x11);
    let second = binding(8, 3, 12, 0x22);
    let required = [
        VerifierClassBinding::new(
            VerifierId::new(8).unwrap(),
            ReceiptSchemaId::new(12).unwrap(),
        ),
        VerifierClassBinding::new(
            VerifierId::new(7).unwrap(),
            ReceiptSchemaId::new(11).unwrap(),
        ),
    ];
    let expected = canonical_verifier_set_digest(&[first, second]).unwrap();
    assert_eq!(
        validate_verifier_set(&[first, second], &required),
        Ok(expected)
    );

    let missing = [VerifierClassBinding::new(
        VerifierId::new(7).unwrap(),
        ReceiptSchemaId::new(11).unwrap(),
    )];
    assert_eq!(
        validate_verifier_set(&[first, second], &missing),
        Err(VerifierSetError::UnexpectedClass)
    );

    assert_eq!(
        validate_verifier_set(&[first, second], &[required[0], required[0], required[1],],),
        Err(VerifierSetError::DuplicateRequiredClass)
    );
}

#[test]
fn catalog_verifier_classes_include_all_receipt_stages_and_evidence() {
    let standard: BTreeSet<_> = [
        VerifierClassBinding::new(REPLY_VERIFIER, REPLY_RECEIPT_SCHEMA),
        VerifierClassBinding::new(REPLY_VERIFIER, REPLY_COMMIT_RECEIPT_SCHEMA),
        VerifierClassBinding::new(REPLY_VERIFIER, REPLY_APPLY_RECEIPT_SCHEMA),
        VerifierClassBinding::new(REPLY_VERIFIER, REPLY_SETTLEMENT_RECEIPT_SCHEMA),
        VerifierClassBinding::new(DEVICE_VERIFIER, DEVICE_RECEIPT_SCHEMA),
        VerifierClassBinding::new(DEVICE_VERIFIER, DEVICE_COMMIT_RECEIPT_SCHEMA),
    ]
    .into_iter()
    .collect();
    assert_eq!(standard_catalog().verifier_class_bindings(), standard);

    let harness: BTreeSet<_> = [
        VerifierClassBinding::new(HARNESS_VERIFIER, HARNESS_RECEIPT_SCHEMA),
        VerifierClassBinding::new(HARNESS_VERIFIER, HARNESS_COMMIT_RECEIPT_SCHEMA),
        VerifierClassBinding::new(HARNESS_VERIFIER, HARNESS_APPLY_RECEIPT_SCHEMA),
        VerifierClassBinding::new(HARNESS_VERIFIER, HARNESS_SETTLEMENT_RECEIPT_SCHEMA),
    ]
    .into_iter()
    .collect();
    assert_eq!(harness_catalog().verifier_class_bindings(), harness);
}

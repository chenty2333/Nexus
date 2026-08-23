//! Canonical SHA-256 checks for the host backend split.
//!
//! The same test is run for both host profiles:
//!
//! ```text
//! cargo test -p cser-core --no-default-features --features std \\
//!     --test hash_backend
//! cargo test -p cser-core --no-default-features \\
//!     --features std,sha2-software-baseline --test hash_backend
//! ```
//!
//! The first command leaves RustCrypto's x86/x86_64 runtime dispatch enabled;
//! the second enables its explicitly software-only compressor. The expected
//! digest bytes are the authority. CPU feature observations below are only
//! diagnostic output and never select or authorize a CSER transition.

#![cfg(feature = "std")]

use sha2::{Digest as _, Sha256};

fn digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

fn digest_chunked(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

fn hex_bytes(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "SHA-256 test vector must contain 32 bytes");
    let mut result = [0u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0]);
        let low = hex_nibble(pair[1]);
        result[index] = (high << 4) | low;
    }
    result
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal test-vector byte: {value}"),
    }
}

#[test]
fn canonical_digest_bytes_match_standard_vectors() {
    let vectors = [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"The quick brown fox jumps over the lazy dog".as_slice(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
        (
            b"The quick brown fox jumps over the lazy dog.".as_slice(),
            "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        ),
    ];

    for (input, expected) in vectors {
        assert_eq!(digest(input), hex_bytes(expected), "input={input:?}");
    }

    let million_a = [b'a'; 1_000_000];
    assert_eq!(
        digest(&million_a),
        hex_bytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    );
}

#[test]
fn canonical_digest_is_independent_of_update_boundaries() {
    let prefix = b"The quick ";
    let middle = b"brown fox jumps over ";
    let suffix = b"the lazy dog";
    assert_eq!(
        digest_chunked(&[prefix, middle, suffix]),
        digest(b"The quick brown fox jumps over the lazy dog")
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_feature_observation() -> String {
    format!(
        "sha_ni={},sse2={},ssse3={},sse4.1={}",
        std::arch::is_x86_feature_detected!("sha"),
        std::arch::is_x86_feature_detected!("sse2"),
        std::arch::is_x86_feature_detected!("ssse3"),
        std::arch::is_x86_feature_detected!("sse4.1"),
    )
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_feature_observation() -> &'static str {
    "non-x86-target"
}

#[test]
fn backend_observation_is_diagnostic_only() {
    let selected_build = if cfg!(feature = "sha2-software-baseline") {
        "software-baseline"
    } else {
        "runtime-dispatch"
    };
    eprintln!(
        "sha256_backend_observation,build={selected_build},cpu={}",
        cpu_feature_observation()
    );

    // Keep the digest assertion independent from CPUID. A host can lack
    // SHA-NI, and a future backend may use a different observation mechanism;
    // neither case changes canonical bytes or CSER authority.
    assert_eq!(
        digest(b"cser-core canonical backend observation"),
        hex_bytes("d13032b3619d22b8742897910329ac8f9d6046061057f52113170fd6a48d0a45")
    );
}

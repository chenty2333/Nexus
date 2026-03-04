use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generate a short 8-hex test id.
pub fn new_test_id() -> String {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let seq = RUN_SEQ.fetch_add(1, Ordering::Relaxed);

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    now_nanos.hash(&mut hasher);
    pid.hash(&mut hasher);
    seq.hash(&mut hasher);
    let digest = hasher.finish();

    format!("{:08x}", (digest & 0xffff_ffff) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_is_8_hex() {
        let id = new_test_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

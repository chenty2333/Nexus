//! A canonical, path-copying sparse Merkle map.
//!
//! The map uses the 256 bits of a fixed-size key as the path through a binary
//! tree. Occupied paths are stored in a compressed Patricia shape: unary runs
//! of the conceptual tree are not allocated. A branch commits directly to its
//! canonical depth, representative key, and child digests, so hashing a
//! compressed edge does not replay the omitted unary path.

extern crate alloc;

use alloc::sync::Arc;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::Digest;

/// Number of bits in an authenticated-map key.
pub const TREE_DEPTH: u16 = 256;

const EMPTY_TAG: &[u8] = b"CSER/AuthenticatedMap/Empty/v2";
const LEAF_TAG: &[u8] = b"CSER/AuthenticatedMap/Leaf/v2";
const BRANCH_TAG: &[u8] = b"CSER/AuthenticatedMap/Branch/v2";

/// A compressed occupied subtree.
///
/// `depth` is the depth of the node in the conceptual tree. Leaves always
/// occur at depth 256. A branch is present only where both paths are needed;
/// the skipped unary path is represented by its [`Node::key`]. The key on a
/// branch is the lexicographically least key in its subtree (the left child's
/// key), making both shape and branch metadata insertion-order independent.
#[derive(Clone, Debug)]
enum Node {
    Leaf {
        key: [u8; 32],
        value: Digest,
        hash: Digest,
    },
    Branch {
        depth: u16,
        key: [u8; 32],
        left: Arc<Node>,
        right: Arc<Node>,
        hash: Digest,
    },
}

impl Node {
    fn key(&self) -> &[u8; 32] {
        match self {
            Self::Leaf { key, .. } | Self::Branch { key, .. } => key,
        }
    }

    fn hash(&self) -> Digest {
        match self {
            Self::Leaf { hash, .. } | Self::Branch { hash, .. } => *hash,
        }
    }
}

/// A canonical compressed Patricia map over `[u8; 32]` keys and [`Digest`]
/// values.
///
/// Cloning the map is `O(1)`.  Updates use path-copying over the compressed
/// occupied tree, allocating at most one branch for each occupied divergence
/// on the changed path. Hashing visits only resident nodes on that path.
/// Node presence is represented structurally, so every 256-bit digest,
/// including [`Digest::ZERO`], is a valid leaf value.
#[derive(Clone, Debug)]
pub struct AuthenticatedMap {
    root: Option<Arc<Node>>,
    len: usize,
    root_digest: Digest,
    empty_digest: Digest,
}

impl PartialEq for AuthenticatedMap {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.root_digest == other.root_digest
    }
}

impl Eq for AuthenticatedMap {}

impl Default for AuthenticatedMap {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticatedMap {
    /// Creates an empty map with its canonical empty-subtree digest.
    #[must_use]
    pub fn new() -> Self {
        let empty_digest = hash_empty();
        Self {
            root: None,
            root_digest: empty_digest,
            empty_digest,
            len: 0,
        }
    }

    /// Returns the number of occupied leaves.
    #[cfg(test)]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether this map has no occupied leaves.
    #[cfg(test)]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the value bound to `key`, if one exists.
    #[cfg(test)]
    #[must_use]
    pub fn get(&self, key: &[u8; 32]) -> Option<Digest> {
        self.root.as_deref().and_then(|node| get_node(node, 0, key))
    }

    /// Returns the cached canonical root digest.
    #[must_use]
    pub const fn root_digest(&self) -> Digest {
        self.root_digest
    }

    /// Inserts `value` for `key`, returning the new map and a replaced value.
    ///
    /// The original map is unchanged.
    #[must_use]
    pub fn insert(&self, key: [u8; 32], value: Digest) -> (Self, Option<Digest>) {
        let (root, previous) = insert_node(self.root.as_ref(), 0, key, value);
        let next_len = if previous.is_some() {
            self.len
        } else {
            self.len + 1
        };
        let root_digest = root.hash();
        (
            Self {
                root: Some(root),
                len: next_len,
                root_digest,
                empty_digest: self.empty_digest,
            },
            previous,
        )
    }

    /// Inserts `value` for `key` in place, returning a replaced value.
    pub fn insert_mut(&mut self, key: [u8; 32], value: Digest) -> Option<Digest> {
        let (next, previous) = self.insert(key, value);
        *self = next;
        previous
    }

    /// Removes `key`, returning the new map and the removed value.
    ///
    /// Removing an absent key returns an unchanged `O(1)` clone.
    #[must_use]
    pub fn remove(&self, key: &[u8; 32]) -> (Self, Option<Digest>) {
        let (root, removed) = remove_node(self.root.as_ref(), 0, key);
        let Some(removed) = removed else {
            return (self.clone(), None);
        };
        let root_digest = root.as_ref().map_or(self.empty_digest, |root| root.hash());
        (
            Self {
                root,
                len: self.len - 1,
                root_digest,
                empty_digest: self.empty_digest,
            },
            Some(removed),
        )
    }

    /// Removes `key` in place, returning the removed value.
    pub fn remove_mut(&mut self, key: &[u8; 32]) -> Option<Digest> {
        let (next, removed) = self.remove(key);
        *self = next;
        removed
    }

    #[cfg(test)]
    fn node_count(&self) -> usize {
        self.root.as_deref().map_or(0, count_nodes)
    }
}

fn hash_empty() -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_TAG);
    hasher.update(TREE_DEPTH.to_be_bytes());
    digest_from_hash(hasher.finalize())
}

fn hash_leaf(key: &[u8; 32], value: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_TAG);
    hasher.update(key);
    hasher.update(value.bytes());
    digest_from_hash(hasher.finalize())
}

fn hash_branch(depth: u16, key: &[u8; 32], left: Digest, right: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(BRANCH_TAG);
    hasher.update(depth.to_be_bytes());
    hasher.update(key);
    hasher.update(left.bytes());
    hasher.update(right.bytes());
    digest_from_hash(hasher.finalize())
}

fn digest_from_hash(hash: sha2::digest::Output<Sha256>) -> Digest {
    Digest::new(hash.into())
}

fn key_bit(key: &[u8; 32], depth: u16) -> bool {
    let byte = key[(depth / 8) as usize];
    byte & (0x80 >> (depth % 8)) != 0
}

fn make_leaf(key: [u8; 32], value: Digest) -> Arc<Node> {
    Arc::new(Node::Leaf {
        key,
        value,
        hash: hash_leaf(&key, value),
    })
}

fn make_branch(depth: u16, left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
    debug_assert!(depth < TREE_DEPTH);
    debug_assert!(key_bit(left.key(), depth) != key_bit(right.key(), depth));
    debug_assert!(left.key() < right.key());
    let key = *left.key();
    let hash = hash_branch(depth, &key, left.hash(), right.hash());
    Arc::new(Node::Branch {
        depth,
        key,
        left,
        right,
        hash,
    })
}

fn first_difference(left: &[u8; 32], right: &[u8; 32], start: u16) -> u16 {
    let mut depth = start;
    while depth < TREE_DEPTH {
        if key_bit(left, depth) != key_bit(right, depth) {
            return depth;
        }
        depth += 1;
    }
    unreachable!("different authenticated-map keys must diverge")
}

#[cfg(test)]
fn get_node(node: &Node, expected_depth: u16, key: &[u8; 32]) -> Option<Digest> {
    match node {
        Node::Leaf {
            key: stored_key,
            value,
            ..
        } => (stored_key == key).then_some(*value),
        Node::Branch {
            depth,
            key: representative,
            left,
            right,
            ..
        } => {
            if *depth < expected_depth
                || (*depth > expected_depth
                    && (expected_depth..*depth)
                        .any(|bit| key_bit(representative, bit) != key_bit(key, bit)))
            {
                return None;
            }
            if key_bit(key, *depth) {
                get_node(right, *depth + 1, key)
            } else {
                get_node(left, *depth + 1, key)
            }
        }
    }
}

fn insert_node(
    node: Option<&Arc<Node>>,
    expected_depth: u16,
    key: [u8; 32],
    value: Digest,
) -> (Arc<Node>, Option<Digest>) {
    let Some(node) = node else {
        return (make_leaf(key, value), None);
    };

    match node.as_ref() {
        Node::Leaf {
            key: stored_key,
            value: stored_value,
            ..
        } => {
            if stored_key == &key {
                if *stored_value == value {
                    (node.clone(), Some(*stored_value))
                } else {
                    (make_leaf(key, value), Some(*stored_value))
                }
            } else {
                let depth = first_difference(stored_key, &key, expected_depth);
                let new_leaf = make_leaf(key, value);
                if key_bit(&key, depth) {
                    (make_branch(depth, node.clone(), new_leaf), None)
                } else {
                    (make_branch(depth, new_leaf, node.clone()), None)
                }
            }
        }
        Node::Branch {
            depth,
            key: representative,
            left,
            right,
            ..
        } => {
            let divergence = (*depth).min(TREE_DEPTH);
            let prefix_diff = (expected_depth..divergence)
                .find(|bit| key_bit(representative, *bit) != key_bit(&key, *bit));
            if let Some(depth) = prefix_diff {
                let new_leaf = make_leaf(key, value);
                if key_bit(&key, depth) {
                    (make_branch(depth, node.clone(), new_leaf), None)
                } else {
                    (make_branch(depth, new_leaf, node.clone()), None)
                }
            } else if key_bit(&key, *depth) {
                let (next_right, previous) = insert_node(Some(right), *depth + 1, key, value);
                (make_branch(*depth, left.clone(), next_right), previous)
            } else {
                let (next_left, previous) = insert_node(Some(left), *depth + 1, key, value);
                (make_branch(*depth, next_left, right.clone()), previous)
            }
        }
    }
}

fn remove_node(
    node: Option<&Arc<Node>>,
    expected_depth: u16,
    key: &[u8; 32],
) -> (Option<Arc<Node>>, Option<Digest>) {
    let Some(node) = node else {
        return (None, None);
    };
    match node.as_ref() {
        Node::Leaf {
            key: stored_key,
            value,
            ..
        } => {
            if stored_key == key {
                (None, Some(*value))
            } else {
                (Some(node.clone()), None)
            }
        }
        Node::Branch {
            depth,
            key: representative,
            left,
            right,
            ..
        } => {
            if *depth < expected_depth
                || (*depth > expected_depth
                    && (expected_depth..*depth)
                        .any(|bit| key_bit(representative, bit) != key_bit(key, bit)))
            {
                return (Some(node.clone()), None);
            }
            if key_bit(key, *depth) {
                let (next_right, removed) = remove_node(Some(right), *depth + 1, key);
                let Some(removed) = removed else {
                    return (Some(node.clone()), None);
                };
                let next = match next_right {
                    Some(next_right) => make_branch(*depth, left.clone(), next_right),
                    None => left.clone(),
                };
                (Some(next), Some(removed))
            } else {
                let (next_left, removed) = remove_node(Some(left), *depth + 1, key);
                let Some(removed) = removed else {
                    return (Some(node.clone()), None);
                };
                let next = match next_left {
                    Some(next_left) => make_branch(*depth, next_left, right.clone()),
                    None => right.clone(),
                };
                (Some(next), Some(removed))
            }
        }
    }
}

#[cfg(test)]
fn count_nodes(node: &Node) -> usize {
    match node {
        Node::Leaf { .. } => 1,
        Node::Branch { left, right, .. } => 1 + count_nodes(left) + count_nodes(right),
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthenticatedMap, Node, TREE_DEPTH};
    use crate::Digest;
    use alloc::sync::Arc;
    use sha2::{Digest as Sha2Digest, Sha256};

    fn key(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn digest(value: u8) -> Digest {
        Digest::new([value; 32])
    }

    #[test]
    fn empty_root_is_deterministic_and_nonzero() {
        let first = AuthenticatedMap::new();
        let second = AuthenticatedMap::new();
        assert!(first.is_empty());
        assert_eq!(first.len(), 0);
        assert_eq!(first.root_digest(), second.root_digest());
        assert_ne!(first.root_digest(), Digest::ZERO);
        assert_eq!(TREE_DEPTH, 256);
        assert_eq!(first.node_count(), 0);
    }

    #[test]
    fn insertion_order_does_not_change_root() {
        let entries = [
            (key(0x00), digest(1)),
            (key(0x80), digest(2)),
            (key(7), digest(3)),
        ];
        let mut forward = AuthenticatedMap::new();
        for (key, value) in entries {
            let _ = forward.insert_mut(key, value);
        }
        let mut reverse = AuthenticatedMap::new();
        for (key, value) in entries.into_iter().rev() {
            let _ = reverse.insert_mut(key, value);
        }
        assert_eq!(forward.root_digest(), reverse.root_digest());
        assert_eq!(forward.len(), entries.len());
    }

    #[test]
    fn clone_isolated_and_update_remove_returns_to_original_root() {
        let mut original = AuthenticatedMap::new();
        let first_key = key(11);
        let second_key = key(12);
        let _ = original.insert_mut(first_key, digest(9));
        let original_root = original.root_digest();

        let mut clone = original.clone();
        let _ = clone.insert_mut(second_key, digest(10));
        assert_eq!(original.root_digest(), original_root);
        assert!(original.get(&second_key).is_none());

        clone.remove_mut(&second_key);
        assert_eq!(clone.root_digest(), original_root);
        assert_eq!(clone.get(&first_key), Some(digest(9)));
    }

    #[test]
    fn zero_leaf_is_a_distinct_present_value() {
        let mut map = AuthenticatedMap::new();
        let empty = map.root_digest();
        assert_eq!(map.insert_mut(key(1), Digest::ZERO), None);
        assert_eq!(map.get(&key(1)), Some(Digest::ZERO));
        assert_ne!(map.root_digest(), empty);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn key_value_and_shape_changes_have_distinct_commitments() {
        let mut baseline = AuthenticatedMap::new();
        let _ = baseline.insert_mut(key(0), digest(1));

        let mut changed_value = AuthenticatedMap::new();
        let _ = changed_value.insert_mut(key(0), digest(2));
        assert_ne!(baseline.root_digest(), changed_value.root_digest());

        let mut changed_key = AuthenticatedMap::new();
        let _ = changed_key.insert_mut(key(1), digest(1));
        assert_ne!(baseline.root_digest(), changed_key.root_digest());

        let mut shallow_shape = AuthenticatedMap::new();
        let _ = shallow_shape.insert_mut(key(0), digest(1));
        let _ = shallow_shape.insert_mut(key(1), digest(2));
        let mut deep_shape = AuthenticatedMap::new();
        let _ = deep_shape.insert_mut(key(0), digest(1));
        let _ = deep_shape.insert_mut(key(128), digest(2));
        assert_ne!(shallow_shape.root_digest(), deep_shape.root_digest());
    }

    #[test]
    fn absent_remove_is_unchanged() {
        let mut map = AuthenticatedMap::new();
        let _ = map.insert_mut(key(1), digest(1));
        let root = map.root_digest();
        assert_eq!(map.remove_mut(&key(2)), None);
        assert_eq!(map.root_digest(), root);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn compressed_nodes_scale_with_leaves() {
        let mut map = AuthenticatedMap::new();
        for (index, value) in [0_u8, 1, 7, 64, 128, 192, 255].into_iter().enumerate() {
            let _ = map.insert_mut(key(value), digest(index as u8));
        }
        assert_eq!(map.len(), 7);
        assert_eq!(map.node_count(), 13);
        assert!(map.node_count() < usize::from(TREE_DEPTH) * map.len());
    }

    #[test]
    fn update_path_copies_only_changed_resident_path() {
        let mut map = AuthenticatedMap::new();
        let _ = map.insert_mut(key(0), digest(1));
        let _ = map.insert_mut(key(128), digest(2));
        let original = map.clone();

        let _ = map.insert_mut(key(1), digest(3));
        let (Some(original_root), Some(updated_root)) = (original.root, map.root) else {
            panic!("two-leaf maps must have roots");
        };
        let Node::Branch {
            right: original_right,
            ..
        } = original_root.as_ref()
        else {
            panic!("two-leaf maps must have a branch root");
        };
        let Node::Branch {
            right: updated_right,
            ..
        } = updated_root.as_ref()
        else {
            panic!("three-leaf maps must have a branch root");
        };
        assert!(Arc::ptr_eq(original_right, updated_right));
    }

    fn oracle_hash_empty() -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"CSER/AuthenticatedMap/Empty/v2");
        hasher.update(TREE_DEPTH.to_be_bytes());
        Digest::new(hasher.finalize().into())
    }

    fn oracle_hash_leaf(key: &[u8; 32], value: Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"CSER/AuthenticatedMap/Leaf/v2");
        hasher.update(key);
        hasher.update(value.bytes());
        Digest::new(hasher.finalize().into())
    }

    fn oracle_hash_branch(depth: u16, key: &[u8; 32], left: Digest, right: Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"CSER/AuthenticatedMap/Branch/v2");
        hasher.update(depth.to_be_bytes());
        hasher.update(key);
        hasher.update(left.bytes());
        hasher.update(right.bytes());
        Digest::new(hasher.finalize().into())
    }

    fn oracle(entries: &[([u8; 32], Digest)], depth: u16) -> Digest {
        if entries.is_empty() {
            assert_eq!(depth, 0);
            return oracle_hash_empty();
        }
        if entries.len() == 1 {
            return oracle_hash_leaf(&entries[0].0, entries[0].1);
        }
        let first = entries.iter().min_by_key(|entry| entry.0).unwrap();
        let last = entries.iter().max_by_key(|entry| entry.0).unwrap();
        let branch_depth = super::first_difference(&first.0, &last.0, depth);
        let mut left = alloc::vec::Vec::new();
        let mut right = alloc::vec::Vec::new();
        for entry in entries {
            if super::key_bit(&entry.0, branch_depth) {
                right.push(*entry);
            } else {
                left.push(*entry);
            }
        }
        oracle_hash_branch(
            branch_depth,
            &first.0,
            oracle(&left, branch_depth + 1),
            oracle(&right, branch_depth + 1),
        )
    }

    #[test]
    fn random_small_sets_match_independent_patricia_oracle() {
        let keys = [
            key(0),
            key(1),
            key(2),
            key(127),
            key(128),
            key(200),
            key(255),
        ];
        let values = [
            digest(3),
            digest(7),
            digest(11),
            digest(13),
            digest(17),
            digest(19),
            digest(23),
        ];
        let mut seed = 0x1234_5678_9abc_def0_u64;
        for _round in 0..64 {
            let mut selected = alloc::vec::Vec::new();
            for index in 0..keys.len() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                if seed & 1 != 0 {
                    selected.push((keys[index], values[index]));
                }
            }
            let mut map = AuthenticatedMap::new();
            for (entry_key, entry_value) in selected.iter().copied() {
                let _ = map.insert_mut(entry_key, entry_value);
            }
            assert_eq!(map.root_digest(), oracle(&selected, 0));
            assert_eq!(map.len(), selected.len());
            for (entry_key, entry_value) in selected.iter().copied() {
                assert_eq!(map.get(&entry_key), Some(entry_value));
            }
        }
    }

    #[test]
    fn replacement_and_removal_preserve_canonical_root() {
        let entries = [
            (key(0), digest(1)),
            (key(1), digest(2)),
            (key(128), Digest::ZERO),
        ];
        let mut map = AuthenticatedMap::new();
        for (entry_key, entry_value) in entries {
            assert_eq!(map.insert_mut(entry_key, entry_value), None);
        }
        assert_eq!(map.insert_mut(entries[1].0, digest(9)), Some(digest(2)));
        let expected = [entries[0], (entries[1].0, digest(9)), entries[2]];
        assert_eq!(map.root_digest(), oracle(&expected, 0));
        assert_eq!(map.remove_mut(&entries[1].0), Some(digest(9)));
        let expected = [entries[0], entries[2]];
        assert_eq!(map.root_digest(), oracle(&expected, 0));
        assert_eq!(map.remove_mut(&entries[0].0), Some(digest(1)));
        assert_eq!(map.remove_mut(&entries[2].0), Some(Digest::ZERO));
        assert!(map.is_empty());
        assert_eq!(map.root_digest(), oracle(&[], 0));
    }
}

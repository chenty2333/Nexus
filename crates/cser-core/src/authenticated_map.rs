//! A canonical, path-copying sparse Merkle map.
//!
//! The map uses the 256 bits of a fixed-size key as the path through a binary
//! tree. Occupied paths are stored in a compressed Patricia shape: unary runs
//! of the conceptual tree are not allocated. A branch commits directly to its
//! canonical depth, representative key, and child digests, so hashing a
//! compressed edge does not replay the omitted unary path.

extern crate alloc;

use alloc::sync::Arc;
#[cfg(test)]
use alloc::vec::Vec;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::Digest;
#[cfg(test)]
use crate::persistent_map::SortedExactError;

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

/// Error returned while building an authenticated map without path copying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedMapBuilderError {
    /// The input attempted to insert an already occupied key.
    DuplicateKey([u8; 32]),
    /// The builder could not obtain unique ownership of one of its nodes.
    ///
    /// This is an internal ownership violation: callers cannot create an
    /// alias to a builder's private root, but returning an error keeps the
    /// builder fail-closed if that invariant ever changes.
    SharedNode,
    /// The number of leaves would overflow the builder's length counter.
    CapacityOverflow,
}

/// A one-pass mutable builder for unsorted authenticated-map leaves.
///
/// The builder owns the resident `Arc` tree exclusively.  Inserting a leaf
/// mutates existing branch nodes in place; only the new leaf and the branch
/// introduced at a previously absent divergence are allocated. Hashes remain
/// unset until [`Self::finish`], which computes them in one post-order pass.
/// No input collection or sorting buffer is retained.
#[derive(Debug)]
pub(crate) struct AuthenticatedMapBuilder {
    root: Option<Arc<Node>>,
    len: usize,
}

impl AuthenticatedMapBuilder {
    /// Creates an empty builder.
    pub(crate) const fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Returns the number of leaves accepted so far.
    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no leaves have been accepted.
    #[cfg(test)]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds one unsorted leaf.
    ///
    /// A duplicate leaves the builder unchanged and returns its exact key.
    /// A zero digest is an ordinary value and is therefore accepted.
    pub(crate) fn insert(
        &mut self,
        key: [u8; 32],
        value: Digest,
    ) -> Result<(), AuthenticatedMapBuilderError> {
        if self.len == usize::MAX {
            return Err(AuthenticatedMapBuilderError::CapacityOverflow);
        }
        if let Some(root) = self.root.as_mut() {
            insert_builder_node(root, 0, key, value)?;
        } else {
            self.root = Some(make_unhashed_leaf(key, value));
        }
        self.len += 1;
        Ok(())
    }

    /// Finishes the map and computes every resident node hash once.
    pub(crate) fn finish(mut self) -> Result<AuthenticatedMap, AuthenticatedMapBuilderError> {
        let empty_digest = hash_empty();
        let root_digest = match self.root.as_mut() {
            Some(root) => finalize_builder_hash(root)?,
            None => empty_digest,
        };
        Ok(AuthenticatedMap {
            root: self.root,
            len: self.len,
            root_digest,
            empty_digest,
        })
    }
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

    /// Builds a canonical authenticated map from exactly `expected_len`
    /// strictly increasing leaves.
    ///
    /// Leaves are consumed once in lexicographic key order.  The builder
    /// maintains only the compressed right frontier (at most one frame per
    /// key bit), constructs each final leaf or branch once, and computes the
    /// same root commitment as inserting the leaves one at a time in any
    /// order.  A zero digest remains a valid leaf value; only a duplicate or
    /// non-increasing key is rejected.
    #[cfg(test)]
    pub fn try_from_sorted_exact<I>(
        leaves: I,
        expected_len: usize,
    ) -> Result<Self, SortedExactError>
    where
        I: IntoIterator<Item = ([u8; 32], Digest)>,
    {
        let mut leaves = leaves.into_iter();
        let mut previous_key = None;
        let mut root = None;
        let mut frontier = Vec::new();

        for (index, _) in (0..expected_len).enumerate() {
            let Some((key, value)) = leaves.next() else {
                return Err(SortedExactError::TooFew {
                    expected: expected_len,
                    actual: index,
                });
            };

            if let Some(previous_key) = previous_key {
                if key <= previous_key {
                    return Err(SortedExactError::NotStrictlyIncreasing);
                }
                let Some(divergence) = (0..TREE_DEPTH)
                    .find(|depth| key_bit(&previous_key, *depth) != key_bit(&key, *depth))
                else {
                    return Err(SortedExactError::NotStrictlyIncreasing);
                };
                while frontier
                    .last()
                    .is_some_and(|frame: &BuildFrame| frame.depth >= divergence)
                {
                    if !finish_frontier_frame(&mut frontier, &mut root) {
                        // The sorted-key checks above make this unreachable
                        // for a valid stream.  Keep the fallible builder
                        // fail-closed if its internal frontier is ever
                        // malformed instead of exposing an `expect` panic to
                        // recovery input.
                        return Err(SortedExactError::NotStrictlyIncreasing);
                    }
                }

                let left = if let Some(parent) = frontier.last_mut() {
                    let Some(left) = parent.right.take() else {
                        return Err(SortedExactError::NotStrictlyIncreasing);
                    };
                    left
                } else {
                    let Some(left) = root.take() else {
                        return Err(SortedExactError::NotStrictlyIncreasing);
                    };
                    left
                };
                frontier.push(BuildFrame {
                    depth: divergence,
                    left,
                    right: Some(make_leaf(key, value)),
                });
            } else {
                root = Some(make_leaf(key, value));
            }
            previous_key = Some(key);
        }

        if leaves.next().is_some() {
            return Err(SortedExactError::TooMany {
                expected: expected_len,
            });
        }

        while !frontier.is_empty() {
            if !finish_frontier_frame(&mut frontier, &mut root) {
                return Err(SortedExactError::NotStrictlyIncreasing);
            }
        }

        let empty_digest = hash_empty();
        let root_digest = root.as_ref().map_or(empty_digest, |root| root.hash());
        Ok(Self {
            root,
            len: expected_len,
            root_digest,
            empty_digest,
        })
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
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn get(&self, key: &[u8; 32]) -> Option<Digest> {
        self.root.as_deref().and_then(|node| get_node(node, 0, key))
    }

    /// Returns the cached canonical root digest.
    #[must_use]
    pub const fn root_digest(&self) -> Digest {
        self.root_digest
    }

    /// Returns whether two maps share the exact persistent root.
    ///
    /// This is used by the prepared-delta publisher to distinguish an
    /// untouched authenticated projection from one whose path was copied.
    /// Digest equality remains the semantic comparison.
    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.root_digest == other.root_digest
            && match (&self.root, &other.root) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
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

fn make_unhashed_leaf(key: [u8; 32], value: Digest) -> Arc<Node> {
    Arc::new(Node::Leaf {
        key,
        value,
        hash: Digest::ZERO,
    })
}

#[cfg(test)]
struct BuildFrame {
    depth: u16,
    left: Arc<Node>,
    right: Option<Arc<Node>>,
}

#[cfg(test)]
fn finish_frontier_frame(frontier: &mut Vec<BuildFrame>, root: &mut Option<Arc<Node>>) -> bool {
    let Some(frame) = frontier.pop() else {
        return false;
    };
    let Some(right) = frame.right else {
        return false;
    };
    let branch = make_branch(frame.depth, frame.left, right);
    if let Some(parent) = frontier.last_mut() {
        debug_assert!(parent.right.is_none());
        parent.right = Some(branch);
    } else {
        *root = Some(branch);
    }
    true
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

fn make_unhashed_branch(depth: u16, left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
    debug_assert!(depth < TREE_DEPTH);
    debug_assert!(key_bit(left.key(), depth) != key_bit(right.key(), depth));
    debug_assert!(left.key() < right.key());
    let key = *left.key();
    Arc::new(Node::Branch {
        depth,
        key,
        left,
        right,
        hash: Digest::ZERO,
    })
}

fn insert_builder_node(
    node: &mut Arc<Node>,
    expected_depth: u16,
    key: [u8; 32],
    value: Digest,
) -> Result<(), AuthenticatedMapBuilderError> {
    match node.as_ref() {
        Node::Leaf {
            key: stored_key, ..
        } => {
            if stored_key == &key {
                return Err(AuthenticatedMapBuilderError::DuplicateKey(key));
            }
            let depth = first_difference(stored_key, &key, expected_depth);
            let old_leaf = node.clone();
            let new_leaf = make_unhashed_leaf(key, value);
            *node = if key_bit(&key, depth) {
                make_unhashed_branch(depth, old_leaf, new_leaf)
            } else {
                make_unhashed_branch(depth, new_leaf, old_leaf)
            };
            Ok(())
        }
        Node::Branch {
            depth,
            key: representative,
            ..
        } => {
            let branch_depth = *depth;
            let prefix_diff = (expected_depth..branch_depth)
                .find(|bit| key_bit(representative, *bit) != key_bit(&key, *bit));
            if let Some(depth) = prefix_diff {
                let old_branch = node.clone();
                let new_leaf = make_unhashed_leaf(key, value);
                *node = if key_bit(&key, depth) {
                    make_unhashed_branch(depth, old_branch, new_leaf)
                } else {
                    make_unhashed_branch(depth, new_leaf, old_branch)
                };
                return Ok(());
            }

            let Some(current) = Arc::get_mut(node) else {
                return Err(AuthenticatedMapBuilderError::SharedNode);
            };
            let Node::Branch {
                depth: current_depth,
                key: current_representative,
                left,
                right,
                ..
            } = current
            else {
                return Err(AuthenticatedMapBuilderError::SharedNode);
            };
            let result = if key_bit(&key, *current_depth) {
                insert_builder_node(right, *current_depth + 1, key, value)
            } else {
                insert_builder_node(left, *current_depth + 1, key, value)
            };
            if result.is_ok() {
                *current_representative = *left.key();
            }
            result
        }
    }
}

fn finalize_builder_hash(node: &mut Arc<Node>) -> Result<Digest, AuthenticatedMapBuilderError> {
    let Some(current) = Arc::get_mut(node) else {
        return Err(AuthenticatedMapBuilderError::SharedNode);
    };
    match current {
        Node::Leaf { key, value, hash } => {
            let digest = hash_leaf(key, *value);
            *hash = digest;
            Ok(digest)
        }
        Node::Branch {
            depth,
            key,
            left,
            right,
            hash,
        } => {
            let left_hash = finalize_builder_hash(left)?;
            let right_hash = finalize_builder_hash(right)?;
            let representative = *left.key();
            let digest = hash_branch(*depth, &representative, left_hash, right_hash);
            *key = representative;
            *hash = digest;
            Ok(digest)
        }
    }
}

#[inline]
fn first_difference(left: &[u8; 32], right: &[u8; 32], start: u16) -> u16 {
    debug_assert!(start < TREE_DEPTH);

    // The first byte may begin in the middle of a byte.  Masking the prefix
    // keeps the MSB-first path semantics while allowing the remaining bytes
    // to be compared in native word-sized chunks.  `from_be_bytes` makes the
    // leading-zero count independent of host endianness, and explicit byte
    // loads remain valid even when the input arrays are not word-aligned.
    let mut byte_index = (start / 8) as usize;
    let bit_offset = start % 8;
    if bit_offset != 0 {
        let difference = (left[byte_index] ^ right[byte_index]) & (0xff >> bit_offset);
        if difference != 0 {
            return (byte_index * 8 + difference.leading_zeros() as usize) as u16;
        }
        byte_index += 1;
    }

    while byte_index + 8 <= left.len() {
        let left_word = u64::from_be_bytes([
            left[byte_index],
            left[byte_index + 1],
            left[byte_index + 2],
            left[byte_index + 3],
            left[byte_index + 4],
            left[byte_index + 5],
            left[byte_index + 6],
            left[byte_index + 7],
        ]);
        let right_word = u64::from_be_bytes([
            right[byte_index],
            right[byte_index + 1],
            right[byte_index + 2],
            right[byte_index + 3],
            right[byte_index + 4],
            right[byte_index + 5],
            right[byte_index + 6],
            right[byte_index + 7],
        ]);
        let difference = left_word ^ right_word;
        if difference != 0 {
            return (byte_index * 8 + difference.leading_zeros() as usize) as u16;
        }
        byte_index += 8;
    }

    while byte_index < left.len() {
        let difference = left[byte_index] ^ right[byte_index];
        if difference != 0 {
            return (byte_index * 8 + difference.leading_zeros() as usize) as u16;
        }
        byte_index += 1;
    }

    unreachable!("different authenticated-map keys must diverge")
}

#[cfg(any(test, feature = "test-support"))]
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
    use super::{
        AuthenticatedMap, AuthenticatedMapBuilder, AuthenticatedMapBuilderError, Node,
        SortedExactError, TREE_DEPTH,
    };
    use crate::Digest;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use sha2::{Digest as Sha2Digest, Sha256};

    fn key(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn key_prefix(prefix: [u8; 4]) -> [u8; 32] {
        let mut key = [0; 32];
        key[..4].copy_from_slice(&prefix);
        key
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

    fn reference_first_difference(left: &[u8; 32], right: &[u8; 32], start: u16) -> u16 {
        (start..TREE_DEPTH)
            .find(|depth| super::key_bit(left, *depth) != super::key_bit(right, *depth))
            .expect("test keys must differ at or after the requested depth")
    }

    #[test]
    fn first_difference_matches_msb_reference_at_every_bit_boundary() {
        for difference_depth in 0..TREE_DEPTH {
            let left = [0; 32];
            let mut right = [0; 32];
            right[(difference_depth / 8) as usize] = 0x80 >> (difference_depth % 8);

            for start in 0..=difference_depth {
                assert_eq!(
                    super::first_difference(&left, &right, start),
                    reference_first_difference(&left, &right, start),
                    "difference depth {difference_depth}, start {start}"
                );
            }
        }
    }

    #[test]
    fn first_difference_matches_msb_reference_for_property_cases() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for round in 0..256 {
            let mut left = [0; 32];
            let mut right = [0; 32];
            for byte in &mut left {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *byte = (seed >> 24) as u8;
            }
            for byte in &mut right {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *byte = (seed >> 32) as u8;
            }
            if left == right {
                right[round % right.len()] ^= 1;
            }

            let first = reference_first_difference(&left, &right, 0);
            for start in 0..=first {
                assert_eq!(
                    super::first_difference(&left, &right, start),
                    reference_first_difference(&left, &right, start),
                    "round {round}, start {start}"
                );
            }
        }
    }

    #[test]
    fn mutable_builder_handles_empty_zero_and_duplicate_leaves() {
        let empty = AuthenticatedMapBuilder::new()
            .finish()
            .expect("an empty builder has no ownership failure");
        assert_eq!(empty, AuthenticatedMap::new());
        assert!(empty.is_empty());

        let duplicate_key = key(0x2a);
        let second_key = key(0x2b);
        let mut builder = AuthenticatedMapBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.insert(duplicate_key, Digest::ZERO), Ok(()));
        assert_eq!(builder.insert(second_key, digest(8)), Ok(()));
        assert_eq!(builder.len(), 2);
        assert_eq!(
            builder.insert(duplicate_key, digest(7)),
            Err(AuthenticatedMapBuilderError::DuplicateKey(duplicate_key))
        );
        let built = builder
            .finish()
            .expect("duplicate rejection leaves the builder valid");
        assert_eq!(built.get(&duplicate_key), Some(Digest::ZERO));
        assert_eq!(built.get(&second_key), Some(digest(8)));
        assert_eq!(built.node_count(), 3);
    }

    #[test]
    fn sorted_builder_matches_inserted_map_and_lookup() {
        let entries = [
            (key(0), Digest::ZERO),
            (key(1), digest(2)),
            (key(7), digest(3)),
            (key(64), digest(4)),
            (key(128), digest(5)),
            (key(255), digest(6)),
        ];
        let built = AuthenticatedMap::try_from_sorted_exact(entries, entries.len())
            .expect("strictly sorted leaves should build");
        let mut inserted = AuthenticatedMap::new();
        for (entry_key, entry_value) in entries {
            assert_eq!(inserted.insert_mut(entry_key, entry_value), None);
        }

        assert_eq!(built.root_digest(), inserted.root_digest());
        assert_eq!(
            built.root_digest(),
            Digest::new([
                0x73, 0x7d, 0x2b, 0xf1, 0xdc, 0xf3, 0x16, 0xa8, 0x0a, 0xb0, 0x74, 0x68, 0xf9, 0x4f,
                0xb4, 0xd1, 0xab, 0xbd, 0x86, 0x0c, 0x4c, 0x17, 0x10, 0x43, 0xd5, 0x54, 0xc6, 0xa3,
                0x2a, 0x82, 0xe6, 0xb9,
            ])
        );
        assert_eq!(built.len(), inserted.len());
        for (entry_key, entry_value) in entries {
            assert_eq!(built.get(&entry_key), Some(entry_value));
        }

        let mut mutable_builder = AuthenticatedMapBuilder::new();
        for (entry_key, entry_value) in entries {
            mutable_builder
                .insert(entry_key, entry_value)
                .expect("fixture keys are unique");
        }
        let mutable = mutable_builder
            .finish()
            .expect("the builder owns every resident node");
        assert_eq!(mutable.root_digest(), built.root_digest());
        assert_eq!(mutable.len(), entries.len());
        assert_eq!(mutable.node_count(), 2 * entries.len() - 1);
    }

    #[test]
    fn sorted_builder_rejects_bad_lengths_and_duplicate_keys() {
        assert_eq!(
            AuthenticatedMap::try_from_sorted_exact([(key(1), digest(1))], 2),
            Err(SortedExactError::TooFew {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            AuthenticatedMap::try_from_sorted_exact([(key(1), digest(1))], 0),
            Err(SortedExactError::TooMany { expected: 0 })
        );
        assert_eq!(
            AuthenticatedMap::try_from_sorted_exact([(key(1), digest(1)), (key(1), digest(2))], 2),
            Err(SortedExactError::NotStrictlyIncreasing)
        );
        assert_eq!(
            AuthenticatedMap::try_from_sorted_exact([(key(2), digest(2)), (key(1), digest(1))], 2),
            Err(SortedExactError::NotStrictlyIncreasing)
        );
    }

    #[test]
    fn mutable_builder_matches_every_permutation_and_sorted_builder() {
        let entries = [
            (key(0), Digest::ZERO),
            (key(1), digest(2)),
            (key(7), digest(3)),
            (key(64), digest(4)),
            (key(128), digest(5)),
            (key(255), digest(6)),
            (key_prefix([0x12, 0x34, 0x56, 0x78]), digest(8)),
            (key_prefix([0xa5, 0x5a, 0x01, 0xfe]), digest(9)),
        ];
        let mut sorted = entries;
        sorted.sort_unstable_by_key(|entry| entry.0);
        let sorted_len = sorted.len();
        let expected = AuthenticatedMap::try_from_sorted_exact(sorted, sorted_len)
            .expect("the sorted fixture should build");
        let mut order: Vec<usize> = (0..entries.len()).collect();
        let mut seed = 0x243f_6a88_85a3_08d3_u64;

        for round in 0..64 {
            for index in (1..order.len()).rev() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let swap = (seed as usize) % (index + 1);
                order.swap(index, swap);
            }

            let mut builder = AuthenticatedMapBuilder::new();
            let mut inserted = AuthenticatedMap::new();
            for &index in &order {
                let (entry_key, entry_value) = entries[index];
                builder
                    .insert(entry_key, entry_value)
                    .expect("the permutation contains unique keys");
                assert_eq!(inserted.insert_mut(entry_key, entry_value), None);
            }
            let built = builder.finish().expect("the builder owns its tree");
            assert_eq!(built.root_digest(), expected.root_digest(), "round {round}");
            assert_eq!(built.root_digest(), inserted.root_digest(), "round {round}");
            assert_eq!(built.len(), entries.len());
            assert_eq!(built.node_count(), 2 * entries.len() - 1);
        }
    }

    #[test]
    fn mutable_builder_handles_prefix_and_depth_boundaries() {
        let depths = [0, 1, 7, 8, 63, 64, 127, 128, 191, 192, 255];
        let entries: Vec<_> = depths
            .into_iter()
            .enumerate()
            .map(|(index, depth)| {
                let mut key = [0; 32];
                key[(depth / 8) as usize] = 0x80 >> (depth % 8);
                (key, digest((index + 1) as u8))
            })
            .collect();
        let mut sorted = entries.clone();
        sorted.sort_unstable_by_key(|entry| entry.0);
        let sorted_len = sorted.len();
        let expected = AuthenticatedMap::try_from_sorted_exact(sorted, sorted_len)
            .expect("boundary keys are unique");

        let mut builder = AuthenticatedMapBuilder::new();
        for (entry_key, entry_value) in entries.iter().copied().rev() {
            builder
                .insert(entry_key, entry_value)
                .expect("boundary keys are unique");
        }
        let built = builder.finish().expect("the builder owns its tree");
        assert_eq!(built.root_digest(), expected.root_digest());
        assert_eq!(built.node_count(), 2 * entries.len() - 1);
        for (entry_key, entry_value) in entries {
            assert_eq!(built.get(&entry_key), Some(entry_value));
        }
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
            let built =
                AuthenticatedMap::try_from_sorted_exact(selected.iter().copied(), selected.len())
                    .expect("the selected fixture keys are strictly sorted");
            assert_eq!(map.root_digest(), oracle(&selected, 0));
            assert_eq!(built.root_digest(), map.root_digest());
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

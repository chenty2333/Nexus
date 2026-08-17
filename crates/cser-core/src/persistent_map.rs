//! An immutable, path-copying ordered map for transition-local state.
//!
//! `StateMap` deliberately has no hash or projection semantics.  It is a small
//! structural sharing primitive: an update copies only the search path in an
//! AVL tree and leaves all other subtrees shared through `Arc`.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::iter::FromIterator;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Node<K, V> {
    key: K,
    // Values are independently shared from the path-copying tree nodes.  A
    // copied ancestor therefore clones this pointer rather than cloning the
    // (potentially large) record it contains.  `get_mut` makes the target
    // value unique only when the caller actually mutates it.
    value: Arc<V>,
    left: Option<Arc<Node<K, V>>>,
    right: Option<Arc<Node<K, V>>>,
    height: u32,
    size: usize,
}

/// An immutable ordered map with logarithmic path-copying updates.
///
/// Cloning a map is `O(1)`.  `insert` and `remove` return a new map and copy
/// only the `O(log n)` path that was changed.  Iteration is in canonical key
/// order.
#[derive(Debug)]
pub struct StateMap<K, V> {
    root: Option<Arc<Node<K, V>>>,
    len: usize,
}

/// An immutable ordered set backed by the same path-copying AVL tree as
/// [`StateMap`].
///
/// The set stores unit values and therefore preserves the map's structural
/// sharing properties: cloning is `O(1)`, while an insertion or removal copies
/// only the changed `O(log n)` path.  Iteration is canonical ascending key
/// order.
#[derive(Debug)]
pub(crate) struct StateSet<K> {
    map: StateMap<K, ()>,
}

impl<K> Clone for StateSet<K> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<K: Ord + PartialEq> PartialEq for StateSet<K> {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl<K: Ord + Eq> Eq for StateSet<K> {}

impl<K> Default for StateSet<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> StateSet<K> {
    /// Creates an empty set.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            map: StateMap::new(),
        }
    }

    /// Returns the number of entries in the set.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns whether the set contains no entries.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns whether two sets share the exact persistent root.
    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        self.map.ptr_eq(&other.map)
    }
}

impl<K: Ord> StateSet<K> {
    /// Returns whether `key` is present.
    #[must_use]
    pub(crate) fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Iterates over keys in ascending order.
    #[must_use]
    pub(crate) fn iter(&self) -> StateSetIter<'_, K> {
        StateSetIter {
            inner: self.map.iter(),
        }
    }
}

impl<K: Ord + Clone> StateSet<K> {
    /// Inserts `key` in place and returns whether it was newly inserted.
    pub(crate) fn insert_mut(&mut self, key: K) -> bool {
        self.map.insert_mut(key, ()).is_none()
    }

    /// Removes `key` in place and returns whether it was present.
    pub(crate) fn remove_mut(&mut self, key: &K) -> bool {
        self.map.remove_mut(key).is_some()
    }

    /// Inserts every key from `iter` in place.
    pub(crate) fn extend<I: IntoIterator<Item = K>>(&mut self, iter: I) {
        for key in iter {
            self.insert_mut(key);
        }
    }
}

impl<K: Ord + Clone> FromIterator<K> for StateSet<K> {
    fn from_iter<T: IntoIterator<Item = K>>(iter: T) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

impl<'a, K: Ord> IntoIterator for &'a StateSet<K> {
    type Item = &'a K;
    type IntoIter = StateSetIter<'a, K>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The in-order iterator returned by [`StateSet::iter`].
pub(crate) struct StateSetIter<'a, K> {
    inner: Iter<'a, K, ()>,
}

impl<'a, K> Iterator for StateSetIter<'a, K> {
    type Item = &'a K;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, _)| key)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V> Clone for StateMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<K: Ord + PartialEq, V: PartialEq> PartialEq for StateMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.iter().zip(other.iter()).all(
                |((left_key, left_value), (right_key, right_value))| {
                    left_key == right_key && left_value == right_value
                },
            )
    }
}

impl<K: Ord + Eq, V: Eq> Eq for StateMap<K, V> {}

impl<'a, K: Ord, V> IntoIterator for &'a StateMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K: Ord + Clone, V: Clone> FromIterator<(K, V)> for StateMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut map = Self::new();
        for (key, value) in iter {
            map.insert_mut(key, value);
        }
        map
    }
}

impl<K, V> Default for StateMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> StateMap<K, V> {
    /// Creates an empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Returns the number of entries in the map.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the map contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether two maps share the exact persistent root.
    ///
    /// Transition preparation uses this identity check to turn unchanged
    /// top-level collections into `Change::Keep` slots without walking their
    /// contents. Digest/equality remains the semantic comparison.
    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        self.len == other.len
            && match (&self.root, &other.root) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }

    /// Removes every entry from the map in place.
    pub fn clear(&mut self) {
        self.root = None;
        self.len = 0;
    }
}

impl<K: Ord, V> StateMap<K, V> {
    /// Returns the value for `key`, if present.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        let mut current = self.root.as_deref();
        while let Some(node) = current {
            match key.cmp(&node.key) {
                Ordering::Less => current = node.left.as_deref(),
                Ordering::Greater => current = node.right.as_deref(),
                Ordering::Equal => return Some(node.value.as_ref()),
            }
        }
        None
    }

    /// Returns whether `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Iterates over entries in ascending key order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_, K, V> {
        let mut iter = Iter { stack: Vec::new() };
        iter.push_left(self.root.as_deref());
        iter
    }

    /// Iterates over values in ascending key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }

    /// Iterates over keys in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(key, _)| key)
    }
}

impl<K: Ord + Clone, V: Clone> StateMap<K, V> {
    /// Returns a mutable value for `key`, inserting one produced by `make` if
    /// the key is absent.
    ///
    /// This deliberately keeps the API smaller than an entry facade.  The
    /// lookup and insertion paths are separate, so callers that need this
    /// helper should use it for infrequent recovery/checkpoint construction,
    /// not as a replacement for a hot batched update path.
    pub fn get_or_insert_with_mut<F>(&mut self, key: K, make: F) -> &mut V
    where
        F: FnOnce() -> V,
    {
        if self.contains_key(&key) {
            return self
                .get_mut(&key)
                .expect("a key observed in the map must remain present");
        }

        let lookup = key.clone();
        self.insert_mut(key, make());
        self.get_mut(&lookup)
            .expect("a freshly inserted key must be present")
    }

    /// Returns a mutable value for `key`, if present.
    ///
    /// `Arc::make_mut` clones only the shared nodes on the search path.  Value
    /// storage is shared independently from those nodes, so a cloned map
    /// clones the target value on first mutation but does not deep-clone the
    /// unrelated ancestor values.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let mut current = self.root.as_mut()?;
        loop {
            let node = Arc::make_mut(current);
            match key.cmp(&node.key) {
                Ordering::Less => {
                    current = node.left.as_mut()?;
                }
                Ordering::Greater => {
                    current = node.right.as_mut()?;
                }
                Ordering::Equal => return Some(Arc::make_mut(&mut node.value)),
            }
        }
    }

    /// Inserts `value` for `key` in place and returns the replaced value, if
    /// any.  The map remains AVL-balanced by delegating to the immutable
    /// path-copying update before swapping the new root into place.
    pub fn insert_mut(&mut self, key: K, value: V) -> Option<V> {
        let (updated, old) = self.insert(key, value);
        *self = updated;
        old
    }

    /// Removes `key` in place and returns the removed value, if any.
    pub fn remove_mut(&mut self, key: &K) -> Option<V> {
        let (updated, old) = self.remove(key);
        *self = updated;
        old
    }

    /// Inserts `value` for `key` and returns the new map and the replaced
    /// value, if any.  The original map is unchanged.
    #[must_use]
    pub fn insert(&self, key: K, value: V) -> (Self, Option<V>) {
        let (root, old) = insert_node(self.root.as_ref(), key, value);
        let len = if old.is_some() {
            self.len
        } else {
            self.len + 1
        };
        (
            Self {
                root: Some(root),
                len,
            },
            old,
        )
    }

    /// Removes `key` and returns the new map and the removed value, if any.
    /// The original map is unchanged.
    #[must_use]
    pub fn remove(&self, key: &K) -> (Self, Option<V>) {
        let (root, old) = remove_node(self.root.as_ref(), key);
        if old.is_none() {
            return (self.clone(), None);
        }
        (
            Self {
                root,
                len: self.len - 1,
            },
            old,
        )
    }

    /// Retains entries for which `keep` returns `true`, allowing the value to
    /// be changed while deciding.
    ///
    /// This is intentionally an `O(n)` recovery/checkpoint utility.  It takes
    /// a snapshot of the ordered keys before invoking the predicate so that
    /// the predicate may mutate values and remove entries without invalidating
    /// traversal.
    pub fn retain_mut<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let keys: Vec<K> = self.keys().cloned().collect();
        for key in keys {
            let retain = {
                let Some(value) = self.get_mut(&key) else {
                    continue;
                };
                keep(&key, value)
            };
            if !retain {
                self.remove_mut(&key);
            }
        }
    }
}

/// The in-order iterator returned by [`StateMap::iter`].
pub struct Iter<'a, K, V> {
    stack: Vec<&'a Node<K, V>>,
}

impl<'a, K, V> Iter<'a, K, V> {
    fn push_left(&mut self, mut node: Option<&'a Node<K, V>>) {
        while let Some(current) = node {
            self.stack.push(current);
            node = current.left.as_deref();
        }
    }
}

impl<'a, K: 'a, V: 'a> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        Some((&node.key, &node.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

fn height<K, V>(node: Option<&Arc<Node<K, V>>>) -> u32 {
    node.map_or(0, |node| node.height)
}

fn make_node<K, V>(
    key: K,
    value: Arc<V>,
    left: Option<Arc<Node<K, V>>>,
    right: Option<Arc<Node<K, V>>>,
) -> Arc<Node<K, V>> {
    let left_height = height(left.as_ref());
    let right_height = height(right.as_ref());
    let size = 1 + size_of(left.as_ref()) + size_of(right.as_ref());
    Arc::new(Node {
        key,
        value,
        left,
        right,
        height: 1 + left_height.max(right_height),
        size,
    })
}

fn size_of<K, V>(node: Option<&Arc<Node<K, V>>>) -> usize {
    node.map_or(0, |node| node.size)
}

fn balance_factor<K, V>(node: &Node<K, V>) -> i32 {
    height(node.left.as_ref()) as i32 - height(node.right.as_ref()) as i32
}

fn rotate_right<K: Clone, V>(
    key: K,
    value: Arc<V>,
    left: Arc<Node<K, V>>,
    right: Option<Arc<Node<K, V>>>,
) -> Arc<Node<K, V>> {
    let new_right = make_node(key, value, left.right.clone(), right);
    make_node(
        left.key.clone(),
        left.value.clone(),
        left.left.clone(),
        Some(new_right),
    )
}

fn rotate_left<K: Clone, V>(
    key: K,
    value: Arc<V>,
    left: Option<Arc<Node<K, V>>>,
    right: Arc<Node<K, V>>,
) -> Arc<Node<K, V>> {
    let new_left = make_node(key, value, left, right.left.clone());
    make_node(
        right.key.clone(),
        right.value.clone(),
        Some(new_left),
        right.right.clone(),
    )
}

fn rebalance<K: Clone, V>(
    key: K,
    value: Arc<V>,
    left: Option<Arc<Node<K, V>>>,
    right: Option<Arc<Node<K, V>>>,
) -> Arc<Node<K, V>> {
    let balance = height(left.as_ref()) as i32 - height(right.as_ref()) as i32;
    if balance > 1 {
        let left_node = left
            .as_ref()
            .expect("an AVL node with balance > 1 has a left child");
        if balance_factor(left_node) < 0 {
            let inner = left_node
                .right
                .as_ref()
                .expect("an AVL left-right rotation has an inner child")
                .clone();
            let rotated_left = rotate_left(
                left_node.key.clone(),
                left_node.value.clone(),
                left_node.left.clone(),
                inner,
            );
            return rotate_right(key, value, rotated_left, right);
        }
        return rotate_right(key, value, left_node.clone(), right);
    }
    if balance < -1 {
        let right_node = right
            .as_ref()
            .expect("an AVL node with balance < -1 has a right child");
        if balance_factor(right_node) > 0 {
            let inner = right_node
                .left
                .as_ref()
                .expect("an AVL right-left rotation has an inner child")
                .clone();
            let rotated_right = rotate_right(
                right_node.key.clone(),
                right_node.value.clone(),
                inner,
                right_node.right.clone(),
            );
            return rotate_left(key, value, left, rotated_right);
        }
        return rotate_left(key, value, left, right_node.clone());
    }
    make_node(key, value, left, right)
}

fn insert_node<K: Ord + Clone, V: Clone>(
    node: Option<&Arc<Node<K, V>>>,
    key: K,
    value: V,
) -> (Arc<Node<K, V>>, Option<V>) {
    let Some(node) = node else {
        return (make_node(key, Arc::new(value), None, None), None);
    };
    match key.cmp(&node.key) {
        Ordering::Less => {
            let (left, old) = insert_node(node.left.as_ref(), key, value);
            (
                rebalance(
                    node.key.clone(),
                    node.value.clone(),
                    Some(left),
                    node.right.clone(),
                ),
                old,
            )
        }
        Ordering::Greater => {
            let (right, old) = insert_node(node.right.as_ref(), key, value);
            (
                rebalance(
                    node.key.clone(),
                    node.value.clone(),
                    node.left.clone(),
                    Some(right),
                ),
                old,
            )
        }
        Ordering::Equal => (
            make_node(
                node.key.clone(),
                Arc::new(value),
                node.left.clone(),
                node.right.clone(),
            ),
            Some(node.value.as_ref().clone()),
        ),
    }
}

fn remove_node<K: Ord + Clone, V: Clone>(
    node: Option<&Arc<Node<K, V>>>,
    key: &K,
) -> (Option<Arc<Node<K, V>>>, Option<V>) {
    let Some(node) = node else {
        return (None, None);
    };
    match key.cmp(&node.key) {
        Ordering::Less => {
            let (left, old) = remove_node(node.left.as_ref(), key);
            let Some(old) = old else {
                return (Some(node.clone()), None);
            };
            (
                Some(rebalance(
                    node.key.clone(),
                    node.value.clone(),
                    left,
                    node.right.clone(),
                )),
                Some(old),
            )
        }
        Ordering::Greater => {
            let (right, old) = remove_node(node.right.as_ref(), key);
            let Some(old) = old else {
                return (Some(node.clone()), None);
            };
            (
                Some(rebalance(
                    node.key.clone(),
                    node.value.clone(),
                    node.left.clone(),
                    right,
                )),
                Some(old),
            )
        }
        Ordering::Equal => {
            let old = node.value.as_ref().clone();
            match (&node.left, &node.right) {
                (None, _) => (node.right.clone(), Some(old)),
                (_, None) => (node.left.clone(), Some(old)),
                (Some(_), Some(right)) => {
                    let (successor_key, successor_value, new_right) = remove_min(right);
                    (
                        Some(rebalance(
                            successor_key,
                            successor_value,
                            node.left.clone(),
                            new_right,
                        )),
                        Some(old),
                    )
                }
            }
        }
    }
}

type RemoveMinResult<K, V> = (K, Arc<V>, Option<Arc<Node<K, V>>>);

fn remove_min<K: Clone, V>(node: &Arc<Node<K, V>>) -> RemoveMinResult<K, V> {
    let Some(left) = node.left.as_ref() else {
        return (node.key.clone(), node.value.clone(), node.right.clone());
    };
    let (key, value, new_left) = remove_min(left);
    let new_root = rebalance(
        node.key.clone(),
        node.value.clone(),
        new_left,
        node.right.clone(),
    );
    (key, value, Some(new_root))
}

#[cfg(test)]
mod tests {
    use super::{StateMap, StateSet};
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec,
        vec::Vec,
    };
    use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    static VALUE_CLONES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Eq, PartialEq)]
    struct CloneCounted(u32);

    impl Clone for CloneCounted {
        fn clone(&self) -> Self {
            VALUE_CLONES.fetch_add(1, AtomicOrdering::Relaxed);
            Self(self.0)
        }
    }

    fn assert_valid<K: Ord, V>(map: &StateMap<K, V>) -> (u32, usize) {
        fn visit<K: Ord, V>(
            node: Option<&super::Node<K, V>>,
            min: Option<&K>,
            max: Option<&K>,
        ) -> (u32, usize) {
            let Some(node) = node else {
                return (0, 0);
            };
            if let Some(min) = min {
                assert!(&node.key > min);
            }
            if let Some(max) = max {
                assert!(&node.key < max);
            }
            let (left_height, left_size) = visit(node.left.as_deref(), min, Some(&node.key));
            let (right_height, right_size) = visit(node.right.as_deref(), Some(&node.key), max);
            assert!((left_height as i32 - right_height as i32).abs() <= 1);
            assert_eq!(node.height, 1 + left_height.max(right_height));
            assert_eq!(node.size, 1 + left_size + right_size);
            (node.height, node.size)
        }

        let result = visit(map.root.as_deref(), None, None);
        assert_eq!(result.1, map.len());
        result
    }

    #[test]
    fn deterministic_operations_match_btree_map() {
        let mut expected = BTreeMap::new();
        let mut actual = StateMap::new();
        let mut seed = 0x9e37_79b9_u64;

        for step in 0..4_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let key = ((seed >> 17) % 401) as i32 - 200;
            if seed & 1 == 0 {
                let value = (seed ^ (step as u64 * 31)) as i64;
                let expected_old = expected.insert(key, value);
                let (new_actual, actual_old) = actual.insert(key, value);
                assert_eq!(actual_old, expected_old);
                actual = new_actual;
            } else {
                let expected_old = expected.remove(&key);
                let (new_actual, actual_old) = actual.remove(&key);
                assert_eq!(actual_old, expected_old);
                actual = new_actual;
            }
            assert_eq!(actual.len(), expected.len());
            assert_eq!(actual.is_empty(), expected.is_empty());
            assert_valid(&actual);
            assert_eq!(
                actual
                    .iter()
                    .map(|(key, value)| (*key, *value))
                    .collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|(key, value)| (*key, *value))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn clone_isolated_and_updates_share_structure() {
        let (map, _) = StateMap::new().insert(2, 20);
        let (map, _) = map.insert(1, 10);
        let (map, _) = map.insert(3, 30);
        let original = map.clone();

        let (updated, old) = map.insert(2, 200);
        assert_eq!(old, Some(20));
        assert_eq!(original.get(&2), Some(&20));
        assert_eq!(updated.get(&2), Some(&200));

        let (removed, old) = original.remove(&1);
        assert_eq!(old, Some(10));
        assert!(removed.get(&1).is_none());
        assert_eq!(original.get(&1), Some(&10));
        assert_eq!(original.len(), 3);
        assert_eq!(removed.len(), 2);
        assert_eq!(
            original
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            vec![(1, 10), (2, 20), (3, 30)]
        );
        assert_eq!(
            updated
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            vec![(1, 10), (2, 200), (3, 30)]
        );
        assert_valid(&updated);
        assert_valid(&removed);
    }

    #[test]
    fn absent_remove_preserves_contents() {
        let (map, _) = StateMap::new().insert(1, 1);
        let (map, _) = map.insert(3, 3);
        let (new_map, old) = map.remove(&2);
        assert_eq!(old, None);
        assert_eq!(new_map.len(), map.len());
        assert_eq!(
            new_map
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            vec![(1, 1), (3, 3)]
        );
        assert_valid(&new_map);
    }

    #[test]
    fn mutable_facade_preserves_clone_isolation_and_order() {
        let mut map = StateMap::new();
        assert_eq!(map.insert_mut(2, 20), None);
        assert_eq!(map.insert_mut(1, 10), None);
        assert_eq!(map.insert_mut(3, 30), None);

        let mut clone = map.clone();
        *map.get_mut(&2).expect("existing value") = 200;
        assert_eq!(map.get(&2), Some(&200));
        assert_eq!(clone.get(&2), Some(&20));

        assert_eq!(clone.insert_mut(2, 220), Some(20));
        assert_eq!(clone.remove_mut(&1), Some(10));
        assert_eq!(clone.remove_mut(&99), None);
        assert_eq!(clone.len(), 2);
        assert_eq!(clone.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(clone.values().copied().collect::<Vec<_>>(), vec![220, 30]);
        assert_eq!(map.len(), 3);
        assert_valid(&map);
        assert_valid(&clone);
    }

    #[test]
    fn path_copy_clones_only_the_target_value() {
        let mut map = StateMap::new();
        for key in 0..128 {
            assert_eq!(map.insert_mut(key, CloneCounted(key as u32)), None);
        }

        let mut updated = map.clone();
        VALUE_CLONES.store(0, AtomicOrdering::Relaxed);
        updated.get_mut(&73).expect("existing value").0 = 7_300;
        assert_eq!(VALUE_CLONES.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(map.get(&73), Some(&CloneCounted(73)));
        assert_eq!(updated.get(&73), Some(&CloneCounted(7_300)));

        VALUE_CLONES.store(0, AtomicOrdering::Relaxed);
        let (inserted, old) = map.insert(256, CloneCounted(256));
        assert_eq!(old, None);
        assert_eq!(VALUE_CLONES.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(inserted.get(&256), Some(&CloneCounted(256)));

        VALUE_CLONES.store(0, AtomicOrdering::Relaxed);
        let (removed, old) = map.remove(&73);
        assert_eq!(old, Some(CloneCounted(73)));
        assert_eq!(VALUE_CLONES.load(AtomicOrdering::Relaxed), 1);
        assert!(removed.get(&73).is_none());
        assert_eq!(map.get(&72), Some(&CloneCounted(72)));
    }

    #[test]
    fn get_or_insert_retain_and_clear_preserve_clone_isolation() {
        let mut map = StateMap::from_iter([(1, 10), (2, 20), (3, 30), (4, 40)]);
        let original = map.clone();
        let mut makes = 0;

        *map.get_or_insert_with_mut(2, || {
            makes += 1;
            200
        }) += 1;
        *map.get_or_insert_with_mut(5, || {
            makes += 1;
            50
        }) += 1;
        assert_eq!(makes, 1);
        assert_eq!(map.get(&2), Some(&21));
        assert_eq!(map.get(&5), Some(&51));
        assert_eq!(original.get(&2), Some(&20));
        assert!(original.get(&5).is_none());

        map.retain_mut(|key, value| {
            *value += *key;
            *key % 2 == 1
        });
        assert_eq!(
            map.iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            vec![(1, 11), (3, 33), (5, 56)]
        );
        assert_valid(&map);

        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(original.len(), 4);
        assert_valid(&map);
        assert_valid(&original);
    }

    #[test]
    fn state_set_matches_btree_set_and_iterates_canonically() {
        let mut expected = BTreeSet::new();
        let mut actual = StateSet::new();
        let mut seed = 0x243f_6a88_u64;

        for step in 0..4_000 {
            seed = seed
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_029_489_791);
            let key = ((seed >> 19) % 401) as i32 - 200;
            if seed & 1 == 0 {
                assert_eq!(actual.insert_mut(key), expected.insert(key));
            } else {
                assert_eq!(actual.remove_mut(&key), expected.remove(&key));
            }
            assert_eq!(actual.len(), expected.len());
            assert_eq!(actual.is_empty(), expected.is_empty());
            assert_eq!(actual.contains(&key), expected.contains(&key));
            assert_eq!(
                actual.iter().copied().collect::<Vec<_>>(),
                expected.iter().copied().collect::<Vec<_>>()
            );

            // Keep the loop's operation index live in the test's diagnostic
            // state without changing the set semantics.
            assert!(step < 4_000);
        }
    }

    #[test]
    fn state_set_clone_extend_and_from_iterator_are_isolated() {
        let mut set = StateSet::from_iter([3, 1, 2, 2]);
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(set.len(), 3);

        let original = set.clone();
        assert!(!set.insert_mut(2));
        assert!(set.insert_mut(4));
        assert!(set.remove_mut(&1));
        assert!(!set.remove_mut(&99));

        assert_eq!(original.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![2, 3, 4]);

        set.extend([5, 4, 6]);
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![2, 3, 4, 5, 6]);
        assert!(set.contains(&5));
        assert!(!set.contains(&1));
        assert_eq!(
            set.into_iter().copied().collect::<Vec<_>>(),
            vec![2, 3, 4, 5, 6]
        );
    }
}

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use axle_types::status::{ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_PATH, ZX_ERR_NOT_FOUND};
use axle_types::zx_status_t;

use crate::fd::{FdOps, OpenFlags};

/// Normalize one absolute namespace path.
///
/// The first round keeps the rules intentionally small:
/// - paths must be absolute
/// - repeated `/` collapses
/// - trailing `/` is removed except for `/`
/// - `.` and `..` are rejected for now
pub fn normalize_namespace_path(path: &str) -> Result<String, zx_status_t> {
    if !path.starts_with('/') {
        return Err(ZX_ERR_BAD_PATH);
    }

    let mut normalized = String::from("/");
    let mut first = true;
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if matches!(component, "." | "..") {
            return Err(ZX_ERR_BAD_PATH);
        }
        if !first {
            normalized.push('/');
        }
        normalized.push_str(component);
        first = false;
    }

    Ok(normalized)
}

/// One namespace mount entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceEntry<T> {
    path: String,
    target: T,
}

impl<T> NamespaceEntry<T> {
    /// Build one entry with a normalized absolute path.
    pub fn new(path: impl AsRef<str>, target: T) -> Result<Self, zx_status_t> {
        Ok(Self {
            path: normalize_namespace_path(path.as_ref())?,
            target,
        })
    }

    /// Normalized mount path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Borrow the mounted target.
    pub fn target(&self) -> &T {
        &self.target
    }

    /// Consume the entry and return the target.
    pub fn into_target(self) -> T {
        self.target
    }
}

/// Result of resolving a concrete path against a namespace trie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceMatch<'a, T> {
    entry: &'a NamespaceEntry<T>,
    relative_path: String,
}

impl<'a, T> NamespaceMatch<'a, T> {
    /// Mounted namespace entry selected by longest-prefix match.
    pub fn entry(&self) -> &'a NamespaceEntry<T> {
        self.entry
    }

    /// Relative path that remains after stripping the selected mount point.
    ///
    /// An exact match returns the empty string.
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

/// Client-owned namespace dispatch table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceTrie<T> {
    mounts: BTreeMap<String, NamespaceEntry<T>>,
}

impl<T> NamespaceTrie<T> {
    /// Build one empty namespace trie.
    pub const fn new() -> Self {
        Self {
            mounts: BTreeMap::new(),
        }
    }

    /// Return the number of mounted prefixes.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// Return `true` when the trie has no entries.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// Insert one mount point.
    pub fn insert(&mut self, path: impl AsRef<str>, target: T) -> Result<(), zx_status_t> {
        self.insert_entry(NamespaceEntry::new(path, target)?)
    }

    /// Insert one pre-built entry.
    pub fn insert_entry(&mut self, entry: NamespaceEntry<T>) -> Result<(), zx_status_t> {
        let key = entry.path.clone();
        if self.mounts.contains_key(&key) {
            return Err(ZX_ERR_ALREADY_EXISTS);
        }
        self.mounts.insert(key, entry);
        Ok(())
    }

    /// Return one exact mount entry.
    pub fn get(&self, path: &str) -> Result<Option<&NamespaceEntry<T>>, zx_status_t> {
        let normalized = normalize_namespace_path(path)?;
        Ok(self.mounts.get(&normalized))
    }

    /// Resolve `path` using longest-prefix mount selection.
    pub fn resolve(&self, path: &str) -> Result<NamespaceMatch<'_, T>, zx_status_t> {
        let normalized = normalize_namespace_path(path)?;
        let mut prefixes = candidate_prefixes(&normalized);
        while let Some(prefix) = prefixes.pop() {
            if let Some(entry) = self.mounts.get(prefix.as_str()) {
                return Ok(NamespaceMatch {
                    entry,
                    relative_path: strip_prefix(&normalized, prefix.as_str()).to_string(),
                });
            }
        }
        Err(ZX_ERR_NOT_FOUND)
    }

    /// Iterate over mounted entries in normalized path order.
    pub fn iter(&self) -> impl Iterator<Item = &NamespaceEntry<T>> {
        self.mounts.values()
    }

    /// Consume the trie and return the installed entries in normalized path order.
    pub fn into_entries(self) -> Vec<NamespaceEntry<T>> {
        self.mounts.into_values().collect()
    }
}

/// Open `path` through one client namespace using longest-prefix dispatch.
pub fn open_namespace_path(
    namespace: &NamespaceTrie<Arc<dyn FdOps>>,
    path: &str,
    flags: OpenFlags,
) -> Result<Arc<dyn FdOps>, zx_status_t> {
    let matched = namespace.resolve(path)?;
    if matched.relative_path().is_empty() {
        Ok(Arc::clone(matched.entry().target()))
    } else {
        matched
            .entry()
            .target()
            .openat(matched.relative_path(), flags)
    }
}

fn candidate_prefixes(path: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut current = String::from("/");
    prefixes.push(current.clone());
    if path == "/" {
        return prefixes;
    }
    current.clear();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        current.push('/');
        current.push_str(component);
        prefixes.push(current.clone());
    }
    prefixes
}

fn strip_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    if prefix == "/" {
        return path.strip_prefix('/').unwrap_or(path);
    }
    if path == prefix {
        return "";
    }
    path.strip_prefix(prefix)
        .and_then(|remainder| remainder.strip_prefix('/'))
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::{NamespaceEntry, NamespaceTrie, normalize_namespace_path, open_namespace_path};
    use crate::fd::{FdFlags, FdOps, OpenFlags, SeekOrigin, WaitSpec};
    use alloc::string::{String, ToString};
    use alloc::sync::Arc;
    use axle_types::status::{ZX_ERR_ALREADY_EXISTS, ZX_ERR_BAD_PATH, ZX_ERR_NOT_FOUND};
    use axle_types::zx_status_t;

    #[test]
    fn normalizes_absolute_paths() {
        assert_eq!(
            normalize_namespace_path("//svc///echo/").expect("path should normalize"),
            "/svc/echo"
        );
        assert_eq!(
            normalize_namespace_path("/").expect("root should normalize"),
            "/"
        );
    }

    #[test]
    fn rejects_relative_and_dot_paths() {
        assert_eq!(normalize_namespace_path("svc"), Err(ZX_ERR_BAD_PATH));
        assert_eq!(
            normalize_namespace_path("/svc/./echo"),
            Err(ZX_ERR_BAD_PATH)
        );
        assert_eq!(
            normalize_namespace_path("/svc/../echo"),
            Err(ZX_ERR_BAD_PATH)
        );
    }

    #[test]
    fn resolve_prefers_longest_prefix() {
        let mut trie = NamespaceTrie::new();
        trie.insert("/svc", 1u32).expect("insert /svc");
        trie.insert("/svc/echo", 2u32).expect("insert /svc/echo");

        let matched = trie
            .resolve("/svc/echo/client")
            .expect("match should resolve");
        assert_eq!(matched.entry().path(), "/svc/echo");
        assert_eq!(*matched.entry().target(), 2u32);
        assert_eq!(matched.relative_path(), "client");
    }

    #[test]
    fn resolve_returns_empty_relative_path_on_exact_mount_match() {
        let mut trie = NamespaceTrie::new();
        trie.insert("/", 1u32).expect("insert root");

        let matched = trie.resolve("/").expect("root should resolve");
        assert_eq!(matched.entry().path(), "/");
        assert_eq!(matched.relative_path(), "");
    }

    #[test]
    fn duplicate_mounts_are_rejected() {
        let mut trie = NamespaceTrie::new();
        trie.insert("/tmp", 1u32).expect("first insert");
        assert_eq!(trie.insert("/tmp/", 2u32), Err(ZX_ERR_ALREADY_EXISTS));
    }

    #[test]
    fn missing_mount_returns_not_found() {
        let trie = NamespaceTrie::<u32>::new();
        assert_eq!(trie.resolve("/data"), Err(ZX_ERR_NOT_FOUND));
    }

    #[test]
    fn entry_constructor_normalizes_paths() {
        let entry = NamespaceEntry::new("//pkg///bin/", 7u32).expect("entry should normalize");
        assert_eq!(entry.path(), "/pkg/bin");
        assert_eq!(*entry.target(), 7u32);
    }

    struct MockDir;

    impl FdOps for MockDir {
        fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
            unreachable!("directory read is not used in this test")
        }

        fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
            unreachable!("directory write is not used in this test")
        }

        fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
            unreachable!("directory seek is not used in this test")
        }

        fn close(&self) -> Result<(), zx_status_t> {
            Ok(())
        }

        fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
            Ok(Arc::new(Self))
        }

        fn wait_interest(&self) -> Option<WaitSpec> {
            None
        }

        fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
            Ok(Arc::new(MockFile(path.to_string())))
        }
    }

    struct MockFile(String);

    impl FdOps for MockFile {
        fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
            unreachable!("file read is not used in this test")
        }

        fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
            unreachable!("file write is not used in this test")
        }

        fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
            unreachable!("file seek is not used in this test")
        }

        fn close(&self) -> Result<(), zx_status_t> {
            Ok(())
        }

        fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
            Ok(Arc::new(Self(self.0.clone())))
        }

        fn wait_interest(&self) -> Option<WaitSpec> {
            None
        }
    }

    #[test]
    fn open_namespace_path_dispatches_to_mount_target() {
        let mut trie = NamespaceTrie::<Arc<dyn FdOps>>::new();
        trie.insert("/svc", Arc::new(MockDir)).expect("insert /svc");

        let opened = open_namespace_path(&trie, "/svc/nexus.echo.Echo", OpenFlags::READABLE)
            .expect("namespace open should succeed");
        let cloned = opened
            .clone_fd(FdFlags::empty())
            .expect("clone should preserve the opened target");
        assert!(cloned.wait_interest().is_none());
    }
}

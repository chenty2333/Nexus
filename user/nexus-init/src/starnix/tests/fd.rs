use super::super::fs::devfs::{NullFd, ZeroFd};
use super::super::fs::tty::{DevDirFd, PtyRegistry};
use super::super::*;
use super::support::RecordingFd;
use alloc::sync::Arc;
use nexus_io::{NamespaceTrie, ProcessNamespace};

#[test]
fn dup2_and_dup3_share_open_file_descriptions() {
    let stdout = RecordingFd::new();
    let mut kernel = super::support::test_kernel_with_stdio(stdout);
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");
    let source_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        )
        .expect("open source fd");
    let source_key = {
        let entry = resources.fs.fd_table.get(source_fd).expect("source entry");
        file_description_key(entry.description())
    };

    assert_eq!(resources.dup2(source_fd, 9).expect("dup2"), 9);
    let dup2_entry = resources.fs.fd_table.get(9).expect("dup2 entry");
    assert_eq!(file_description_key(dup2_entry.description()), source_key);
    assert_eq!(dup2_entry.flags(), FdFlags::empty());

    assert_eq!(
        resources
            .dup3(source_fd, 10, LINUX_O_CLOEXEC)
            .expect("dup3 cloexec"),
        10
    );
    let dup3_entry = resources.fs.fd_table.get(10).expect("dup3 entry");
    assert_eq!(file_description_key(dup3_entry.description()), source_key);
    assert_eq!(dup3_entry.flags(), FdFlags::CLOEXEC);
    assert_eq!(
        resources
            .fs
            .fd_table
            .get(source_fd)
            .expect("source after dup3")
            .flags(),
        FdFlags::empty()
    );
}

#[test]
fn fcntl_dupfd_variants_share_open_file_descriptions_and_apply_cloexec() {
    let stdout = RecordingFd::new();
    let mut kernel = super::support::test_kernel_with_stdio(stdout);
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");
    let source_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        )
        .expect("open source fd");
    let source_key = {
        let entry = resources.fs.fd_table.get(source_fd).expect("source entry");
        file_description_key(entry.description())
    };

    let dupfd = resources
        .fcntl(source_fd, LINUX_F_DUPFD, 8)
        .expect("f_dupfd") as i32;
    let dupfd_entry = resources.fs.fd_table.get(dupfd).expect("dupfd entry");
    assert_eq!(dupfd, 8);
    assert_eq!(file_description_key(dupfd_entry.description()), source_key);
    assert_eq!(dupfd_entry.flags(), FdFlags::empty());

    let dupfd_cloexec = resources
        .fcntl(source_fd, LINUX_F_DUPFD_CLOEXEC, 11)
        .expect("f_dupfd_cloexec") as i32;
    let cloexec_entry = resources
        .fs
        .fd_table
        .get(dupfd_cloexec)
        .expect("cloexec dupfd entry");
    assert_eq!(dupfd_cloexec, 11);
    assert_eq!(
        file_description_key(cloexec_entry.description()),
        source_key
    );
    assert_eq!(cloexec_entry.flags(), FdFlags::CLOEXEC);
}

#[test]
fn dup2_replaces_existing_target_description() {
    let stdout = RecordingFd::new();
    let mut kernel = super::support::test_kernel_with_stdio(stdout);
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");
    let source_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        )
        .expect("open source fd");
    let target_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::CLOEXEC,
        )
        .expect("open target fd");
    let source_key = {
        let entry = resources.fs.fd_table.get(source_fd).expect("source entry");
        file_description_key(entry.description())
    };
    let original_target_key = {
        let entry = resources.fs.fd_table.get(target_fd).expect("target entry");
        file_description_key(entry.description())
    };
    assert_ne!(source_key, original_target_key);

    assert_eq!(
        resources.dup2(source_fd, target_fd).expect("dup2 replace"),
        target_fd as u64
    );
    let target_entry = resources
        .fs
        .fd_table
        .get(target_fd)
        .expect("target after dup2");
    assert_eq!(file_description_key(target_entry.description()), source_key);
    assert_eq!(target_entry.flags(), FdFlags::empty());
}

#[test]
fn fs_context_fork_clone_preserves_namespace_offsets_and_file_descriptions() {
    let stdout = RecordingFd::new();
    let mut kernel = super::support::test_kernel_with_stdio(stdout);
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");
    let source_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE | OpenFlags::WRITABLE,
            FdFlags::empty(),
        )
        .expect("open source fd");
    resources.fs.directory_offsets.insert(11, 3);
    let source_key = {
        let entry = resources.fs.fd_table.get(source_fd).expect("source entry");
        file_description_key(entry.description())
    };
    let parent_cwd = resources.fs.namespace.cwd();

    let cloned = resources.fs.fork_clone();
    let cloned_entry = cloned.fd_table.get(source_fd).expect("fork-cloned source");
    assert_eq!(file_description_key(cloned_entry.description()), source_key);
    assert_eq!(cloned.directory_offsets.get(&11), Some(&3));
    assert_eq!(cloned.namespace.cwd(), parent_cwd);
}

#[test]
fn exec_fd_replace_drops_cloexec_entries_and_clears_offsets() {
    let stdout = RecordingFd::new();
    let mut kernel = super::support::test_kernel_with_stdio(stdout);
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");
    let cloexec_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE,
            FdFlags::CLOEXEC,
        )
        .expect("open cloexec fd");
    let kept_fd = resources
        .fs
        .fd_table
        .open(
            Arc::new(PseudoNodeFd::new(None)),
            OpenFlags::READABLE,
            FdFlags::empty(),
        )
        .expect("open kept fd");
    resources.fs.directory_offsets.insert(11, 3);

    let replaced = resources.fs.exec_replace();
    assert!(replaced.fd_table.get(cloexec_fd).is_none());
    assert!(replaced.fd_table.get(kept_fd).is_some());
    assert!(replaced.directory_offsets.is_empty());
}

#[test]
fn stat_metadata_for_dev_ptmx_is_side_effect_free() {
    let stdout = RecordingFd::new();
    let mut kernel = super::support::test_kernel_with_stdio(stdout);
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");

    let registry = Arc::new(PtyRegistry::new());
    let tty = registry.allocate_console_slave();
    let controlling_tty = Arc::new(Mutex::new(Some(tty)));
    let dev_root: Arc<dyn FdOps> = Arc::new(DevDirFd::new(
        controlling_tty,
        registry.clone(),
        Arc::new(NullFd),
        Arc::new(ZeroFd),
    ));
    let mut mounts = NamespaceTrie::new();
    mounts
        .insert("/dev", dev_root.clone())
        .expect("insert /dev");
    resources.fs.base_namespace = ProcessNamespace::new(mounts.clone());
    resources.fs.namespace = ProcessNamespace::new(mounts);

    let before = resources
        .fs
        .namespace
        .readdir("/dev/pts")
        .expect("readdir /dev/pts before")
        .len();
    let absolute = resources
        .stat_metadata_at_path(LINUX_AT_FDCWD, "/dev/ptmx", 0)
        .expect("stat /dev/ptmx");
    let after_absolute = resources
        .fs
        .namespace
        .readdir("/dev/pts")
        .expect("readdir /dev/pts after absolute stat")
        .len();
    assert_eq!(before, after_absolute);
    assert_eq!(absolute.mode & LINUX_S_IFMT, LINUX_S_IFCHR);

    let dev_fd = resources
        .fs
        .fd_table
        .open(
            dev_root,
            OpenFlags::READABLE | OpenFlags::DIRECTORY,
            FdFlags::empty(),
        )
        .expect("open /dev fd");
    let relative = resources
        .stat_metadata_at_path(dev_fd, "ptmx", 0)
        .expect("fstatat ptmx");
    let after_relative = resources
        .fs
        .namespace
        .readdir("/dev/pts")
        .expect("readdir /dev/pts after relative stat")
        .len();
    assert_eq!(before, after_relative);
    assert_eq!(relative.mode & LINUX_S_IFMT, LINUX_S_IFCHR);
}

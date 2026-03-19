use super::super::*;
use super::support::{RecordingFd, SyntheticWaitFd, test_kernel_with_stdio};
use alloc::sync::Arc;

#[test]
fn epoll_translates_synthetic_waitable_readiness() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let (description, target_key, wait_interest) = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let fd = resources
            .fs
            .fd_table
            .open(
                Arc::new(SyntheticWaitFd),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("open synthetic waitable");
        let entry = resources
            .fs
            .fd_table
            .get(fd)
            .expect("synthetic waitable entry");
        let description = Arc::clone(entry.description());
        let target_key = file_description_key(&description);
        let wait_interest = resources
            .fs
            .fd_table
            .wait_interest(fd)
            .expect("synthetic wait interest")
            .map(|interest| {
                super::super::poll::readiness::filter_epoll_wait_interest(interest, LINUX_EPOLLIN)
            });
        (description, target_key, wait_interest)
    };
    assert_eq!(
        wait_interest.expect("readable wait interest").signals(),
        EVENTFD_READABLE_SIGNAL
    );

    let epoll_key = LinuxFileDescriptionKey(0xface);
    let packet_key = Some(kernel.alloc_packet_key().expect("packet key"));
    if let Some(packet_key) = packet_key {
        kernel
            .epoll_packets
            .insert(packet_key, (epoll_key, target_key));
    }
    let mut instance = EpollInstance::new();
    instance.entries.insert(
        target_key,
        super::super::poll::epoll::EpollEntry::new(
            description,
            LINUX_EPOLLIN,
            0x1234,
            wait_interest,
            packet_key,
        ),
    );
    kernel.epolls.insert(epoll_key, instance);

    kernel.queue_epoll_ready(
        epoll_key,
        target_key,
        super::super::poll::readiness::map_wait_signals_to_epoll(EVENTFD_READABLE_SIGNAL),
    );
    let instance = kernel.epolls.get(&epoll_key).expect("epoll instance");
    assert!(instance.ready_set.contains(&target_key));
    assert_eq!(instance.ready_list.front(), Some(&target_key));
}

#[test]
fn epoll_level_triggered_entries_requeue_while_target_stays_ready() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let (description, target_key) = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let fd = resources
            .fs
            .fd_table
            .open(
                Arc::new(PseudoNodeFd::new(None)),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("open pseudo fd");
        let entry = resources.fs.fd_table.get(fd).expect("pseudo entry");
        (
            Arc::clone(entry.description()),
            file_description_key(entry.description()),
        )
    };
    let epoll_key = LinuxFileDescriptionKey(0xbeef);
    let mut instance = EpollInstance::new();
    instance.entries.insert(
        target_key,
        super::super::poll::epoll::EpollEntry::new(description, LINUX_EPOLLIN, 0xaaaa, None, None),
    );
    kernel.epolls.insert(epoll_key, instance);

    kernel.queue_epoll_ready(epoll_key, target_key, LINUX_EPOLLIN);
    let first = kernel
        .collect_epoll_events_for_test(epoll_key, 1)
        .expect("first epoll collect");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].events, LINUX_EPOLLIN);
    assert_eq!(first[0].data, 0xaaaa);

    let second = kernel
        .collect_epoll_events_for_test(epoll_key, 1)
        .expect("second epoll collect");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].events, LINUX_EPOLLIN);
    assert_eq!(second[0].data, 0xaaaa);
}

#[test]
fn epoll_oneshot_entries_disable_after_first_delivery() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let (description, target_key) = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let fd = resources
            .fs
            .fd_table
            .open(
                Arc::new(PseudoNodeFd::new(None)),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("open pseudo fd");
        let entry = resources.fs.fd_table.get(fd).expect("pseudo entry");
        (
            Arc::clone(entry.description()),
            file_description_key(entry.description()),
        )
    };
    let epoll_key = LinuxFileDescriptionKey(0xcafe);
    let mut instance = EpollInstance::new();
    instance.entries.insert(
        target_key,
        super::super::poll::epoll::EpollEntry::new(
            description,
            LINUX_EPOLLIN | LINUX_EPOLLONESHOT,
            0xbbbb,
            None,
            None,
        ),
    );
    kernel.epolls.insert(epoll_key, instance);

    kernel.queue_epoll_ready(epoll_key, target_key, LINUX_EPOLLIN);
    let first = kernel
        .collect_epoll_events_for_test(epoll_key, 1)
        .expect("oneshot epoll collect");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].events, LINUX_EPOLLIN);
    assert_eq!(first[0].data, 0xbbbb);
    assert_eq!(
        kernel.epoll_entry_disabled_for_test(epoll_key, target_key),
        Some(true)
    );

    let second = kernel
        .collect_epoll_events_for_test(epoll_key, 1)
        .expect("second oneshot epoll collect");
    assert!(second.is_empty());
}

use super::super::*;
use super::support::{RecordingFd, test_kernel_with_stdio};
use alloc::sync::Arc;

fn open_inet_socket(
    kernel: &mut StarnixKernel,
    open_flags: OpenFlags,
) -> (i32, InetSocketFd, LinuxFileDescriptionKey) {
    let resources = kernel
        .groups
        .get_mut(&1)
        .expect("root group")
        .resources
        .as_mut()
        .expect("root resources");
    let socket = InetSocketFd::new_stream();
    let fd = resources
        .fs
        .fd_table
        .open(Arc::new(socket.clone()), open_flags, FdFlags::empty())
        .expect("open inet socket");
    let key = {
        let entry = resources.fs.fd_table.get(fd).expect("inet entry");
        file_description_key(entry.description())
    };
    (fd, socket, key)
}

#[test]
fn loopback_listener_accepts_and_streams_bytes() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let (_listener_fd, listener, _) =
        open_inet_socket(&mut kernel, OpenFlags::READABLE | OpenFlags::WRITABLE);
    let (_client_fd, client, _) =
        open_inet_socket(&mut kernel, OpenFlags::READABLE | OpenFlags::WRITABLE);
    let listen_addr = LoopbackSocketAddr::loopback(4_242);

    listener
        .bind(&mut kernel.loopback_net, listen_addr)
        .expect("bind listener");
    listener
        .listen(&mut kernel.loopback_net, 4)
        .expect("listen");
    client
        .connect(&mut kernel.loopback_net, listen_addr)
        .expect("connect");

    let accepted = listener.accept().expect("accept");
    assert_eq!(accepted.getsockname().expect("accepted local"), listen_addr);
    assert_eq!(client.getpeername().expect("client peer"), listen_addr,);

    assert_eq!(client.write(b"ping").expect("client write"), 4);
    let mut server_buffer = [0u8; 8];
    let actual = accepted.read(&mut server_buffer).expect("accepted read");
    assert_eq!(&server_buffer[..actual], b"ping");

    assert_eq!(accepted.write(b"pong").expect("accepted write"), 4);
    let mut client_buffer = [0u8; 8];
    let actual = client.read(&mut client_buffer).expect("client read");
    assert_eq!(&client_buffer[..actual], b"pong");
}

#[test]
fn loopback_listener_readiness_maps_into_epoll() {
    let stdout = RecordingFd::new();
    let mut kernel = test_kernel_with_stdio(stdout);
    let (listener_fd, listener, listener_key) =
        open_inet_socket(&mut kernel, OpenFlags::READABLE | OpenFlags::WRITABLE);
    let (_client_fd, client, _) =
        open_inet_socket(&mut kernel, OpenFlags::READABLE | OpenFlags::WRITABLE);
    let listen_addr = LoopbackSocketAddr::loopback(4_243);

    listener
        .bind(&mut kernel.loopback_net, listen_addr)
        .expect("bind listener");
    listener
        .listen(&mut kernel.loopback_net, 4)
        .expect("listen");

    let (listener_desc, listener_wait_interest) = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let entry = resources
            .fs
            .fd_table
            .get(listener_fd)
            .expect("listener entry");
        (
            Arc::clone(entry.description()),
            resources
                .fs
                .fd_table
                .wait_interest(listener_fd)
                .expect("listener wait interest")
                .map(|interest| {
                    super::super::poll::readiness::filter_epoll_wait_interest(
                        interest,
                        LINUX_EPOLLIN,
                    )
                }),
        )
    };
    let epoll_key = LinuxFileDescriptionKey(0x5150);
    let mut instance = EpollInstance::new();
    instance.entries.insert(
        listener_key,
        super::super::poll::epoll::EpollEntry::new(
            listener_desc,
            LINUX_EPOLLIN,
            0x1111,
            listener_wait_interest,
            None,
        ),
    );
    kernel.epolls.insert(epoll_key, instance);

    client
        .connect(&mut kernel.loopback_net, listen_addr)
        .expect("connect");
    kernel.queue_epoll_ready(
        epoll_key,
        listener_key,
        super::super::poll::readiness::map_wait_signals_to_epoll(INET_READABLE_SIGNAL),
    );
    let events = kernel
        .collect_epoll_events_for_test(epoll_key, 1)
        .expect("collect listener epoll");
    assert_eq!(events.len(), 1);
    assert_ne!(events[0].events & LINUX_EPOLLIN, 0);
    assert_eq!(events[0].data, 0x1111);

    let accepted = listener.accept().expect("accept");
    let (accepted_fd, accepted_key) = {
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
                Arc::new(accepted.clone()),
                OpenFlags::READABLE | OpenFlags::WRITABLE,
                FdFlags::empty(),
            )
            .expect("install accepted");
        let key = {
            let entry = resources.fs.fd_table.get(fd).expect("accepted entry");
            file_description_key(entry.description())
        };
        (fd, key)
    };
    let (stream_desc, stream_wait_interest) = {
        let resources = kernel
            .groups
            .get_mut(&1)
            .expect("root group")
            .resources
            .as_mut()
            .expect("root resources");
        let entry = resources
            .fs
            .fd_table
            .get(accepted_fd)
            .expect("accepted entry");
        (
            Arc::clone(entry.description()),
            resources
                .fs
                .fd_table
                .wait_interest(accepted_fd)
                .expect("stream wait interest")
                .map(|interest| {
                    super::super::poll::readiness::filter_epoll_wait_interest(
                        interest,
                        LINUX_EPOLLIN,
                    )
                }),
        )
    };
    let stream_epoll_key = LinuxFileDescriptionKey(0x5151);
    let mut stream_instance = EpollInstance::new();
    stream_instance.entries.insert(
        accepted_key,
        super::super::poll::epoll::EpollEntry::new(
            stream_desc,
            LINUX_EPOLLIN,
            0x2222,
            stream_wait_interest,
            None,
        ),
    );
    kernel.epolls.insert(stream_epoll_key, stream_instance);

    client.write(b"x").expect("client write");
    kernel.queue_epoll_ready(
        stream_epoll_key,
        accepted_key,
        super::super::poll::readiness::map_wait_signals_to_epoll(INET_READABLE_SIGNAL),
    );
    let events = kernel
        .collect_epoll_events_for_test(stream_epoll_key, 1)
        .expect("collect stream epoll");
    assert_eq!(events.len(), 1);
    assert_ne!(events[0].events & LINUX_EPOLLIN, 0);
    assert_eq!(events[0].data, 0x2222);
}

#[test]
fn loopback_socket_stat_metadata_is_socket() {
    let socket = InetSocketFd::new_stream();
    let metadata = stat_metadata_for_ops(&socket).expect("inet socket stat");
    assert_eq!(metadata.mode & LINUX_S_IFMT, LINUX_S_IFSOCK);
}

#[test]
fn loopback_socket_option_roundtrips() {
    let socket = InetSocketFd::new_stream();
    let enabled = 1i32.to_ne_bytes();
    socket
        .setsockopt(LINUX_SOL_SOCKET, LINUX_SO_REUSEADDR, &enabled)
        .expect("set SO_REUSEADDR");
    socket
        .setsockopt(LINUX_IPPROTO_TCP, LINUX_TCP_NODELAY, &enabled)
        .expect("set TCP_NODELAY");

    assert_eq!(
        socket
            .getsockopt(LINUX_SOL_SOCKET, LINUX_SO_REUSEADDR)
            .expect("get SO_REUSEADDR"),
        1,
    );
    assert_eq!(
        socket
            .getsockopt(LINUX_IPPROTO_TCP, LINUX_TCP_NODELAY)
            .expect("get TCP_NODELAY"),
        1,
    );
    assert_eq!(
        socket
            .getsockopt(LINUX_SOL_SOCKET, LINUX_SO_TYPE)
            .expect("get SO_TYPE"),
        LINUX_SOCK_STREAM as i32,
    );
    assert_eq!(
        socket
            .getsockopt(LINUX_SOL_SOCKET, LINUX_SO_ERROR)
            .expect("get SO_ERROR"),
        0,
    );
}

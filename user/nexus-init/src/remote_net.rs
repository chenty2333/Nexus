use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering, fence};

use axle_arch_x86_64::{native_syscall8, rdtsc};
use axle_types::handle::ZX_HANDLE_INVALID;
use axle_types::signals::{
    ZX_CHANNEL_PEER_CLOSED, ZX_CHANNEL_READABLE, ZX_SOCKET_PEER_CLOSED, ZX_SOCKET_READABLE,
    ZX_TIMER_SIGNALED,
};
use axle_types::status::{
    ZX_ERR_BAD_HANDLE, ZX_ERR_BAD_STATE, ZX_ERR_INVALID_ARGS, ZX_ERR_IO, ZX_ERR_NOT_FOUND,
    ZX_ERR_NOT_SUPPORTED, ZX_ERR_SHOULD_WAIT, ZX_ERR_TIMED_OUT, ZX_OK,
};
use axle_types::syscall_numbers::AXLE_SYS_VMAR_MAP;
use axle_types::{zx_handle_t, zx_status_t};
use axle_virtio_transport::{
    QUEUE_SIZE as TRANSPORT_QUEUE_SIZE, VirtioNetHdr, VirtioPciDiscovery, VirtqAvail, VirtqDesc,
    VirtqUsed, discover_pci_transport,
};
use libax::compat::{ZX_TIME_INFINITE, zx_channel_read_alloc, zx_channel_write};
use libzircon::dma::{ZX_DMA_PERM_DEVICE_READ, ZX_DMA_PERM_DEVICE_WRITE, zx_dma_segment_info_t};
use libzircon::pci::{
    ZX_PCI_COMMAND_BUS_MASTER, ZX_PCI_COMMAND_MEMORY_SPACE, ZX_PCI_RESOURCE_KIND_BAR,
    ZX_PCI_RESOURCE_KIND_CONFIG, zx_pci_resource_info_t,
};
use libzircon::vm::{ZX_VM_PERM_READ, ZX_VM_PERM_WRITE};
use libzircon::{
    ax_dma_region_get_segment, ax_pci_device_get_resource, ax_pci_device_get_resource_count,
    ax_pci_device_set_command, ax_vmo_pin, zx_handle_close, zx_object_wait_one, zx_socket_read,
    zx_socket_write, zx_timer_create_monotonic, zx_timer_set, zx_vmo_create_contiguous,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use spin::Mutex;

use crate::{SLOT_ROOT_VMAR_H, lifecycle::poll_controller_event, read_slot};

const SLOT_REAL_NET_PCI_DEVICE_H: usize = 649;

const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

const LISTEN_PORT: u16 = 22;
const TCP_BUFFER_BYTES: usize = 16 * 1024;
const TTY_SCRATCH_BYTES: usize = 1024;
const SHELL_POLL_SLEEP_NS: u64 = 2_000_000;
const SHELL_OUTPUT_WAIT_NS: u64 = 100_000_000;
const VIRTIO_QUEUE_SIZE: u16 = TRANSPORT_QUEUE_SIZE as u16;
const VIRTIO_BUFFER_BYTES: usize = 2048;
const VIRTIO_HEADER_BYTES: usize = core::mem::size_of::<RealVirtioNetHdr>();
const VIRTIO_FRAME_BYTES: usize = VIRTIO_BUFFER_BYTES - VIRTIO_HEADER_BYTES;

const VIRTIO_NET_F_MAC: u64 = 5;
const VIRTIO_F_VERSION_1: u64 = 32;

const COMMON_DFSELECT: u64 = 0;
const COMMON_DF: u64 = 4;
const COMMON_GFSELECT: u64 = 8;
const COMMON_GF: u64 = 12;
const COMMON_STATUS: u64 = 20;
const COMMON_Q_SELECT: u64 = 22;
const COMMON_Q_SIZE: u64 = 24;
const COMMON_Q_ENABLE: u64 = 28;
const COMMON_Q_NOFF: u64 = 30;
const COMMON_Q_DESCLO: u64 = 32;
const COMMON_Q_AVAILLO: u64 = 40;
const COMMON_Q_USEDLO: u64 = 48;

const DEVICE_STATUS_ACKNOWLEDGE: u8 = 1 << 0;
const DEVICE_STATUS_DRIVER: u8 = 1 << 1;
const DEVICE_STATUS_FEATURES_OK: u8 = 1 << 3;
const DEVICE_STATUS_DRIVER_OK: u8 = 1 << 2;
const VIRTQ_DESC_F_WRITE: u16 = 2;

static RX_DEBUG_COUNT: AtomicU32 = AtomicU32::new(0);
static TX_DEBUG_COUNT: AtomicU32 = AtomicU32::new(0);
static TCP_ACTIVE_STATE: AtomicU32 = AtomicU32::new(0);
static TCP_LISTEN_LOGGED: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShellStdoutMode {
    Socket,
    Channel,
}

pub(crate) fn run_remote_shell(
    stdin: zx_handle_t,
    stdout: zx_handle_t,
    controller: zx_handle_t,
    stdout_mode: ShellStdoutMode,
) -> Result<Option<i64>, zx_status_t> {
    debug_console(b"remote-net: start\n");
    let mut poll_timer = ZX_HANDLE_INVALID;
    let timer_status = zx_timer_create_monotonic(0, &mut poll_timer);
    if timer_status != ZX_OK {
        return Err(timer_status);
    }
    let mut device = VirtioNetDevice::new(read_root_vmar()?, read_real_net_pci_handle()?)?;
    debug_console(b"remote-net: device-ready\n");
    device.emit_probe_frame()?;
    debug_console(b"remote-net: probe-tx\n");
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(GUEST_MAC)));
    config.random_seed = rdtsc();

    let mut iface = Interface::new(config, &mut device, monotonic_now());
    let mut cidr_status = ZX_OK;
    iface.update_ip_addrs(|addrs| {
        if addrs
            .push(IpCidr::new(
                IpAddress::v4(GUEST_IP[0], GUEST_IP[1], GUEST_IP[2], GUEST_IP[3]),
                24,
            ))
            .is_err()
        {
            cidr_status = ZX_ERR_BAD_STATE;
        }
    });
    if cidr_status != ZX_OK {
        return Err(cidr_status);
    }
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(
            GATEWAY_IP[0],
            GATEWAY_IP[1],
            GATEWAY_IP[2],
            GATEWAY_IP[3],
        ))
        .map_err(|_| ZX_ERR_BAD_STATE)?;

    let tcp_rx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
    let tcp_tx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
    let tcp_socket = tcp::Socket::new(tcp_rx, tcp_tx);
    let mut sockets = SocketSet::new(vec![]);
    let shell_socket = sockets.add(tcp_socket);

    let mut saw_session = false;
    let mut shell_peer_closed = false;
    let mut net_to_tty = VecDeque::<u8>::new();
    let mut tty_to_net = VecDeque::<u8>::new();

    if let Some(return_code) =
        wait_for_shell_ready(stdout, stdout_mode, &mut tty_to_net, &mut shell_peer_closed)?
    {
        let _ = zx_handle_close(poll_timer);
        return Ok(Some(return_code));
    }

    loop {
        let mut made_progress = false;
        match poll_controller_event(controller) {
            Ok(Some(code)) => {
                debug_console(b"remote-net: child-exit\n");
                let _ = zx_handle_close(poll_timer);
                return Ok(Some(code));
            }
            Ok(None) => {}
            Err(status) => {
                let _ = zx_handle_close(poll_timer);
                return Err(status);
            }
        }
        let now = monotonic_now();
        made_progress |=
            iface.poll(now, &mut device, &mut sockets) != smoltcp::iface::PollResult::None;

        {
            let socket = sockets.get_mut::<tcp::Socket>(shell_socket);
            if !socket.is_open() {
                socket.listen(LISTEN_PORT).map_err(|_| ZX_ERR_BAD_STATE)?;
                if TCP_LISTEN_LOGGED.swap(1, Ordering::Relaxed) == 0 {
                    debug_console(b"remote-net: tcp-listen\n");
                }
            }
            let active = socket.is_active();
            let active_value = u32::from(active);
            if TCP_ACTIVE_STATE.swap(active_value, Ordering::Relaxed) != active_value {
                if active {
                    debug_console(b"remote-net: tcp-active\n");
                } else {
                    debug_console(b"remote-net: tcp-inactive\n");
                }
            }
            if active {
                saw_session = true;
            }
            if socket.can_recv() {
                let mut scratch = [0u8; TTY_SCRATCH_BYTES];
                let actual = socket.recv_slice(&mut scratch).map_err(|_| ZX_ERR_IO)?;
                made_progress |= actual != 0;
                net_to_tty.extend(scratch[..actual].iter().copied());
            }
        }

        let flushed_shell_input =
            flush_to_shell(stdin, stdout_mode, &mut net_to_tty, &mut shell_peer_closed)?;
        made_progress |= flushed_shell_input;
        if flushed_shell_input {
            sleep_after_shell_input(poll_timer)?;
        }
        made_progress |=
            pump_shell_output(stdout, stdout_mode, &mut tty_to_net, &mut shell_peer_closed)?;

        {
            let socket = sockets.get_mut::<tcp::Socket>(shell_socket);
            if socket.can_send() && !tty_to_net.is_empty() {
                let mut burst = [0u8; TTY_SCRATCH_BYTES];
                let count = min(burst.len(), tty_to_net.len());
                for byte in &mut burst[..count] {
                    *byte = tty_to_net.pop_front().ok_or(ZX_ERR_BAD_STATE)?;
                }
                let sent = socket.send_slice(&burst[..count]).map_err(|_| ZX_ERR_IO)?;
                if sent != 0 {
                    made_progress = true;
                    log_shell_bytes(
                        b"remote-net: tcp-out ",
                        &burst[..sent.min(count)],
                        &TX_DEBUG_COUNT,
                    );
                }
                if sent < count {
                    for &byte in burst[sent..count].iter().rev() {
                        tty_to_net.push_front(byte);
                    }
                }
            }
            if shell_peer_closed && tty_to_net.is_empty() && socket.may_send() {
                socket.close();
            }
            if saw_session && !socket.is_active() && tty_to_net.is_empty() && net_to_tty.is_empty()
            {
                let _ = zx_handle_close(poll_timer);
                return Ok(None);
            }
        }

        if !made_progress {
            sleep_until_next_poll(poll_timer)?;
        }
    }
}

fn debug_console(bytes: &[u8]) {
    let _ = bytes;
}

fn wait_for_shell_ready(
    stdout: zx_handle_t,
    stdout_mode: ShellStdoutMode,
    tty_to_net: &mut VecDeque<u8>,
    shell_peer_closed: &mut bool,
) -> Result<Option<i64>, zx_status_t> {
    loop {
        pump_shell_output(stdout, stdout_mode, tty_to_net, shell_peer_closed)?;
        if !tty_to_net.is_empty() || *shell_peer_closed {
            return Ok(None);
        }
        let signals = match stdout_mode {
            ShellStdoutMode::Socket => ZX_SOCKET_READABLE | ZX_SOCKET_PEER_CLOSED,
            ShellStdoutMode::Channel => ZX_CHANNEL_READABLE | ZX_CHANNEL_PEER_CLOSED,
        };
        let mut observed = 0u32;
        let status = zx_object_wait_one(stdout, signals, ZX_TIME_INFINITE, &mut observed);
        if status != ZX_OK {
            return Err(status);
        }
    }
}

fn log_rx_packet(packet: &[u8]) {
    if RX_DEBUG_COUNT.fetch_add(1, Ordering::Relaxed) >= 24 {
        return;
    }
    if packet.len() < 14 {
        debug_console(b"remote-net: rx-short\n");
        return;
    }
    match (packet[12], packet[13]) {
        (0x08, 0x06) => debug_console(b"remote-net: rx-arp\n"),
        (0x08, 0x00) => {
            if packet.len() >= 24 && packet[23] == 6 {
                debug_console(b"remote-net: rx-ipv4-tcp\n");
            } else {
                debug_console(b"remote-net: rx-ipv4\n");
            }
        }
        (0x86, 0xdd) => debug_console(b"remote-net: rx-ipv6\n"),
        _ => {
            debug_console(b"remote-net: rx-other\n");
            log_packet_prefix(packet);
        }
    }
}

fn log_tx_packet(frame: &[u8]) {
    if TX_DEBUG_COUNT.fetch_add(1, Ordering::Relaxed) >= 24 {
        return;
    }
    if frame.len() < 14 {
        debug_console(b"remote-net: tx-short\n");
        return;
    }
    match (frame[12], frame[13]) {
        (0x08, 0x06) => debug_console(b"remote-net: tx-arp\n"),
        (0x08, 0x00) => {
            if frame.len() >= 24 && frame[23] == 6 {
                debug_console(b"remote-net: tx-ipv4-tcp\n");
            } else {
                debug_console(b"remote-net: tx-ipv4\n");
            }
        }
        _ => debug_console(b"remote-net: tx-other\n"),
    }
}

fn log_packet_prefix(packet: &[u8]) {
    let mut line = [0u8; 96];
    let mut out = 0usize;
    const PREFIX: &[u8] = b"remote-net: bytes";
    line[..PREFIX.len()].copy_from_slice(PREFIX);
    out += PREFIX.len();
    let count = min(packet.len(), 16);
    for &byte in &packet[..count] {
        if out + 3 >= line.len() {
            break;
        }
        line[out] = b' ';
        out += 1;
        line[out] = nybble_hex(byte >> 4);
        out += 1;
        line[out] = nybble_hex(byte & 0x0f);
        out += 1;
    }
    if out < line.len() {
        line[out] = b'\n';
        out += 1;
    }
    debug_console(&line[..out]);
}

const fn nybble_hex(value: u8) -> u8 {
    match value & 0x0f {
        0..=9 => b'0' + (value & 0x0f),
        _ => b'a' + ((value & 0x0f) - 10),
    }
}

fn log_shell_bytes(prefix: &[u8], bytes: &[u8], counter: &AtomicU32) {
    let _ = prefix;
    let _ = bytes;
    let _ = counter;
}

struct VirtioNetDevice {
    core: Arc<Mutex<VirtioNetCore>>,
    caps: DeviceCapabilities,
}

struct VirtioNetCore {
    common_base: u64,
    notify_base: u64,
    notify_multiplier: u32,
    queue_mem_base: u64,
    queue_iova: u64,
    queue_mem_handle: zx_handle_t,
    queue_dma_handle: zx_handle_t,
    config_handle: zx_handle_t,
    bar_handle: zx_handle_t,
    tx: VirtQueue,
    rx: VirtQueue,
    tx_free: VecDeque<u16>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RealVirtioNetHdr {
    hdr: VirtioNetHdr,
    num_buffers: u16,
}

#[derive(Clone, Copy)]
struct VirtQueue {
    index: u16,
    size: u16,
    notify_off: u16,
    desc_off: u64,
    avail_off: u64,
    used_off: u64,
    buffers_off: u64,
    last_used_idx: u16,
}

impl VirtioNetDevice {
    fn new(root_vmar: zx_handle_t, pci_device: zx_handle_t) -> Result<Self, zx_status_t> {
        let status = ax_pci_device_set_command(
            pci_device,
            ZX_PCI_COMMAND_MEMORY_SPACE | ZX_PCI_COMMAND_BUS_MASTER,
        );
        if status != ZX_OK {
            return Err(status);
        }
        let resources = collect_real_net_resources(pci_device)?;
        let config_base = map_vmo_local(
            root_vmar,
            resources.config_handle,
            resources.config_map_options | ZX_VM_PERM_READ,
            0,
            resources.config_size,
        )?;
        let discovery = discover_pci_config(config_base, resources.config_size)?;
        if discovery.common.bar != discovery.notify.bar
            || discovery.common.bar != discovery.device.bar
            || discovery.common.bar != discovery.isr.bar
        {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }

        let bar_base = map_vmo_local(
            root_vmar,
            resources.bar_handle,
            resources.bar_map_options | ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
            0,
            resources.bar_size,
        )?;

        let queue_size = discover_queue_size(bar_base + u64::from(discovery.common.offset))?;
        let queue_size = queue_size.clamp(1, VIRTIO_QUEUE_SIZE);
        let queue_layout = QueueLayout::new(queue_size);

        let mut queue_mem = ZX_HANDLE_INVALID;
        let queue_bytes = queue_layout.total_bytes;
        let status = zx_vmo_create_contiguous(queue_bytes, 0, &mut queue_mem);
        if status != ZX_OK {
            return Err(status);
        }
        let mut queue_dma = ZX_HANDLE_INVALID;
        let status = ax_vmo_pin(
            queue_mem,
            0,
            queue_bytes,
            ZX_DMA_PERM_DEVICE_READ | ZX_DMA_PERM_DEVICE_WRITE,
            &mut queue_dma,
        );
        if status != ZX_OK {
            let _ = zx_handle_close(queue_mem);
            return Err(status);
        }
        let mut segment = zx_dma_segment_info_t::default();
        let status = ax_dma_region_get_segment(queue_dma, 0, &mut segment);
        if status != ZX_OK || segment.iova_base == 0 {
            let _ = zx_handle_close(queue_dma);
            let _ = zx_handle_close(queue_mem);
            return Err(if status == ZX_OK {
                ZX_ERR_BAD_STATE
            } else {
                status
            });
        }
        let queue_mem_base = map_vmo_local(
            root_vmar,
            queue_mem,
            ZX_VM_PERM_READ | ZX_VM_PERM_WRITE,
            0,
            queue_bytes,
        )?;

        let mut core = VirtioNetCore {
            common_base: bar_base + u64::from(discovery.common.offset),
            notify_base: bar_base + u64::from(discovery.notify.offset),
            notify_multiplier: discovery.notify_multiplier,
            queue_mem_base,
            queue_iova: segment.iova_base,
            queue_mem_handle: queue_mem,
            queue_dma_handle: queue_dma,
            config_handle: resources.config_handle,
            bar_handle: resources.bar_handle,
            tx: queue_layout.tx_queue,
            rx: queue_layout.rx_queue,
            tx_free: VecDeque::new(),
        };
        for desc in 0..queue_size {
            core.tx_free.push_back(desc);
        }
        core.reset_device();
        core.negotiate_features()?;
        core.init_tx_ring();
        core.init_rx_ring();
        core.setup_queue(core.rx)?;
        core.setup_queue(core.tx)?;
        core.set_status(
            DEVICE_STATUS_ACKNOWLEDGE
                | DEVICE_STATUS_DRIVER
                | DEVICE_STATUS_FEATURES_OK
                | DEVICE_STATUS_DRIVER_OK,
        );

        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);
        caps.checksum.tcp = smoltcp::phy::Checksum::Both;
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Both;

        Ok(Self {
            core: Arc::new(Mutex::new(core)),
            caps,
        })
    }

    fn emit_probe_frame(&mut self) -> Result<(), zx_status_t> {
        let mut frame = [0u8; 60];
        frame[..6].fill(0xff);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        frame[14..24].copy_from_slice(b"axle-probe");
        self.core.lock().transmit_frame(&frame)
    }
}

impl Drop for VirtioNetCore {
    fn drop(&mut self) {
        let _ = zx_handle_close(self.queue_dma_handle);
        let _ = zx_handle_close(self.queue_mem_handle);
        let _ = zx_handle_close(self.config_handle);
        let _ = zx_handle_close(self.bar_handle);
    }
}

impl Device for VirtioNetDevice {
    type RxToken<'a>
        = VirtioNetRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtioNetTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = {
            let mut core = self.core.lock();
            core.reap_tx();
            core.poll_rx_packet()
        }?;
        Some((
            VirtioNetRxToken { packet },
            VirtioNetTxToken {
                core: Arc::clone(&self.core),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let mut core = self.core.lock();
        core.reap_tx();
        (!core.tx_free.is_empty()).then(|| VirtioNetTxToken {
            core: Arc::clone(&self.core),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

struct VirtioNetRxToken {
    packet: Vec<u8>,
}

struct VirtioNetTxToken {
    core: Arc<Mutex<VirtioNetCore>>,
}

impl RxToken for VirtioNetRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

impl TxToken for VirtioNetTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        if len != 0 {
            let _ = self.core.lock().transmit_frame(&frame);
        }
        result
    }
}

impl VirtioNetCore {
    fn reset_device(&mut self) {
        self.write_common_u8(COMMON_STATUS, 0);
    }

    fn negotiate_features(&mut self) -> Result<(), zx_status_t> {
        self.set_status(DEVICE_STATUS_ACKNOWLEDGE);
        self.set_status(DEVICE_STATUS_ACKNOWLEDGE | DEVICE_STATUS_DRIVER);

        let low = self.read_device_features(0);
        let high = self.read_device_features(1);
        let version_supported = (high & (1 << (VIRTIO_F_VERSION_1 - 32))) != 0;
        if !version_supported {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }

        let mut driver_low = 0u32;
        if (low & (1 << VIRTIO_NET_F_MAC)) != 0 {
            driver_low |= 1 << VIRTIO_NET_F_MAC;
        }
        let driver_high = 1u32 << (VIRTIO_F_VERSION_1 - 32);

        self.write_driver_features(0, driver_low);
        self.write_driver_features(1, driver_high);

        self.set_status(
            DEVICE_STATUS_ACKNOWLEDGE | DEVICE_STATUS_DRIVER | DEVICE_STATUS_FEATURES_OK,
        );
        let status = self.read_common_u8(COMMON_STATUS);
        if (status & DEVICE_STATUS_FEATURES_OK) == 0 {
            return Err(ZX_ERR_NOT_SUPPORTED);
        }
        Ok(())
    }

    fn init_tx_ring(&mut self) {
        self.zero_range(self.tx.desc_off, self.queue_bytes(self.tx));
    }

    fn init_rx_ring(&mut self) {
        self.zero_range(self.rx.desc_off, self.queue_bytes(self.rx));
        for desc in 0..self.rx.size {
            let addr = self.rx_buffer_iova(desc);
            self.write_desc(
                self.rx,
                desc,
                VirtqDesc {
                    addr,
                    len: VIRTIO_BUFFER_BYTES as u32,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                },
            );
            self.rx_post_desc(desc);
        }
        fence(Ordering::SeqCst);
        self.notify_queue(self.rx);
    }

    fn setup_queue(&mut self, queue: VirtQueue) -> Result<(), zx_status_t> {
        self.write_common_u16(COMMON_Q_SELECT, queue.index);
        let device_queue_size = self.read_common_u16(COMMON_Q_SIZE);
        if device_queue_size == 0 || queue.size > device_queue_size {
            return Err(ZX_ERR_BAD_STATE);
        }
        let notify_off = self.read_common_u16(COMMON_Q_NOFF);
        if notify_off != queue.notify_off {
            return Err(ZX_ERR_BAD_STATE);
        }
        self.write_common_u16(COMMON_Q_SIZE, queue.size);
        self.write_common_u64(COMMON_Q_DESCLO, self.queue_iova + queue.desc_off);
        self.write_common_u64(COMMON_Q_AVAILLO, self.queue_iova + queue.avail_off);
        self.write_common_u64(COMMON_Q_USEDLO, self.queue_iova + queue.used_off);
        self.write_common_u16(COMMON_Q_ENABLE, 1);
        fence(Ordering::SeqCst);
        Ok(())
    }

    fn poll_rx_packet(&mut self) -> Option<Vec<u8>> {
        let used = self.read_used(self.rx);
        if used.idx == self.rx.last_used_idx {
            return None;
        }
        let ring_index = usize::from(self.rx.last_used_idx % self.rx.size);
        let elem = used.ring[ring_index];
        self.rx.last_used_idx = self.rx.last_used_idx.wrapping_add(1);
        let desc = elem.id as u16;
        let packet_len = elem.len.saturating_sub(VIRTIO_HEADER_BYTES as u32) as usize;
        let packet_len = packet_len.min(VIRTIO_FRAME_BYTES);
        let mut packet = vec![0u8; packet_len];
        self.read_buffer(self.rx, desc, VIRTIO_HEADER_BYTES, &mut packet);
        self.rx_post_desc(desc);
        self.notify_queue(self.rx);
        log_rx_packet(&packet);
        Some(packet)
    }

    fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), zx_status_t> {
        log_tx_packet(frame);
        self.reap_tx();
        let Some(desc) = self.tx_free.pop_front() else {
            return Err(ZX_ERR_SHOULD_WAIT);
        };
        let padded_len = frame.len().max(60);
        let payload_len = padded_len.min(VIRTIO_FRAME_BYTES);
        self.write_buffer(self.tx, desc, 0, &RealVirtioNetHdr::default());
        self.write_payload(self.tx, desc, frame, payload_len);
        self.write_desc(
            self.tx,
            desc,
            VirtqDesc {
                addr: self.tx_buffer_iova(desc),
                len: (VIRTIO_HEADER_BYTES + payload_len) as u32,
                flags: 0,
                next: 0,
            },
        );
        self.tx_post_desc(desc);
        fence(Ordering::SeqCst);
        self.notify_queue(self.tx);
        Ok(())
    }

    fn reap_tx(&mut self) {
        let used = self.read_used(self.tx);
        while self.tx.last_used_idx != used.idx {
            let ring_index = usize::from(self.tx.last_used_idx % self.tx.size);
            let elem = used.ring[ring_index];
            self.tx.last_used_idx = self.tx.last_used_idx.wrapping_add(1);
            self.tx_free.push_back(elem.id as u16);
        }
    }

    fn tx_post_desc(&mut self, desc: u16) {
        self.post_desc(self.tx, desc);
    }

    fn rx_post_desc(&mut self, desc: u16) {
        self.post_desc(self.rx, desc);
    }

    fn post_desc(&mut self, queue: VirtQueue, desc: u16) {
        let mut avail = self.read_avail(queue);
        let slot = usize::from(avail.idx % queue.size);
        avail.ring[slot] = desc;
        fence(Ordering::SeqCst);
        avail.idx = avail.idx.wrapping_add(1);
        self.write_avail(queue, avail);
    }

    fn notify_queue(&self, queue: VirtQueue) {
        let offset = u64::from(queue.notify_off) * u64::from(self.notify_multiplier);
        self.mmio_write_u16(self.notify_base + offset, queue.index);
    }

    fn tx_buffer_iova(&self, desc: u16) -> u64 {
        self.queue_iova + self.tx.buffers_off + u64::from(desc) * VIRTIO_BUFFER_BYTES as u64
    }

    fn rx_buffer_iova(&self, desc: u16) -> u64 {
        self.queue_iova + self.rx.buffers_off + u64::from(desc) * VIRTIO_BUFFER_BYTES as u64
    }

    fn queue_bytes(&self, queue: VirtQueue) -> u64 {
        queue_end(queue) - queue.desc_off
    }

    fn zero_range(&self, offset: u64, len: u64) {
        for index in 0..len {
            self.mmio_write_u8(self.queue_mem_base + offset + index, 0);
        }
    }

    fn read_device_features(&self, selector: u32) -> u32 {
        self.write_common_u32(COMMON_DFSELECT, selector);
        self.read_common_u32(COMMON_DF)
    }

    fn write_driver_features(&self, selector: u32, features: u32) {
        self.write_common_u32(COMMON_GFSELECT, selector);
        self.write_common_u32(COMMON_GF, features);
    }

    fn set_status(&self, status: u8) {
        self.write_common_u8(COMMON_STATUS, status);
    }

    fn write_desc(&self, queue: VirtQueue, index: u16, desc: VirtqDesc) {
        let addr = self.queue_mem_base + queue.desc_off + u64::from(index) * 16;
        // SAFETY: descriptor tables live inside the queue VMO mapping and the driver is the sole writer.
        unsafe { ptr::write_volatile(addr as *mut VirtqDesc, desc) }
    }

    fn read_avail(&self, queue: VirtQueue) -> VirtqAvail {
        let addr = self.queue_mem_base + queue.avail_off;
        // SAFETY: avail rings live inside the queue VMO mapping and are valid for the full driver lifetime.
        unsafe { ptr::read_volatile(addr as *const VirtqAvail) }
    }

    fn write_avail(&self, queue: VirtQueue, avail: VirtqAvail) {
        let addr = self.queue_mem_base + queue.avail_off;
        // SAFETY: avail rings live inside the queue VMO mapping and the driver is the sole writer.
        unsafe { ptr::write_volatile(addr as *mut VirtqAvail, avail) }
    }

    fn read_used(&self, queue: VirtQueue) -> VirtqUsed {
        let addr = self.queue_mem_base + queue.used_off;
        // SAFETY: used rings live inside the queue VMO mapping and are written by the device.
        unsafe { ptr::read_volatile(addr as *const VirtqUsed) }
    }

    fn read_buffer(&self, queue: VirtQueue, desc: u16, skip: usize, out: &mut [u8]) {
        let base = self.queue_mem_base
            + queue.buffers_off
            + u64::from(desc) * VIRTIO_BUFFER_BYTES as u64
            + skip as u64;
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.mmio_read_u8(base + index as u64);
        }
    }

    fn write_payload(&self, queue: VirtQueue, desc: u16, payload: &[u8], padded_len: usize) {
        let base = self.queue_mem_base
            + queue.buffers_off
            + u64::from(desc) * VIRTIO_BUFFER_BYTES as u64
            + VIRTIO_HEADER_BYTES as u64;
        for index in 0..padded_len {
            let byte = payload.get(index).copied().unwrap_or(0);
            self.mmio_write_u8(base + index as u64, byte);
        }
    }

    fn write_buffer<T: Copy>(&self, queue: VirtQueue, desc: u16, offset: usize, value: &T) {
        let base = self.queue_mem_base
            + queue.buffers_off
            + u64::from(desc) * VIRTIO_BUFFER_BYTES as u64
            + offset as u64;
        // SAFETY: the destination lies within the mapped queue buffer slab owned by this driver.
        unsafe { ptr::write_volatile(base as *mut T, *value) }
    }

    fn read_common_u8(&self, offset: u64) -> u8 {
        self.mmio_read_u8(self.common_base + offset)
    }

    fn read_common_u16(&self, offset: u64) -> u16 {
        self.mmio_read_u16(self.common_base + offset)
    }

    fn read_common_u32(&self, offset: u64) -> u32 {
        self.mmio_read_u32(self.common_base + offset)
    }

    fn write_common_u8(&self, offset: u64, value: u8) {
        self.mmio_write_u8(self.common_base + offset, value);
    }

    fn write_common_u16(&self, offset: u64, value: u16) {
        self.mmio_write_u16(self.common_base + offset, value);
    }

    fn write_common_u32(&self, offset: u64, value: u32) {
        self.mmio_write_u32(self.common_base + offset, value);
    }

    fn write_common_u64(&self, lo_offset: u64, value: u64) {
        self.write_common_u32(lo_offset, value as u32);
        self.write_common_u32(lo_offset + 4, (value >> 32) as u32);
    }

    fn mmio_read_u8(&self, addr: u64) -> u8 {
        // SAFETY: callers only pass mapped MMIO or queue-buffer addresses that remain valid for the driver lifetime.
        unsafe { ptr::read_volatile(addr as *const u8) }
    }

    fn mmio_read_u16(&self, addr: u64) -> u16 {
        // SAFETY: callers only pass mapped MMIO addresses aligned as defined by the virtio-pci layout.
        unsafe { ptr::read_volatile(addr as *const u16) }
    }

    fn mmio_read_u32(&self, addr: u64) -> u32 {
        // SAFETY: callers only pass mapped MMIO addresses aligned as defined by the virtio-pci layout.
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    fn mmio_write_u8(&self, addr: u64, value: u8) {
        // SAFETY: callers only pass mapped MMIO or queue-buffer addresses owned by this driver.
        unsafe { ptr::write_volatile(addr as *mut u8, value) }
    }

    fn mmio_write_u16(&self, addr: u64, value: u16) {
        // SAFETY: callers only pass mapped MMIO addresses aligned as defined by the virtio-pci layout.
        unsafe { ptr::write_volatile(addr as *mut u16, value) }
    }

    fn mmio_write_u32(&self, addr: u64, value: u32) {
        // SAFETY: callers only pass mapped MMIO addresses aligned as defined by the virtio-pci layout.
        unsafe { ptr::write_volatile(addr as *mut u32, value) }
    }
}

struct QueueLayout {
    tx_queue: VirtQueue,
    rx_queue: VirtQueue,
    total_bytes: u64,
}

impl QueueLayout {
    fn new(queue_size: u16) -> Self {
        let rx_queue = layout_queue(0, 0, queue_size);
        let tx_queue = layout_queue(1, align_up(queue_end(rx_queue), 4096), queue_size);
        Self {
            tx_queue,
            rx_queue,
            total_bytes: align_up(queue_end(tx_queue), 4096),
        }
    }
}

fn layout_queue(index: u16, base: u64, size: u16) -> VirtQueue {
    let desc_off = align_up(base, 16);
    let avail_off = align_up(desc_off + desc_bytes(size), 2);
    let used_off = align_up(avail_off + avail_bytes(size), 4);
    let buffers_off = align_up(used_off + used_bytes(size), 16);
    VirtQueue {
        index,
        size,
        notify_off: index,
        desc_off,
        avail_off,
        used_off,
        buffers_off,
        last_used_idx: 0,
    }
}

fn queue_end(queue: VirtQueue) -> u64 {
    queue.buffers_off + u64::from(queue.size) * VIRTIO_BUFFER_BYTES as u64
}

const fn desc_bytes(size: u16) -> u64 {
    size as u64 * 16
}

const fn avail_bytes(size: u16) -> u64 {
    6 + size as u64 * 2 + 2
}

const fn used_bytes(size: u16) -> u64 {
    6 + size as u64 * 8 + 2
}

const fn align_up(value: u64, align: u64) -> u64 {
    let mask = align - 1;
    (value + mask) & !mask
}

struct RealNetResources {
    config_handle: zx_handle_t,
    config_size: u64,
    config_map_options: u32,
    bar_handle: zx_handle_t,
    bar_size: u64,
    bar_map_options: u32,
}

fn collect_real_net_resources(pci_device: zx_handle_t) -> Result<RealNetResources, zx_status_t> {
    let mut count = 0u64;
    let status = ax_pci_device_get_resource_count(pci_device, &mut count);
    if status != ZX_OK {
        return Err(status);
    }

    let mut config_handle = ZX_HANDLE_INVALID;
    let mut config_size = 0u64;
    let mut config_map_options = 0u32;
    let mut bar_handle = ZX_HANDLE_INVALID;
    let mut bar_size = 0u64;
    let mut bar_map_options = 0u32;

    for ordinal in 0..count {
        let mut info = zx_pci_resource_info_t::default();
        let status = ax_pci_device_get_resource(pci_device, ordinal as u32, &mut info);
        if status != ZX_OK {
            close_if_valid(config_handle);
            close_if_valid(bar_handle);
            return Err(status);
        }
        match info.kind {
            ZX_PCI_RESOURCE_KIND_CONFIG => {
                config_handle = info.handle;
                config_size = info.size;
                config_map_options = info.map_options;
            }
            ZX_PCI_RESOURCE_KIND_BAR if bar_handle == ZX_HANDLE_INVALID => {
                bar_handle = info.handle;
                bar_size = info.size;
                bar_map_options = info.map_options;
            }
            _ => {
                close_if_valid(info.handle);
            }
        }
    }

    if config_handle == ZX_HANDLE_INVALID || bar_handle == ZX_HANDLE_INVALID {
        close_if_valid(config_handle);
        close_if_valid(bar_handle);
        return Err(ZX_ERR_NOT_FOUND);
    }

    Ok(RealNetResources {
        config_handle,
        config_size,
        config_map_options,
        bar_handle,
        bar_size,
        bar_map_options,
    })
}

fn discover_pci_config(mapped_base: u64, size: u64) -> Result<VirtioPciDiscovery, zx_status_t> {
    if size == 0 || size > usize::MAX as u64 {
        return Err(ZX_ERR_INVALID_ARGS);
    }
    // SAFETY: the PCI config VMO remains mapped read-only for the lifetime of discovery.
    let bytes = unsafe { core::slice::from_raw_parts(mapped_base as *const u8, size as usize) };
    discover_pci_transport(bytes).ok_or(ZX_ERR_NOT_SUPPORTED)
}

fn discover_queue_size(common_base: u64) -> Result<u16, zx_status_t> {
    write_mmio_u16(common_base + COMMON_Q_SELECT, 0);
    let size = read_mmio_u16(common_base + COMMON_Q_SIZE);
    if size == 0 {
        return Err(ZX_ERR_BAD_STATE);
    }
    Ok(size)
}

fn read_root_vmar() -> Result<zx_handle_t, zx_status_t> {
    let handle = read_slot(SLOT_ROOT_VMAR_H) as zx_handle_t;
    if handle == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_BAD_HANDLE);
    }
    Ok(handle)
}

fn read_real_net_pci_handle() -> Result<zx_handle_t, zx_status_t> {
    let handle = read_slot(SLOT_REAL_NET_PCI_DEVICE_H) as zx_handle_t;
    if handle == ZX_HANDLE_INVALID {
        return Err(ZX_ERR_NOT_FOUND);
    }
    Ok(handle)
}

fn map_vmo_local(
    vmar: zx_handle_t,
    vmo: zx_handle_t,
    options: u32,
    vmo_offset: u64,
    len: u64,
) -> Result<u64, zx_status_t> {
    let mut mapped = 0u64;
    let status = native_syscall8(
        AXLE_SYS_VMAR_MAP as u64,
        [
            vmar,
            options as u64,
            0,
            vmo,
            vmo_offset,
            len,
            (&mut mapped as *mut u64) as u64,
            0,
        ],
    ) as zx_status_t;
    if status != ZX_OK {
        return Err(status);
    }
    Ok(mapped)
}

fn pump_shell_output(
    stdout: zx_handle_t,
    stdout_mode: ShellStdoutMode,
    pending: &mut VecDeque<u8>,
    peer_closed: &mut bool,
) -> Result<bool, zx_status_t> {
    if *peer_closed {
        return Ok(false);
    }
    let mut made_progress = false;
    match stdout_mode {
        ShellStdoutMode::Socket => {
            let mut scratch = [0u8; TTY_SCRATCH_BYTES];
            loop {
                let mut actual = 0usize;
                let status =
                    zx_socket_read(stdout, 0, scratch.as_mut_ptr(), scratch.len(), &mut actual);
                if status == ZX_OK {
                    made_progress |= actual != 0;
                    log_shell_bytes(
                        b"remote-net: shell-out ",
                        &scratch[..actual],
                        &RX_DEBUG_COUNT,
                    );
                    pending.extend(scratch[..actual].iter().copied());
                    continue;
                }
                if status == ZX_ERR_SHOULD_WAIT {
                    return Ok(made_progress);
                }
                if status == axle_types::status::ZX_ERR_PEER_CLOSED {
                    *peer_closed = true;
                    return Ok(made_progress);
                }
                return Err(status);
            }
        }
        ShellStdoutMode::Channel => loop {
            match zx_channel_read_alloc(stdout, 0) {
                Ok((bytes, handles)) => {
                    made_progress |= !bytes.is_empty();
                    for handle in handles {
                        let _ = zx_handle_close(handle);
                    }
                    log_shell_bytes(b"remote-net: shell-out ", &bytes, &RX_DEBUG_COUNT);
                    pending.extend(bytes.iter().copied());
                }
                Err(ZX_ERR_SHOULD_WAIT) => return Ok(made_progress),
                Err(axle_types::status::ZX_ERR_PEER_CLOSED) => {
                    *peer_closed = true;
                    return Ok(made_progress);
                }
                Err(status) => return Err(status),
            }
        },
    }
}

fn flush_to_shell(
    stdin: zx_handle_t,
    stdout_mode: ShellStdoutMode,
    pending: &mut VecDeque<u8>,
    peer_closed: &mut bool,
) -> Result<bool, zx_status_t> {
    if pending.is_empty() || *peer_closed {
        return Ok(false);
    }
    let mut made_progress = false;
    let mut burst = [0u8; TTY_SCRATCH_BYTES];
    while !pending.is_empty() {
        let count = min(burst.len(), pending.len());
        for byte in &mut burst[..count] {
            *byte = pending.pop_front().ok_or(ZX_ERR_BAD_STATE)?;
        }
        let (status, actual) = match stdout_mode {
            ShellStdoutMode::Socket => {
                let mut actual = 0usize;
                let status = zx_socket_write(stdin, 0, burst.as_ptr(), count, &mut actual);
                (status, actual)
            }
            ShellStdoutMode::Channel => {
                let status =
                    zx_channel_write(stdin, 0, burst.as_ptr(), count as u32, core::ptr::null(), 0);
                (status, usize::from(status == ZX_OK) * count)
            }
        };
        if status == ZX_OK {
            made_progress |= actual != 0;
            log_shell_bytes(
                b"remote-net: shell-in  ",
                &burst[..actual.min(count)],
                &TX_DEBUG_COUNT,
            );
            if actual < count {
                for &byte in burst[actual..count].iter().rev() {
                    pending.push_front(byte);
                }
                return Ok(made_progress);
            }
            continue;
        }
        if status == ZX_ERR_SHOULD_WAIT {
            for &byte in burst[..count].iter().rev() {
                pending.push_front(byte);
            }
            return Ok(made_progress);
        }
        if status == axle_types::status::ZX_ERR_PEER_CLOSED {
            *peer_closed = true;
            for &byte in burst[..count].iter().rev() {
                pending.push_front(byte);
            }
            return Ok(made_progress);
        }
        return Err(status);
    }
    Ok(made_progress)
}

fn sleep_until_next_poll(timer_handle: zx_handle_t) -> Result<(), zx_status_t> {
    let deadline = rdtsc()
        .saturating_add(SHELL_POLL_SLEEP_NS)
        .min(i64::MAX as u64) as i64;
    let status = zx_timer_set(timer_handle, deadline, 0);
    if status != ZX_OK {
        return Err(status);
    }
    let mut observed = 0u32;
    let status = zx_object_wait_one(
        timer_handle,
        ZX_TIMER_SIGNALED,
        ZX_TIME_INFINITE,
        &mut observed,
    );
    if status != ZX_OK {
        return Err(status);
    }
    Ok(())
}

fn sleep_after_shell_input(timer_handle: zx_handle_t) -> Result<(), zx_status_t> {
    let deadline = rdtsc()
        .saturating_add(SHELL_OUTPUT_WAIT_NS)
        .min(i64::MAX as u64) as i64;
    let status = zx_timer_set(timer_handle, deadline, 0);
    if status != ZX_OK {
        return Err(status);
    }
    let mut observed = 0u32;
    let status = zx_object_wait_one(
        timer_handle,
        ZX_TIMER_SIGNALED,
        ZX_TIME_INFINITE,
        &mut observed,
    );
    if status == ZX_OK || status == ZX_ERR_TIMED_OUT {
        return Ok(());
    }
    Err(status)
}

fn monotonic_now() -> Instant {
    Instant::from_micros((rdtsc() / 1000) as i64)
}

fn close_if_valid(handle: zx_handle_t) {
    if handle != ZX_HANDLE_INVALID {
        let _ = zx_handle_close(handle);
    }
}

fn read_mmio_u16(addr: u64) -> u16 {
    // SAFETY: callers only pass mapped MMIO addresses aligned for `u16`.
    unsafe { ptr::read_volatile(addr as *const u16) }
}

fn write_mmio_u16(addr: u64, value: u16) {
    // SAFETY: callers only pass mapped MMIO addresses aligned for `u16`.
    unsafe { ptr::write_volatile(addr as *mut u16, value) }
}

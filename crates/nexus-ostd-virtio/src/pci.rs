// SPDX-License-Identifier: MPL-2.0

//! Private PCI configuration, BAR-ownership, and MMIO-claim substrate.

use alloc::sync::Arc;
use core::{fmt, ptr::NonNull};

use ostd::{
    arch::device::io_port::ReadWriteAccess,
    io::{IoMem, IoPort},
    sync::SpinLock,
};
use virtio_drivers::{
    PhysAddr,
    transport::{
        DeviceType,
        pci::{
            bus::{BarInfo, Command, ConfigurationAccess, DeviceFunction, PciRoot},
            virtio_device_type,
        },
    },
};

const CONFIG_ADDRESS: u16 = 0x0cf8;
const CONFIG_DATA: u16 = 0x0cfc;
const EXPECTED_DEVICE: DeviceFunction = DeviceFunction {
    bus: 0,
    device: 5,
    function: 0,
};
const MODERN_VIRTIO_BLOCK_DEVICE_ID: u16 = 0x1042;

struct ConfigPorts {
    address: IoPort<u32, ReadWriteAccess>,
    data: IoPort<u32, ReadWriteAccess>,
}

/// Serialized PCI configuration mechanism #1 access.
#[derive(Clone)]
pub(crate) struct PioConfigurationAccess {
    ports: Arc<SpinLock<ConfigPorts>>,
}

impl PioConfigurationAccess {
    fn acquire() -> Self {
        let address = IoPort::acquire(CONFIG_ADDRESS).expect("acquire PCI CONFIG_ADDRESS");
        let data = IoPort::acquire(CONFIG_DATA).expect("acquire PCI CONFIG_DATA");
        Self {
            ports: Arc::new(SpinLock::new(ConfigPorts { address, data })),
        }
    }
}

fn config_address(device_function: DeviceFunction, register_offset: u8) -> u32 {
    assert!(device_function.valid());
    assert_eq!(
        register_offset & 0x03,
        0,
        "PCI config access is word aligned"
    );

    0x8000_0000
        | (u32::from(device_function.bus) << 16)
        | (u32::from(device_function.device) << 11)
        | (u32::from(device_function.function) << 8)
        | u32::from(register_offset)
}

impl ConfigurationAccess for PioConfigurationAccess {
    fn read_word(&self, device_function: DeviceFunction, register_offset: u8) -> u32 {
        let ports = self.ports.lock();
        ports
            .address
            .write(config_address(device_function, register_offset));
        ports.data.read()
    }

    fn write_word(&mut self, device_function: DeviceFunction, register_offset: u8, data: u32) {
        let ports = self.ports.lock();
        ports
            .address
            .write(config_address(device_function, register_offset));
        ports.data.write(data);
    }

    unsafe fn unsafe_clone(&self) -> Self {
        Self {
            ports: self.ports.clone(),
        }
    }
}

pub(crate) type RawRoot = PciRoot<PioConfigurationAccess>;

/// Copyable descriptive identity, never an ownership or MMIO capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceBdf {
    bus: u8,
    device: u8,
    function: u8,
}

impl DeviceBdf {
    /// Constructs descriptive PCI coordinates without claiming hardware.
    pub const fn from_coordinates(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    pub const fn bus(self) -> u8 {
        self.bus
    }

    pub const fn device(self) -> u8 {
        self.device
    }

    pub const fn function(self) -> u8 {
        self.function
    }
}

impl From<DeviceFunction> for DeviceBdf {
    fn from(value: DeviceFunction) -> Self {
        Self {
            bus: value.bus,
            device: value.device,
            function: value.function,
        }
    }
}

impl fmt::Display for DeviceBdf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}.{}",
            self.bus, self.device, self.function
        )
    }
}

/// Opaque, non-copyable owner of the PCI configuration root and the one
/// discovered VirtIO block function.
///
/// The raw `PciRoot<PioConfigurationAccess>` is deliberately private: callers
/// can neither clone the configuration accessor nor manufacture an MMIO
/// capability outside the facade lifecycle.
pub struct Root {
    inner: RawRoot,
    device_function: DeviceFunction,
    memory_bars: usize,
    portal_claimed: bool,
}

impl Root {
    pub const fn device_bdf(&self) -> DeviceBdf {
        DeviceBdf {
            bus: self.device_function.bus,
            device: self.device_function.device,
            function: self.device_function.function,
        }
    }

    pub const fn memory_bar_count(&self) -> usize {
        self.memory_bars
    }

    pub(crate) const fn device_function(&self) -> DeviceFunction {
        self.device_function
    }

    pub(crate) fn claim_device_function(&mut self) -> DeviceFunction {
        assert!(!self.portal_claimed, "PCI device portal claimed twice");
        self.portal_claimed = true;
        self.device_function
    }

    pub(crate) fn raw_mut(&mut self) -> &mut RawRoot {
        &mut self.inner
    }

    fn assert_device(&self, device_function: DeviceFunction) {
        assert_eq!(
            self.device_function, device_function,
            "foreign PCI root owner"
        );
    }
}

struct BarOwner {
    start: usize,
    end: usize,
    io_mem: IoMem,
}

struct BarRegistry {
    owners: [Option<BarOwner>; 6],
    installed: bool,
    transport_claims_active: bool,
    claims: [Option<MmioClaim>; 4],
}

#[derive(Clone, Copy)]
struct MmioClaim {
    start: usize,
    end: usize,
}

impl BarRegistry {
    const fn new() -> Self {
        Self {
            owners: [const { None }; 6],
            installed: false,
            transport_claims_active: false,
            claims: [const { None }; 4],
        }
    }
}

pub fn begin_transport_claims() {
    let mut registry = BAR_REGISTRY.lock();
    assert!(registry.installed);
    assert!(!registry.transport_claims_active);
    assert!(registry.claims.iter().all(Option::is_none));
    registry.transport_claims_active = true;
}

/// Releases the raw capability subranges claimed by one destroyed transport.
///
/// # Safety
///
/// Every `PciTransport` and raw MMIO pointer for the transport generation must
/// already have been destroyed. A quarantined live transport must retain its
/// claims so a replacement cannot alias its capability mappings.
pub(crate) unsafe fn release_transport_claims() {
    let mut registry = BAR_REGISTRY.lock();
    assert!(registry.transport_claims_active);
    registry.claims.fill(None);
    registry.transport_claims_active = false;
}

static BAR_REGISTRY: SpinLock<BarRegistry> = SpinLock::new(BarRegistry::new());

/// Discovers exactly one modern VirtIO block device on bus 0 and installs one
/// owner for each of its memory BARs before raw capability pointers are made.
pub fn discover_and_own_bars() -> Root {
    let mut root = RawRoot::new(PioConfigurationAccess::acquire());
    let mut found = None;

    for (device_function, info) in root.enumerate_bus(0) {
        if virtio_device_type(&info) == Some(DeviceType::Block) {
            assert!(found.is_none(), "expected one VirtIO block device");
            found = Some((device_function, info));
        }
    }

    let (device_function, info) = found.expect("missing VirtIO block device");
    assert_eq!(
        device_function, EXPECTED_DEVICE,
        "unexpected block-device BDF"
    );
    assert_eq!(info.vendor_id, 0x1af4, "unexpected VirtIO vendor");
    assert_eq!(
        info.device_id, MODERN_VIRTIO_BLOCK_DEVICE_ID,
        "legacy or non-block VirtIO device"
    );

    let bars = root.bars(device_function).expect("read VirtIO PCI BARs");
    let mut registry = BAR_REGISTRY.lock();
    assert!(!registry.installed, "BAR owners installed twice");
    let mut memory_bars = 0;

    for (index, bar) in bars.into_iter().enumerate() {
        let Some(BarInfo::Memory { address, size, .. }) = bar else {
            continue;
        };
        assert_ne!(address, 0, "VirtIO BAR is not allocated");
        assert_ne!(size, 0, "VirtIO BAR has zero size");
        let start = usize::try_from(address).expect("BAR address fits usize");
        let length = usize::try_from(size).expect("BAR size fits usize");
        let end = start.checked_add(length).expect("BAR range overflow");
        let io_mem = IoMem::acquire(start..end).expect("acquire unique VirtIO BAR owner");
        registry.owners[index] = Some(BarOwner { start, end, io_mem });
        memory_bars += 1;
    }

    assert_ne!(memory_bars, 0, "VirtIO device has no memory BAR");
    registry.installed = true;
    drop(registry);
    Root {
        inner: root,
        device_function,
        memory_bars,
        portal_claimed: false,
    }
}

pub(crate) fn enable_device_for_prepare(
    root: &mut Root,
    device_function: DeviceFunction,
) -> Command {
    root.assert_device(device_function);
    let (_, command) = root.inner.get_status_command(device_function);
    root.inner.set_command(
        device_function,
        command | Command::MEMORY_SPACE | Command::BUS_MASTER | Command::INTERRUPT_DISABLE,
    );
    command
}

pub(crate) fn enable_device(root: &mut Root, device_function: DeviceFunction) {
    let _ = enable_device_for_prepare(root, device_function);
}

pub(crate) fn restore_device_command(
    root: &mut Root,
    device_function: DeviceFunction,
    command: Command,
) {
    root.assert_device(device_function);
    root.inner.set_command(device_function, command);
    let (_, observed) = root.inner.get_status_command(device_function);
    assert_eq!(observed, command);
}

pub(crate) fn disable_bus_master(root: &mut Root, device_function: DeviceFunction) {
    root.assert_device(device_function);
    let (_, command) = root.inner.get_status_command(device_function);
    root.inner.set_command(
        device_function,
        (command & !Command::BUS_MASTER) | Command::INTERRUPT_DISABLE,
    );
    let (_, observed) = root.inner.get_status_command(device_function);
    assert!(!observed.contains(Command::BUS_MASTER));
    assert!(observed.contains(Command::INTERRUPT_DISABLE));
}

/// Returns a BAR-subrange pointer while the registry retains the unique
/// `IoMem` owner. The VirtIO HAL is the only caller and never accesses the
/// same range through `IoMem` while a transport exists.
pub(crate) unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
    let start = usize::try_from(paddr).expect("MMIO address fits usize");
    let end = start.checked_add(size).expect("MMIO range overflow");
    let mut registry = BAR_REGISTRY.lock();
    assert!(
        registry.transport_claims_active,
        "MMIO pointer requested outside a retained transport lifecycle"
    );

    for claim in registry.claims.iter().flatten() {
        assert!(
            end <= claim.start || claim.end <= start,
            "overlapping VirtIO MMIO capability claims"
        );
    }
    let claim_slot = registry
        .claims
        .iter_mut()
        .find(|claim| claim.is_none())
        .expect("unexpected number of VirtIO MMIO capability ranges");
    *claim_slot = Some(MmioClaim { start, end });

    for owner in registry.owners.iter().flatten() {
        if owner.start <= start && end <= owner.end {
            // SAFETY: `owner` remains installed for the lifetime of every PCI
            // transport. The caller upholds the no-alias MMIO access contract.
            let base = unsafe { owner.io_mem.as_non_null_ptr() };
            let offset = start - owner.start;
            // SAFETY: containment above proves `offset..offset + size` lies in
            // the owner-bound MMIO mapping.
            return unsafe { NonNull::new_unchecked(base.as_ptr().add(offset)) };
        }
    }

    panic!("VirtIO requested MMIO outside retained BAR owners");
}

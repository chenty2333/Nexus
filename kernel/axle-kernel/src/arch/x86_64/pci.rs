//! Minimal x86 PCI config-space helpers for bootstrap device discovery.

use spin::Mutex;
use x86_64::instructions::port::Port;

const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;
const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;

/// Global lock protecting the 0xCF8/0xCFC port pair. The PCI config-space
/// address/data mechanism is a shared global resource; concurrent access from
/// multiple CPUs would interleave address writes with data reads.
static PCI_CONFIG_LOCK: Mutex<()> = Mutex::new(());
const PCI_INVALID_VENDOR_ID: u16 = 0xFFFF;
const PCI_VENDOR_ID_OFF: u16 = 0x00;
const PCI_DEVICE_ID_OFF: u16 = 0x02;
const PCI_PROG_IF_OFF: u16 = 0x09;
const PCI_SUBCLASS_OFF: u16 = 0x0A;
const PCI_CLASS_CODE_OFF: u16 = 0x0B;
const PCI_HEADER_TYPE_OFF: u16 = 0x0E;
const PCI_BAR0_OFF: u16 = 0x10;
const PCI_INTERRUPT_LINE_OFF: u16 = 0x3C;
const PCI_INTERRUPT_PIN_OFF: u16 = 0x3D;
const PCI_HEADER_TYPE_MULTI_FUNCTION: u8 = 1 << 7;
const PCI_BAR_COUNT: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PciFunctionLocation {
    pub(crate) bus: u8,
    pub(crate) device: u8,
    pub(crate) function: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PciFunctionInfo {
    pub(crate) location: PciFunctionLocation,
    pub(crate) vendor_id: u16,
    pub(crate) device_id: u16,
    pub(crate) prog_if: u8,
    pub(crate) subclass: u8,
    pub(crate) class_code: u8,
    pub(crate) interrupt_line: u8,
    pub(crate) interrupt_pin: u8,
    pub(crate) bars: [u32; PCI_BAR_COUNT],
    pub(crate) config_space: [u8; 256],
}

pub(crate) fn find_first_network_function() -> Option<PciFunctionInfo> {
    for device in 0..32u8 {
        let header = read_config_u8(0, device, 0, PCI_HEADER_TYPE_OFF)?;
        let function_count = if (header & PCI_HEADER_TYPE_MULTI_FUNCTION) != 0 {
            8
        } else {
            1
        };
        for function in 0..function_count {
            let vendor_id = read_config_u16(0, device, function, PCI_VENDOR_ID_OFF)?;
            if vendor_id == PCI_INVALID_VENDOR_ID {
                continue;
            }
            let class_code = read_config_u8(0, device, function, PCI_CLASS_CODE_OFF)?;
            let subclass = read_config_u8(0, device, function, PCI_SUBCLASS_OFF)?;
            if class_code != 0x02 {
                continue;
            }
            let mut config_space = [0u8; 256];
            for dword_index in 0..(config_space.len() / 4) {
                let value = read_config_u32(0, device, function, (dword_index * 4) as u16)?;
                config_space[dword_index * 4..dword_index * 4 + 4]
                    .copy_from_slice(&value.to_le_bytes());
            }
            let mut bars = [0u32; PCI_BAR_COUNT];
            for (bar_index, slot) in bars.iter_mut().enumerate() {
                *slot =
                    read_config_u32(0, device, function, PCI_BAR0_OFF + (bar_index as u16 * 4))?;
            }
            return Some(PciFunctionInfo {
                location: PciFunctionLocation {
                    bus: 0,
                    device,
                    function,
                },
                vendor_id,
                device_id: read_config_u16(0, device, function, PCI_DEVICE_ID_OFF)?,
                prog_if: read_config_u8(0, device, function, PCI_PROG_IF_OFF)?,
                subclass,
                class_code,
                interrupt_line: read_config_u8(0, device, function, PCI_INTERRUPT_LINE_OFF)?,
                interrupt_pin: read_config_u8(0, device, function, PCI_INTERRUPT_PIN_OFF)?,
                bars,
                config_space,
            });
        }
    }
    None
}

fn read_config_u8(bus: u8, device: u8, function: u8, offset: u16) -> Option<u8> {
    let aligned = offset & !0x3;
    let shift = u32::from((offset & 0x3) * 8);
    Some(((read_config_u32(bus, device, function, aligned)? >> shift) & 0xff) as u8)
}

fn read_config_u16(bus: u8, device: u8, function: u8, offset: u16) -> Option<u16> {
    let aligned = offset & !0x3;
    let shift = u32::from((offset & 0x2) * 8);
    Some(((read_config_u32(bus, device, function, aligned)? >> shift) & 0xffff) as u16)
}

fn read_config_u32(bus: u8, device: u8, function: u8, offset: u16) -> Option<u32> {
    let _guard = PCI_CONFIG_LOCK.lock();
    read_config_u32_locked(bus, device, function, offset)
}

/// Inner read that assumes PCI_CONFIG_LOCK is already held by the caller.
fn read_config_u32_locked(bus: u8, device: u8, function: u8, offset: u16) -> Option<u32> {
    if device >= 32 || function >= 8 || offset >= 256 {
        return None;
    }
    let address = 0x8000_0000u32
        | (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | u32::from(offset & !0x3);

    // SAFETY: x86 PCI config mechanism #1 uses the architected 0xCF8/0xCFC
    // ports. Axle only reads these fixed ports during bootstrap device
    // discovery on PC-compatible x86_64 platforms.
    unsafe {
        let mut addr: Port<u32> = Port::new(PCI_CONFIG_ADDRESS_PORT);
        let mut data: Port<u32> = Port::new(PCI_CONFIG_DATA_PORT);
        addr.write(address);
        Some(data.read())
    }
}

pub(crate) fn write_config_u16(
    location: PciFunctionLocation,
    offset: u16,
    value: u16,
) -> Option<()> {
    if location.device >= 32 || location.function >= 8 || offset >= 256 {
        return None;
    }
    let aligned = offset & !0x3;
    let shift = u32::from((offset & 0x2) * 8);
    let mask = !(0xffffu32 << shift);

    // Hold the lock across the entire read-modify-write to prevent another CPU
    // from interleaving a config-space access between our read and write.
    let _guard = PCI_CONFIG_LOCK.lock();
    let mut dword =
        read_config_u32_locked(location.bus, location.device, location.function, aligned)?;
    dword = (dword & mask) | (u32::from(value) << shift);
    write_config_u32_locked(location, aligned, dword)
}

#[allow(dead_code)]
fn write_config_u32(location: PciFunctionLocation, offset: u16, value: u32) -> Option<()> {
    let _guard = PCI_CONFIG_LOCK.lock();
    write_config_u32_locked(location, offset, value)
}

/// Inner write that assumes PCI_CONFIG_LOCK is already held by the caller.
fn write_config_u32_locked(location: PciFunctionLocation, offset: u16, value: u32) -> Option<()> {
    if location.device >= 32 || location.function >= 8 || offset >= 256 {
        return None;
    }
    let address = 0x8000_0000u32
        | (u32::from(location.bus) << 16)
        | (u32::from(location.device) << 11)
        | (u32::from(location.function) << 8)
        | u32::from(offset & !0x3);

    // SAFETY: x86 PCI config mechanism #1 uses the architected 0xCF8/0xCFC
    // ports. Axle only writes these fixed ports for explicit driver-facing
    // PCI config updates on PC-compatible x86_64 platforms.
    unsafe {
        let mut addr: Port<u32> = Port::new(PCI_CONFIG_ADDRESS_PORT);
        let mut data: Port<u32> = Port::new(PCI_CONFIG_DATA_PORT);
        addr.write(address);
        data.write(value);
    }
    Some(())
}

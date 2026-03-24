//! Minimal IOAPIC driver for hardware IRQ routing.
//!
//! Programs redirection entries to route legacy IRQ pins to specified
//! APIC vectors.  The IOAPIC base address defaults to the standard
//! 0xFEC0_0000.

use core::ptr;

/// Default IOAPIC MMIO base (standard x86 platforms).
const IOAPIC_BASE: u64 = 0xFEC0_0000;

// Register offsets
const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;
const IOAPICVER: u32 = 0x01;
const IOREDTBL_BASE: u32 = 0x10;

/// Cached IOAPIC state.
static IOAPIC_MAX_ENTRIES: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);
static IOAPIC_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

unsafe fn ioapic_read(reg: u32) -> u32 {
    let base = IOAPIC_BASE as *mut u32;
    unsafe {
        ptr::write_volatile(base.byte_add(IOREGSEL), reg);
        ptr::read_volatile(base.byte_add(IOWIN) as *const u32)
    }
}

unsafe fn ioapic_write(reg: u32, val: u32) {
    let base = IOAPIC_BASE as *mut u32;
    unsafe {
        ptr::write_volatile(base.byte_add(IOREGSEL), reg);
        ptr::write_volatile(base.byte_add(IOWIN), val);
    }
}

/// Initialize the IOAPIC: read version/max entries, mask all pins.
pub(crate) fn init() {
    // SAFETY: IOAPIC MMIO is identity-mapped in the bootstrap page tables.
    unsafe {
        let ver = ioapic_read(IOAPICVER);
        let max_entry = ((ver >> 16) & 0xFF) as u8;
        IOAPIC_MAX_ENTRIES.store(max_entry, core::sync::atomic::Ordering::Relaxed);
        // Mask all redirection entries.
        for i in 0..=max_entry {
            let reg = IOREDTBL_BASE + (i as u32) * 2;
            let low = ioapic_read(reg);
            ioapic_write(reg, low | (1 << 16)); // set mask bit
        }
        IOAPIC_INITIALIZED.store(true, core::sync::atomic::Ordering::Release);
    }
}

/// Route one IOAPIC pin to a given vector on a given destination APIC.
/// The entry is unmasked after programming.
pub(crate) fn route_pin(pin: u8, vector: u8, dest_apic_id: u8) {
    if !IOAPIC_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let max = IOAPIC_MAX_ENTRIES.load(core::sync::atomic::Ordering::Relaxed);
    if pin > max {
        return;
    }
    let reg = IOREDTBL_BASE + (pin as u32) * 2;
    // Low 32 bits: vector, delivery mode 0 (Fixed), active-high,
    // edge-triggered, not masked.
    let low: u32 = vector as u32; // bits 7:0 = vector, rest = 0 (fixed, edge, active-high, unmasked)
    // High 32 bits: destination APIC id in bits 24:27.
    let high: u32 = (dest_apic_id as u32) << 24;
    unsafe {
        ioapic_write(reg + 1, high);
        ioapic_write(reg, low);
    }
}

/// Mask one IOAPIC pin.
pub(crate) fn mask_pin(pin: u8) {
    if !IOAPIC_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let reg = IOREDTBL_BASE + (pin as u32) * 2;
    unsafe {
        let low = ioapic_read(reg);
        ioapic_write(reg, low | (1 << 16));
    }
}

/// Unmask one IOAPIC pin.
pub(crate) fn unmask_pin(pin: u8) {
    if !IOAPIC_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let reg = IOREDTBL_BASE + (pin as u32) * 2;
    unsafe {
        let low = ioapic_read(reg);
        ioapic_write(reg, low & !(1 << 16));
    }
}

/// Returns the maximum redirection entry index (0-based), or 0 if not initialized.
pub(crate) fn max_entries() -> u8 {
    IOAPIC_MAX_ENTRIES.load(core::sync::atomic::Ordering::Relaxed)
}

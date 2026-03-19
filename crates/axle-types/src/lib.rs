//! Public UAPI types and constants for Axle/Nexus.
//!
//! This crate is intentionally tiny and `no_std` so it can be shared by:
//! - kernel (`no_std`)
//! - userspace runtime (`no_std`)
//! - host-side conformance tests (`std` via consumers)
//!
//! The native Axle personality is `ax_*`.
//! Frozen Zircon-compatible `zx_*` aliases remain available as a legacy
//! compatibility surface while the repository migrates toward native `ax_*`
//! naming and wider handle encoding.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(non_camel_case_types)]

/// Native Axle handle type.
///
/// The live kernel/user handle codec is now native 64-bit. Source-level
/// `zx_handle_t` compatibility remains as an alias of this type, but the old
/// 32-bit live handle width has been retired.
pub type ax_handle_t = u64;
/// Native Axle status/error type.
pub type ax_status_t = i32;
/// Native Axle signals type.
pub type ax_signals_t = u32;
/// Native Axle rights bitmask type.
pub type ax_rights_t = u32;
/// Native Axle kernel object id type.
pub type ax_koid_t = u64;
/// Native Axle futex word type.
pub type ax_futex_t = i32;
/// Native Axle absolute time / deadline type (monotonic nanoseconds).
pub type ax_time_t = i64;
/// Native Axle duration / interval type (nanoseconds).
pub type ax_duration_t = i64;
/// Native Axle clock id type.
pub type ax_clock_t = u32;
/// Native Axle packet type id.
pub type ax_packet_type_t = u32;
/// Native Axle VM option bitmask type.
pub type ax_vm_option_t = u32;
/// Native Axle virtual address type.
pub type ax_vaddr_t = u64;

/// Frozen Zircon-compat handle name.
///
/// The old 32-bit live handle width has been retired. `zx_handle_t` now remains
/// only as a source-level compatibility alias over the native 64-bit handle
/// width so legacy code can continue compiling while the repository migrates
/// away from `zx_*` naming.
pub type zx_handle_t = ax_handle_t;
/// Frozen Zircon-compat status/error type (i32).
pub type zx_status_t = i32;
/// Frozen Zircon-compat signals type (u32 bitmask).
pub type zx_signals_t = u32;
/// Frozen Zircon-compat rights bitmask type.
pub type zx_rights_t = u32;
/// Frozen Zircon-compat kernel object id type.
pub type zx_koid_t = u64;
/// Frozen Zircon-compat futex word type.
pub type zx_futex_t = i32;
/// Frozen Zircon-compat absolute time / deadline type (monotonic nanoseconds).
pub type zx_time_t = i64;
/// Frozen Zircon-compat duration / interval type (nanoseconds).
pub type zx_duration_t = i64;
/// Frozen Zircon-compat clock id type.
pub type zx_clock_t = u32;
/// Frozen Zircon-compat packet type id.
pub type zx_packet_type_t = u32;
/// Frozen Zircon-compat VM option bitmask type.
pub type zx_vm_option_t = u32;
/// Frozen Zircon-compat virtual address type.
pub type zx_vaddr_t = u64;

/// Guest stop state for one supervised guest thread.
///
/// The v1 ABI uses an explicit sidecar byte layout rather than a shared Rust
/// union or direct typed mapping so both kernel and userspace can read/write
/// the state without introducing `unsafe`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_guest_x64_regs_t {
    /// `rax`
    pub rax: u64,
    /// `rdi`
    pub rdi: u64,
    /// `rsi`
    pub rsi: u64,
    /// `rdx`
    pub rdx: u64,
    /// `r10`
    pub r10: u64,
    /// `r8`
    pub r8: u64,
    /// `r9`
    pub r9: u64,
    /// `rcx`
    pub rcx: u64,
    /// `r11`
    pub r11: u64,
    /// `rbx`
    pub rbx: u64,
    /// `rbp`
    pub rbp: u64,
    /// `r12`
    pub r12: u64,
    /// `r13`
    pub r13: u64,
    /// `r14`
    pub r14: u64,
    /// `r15`
    pub r15: u64,
    /// `rip`
    pub rip: u64,
    /// `rsp`
    pub rsp: u64,
    /// `rflags`
    pub rflags: u64,
}

impl ax_guest_x64_regs_t {
    /// Number of encoded bytes in one register snapshot.
    pub const BYTE_LEN: usize = 18 * core::mem::size_of::<u64>();

    fn encode_into(self, out: &mut [u8]) -> bool {
        if out.len() < Self::BYTE_LEN {
            return false;
        }
        let mut offset = 0usize;
        for value in [
            self.rax,
            self.rdi,
            self.rsi,
            self.rdx,
            self.r10,
            self.r8,
            self.r9,
            self.rcx,
            self.r11,
            self.rbx,
            self.rbp,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.rip,
            self.rsp,
            self.rflags,
        ] {
            write_u64_le(out, offset, value);
            offset += core::mem::size_of::<u64>();
        }
        true
    }

    fn decode_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::BYTE_LEN {
            return None;
        }
        let mut offset = 0usize;
        let mut next = || {
            let value = read_u64_le(bytes, offset)?;
            offset += core::mem::size_of::<u64>();
            Some(value)
        };
        Some(Self {
            rax: next()?,
            rdi: next()?,
            rsi: next()?,
            rdx: next()?,
            r10: next()?,
            r8: next()?,
            r9: next()?,
            rcx: next()?,
            r11: next()?,
            rbx: next()?,
            rbp: next()?,
            r12: next()?,
            r13: next()?,
            r14: next()?,
            r15: next()?,
            rip: next()?,
            rsp: next()?,
            rflags: next()?,
        })
    }
}

/// Sidecar state written by the kernel when a supervised guest thread stops.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_guest_stop_state_t {
    /// ABI version of this sidecar layout.
    pub version: u32,
    /// Guest architecture id.
    pub arch: u16,
    /// Stop reason for this snapshot.
    pub stop_reason: u16,
    /// Monotonic stop sequence issued by the kernel for this guest session.
    pub stop_seq: u64,
    /// Saved architectural register state.
    pub regs: ax_guest_x64_regs_t,
}

impl ax_guest_stop_state_t {
    /// Number of encoded bytes in one v1 stop-state snapshot.
    pub const BYTE_LEN: usize = 4 + 2 + 2 + 8 + ax_guest_x64_regs_t::BYTE_LEN;

    /// Encode into a fixed little-endian sidecar image.
    pub fn encode(self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        write_u32_le(&mut out, 0, self.version);
        write_u16_le(&mut out, 4, self.arch);
        write_u16_le(&mut out, 6, self.stop_reason);
        write_u64_le(&mut out, 8, self.stop_seq);
        let _ = self.regs.encode_into(&mut out[16..]);
        out
    }

    /// Decode one fixed sidecar image.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::BYTE_LEN {
            return None;
        }
        Some(Self {
            version: read_u32_le(bytes, 0)?,
            arch: read_u16_le(bytes, 4)?,
            stop_reason: read_u16_le(bytes, 6)?,
            stop_seq: read_u64_le(bytes, 8)?,
            regs: ax_guest_x64_regs_t::decode_from(&bytes[16..16 + ax_guest_x64_regs_t::BYTE_LEN])?,
        })
    }
}

/// Header for the opaque `ax_process_prepare_linux_exec` specification blob.
///
/// The full blob is:
/// - this header
/// - followed immediately by `stack_bytes_len` bytes of stack image data
/// - for v2 with `AX_LINUX_EXEC_SPEC_F_INTERP`, one
///   `ax_linux_exec_interp_header_t`
/// - followed immediately by `image_bytes_len` bytes of interpreter ELF file
///   contents
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_linux_exec_spec_header_t {
    /// Exec-spec ABI version.
    pub version: u32,
    /// Reserved for future flags.
    pub flags: u32,
    /// Userspace entry point.
    pub entry: u64,
    /// Initial userspace stack pointer.
    pub stack_pointer: u64,
    /// Offset within the fixed startup stack VMO where `stack_bytes` begin.
    pub stack_vmo_offset: u64,
    /// Number of bytes that follow this header in the exec-spec blob.
    pub stack_bytes_len: u64,
}

impl ax_linux_exec_spec_header_t {
    /// Encoded byte size of the v1 header.
    pub const BYTE_LEN: usize = 40;

    /// Encode into the fixed little-endian header form.
    pub fn encode(self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        write_u32_le(&mut out, 0, self.version);
        write_u32_le(&mut out, 4, self.flags);
        write_u64_le(&mut out, 8, self.entry);
        write_u64_le(&mut out, 16, self.stack_pointer);
        write_u64_le(&mut out, 24, self.stack_vmo_offset);
        write_u64_le(&mut out, 32, self.stack_bytes_len);
        out
    }

    /// Decode from the prefix of one exec-spec blob.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::BYTE_LEN {
            return None;
        }
        Some(Self {
            version: read_u32_le(bytes, 0)?,
            flags: read_u32_le(bytes, 4)?,
            entry: read_u64_le(bytes, 8)?,
            stack_pointer: read_u64_le(bytes, 16)?,
            stack_vmo_offset: read_u64_le(bytes, 24)?,
            stack_bytes_len: read_u64_le(bytes, 32)?,
        })
    }
}

/// Optional trailing header for one interpreter image in a Linux exec-spec blob.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_linux_exec_interp_header_t {
    /// Fixed load bias to apply when mapping one ET_DYN interpreter image.
    pub load_bias: u64,
    /// Number of bytes that follow this header in the exec-spec blob.
    pub image_bytes_len: u64,
}

impl ax_linux_exec_interp_header_t {
    /// Encoded byte size of the fixed little-endian trailing header.
    pub const BYTE_LEN: usize = 16;

    /// Encode into the fixed little-endian header form.
    pub fn encode(self) -> [u8; Self::BYTE_LEN] {
        let mut out = [0u8; Self::BYTE_LEN];
        write_u64_le(&mut out, 0, self.load_bias);
        write_u64_le(&mut out, 8, self.image_bytes_len);
        out
    }

    /// Decode from the prefix of one interpreter-image payload.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::BYTE_LEN {
            return None;
        }
        Some(Self {
            load_bias: read_u64_le(bytes, 0)?,
            image_bytes_len: read_u64_le(bytes, 8)?,
        })
    }
}

/// Native Axle user packet payload (32 bytes).
///
/// We use a 4x `u64` layout to keep the payload naturally 8-byte aligned
/// while preserving the exact 32-byte payload size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_packet_user_t {
    /// User-controlled payload words.
    pub u64: [u64; 4],
}

/// Native Axle signal packet payload (32 bytes).
///
/// This corresponds to `ax_packet_signal_t` (used with `AX_PKT_TYPE_SIGNAL_ONE`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_packet_signal_t {
    /// Watched signal mask that triggered the packet.
    pub trigger: ax_signals_t,
    /// Observed signals at the time of delivery.
    pub observed: ax_signals_t,
    /// Delivery count (merged on overflow in some port implementations).
    pub count: u64,
    /// Monotonic timestamp (when requested via wait-async options).
    pub timestamp: ax_time_t,
    /// Reserved.
    pub reserved1: u64,
}

impl ax_packet_signal_t {
    /// Encode into the raw 32-byte union payload shape (`ax_packet_user_t` view).
    ///
    /// This avoids Rust unions in the public ABI while preserving layout
    /// compatibility with Axle's `ax_port_packet_t` union.
    pub const fn to_user(self) -> ax_packet_user_t {
        let first = (self.trigger as u64) | ((self.observed as u64) << 32);
        ax_packet_user_t {
            u64: [first, self.count, self.timestamp as u64, self.reserved1],
        }
    }

    /// Decode from the raw 32-byte union payload shape (`ax_packet_user_t` view).
    pub const fn from_user(user: ax_packet_user_t) -> Self {
        let first = user.u64[0];
        Self {
            trigger: first as ax_signals_t,
            observed: (first >> 32) as ax_signals_t,
            count: user.u64[1],
            timestamp: user.u64[2] as ax_time_t,
            reserved1: user.u64[3],
        }
    }
}

/// Native Axle port packet (minimal Phase-B ABI shape).
///
/// For bootstrap we model the user-packet path used by `ax_port_queue` and
/// `ax_port_wait`. Additional packet variants can be added later without
/// changing this baseline layout: the `user` payload is the 32-byte union area
/// shared by user packets, signal packets, and future packet families.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ax_port_packet_t {
    /// User-defined key.
    pub key: u64,
    /// Packet type (for now `AX_PKT_TYPE_USER`).
    pub type_: ax_packet_type_t,
    /// Status associated with the packet.
    pub status: ax_status_t,
    /// User payload.
    pub user: ax_packet_user_t,
}

/// Frozen Zircon-compat alias for the raw user-packet payload shape.
pub type zx_packet_user_t = ax_packet_user_t;
/// Frozen Zircon-compat alias for the signal-packet payload shape.
pub type zx_packet_signal_t = ax_packet_signal_t;
/// Frozen Zircon-compat alias for the bootstrap port-packet layout.
pub type zx_port_packet_t = ax_port_packet_t;

const _: [(); 32] = [(); core::mem::size_of::<ax_packet_user_t>()];
const _: [(); 32] = [(); core::mem::size_of::<ax_packet_signal_t>()];
const _: [(); 48] = [(); core::mem::size_of::<ax_port_packet_t>()];
const _: [(); 8] = [(); core::mem::align_of::<ax_port_packet_t>()];

/// Clock ids.
pub mod clock {
    use super::{ax_clock_t, zx_clock_t};

    /// Native monotonic clock.
    pub const AX_CLOCK_MONOTONIC: ax_clock_t = 0;
    /// Native UTC clock.
    pub const AX_CLOCK_UTC: ax_clock_t = 1;
    /// Native thread clock.
    pub const AX_CLOCK_THREAD: ax_clock_t = 2;

    /// Monotonic clock.
    pub const ZX_CLOCK_MONOTONIC: zx_clock_t = AX_CLOCK_MONOTONIC as zx_clock_t;
    /// UTC clock.
    pub const ZX_CLOCK_UTC: zx_clock_t = AX_CLOCK_UTC as zx_clock_t;
    /// Thread clock.
    pub const ZX_CLOCK_THREAD: zx_clock_t = AX_CLOCK_THREAD as zx_clock_t;
}

/// Port packet type ids.
pub mod packet {
    use super::{ax_packet_type_t, zx_packet_type_t};

    /// Native user-defined packet (`ax_port_queue`).
    pub const AX_PKT_TYPE_USER: ax_packet_type_t = 0;
    /// Native signal packet delivered by `ax_object_wait_async`.
    pub const AX_PKT_TYPE_SIGNAL_ONE: ax_packet_type_t = 1;

    /// User-defined packet (`zx_port_queue`).
    pub const ZX_PKT_TYPE_USER: zx_packet_type_t = AX_PKT_TYPE_USER as zx_packet_type_t;
    /// Signal packet delivered by `zx_object_wait_async`.
    pub const ZX_PKT_TYPE_SIGNAL_ONE: zx_packet_type_t = AX_PKT_TYPE_SIGNAL_ONE as zx_packet_type_t;
}

/// Options for `zx_object_wait_async`.
///
/// Values follow Zircon's `zircon/syscalls/port.h`.
pub mod wait_async {
    /// Native one-shot wait registration (default).
    pub const AX_WAIT_ASYNC_ONCE: u32 = 0;
    /// Native packet requests monotonic timestamp delivery.
    pub const AX_WAIT_ASYNC_TIMESTAMP: u32 = 1;
    /// Native edge-triggered wait registration.
    pub const AX_WAIT_ASYNC_EDGE: u32 = 2;
    /// Native packet requests boot timestamp delivery.
    pub const AX_WAIT_ASYNC_BOOT_TIMESTAMP: u32 = 4;

    /// One-shot (default).
    pub const ZX_WAIT_ASYNC_ONCE: u32 = AX_WAIT_ASYNC_ONCE;
    /// Request monotonic timestamp in packets.
    pub const ZX_WAIT_ASYNC_TIMESTAMP: u32 = AX_WAIT_ASYNC_TIMESTAMP;
    /// Edge-triggered: only fire on transition from not-satisfied to satisfied.
    pub const ZX_WAIT_ASYNC_EDGE: u32 = AX_WAIT_ASYNC_EDGE;
    /// Request boot timestamp in packets.
    ///
    /// In current bring-up Axle exposes the same underlying monotonic timeline
    /// for both monotonic and boot timestamps because suspend/resume time
    /// accounting has not been introduced yet.
    pub const ZX_WAIT_ASYNC_BOOT_TIMESTAMP: u32 = AX_WAIT_ASYNC_BOOT_TIMESTAMP;
}

/// Socket creation/read options.
pub mod socket {
    /// Native stream socket.
    pub const AX_SOCKET_STREAM: u32 = 0;
    /// Native datagram socket.
    pub const AX_SOCKET_DATAGRAM: u32 = 1;
    /// Native peek without consuming bytes from the socket.
    pub const AX_SOCKET_PEEK: u32 = 1;

    /// Stream socket.
    pub const ZX_SOCKET_STREAM: u32 = AX_SOCKET_STREAM;
    /// Datagram socket.
    pub const ZX_SOCKET_DATAGRAM: u32 = AX_SOCKET_DATAGRAM;
    /// Peek without consuming bytes from the socket.
    pub const ZX_SOCKET_PEEK: u32 = AX_SOCKET_PEEK;
}

/// Interrupt creation options.
pub mod interrupt {
    use super::{ax_handle_t, ax_vm_option_t, zx_handle_t, zx_vm_option_t};

    /// Create one software-triggerable virtual interrupt object.
    pub const AX_INTERRUPT_VIRTUAL: ax_vm_option_t = 1 << 0;

    /// Create one software-triggerable virtual interrupt object.
    pub const ZX_INTERRUPT_VIRTUAL: zx_vm_option_t = AX_INTERRUPT_VIRTUAL as zx_vm_option_t;

    /// Interrupt object delivers one synthetic virtual line.
    pub const AX_INTERRUPT_MODE_VIRTUAL: u32 = 0;
    /// Reserved mode for future hardware INTx wiring.
    pub const AX_INTERRUPT_MODE_LEGACY: u32 = 1;
    /// Reserved mode for future MSI wiring.
    pub const AX_INTERRUPT_MODE_MSI: u32 = 2;
    /// Reserved mode for future MSI-X wiring.
    pub const AX_INTERRUPT_MODE_MSIX: u32 = 3;

    /// Interrupt object delivers one synthetic virtual line.
    pub const ZX_INTERRUPT_MODE_VIRTUAL: u32 = AX_INTERRUPT_MODE_VIRTUAL;
    /// Reserved mode for future hardware INTx wiring.
    pub const ZX_INTERRUPT_MODE_LEGACY: u32 = AX_INTERRUPT_MODE_LEGACY;
    /// Reserved mode for future MSI wiring.
    pub const ZX_INTERRUPT_MODE_MSI: u32 = AX_INTERRUPT_MODE_MSI;
    /// Reserved mode for future MSI-X wiring.
    pub const ZX_INTERRUPT_MODE_MSIX: u32 = AX_INTERRUPT_MODE_MSIX;

    /// Software trigger is permitted through `ax_interrupt_trigger()`.
    pub const AX_INTERRUPT_INFO_FLAG_TRIGGERABLE: u32 = 1 << 0;
    /// Software trigger is permitted through `ax_interrupt_trigger()`.
    pub const ZX_INTERRUPT_INFO_FLAG_TRIGGERABLE: u32 = AX_INTERRUPT_INFO_FLAG_TRIGGERABLE;

    /// One interrupt-object metadata snapshot.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_interrupt_info_t {
        /// Handle naming the interrupt object that produced this snapshot.
        pub handle: ax_handle_t,
        /// Delivery mode for this interrupt object.
        pub mode: u32,
        /// Opaque vector or line index within that delivery mode.
        pub vector: u32,
        /// Capability and source flags for this interrupt object.
        pub flags: u32,
        /// Reserved for later expansion.
        pub reserved0: u32,
    }

    /// Frozen Zircon-compat alias over the native interrupt-info record.
    pub type zx_interrupt_info_t = ax_interrupt_info_t;

    const _: () = {
        let _ = core::mem::size_of::<zx_handle_t>();
    };
}

/// DMA pin options and metadata.
pub mod dma {
    /// Device may read from the pinned region.
    pub const AX_DMA_PERM_DEVICE_READ: u32 = 1 << 0;
    /// Device may write into the pinned region.
    pub const AX_DMA_PERM_DEVICE_WRITE: u32 = 1 << 1;
    /// The current device-visible address view is identical to the backing physical address.
    pub const AX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA: u32 = 1 << 0;
    /// The pinned frame set is physically contiguous across the full region.
    pub const AX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS: u32 = 1 << 1;

    /// Device may read from the pinned region.
    pub const ZX_DMA_PERM_DEVICE_READ: u32 = AX_DMA_PERM_DEVICE_READ;
    /// Device may write into the pinned region.
    pub const ZX_DMA_PERM_DEVICE_WRITE: u32 = AX_DMA_PERM_DEVICE_WRITE;
    /// The current device-visible address view is identical to the backing physical address.
    pub const ZX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA: u32 = AX_DMA_REGION_INFO_FLAG_IDENTITY_IOVA;
    /// The pinned frame set is physically contiguous across the full region.
    pub const ZX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS: u32 =
        AX_DMA_REGION_INFO_FLAG_PHYSICALLY_CONTIGUOUS;

    /// One pinned DMA-region metadata snapshot.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_dma_region_info_t {
        /// Pinned region size in bytes.
        pub size_bytes: u64,
        /// Creation-time DMA permission bits.
        pub options: u32,
        /// Region metadata flags.
        pub flags: u32,
        /// Base physical address for offset zero.
        pub paddr_base: u64,
        /// Base device-visible address for offset zero.
        pub iova_base: u64,
    }

    /// Frozen Zircon-compat alias over the native DMA-region info record.
    pub type zx_dma_region_info_t = ax_dma_region_info_t;
}

/// Narrow PCI/device-facing bootstrap types and constants.
pub mod pci {
    use super::{ax_handle_t, zx_handle_t};

    /// Export the current queue-ready interrupt for one queue pair.
    pub const AX_PCI_INTERRUPT_GROUP_READY: u32 = 0;
    /// Export the current TX-kick interrupt for one queue pair.
    pub const AX_PCI_INTERRUPT_GROUP_TX_KICK: u32 = 1;
    /// Export the current RX-complete interrupt for one queue pair.
    pub const AX_PCI_INTERRUPT_GROUP_RX_COMPLETE: u32 = 2;

    /// Export the current queue-ready interrupt for one queue pair.
    pub const ZX_PCI_INTERRUPT_GROUP_READY: u32 = AX_PCI_INTERRUPT_GROUP_READY;
    /// Export the current TX-kick interrupt for one queue pair.
    pub const ZX_PCI_INTERRUPT_GROUP_TX_KICK: u32 = AX_PCI_INTERRUPT_GROUP_TX_KICK;
    /// Export the current RX-complete interrupt for one queue pair.
    pub const ZX_PCI_INTERRUPT_GROUP_RX_COMPLETE: u32 = AX_PCI_INTERRUPT_GROUP_RX_COMPLETE;

    /// BAR names one MMIO window.
    pub const AX_PCI_BAR_FLAG_MMIO: u32 = 1 << 0;
    /// BAR names one MMIO window.
    pub const ZX_PCI_BAR_FLAG_MMIO: u32 = AX_PCI_BAR_FLAG_MMIO;

    /// Config window is one MMIO-style exported config-space alias.
    pub const AX_PCI_CONFIG_FLAG_MMIO: u32 = 1 << 0;
    /// Config window should be treated as read-only by the driver.
    pub const AX_PCI_CONFIG_FLAG_READ_ONLY: u32 = 1 << 1;

    /// Config window is one MMIO-style exported config-space alias.
    pub const ZX_PCI_CONFIG_FLAG_MMIO: u32 = AX_PCI_CONFIG_FLAG_MMIO;
    /// Config window should be treated as read-only by the driver.
    pub const ZX_PCI_CONFIG_FLAG_READ_ONLY: u32 = AX_PCI_CONFIG_FLAG_READ_ONLY;

    /// Interrupt resource is one synthetic virtual line.
    pub const AX_PCI_INTERRUPT_MODE_VIRTUAL: u32 = 0;
    /// Reserved mode for future hardware INTx wiring.
    pub const AX_PCI_INTERRUPT_MODE_LEGACY: u32 = 1;
    /// Reserved mode for future MSI wiring.
    pub const AX_PCI_INTERRUPT_MODE_MSI: u32 = 2;
    /// Reserved mode for future MSI-X wiring.
    pub const AX_PCI_INTERRUPT_MODE_MSIX: u32 = 3;

    /// Interrupt resource is one synthetic virtual line.
    pub const ZX_PCI_INTERRUPT_MODE_VIRTUAL: u32 = AX_PCI_INTERRUPT_MODE_VIRTUAL;
    /// Reserved mode for future hardware INTx wiring.
    pub const ZX_PCI_INTERRUPT_MODE_LEGACY: u32 = AX_PCI_INTERRUPT_MODE_LEGACY;
    /// Reserved mode for future MSI wiring.
    pub const ZX_PCI_INTERRUPT_MODE_MSI: u32 = AX_PCI_INTERRUPT_MODE_MSI;
    /// Reserved mode for future MSI-X wiring.
    pub const ZX_PCI_INTERRUPT_MODE_MSIX: u32 = AX_PCI_INTERRUPT_MODE_MSIX;
    /// Interrupt mode is exported by this device object.
    pub const AX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED: u32 = 1 << 0;
    /// Interrupt mode is the device object's current active delivery mode.
    pub const AX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE: u32 = 1 << 1;
    /// Interrupt mode currently routes through triggerable interrupt objects.
    pub const AX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE: u32 = 1 << 2;

    /// Interrupt mode is exported by this device object.
    pub const ZX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED: u32 =
        AX_PCI_INTERRUPT_MODE_INFO_FLAG_SUPPORTED;
    /// Interrupt mode is the device object's current active delivery mode.
    pub const ZX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE: u32 = AX_PCI_INTERRUPT_MODE_INFO_FLAG_ACTIVE;
    /// Interrupt mode currently routes through triggerable interrupt objects.
    pub const ZX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE: u32 =
        AX_PCI_INTERRUPT_MODE_INFO_FLAG_TRIGGERABLE;

    /// One narrow public PCI/device info snapshot.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_pci_device_info_t {
        /// Vendor id.
        pub vendor_id: u16,
        /// Device id.
        pub device_id: u16,
        /// Programming interface byte.
        pub prog_if: u8,
        /// Subclass byte.
        pub subclass: u8,
        /// Class-code byte.
        pub class_code: u8,
        /// Revision id.
        pub revision_id: u8,
        /// Number of exported BAR resources.
        pub bar_count: u32,
        /// Number of queue pairs visible through the current narrow transport contract.
        pub queue_pairs: u32,
        /// Queue size in descriptor slots.
        pub queue_size: u32,
        /// Device feature bits exported through the current narrow transport contract.
        pub device_features: u32,
        /// Interrupt-resource groups exported per queue pair.
        pub interrupt_groups: u32,
        /// Reserved for later expansion.
        pub reserved0: u32,
    }

    /// Frozen Zircon-compat alias over the native PCI/device info record.
    pub type zx_pci_device_info_t = ax_pci_device_info_t;

    /// One BAR export result.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_pci_bar_info_t {
        /// Handle naming the exported BAR VMO.
        pub handle: ax_handle_t,
        /// BAR size in bytes.
        pub size: u64,
        /// Resource flags describing the BAR window.
        pub flags: u32,
        /// Mapping options the driver should apply when installing this BAR.
        pub map_options: u32,
    }

    /// Frozen Zircon-compat alias over the native BAR-export result.
    pub type zx_pci_bar_info_t = ax_pci_bar_info_t;

    /// One exported PCI config-space window.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_pci_config_info_t {
        /// Handle naming the exported config-space VMO.
        pub handle: ax_handle_t,
        /// Config-space window size in bytes.
        pub size: u64,
        /// Resource flags describing that config-space export.
        pub flags: u32,
        /// Mapping options the driver should apply when installing this window.
        pub map_options: u32,
    }

    /// Frozen Zircon-compat alias over the native config-window export result.
    pub type zx_pci_config_info_t = ax_pci_config_info_t;

    /// One interrupt export result.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_pci_interrupt_info_t {
        /// Handle naming the exported interrupt object.
        pub handle: ax_handle_t,
        /// Interrupt delivery mode for this resource.
        pub mode: u32,
        /// Opaque vector or line index within that delivery mode.
        pub vector: u32,
    }

    /// Frozen Zircon-compat alias over the native interrupt-export result.
    pub type zx_pci_interrupt_info_t = ax_pci_interrupt_info_t;

    /// One interrupt-mode capability snapshot for a PCI/device handle.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ax_pci_interrupt_mode_info_t {
        /// Interrupt delivery mode this snapshot describes.
        pub mode: u32,
        /// Capability and activity flags for that mode.
        pub flags: u32,
        /// Base vector or line index exported for this mode.
        pub base_vector: u32,
        /// Number of vectors or lines exported in this mode.
        pub vector_count: u32,
    }

    /// Frozen Zircon-compat alias over the native interrupt-mode info record.
    pub type zx_pci_interrupt_mode_info_t = ax_pci_interrupt_mode_info_t;

    const _: () = {
        let _ = core::mem::size_of::<zx_handle_t>();
    };
}

pub use dma::{ax_dma_region_info_t, zx_dma_region_info_t};
pub use interrupt::{ax_interrupt_info_t, zx_interrupt_info_t};
pub use pci::{
    ax_pci_bar_info_t, ax_pci_config_info_t, ax_pci_device_info_t, ax_pci_interrupt_info_t,
    ax_pci_interrupt_mode_info_t, zx_pci_bar_info_t, zx_pci_config_info_t, zx_pci_device_info_t,
    zx_pci_interrupt_info_t, zx_pci_interrupt_mode_info_t,
};

/// VM mapping and protection options.
///
/// VM option bits used by Axle's Zircon-style VM syscalls.
pub mod vm {
    use super::{ax_vm_option_t, zx_vm_option_t};

    /// Native mapping/protection grants read access.
    pub const AX_VM_PERM_READ: ax_vm_option_t = 1 << 0;
    /// Native mapping/protection grants write access.
    pub const AX_VM_PERM_WRITE: ax_vm_option_t = 1 << 1;
    /// Native mapping/protection grants execute access.
    pub const AX_VM_PERM_EXECUTE: ax_vm_option_t = 1 << 2;
    /// Native compact VMAR allocation preference.
    pub const AX_VM_COMPACT: ax_vm_option_t = 1 << 3;
    /// Native private-clone mapping request over one shared pager/file-backed source.
    ///
    /// The initial mapping remains read-only in hardware. The first write faults in one
    /// mapping-local private page without mutating the shared source object.
    pub const AX_VM_PRIVATE_CLONE: ax_vm_option_t = 1 << 4;
    /// Native device/MMIO mapping request.
    ///
    /// This requests one uncached device-style mapping attribute on the installed leaf PTEs.
    /// It is currently intended only for physical/contiguous device-facing VMOs.
    pub const AX_VM_MAP_MMIO: ax_vm_option_t = 1 << 5;
    /// Native upper-bound interpretation for non-specific VMAR allocation.
    pub const AX_VM_OFFSET_IS_UPPER_LIMIT: ax_vm_option_t = 1 << 9;
    /// Native child VMAR may create readable mappings.
    pub const AX_VM_CAN_MAP_READ: ax_vm_option_t = 1 << 11;
    /// Native child VMAR may create writable mappings.
    pub const AX_VM_CAN_MAP_WRITE: ax_vm_option_t = 1 << 12;
    /// Native child VMAR may create executable mappings.
    pub const AX_VM_CAN_MAP_EXECUTE: ax_vm_option_t = 1 << 13;
    /// Native exact-address mapping request.
    pub const AX_VM_SPECIFIC: ax_vm_option_t = 1 << 10;
    /// Native child VMAR may create exact-address mappings.
    pub const AX_VM_CAN_MAP_SPECIFIC: ax_vm_option_t = 1 << 14;
    /// Bit position of the encoded native VM alignment subfield.
    pub const AX_VM_ALIGN_BASE: u32 = 24;
    /// Bit mask covering the encoded native VM alignment subfield.
    pub const AX_VM_ALIGN_MASK: ax_vm_option_t = 0x1f << AX_VM_ALIGN_BASE;
    /// Request 1 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_1KB: ax_vm_option_t = 10 << AX_VM_ALIGN_BASE;
    /// Request 2 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_2KB: ax_vm_option_t = 11 << AX_VM_ALIGN_BASE;
    /// Request 4 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_4KB: ax_vm_option_t = 12 << AX_VM_ALIGN_BASE;
    /// Request 8 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_8KB: ax_vm_option_t = 13 << AX_VM_ALIGN_BASE;
    /// Request 16 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_16KB: ax_vm_option_t = 14 << AX_VM_ALIGN_BASE;
    /// Request 32 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_32KB: ax_vm_option_t = 15 << AX_VM_ALIGN_BASE;
    /// Request 64 KiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_64KB: ax_vm_option_t = 16 << AX_VM_ALIGN_BASE;
    /// Request 1 MiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_1MB: ax_vm_option_t = 20 << AX_VM_ALIGN_BASE;
    /// Request 2 MiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_2MB: ax_vm_option_t = 21 << AX_VM_ALIGN_BASE;
    /// Request 1 GiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_1GB: ax_vm_option_t = 30 << AX_VM_ALIGN_BASE;
    /// Request 4 GiB alignment for non-specific VMAR allocation.
    pub const AX_VM_ALIGN_4GB: ax_vm_option_t = 32 << AX_VM_ALIGN_BASE;

    /// Mapping/protection grants read access.
    pub const ZX_VM_PERM_READ: zx_vm_option_t = AX_VM_PERM_READ as zx_vm_option_t;
    /// Mapping/protection grants write access.
    pub const ZX_VM_PERM_WRITE: zx_vm_option_t = AX_VM_PERM_WRITE as zx_vm_option_t;
    /// Mapping/protection grants execute access.
    pub const ZX_VM_PERM_EXECUTE: zx_vm_option_t = AX_VM_PERM_EXECUTE as zx_vm_option_t;
    /// Prefer compact placement instead of ASLR-style placement for non-specific VMAR allocation.
    pub const ZX_VM_COMPACT: zx_vm_option_t = AX_VM_COMPACT as zx_vm_option_t;
    /// Map one shared pager/file-backed VMO through a private copy-on-write view.
    pub const ZX_VM_PRIVATE_CLONE: zx_vm_option_t = AX_VM_PRIVATE_CLONE as zx_vm_option_t;
    /// Map one physical/contiguous VMO with device/MMIO cache attributes.
    pub const ZX_VM_MAP_MMIO: zx_vm_option_t = AX_VM_MAP_MMIO as zx_vm_option_t;
    /// Interpret the supplied offset as an upper bound for non-specific VMAR allocation.
    pub const ZX_VM_OFFSET_IS_UPPER_LIMIT: zx_vm_option_t =
        AX_VM_OFFSET_IS_UPPER_LIMIT as zx_vm_option_t;
    /// Child VMAR may create readable mappings.
    pub const ZX_VM_CAN_MAP_READ: zx_vm_option_t = AX_VM_CAN_MAP_READ as zx_vm_option_t;
    /// Child VMAR may create writable mappings.
    pub const ZX_VM_CAN_MAP_WRITE: zx_vm_option_t = AX_VM_CAN_MAP_WRITE as zx_vm_option_t;
    /// Child VMAR may create executable mappings.
    pub const ZX_VM_CAN_MAP_EXECUTE: zx_vm_option_t = AX_VM_CAN_MAP_EXECUTE as zx_vm_option_t;
    /// Map at an exact address (`vmar_offset` must be honored exactly).
    pub const ZX_VM_SPECIFIC: zx_vm_option_t = AX_VM_SPECIFIC as zx_vm_option_t;
    /// Child VMAR may create exact-address mappings.
    pub const ZX_VM_CAN_MAP_SPECIFIC: zx_vm_option_t = AX_VM_CAN_MAP_SPECIFIC as zx_vm_option_t;
    /// Bit position of the encoded VM alignment subfield.
    pub const ZX_VM_ALIGN_BASE: u32 = AX_VM_ALIGN_BASE;
    /// Bit mask covering the encoded VM alignment subfield.
    pub const ZX_VM_ALIGN_MASK: zx_vm_option_t = AX_VM_ALIGN_MASK as zx_vm_option_t;
    /// Request 1 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_1KB: zx_vm_option_t = AX_VM_ALIGN_1KB as zx_vm_option_t;
    /// Request 2 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_2KB: zx_vm_option_t = AX_VM_ALIGN_2KB as zx_vm_option_t;
    /// Request 4 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_4KB: zx_vm_option_t = AX_VM_ALIGN_4KB as zx_vm_option_t;
    /// Request 8 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_8KB: zx_vm_option_t = AX_VM_ALIGN_8KB as zx_vm_option_t;
    /// Request 16 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_16KB: zx_vm_option_t = AX_VM_ALIGN_16KB as zx_vm_option_t;
    /// Request 32 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_32KB: zx_vm_option_t = AX_VM_ALIGN_32KB as zx_vm_option_t;
    /// Request 64 KiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_64KB: zx_vm_option_t = AX_VM_ALIGN_64KB as zx_vm_option_t;
    /// Request 1 MiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_1MB: zx_vm_option_t = AX_VM_ALIGN_1MB as zx_vm_option_t;
    /// Request 2 MiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_2MB: zx_vm_option_t = AX_VM_ALIGN_2MB as zx_vm_option_t;
    /// Request 1 GiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_1GB: zx_vm_option_t = AX_VM_ALIGN_1GB as zx_vm_option_t;
    /// Request 4 GiB alignment for non-specific VMAR allocation.
    pub const ZX_VM_ALIGN_4GB: zx_vm_option_t = AX_VM_ALIGN_4GB as zx_vm_option_t;
}

/// Guest-supervision and Linux exec helper constants.
pub mod guest {
    /// x86_64 guest architecture id.
    pub const AX_GUEST_ARCH_X86_64: u16 = 1;
    /// x86_64 guest stop due to one `syscall` instruction trap.
    pub const AX_GUEST_STOP_REASON_X64_SYSCALL: u16 = 1;
    /// ABI version for the v1 stop-state sidecar.
    pub const AX_GUEST_STOP_STATE_V1: u32 = 1;
    /// Length in bytes of one x86_64 `syscall` instruction.
    pub const AX_GUEST_X64_SYSCALL_INSN_LEN: u64 = 2;
    /// ABI version for the v1 Linux exec specification header.
    pub const AX_LINUX_EXEC_SPEC_V1: u32 = 1;
    /// ABI version for the v2 Linux exec specification header.
    pub const AX_LINUX_EXEC_SPEC_V2: u32 = 2;
    /// v2 exec-spec flag: one interpreter image header and payload follow the
    /// stack-image bytes.
    pub const AX_LINUX_EXEC_SPEC_F_INTERP: u32 = 1 << 0;
}

/// Zircon handle rights bit definitions.
pub mod rights {
    use super::{ax_rights_t, zx_rights_t};

    /// Duplicate the native handle.
    pub const AX_RIGHT_DUPLICATE: ax_rights_t = 1u32 << 0;
    /// Transfer the native handle to another process.
    pub const AX_RIGHT_TRANSFER: ax_rights_t = 1u32 << 1;
    /// Read from the object.
    pub const AX_RIGHT_READ: ax_rights_t = 1u32 << 2;
    /// Write to the object.
    pub const AX_RIGHT_WRITE: ax_rights_t = 1u32 << 3;
    /// Execute from the object.
    pub const AX_RIGHT_EXECUTE: ax_rights_t = 1u32 << 4;
    /// Map the object into a VMAR.
    pub const AX_RIGHT_MAP: ax_rights_t = 1u32 << 5;
    /// Read object properties.
    pub const AX_RIGHT_GET_PROPERTY: ax_rights_t = 1u32 << 6;
    /// Set object properties.
    pub const AX_RIGHT_SET_PROPERTY: ax_rights_t = 1u32 << 7;
    /// Enumerate children or related objects.
    pub const AX_RIGHT_ENUMERATE: ax_rights_t = 1u32 << 8;
    /// Destroy the object.
    pub const AX_RIGHT_DESTROY: ax_rights_t = 1u32 << 9;
    /// Set policy on the object.
    pub const AX_RIGHT_SET_POLICY: ax_rights_t = 1u32 << 10;
    /// Get policy from the object.
    pub const AX_RIGHT_GET_POLICY: ax_rights_t = 1u32 << 11;
    /// Set user signals on the object itself.
    pub const AX_RIGHT_SIGNAL: ax_rights_t = 1u32 << 12;
    /// Set signals on the peer of a peered object.
    pub const AX_RIGHT_SIGNAL_PEER: ax_rights_t = 1u32 << 13;
    /// Wait on the object.
    pub const AX_RIGHT_WAIT: ax_rights_t = 1u32 << 14;
    /// Inspect the object.
    pub const AX_RIGHT_INSPECT: ax_rights_t = 1u32 << 15;
    /// Manage a job.
    pub const AX_RIGHT_MANAGE_JOB: ax_rights_t = 1u32 << 16;
    /// Manage a process.
    pub const AX_RIGHT_MANAGE_PROCESS: ax_rights_t = 1u32 << 17;
    /// Manage a thread.
    pub const AX_RIGHT_MANAGE_THREAD: ax_rights_t = 1u32 << 18;
    /// Apply a profile.
    pub const AX_RIGHT_APPLY_PROFILE: ax_rights_t = 1u32 << 19;
    /// Basic transferable/duplicable/waitable rights.
    pub const AX_RIGHTS_BASIC: ax_rights_t =
        AX_RIGHT_TRANSFER | AX_RIGHT_DUPLICATE | AX_RIGHT_WAIT | AX_RIGHT_INSPECT;
    /// Read/write I/O rights.
    pub const AX_RIGHTS_IO: ax_rights_t = AX_RIGHT_READ | AX_RIGHT_WRITE;
    /// Keep the same rights as the source handle when duplicating/replacing.
    pub const AX_RIGHT_SAME_RIGHTS: ax_rights_t = u32::MAX;
    /// Mask of all currently defined native right bits.
    pub const AX_RIGHTS_ALL: ax_rights_t = AX_RIGHT_DUPLICATE
        | AX_RIGHT_TRANSFER
        | AX_RIGHT_READ
        | AX_RIGHT_WRITE
        | AX_RIGHT_EXECUTE
        | AX_RIGHT_MAP
        | AX_RIGHT_GET_PROPERTY
        | AX_RIGHT_SET_PROPERTY
        | AX_RIGHT_ENUMERATE
        | AX_RIGHT_DESTROY
        | AX_RIGHT_SET_POLICY
        | AX_RIGHT_GET_POLICY
        | AX_RIGHT_SIGNAL
        | AX_RIGHT_SIGNAL_PEER
        | AX_RIGHT_WAIT
        | AX_RIGHT_INSPECT
        | AX_RIGHT_MANAGE_JOB
        | AX_RIGHT_MANAGE_PROCESS
        | AX_RIGHT_MANAGE_THREAD
        | AX_RIGHT_APPLY_PROFILE;

    /// Duplicate the handle.
    pub const ZX_RIGHT_DUPLICATE: zx_rights_t = AX_RIGHT_DUPLICATE as zx_rights_t;
    /// Transfer the handle to another process.
    pub const ZX_RIGHT_TRANSFER: zx_rights_t = AX_RIGHT_TRANSFER as zx_rights_t;
    /// Read from the object.
    pub const ZX_RIGHT_READ: zx_rights_t = AX_RIGHT_READ as zx_rights_t;
    /// Write to the object.
    pub const ZX_RIGHT_WRITE: zx_rights_t = AX_RIGHT_WRITE as zx_rights_t;
    /// Execute from the object.
    pub const ZX_RIGHT_EXECUTE: zx_rights_t = AX_RIGHT_EXECUTE as zx_rights_t;
    /// Map the object into a VMAR.
    pub const ZX_RIGHT_MAP: zx_rights_t = AX_RIGHT_MAP as zx_rights_t;
    /// Read object properties.
    pub const ZX_RIGHT_GET_PROPERTY: zx_rights_t = AX_RIGHT_GET_PROPERTY as zx_rights_t;
    /// Set object properties.
    pub const ZX_RIGHT_SET_PROPERTY: zx_rights_t = AX_RIGHT_SET_PROPERTY as zx_rights_t;
    /// Enumerate children or related objects.
    pub const ZX_RIGHT_ENUMERATE: zx_rights_t = AX_RIGHT_ENUMERATE as zx_rights_t;
    /// Destroy the object.
    pub const ZX_RIGHT_DESTROY: zx_rights_t = AX_RIGHT_DESTROY as zx_rights_t;
    /// Set policy on the object.
    pub const ZX_RIGHT_SET_POLICY: zx_rights_t = AX_RIGHT_SET_POLICY as zx_rights_t;
    /// Get policy from the object.
    pub const ZX_RIGHT_GET_POLICY: zx_rights_t = AX_RIGHT_GET_POLICY as zx_rights_t;
    /// Set user signals on the object itself.
    pub const ZX_RIGHT_SIGNAL: zx_rights_t = AX_RIGHT_SIGNAL as zx_rights_t;
    /// Set signals on the peer of a peered object.
    pub const ZX_RIGHT_SIGNAL_PEER: zx_rights_t = AX_RIGHT_SIGNAL_PEER as zx_rights_t;
    /// Wait on the object.
    pub const ZX_RIGHT_WAIT: zx_rights_t = AX_RIGHT_WAIT as zx_rights_t;
    /// Inspect the object.
    pub const ZX_RIGHT_INSPECT: zx_rights_t = AX_RIGHT_INSPECT as zx_rights_t;
    /// Manage a job.
    pub const ZX_RIGHT_MANAGE_JOB: zx_rights_t = AX_RIGHT_MANAGE_JOB as zx_rights_t;
    /// Manage a process.
    pub const ZX_RIGHT_MANAGE_PROCESS: zx_rights_t = AX_RIGHT_MANAGE_PROCESS as zx_rights_t;
    /// Manage a thread.
    pub const ZX_RIGHT_MANAGE_THREAD: zx_rights_t = AX_RIGHT_MANAGE_THREAD as zx_rights_t;
    /// Apply a profile.
    pub const ZX_RIGHT_APPLY_PROFILE: zx_rights_t = AX_RIGHT_APPLY_PROFILE as zx_rights_t;

    /// Basic transferable/duplicable/waitable rights.
    pub const ZX_RIGHTS_BASIC: zx_rights_t = AX_RIGHTS_BASIC as zx_rights_t;
    /// Read/write I/O rights.
    pub const ZX_RIGHTS_IO: zx_rights_t = AX_RIGHTS_IO as zx_rights_t;
    /// Keep the same rights as the source handle when duplicating/replacing.
    pub const ZX_RIGHT_SAME_RIGHTS: zx_rights_t = AX_RIGHT_SAME_RIGHTS as zx_rights_t;
    /// Mask of all currently defined right bits.
    pub const ZX_RIGHTS_ALL: zx_rights_t = AX_RIGHTS_ALL as zx_rights_t;
}

/// Generated syscall numbers (ABI).
///
/// Single source of truth:
/// - `syscalls/spec/syscalls.toml`
/// - generated by `tools/syscalls-gen` into `syscalls/generated`
#[allow(missing_docs)]
#[path = "../../../syscalls/generated/syscall_numbers.rs"]
pub mod syscall_numbers;

/// Handle constants.
pub mod handle {
    use super::{ax_handle_t, zx_handle_t};

    /// Invalid native handle value.
    pub const AX_HANDLE_INVALID: ax_handle_t = 0;

    /// Invalid handle value.
    pub const ZX_HANDLE_INVALID: zx_handle_t = AX_HANDLE_INVALID as zx_handle_t;

    /// Legacy mask for the retired 32-bit handle codec's low fixed bits.
    ///
    /// Native 64-bit Axle handles do not provide any fixed low-bit guarantee.
    pub const ZX_HANDLE_FIXED_BITS_MASK: zx_handle_t = 0x3;
    /// Legacy fixed-bit value from the retired 32-bit handle codec.
    pub const ZX_HANDLE_FIXED_BITS_VALUE: zx_handle_t = 0x3;
}

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + core::mem::size_of::<u16>()].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + core::mem::size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + core::mem::size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(core::mem::size_of::<u16>())?;
    let slice = bytes.get(offset..end)?;
    let mut array = [0u8; core::mem::size_of::<u16>()];
    array.copy_from_slice(slice);
    Some(u16::from_le_bytes(array))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(core::mem::size_of::<u32>())?;
    let slice = bytes.get(offset..end)?;
    let mut array = [0u8; core::mem::size_of::<u32>()];
    array.copy_from_slice(slice);
    Some(u32::from_le_bytes(array))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(core::mem::size_of::<u64>())?;
    let slice = bytes.get(offset..end)?;
    let mut array = [0u8; core::mem::size_of::<u64>()];
    array.copy_from_slice(slice);
    Some(u64::from_le_bytes(array))
}

/// Kernel object id constants.
pub mod koid {
    use super::{ax_koid_t, zx_koid_t};

    /// Invalid native kernel object id.
    pub const AX_KOID_INVALID: ax_koid_t = 0;

    /// Invalid kernel object id.
    pub const ZX_KOID_INVALID: zx_koid_t = AX_KOID_INVALID as zx_koid_t;
}

/// Status / error codes.
///
/// Values follow Zircon's `zircon/errors.h`.
pub mod status {
    use super::{ax_status_t, zx_status_t};

    /// Native operation successful.
    pub const AX_OK: ax_status_t = 0;
    /// Native internal error.
    pub const AX_ERR_INTERNAL: ax_status_t = -1;
    /// Native not-supported result.
    pub const AX_ERR_NOT_SUPPORTED: ax_status_t = -2;
    /// Native no-resources result.
    pub const AX_ERR_NO_RESOURCES: ax_status_t = -3;
    /// Native no-memory result.
    pub const AX_ERR_NO_MEMORY: ax_status_t = -4;
    /// Native invalid-args result.
    pub const AX_ERR_INVALID_ARGS: ax_status_t = -10;
    /// Native bad-handle result.
    pub const AX_ERR_BAD_HANDLE: ax_status_t = -11;
    /// Native wrong-type result.
    pub const AX_ERR_WRONG_TYPE: ax_status_t = -12;
    /// Native bad-syscall result.
    pub const AX_ERR_BAD_SYSCALL: ax_status_t = -13;
    /// Native out-of-range result.
    pub const AX_ERR_OUT_OF_RANGE: ax_status_t = -14;
    /// Native buffer-too-small result.
    pub const AX_ERR_BUFFER_TOO_SMALL: ax_status_t = -15;
    /// Native bad-state result.
    pub const AX_ERR_BAD_STATE: ax_status_t = -20;
    /// Native timed-out result.
    pub const AX_ERR_TIMED_OUT: ax_status_t = -21;
    /// Native would-block result.
    pub const AX_ERR_SHOULD_WAIT: ax_status_t = -22;
    /// Native canceled result.
    pub const AX_ERR_CANCELED: ax_status_t = -23;
    /// Native peer-closed result.
    pub const AX_ERR_PEER_CLOSED: ax_status_t = -24;
    /// Native not-found result.
    pub const AX_ERR_NOT_FOUND: ax_status_t = -25;
    /// Native already-exists result.
    pub const AX_ERR_ALREADY_EXISTS: ax_status_t = -26;
    /// Native already-bound result.
    pub const AX_ERR_ALREADY_BOUND: ax_status_t = -27;
    /// Native unavailable result.
    pub const AX_ERR_UNAVAILABLE: ax_status_t = -28;
    /// Native access-denied result.
    pub const AX_ERR_ACCESS_DENIED: ax_status_t = -30;
    /// Native I/O error.
    pub const AX_ERR_IO: ax_status_t = -40;
    /// Native I/O refused error.
    pub const AX_ERR_IO_REFUSED: ax_status_t = -41;
    /// Native data-integrity error.
    pub const AX_ERR_IO_DATA_INTEGRITY: ax_status_t = -42;
    /// Native data-loss error.
    pub const AX_ERR_IO_DATA_LOSS: ax_status_t = -43;
    /// Native device-not-present error.
    pub const AX_ERR_IO_NOT_PRESENT: ax_status_t = -44;
    /// Native I/O overrun error.
    pub const AX_ERR_IO_OVERRUN: ax_status_t = -45;
    /// Native missed-deadline error.
    pub const AX_ERR_IO_MISSED_DEADLINE: ax_status_t = -46;
    /// Native invalid-I/O error.
    pub const AX_ERR_IO_INVALID: ax_status_t = -47;
    /// Native bad-path error.
    pub const AX_ERR_BAD_PATH: ax_status_t = -50;
    /// Native not-directory error.
    pub const AX_ERR_NOT_DIR: ax_status_t = -51;
    /// Native not-file error.
    pub const AX_ERR_NOT_FILE: ax_status_t = -52;
    /// Native file-too-large error.
    pub const AX_ERR_FILE_BIG: ax_status_t = -53;
    /// Native no-space-left error.
    pub const AX_ERR_NO_SPACE: ax_status_t = -54;
    /// Native directory-not-empty error.
    pub const AX_ERR_NOT_EMPTY: ax_status_t = -55;
    /// Native protocol-not-supported error.
    pub const AX_ERR_PROTOCOL_NOT_SUPPORTED: ax_status_t = -70;
    /// Native address-unreachable error.
    pub const AX_ERR_ADDRESS_UNREACHABLE: ax_status_t = -71;
    /// Native address-in-use error.
    pub const AX_ERR_ADDRESS_IN_USE: ax_status_t = -72;
    /// Native not-connected error.
    pub const AX_ERR_NOT_CONNECTED: ax_status_t = -73;
    /// Native connection-refused error.
    pub const AX_ERR_CONNECTION_REFUSED: ax_status_t = -74;
    /// Native connection-reset error.
    pub const AX_ERR_CONNECTION_RESET: ax_status_t = -75;
    /// Native connection-aborted error.
    pub const AX_ERR_CONNECTION_ABORTED: ax_status_t = -76;

    /// Operation successful.
    pub const ZX_OK: zx_status_t = AX_OK as zx_status_t;

    /// Internal error.
    pub const ZX_ERR_INTERNAL: zx_status_t = AX_ERR_INTERNAL as zx_status_t;
    /// Not supported.
    pub const ZX_ERR_NOT_SUPPORTED: zx_status_t = AX_ERR_NOT_SUPPORTED as zx_status_t;
    /// No resources.
    pub const ZX_ERR_NO_RESOURCES: zx_status_t = AX_ERR_NO_RESOURCES as zx_status_t;
    /// No memory.
    pub const ZX_ERR_NO_MEMORY: zx_status_t = AX_ERR_NO_MEMORY as zx_status_t;

    /// Invalid argument(s).
    pub const ZX_ERR_INVALID_ARGS: zx_status_t = AX_ERR_INVALID_ARGS as zx_status_t;
    /// Bad handle.
    pub const ZX_ERR_BAD_HANDLE: zx_status_t = AX_ERR_BAD_HANDLE as zx_status_t;
    /// Wrong object type.
    pub const ZX_ERR_WRONG_TYPE: zx_status_t = AX_ERR_WRONG_TYPE as zx_status_t;
    /// Bad syscall number.
    pub const ZX_ERR_BAD_SYSCALL: zx_status_t = AX_ERR_BAD_SYSCALL as zx_status_t;
    /// Out of range.
    pub const ZX_ERR_OUT_OF_RANGE: zx_status_t = AX_ERR_OUT_OF_RANGE as zx_status_t;
    /// Buffer too small.
    pub const ZX_ERR_BUFFER_TOO_SMALL: zx_status_t = AX_ERR_BUFFER_TOO_SMALL as zx_status_t;

    /// Bad state.
    pub const ZX_ERR_BAD_STATE: zx_status_t = AX_ERR_BAD_STATE as zx_status_t;
    /// Timed out.
    pub const ZX_ERR_TIMED_OUT: zx_status_t = AX_ERR_TIMED_OUT as zx_status_t;
    /// Should wait (would block).
    pub const ZX_ERR_SHOULD_WAIT: zx_status_t = AX_ERR_SHOULD_WAIT as zx_status_t;
    /// Canceled.
    pub const ZX_ERR_CANCELED: zx_status_t = AX_ERR_CANCELED as zx_status_t;
    /// Peer closed.
    pub const ZX_ERR_PEER_CLOSED: zx_status_t = AX_ERR_PEER_CLOSED as zx_status_t;
    /// Not found.
    pub const ZX_ERR_NOT_FOUND: zx_status_t = AX_ERR_NOT_FOUND as zx_status_t;
    /// Already exists.
    pub const ZX_ERR_ALREADY_EXISTS: zx_status_t = AX_ERR_ALREADY_EXISTS as zx_status_t;
    /// Already bound.
    pub const ZX_ERR_ALREADY_BOUND: zx_status_t = AX_ERR_ALREADY_BOUND as zx_status_t;
    /// Unavailable.
    pub const ZX_ERR_UNAVAILABLE: zx_status_t = AX_ERR_UNAVAILABLE as zx_status_t;
    /// Access denied.
    pub const ZX_ERR_ACCESS_DENIED: zx_status_t = AX_ERR_ACCESS_DENIED as zx_status_t;

    /// I/O error.
    pub const ZX_ERR_IO: zx_status_t = AX_ERR_IO as zx_status_t;
    /// Device or peer refused the operation.
    pub const ZX_ERR_IO_REFUSED: zx_status_t = AX_ERR_IO_REFUSED as zx_status_t;
    /// Data integrity / checksum failure.
    pub const ZX_ERR_IO_DATA_INTEGRITY: zx_status_t = AX_ERR_IO_DATA_INTEGRITY as zx_status_t;
    /// Data loss.
    pub const ZX_ERR_IO_DATA_LOSS: zx_status_t = AX_ERR_IO_DATA_LOSS as zx_status_t;
    /// Device not present.
    pub const ZX_ERR_IO_NOT_PRESENT: zx_status_t = AX_ERR_IO_NOT_PRESENT as zx_status_t;
    /// I/O overrun.
    pub const ZX_ERR_IO_OVERRUN: zx_status_t = AX_ERR_IO_OVERRUN as zx_status_t;
    /// Missed I/O deadline.
    pub const ZX_ERR_IO_MISSED_DEADLINE: zx_status_t = AX_ERR_IO_MISSED_DEADLINE as zx_status_t;
    /// Invalid I/O request or payload.
    pub const ZX_ERR_IO_INVALID: zx_status_t = AX_ERR_IO_INVALID as zx_status_t;

    /// Bad or malformed path.
    pub const ZX_ERR_BAD_PATH: zx_status_t = AX_ERR_BAD_PATH as zx_status_t;
    /// Not a directory.
    pub const ZX_ERR_NOT_DIR: zx_status_t = AX_ERR_NOT_DIR as zx_status_t;
    /// Not a regular file.
    pub const ZX_ERR_NOT_FILE: zx_status_t = AX_ERR_NOT_FILE as zx_status_t;
    /// File too large.
    pub const ZX_ERR_FILE_BIG: zx_status_t = AX_ERR_FILE_BIG as zx_status_t;
    /// No space left.
    pub const ZX_ERR_NO_SPACE: zx_status_t = AX_ERR_NO_SPACE as zx_status_t;
    /// Directory not empty.
    pub const ZX_ERR_NOT_EMPTY: zx_status_t = AX_ERR_NOT_EMPTY as zx_status_t;

    /// Protocol not supported.
    pub const ZX_ERR_PROTOCOL_NOT_SUPPORTED: zx_status_t =
        AX_ERR_PROTOCOL_NOT_SUPPORTED as zx_status_t;
    /// Address unreachable.
    pub const ZX_ERR_ADDRESS_UNREACHABLE: zx_status_t = AX_ERR_ADDRESS_UNREACHABLE as zx_status_t;
    /// Address already in use.
    pub const ZX_ERR_ADDRESS_IN_USE: zx_status_t = AX_ERR_ADDRESS_IN_USE as zx_status_t;
    /// Not connected.
    pub const ZX_ERR_NOT_CONNECTED: zx_status_t = AX_ERR_NOT_CONNECTED as zx_status_t;
    /// Connection refused.
    pub const ZX_ERR_CONNECTION_REFUSED: zx_status_t = AX_ERR_CONNECTION_REFUSED as zx_status_t;
    /// Connection reset.
    pub const ZX_ERR_CONNECTION_RESET: zx_status_t = AX_ERR_CONNECTION_RESET as zx_status_t;
    /// Connection aborted.
    pub const ZX_ERR_CONNECTION_ABORTED: zx_status_t = AX_ERR_CONNECTION_ABORTED as zx_status_t;
}

/// Signals bitmask constants.
///
/// Values follow Zircon's `zircon/types.h`.
pub mod signals {
    use super::{ax_signals_t, zx_signals_t};

    /// No native signals.
    pub const AX_SIGNAL_NONE: ax_signals_t = 0;
    /// Native readable signal.
    pub const AX_OBJECT_READABLE: ax_signals_t = 1u32 << 0;
    /// Native writable signal.
    pub const AX_OBJECT_WRITABLE: ax_signals_t = 1u32 << 1;
    /// Native peer-closed signal.
    pub const AX_OBJECT_PEER_CLOSED: ax_signals_t = 1u32 << 2;
    /// Native signaled bit.
    pub const AX_OBJECT_SIGNALED: ax_signals_t = 1u32 << 3;
    /// Native handle-closed cancellation signal.
    pub const AX_SIGNAL_HANDLE_CLOSED: ax_signals_t = 1u32 << 23;
    /// Native user signal mask (bits 24..31).
    pub const AX_USER_SIGNAL_ALL: ax_signals_t = 0xff00_0000;
    /// Native user signal 0.
    pub const AX_USER_SIGNAL_0: ax_signals_t = 1u32 << 24;
    /// Native user signal 1.
    pub const AX_USER_SIGNAL_1: ax_signals_t = 1u32 << 25;
    /// Native user signal 2.
    pub const AX_USER_SIGNAL_2: ax_signals_t = 1u32 << 26;
    /// Native user signal 3.
    pub const AX_USER_SIGNAL_3: ax_signals_t = 1u32 << 27;
    /// Native user signal 4.
    pub const AX_USER_SIGNAL_4: ax_signals_t = 1u32 << 28;
    /// Native user signal 5.
    pub const AX_USER_SIGNAL_5: ax_signals_t = 1u32 << 29;
    /// Native user signal 6.
    pub const AX_USER_SIGNAL_6: ax_signals_t = 1u32 << 30;
    /// Native user signal 7.
    pub const AX_USER_SIGNAL_7: ax_signals_t = 1u32 << 31;
    /// Native channel readable alias.
    pub const AX_CHANNEL_READABLE: ax_signals_t = AX_OBJECT_READABLE;
    /// Native channel writable alias.
    pub const AX_CHANNEL_WRITABLE: ax_signals_t = AX_OBJECT_WRITABLE;
    /// Native channel peer-closed alias.
    pub const AX_CHANNEL_PEER_CLOSED: ax_signals_t = AX_OBJECT_PEER_CLOSED;
    /// Native socket readable alias.
    pub const AX_SOCKET_READABLE: ax_signals_t = AX_OBJECT_READABLE;
    /// Native socket writable alias.
    pub const AX_SOCKET_WRITABLE: ax_signals_t = AX_OBJECT_WRITABLE;
    /// Native socket peer-closed alias.
    pub const AX_SOCKET_PEER_CLOSED: ax_signals_t = AX_OBJECT_PEER_CLOSED;
    /// Native timer signaled alias.
    pub const AX_TIMER_SIGNALED: ax_signals_t = AX_OBJECT_SIGNALED;
    /// Native interrupt signaled alias.
    pub const AX_INTERRUPT_SIGNALED: ax_signals_t = AX_OBJECT_SIGNALED;
    /// Native task terminated alias.
    pub const AX_TASK_TERMINATED: ax_signals_t = AX_OBJECT_SIGNALED;

    /// No signals.
    pub const ZX_SIGNAL_NONE: zx_signals_t = AX_SIGNAL_NONE as zx_signals_t;

    // Common object signals (implementation details in Zircon header, but stable in practice).
    /// Readable.
    pub const ZX_OBJECT_READABLE: zx_signals_t = AX_OBJECT_READABLE as zx_signals_t;
    /// Writable.
    pub const ZX_OBJECT_WRITABLE: zx_signals_t = AX_OBJECT_WRITABLE as zx_signals_t;
    /// Peer closed.
    pub const ZX_OBJECT_PEER_CLOSED: zx_signals_t = AX_OBJECT_PEER_CLOSED as zx_signals_t;
    /// Signaled.
    pub const ZX_OBJECT_SIGNALED: zx_signals_t = AX_OBJECT_SIGNALED as zx_signals_t;

    /// Handle closed (cancellation).
    pub const ZX_SIGNAL_HANDLE_CLOSED: zx_signals_t = AX_SIGNAL_HANDLE_CLOSED as zx_signals_t;

    /// User signals mask (bits 24..31).
    pub const ZX_USER_SIGNAL_ALL: zx_signals_t = AX_USER_SIGNAL_ALL as zx_signals_t;

    /// User signal 0.
    pub const ZX_USER_SIGNAL_0: zx_signals_t = AX_USER_SIGNAL_0 as zx_signals_t;
    /// User signal 1.
    pub const ZX_USER_SIGNAL_1: zx_signals_t = AX_USER_SIGNAL_1 as zx_signals_t;
    /// User signal 2.
    pub const ZX_USER_SIGNAL_2: zx_signals_t = AX_USER_SIGNAL_2 as zx_signals_t;
    /// User signal 3.
    pub const ZX_USER_SIGNAL_3: zx_signals_t = AX_USER_SIGNAL_3 as zx_signals_t;
    /// User signal 4.
    pub const ZX_USER_SIGNAL_4: zx_signals_t = AX_USER_SIGNAL_4 as zx_signals_t;
    /// User signal 5.
    pub const ZX_USER_SIGNAL_5: zx_signals_t = AX_USER_SIGNAL_5 as zx_signals_t;
    /// User signal 6.
    pub const ZX_USER_SIGNAL_6: zx_signals_t = AX_USER_SIGNAL_6 as zx_signals_t;
    /// User signal 7.
    pub const ZX_USER_SIGNAL_7: zx_signals_t = AX_USER_SIGNAL_7 as zx_signals_t;

    // Aliases (object-specific names).
    /// Channel readable.
    pub const ZX_CHANNEL_READABLE: zx_signals_t = AX_CHANNEL_READABLE as zx_signals_t;
    /// Channel writable.
    pub const ZX_CHANNEL_WRITABLE: zx_signals_t = AX_CHANNEL_WRITABLE as zx_signals_t;
    /// Channel peer closed.
    pub const ZX_CHANNEL_PEER_CLOSED: zx_signals_t = AX_CHANNEL_PEER_CLOSED as zx_signals_t;

    /// Socket readable.
    pub const ZX_SOCKET_READABLE: zx_signals_t = AX_SOCKET_READABLE as zx_signals_t;
    /// Socket writable.
    pub const ZX_SOCKET_WRITABLE: zx_signals_t = AX_SOCKET_WRITABLE as zx_signals_t;
    /// Socket peer closed.
    pub const ZX_SOCKET_PEER_CLOSED: zx_signals_t = AX_SOCKET_PEER_CLOSED as zx_signals_t;

    /// Timer signaled.
    pub const ZX_TIMER_SIGNALED: zx_signals_t = AX_TIMER_SIGNALED as zx_signals_t;
    /// Interrupt signaled.
    pub const ZX_INTERRUPT_SIGNALED: zx_signals_t = AX_INTERRUPT_SIGNALED as zx_signals_t;

    /// Task terminated.
    pub const ZX_TASK_TERMINATED: zx_signals_t = AX_TASK_TERMINATED as zx_signals_t;
}

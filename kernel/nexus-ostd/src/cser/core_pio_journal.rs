// SPDX-License-Identifier: MPL-2.0

//! Bounded ATA PIO persistence provider for the portable CSER journal.
//!
//! The fixture is a dedicated QEMU ATA fixed disk.  It deliberately does not
//! share the VirtIO DMA owner used by the device-recovery slice.  Every ATA
//! register is acquired through OSTD's linear [`IoPort`] allocator.
//!
//! The on-disk format is a two-bank copy-on-write image:
//!
//! 1. write the complete next logical journal into the inactive bank;
//! 2. issue ATA `FLUSH CACHE`;
//! 3. write that bank's generation/length/payload-digest header; and
//! 4. issue ATA `FLUSH CACHE` again.
//!
//! A bank is eligible only when both its header checksum and the digest of its
//! exact logical payload validate.  A torn payload or header therefore leaves
//! the previous bank authoritative.  Repair publishes the exact accepted
//! prefix as another generation; it never silently rounds a core-provided
//! repair offset to a sector boundary.
//!
//! Evidence boundary: QEMU raw-image persistence plus an acknowledged ATA
//! flush exercises a real kernel/PIO/device-model command path.  It is not
//! evidence for physical-media power-loss behavior, controller capacitor
//! behavior, or host-filesystem durability.  The journal is also rollbackable
//! with its raw image, so cross-restart freshness still requires an independent
//! non-rollback [`cser_core::TrustedAnchorBackend`].

use alloc::vec::Vec;
use core::{hint::spin_loop, mem::size_of};

use cser_core::{DurableJournalBackend, JournalRecord, JournalRepair};
use ostd::{arch::device::io_port::ReadWriteAccess, io::IoPort};
use sha2::{Digest as _, Sha256};

use crate::core_reboot::OstdBootJournal;

pub(crate) const SECTOR_BYTES: usize = 512;
const WORDS_PER_SECTOR: usize = SECTOR_BYTES / size_of::<u16>();

// LBA 0 is left untouched so an accidental attachment remains recognizable to
// ordinary disk tooling.  Each bank owns one header sector and 128 data
// sectors.  The resulting 64-KiB cap is intentional backpressure, not an
// expandable allocation or overwrite policy.
const FIRST_BANK_LBA: u32 = 1;
const BANK_DATA_SECTORS: u32 = 128;
const BANK_SECTORS: u32 = 1 + BANK_DATA_SECTORS;
const REQUIRED_SECTORS: u32 = FIRST_BANK_LBA + 2 * BANK_SECTORS;
const JOURNAL_CAPACITY: usize = BANK_DATA_SECTORS as usize * SECTOR_BYTES;

// vNext deliberately lives after the currently deployed two-bank format.  It
// is not selected by `AtaPioJournal` yet: a CSER journal stream has no
// snapshot/checkpoint record from which a generic provider may safely discard
// old transitions.  Keeping the format disjoint lets development exercise the
// append protocol without silently changing the deployed recovery contract.
const VNEXT_FIRST_SEGMENT_LBA: u32 = REQUIRED_SECTORS;
// Three live segments plus three alternate segments make an exact-prefix
// repair/checkpoint possible without overwriting the manifest-selected chain.
const VNEXT_SEGMENT_COUNT: u32 = 6;
const VNEXT_LIVE_SEGMENT_LIMIT: usize = 3;
const VNEXT_HEADER_COPIES: u32 = 2;
const VNEXT_SEGMENT_SECTORS: u32 = VNEXT_HEADER_COPIES + BANK_DATA_SECTORS;
const VNEXT_MANIFEST_LBA: u32 =
    VNEXT_FIRST_SEGMENT_LBA + VNEXT_SEGMENT_COUNT * VNEXT_SEGMENT_SECTORS;
const VNEXT_REQUIRED_SECTORS: u32 = VNEXT_MANIFEST_LBA + VNEXT_HEADER_COPIES;
const VNEXT_SEGMENT_CAPACITY: usize = BANK_DATA_SECTORS as usize * SECTOR_BYTES;
const VNEXT_CAPACITY: usize = VNEXT_LIVE_SEGMENT_LIMIT * VNEXT_SEGMENT_CAPACITY;

const BANK_MAGIC: [u8; 8] = *b"CSERPIO\0";
const BANK_VERSION: u16 = 1;
const HEADER_LEN: u16 = 112;
const HEADER_HASH_OFFSET: usize = 80;
const HEADER_HASH_END: usize = 112;

const VNEXT_MAGIC: [u8; 8] = *b"CSERAP2\0";
const VNEXT_MANIFEST_MAGIC: [u8; 8] = *b"CSERMN2\0";
const VNEXT_VERSION: u16 = 2;
const VNEXT_HEADER_LEN: u16 = 176;
const VNEXT_HEADER_HASH_OFFSET: usize = 144;
const VNEXT_HEADER_HASH_END: usize = 176;
const VNEXT_FRAME_MAGIC: [u8; 8] = *b"CSERFR2\0";
const VNEXT_FRAME_HEADER: usize = 48;

const ATA_PRIMARY_BASE: u16 = 0x01f0;
const ATA_PRIMARY_CONTROL: u16 = 0x03f6;
const ATA_SECONDARY_BASE: u16 = 0x0170;
const ATA_SECONDARY_CONTROL: u16 = 0x0376;

const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_FLUSH_CACHE: u8 = 0xe7;
const ATA_CMD_IDENTIFY_DEVICE: u8 = 0xec;
const ATA_CONTROL_NIEN: u8 = 1 << 1;

const ATA_STATUS_ERR: u8 = 1 << 0;
const ATA_STATUS_DRQ: u8 = 1 << 3;
const ATA_STATUS_DF: u8 = 1 << 5;
const ATA_STATUS_DRDY: u8 = 1 << 6;
const ATA_STATUS_BSY: u8 = 1 << 7;

const IDENTIFY_CAPABILITIES: usize = 49;
const IDENTIFY_COMMAND_SET_2: usize = 83;
const IDENTIFY_SECTOR_COUNT_LOW: usize = 60;
const IDENTIFY_SECTOR_COUNT_HIGH: usize = 61;
const IDENTIFY_SECTOR_SIZE: usize = 106;
const IDENTIFY_LOGICAL_WORDS_LOW: usize = 117;
const IDENTIFY_LOGICAL_WORDS_HIGH: usize = 118;

const IDENTIFY_LBA_SUPPORTED: u16 = 1 << 9;
const IDENTIFY_FLUSH_CACHE_SUPPORTED: u16 = 1 << 12;
const IDENTIFY_WORD_VALID_MASK: u16 = 0xc000;
const IDENTIFY_WORD_VALID: u16 = 0x4000;
const IDENTIFY_LONG_LOGICAL_SECTOR: u16 = 1 << 12;
const IDENTIFY_REMOVABLE_MEDIA: u16 = 1 << 7;
const LBA28_MAX: u32 = 0x0fff_ffff;

// This is a bounded spin count rather than an elapsed-time claim.  The caller
// remains fail-closed when an emulated or physical device never progresses.
const ATA_POLL_LIMIT: u32 = 10_000_000;

/// Explicit ATA attachment chosen by the boot profile.
///
/// The journal never probes every disk looking for a convenient target.
/// Selecting a fixture is therefore an explicit destructive ownership
/// decision made by the QEMU/boot configuration.
///
/// A `q35 -nodefaults` machine does not imply legacy command-block decoding.
/// The QEMU profile must attach an explicit legacy controller, for example
/// `-device piix3-ide,id=legacy-ide` plus an `ide-hd` on the selected bus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum AtaJournalFixture {
    PrimaryMaster,
    PrimarySlave,
    SecondaryMaster,
    SecondarySlave,
}

impl AtaJournalFixture {
    const fn coordinates(self) -> (u16, u16, AtaDrive) {
        match self {
            Self::PrimaryMaster => (ATA_PRIMARY_BASE, ATA_PRIMARY_CONTROL, AtaDrive::Master),
            Self::PrimarySlave => (ATA_PRIMARY_BASE, ATA_PRIMARY_CONTROL, AtaDrive::Slave),
            Self::SecondaryMaster => (ATA_SECONDARY_BASE, ATA_SECONDARY_CONTROL, AtaDrive::Master),
            Self::SecondarySlave => (ATA_SECONDARY_BASE, ATA_SECONDARY_CONTROL, AtaDrive::Slave),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtaDrive {
    Master,
    Slave,
}

impl AtaDrive {
    const fn select_bit(self) -> u8 {
        match self {
            Self::Master => 0,
            Self::Slave => 1 << 4,
        }
    }
}

/// Bounded ATA command phase reported by timeout/error diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtaOperation {
    Select,
    Identify,
    Read,
    Write,
    Flush,
}

/// Failure from ATA discovery or one PIO command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtaPioError {
    /// Another OSTD owner already owns one register in this ATA channel.
    PortBusy { port: u16 },
    /// Status was zero or floating-bus `0xff`; no ATA device answered.
    NoDevice,
    /// IDENTIFY reported a packet-device signature instead of an ATA disk.
    PacketDevice { lba_mid: u8, lba_high: u8 },
    /// The selected device is removable rather than a fixed fixture.
    RemovableDevice,
    /// The disk does not support LBA addressing.
    LbaUnsupported,
    /// The disk does not advertise the `FLUSH CACHE` command.
    FlushCacheUnsupported,
    /// This provider intentionally supports only 512-byte logical sectors.
    UnsupportedLogicalSector { words: u32 },
    /// IDENTIFY returned no usable LBA28 sectors.
    InvalidCapacity,
    /// The fixed two-bank region does not fit on the disk.
    DeviceTooSmall { sectors: u32, required: u32 },
    /// A request escaped either the device or LBA28 address space.
    LbaOutOfRange { lba: u32, sectors: u32 },
    /// The status register did not reach the required state.
    Timeout { operation: AtaOperation, status: u8 },
    /// ATA reported its device-fault bit.
    DeviceFault { operation: AtaOperation, status: u8 },
    /// ATA reported its error bit and error register.
    DeviceError {
        operation: AtaOperation,
        status: u8,
        error: u8,
    },
    /// A command completed in a state inconsistent with its protocol.
    UnexpectedStatus { operation: AtaOperation, status: u8 },
}

/// Journal-format or underlying-sector failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BankedJournalError<E> {
    Storage(E),
    DeviceTooSmall {
        sectors: u32,
        required: u32,
    },
    JournalFull {
        current: usize,
        additional: usize,
        capacity: usize,
    },
    AllocationFailed {
        requested: usize,
    },
    CorruptBankMetadata,
    ConflictingGeneration {
        generation: u64,
    },
    GenerationExhausted,
    InvalidRepairOffset {
        offset: usize,
        length: usize,
    },
    ReadbackMismatch,
}

pub(crate) type AtaPioJournalError = BankedJournalError<AtaPioError>;

/// Minimal fixed-sector contract shared by the journal and other dedicated
/// polling-only ATA persistence providers.
///
/// This remains crate-private: it is a mechanical transport primitive, not a
/// second durability or recovery authority.
pub(crate) trait SectorBackend {
    type Error;

    fn sector_count(&self) -> u32;
    fn read_sector(&mut self, lba: u32, output: &mut [u8; SECTOR_BYTES])
    -> Result<(), Self::Error>;
    fn write_sector(&mut self, lba: u32, input: &[u8; SECTOR_BYTES]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug)]
struct AtaPorts {
    // A 16-bit transfer at the ATA data register still names one hardware
    // register. `acquire_overlapping` prevents OSTD's width-based allocator
    // from incorrectly consuming the adjacent error/features register; every
    // actual register remains separately and linearly owned below.
    data: IoPort<u16, ReadWriteAccess>,
    error_features: IoPort<u8, ReadWriteAccess>,
    sector_count: IoPort<u8, ReadWriteAccess>,
    lba_low: IoPort<u8, ReadWriteAccess>,
    lba_mid: IoPort<u8, ReadWriteAccess>,
    lba_high: IoPort<u8, ReadWriteAccess>,
    drive_head: IoPort<u8, ReadWriteAccess>,
    status_command: IoPort<u8, ReadWriteAccess>,
    alternate_status_control: IoPort<u8, ReadWriteAccess>,
}

impl AtaPorts {
    fn acquire(base: u16, control: u16) -> Result<Self, AtaPioError> {
        let data =
            IoPort::acquire_overlapping(base).map_err(|_| AtaPioError::PortBusy { port: base })?;
        let error_features =
            IoPort::acquire(base + 1).map_err(|_| AtaPioError::PortBusy { port: base + 1 })?;
        let sector_count =
            IoPort::acquire(base + 2).map_err(|_| AtaPioError::PortBusy { port: base + 2 })?;
        let lba_low =
            IoPort::acquire(base + 3).map_err(|_| AtaPioError::PortBusy { port: base + 3 })?;
        let lba_mid =
            IoPort::acquire(base + 4).map_err(|_| AtaPioError::PortBusy { port: base + 4 })?;
        let lba_high =
            IoPort::acquire(base + 5).map_err(|_| AtaPioError::PortBusy { port: base + 5 })?;
        let drive_head =
            IoPort::acquire(base + 6).map_err(|_| AtaPioError::PortBusy { port: base + 6 })?;
        let status_command =
            IoPort::acquire(base + 7).map_err(|_| AtaPioError::PortBusy { port: base + 7 })?;
        let alternate_status_control =
            IoPort::acquire(control).map_err(|_| AtaPioError::PortBusy { port: control })?;

        Ok(Self {
            data,
            error_features,
            sector_count,
            lba_low,
            lba_mid,
            lba_high,
            drive_head,
            status_command,
            alternate_status_control,
        })
    }

    fn delay_400ns(&self) {
        for _ in 0..4 {
            let _ = self.alternate_status_control.read();
        }
    }
}

/// Linear owner of one detected 512-byte-sector ATA fixed disk.
#[derive(Debug)]
pub(crate) struct AtaPioDisk {
    ports: AtaPorts,
    drive: AtaDrive,
    sectors: u32,
}

impl AtaPioDisk {
    pub(crate) fn acquire(fixture: AtaJournalFixture) -> Result<Self, AtaPioError> {
        let (base, control, drive) = fixture.coordinates();
        let ports = AtaPorts::acquire(base, control)?;
        // This owner is polling-only.  Mask device-generated legacy IRQs
        // before issuing IDENTIFY so no completion escapes to an unowned
        // IRQ14/IRQ15 path.
        ports.alternate_status_control.write(ATA_CONTROL_NIEN);
        ports.delay_400ns();
        let mut disk = Self {
            ports,
            drive,
            sectors: 0,
        };
        disk.identify()?;
        if disk.sectors < REQUIRED_SECTORS {
            return Err(AtaPioError::DeviceTooSmall {
                sectors: disk.sectors,
                required: REQUIRED_SECTORS,
            });
        }
        Ok(disk)
    }

    fn identify(&mut self) -> Result<(), AtaPioError> {
        self.wait_not_busy(AtaOperation::Select)?;
        self.ports.drive_head.write(0xa0 | self.drive.select_bit());
        self.ports.delay_400ns();
        self.wait_not_busy(AtaOperation::Select)?;

        self.ports.sector_count.write(0);
        self.ports.lba_low.write(0);
        self.ports.lba_mid.write(0);
        self.ports.lba_high.write(0);
        self.ports.status_command.write(ATA_CMD_IDENTIFY_DEVICE);

        let initial = self.ports.status_command.read();
        if initial == 0 || initial == u8::MAX {
            return Err(AtaPioError::NoDevice);
        }
        self.wait_not_busy(AtaOperation::Identify)?;

        let lba_mid = self.ports.lba_mid.read();
        let lba_high = self.ports.lba_high.read();
        if lba_mid != 0 || lba_high != 0 {
            return Err(AtaPioError::PacketDevice { lba_mid, lba_high });
        }
        self.check_error_bits(AtaOperation::Identify, self.ports.status_command.read())?;
        self.wait_data_request(AtaOperation::Identify)?;

        let mut words = [0u16; WORDS_PER_SECTOR];
        for word in &mut words {
            *word = self.ports.data.read();
        }
        self.wait_command_complete(AtaOperation::Identify)?;

        if words[0] & IDENTIFY_REMOVABLE_MEDIA != 0 {
            return Err(AtaPioError::RemovableDevice);
        }
        if words[IDENTIFY_CAPABILITIES] & IDENTIFY_LBA_SUPPORTED == 0 {
            return Err(AtaPioError::LbaUnsupported);
        }
        if words[IDENTIFY_COMMAND_SET_2] & IDENTIFY_WORD_VALID_MASK != IDENTIFY_WORD_VALID
            || words[IDENTIFY_COMMAND_SET_2] & IDENTIFY_FLUSH_CACHE_SUPPORTED == 0
        {
            return Err(AtaPioError::FlushCacheUnsupported);
        }

        let sector_size = words[IDENTIFY_SECTOR_SIZE];
        if sector_size & IDENTIFY_WORD_VALID_MASK == IDENTIFY_WORD_VALID
            && sector_size & IDENTIFY_LONG_LOGICAL_SECTOR != 0
        {
            let logical_words = u32::from(words[IDENTIFY_LOGICAL_WORDS_LOW])
                | (u32::from(words[IDENTIFY_LOGICAL_WORDS_HIGH]) << 16);
            if logical_words != WORDS_PER_SECTOR as u32 {
                return Err(AtaPioError::UnsupportedLogicalSector {
                    words: logical_words,
                });
            }
        }

        let reported = u32::from(words[IDENTIFY_SECTOR_COUNT_LOW])
            | (u32::from(words[IDENTIFY_SECTOR_COUNT_HIGH]) << 16);
        if reported == 0 {
            return Err(AtaPioError::InvalidCapacity);
        }
        // A 28-bit command can address LBAs 0..=0x0fff_ffff, i.e. at most
        // 0x1000_0000 sectors.
        self.sectors = reported.min(LBA28_MAX + 1);
        Ok(())
    }

    fn select_lba(&self, lba: u32, operation: AtaOperation) -> Result<(), AtaPioError> {
        self.check_lba(lba)?;
        self.wait_not_busy(operation)?;
        self.ports
            .drive_head
            .write(0xe0 | self.drive.select_bit() | ((lba >> 24) & 0x0f) as u8);
        self.ports.delay_400ns();
        self.wait_not_busy(operation)?;
        self.ports.error_features.write(0);
        self.ports.sector_count.write(1);
        self.ports.lba_low.write(lba as u8);
        self.ports.lba_mid.write((lba >> 8) as u8);
        self.ports.lba_high.write((lba >> 16) as u8);
        Ok(())
    }

    fn check_lba(&self, lba: u32) -> Result<(), AtaPioError> {
        if lba >= self.sectors || lba > LBA28_MAX {
            return Err(AtaPioError::LbaOutOfRange {
                lba,
                sectors: self.sectors,
            });
        }
        Ok(())
    }

    fn read_one(&mut self, lba: u32, output: &mut [u8; SECTOR_BYTES]) -> Result<(), AtaPioError> {
        self.select_lba(lba, AtaOperation::Read)?;
        self.ports.status_command.write(ATA_CMD_READ_SECTORS);
        self.wait_data_request(AtaOperation::Read)?;
        for chunk in output.chunks_exact_mut(2) {
            chunk.copy_from_slice(&self.ports.data.read().to_le_bytes());
        }
        self.wait_command_complete(AtaOperation::Read)
    }

    fn write_one(&mut self, lba: u32, input: &[u8; SECTOR_BYTES]) -> Result<(), AtaPioError> {
        self.select_lba(lba, AtaOperation::Write)?;
        self.ports.status_command.write(ATA_CMD_WRITE_SECTORS);
        self.wait_data_request(AtaOperation::Write)?;
        for chunk in input.chunks_exact(2) {
            self.ports
                .data
                .write(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        self.wait_command_complete(AtaOperation::Write)
    }

    fn flush_cache(&mut self) -> Result<(), AtaPioError> {
        self.wait_not_busy(AtaOperation::Flush)?;
        self.ports.drive_head.write(0xe0 | self.drive.select_bit());
        self.ports.delay_400ns();
        self.wait_not_busy(AtaOperation::Flush)?;
        self.ports.status_command.write(ATA_CMD_FLUSH_CACHE);
        self.wait_command_complete(AtaOperation::Flush)
    }

    fn wait_not_busy(&self, operation: AtaOperation) -> Result<(), AtaPioError> {
        let mut last = 0u8;
        for _ in 0..ATA_POLL_LIMIT {
            last = self.ports.status_command.read();
            if last == 0 || last == u8::MAX {
                return Err(AtaPioError::NoDevice);
            }
            if last & ATA_STATUS_BSY == 0 {
                return Ok(());
            }
            spin_loop();
        }
        Err(AtaPioError::Timeout {
            operation,
            status: last,
        })
    }

    fn wait_data_request(&self, operation: AtaOperation) -> Result<(), AtaPioError> {
        let mut last = 0u8;
        for _ in 0..ATA_POLL_LIMIT {
            last = self.ports.status_command.read();
            if last == 0 || last == u8::MAX {
                return Err(AtaPioError::NoDevice);
            }
            if last & ATA_STATUS_BSY == 0 {
                self.check_error_bits(operation, last)?;
                if last & ATA_STATUS_DRQ != 0 {
                    return Ok(());
                }
            }
            spin_loop();
        }
        Err(AtaPioError::Timeout {
            operation,
            status: last,
        })
    }

    fn wait_command_complete(&self, operation: AtaOperation) -> Result<(), AtaPioError> {
        let mut last = 0u8;
        for _ in 0..ATA_POLL_LIMIT {
            last = self.ports.status_command.read();
            if last == 0 || last == u8::MAX {
                return Err(AtaPioError::NoDevice);
            }
            if last & (ATA_STATUS_BSY | ATA_STATUS_DRQ) == 0 {
                self.check_error_bits(operation, last)?;
                if last & ATA_STATUS_DRDY != 0 {
                    return Ok(());
                }
                return Err(AtaPioError::UnexpectedStatus {
                    operation,
                    status: last,
                });
            }
            spin_loop();
        }
        Err(AtaPioError::Timeout {
            operation,
            status: last,
        })
    }

    fn check_error_bits(&self, operation: AtaOperation, status: u8) -> Result<(), AtaPioError> {
        if status & ATA_STATUS_DF != 0 {
            return Err(AtaPioError::DeviceFault { operation, status });
        }
        if status & ATA_STATUS_ERR != 0 {
            return Err(AtaPioError::DeviceError {
                operation,
                status,
                error: self.ports.error_features.read(),
            });
        }
        Ok(())
    }
}

impl SectorBackend for AtaPioDisk {
    type Error = AtaPioError;

    fn sector_count(&self) -> u32 {
        self.sectors
    }

    fn read_sector(
        &mut self,
        lba: u32,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), Self::Error> {
        self.read_one(lba, output)
    }

    fn write_sector(&mut self, lba: u32, input: &[u8; SECTOR_BYTES]) -> Result<(), Self::Error> {
        self.write_one(lba, input)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.flush_cache()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BankHeader {
    bank: u32,
    generation: u64,
    logical_len: usize,
    payload_digest: [u8; 32],
}

impl BankHeader {
    fn encode(self) -> [u8; SECTOR_BYTES] {
        let mut bytes = [0u8; SECTOR_BYTES];
        bytes[..8].copy_from_slice(&BANK_MAGIC);
        bytes[8..10].copy_from_slice(&BANK_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&HEADER_LEN.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.bank.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&(self.logical_len as u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(JOURNAL_CAPACITY as u64).to_le_bytes());
        bytes[48..80].copy_from_slice(&self.payload_digest);
        let header_digest: [u8; 32] = Sha256::digest(&bytes[..HEADER_HASH_OFFSET]).into();
        bytes[HEADER_HASH_OFFSET..HEADER_HASH_END].copy_from_slice(&header_digest);
        bytes
    }

    fn decode(expected_bank: u32, bytes: &[u8; SECTOR_BYTES]) -> HeaderInspection {
        if bytes.iter().all(|byte| *byte == 0) {
            return HeaderInspection::Blank;
        }
        if bytes[..8] != BANK_MAGIC
            || read_u16(bytes, 8) != BANK_VERSION
            || read_u16(bytes, 10) != HEADER_LEN
            || read_u32(bytes, 12) != expected_bank
            || read_u64(bytes, 16) == 0
            || read_u64(bytes, 32) != JOURNAL_CAPACITY as u64
            || bytes[40..48].iter().any(|byte| *byte != 0)
            || bytes[HEADER_HASH_END..].iter().any(|byte| *byte != 0)
        {
            return HeaderInspection::Invalid;
        }
        let expected_digest: [u8; 32] = Sha256::digest(&bytes[..HEADER_HASH_OFFSET]).into();
        if bytes[HEADER_HASH_OFFSET..HEADER_HASH_END] != expected_digest {
            return HeaderInspection::Invalid;
        }
        let logical_len_u64 = read_u64(bytes, 24);
        let Ok(logical_len) = usize::try_from(logical_len_u64) else {
            return HeaderInspection::Invalid;
        };
        if logical_len > JOURNAL_CAPACITY {
            return HeaderInspection::Invalid;
        }
        let mut payload_digest = [0u8; 32];
        payload_digest.copy_from_slice(&bytes[48..80]);
        HeaderInspection::Valid(Self {
            bank: expected_bank,
            generation: read_u64(bytes, 16),
            logical_len,
            payload_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderInspection {
    Blank,
    Invalid,
    Valid(BankHeader),
}

#[derive(Debug)]
enum BankInspection {
    Blank,
    Invalid,
    Valid(ActiveImage),
}

#[derive(Clone, Debug)]
struct ActiveImage {
    bank: Option<u32>,
    generation: u64,
    bytes: Vec<u8>,
}

/// Default-off, operation-level accounting for the bounded journal.
///
/// Counters are updated at the provider boundary, so they describe the sector
/// transfers, flushes, and payload hashes actually requested by this layer.
/// They intentionally do not turn ATA completion into a byte-accurate device
/// claim.  The x86 TSC values are diagnostic phase stamps only; they are not
/// wall-clock measurements and remain zero on non-x86 targets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct JournalIoTelemetry {
    pub(crate) sectors_read: u64,
    pub(crate) sectors_written: u64,
    pub(crate) flushes: u64,
    pub(crate) hash_bytes: u64,
    pub(crate) phase_tsc: [u64; 6],
}

/// Publication phases indexed by [`JournalIoTelemetry::phase_tsc`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum JournalIoPhase {
    PayloadWritten = 0,
    PayloadFlushed = 1,
    HeaderWritten = 2,
    HeaderFlushed = 3,
    ReadbackValidated = 4,
    CacheUpdated = 5,
}

/// A self-contained durable record selected by the ATA double-bank protocol.
///
/// This is intentionally not a CSER journal record.  Experiments can use the
/// exact same PIO, flush, and readback path to persist a small independent
/// state machine without acquiring `Engine` or `JournalRecord` authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AtaDoubleBankSnapshot {
    revision: u64,
    digest: [u8; 32],
    bytes: Vec<u8>,
}

impl AtaDoubleBankSnapshot {
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Error from the experiment-only raw-record durability facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AtaDoubleBankError<E> {
    Banked(BankedJournalError<E>),
    RevisionMismatch { expected: u64, supplied: u64 },
}

#[derive(Debug)]
struct BankedJournal<B> {
    backend: B,
    // The provider owns its dedicated fixture exclusively.  No other writer
    // may mutate the two banks while this object is live; reopening validates
    // both banks again before establishing a new cache.
    active: ActiveImage,
    // Disabled in production unless an owner explicitly opts in.  Keeping the
    // field absent from the default path avoids changing the measurement
    // envelope that the journal is intended to observe.
    telemetry: Option<JournalIoTelemetry>,
}

impl<B> BankedJournal<B>
where
    B: SectorBackend,
{
    fn open(backend: B) -> Result<Self, BankedJournalError<B::Error>> {
        Self::open_validated(backend, false)
    }

    fn open_strict(backend: B) -> Result<Self, BankedJournalError<B::Error>> {
        Self::open_validated(backend, true)
    }

    fn open_validated(backend: B, strict: bool) -> Result<Self, BankedJournalError<B::Error>> {
        let sectors = backend.sector_count();
        if sectors < REQUIRED_SECTORS {
            return Err(BankedJournalError::DeviceTooSmall {
                sectors,
                required: REQUIRED_SECTORS,
            });
        }
        let mut journal = Self {
            backend,
            active: ActiveImage {
                bank: None,
                generation: 0,
                bytes: Vec::new(),
            },
            telemetry: None,
        };
        // Validate both banks once before trusting a cache.  Subsequent
        // operations retain exclusive ownership and update it only after a
        // complete new-bank readback succeeds.
        journal.active = if strict {
            journal.read_active_strict()?
        } else {
            journal.read_active()?
        };
        Ok(journal)
    }

    fn read_all_image(&mut self) -> Result<Vec<u8>, BankedJournalError<B::Error>> {
        Ok(self.active.bytes.clone())
    }

    fn append_exact(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        let mut active = self.active.clone();
        let resulting_len = active.bytes.len().checked_add(suffix.len()).ok_or(
            BankedJournalError::JournalFull {
                current: active.bytes.len(),
                additional: suffix.len(),
                capacity: JOURNAL_CAPACITY,
            },
        )?;
        if resulting_len > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: active.bytes.len(),
                additional: suffix.len(),
                capacity: JOURNAL_CAPACITY,
            });
        }
        active.bytes.try_reserve_exact(suffix.len()).map_err(|_| {
            BankedJournalError::AllocationFailed {
                requested: resulting_len,
            }
        })?;
        active.bytes.extend_from_slice(suffix);
        let published = self.publish_next(active.bank, active.generation, &active.bytes)?;
        self.active = published;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn repair_exact(&mut self, repair: JournalRepair) -> Result<(), BankedJournalError<B::Error>> {
        let mut active = self.active.clone();
        let offset = repair.offset();
        if offset > active.bytes.len() {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: active.bytes.len(),
            });
        }
        if offset == active.bytes.len() {
            // There is no suffix to rewrite, but the recovery contract still
            // asks this provider to complete a durability barrier.
            return self.flush();
        }
        active.bytes.truncate(offset);
        let published = self.publish_next(active.bank, active.generation, &active.bytes)?;
        self.active = published;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn publish_next(
        &mut self,
        active_bank: Option<u32>,
        generation: u64,
        bytes: &[u8],
    ) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        if bytes.len() > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: bytes.len(),
                capacity: JOURNAL_CAPACITY,
            });
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        let target_bank = active_bank.map_or(0, |bank| bank ^ 1);
        self.write_payload(target_bank, bytes)?;
        self.mark_phase(JournalIoPhase::PayloadWritten);
        self.flush()?;
        self.mark_phase(JournalIoPhase::PayloadFlushed);

        let header = BankHeader {
            bank: target_bank,
            generation: next_generation,
            logical_len: bytes.len(),
            payload_digest: self.hash(bytes),
        }
        .encode();
        self.write_sector(bank_header_lba(target_bank), &header)?;
        self.mark_phase(JournalIoPhase::HeaderWritten);
        self.flush()?;
        self.mark_phase(JournalIoPhase::HeaderFlushed);

        match self.inspect_bank(target_bank)? {
            BankInspection::Valid(image)
                if image.generation == next_generation && image.bytes == bytes =>
            {
                self.mark_phase(JournalIoPhase::ReadbackValidated);
                Ok(image)
            }
            BankInspection::Blank | BankInspection::Invalid | BankInspection::Valid(_) => {
                Err(BankedJournalError::ReadbackMismatch)
            }
        }
    }

    fn write_payload(
        &mut self,
        bank: u32,
        bytes: &[u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        for (sector_index, chunk) in bytes.chunks(SECTOR_BYTES).enumerate() {
            let mut sector = [0u8; SECTOR_BYTES];
            sector[..chunk.len()].copy_from_slice(chunk);
            self.write_sector(
                bank_data_lba(bank)
                    + u32::try_from(sector_index).map_err(|_| BankedJournalError::JournalFull {
                        current: 0,
                        additional: bytes.len(),
                        capacity: JOURNAL_CAPACITY,
                    })?,
                &sector,
            )?;
        }
        Ok(())
    }

    fn read_active(&mut self) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        let first = self.inspect_bank(0)?;
        let second = self.inspect_bank(1)?;
        match (first, second) {
            (BankInspection::Valid(left), BankInspection::Valid(right)) => {
                if left.generation > right.generation {
                    Ok(left)
                } else if right.generation > left.generation {
                    Ok(right)
                } else if left.bytes == right.bytes {
                    Ok(left)
                } else {
                    Err(BankedJournalError::ConflictingGeneration {
                        generation: left.generation,
                    })
                }
            }
            (BankInspection::Valid(image), _) | (_, BankInspection::Valid(image)) => Ok(image),
            (BankInspection::Blank, BankInspection::Blank)
            | (BankInspection::Blank, BankInspection::Invalid)
            | (BankInspection::Invalid, BankInspection::Blank) => Ok(ActiveImage {
                bank: None,
                generation: 0,
                bytes: Vec::new(),
            }),
            (BankInspection::Invalid, BankInspection::Invalid) => {
                Err(BankedJournalError::CorruptBankMetadata)
            }
        }
    }

    /// Like `read_active`, but treats a malformed lone bank as corruption
    /// rather than an uninitialized medium.  A valid old bank plus a torn
    /// inactive update remains recoverable, which is the double-bank crash
    /// contract; a blank peer gives no such recovery authority.
    fn read_active_strict(&mut self) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        let first = self.inspect_bank(0)?;
        let second = self.inspect_bank(1)?;
        match (first, second) {
            (BankInspection::Valid(left), BankInspection::Valid(right)) => {
                if left.generation > right.generation {
                    Ok(left)
                } else if right.generation > left.generation {
                    Ok(right)
                } else if left.bytes == right.bytes {
                    Ok(left)
                } else {
                    Err(BankedJournalError::ConflictingGeneration {
                        generation: left.generation,
                    })
                }
            }
            (BankInspection::Valid(image), _) | (_, BankInspection::Valid(image)) => Ok(image),
            (BankInspection::Blank, BankInspection::Blank) => Ok(ActiveImage {
                bank: None,
                generation: 0,
                bytes: Vec::new(),
            }),
            (BankInspection::Blank, BankInspection::Invalid)
            | (BankInspection::Invalid, BankInspection::Blank)
            | (BankInspection::Invalid, BankInspection::Invalid) => {
                Err(BankedJournalError::CorruptBankMetadata)
            }
        }
    }

    fn inspect_bank(&mut self, bank: u32) -> Result<BankInspection, BankedJournalError<B::Error>> {
        let mut header_sector = [0u8; SECTOR_BYTES];
        self.read_sector(bank_header_lba(bank), &mut header_sector)?;
        let HeaderInspection::Valid(header) = BankHeader::decode(bank, &header_sector) else {
            return Ok(match BankHeader::decode(bank, &header_sector) {
                HeaderInspection::Blank => BankInspection::Blank,
                HeaderInspection::Invalid => BankInspection::Invalid,
                HeaderInspection::Valid(_) => unreachable!(),
            });
        };

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(header.logical_len).map_err(|_| {
            BankedJournalError::AllocationFailed {
                requested: header.logical_len,
            }
        })?;
        bytes.resize(header.logical_len, 0);
        for (sector_index, chunk) in bytes.chunks_mut(SECTOR_BYTES).enumerate() {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(
                bank_data_lba(bank)
                    + u32::try_from(sector_index)
                        .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                &mut sector,
            )?;
            chunk.copy_from_slice(&sector[..chunk.len()]);
        }
        let actual_digest = self.hash(&bytes);
        if actual_digest != header.payload_digest {
            return Ok(BankInspection::Invalid);
        }
        Ok(BankInspection::Valid(ActiveImage {
            bank: Some(header.bank),
            generation: header.generation,
            bytes,
        }))
    }

    #[cfg(ktest)]
    fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    #[cfg(ktest)]
    fn into_backend(self) -> B {
        self.backend
    }

    #[cfg(ktest)]
    fn enable_telemetry(&mut self) {
        self.telemetry = Some(JournalIoTelemetry::default());
    }

    #[cfg(ktest)]
    fn telemetry(&self) -> Option<JournalIoTelemetry> {
        self.telemetry
    }

    fn read_sector(
        &mut self,
        lba: u32,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.backend
            .read_sector(lba, output)
            .map_err(BankedJournalError::Storage)?;
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.sectors_read = telemetry.sectors_read.saturating_add(1);
        }
        Ok(())
    }

    fn write_sector(
        &mut self,
        lba: u32,
        input: &[u8; SECTOR_BYTES],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.backend
            .write_sector(lba, input)
            .map_err(BankedJournalError::Storage)?;
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.sectors_written = telemetry.sectors_written.saturating_add(1);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        self.backend.flush().map_err(BankedJournalError::Storage)?;
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.flushes = telemetry.flushes.saturating_add(1);
        }
        Ok(())
    }

    fn hash(&mut self, bytes: &[u8]) -> [u8; 32] {
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.hash_bytes = telemetry.hash_bytes.saturating_add(bytes.len() as u64);
        }
        Sha256::digest(bytes).into()
    }

    fn mark_phase(&mut self, phase: JournalIoPhase) {
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.phase_tsc[phase as usize] = diagnostic_tsc();
        }
    }
}

/// One redundant committed header for one append-oriented vNext segment.
///
/// `previous_head` binds a segment to the exact prefix preceding it; `head`
/// binds that prefix and this segment's exact payload.  Recovery therefore
/// selects a newest *chain*, rather than treating the largest independently
/// valid sector as authoritative.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VNextHeader {
    segment: u32,
    generation: u64,
    first_generation: u64,
    logical_len: usize,
    previous_head: [u8; 32],
    payload_digest: [u8; 32],
    head: [u8; 32],
}

impl VNextHeader {
    fn encode(&self) -> [u8; SECTOR_BYTES] {
        self.encode_with_magic(VNEXT_MAGIC)
    }

    fn encode_with_magic(&self, magic: [u8; 8]) -> [u8; SECTOR_BYTES] {
        let mut bytes = [0u8; SECTOR_BYTES];
        bytes[..8].copy_from_slice(&magic);
        bytes[8..10].copy_from_slice(&VNEXT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&VNEXT_HEADER_LEN.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.segment.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.first_generation.to_le_bytes());
        bytes[32..40].copy_from_slice(&(self.logical_len as u64).to_le_bytes());
        bytes[40..48].copy_from_slice(&(VNEXT_SEGMENT_CAPACITY as u64).to_le_bytes());
        bytes[48..80].copy_from_slice(&self.previous_head);
        bytes[80..112].copy_from_slice(&self.payload_digest);
        bytes[112..144].copy_from_slice(&self.head);
        let digest: [u8; 32] = Sha256::digest(&bytes[..VNEXT_HEADER_HASH_OFFSET]).into();
        bytes[VNEXT_HEADER_HASH_OFFSET..VNEXT_HEADER_HASH_END].copy_from_slice(&digest);
        bytes
    }

    fn decode(expected_segment: u32, bytes: &[u8; SECTOR_BYTES]) -> VNextHeaderInspection {
        Self::decode_with_magic(Some(expected_segment), bytes, VNEXT_MAGIC)
    }

    fn decode_with_magic(
        expected_segment: Option<u32>,
        bytes: &[u8; SECTOR_BYTES],
        magic: [u8; 8],
    ) -> VNextHeaderInspection {
        if bytes.iter().all(|byte| *byte == 0) {
            return VNextHeaderInspection::Blank;
        }
        if bytes[..8] != magic
            || read_u16(bytes, 8) != VNEXT_VERSION
            || read_u16(bytes, 10) != VNEXT_HEADER_LEN
            || matches!(expected_segment, Some(segment) if read_u32(bytes, 12) != segment)
            || read_u64(bytes, 16) == 0
            || read_u64(bytes, 24) == 0
            || read_u64(bytes, 24) > read_u64(bytes, 16)
            || read_u64(bytes, 40) != VNEXT_SEGMENT_CAPACITY as u64
            || bytes[VNEXT_HEADER_HASH_END..].iter().any(|byte| *byte != 0)
        {
            return VNextHeaderInspection::Invalid;
        }
        let expected_digest: [u8; 32] = Sha256::digest(&bytes[..VNEXT_HEADER_HASH_OFFSET]).into();
        if bytes[VNEXT_HEADER_HASH_OFFSET..VNEXT_HEADER_HASH_END] != expected_digest {
            return VNextHeaderInspection::Invalid;
        }
        let Ok(logical_len) = usize::try_from(read_u64(bytes, 32)) else {
            return VNextHeaderInspection::Invalid;
        };
        if logical_len > VNEXT_SEGMENT_CAPACITY {
            return VNextHeaderInspection::Invalid;
        }
        let mut previous_head = [0u8; 32];
        let mut payload_digest = [0u8; 32];
        let mut head = [0u8; 32];
        previous_head.copy_from_slice(&bytes[48..80]);
        payload_digest.copy_from_slice(&bytes[80..112]);
        head.copy_from_slice(&bytes[112..144]);
        VNextHeaderInspection::Valid(Self {
            segment: read_u32(bytes, 12),
            generation: read_u64(bytes, 16),
            first_generation: read_u64(bytes, 24),
            logical_len,
            previous_head,
            payload_digest,
            head,
        })
    }
}

/// Redundant root that alone selects a vNext chain endpoint.  Segment headers
/// prove predecessors but never become authoritative merely by having a newer
/// generation on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VNextManifest {
    endpoint: VNextHeader,
}

impl VNextManifest {
    fn encode(&self) -> [u8; SECTOR_BYTES] {
        self.endpoint.encode_with_magic(VNEXT_MANIFEST_MAGIC)
    }

    fn decode(bytes: &[u8; SECTOR_BYTES]) -> VNextManifestInspection {
        if bytes.iter().all(|byte| *byte == 0) {
            return VNextManifestInspection::Blank;
        }
        match VNextHeader::decode_with_magic(None, bytes, VNEXT_MANIFEST_MAGIC) {
            VNextHeaderInspection::Valid(endpoint) => {
                if endpoint.segment >= VNEXT_SEGMENT_COUNT {
                    VNextManifestInspection::Invalid
                } else {
                    VNextManifestInspection::Valid(Self { endpoint })
                }
            }
            VNextHeaderInspection::Blank => VNextManifestInspection::Blank,
            VNextHeaderInspection::Invalid => VNextManifestInspection::Invalid,
        }
    }
}

#[derive(Clone, Debug)]
enum VNextManifestInspection {
    Blank,
    Invalid,
    Valid(VNextManifest),
}

#[derive(Clone, Debug)]
enum VNextHeaderInspection {
    Blank,
    Invalid,
    Valid(VNextHeader),
}

#[derive(Clone, Debug)]
enum VNextSegmentInspection {
    Blank,
    Invalid,
    Valid(VNextSegmentImage),
}

#[derive(Clone, Debug)]
struct VNextSegmentImage {
    header: VNextHeader,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct VNextActiveImage {
    header: Option<VNextHeader>,
    bytes: Vec<u8>,
    occupied: [bool; VNEXT_SEGMENT_COUNT as usize],
}

/// Development vNext journal: three append-only segments, two independently
/// checksummed committed headers per segment, and a prefix hash chain.
///
/// Normal appends only rewrite the final partially filled data sector plus two
/// small header sectors.  It is intentionally kept behind a separate type
/// until the core exposes a replayable checkpoint representation.  Calling
/// [`Self::checkpoint_exact`] is only sound when its `image` is already a
/// complete replacement journal stream (for example a future core snapshot
/// envelope); the current `JournalRecord` stream does not provide that.
#[derive(Debug)]
#[allow(dead_code)]
struct SegmentedJournalVNext<B> {
    backend: B,
    active: VNextActiveImage,
    poisoned: bool,
    telemetry: Option<JournalIoTelemetry>,
}

impl<B> SegmentedJournalVNext<B>
where
    B: SectorBackend,
{
    fn open(backend: B) -> Result<Self, BankedJournalError<B::Error>> {
        if backend.sector_count() < VNEXT_REQUIRED_SECTORS {
            return Err(BankedJournalError::DeviceTooSmall {
                sectors: backend.sector_count(),
                required: VNEXT_REQUIRED_SECTORS,
            });
        }
        let mut journal = Self {
            backend,
            active: VNextActiveImage {
                header: None,
                bytes: Vec::new(),
                occupied: [false; VNEXT_SEGMENT_COUNT as usize],
            },
            poisoned: false,
            telemetry: None,
        };
        journal.active = journal.recover_prefix()?;
        Ok(journal)
    }

    fn read_all_image(&mut self) -> Result<Vec<u8>, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        decode_vnext_frames(&self.active.bytes).ok_or(BankedJournalError::CorruptBankMetadata)
    }

    fn append_exact(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let framed = encode_vnext_frame(suffix).ok_or(BankedJournalError::AllocationFailed {
            requested: suffix.len(),
        })?;
        let resulting = self.active.bytes.len().checked_add(framed.len()).ok_or(
            BankedJournalError::JournalFull {
                current: self.active.bytes.len(),
                additional: framed.len(),
                capacity: VNEXT_CAPACITY,
            },
        )?;
        if resulting > VNEXT_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: self.active.bytes.len(),
                additional: framed.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        self.append_framed(&framed)
    }

    fn append_framed(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        if suffix.is_empty() {
            return self.flush();
        }
        let Some(current) = self.active.header.clone() else {
            let first = suffix.len().min(VNEXT_SEGMENT_CAPACITY);
            self.publish_new_segment(0, [0; 32], &suffix[..first], false)?;
            return if first == suffix.len() {
                Ok(())
            } else {
                self.append_framed(&suffix[first..])
            };
        };
        let current_start = self
            .active
            .bytes
            .len()
            .checked_sub(current.logical_len)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let current_bytes = &self.active.bytes[current_start..];
        let new_len = current.logical_len.checked_add(suffix.len()).ok_or(
            BankedJournalError::JournalFull {
                current: self.active.bytes.len(),
                additional: suffix.len(),
                capacity: VNEXT_CAPACITY,
            },
        )?;
        if new_len <= VNEXT_SEGMENT_CAPACITY {
            let mut payload = current_bytes.to_vec();
            payload
                .try_reserve_exact(suffix.len())
                .map_err(|_| BankedJournalError::AllocationFailed { requested: new_len })?;
            payload.extend_from_slice(suffix);
            let generation = current
                .generation
                .checked_add(1)
                .ok_or(BankedJournalError::GenerationExhausted)?;
            // Never rewrite the manifest-selected segment.  Until the new
            // manifest is durable, its old header and payload remain an exact
            // recoverable prefix; after publication this alternate segment
            // becomes the endpoint and the former one becomes free.
            let replacement = (1..=VNEXT_SEGMENT_COUNT)
                .map(|offset| (current.segment + offset) % VNEXT_SEGMENT_COUNT)
                .find(|segment| !self.active.occupied[*segment as usize])
                .ok_or(BankedJournalError::JournalFull {
                    current: self.active.bytes.len(),
                    additional: suffix.len(),
                    capacity: VNEXT_CAPACITY,
                })?;
            let header = self.publish_segment(
                replacement,
                generation,
                current.first_generation,
                current.previous_head,
                &payload,
                0,
            )?;
            self.publish_manifest(&header)?;
            self.active.bytes.truncate(current_start);
            self.active.bytes.extend_from_slice(&payload);
            self.active.occupied[current.segment as usize] = false;
            self.active.occupied[replacement as usize] = true;
            self.active.header = Some(header);
            self.mark_phase(JournalIoPhase::CacheUpdated);
            return Ok(());
        }
        let available = VNEXT_SEGMENT_CAPACITY - current.logical_len;
        if available != 0 {
            // A single journal record may cross a physical segment boundary.
            // The intermediate manifest is an unanchored prefix after a crash
            // and is therefore repaired by the existing anchor protocol.
            self.append_framed(&suffix[..available])?;
            return self.append_framed(&suffix[available..]);
        }
        if self
            .active
            .occupied
            .iter()
            .filter(|occupied| **occupied)
            .count()
            >= VNEXT_LIVE_SEGMENT_LIMIT
        {
            return Err(BankedJournalError::JournalFull {
                current: self.active.bytes.len(),
                additional: suffix.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let next = (1..=VNEXT_SEGMENT_COUNT)
            .map(|offset| (current.segment + offset) % VNEXT_SEGMENT_COUNT)
            .find(|segment| !self.active.occupied[*segment as usize])
            .ok_or(BankedJournalError::JournalFull {
                current: self.active.bytes.len(),
                additional: suffix.len(),
                capacity: VNEXT_CAPACITY,
            })?;
        let first_len = suffix.len().min(VNEXT_SEGMENT_CAPACITY);
        self.publish_new_segment(next, current.head, &suffix[..first_len], false)?;
        if first_len == suffix.len() {
            Ok(())
        } else {
            self.append_framed(&suffix[first_len..])
        }
    }

    /// Publishes a replacement replay image in an alternate segment.
    ///
    /// This is the vNext checkpoint/compaction primitive.  Callers must supply
    /// an exact replayable replacement image; anchored recovery uses it for
    /// exact-prefix repair, while a future state-snapshot producer may use the
    /// same atomic alternate-chain publication path.
    fn checkpoint_exact(&mut self, image: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let framed = encode_vnext_frame(image).ok_or(BankedJournalError::AllocationFailed {
            requested: image.len(),
        })?;
        self.replace_exact(&framed)
    }

    fn repair_exact(&mut self, offset: usize) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let raw = decode_vnext_frames(&self.active.bytes)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        if offset > raw.len() {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: raw.len(),
            });
        }
        if offset == raw.len() {
            return self.flush();
        }
        let prefix = encode_vnext_frame(&raw[..offset])
            .ok_or(BankedJournalError::AllocationFailed { requested: offset })?;
        self.replace_exact(&prefix)
    }

    fn replace_exact(&mut self, image: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        if image.len() > VNEXT_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: image.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let needed = image.len().div_ceil(VNEXT_SEGMENT_CAPACITY).max(1);
        let mut free = Vec::new();
        for segment in 0..VNEXT_SEGMENT_COUNT {
            if !self.active.occupied[segment as usize] {
                free.push(segment);
            }
        }
        if free.len() < needed {
            return Err(BankedJournalError::JournalFull {
                current: self.active.bytes.len(),
                additional: image.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let mut generation = self
            .active
            .header
            .as_ref()
            .map_or(0, |header| header.generation);
        let mut previous_head = [0; 32];
        let mut endpoint = None;
        for (index, &segment) in free.iter().enumerate().take(needed) {
            generation = generation
                .checked_add(1)
                .ok_or(BankedJournalError::GenerationExhausted)?;
            let begin = index * VNEXT_SEGMENT_CAPACITY;
            let end = (begin + VNEXT_SEGMENT_CAPACITY).min(image.len());
            let header = self.publish_segment(
                segment,
                generation,
                generation,
                previous_head,
                &image[begin..end],
                0,
            )?;
            previous_head = header.head;
            endpoint = Some(header);
        }
        let endpoint = endpoint.ok_or(BankedJournalError::CorruptBankMetadata)?;
        self.publish_manifest(&endpoint)?;
        self.active.bytes.clear();
        self.active
            .bytes
            .try_reserve_exact(image.len())
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: image.len(),
            })?;
        self.active.bytes.extend_from_slice(image);
        self.active.occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        for segment in free.into_iter().take(needed) {
            self.active.occupied[segment as usize] = true;
        }
        self.active.header = Some(endpoint);
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn publish_new_segment(
        &mut self,
        segment: u32,
        previous_head: [u8; 32],
        payload: &[u8],
        checkpoint: bool,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let generation = match self.active.header.as_ref() {
            Some(header) => header
                .generation
                .checked_add(1)
                .ok_or(BankedJournalError::GenerationExhausted)?,
            None => 1,
        };
        let header =
            self.publish_segment(segment, generation, generation, previous_head, payload, 0)?;
        self.publish_manifest(&header)?;
        if checkpoint {
            self.active.bytes.clear();
            self.active.occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        }
        self.active
            .bytes
            .try_reserve_exact(payload.len())
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: payload.len(),
            })?;
        self.active.bytes.extend_from_slice(payload);
        self.active.occupied[segment as usize] = true;
        self.active.header = Some(header);
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn publish_segment(
        &mut self,
        segment: u32,
        generation: u64,
        first_generation: u64,
        previous_head: [u8; 32],
        payload: &[u8],
        previous_len: usize,
    ) -> Result<VNextHeader, BankedJournalError<B::Error>> {
        if payload.len() > VNEXT_SEGMENT_CAPACITY || previous_len > payload.len() {
            return Err(BankedJournalError::JournalFull {
                current: previous_len,
                additional: payload.len().saturating_sub(previous_len),
                capacity: VNEXT_SEGMENT_CAPACITY,
            });
        }
        self.write_segment_tail(segment, payload, previous_len)?;
        self.mark_phase(JournalIoPhase::PayloadWritten);
        self.flush()?;
        self.mark_phase(JournalIoPhase::PayloadFlushed);

        let payload_digest = self.hash(payload);
        let head = self.segment_head(previous_head, payload);
        let header = VNextHeader {
            segment,
            generation,
            first_generation,
            logical_len: payload.len(),
            previous_head,
            payload_digest,
            head,
        };
        let encoded = header.encode();
        // Each copy is independently a complete committed superblock.  A
        // crash after the first flush may expose the new prefix; a corrupted
        // first copy still leaves the previous committed copy usable.
        self.write_sector(vnext_header_lba(segment, 0), &encoded)?;
        self.mark_phase(JournalIoPhase::HeaderWritten);
        self.flush()?;
        self.write_sector(vnext_header_lba(segment, 1), &encoded)?;
        self.flush()?;
        self.mark_phase(JournalIoPhase::HeaderFlushed);

        match self.inspect_segment(segment)? {
            VNextSegmentInspection::Valid(image)
                if image.header == header && image.bytes == payload =>
            {
                self.mark_phase(JournalIoPhase::ReadbackValidated);
                Ok(header)
            }
            VNextSegmentInspection::Blank
            | VNextSegmentInspection::Invalid
            | VNextSegmentInspection::Valid(_) => Err(BankedJournalError::ReadbackMismatch),
        }
    }

    fn write_segment_tail(
        &mut self,
        segment: u32,
        payload: &[u8],
        previous_len: usize,
    ) -> Result<(), BankedJournalError<B::Error>> {
        if payload.is_empty() {
            return Ok(());
        }
        let first_sector = previous_len / SECTOR_BYTES;
        let last_sector = (payload.len() - 1) / SECTOR_BYTES;
        for sector_index in first_sector..=last_sector {
            let mut sector = [0u8; SECTOR_BYTES];
            let begin = sector_index * SECTOR_BYTES;
            let end = (begin + SECTOR_BYTES).min(payload.len());
            sector[..end - begin].copy_from_slice(&payload[begin..end]);
            self.write_sector(
                vnext_data_lba(segment)
                    + u32::try_from(sector_index).map_err(|_| BankedJournalError::JournalFull {
                        current: previous_len,
                        additional: payload.len().saturating_sub(previous_len),
                        capacity: VNEXT_SEGMENT_CAPACITY,
                    })?,
                &sector,
            )?;
        }
        Ok(())
    }

    fn recover_prefix(&mut self) -> Result<VNextActiveImage, BankedJournalError<B::Error>> {
        let Some(manifest) = self.read_manifest()? else {
            return Ok(VNextActiveImage {
                header: None,
                bytes: Vec::new(),
                occupied: [false; VNEXT_SEGMENT_COUNT as usize],
            });
        };
        let endpoint = manifest.endpoint;
        let Some(current) = self.validate_segment_payload(endpoint.clone())? else {
            return Err(BankedJournalError::CorruptBankMetadata);
        };
        match self.inspect_segment(endpoint.segment)? {
            VNextSegmentInspection::Valid(image) if image.header == endpoint => {}
            _ => return Err(BankedJournalError::CorruptBankMetadata),
        }
        let mut images = Vec::new();
        for segment in 0..VNEXT_SEGMENT_COUNT {
            match self.inspect_segment(segment)? {
                VNextSegmentInspection::Valid(image) => images.push(image),
                VNextSegmentInspection::Invalid | VNextSegmentInspection::Blank => {}
            }
        }
        let mut chain = Vec::new();
        let mut next_head = endpoint.previous_head;
        let mut next_generation = endpoint.generation;
        loop {
            if next_head == [0; 32] {
                break;
            }
            let Some(found) = images
                .iter()
                .position(|image| image.header.head == next_head)
            else {
                // The newest independent header lacks its required prefix. It
                // is a corrupt/uncommitted suffix, not a new authority.
                return Err(BankedJournalError::CorruptBankMetadata);
            };
            if chain.contains(&found) {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
            if images[found].header.first_generation > images[found].header.generation
                || images[found].header.generation >= next_generation
            {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
            next_head = images[found].header.previous_head;
            next_generation = images[found].header.generation;
            chain.push(found);
        }
        chain.reverse();
        let mut bytes = Vec::new();
        let mut occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        for index in chain {
            let image = &images[index];
            bytes.try_reserve_exact(image.bytes.len()).map_err(|_| {
                BankedJournalError::AllocationFailed {
                    requested: bytes.len().saturating_add(image.bytes.len()),
                }
            })?;
            bytes.extend_from_slice(&image.bytes);
            occupied[image.header.segment as usize] = true;
        }
        bytes.try_reserve_exact(current.bytes.len()).map_err(|_| {
            BankedJournalError::AllocationFailed {
                requested: bytes.len().saturating_add(current.bytes.len()),
            }
        })?;
        bytes.extend_from_slice(&current.bytes);
        occupied[current.header.segment as usize] = true;
        Ok(VNextActiveImage {
            header: Some(endpoint),
            bytes,
            occupied,
        })
    }

    fn read_manifest(&mut self) -> Result<Option<VNextManifest>, BankedJournalError<B::Error>> {
        let mut first = [0u8; SECTOR_BYTES];
        let mut second = [0u8; SECTOR_BYTES];
        self.read_sector(vnext_manifest_lba(0), &mut first)?;
        self.read_sector(vnext_manifest_lba(1), &mut second)?;
        match (
            VNextManifest::decode(&first),
            VNextManifest::decode(&second),
        ) {
            (VNextManifestInspection::Blank, VNextManifestInspection::Blank) => Ok(None),
            (VNextManifestInspection::Valid(left), VNextManifestInspection::Valid(right)) => {
                if left == right {
                    Ok(Some(left))
                } else if left.endpoint.generation == right.endpoint.generation {
                    Err(BankedJournalError::ConflictingGeneration {
                        generation: left.endpoint.generation,
                    })
                } else if left.endpoint.generation > right.endpoint.generation {
                    Ok(Some(left))
                } else {
                    Ok(Some(right))
                }
            }
            (VNextManifestInspection::Valid(manifest), _)
            | (_, VNextManifestInspection::Valid(manifest)) => Ok(Some(manifest)),
            _ => Err(BankedJournalError::CorruptBankMetadata),
        }
    }

    fn publish_manifest(
        &mut self,
        endpoint: &VNextHeader,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let manifest = VNextManifest {
            endpoint: endpoint.clone(),
        };
        let bytes = manifest.encode();
        let result = (|| {
            self.write_sector(vnext_manifest_lba(0), &bytes)?;
            self.flush()?;
            self.write_sector(vnext_manifest_lba(1), &bytes)?;
            self.flush()?;
            if self.read_manifest()?.as_ref() != Some(&manifest) {
                return Err(BankedJournalError::ReadbackMismatch);
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn require_reopen(&self) -> Result<(), BankedJournalError<B::Error>> {
        if self.poisoned {
            Err(BankedJournalError::CorruptBankMetadata)
        } else {
            Ok(())
        }
    }

    fn inspect_segment(
        &mut self,
        segment: u32,
    ) -> Result<VNextSegmentInspection, BankedJournalError<B::Error>> {
        let mut first = [0u8; SECTOR_BYTES];
        let mut second = [0u8; SECTOR_BYTES];
        self.read_sector(vnext_header_lba(segment, 0), &mut first)?;
        self.read_sector(vnext_header_lba(segment, 1), &mut second)?;
        let first = VNextHeader::decode(segment, &first);
        let second = VNextHeader::decode(segment, &second);
        let both_blank = matches!(&first, VNextHeaderInspection::Blank)
            && matches!(&second, VNextHeaderInspection::Blank);
        let mut candidates = Vec::new();
        if let VNextHeaderInspection::Valid(header) = first {
            candidates.push(header);
        }
        if let VNextHeaderInspection::Valid(header) = second {
            candidates.push(header);
        }
        if candidates.is_empty() {
            return Ok(if both_blank {
                VNextSegmentInspection::Blank
            } else {
                VNextSegmentInspection::Invalid
            });
        }
        if candidates.len() == 2 {
            if candidates[0].generation == candidates[1].generation
                && candidates[0] != candidates[1]
            {
                return Ok(VNextSegmentInspection::Invalid);
            }
            if candidates[1].generation > candidates[0].generation {
                candidates.swap(0, 1);
            }
        }
        for header in candidates {
            if let Some(image) = self.validate_segment_payload(header)? {
                return Ok(VNextSegmentInspection::Valid(image));
            }
        }
        Ok(VNextSegmentInspection::Invalid)
    }

    fn validate_segment_payload(
        &mut self,
        header: VNextHeader,
    ) -> Result<Option<VNextSegmentImage>, BankedJournalError<B::Error>> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(header.logical_len).map_err(|_| {
            BankedJournalError::AllocationFailed {
                requested: header.logical_len,
            }
        })?;
        bytes.resize(header.logical_len, 0);
        for (index, chunk) in bytes.chunks_mut(SECTOR_BYTES).enumerate() {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(
                vnext_data_lba(header.segment)
                    + u32::try_from(index).map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                &mut sector,
            )?;
            chunk.copy_from_slice(&sector[..chunk.len()]);
        }
        if self.hash(&bytes) != header.payload_digest
            || self.segment_head(header.previous_head, &bytes) != header.head
        {
            return Ok(None);
        }
        Ok(Some(VNextSegmentImage { header, bytes }))
    }

    #[cfg(ktest)]
    fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    #[cfg(ktest)]
    fn into_backend(self) -> B {
        self.backend
    }

    #[cfg(ktest)]
    fn enable_telemetry(&mut self) {
        self.telemetry = Some(JournalIoTelemetry::default());
    }

    #[cfg(ktest)]
    fn telemetry(&self) -> Option<JournalIoTelemetry> {
        self.telemetry
    }

    fn segment_head(&mut self, previous: [u8; 32], bytes: &[u8]) -> [u8; 32] {
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.hash_bytes = telemetry
                .hash_bytes
                .saturating_add(previous.len() as u64 + bytes.len() as u64);
        }
        let mut hasher = Sha256::new();
        hasher.update(previous);
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn read_sector(
        &mut self,
        lba: u32,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.backend
            .read_sector(lba, output)
            .map_err(BankedJournalError::Storage)?;
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.sectors_read = telemetry.sectors_read.saturating_add(1);
        }
        Ok(())
    }

    fn write_sector(
        &mut self,
        lba: u32,
        input: &[u8; SECTOR_BYTES],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.backend
            .write_sector(lba, input)
            .map_err(BankedJournalError::Storage)?;
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.sectors_written = telemetry.sectors_written.saturating_add(1);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        self.backend.flush().map_err(BankedJournalError::Storage)?;
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.flushes = telemetry.flushes.saturating_add(1);
        }
        Ok(())
    }

    fn hash(&mut self, bytes: &[u8]) -> [u8; 32] {
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.hash_bytes = telemetry.hash_bytes.saturating_add(bytes.len() as u64);
        }
        Sha256::digest(bytes).into()
    }

    fn mark_phase(&mut self, phase: JournalIoPhase) {
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.phase_tsc[phase as usize] = diagnostic_tsc();
        }
    }
}

fn diagnostic_tsc() -> u64 {
    // Only called when telemetry is enabled; callers must not infer elapsed
    // time across CPUs, migration, frequency changes, or virtualization.
    ostd::arch::read_tsc()
}

const fn bank_header_lba(bank: u32) -> u32 {
    FIRST_BANK_LBA + bank * BANK_SECTORS
}

const fn bank_data_lba(bank: u32) -> u32 {
    bank_header_lba(bank) + 1
}

const fn vnext_segment_lba(segment: u32) -> u32 {
    VNEXT_FIRST_SEGMENT_LBA + segment * VNEXT_SEGMENT_SECTORS
}

const fn vnext_header_lba(segment: u32, copy: u32) -> u32 {
    vnext_segment_lba(segment) + copy
}

const fn vnext_data_lba(segment: u32) -> u32 {
    vnext_segment_lba(segment) + VNEXT_HEADER_COPIES
}

const fn vnext_manifest_lba(copy: u32) -> u32 {
    VNEXT_MANIFEST_LBA + copy
}

fn encode_vnext_frame(bytes: &[u8]) -> Option<Vec<u8>> {
    let used = VNEXT_FRAME_HEADER.checked_add(bytes.len())?;
    let padded = used.div_ceil(SECTOR_BYTES).checked_mul(SECTOR_BYTES)?;
    let mut frame = Vec::new();
    frame.try_reserve_exact(padded).ok()?;
    frame.resize(padded, 0);
    frame[..8].copy_from_slice(&VNEXT_FRAME_MAGIC);
    frame[8..12].copy_from_slice(&u32::try_from(bytes.len()).ok()?.to_le_bytes());
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    frame[16..48].copy_from_slice(&digest);
    frame[48..48 + bytes.len()].copy_from_slice(bytes);
    Some(frame)
}

fn decode_vnext_frames(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = 0usize;
    let mut raw = Vec::new();
    while cursor < bytes.len() {
        if bytes.len().checked_sub(cursor)? < VNEXT_FRAME_HEADER
            || bytes[cursor..cursor + 8] != VNEXT_FRAME_MAGIC
        {
            return None;
        }
        let len = usize::try_from(read_u32(bytes, cursor + 8)).ok()?;
        let used = VNEXT_FRAME_HEADER.checked_add(len)?;
        let padded = used.div_ceil(SECTOR_BYTES).checked_mul(SECTOR_BYTES)?;
        if cursor.checked_add(padded)? > bytes.len() {
            return None;
        }
        let payload = &bytes[cursor + VNEXT_FRAME_HEADER..cursor + VNEXT_FRAME_HEADER + len];
        let digest: [u8; 32] = Sha256::digest(payload).into();
        if bytes[cursor + 16..cursor + 48] != digest
            || bytes[cursor + used..cursor + padded]
                .iter()
                .any(|b| *b != 0)
        {
            return None;
        }
        raw.extend_from_slice(payload);
        cursor += padded;
    }
    Some(raw)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Concrete durable-journal owner for a dedicated ATA fixture.
#[derive(Debug)]
pub(crate) struct AtaPioJournal {
    journal: BankedJournal<AtaPioDisk>,
}

impl AtaPioJournal {
    /// Acquires and identifies exactly the requested fixed disk.
    pub(crate) fn acquire(fixture: AtaJournalFixture) -> Result<Self, AtaPioJournalError> {
        let disk = AtaPioDisk::acquire(fixture).map_err(BankedJournalError::Storage)?;
        Ok(Self {
            journal: BankedJournal::open(disk)?,
        })
    }
}

impl DurableJournalBackend for AtaPioJournal {
    type Error = AtaPioJournalError;

    fn append_and_sync(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.journal.append_exact(record.bytes())
    }
}

impl OstdBootJournal for AtaPioJournal {
    type RecoveryError = AtaPioJournalError;

    fn read_all(&mut self) -> Result<Vec<u8>, Self::RecoveryError> {
        self.journal.read_all_image()
    }

    fn repair_and_sync(&mut self, repair: JournalRepair) -> Result<(), Self::RecoveryError> {
        self.journal.repair_exact(repair)
    }
}

/// Isolated ATA owner for the append/checkpoint journal-vNext format.
///
/// This has a separate type and disk region from the legacy journal; no legacy
/// image is ever reinterpreted or overwritten.  It remains an experiment-only
/// path until its payload layout gains sector-aligned append frames.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct AtaPioJournalVNext {
    journal: SegmentedJournalVNext<AtaPioDisk>,
}

#[allow(dead_code)]
impl AtaPioJournalVNext {
    pub(crate) fn acquire(fixture: AtaJournalFixture) -> Result<Self, AtaPioJournalError> {
        let disk = AtaPioDisk::acquire(fixture).map_err(BankedJournalError::Storage)?;
        Ok(Self {
            journal: SegmentedJournalVNext::open(disk)?,
        })
    }

    pub(crate) fn append_exact(&mut self, bytes: &[u8]) -> Result<(), AtaPioJournalError> {
        self.journal.append_exact(bytes)
    }

    /// Publishes an externally validated replacement replay image.
    pub(crate) fn checkpoint_exact(&mut self, bytes: &[u8]) -> Result<(), AtaPioJournalError> {
        self.journal.checkpoint_exact(bytes)
    }

    pub(crate) fn read_all(&mut self) -> Result<Vec<u8>, AtaPioJournalError> {
        self.journal.read_all_image()
    }
}

impl DurableJournalBackend for AtaPioJournalVNext {
    type Error = AtaPioJournalError;
    fn append_and_sync(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.journal.append_exact(record.bytes())
    }
}

impl OstdBootJournal for AtaPioJournalVNext {
    type RecoveryError = AtaPioJournalError;
    fn read_all(&mut self) -> Result<Vec<u8>, Self::RecoveryError> {
        self.journal.read_all_image()
    }
    fn repair_and_sync(&mut self, repair: JournalRepair) -> Result<(), Self::RecoveryError> {
        self.journal.repair_exact(repair.offset())
    }
}

/// Dedicated ATA two-bank cell for experiment state outside the CSER journal.
///
/// It owns the selected ATA fixture linearly and publishes `revision` only
/// after the entire record has been written, flushed, header-published,
/// flushed, and read back.  The caller supplies an independently calculated
/// digest; this facade verifies it before and after publication.  A TPM anchor
/// can therefore compare the same `(revision, digest)` without importing any
/// CSER journal format.
#[derive(Debug)]
pub(crate) struct AtaDoubleBank {
    banks: BankedJournal<AtaPioDisk>,
}

impl AtaDoubleBank {
    pub(crate) fn acquire(
        fixture: AtaJournalFixture,
    ) -> Result<Self, AtaDoubleBankError<AtaPioError>> {
        let disk = AtaPioDisk::acquire(fixture)
            .map_err(|error| AtaDoubleBankError::Banked(BankedJournalError::Storage(error)))?;
        let banks = BankedJournal::open_strict(disk).map_err(AtaDoubleBankError::Banked)?;
        Ok(Self { banks })
    }

    /// Reads the authoritative record, rejecting a corrupt unpaired bank.
    pub(crate) fn load(
        &mut self,
    ) -> Result<Option<AtaDoubleBankSnapshot>, AtaDoubleBankError<AtaPioError>> {
        let active = self.banks.active.clone();
        if active.bank.is_none() {
            return Ok(None);
        }
        let digest: [u8; 32] = Sha256::digest(&active.bytes).into();
        Ok(Some(AtaDoubleBankSnapshot {
            revision: active.generation,
            digest,
            bytes: active.bytes,
        }))
    }

    /// Persists exactly one next revision.  Rollback and skipped revisions are
    /// rejected locally; an external TPM anchor may additionally reject a raw
    /// ATA image rolled back to an older, otherwise valid revision.
    pub(crate) fn publish(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<AtaDoubleBankSnapshot, AtaDoubleBankError<AtaPioError>> {
        let actual_digest: [u8; 32] = Sha256::digest(bytes).into();
        if actual_digest != digest {
            return Err(AtaDoubleBankError::Banked(
                BankedJournalError::ReadbackMismatch,
            ));
        }
        let active = self
            .banks
            .read_active_strict()
            .map_err(AtaDoubleBankError::Banked)?;
        let expected = active
            .generation
            .checked_add(1)
            .ok_or(AtaDoubleBankError::Banked(
                BankedJournalError::GenerationExhausted,
            ))?;
        if revision != expected {
            return Err(AtaDoubleBankError::RevisionMismatch {
                expected,
                supplied: revision,
            });
        }
        let published = self
            .banks
            .publish_next(active.bank, active.generation, bytes)
            .map_err(AtaDoubleBankError::Banked)?;
        self.banks.active = published;
        let snapshot = self.load()?.ok_or(AtaDoubleBankError::Banked(
            BankedJournalError::ReadbackMismatch,
        ))?;
        if snapshot.revision != revision || snapshot.digest != digest || snapshot.bytes != bytes {
            return Err(AtaDoubleBankError::Banked(
                BankedJournalError::ReadbackMismatch,
            ));
        }
        Ok(snapshot)
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::{vec, vec::Vec};

    use ostd::prelude::ktest;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryError {
        Bounds,
        InjectedWriteFailure,
        InjectedReadFailure,
        InjectedFlushFailure,
    }

    #[derive(Debug)]
    struct MemoryDisk {
        sectors: Vec<[u8; SECTOR_BYTES]>,
        flushes: u32,
        fail_writes_after: Option<u32>,
        fail_reads_after: Option<u32>,
        fail_flushes_after: Option<u32>,
    }

    impl MemoryDisk {
        fn fixture() -> Self {
            Self {
                sectors: vec![[0u8; SECTOR_BYTES]; VNEXT_REQUIRED_SECTORS as usize],
                flushes: 0,
                fail_writes_after: None,
                fail_reads_after: None,
                fail_flushes_after: None,
            }
        }
    }

    impl SectorBackend for MemoryDisk {
        type Error = MemoryError;

        fn sector_count(&self) -> u32 {
            self.sectors.len() as u32
        }

        fn read_sector(
            &mut self,
            lba: u32,
            output: &mut [u8; SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            if let Some(remaining) = self.fail_reads_after.as_mut() {
                if *remaining == 0 {
                    return Err(MemoryError::InjectedReadFailure);
                }
                *remaining -= 1;
            }
            *output = *self.sectors.get(lba as usize).ok_or(MemoryError::Bounds)?;
            Ok(())
        }

        fn write_sector(
            &mut self,
            lba: u32,
            input: &[u8; SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            if let Some(remaining) = self.fail_writes_after.as_mut() {
                if *remaining == 0 {
                    return Err(MemoryError::InjectedWriteFailure);
                }
                *remaining -= 1;
            }
            *self
                .sectors
                .get_mut(lba as usize)
                .ok_or(MemoryError::Bounds)? = *input;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            if let Some(remaining) = self.fail_flushes_after.as_mut() {
                if *remaining == 0 {
                    return Err(MemoryError::InjectedFlushFailure);
                }
                *remaining -= 1;
            }
            self.flushes += 1;
            Ok(())
        }
    }

    fn journal() -> BankedJournal<MemoryDisk> {
        BankedJournal::open(MemoryDisk::fixture()).expect("open memory disk")
    }

    #[ktest]
    fn pio_journal_format_appends_exact_bytes_and_uses_two_barriers() {
        let mut journal = journal();
        journal
            .append_exact(b"first-record")
            .expect("publish first record");
        journal
            .append_exact(b":second-record")
            .expect("publish second record");

        assert_eq!(
            journal.read_all_image().expect("read exact image"),
            b"first-record:second-record"
        );
        assert_eq!(journal.backend_mut().flushes, 4);
    }

    #[ktest]
    fn pio_journal_torn_data_falls_back_to_last_committed_bank() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish baseline");

        let proposed = b"committed-but-torn";
        let header = BankHeader {
            bank: 1,
            generation: 2,
            logical_len: proposed.len(),
            payload_digest: Sha256::digest(proposed).into(),
        }
        .encode();
        let mut torn_data = [0u8; SECTOR_BYTES];
        torn_data[..5].copy_from_slice(&proposed[..5]);
        journal
            .backend_mut()
            .write_sector(bank_data_lba(1), &torn_data)
            .expect("inject torn payload");
        journal
            .backend_mut()
            .write_sector(bank_header_lba(1), &header)
            .expect("publish header over torn payload");

        let mut reopened = BankedJournal::open(journal.into_backend()).expect("reopen fixture");
        assert_eq!(reopened.read_all_image().expect("fall back"), b"committed");
    }

    #[ktest]
    fn pio_journal_torn_header_falls_back_to_last_committed_bank() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish baseline");

        let proposed = b"committed-plus-data";
        let mut data = [0u8; SECTOR_BYTES];
        data[..proposed.len()].copy_from_slice(proposed);
        journal
            .backend_mut()
            .write_sector(bank_data_lba(1), &data)
            .expect("write complete proposed payload");
        let complete_header = BankHeader {
            bank: 1,
            generation: 2,
            logical_len: proposed.len(),
            payload_digest: Sha256::digest(proposed).into(),
        }
        .encode();
        let mut torn_header = [0u8; SECTOR_BYTES];
        torn_header[..37].copy_from_slice(&complete_header[..37]);
        journal
            .backend_mut()
            .write_sector(bank_header_lba(1), &torn_header)
            .expect("inject torn header");

        let mut reopened = BankedJournal::open(journal.into_backend()).expect("reopen fixture");
        assert_eq!(reopened.read_all_image().expect("fall back"), b"committed");
    }

    #[ktest]
    fn strict_double_bank_rejects_a_lone_corrupt_bank() {
        let mut journal = journal();
        let mut corrupt = [0u8; SECTOR_BYTES];
        corrupt[..10].copy_from_slice(b"not-a-bank");
        journal
            .backend_mut()
            .write_sector(bank_header_lba(0), &corrupt)
            .expect("inject malformed lone header");

        assert!(matches!(
            journal.read_active_strict(),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn strict_double_bank_keeps_a_valid_predecessor_after_torn_successor() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish predecessor");
        let mut corrupt = [0u8; SECTOR_BYTES];
        corrupt[..10].copy_from_slice(b"not-a-bank");
        journal
            .backend_mut()
            .write_sector(bank_header_lba(1), &corrupt)
            .expect("inject malformed inactive header");

        assert_eq!(
            journal
                .read_active_strict()
                .expect("valid predecessor remains authoritative")
                .bytes,
            b"committed"
        );
    }

    #[ktest]
    fn pio_journal_repair_publishes_the_exact_prefix() {
        let mut journal = journal();
        journal
            .append_exact(b"anchored-recordunanchored-suffix")
            .expect("publish image");
        journal
            .repair_exact(JournalRepair::UnanchoredSuffix {
                offset: b"anchored-record".len(),
            })
            .expect("repair exact suffix");

        assert_eq!(
            journal.read_all_image().expect("read repaired image"),
            b"anchored-record"
        );
    }

    #[ktest]
    fn pio_journal_capacity_is_explicit_backpressure() {
        let mut journal = journal();
        let full = vec![0x5a; JOURNAL_CAPACITY];
        journal.append_exact(&full).expect("fill bounded bank");
        let error = journal
            .append_exact(&[0xa5])
            .expect_err("one byte beyond capacity must fail");

        assert_eq!(
            error,
            BankedJournalError::JournalFull {
                current: JOURNAL_CAPACITY,
                additional: 1,
                capacity: JOURNAL_CAPACITY,
            }
        );
        assert_eq!(journal.read_all_image().expect("full image retained"), full);
    }

    #[ktest]
    fn pio_journal_cache_avoids_revalidating_banks_between_appends() {
        let mut journal = journal();
        journal.enable_telemetry();

        // A deterministic fill profile makes the full-bank rewrite visible:
        // committing the first 64 KiB in 512-byte records writes and reads
        // 8,384 sectors each, for 65.5x the logical payload in writes alone.
        for record in 1..=BANK_DATA_SECTORS {
            journal
                .append_exact(&vec![record as u8; SECTOR_BYTES])
                .expect("publish fill record");
        }

        let telemetry = journal.telemetry().expect("telemetry enabled");
        assert_eq!(telemetry.sectors_written, 8_384);
        assert_eq!(telemetry.sectors_read, 8_384);
        assert_eq!(telemetry.flushes, 256);
        assert_eq!(telemetry.hash_bytes, 8_454_144);
        assert_ne!(
            telemetry.phase_tsc[JournalIoPhase::ReadbackValidated as usize],
            0
        );
        assert_ne!(
            telemetry.phase_tsc[JournalIoPhase::CacheUpdated as usize],
            0
        );
    }

    #[ktest]
    fn pio_journal_failed_append_keeps_the_validated_cache() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish baseline");
        journal.backend_mut().fail_writes_after = Some(0);

        assert_eq!(
            journal.append_exact(b"-new"),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedWriteFailure
            ))
        );
        assert_eq!(
            journal.read_all_image().expect("cache remains valid"),
            b"committed"
        );
    }

    #[ktest]
    fn pio_journal_failed_repair_keeps_the_validated_cache() {
        let mut journal = journal();
        journal
            .append_exact(b"anchored-unanchored")
            .expect("publish image");
        journal.backend_mut().fail_writes_after = Some(0);

        assert_eq!(
            journal.repair_exact(JournalRepair::UnanchoredSuffix { offset: 8 }),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedWriteFailure
            ))
        );
        assert_eq!(
            journal.read_all_image().expect("cache remains valid"),
            b"anchored-unanchored"
        );
    }

    #[ktest]
    fn pio_journal_reopen_revalidates_corrupted_cached_bank() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish baseline");
        let active_bank = journal.active.bank.expect("published bank");
        journal.backend_mut().sectors[bank_header_lba(active_bank) as usize][0] ^= 0xff;

        let reopened = BankedJournal::open(journal.into_backend()).expect("reopen fixture");
        assert!(reopened.active.bank.is_none());
        assert!(reopened.active.bytes.is_empty());
    }

    #[ktest]
    fn pio_journal_repair_updates_cache_only_after_readback() {
        let mut journal = journal();
        journal
            .append_exact(b"anchored-unanchored")
            .expect("publish image");
        journal
            .repair_exact(JournalRepair::UnanchoredSuffix { offset: 8 })
            .expect("publish repair");
        assert_eq!(
            journal.read_all_image().expect("cached repair"),
            b"anchored"
        );
    }

    fn vnext_journal() -> SegmentedJournalVNext<MemoryDisk> {
        SegmentedJournalVNext::open(MemoryDisk::fixture()).expect("open vNext memory disk")
    }

    #[ktest]
    fn pio_vnext_appends_without_rewriting_the_prefix_and_reports_io() {
        let mut journal = vnext_journal();
        journal.enable_telemetry();
        journal.append_exact(b"first").expect("first append");
        let before = journal.telemetry().expect("telemetry");
        journal.append_exact(b"-second").expect("second append");
        let after = journal.telemetry().expect("telemetry");

        assert_eq!(journal.read_all_image().expect("image"), b"first-second");
        // COW keeps the committed prefix untouched: the replacement contains
        // both framed sectors, followed by two headers and two manifest
        // copies. This is bounded by one segment rather than the whole log.
        assert_eq!(after.sectors_written - before.sectors_written, 6);
        assert_eq!(after.flushes - before.flushes, 5);
        assert_eq!(after.sectors_read - before.sectors_read, 6);
        assert!(after.hash_bytes > before.hash_bytes);
        assert_ne!(after.phase_tsc[JournalIoPhase::PayloadWritten as usize], 0);
        assert_ne!(
            after.phase_tsc[JournalIoPhase::ReadbackValidated as usize],
            0
        );
    }

    #[ktest]
    fn pio_vnext_unpublished_replacement_keeps_the_manifest_selected_prefix() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");

        // Same-segment growth is copy-on-write. Simulate a crash after the
        // replacement payload and one independently valid header copy reach
        // the alternate segment, but before either manifest copy names it.
        // Recovery must follow the old manifest and ignore the orphan.
        let mut replacement = encode_vnext_frame(b"committed").expect("base frame");
        replacement.extend_from_slice(&encode_vnext_frame(b"-new-tail").expect("tail frame"));
        for (index, chunk) in replacement.chunks(SECTOR_BYTES).enumerate() {
            let mut sector = [0u8; SECTOR_BYTES];
            sector[..chunk.len()].copy_from_slice(chunk);
            journal
                .backend_mut()
                .write_sector(vnext_data_lba(1) + index as u32, &sector)
                .expect("inject replacement payload");
        }
        let replacement_header = VNextHeader {
            segment: 1,
            generation: 2,
            first_generation: 1,
            logical_len: replacement.len(),
            previous_head: [0; 32],
            payload_digest: Sha256::digest(&replacement).into(),
            head: journal.segment_head([0; 32], &replacement),
        }
        .encode();
        journal
            .backend_mut()
            .write_sector(vnext_header_lba(1, 0), &replacement_header)
            .expect("inject replacement header copy");

        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(reopened.read_all_image().expect("old prefix"), b"committed");
    }

    #[ktest]
    fn pio_vnext_torn_header_copy_keeps_the_other_committed_copy() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");
        journal.backend_mut().sectors[vnext_header_lba(0, 0) as usize][0] ^= 0xff;

        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("other header"),
            b"committed"
        );
    }

    #[ktest]
    fn pio_vnext_manifest_selects_the_committed_endpoint_and_rejects_a_tie() {
        let mut journal = vnext_journal();
        journal.append_exact(b"first").expect("first");
        let old_manifest = journal.backend_mut().sectors[vnext_manifest_lba(1) as usize];
        journal.append_exact(b"-second").expect("second");
        // A torn second manifest copy still leaves the newer first copy as the
        // selected endpoint; recovery never scans for a largest segment.
        journal.backend_mut().sectors[vnext_manifest_lba(1) as usize] = old_manifest;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("new endpoint"),
            b"first-second"
        );

        let mut endpoint = reopened.active.header.clone().expect("endpoint");
        endpoint.head[0] ^= 0xff;
        let conflicting = VNextManifest { endpoint }.encode();
        reopened.backend_mut().sectors[vnext_manifest_lba(1) as usize] = conflicting;
        assert!(matches!(
            SegmentedJournalVNext::open(reopened.into_backend()),
            Err(BankedJournalError::ConflictingGeneration { .. })
        ));
    }

    #[ktest]
    fn pio_vnext_interrupted_checkpoint_keeps_the_old_chain() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old-prefix").expect("baseline");
        // checkpoint writes one payload sector first; failing the first header
        // publication must not make its replacement image authoritative.
        journal.backend_mut().fail_writes_after = Some(1);
        assert_eq!(
            journal.checkpoint_exact(b"replacement"),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedWriteFailure
            ))
        );
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(reopened.read_all_image().expect("old chain"), b"old-prefix");
    }

    #[ktest]
    fn pio_vnext_readback_failure_does_not_publish_the_cache() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");
        journal.backend_mut().fail_reads_after = Some(0);
        assert_eq!(
            journal.append_exact(b"-unread"),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedReadFailure
            ))
        );
        journal.backend_mut().fail_reads_after = None;
        assert_eq!(
            journal.read_all_image().expect("cached prefix"),
            b"committed"
        );
    }

    #[ktest]
    fn pio_vnext_flush_failure_does_not_publish_the_cache() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");
        journal.backend_mut().fail_flushes_after = Some(0);
        assert_eq!(
            journal.append_exact(b"-unflushed"),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedFlushFailure
            ))
        );
        journal.backend_mut().fail_flushes_after = None;
        assert_eq!(
            journal.read_all_image().expect("cached prefix"),
            b"committed"
        );
    }

    #[ktest]
    fn pio_vnext_corrupt_reopen_fails_closed() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");
        journal.backend_mut().sectors[vnext_manifest_lba(0) as usize][0] ^= 0xff;
        journal.backend_mut().sectors[vnext_manifest_lba(1) as usize][0] ^= 0xff;
        assert!(matches!(
            SegmentedJournalVNext::open(journal.into_backend()),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn pio_vnext_rolls_to_segments_then_backpressures_and_recovers_twice() {
        let mut journal = vnext_journal();
        let usable = VNEXT_SEGMENT_CAPACITY - VNEXT_FRAME_HEADER;
        let first = vec![0x11; usable];
        let second = vec![0x22; usable];
        let third = vec![0x33; usable];
        journal.append_exact(&first).expect("first segment");
        journal.append_exact(&second).expect("second segment");
        journal.append_exact(&third).expect("third segment");
        assert_eq!(
            journal.append_exact(b"full"),
            Err(BankedJournalError::JournalFull {
                current: VNEXT_CAPACITY,
                additional: SECTOR_BYTES,
                capacity: VNEXT_CAPACITY,
            })
        );
        let mut once = SegmentedJournalVNext::open(journal.into_backend()).expect("first reopen");
        assert_eq!(once.read_all_image().expect("recovered").len(), 3 * usable);
        let mut twice = SegmentedJournalVNext::open(once.into_backend()).expect("second reopen");
        assert_eq!(
            twice.read_all_image().expect("second recovery").len(),
            3 * usable
        );
    }

    #[ktest]
    fn pio_vnext_checkpoint_rotates_to_a_single_replayable_replacement() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("old image");
        journal
            .checkpoint_exact(b"replacement-image")
            .expect("replacement checkpoint");
        journal
            .append_exact(b"-plus-append")
            .expect("append after checkpoint");
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("checkpoint image"),
            b"replacement-image-plus-append"
        );
    }

    #[ktest]
    fn pio_vnext_spans_segment_boundaries_without_fragmentation() {
        let mut journal = vnext_journal();
        let payload = vec![0x5a; VNEXT_SEGMENT_CAPACITY + 17];
        journal.append_exact(&payload).expect("spanning append");
        assert_eq!(journal.read_all_image().expect("spanning image"), payload);
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("spanning recovery").len(),
            VNEXT_SEGMENT_CAPACITY + 17
        );
    }

    #[ktest]
    fn pio_vnext_repair_publishes_early_current_and_zero_prefixes() {
        let mut early = vnext_journal();
        early.append_exact(b"alpha-beta-gamma").expect("image");
        early.repair_exact(5).expect("early repair");
        let mut reopened = SegmentedJournalVNext::open(early.into_backend()).expect("reopen early");
        assert_eq!(reopened.read_all_image().expect("early prefix"), b"alpha");

        let mut current = vnext_journal();
        current.append_exact(b"alpha-beta-gamma").expect("image");
        current.repair_exact(10).expect("current repair");
        let mut reopened =
            SegmentedJournalVNext::open(current.into_backend()).expect("reopen current");
        assert_eq!(
            reopened.read_all_image().expect("current prefix"),
            b"alpha-beta"
        );

        let mut zero = vnext_journal();
        zero.append_exact(b"alpha-beta-gamma").expect("image");
        zero.repair_exact(0).expect("zero repair");
        let mut reopened = SegmentedJournalVNext::open(zero.into_backend()).expect("reopen zero");
        assert!(reopened.read_all_image().expect("zero prefix").is_empty());
    }

    #[ktest]
    fn pio_vnext_cow_cut_before_manifest_reopens_old_endpoint() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("baseline");
        // Alternate payload plus both headers are durable; the first manifest
        // sector is the next write and fails before authority changes.
        journal.backend_mut().fail_writes_after = Some(3);
        assert!(journal.append_exact(b"-new").is_err());
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(reopened.read_all_image().expect("old endpoint"), b"old");
    }

    #[ktest]
    fn pio_vnext_cow_cut_after_manifest_copy_zero_is_complete() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("baseline");
        // The first manifest copy and its flush complete; copy one fails.
        journal.backend_mut().fail_writes_after = Some(4);
        assert!(journal.append_exact(b"-new").is_err());
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        let image = reopened.read_all_image().expect("complete endpoint");
        assert!(image == b"old" || image == b"old-new");
    }

    #[ktest]
    fn pio_vnext_full_preflight_keeps_old_replay_image() {
        let mut journal = vnext_journal();
        let usable = VNEXT_SEGMENT_CAPACITY - VNEXT_FRAME_HEADER;
        journal.append_exact(&vec![0x11; usable]).expect("first");
        journal.append_exact(&vec![0x22; usable]).expect("second");
        journal.append_exact(&vec![0x33; usable]).expect("third");
        assert!(matches!(
            journal.append_exact(b"overflow"),
            Err(BankedJournalError::JournalFull { .. })
        ));
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("old replay").len(),
            3 * usable
        );
    }

    /// Stable public OSDK gate. Cargo-OSDK 0.18 filters test names by exact
    /// path suffix despite documenting substring matching, so one named gate
    /// invokes the complete journal-specific regression set and yields an
    /// unambiguous non-zero execution receipt.
    #[ktest]
    fn cser_pio_journal_gate() {
        pio_journal_format_appends_exact_bytes_and_uses_two_barriers();
        pio_journal_torn_data_falls_back_to_last_committed_bank();
        pio_journal_torn_header_falls_back_to_last_committed_bank();
        strict_double_bank_rejects_a_lone_corrupt_bank();
        strict_double_bank_keeps_a_valid_predecessor_after_torn_successor();
        pio_journal_repair_publishes_the_exact_prefix();
        pio_journal_capacity_is_explicit_backpressure();
        pio_journal_cache_avoids_revalidating_banks_between_appends();
        pio_journal_failed_append_keeps_the_validated_cache();
        pio_journal_failed_repair_keeps_the_validated_cache();
        pio_journal_reopen_revalidates_corrupted_cached_bank();
        pio_journal_repair_updates_cache_only_after_readback();
        pio_vnext_appends_without_rewriting_the_prefix_and_reports_io();
        pio_vnext_unpublished_replacement_keeps_the_manifest_selected_prefix();
        pio_vnext_torn_header_copy_keeps_the_other_committed_copy();
        pio_vnext_manifest_selects_the_committed_endpoint_and_rejects_a_tie();
        pio_vnext_interrupted_checkpoint_keeps_the_old_chain();
        pio_vnext_readback_failure_does_not_publish_the_cache();
        pio_vnext_flush_failure_does_not_publish_the_cache();
        pio_vnext_corrupt_reopen_fails_closed();
        pio_vnext_rolls_to_segments_then_backpressures_and_recovers_twice();
        pio_vnext_checkpoint_rotates_to_a_single_replayable_replacement();
        pio_vnext_spans_segment_boundaries_without_fragmentation();
        pio_vnext_repair_publishes_early_current_and_zero_prefixes();
        pio_vnext_cow_cut_before_manifest_reopens_old_endpoint();
        pio_vnext_cow_cut_after_manifest_copy_zero_is_complete();
        pio_vnext_full_preflight_keeps_old_replay_image();
    }
}

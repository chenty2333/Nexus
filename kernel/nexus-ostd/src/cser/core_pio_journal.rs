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

const SECTOR_BYTES: usize = 512;
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

const BANK_MAGIC: [u8; 8] = *b"CSERPIO\0";
const BANK_VERSION: u16 = 1;
const HEADER_LEN: u16 = 112;
const HEADER_HASH_OFFSET: usize = 80;
const HEADER_HASH_END: usize = 112;

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

trait SectorBackend {
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
struct AtaPioDisk {
    ports: AtaPorts,
    drive: AtaDrive,
    sectors: u32,
}

impl AtaPioDisk {
    fn acquire(fixture: AtaJournalFixture) -> Result<Self, AtaPioError> {
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

#[derive(Debug)]
struct ActiveImage {
    bank: Option<u32>,
    generation: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct BankedJournal<B> {
    backend: B,
}

impl<B> BankedJournal<B>
where
    B: SectorBackend,
{
    fn open(backend: B) -> Result<Self, BankedJournalError<B::Error>> {
        let sectors = backend.sector_count();
        if sectors < REQUIRED_SECTORS {
            return Err(BankedJournalError::DeviceTooSmall {
                sectors,
                required: REQUIRED_SECTORS,
            });
        }
        Ok(Self { backend })
    }

    fn read_all_image(&mut self) -> Result<Vec<u8>, BankedJournalError<B::Error>> {
        Ok(self.read_active()?.bytes)
    }

    fn append_exact(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        let mut active = self.read_active()?;
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
        self.publish_next(active.bank, active.generation, &active.bytes)
    }

    fn repair_exact(&mut self, repair: JournalRepair) -> Result<(), BankedJournalError<B::Error>> {
        let mut active = self.read_active()?;
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
            return self.backend.flush().map_err(BankedJournalError::Storage);
        }
        active.bytes.truncate(offset);
        self.publish_next(active.bank, active.generation, &active.bytes)
    }

    fn publish_next(
        &mut self,
        active_bank: Option<u32>,
        generation: u64,
        bytes: &[u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
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
        self.backend.flush().map_err(BankedJournalError::Storage)?;

        let header = BankHeader {
            bank: target_bank,
            generation: next_generation,
            logical_len: bytes.len(),
            payload_digest: Sha256::digest(bytes).into(),
        }
        .encode();
        self.backend
            .write_sector(bank_header_lba(target_bank), &header)
            .map_err(BankedJournalError::Storage)?;
        self.backend.flush().map_err(BankedJournalError::Storage)?;

        match self.inspect_bank(target_bank)? {
            BankInspection::Valid(image)
                if image.generation == next_generation && image.bytes == bytes =>
            {
                Ok(())
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
            self.backend
                .write_sector(
                    bank_data_lba(bank)
                        + u32::try_from(sector_index).map_err(|_| {
                            BankedJournalError::JournalFull {
                                current: 0,
                                additional: bytes.len(),
                                capacity: JOURNAL_CAPACITY,
                            }
                        })?,
                    &sector,
                )
                .map_err(BankedJournalError::Storage)?;
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

    fn inspect_bank(&mut self, bank: u32) -> Result<BankInspection, BankedJournalError<B::Error>> {
        let mut header_sector = [0u8; SECTOR_BYTES];
        self.backend
            .read_sector(bank_header_lba(bank), &mut header_sector)
            .map_err(BankedJournalError::Storage)?;
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
            self.backend
                .read_sector(
                    bank_data_lba(bank)
                        + u32::try_from(sector_index)
                            .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                    &mut sector,
                )
                .map_err(BankedJournalError::Storage)?;
            chunk.copy_from_slice(&sector[..chunk.len()]);
        }
        let actual_digest: [u8; 32] = Sha256::digest(&bytes).into();
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
}

const fn bank_header_lba(bank: u32) -> u32 {
    FIRST_BANK_LBA + bank * BANK_SECTORS
}

const fn bank_data_lba(bank: u32) -> u32 {
    bank_header_lba(bank) + 1
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

#[cfg(ktest)]
mod tests {
    use alloc::{vec, vec::Vec};

    use ostd::prelude::ktest;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryError {
        Bounds,
    }

    #[derive(Debug)]
    struct MemoryDisk {
        sectors: Vec<[u8; SECTOR_BYTES]>,
        flushes: u32,
    }

    impl MemoryDisk {
        fn fixture() -> Self {
            Self {
                sectors: vec![[0u8; SECTOR_BYTES]; REQUIRED_SECTORS as usize],
                flushes: 0,
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
            *output = *self.sectors.get(lba as usize).ok_or(MemoryError::Bounds)?;
            Ok(())
        }

        fn write_sector(
            &mut self,
            lba: u32,
            input: &[u8; SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            *self
                .sectors
                .get_mut(lba as usize)
                .ok_or(MemoryError::Bounds)? = *input;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
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

        assert_eq!(journal.read_all_image().expect("fall back"), b"committed");
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

        assert_eq!(journal.read_all_image().expect("fall back"), b"committed");
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
}

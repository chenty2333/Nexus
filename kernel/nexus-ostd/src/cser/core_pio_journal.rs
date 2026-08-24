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

use alloc::{vec, vec::Vec};
use core::{hint::spin_loop, mem::size_of};

use cser_core::{
    CheckpointRecordPlan, CheckpointWrite, CompactingJournalBackend, Digest, DurableJournalBackend,
    JournalRecord, JournalRepair, StreamingJournalBackend,
};
use ostd::{arch::device::io_port::ReadWriteAccess, io::IoPort};
use sha2::{Digest as _, Sha256};

use crate::core_reboot::{OstdBootJournal, RecoveryCandidate};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryCandidateInspection {
    Blank,
    Invalid,
    Valid(BankRecoveryCandidate),
}

/// A complete, physically validated bank retained for trusted logical
/// selection.  The payload is intentionally not cached here; recovery reads
/// it through the bounded `RecoveryCandidate` source interface only after a
/// CSER anchor has been reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BankRecoveryCandidate {
    header: BankHeader,
}

impl BankRecoveryCandidate {
    fn descriptor(self) -> RecoveryCandidate {
        RecoveryCandidate::new(
            self.header.bank,
            self.header.generation,
            self.header.logical_len,
            Digest::new(self.header.payload_digest),
        )
    }
}

/// Selected/write metadata only; the logical payload remains on the bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveImage {
    bank: Option<u32>,
    generation: u64,
    logical_len: usize,
    payload_digest: [u8; 32],
}

struct PayloadWriteState {
    sector: [u8; SECTOR_BYTES],
    buffered: usize,
    target_sector: u32,
    written: usize,
    digest: Sha256,
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

/// Read-only snapshot of an explicitly enabled ATA journal measurement.
///
/// `image_bytes` is the currently replayable image, not physical device
/// occupancy.  Phase TSC values are diagnostic/un-calibrated guest samples;
/// callers must not treat them as wall-clock latency.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct JournalIoSnapshot {
    pub(crate) counters: JournalIoTelemetry,
    pub(crate) image_bytes: u64,
    pub(crate) capacity_bytes: u64,
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
    // The provider owns its dedicated fixture exclusively. No other writer
    // may mutate the two banks while this object is live; reopening validates
    // both banks again before establishing a new metadata cache.
    active: ActiveImage,
    /// Every bank whose header and exact payload digest validated at open.
    /// This is the recovery candidate set; `active` is only a selected/write
    /// metadata cache and is never established from physical generation alone.
    recovery_candidates: Vec<BankRecoveryCandidate>,
    /// Any failed mutation or post-mutation validation poisons this owner.
    /// The caller must reopen and re-enumerate the durable candidates before
    /// issuing another operation.
    poisoned: bool,
    // Disabled in production unless an owner explicitly opts in.  Keeping the
    // field absent from the default path avoids changing the measurement
    // envelope that the journal is intended to observe.
    telemetry: Option<JournalIoTelemetry>,
}

/// Fixed-scratch checkpoint destination for the legacy two-bank format.
/// `CheckpointRecordPlan::write_to` supplies arbitrary-sized slices; this sink
/// turns them into sector writes without constructing a checkpoint-sized
/// `Vec` or a `JournalRecord`.
struct BankCheckpointSink<'a, B>
where
    B: SectorBackend,
{
    journal: &'a mut BankedJournal<B>,
    bank: u32,
    sector_index: u32,
    buffer: [u8; SECTOR_BYTES],
    buffered: usize,
    written: usize,
    digest: Sha256,
}

impl<'a, B> BankCheckpointSink<'a, B>
where
    B: SectorBackend,
{
    fn new(journal: &'a mut BankedJournal<B>, bank: u32) -> Self {
        Self {
            journal,
            bank,
            sector_index: 0,
            buffer: [0; SECTOR_BYTES],
            buffered: 0,
            written: 0,
            digest: Sha256::new(),
        }
    }

    fn flush_buffer(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        if self.buffered == 0 {
            return Ok(());
        }
        let sector = self.buffer;
        self.journal
            .write_sector(bank_data_lba(self.bank) + self.sector_index, &sector)?;
        self.sector_index = self
            .sector_index
            .checked_add(1)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        self.buffer = [0; SECTOR_BYTES];
        self.buffered = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<([u8; 32], usize), BankedJournalError<B::Error>> {
        self.flush_buffer()?;
        Ok((self.digest.finalize().into(), self.written))
    }
}

impl<B> CheckpointWrite for BankCheckpointSink<'_, B>
where
    B: SectorBackend,
{
    type Error = BankedJournalError<B::Error>;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let resulting =
            self.written
                .checked_add(bytes.len())
                .ok_or(BankedJournalError::JournalFull {
                    current: self.written,
                    additional: bytes.len(),
                    capacity: JOURNAL_CAPACITY,
                })?;
        if resulting > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: self.written,
                additional: bytes.len(),
                capacity: JOURNAL_CAPACITY,
            });
        }

        let mut remaining = bytes;
        while !remaining.is_empty() {
            let available = SECTOR_BYTES - self.buffered;
            let amount = available.min(remaining.len());
            self.buffer[self.buffered..self.buffered + amount]
                .copy_from_slice(&remaining[..amount]);
            self.digest.update(&remaining[..amount]);
            if let Some(telemetry) = &mut self.journal.telemetry {
                telemetry.hash_bytes = telemetry.hash_bytes.saturating_add(amount as u64);
            }
            self.buffered += amount;
            self.written += amount;
            remaining = &remaining[amount..];
            if self.buffered == SECTOR_BYTES {
                self.flush_buffer()?;
            }
        }
        Ok(())
    }
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
                logical_len: 0,
                payload_digest: Sha256::digest(&[] as &[u8]).into(),
            },
            recovery_candidates: Vec::new(),
            poisoned: false,
            telemetry: None,
        };
        // Validate both banks once and retain every valid candidate.  No
        // physical generation is promoted to an authority cache here; boot
        // selects one only after the trusted CSER lease is available.
        journal.recovery_candidates = journal.discover_candidates(strict)?;
        Ok(journal)
    }

    fn read_all_image(&mut self) -> Result<Vec<u8>, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let candidate = if let Some(bank) = self.active.bank {
            Some(
                self.recovery_candidates
                    .iter()
                    .copied()
                    .find(|candidate| {
                        candidate.header.bank == bank
                            && candidate.header.generation == self.active.generation
                            && candidate.header.logical_len == self.active.logical_len
                            && candidate.header.payload_digest == self.active.payload_digest
                    })
                    .ok_or(BankedJournalError::CorruptBankMetadata)?,
            )
        } else {
            let candidate = self
                .recovery_candidates
                .iter()
                .max_by_key(|candidate| candidate.header.generation)
                .copied();
            if let Some(candidate) = candidate {
                // This is an explicit compatibility read, outside the
                // trusted candidate-selection path. Retain only metadata so
                // raw two-bank callers can continue their revision protocol
                // without making a payload cache authoritative for CSER.
                self.active = self.load_candidate(candidate)?;
            }
            candidate
        };
        let Some(candidate) = candidate else {
            return Ok(Vec::new());
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(candidate.header.logical_len)
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: candidate.header.logical_len,
            })?;
        bytes.resize(candidate.header.logical_len, 0);
        self.read_candidate_at(candidate.descriptor(), 0, &mut bytes)?;
        Ok(bytes)
    }

    fn discover_candidates(
        &mut self,
        strict: bool,
    ) -> Result<Vec<BankRecoveryCandidate>, BankedJournalError<B::Error>> {
        let first = self.inspect_bank_candidate(0)?;
        let second = self.inspect_bank_candidate(1)?;
        let mut candidates = Vec::new();
        if let RecoveryCandidateInspection::Valid(candidate) = first {
            candidates.push(candidate);
        }
        if let RecoveryCandidateInspection::Valid(candidate) = second {
            candidates.push(candidate);
        }
        if candidates.is_empty() {
            let invalid = matches!(first, RecoveryCandidateInspection::Invalid)
                || matches!(second, RecoveryCandidateInspection::Invalid);
            let both_invalid = matches!(first, RecoveryCandidateInspection::Invalid)
                && matches!(second, RecoveryCandidateInspection::Invalid);
            if (strict && invalid) || both_invalid {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
        }
        Ok(candidates)
    }

    fn read_bank_header_state(
        &mut self,
        bank: u32,
    ) -> Result<HeaderInspection, BankedJournalError<B::Error>> {
        let mut header_sector = [0u8; SECTOR_BYTES];
        self.read_sector(bank_header_lba(bank), &mut header_sector)?;
        Ok(BankHeader::decode(bank, &header_sector))
    }

    /// Validates a bank's exact payload digest without retaining its logical
    /// bytes. This keeps the candidate set bounded even when both banks carry
    /// long divergent streams.
    fn inspect_bank_candidate(
        &mut self,
        bank: u32,
    ) -> Result<RecoveryCandidateInspection, BankedJournalError<B::Error>> {
        let header = match self.read_bank_header_state(bank)? {
            HeaderInspection::Blank => return Ok(RecoveryCandidateInspection::Blank),
            HeaderInspection::Invalid => return Ok(RecoveryCandidateInspection::Invalid),
            HeaderInspection::Valid(header) => header,
        };
        let mut hasher = Sha256::new();
        let mut remaining = header.logical_len;
        let mut sector_index = 0u32;
        while remaining != 0 {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(bank_data_lba(bank) + sector_index, &mut sector)?;
            let used = remaining.min(SECTOR_BYTES);
            hasher.update(&sector[..used]);
            if let Some(telemetry) = &mut self.telemetry {
                telemetry.hash_bytes = telemetry.hash_bytes.saturating_add(used as u64);
            }
            remaining -= used;
            sector_index = sector_index
                .checked_add(1)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        if <[u8; 32]>::from(hasher.finalize()) != header.payload_digest {
            return Ok(RecoveryCandidateInspection::Invalid);
        }
        Ok(RecoveryCandidateInspection::Valid(BankRecoveryCandidate {
            header,
        }))
    }

    fn load_candidate(
        &mut self,
        candidate: BankRecoveryCandidate,
    ) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        // Candidate validation already streamed and hashed the exact payload.
        // Selecting it therefore installs only the bounded metadata needed by
        // the next append/repair; the logical bytes remain on media.
        Ok(ActiveImage {
            bank: Some(candidate.header.bank),
            generation: candidate.header.generation,
            logical_len: candidate.header.logical_len,
            payload_digest: candidate.header.payload_digest,
        })
    }

    fn select_candidate(
        &mut self,
        requested: Option<RecoveryCandidate>,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let Some(requested) = requested else {
            self.active = ActiveImage {
                bank: None,
                generation: 0,
                logical_len: 0,
                payload_digest: Sha256::digest(&[] as &[u8]).into(),
            };
            return Ok(());
        };
        self.revalidate_candidate(requested)?;
        let bank = self
            .recovery_candidates
            .iter()
            .copied()
            .find(|candidate| candidate.descriptor() == requested)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        self.active = self.load_candidate(bank)?;
        Ok(())
    }

    fn revalidate_candidate(
        &mut self,
        requested: RecoveryCandidate,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let bank = self
            .recovery_candidates
            .iter()
            .copied()
            .find(|candidate| candidate.descriptor() == requested)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        match self.inspect_bank_candidate(bank.header.bank)? {
            RecoveryCandidateInspection::Valid(current) if current.descriptor() == requested => {
                Ok(())
            }
            RecoveryCandidateInspection::Blank
            | RecoveryCandidateInspection::Invalid
            | RecoveryCandidateInspection::Valid(_) => Err(BankedJournalError::CorruptBankMetadata),
        }
    }

    fn recovery_candidates(
        &mut self,
    ) -> Result<Vec<RecoveryCandidate>, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        // Re-enumerate after any anchored repair/append. The retained vector
        // is the last validated set, not an authority cache which may outlive
        // a durable bank replacement.
        self.recovery_candidates = self.discover_candidates(true)?;
        Ok(self
            .recovery_candidates
            .iter()
            .copied()
            .map(BankRecoveryCandidate::descriptor)
            .collect())
    }

    fn read_candidate_at(
        &mut self,
        requested: RecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let bank = self
            .recovery_candidates
            .iter()
            .copied()
            .find(|candidate| candidate.descriptor() == requested)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let end =
            offset
                .checked_add(output.len())
                .ok_or(BankedJournalError::InvalidRepairOffset {
                    offset,
                    length: bank.header.logical_len,
                })?;
        if end > bank.header.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: bank.header.logical_len,
            });
        }
        if output.is_empty() {
            return Ok(());
        }
        let first_sector = offset / SECTOR_BYTES;
        let last_sector = (end - 1) / SECTOR_BYTES;
        for sector_index in first_sector..=last_sector {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(
                bank_data_lba(bank.header.bank)
                    + u32::try_from(sector_index)
                        .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                &mut sector,
            )?;
            let sector_begin = sector_index * SECTOR_BYTES;
            let begin = offset.max(sector_begin);
            let copy_end = end.min(sector_begin + SECTOR_BYTES);
            output[begin - offset..copy_end - offset]
                .copy_from_slice(&sector[begin - sector_begin..copy_end - sector_begin]);
        }
        Ok(())
    }

    fn append_exact(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let resulting_len = self.active.logical_len.checked_add(suffix.len()).ok_or(
            BankedJournalError::JournalFull {
                current: self.active.logical_len,
                additional: suffix.len(),
                capacity: JOURNAL_CAPACITY,
            },
        )?;
        if resulting_len > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: self.active.logical_len,
                additional: suffix.len(),
                capacity: JOURNAL_CAPACITY,
            });
        }
        let target_bank = self.active.bank.map_or(0, |bank| bank ^ 1);
        self.prepare_candidate_slot(target_bank)?;
        let published = self.publish_next_stream(
            self.active.bank,
            self.active.generation,
            self.active.logical_len,
            suffix,
        )?;
        self.install_active_candidate(published);
        self.active = published;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn repair_exact(&mut self, repair: JournalRepair) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let offset = repair.offset();
        if offset > self.active.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: self.active.logical_len,
            });
        }
        if offset == self.active.logical_len {
            // There is no suffix to rewrite, but the recovery contract still
            // asks this provider to complete a durability barrier.
            return self.flush();
        }
        let target_bank = self.active.bank.map_or(0, |bank| bank ^ 1);
        self.prepare_candidate_slot(target_bank)?;
        let published =
            self.publish_next_stream(self.active.bank, self.active.generation, offset, &[])?;
        self.install_active_candidate(published);
        self.active = published;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn repair_exact_from_candidate(
        &mut self,
        repair: JournalRepair,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let Some(requested) = candidate else {
            return self.repair_exact(repair);
        };
        self.require_reopen()?;
        self.revalidate_candidate(requested)?;
        let source = self
            .recovery_candidates
            .iter()
            .copied()
            .find(|candidate| candidate.descriptor() == requested)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let offset = repair.offset();
        if offset > source.header.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: source.header.logical_len,
            });
        }
        if offset == source.header.logical_len {
            return self.flush();
        }
        let target_bank = source.header.bank ^ 1;
        self.prepare_candidate_slot(target_bank)?;
        let published = self.publish_next_stream(
            Some(source.header.bank),
            source.header.generation,
            offset,
            &[],
        )?;
        self.install_active_candidate(published);
        self.active = published;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    /// Publishes an independently supplied complete payload. This remains for
    /// the raw two-bank facade; the CSER append/repair paths use
    /// [`Self::publish_next_stream`] so the existing payload is copied sector
    /// by sector instead of being cloned into a second `Vec`.
    fn publish_next(
        &mut self,
        active_bank: Option<u32>,
        generation: u64,
        bytes: &[u8],
    ) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        if bytes.len() > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: bytes.len(),
                capacity: JOURNAL_CAPACITY,
            });
        }
        let target_bank = active_bank.map_or(0, |bank| bank ^ 1);
        self.prepare_candidate_slot(target_bank)?;
        let published = self.publish_next_stream(active_bank, generation, 0, bytes)?;
        self.install_active_candidate(published);
        self.active = published;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(published)
    }

    /// Copies the old logical prefix from its bank into the inactive bank and
    /// appends `suffix` using one sector scratch buffer. The source is never
    /// materialized, and the returned metadata is the only post-publication
    /// cache installed by the journal.
    fn publish_next_stream(
        &mut self,
        active_bank: Option<u32>,
        generation: u64,
        source_len: usize,
        suffix: &[u8],
    ) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        if active_bank.is_none() && source_len != 0 {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let logical_len =
            source_len
                .checked_add(suffix.len())
                .ok_or(BankedJournalError::JournalFull {
                    current: source_len,
                    additional: suffix.len(),
                    capacity: JOURNAL_CAPACITY,
                })?;
        if logical_len > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: source_len,
                additional: suffix.len(),
                capacity: JOURNAL_CAPACITY,
            });
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        let target_bank = active_bank.map_or(0, |bank| bank ^ 1);
        let result = (|| {
            let (payload_digest, written) =
                self.write_payload_stream(target_bank, active_bank, source_len, suffix)?;
            if written != logical_len {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
            self.mark_phase(JournalIoPhase::PayloadWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::PayloadFlushed);

            let expected = BankHeader {
                bank: target_bank,
                generation: next_generation,
                logical_len,
                payload_digest,
            };
            let encoded = expected.encode();
            self.write_sector(bank_header_lba(target_bank), &encoded)?;
            self.mark_phase(JournalIoPhase::HeaderWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::HeaderFlushed);

            let RecoveryCandidateInspection::Valid(candidate) =
                self.inspect_bank_candidate(target_bank)?
            else {
                return Err(BankedJournalError::ReadbackMismatch);
            };
            if candidate.header != expected {
                return Err(BankedJournalError::ReadbackMismatch);
            }
            self.mark_phase(JournalIoPhase::ReadbackValidated);
            Ok(ActiveImage {
                bank: Some(target_bank),
                generation: next_generation,
                logical_len,
                payload_digest,
            })
        })();
        if result.is_err() {
            // From the first payload write onward the medium may contain an
            // indistinguishable torn successor. Never continue using this
            // owner after any such error; a fresh open must re-enumerate it.
            self.poisoned = true;
        }
        result
    }

    fn write_payload_stream(
        &mut self,
        target_bank: u32,
        source_bank: Option<u32>,
        source_len: usize,
        suffix: &[u8],
    ) -> Result<([u8; 32], usize), BankedJournalError<B::Error>> {
        let mut output = PayloadWriteState {
            sector: [0u8; SECTOR_BYTES],
            buffered: 0,
            target_sector: 0,
            written: 0,
            digest: Sha256::new(),
        };

        let mut remaining = source_len;
        let mut source_sector = 0u32;
        while remaining != 0 {
            let bank = source_bank.ok_or(BankedJournalError::CorruptBankMetadata)?;
            let mut source = [0u8; SECTOR_BYTES];
            self.read_sector(bank_data_lba(bank) + source_sector, &mut source)?;
            let used = remaining.min(SECTOR_BYTES);
            self.write_payload_piece(target_bank, &mut output, &source[..used])?;
            remaining -= used;
            source_sector = source_sector
                .checked_add(1)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        self.write_payload_piece(target_bank, &mut output, suffix)?;
        if output.buffered != 0 {
            self.write_sector(
                bank_data_lba(target_bank) + output.target_sector,
                &output.sector,
            )?;
        }
        Ok((output.digest.finalize().into(), output.written))
    }

    fn write_payload_piece(
        &mut self,
        target_bank: u32,
        output: &mut PayloadWriteState,
        bytes: &[u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let amount = (SECTOR_BYTES - output.buffered).min(remaining.len());
            output.sector[output.buffered..output.buffered + amount]
                .copy_from_slice(&remaining[..amount]);
            output.digest.update(&remaining[..amount]);
            if let Some(telemetry) = &mut self.telemetry {
                telemetry.hash_bytes = telemetry.hash_bytes.saturating_add(amount as u64);
            }
            output.buffered += amount;
            output.written = output
                .written
                .checked_add(amount)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            remaining = &remaining[amount..];
            if output.buffered == SECTOR_BYTES {
                let full = output.sector;
                self.write_sector(bank_data_lba(target_bank) + output.target_sector, &full)?;
                output.target_sector = output
                    .target_sector
                    .checked_add(1)
                    .ok_or(BankedJournalError::CorruptBankMetadata)?;
                output.sector = [0; SECTOR_BYTES];
                output.buffered = 0;
            }
        }
        Ok(())
    }

    fn stage_checkpoint(
        &mut self,
        plan: &CheckpointRecordPlan,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let logical_len = plan.record_len();
        if logical_len > JOURNAL_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: logical_len,
                capacity: JOURNAL_CAPACITY,
            });
        }
        if !self.recovery_candidates.is_empty() && self.active.bank.is_none() {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let target_bank = self.active.bank.map_or(0, |bank| bank ^ 1);
        let generation = self
            .active
            .generation
            .checked_add(1)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        // The candidate vector is bounded to the two physical banks. Reserve
        // its only possible growth before any durable write.
        self.prepare_candidate_slot(target_bank)?;

        let result = (|| {
            let mut sink = BankCheckpointSink::new(self, target_bank);
            let written = plan.write_to(&mut sink)?;
            let (payload_digest, sink_written) = sink.finish()?;
            if written != sink_written {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
            if written != logical_len {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
            self.mark_phase(JournalIoPhase::PayloadWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::PayloadFlushed);

            let expected_header = BankHeader {
                bank: target_bank,
                generation,
                logical_len,
                payload_digest,
            };
            let header = expected_header.encode();
            self.write_sector(bank_header_lba(target_bank), &header)?;
            self.mark_phase(JournalIoPhase::HeaderWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::HeaderFlushed);

            let RecoveryCandidateInspection::Valid(candidate) =
                self.inspect_bank_candidate(target_bank)?
            else {
                return Err(BankedJournalError::ReadbackMismatch);
            };
            if candidate.header != expected_header {
                return Err(BankedJournalError::ReadbackMismatch);
            }
            self.mark_phase(JournalIoPhase::ReadbackValidated);
            self.install_candidate(candidate);
            self.active = ActiveImage {
                bank: Some(target_bank),
                generation,
                logical_len,
                payload_digest,
            };
            self.mark_phase(JournalIoPhase::CacheUpdated);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn read_active(&mut self) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let candidates = self.discover_candidates(false)?;
        match candidates.as_slice() {
            [] => Ok(ActiveImage {
                bank: None,
                generation: 0,
                logical_len: 0,
                payload_digest: Sha256::digest(&[] as &[u8]).into(),
            }),
            [candidate] => self.load_candidate(*candidate),
            [left, right] => {
                let left_image = self.load_candidate(*left)?;
                let right_image = self.load_candidate(*right)?;
                if left.header.logical_len == right.header.logical_len
                    && left.header.payload_digest == right.header.payload_digest
                {
                    Ok(if left.header.generation >= right.header.generation {
                        left_image
                    } else {
                        right_image
                    })
                } else {
                    Err(BankedJournalError::ConflictingGeneration {
                        generation: left.header.generation.max(right.header.generation),
                    })
                }
            }
            _ => Err(BankedJournalError::CorruptBankMetadata),
        }
    }

    /// Like `read_active`, but treats a malformed lone bank as corruption
    /// rather than an uninitialized medium.  A valid old bank plus a torn
    /// inactive update remains recoverable, which is the double-bank crash
    /// contract; a blank peer gives no such recovery authority.
    fn read_active_strict(&mut self) -> Result<ActiveImage, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let candidates = self.discover_candidates(true)?;
        match candidates.as_slice() {
            [] => Ok(ActiveImage {
                bank: None,
                generation: 0,
                logical_len: 0,
                payload_digest: Sha256::digest(&[] as &[u8]).into(),
            }),
            [candidate] => self.load_candidate(*candidate),
            [left, right] => {
                let left_image = self.load_candidate(*left)?;
                let right_image = self.load_candidate(*right)?;
                if left.header.logical_len == right.header.logical_len
                    && left.header.payload_digest == right.header.payload_digest
                {
                    Ok(if left.header.generation >= right.header.generation {
                        left_image
                    } else {
                        right_image
                    })
                } else {
                    Err(BankedJournalError::ConflictingGeneration {
                        generation: left.header.generation.max(right.header.generation),
                    })
                }
            }
            _ => Err(BankedJournalError::CorruptBankMetadata),
        }
    }

    fn prepare_candidate_slot(&mut self, bank: u32) -> Result<(), BankedJournalError<B::Error>> {
        if self
            .recovery_candidates
            .iter()
            .any(|candidate| candidate.header.bank == bank)
        {
            return Ok(());
        }
        self.recovery_candidates
            .try_reserve(1)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: 1 })?;
        Ok(())
    }

    fn install_candidate(&mut self, candidate: BankRecoveryCandidate) {
        if let Some(existing) = self
            .recovery_candidates
            .iter_mut()
            .find(|existing| existing.header.bank == candidate.header.bank)
        {
            *existing = candidate;
        } else {
            // `prepare_candidate_slot` has reserved this bounded insertion
            // before the first media mutation. The vector is therefore full
            // only with the two fixed physical banks and cannot allocate here.
            self.recovery_candidates.push(candidate);
        }
    }

    fn install_active_candidate(&mut self, active: ActiveImage) {
        let Some(bank) = active.bank else {
            return;
        };
        self.install_candidate(BankRecoveryCandidate {
            header: BankHeader {
                bank,
                generation: active.generation,
                logical_len: active.logical_len,
                payload_digest: active.payload_digest,
            },
        });
    }

    fn require_reopen(&self) -> Result<(), BankedJournalError<B::Error>> {
        if self.poisoned {
            Err(BankedJournalError::CorruptBankMetadata)
        } else {
            Ok(())
        }
    }

    #[cfg(ktest)]
    fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    #[cfg(ktest)]
    fn into_backend(self) -> B {
        self.backend
    }

    fn set_telemetry(&mut self, enabled: bool) {
        self.telemetry = enabled.then(JournalIoTelemetry::default);
    }

    fn telemetry(&self) -> Option<JournalIoTelemetry> {
        self.telemetry
    }

    fn active_logical_len(&self) -> usize {
        self.active.bank.map_or(0, |_| self.active.logical_len)
    }

    #[cfg(ktest)]
    fn enable_telemetry(&mut self) {
        self.set_telemetry(true);
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
        if let Err(error) = self.backend.write_sector(lba, input) {
            self.poisoned = true;
            return Err(BankedJournalError::Storage(error));
        }
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.sectors_written = telemetry.sectors_written.saturating_add(1);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        if let Err(error) = self.backend.flush() {
            self.poisoned = true;
            return Err(BankedJournalError::Storage(error));
        }
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.flushes = telemetry.flushes.saturating_add(1);
        }
        Ok(())
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
        // Canonical vNext frames are padded to sectors. In-place append relies
        // on this invariant so it never read-modify-writes a sector belonging
        // to the previously committed endpoint.
        if logical_len > VNEXT_SEGMENT_CAPACITY || logical_len % SECTOR_BYTES != 0 {
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
    Valid(VNextHeader),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VNextFrameSpan {
    raw_start: usize,
    logical_start: usize,
    logical_len: usize,
}

type VNextCheckpointFinish<E> = Result<
    (
        [Option<VNextHeader>; VNEXT_SEGMENT_COUNT as usize],
        usize,
        VNextHeader,
    ),
    BankedJournalError<E>,
>;
type VNextSegmentDigests<E> = Result<([u8; 32], [u8; 32]), BankedJournalError<E>>;
type VNextFrameScan<E> = Result<Option<(Vec<VNextFrameSpan>, usize)>, BankedJournalError<E>>;

/// A manifest-selected physical chain retained without its complete replay
/// image. `head` is a storage hash only; logical CSER validation is performed
/// by the recovery source after the trusted anchor is available.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VNextRecoveryCandidate {
    manifest_copy: u32,
    /// Header copy which was observed to carry the selected endpoint.  The
    /// other copy is kept intact while an in-place append is staged, so the
    /// manifest-selected old endpoint remains recoverable until the final
    /// manifest pivot.
    endpoint_copy: u32,
    endpoint: VNextHeader,
    segments: Vec<VNextHeader>,
    frames: Vec<VNextFrameSpan>,
    logical_len: usize,
}

impl VNextRecoveryCandidate {
    fn descriptor(&self) -> RecoveryCandidate {
        RecoveryCandidate::new(
            self.manifest_copy,
            self.endpoint.generation,
            self.logical_len,
            Digest::new(self.endpoint.head),
        )
    }
}

#[derive(Clone, Debug)]
struct VNextActiveImage {
    header: Option<VNextHeader>,
    /// Manifest copy selected by trusted recovery. Publication overwrites the
    /// other copy first so this authority root survives every pre-pivot tear.
    manifest_copy: Option<u32>,
    occupied: [bool; VNEXT_SEGMENT_COUNT as usize],
}

/// Development vNext journal: three append-only segments, two independently
/// checksummed committed headers per segment, and a prefix hash chain.
///
/// Normal appends only rewrite the final partially filled data sector plus one
/// newly committed header copy.  The manifest makes that copy authoritative
/// before the other header copy is mirrored, so a crash always has either the
/// old endpoint or a self-validating new endpoint. It is intentionally kept
/// behind a separate type
/// until the core exposes a replayable checkpoint representation.  Calling
/// [`Self::checkpoint_exact`] is only sound when its `image` is already a
/// complete replacement journal stream (for example a future core snapshot
/// envelope); the current `JournalRecord` stream does not provide that.
#[derive(Debug)]
#[allow(dead_code)]
struct SegmentedJournalVNext<B> {
    backend: B,
    active: VNextActiveImage,
    /// Whether the selected metadata snapshot was explicitly installed for
    /// the legacy compatibility append/read facade. No payload bytes are
    /// retained here; recovery always uses candidate metadata and read-at.
    active_materialized: bool,
    recovery_candidates: Vec<VNextRecoveryCandidate>,
    poisoned: bool,
    telemetry: Option<JournalIoTelemetry>,
}

struct VNextCheckpointSegment {
    segment: u32,
    generation: u64,
    first_generation: u64,
    previous_head: [u8; 32],
    logical_len: usize,
    sector_index: u32,
    buffer: [u8; SECTOR_BYTES],
    buffered: usize,
    payload_digest: Sha256,
    head_digest: Sha256,
}

impl VNextCheckpointSegment {
    fn new(segment: u32, generation: u64, first_generation: u64, previous_head: [u8; 32]) -> Self {
        let mut head_digest = Sha256::new();
        head_digest.update(previous_head);
        Self {
            segment,
            generation,
            first_generation,
            previous_head,
            logical_len: 0,
            sector_index: 0,
            buffer: [0; SECTOR_BYTES],
            buffered: 0,
            payload_digest: Sha256::new(),
            head_digest,
        }
    }
}

/// Streams one canonical checkpoint frame through inactive vNext segments.
/// Only sector scratch, digest state, and a bounded header table are retained;
/// the checkpoint record and framed image never become a `Vec`.
struct VNextCheckpointWriter<'a, B>
where
    B: SectorBackend,
{
    journal: &'a mut SegmentedJournalVNext<B>,
    free: [u32; VNEXT_SEGMENT_COUNT as usize],
    free_len: usize,
    next_free: usize,
    needed: usize,
    expected_raw_len: usize,
    written: usize,
    frame_digest: Sha256,
    frame_payload_written: usize,
    current: Option<VNextCheckpointSegment>,
    headers: [Option<VNextHeader>; VNEXT_SEGMENT_COUNT as usize],
    header_count: usize,
    first_generation: u64,
    previous_head: [u8; 32],
}

impl<'a, B> VNextCheckpointWriter<'a, B>
where
    B: SectorBackend,
{
    fn new(
        journal: &'a mut SegmentedJournalVNext<B>,
        free: [u32; VNEXT_SEGMENT_COUNT as usize],
        free_len: usize,
        needed: usize,
        expected_raw_len: usize,
        first_generation: u64,
    ) -> Result<Self, BankedJournalError<B::Error>> {
        if free_len < needed || needed == 0 || needed > VNEXT_SEGMENT_COUNT as usize {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: expected_raw_len,
                capacity: VNEXT_CAPACITY,
            });
        }
        let first_segment = free[0];
        let current =
            VNextCheckpointSegment::new(first_segment, first_generation, first_generation, [0; 32]);
        Ok(Self {
            journal,
            free,
            free_len,
            next_free: 1,
            needed,
            expected_raw_len,
            written: 0,
            frame_digest: Sha256::new(),
            frame_payload_written: 0,
            current: Some(current),
            headers: core::array::from_fn(|_| None),
            header_count: 0,
            first_generation,
            previous_head: [0; 32],
        })
    }

    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        let resulting =
            self.written
                .checked_add(bytes.len())
                .ok_or(BankedJournalError::JournalFull {
                    current: self.written,
                    additional: bytes.len(),
                    capacity: VNEXT_CAPACITY,
                })?;
        if resulting > self.expected_raw_len {
            return Err(BankedJournalError::JournalFull {
                current: self.written,
                additional: bytes.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if self.current.is_none() {
                self.start_next_segment()?;
            }
            let segment_remaining = {
                let current = self
                    .current
                    .as_ref()
                    .ok_or(BankedJournalError::CorruptBankMetadata)?;
                VNEXT_SEGMENT_CAPACITY - current.logical_len
            };
            if segment_remaining == 0 {
                self.finish_current_segment()?;
                continue;
            }
            let sector_remaining = {
                let current = self
                    .current
                    .as_ref()
                    .ok_or(BankedJournalError::CorruptBankMetadata)?;
                SECTOR_BYTES - current.buffered
            };
            let amount = remaining.len().min(segment_remaining).min(sector_remaining);
            {
                let current = self
                    .current
                    .as_mut()
                    .ok_or(BankedJournalError::CorruptBankMetadata)?;
                current.buffer[current.buffered..current.buffered + amount]
                    .copy_from_slice(&remaining[..amount]);
                current.payload_digest.update(&remaining[..amount]);
                current.head_digest.update(&remaining[..amount]);
                current.buffered += amount;
                current.logical_len += amount;
            }
            self.written += amount;
            remaining = &remaining[amount..];
            let full_sector = self
                .current
                .as_ref()
                .is_some_and(|current| current.buffered == SECTOR_BYTES);
            if full_sector {
                self.flush_current_sector()?;
            }
            let full_segment = self
                .current
                .as_ref()
                .is_some_and(|current| current.logical_len == VNEXT_SEGMENT_CAPACITY);
            if full_segment && !remaining.is_empty() {
                self.finish_current_segment()?;
            }
        }
        Ok(())
    }

    fn write_candidate_raw(
        &mut self,
        candidate: &VNextRecoveryCandidate,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let raw_len = SegmentedJournalVNext::<B>::candidate_raw_len(candidate)?;
        let mut offset = 0usize;
        let mut scratch = [0u8; SECTOR_BYTES];
        while offset < raw_len {
            let amount = (raw_len - offset).min(scratch.len());
            self.journal
                .read_candidate_raw_at_inner(candidate, offset, &mut scratch[..amount])?;
            self.write_raw(&scratch[..amount])?;
            offset = offset
                .checked_add(amount)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        Ok(())
    }

    fn write_candidate_logical_prefix(
        &mut self,
        candidate: &VNextRecoveryCandidate,
        logical_len: usize,
    ) -> Result<(), BankedJournalError<B::Error>> {
        if logical_len > candidate.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset: logical_len,
                length: candidate.logical_len,
            });
        }
        let mut offset = 0usize;
        let mut scratch = [0u8; SECTOR_BYTES];
        while offset < logical_len {
            let amount = (logical_len - offset).min(scratch.len());
            self.journal
                .read_candidate_at_inner(candidate, offset, &mut scratch[..amount])?;
            self.write_all(&scratch[..amount])?;
            offset = offset
                .checked_add(amount)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        Ok(())
    }

    fn flush_current_sector(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        let (segment, sector_index, sector) = {
            let current = self
                .current
                .as_ref()
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            if current.buffered == 0 {
                return Ok(());
            }
            (current.segment, current.sector_index, current.buffer)
        };
        self.journal
            .write_sector(vnext_data_lba(segment) + sector_index, &sector)?;
        let current = self
            .current
            .as_mut()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        current.sector_index = current
            .sector_index
            .checked_add(1)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        current.buffer = [0; SECTOR_BYTES];
        current.buffered = 0;
        Ok(())
    }

    fn start_next_segment(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        if self.next_free >= self.free_len || self.header_count >= self.needed {
            return Err(BankedJournalError::JournalFull {
                current: self.written,
                additional: self.expected_raw_len.saturating_sub(self.written),
                capacity: VNEXT_CAPACITY,
            });
        }
        let generation = self
            .first_generation
            .checked_add(self.header_count as u64)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        let segment = self.free[self.next_free];
        self.next_free += 1;
        self.current = Some(VNextCheckpointSegment::new(
            segment,
            generation,
            self.first_generation,
            self.previous_head,
        ));
        Ok(())
    }

    fn finish_current_segment(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        self.flush_current_sector()?;
        let current = self
            .current
            .take()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let payload_digest: [u8; 32] = current.payload_digest.finalize().into();
        let head: [u8; 32] = current.head_digest.finalize().into();
        let header = VNextHeader {
            segment: current.segment,
            generation: current.generation,
            first_generation: current.first_generation,
            logical_len: current.logical_len,
            previous_head: current.previous_head,
            payload_digest,
            head,
        };
        self.journal.publish_stream_segment_header(&header)?;
        if self.header_count >= self.headers.len() {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        self.headers[self.header_count] = Some(header.clone());
        self.header_count += 1;
        self.previous_head = header.head;
        Ok(())
    }

    fn finish_frame_payload(
        &mut self,
        expected_digest: [u8; 32],
        expected_len: usize,
    ) -> Result<(), BankedJournalError<B::Error>> {
        if self.frame_payload_written != expected_len
            || <[u8; 32]>::from(self.frame_digest.clone().finalize()) != expected_digest
        {
            return Err(BankedJournalError::ReadbackMismatch);
        }
        Ok(())
    }

    fn finish(mut self) -> VNextCheckpointFinish<B::Error> {
        if self.written != self.expected_raw_len {
            return Err(BankedJournalError::ReadbackMismatch);
        }
        self.finish_current_segment()?;
        if self.header_count != self.needed {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let endpoint = self.headers[self.header_count - 1]
            .as_ref()
            .cloned()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        Ok((self.headers, self.header_count, endpoint))
    }
}

impl<B> CheckpointWrite for VNextCheckpointWriter<'_, B>
where
    B: SectorBackend,
{
    type Error = BankedJournalError<B::Error>;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.frame_digest.update(bytes);
        self.frame_payload_written = self.frame_payload_written.checked_add(bytes.len()).ok_or(
            BankedJournalError::JournalFull {
                current: self.frame_payload_written,
                additional: bytes.len(),
                capacity: VNEXT_CAPACITY,
            },
        )?;
        self.write_raw(bytes)
    }
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
                manifest_copy: None,
                occupied: [false; VNEXT_SEGMENT_COUNT as usize],
            },
            active_materialized: false,
            recovery_candidates: Vec::new(),
            poisoned: false,
            telemetry: None,
        };
        // Keep every valid manifest chain. No endpoint is promoted to the
        // active cache until recovery compares its logical records with the
        // trusted CSER snapshot.
        journal.recovery_candidates = journal.discover_candidates()?;
        journal.active_materialized = journal.recovery_candidates.is_empty();
        Ok(journal)
    }

    fn read_all_image(&mut self) -> Result<Vec<u8>, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        if self.active.header.is_none() && !self.recovery_candidates.is_empty() {
            // Compatibility-only inspection. The trusted boot path uses
            // `recovery_candidates` + `read_candidate_at` and never chooses by
            // this physical generation ordering.
            let candidate = self
                .recovery_candidates
                .iter()
                .max_by_key(|candidate| candidate.endpoint.generation)
                .cloned()
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            self.set_active_candidate(&candidate, true);
            self.active_materialized = true;
        }
        let Some(candidate) = self.active_candidate().cloned() else {
            return Ok(Vec::new());
        };
        let raw_len = Self::candidate_raw_len(&candidate)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(raw_len)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: raw_len })?;
        raw.resize(raw_len, 0);
        self.read_candidate_raw_at_inner(&candidate, 0, &mut raw)?;
        decode_vnext_frames(&raw).ok_or(BankedJournalError::CorruptBankMetadata)
    }

    fn recovery_candidates(
        &mut self,
    ) -> Result<Vec<RecoveryCandidate>, BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let candidates = self.discover_candidates()?;
        let descriptors = candidates
            .iter()
            .map(VNextRecoveryCandidate::descriptor)
            .collect();
        self.recovery_candidates = candidates;
        Ok(descriptors)
    }

    fn select_candidate(
        &mut self,
        requested: Option<RecoveryCandidate>,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let Some(requested) = requested else {
            self.active = VNextActiveImage {
                header: None,
                manifest_copy: None,
                occupied: [false; VNEXT_SEGMENT_COUNT as usize],
            };
            self.active_materialized = true;
            return Ok(());
        };
        self.revalidate_candidate(requested)?;
        let candidate = self
            .recovery_candidates
            .iter()
            .find(|candidate| candidate.descriptor() == requested)
            .cloned()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        self.set_active_candidate(&candidate, true);
        self.active_materialized = true;
        Ok(())
    }

    fn revalidate_candidate(
        &mut self,
        requested: RecoveryCandidate,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let expected = self
            .recovery_candidates
            .iter()
            .find(|candidate| candidate.descriptor() == requested)
            .cloned()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let current = self
            .discover_candidates()?
            .into_iter()
            .find(|candidate| candidate.descriptor() == requested);
        if current.as_ref() == Some(&expected) {
            Ok(())
        } else {
            Err(BankedJournalError::CorruptBankMetadata)
        }
    }

    fn set_active_candidate(&mut self, candidate: &VNextRecoveryCandidate, _selected: bool) {
        let mut occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        for segment in &candidate.segments {
            occupied[segment.segment as usize] = true;
        }
        self.active = VNextActiveImage {
            header: Some(candidate.endpoint.clone()),
            manifest_copy: Some(candidate.manifest_copy),
            occupied,
        };
    }

    fn active_candidate(&self) -> Option<&VNextRecoveryCandidate> {
        let endpoint = self.active.header.as_ref()?;
        self.recovery_candidates
            .iter()
            .find(|candidate| candidate.endpoint == *endpoint)
    }

    fn candidate_raw_len(
        candidate: &VNextRecoveryCandidate,
    ) -> Result<usize, BankedJournalError<B::Error>> {
        candidate
            .segments
            .iter()
            .try_fold(0usize, |total, segment| {
                total.checked_add(segment.logical_len)
            })
            .ok_or(BankedJournalError::CorruptBankMetadata)
    }

    fn read_candidate_at(
        &mut self,
        requested: RecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let candidate = self
            .recovery_candidates
            .iter()
            .find(|candidate| candidate.descriptor() == requested)
            .cloned()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let end =
            offset
                .checked_add(output.len())
                .ok_or(BankedJournalError::InvalidRepairOffset {
                    offset,
                    length: candidate.logical_len,
                })?;
        if end > candidate.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: candidate.logical_len,
            });
        }
        if output.is_empty() {
            return Ok(());
        }
        self.read_candidate_at_inner(&candidate, offset, output)
    }

    fn read_candidate_at_inner(
        &mut self,
        candidate: &VNextRecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        let end = offset
            .checked_add(output.len())
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        if end > candidate.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: candidate.logical_len,
            });
        }
        let mut copied = 0usize;
        for frame in &candidate.frames {
            let frame_end = frame
                .logical_start
                .checked_add(frame.logical_len)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            let begin = offset.max(frame.logical_start);
            let copy_end = end.min(frame_end);
            if begin >= copy_end {
                continue;
            }
            let raw_offset = frame.raw_start + (begin - frame.logical_start);
            let amount = copy_end - begin;
            self.read_candidate_raw_at_inner(
                candidate,
                raw_offset,
                &mut output[copied..copied + amount],
            )?;
            copied += amount;
        }
        if copied != output.len() {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        Ok(())
    }

    fn read_candidate_raw_at_inner(
        &mut self,
        candidate: &VNextRecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.read_segments_at(&candidate.segments, offset, output)
    }

    fn read_segments_at(
        &mut self,
        segments: &[VNextHeader],
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        let raw_len = segments
            .iter()
            .try_fold(0usize, |total, segment| {
                total.checked_add(segment.logical_len)
            })
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let end = offset
            .checked_add(output.len())
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        if end > raw_len {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        if output.is_empty() {
            return Ok(());
        }
        let mut destination = 0usize;
        let mut raw_cursor = 0usize;
        for segment in segments {
            let segment_end = raw_cursor
                .checked_add(segment.logical_len)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            let begin = offset.max(raw_cursor);
            let copy_end = end.min(segment_end);
            if begin < copy_end {
                let mut segment_offset = begin - raw_cursor;
                let segment_end_offset = copy_end - raw_cursor;
                while segment_offset < segment_end_offset {
                    let sector_index = segment_offset / SECTOR_BYTES;
                    let sector_offset = segment_offset % SECTOR_BYTES;
                    let mut sector = [0u8; SECTOR_BYTES];
                    self.read_sector(
                        vnext_data_lba(segment.segment)
                            + u32::try_from(sector_index)
                                .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                        &mut sector,
                    )?;
                    let amount =
                        (segment_end_offset - segment_offset).min(SECTOR_BYTES - sector_offset);
                    output[destination..destination + amount]
                        .copy_from_slice(&sector[sector_offset..sector_offset + amount]);
                    destination += amount;
                    segment_offset = segment_offset
                        .checked_add(amount)
                        .ok_or(BankedJournalError::CorruptBankMetadata)?;
                }
            }
            raw_cursor = segment_end;
            if raw_cursor >= end {
                break;
            }
        }
        if destination != output.len() {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        Ok(())
    }

    fn append_exact(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let result = self.append_exact_inner(suffix);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn append_exact_inner(&mut self, suffix: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_logical_selection()?;
        let framed = encode_vnext_frame(suffix).ok_or(BankedJournalError::AllocationFailed {
            requested: suffix.len(),
        })?;
        let source = self.active_candidate().cloned();
        let raw_len = source
            .as_ref()
            .map(Self::candidate_raw_len)
            .transpose()?
            .unwrap_or(0);
        let resulting =
            raw_len
                .checked_add(framed.len())
                .ok_or(BankedJournalError::JournalFull {
                    current: raw_len,
                    additional: framed.len(),
                    capacity: VNEXT_CAPACITY,
                })?;
        if resulting > VNEXT_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: raw_len,
                additional: framed.len(),
                capacity: VNEXT_CAPACITY,
            });
        }

        if let Some(source) = source {
            let current = source
                .segments
                .last()
                .cloned()
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            let available = VNEXT_SEGMENT_CAPACITY
                .checked_sub(current.logical_len)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            if framed.len() <= available {
                let generation = current
                    .generation
                    .checked_add(1)
                    .ok_or(BankedJournalError::GenerationExhausted)?;
                let (header, _fresh_copy) = self.publish_append_in_place(
                    &current,
                    generation,
                    &framed,
                    source.endpoint_copy,
                )?;
                return self.install_in_place_append(&source, header, suffix.len());
            }
            // The whole frame is staged into an alternate chain. In
            // particular, do not commit the prefix which happens to fit in
            // the current segment: one final manifest names the complete
            // frame and its complete segment chain.
            return self.stage_append_frame(Some(&source), &framed, suffix.len());
        }

        if framed.len() <= VNEXT_SEGMENT_CAPACITY {
            self.replace_exact(&framed)
        } else {
            self.stage_append_frame(None, &framed, suffix.len())
        }
    }

    /// Stages a complete frame and, when present, the already committed
    /// framed prefix into alternate segments. Segment headers are validated
    /// as they are sealed, but no manifest is written until the writer has
    /// consumed and validated every byte. This is the atomic path for a
    /// frame which crosses a segment boundary.
    fn stage_append_frame(
        &mut self,
        source: Option<&VNextRecoveryCandidate>,
        framed: &[u8],
        logical_len: usize,
    ) -> Result<(), BankedJournalError<B::Error>> {
        if framed.len() < VNEXT_FRAME_HEADER
            || framed[..8] != VNEXT_FRAME_MAGIC
            || framed[12..16].iter().any(|byte| *byte != 0)
        {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let payload_len = usize::try_from(read_u32(framed, 8))
            .map_err(|_| BankedJournalError::CorruptBankMetadata)?;
        let used = VNEXT_FRAME_HEADER
            .checked_add(payload_len)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        if used > framed.len() {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let raw_len = source
            .map(Self::candidate_raw_len)
            .transpose()?
            .unwrap_or(0);
        let total_len =
            raw_len
                .checked_add(framed.len())
                .ok_or(BankedJournalError::JournalFull {
                    current: raw_len,
                    additional: framed.len(),
                    capacity: VNEXT_CAPACITY,
                })?;
        if total_len > VNEXT_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: raw_len,
                additional: framed.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let needed = total_len.div_ceil(VNEXT_SEGMENT_CAPACITY).max(1);
        if needed > VNEXT_LIVE_SEGMENT_LIMIT {
            return Err(BankedJournalError::JournalFull {
                current: raw_len,
                additional: framed.len(),
                capacity: VNEXT_CAPACITY,
            });
        }

        let mut occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        if let Some(source) = source {
            for segment in &source.segments {
                if segment.segment >= VNEXT_SEGMENT_COUNT {
                    return Err(BankedJournalError::CorruptBankMetadata);
                }
                occupied[segment.segment as usize] = true;
            }
        }
        let mut free = [0u32; VNEXT_SEGMENT_COUNT as usize];
        let mut free_len = 0usize;
        for segment in 0..VNEXT_SEGMENT_COUNT {
            if !occupied[segment as usize] {
                free[free_len] = segment;
                free_len += 1;
            }
        }
        if free_len < needed {
            return Err(BankedJournalError::JournalFull {
                current: raw_len,
                additional: framed.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let base_generation = source.map_or(0, |candidate| candidate.endpoint.generation);
        let first_generation = base_generation
            .checked_add(1)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        first_generation
            .checked_add((needed - 1) as u64)
            .ok_or(BankedJournalError::GenerationExhausted)?;

        // All post-pivot metadata allocations happen before the first sector
        // write. The vectors contain only bounded headers and frame spans.
        let mut staged_segments = Vec::new();
        staged_segments
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let mut staged_segments_mirror = Vec::new();
        staged_segments_mirror
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let old_frame_count = source.map_or(0, |candidate| candidate.frames.len());
        let mut staged_frames = Vec::new();
        staged_frames
            .try_reserve_exact(old_frame_count.saturating_add(1))
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: old_frame_count.saturating_add(1),
            })?;
        let mut staged_frames_mirror = Vec::new();
        staged_frames_mirror
            .try_reserve_exact(old_frame_count.saturating_add(1))
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: old_frame_count.saturating_add(1),
            })?;
        let mut staged_candidates = Vec::new();
        staged_candidates
            .try_reserve_exact(VNEXT_HEADER_COPIES as usize)
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: VNEXT_HEADER_COPIES as usize,
            })?;

        let (headers, header_count, endpoint) = {
            let mut writer = VNextCheckpointWriter::new(
                self,
                free,
                free_len,
                needed,
                total_len,
                first_generation,
            )?;
            if let Some(source) = source {
                writer.write_candidate_raw(source)?;
            }
            writer.write_raw(&framed[..VNEXT_FRAME_HEADER])?;
            writer.write_all(&framed[VNEXT_FRAME_HEADER..used])?;
            writer.finish_frame_payload(
                <[u8; 32]>::try_from(&framed[16..48])
                    .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                logical_len,
            )?;
            writer.write_raw(&framed[used..])?;
            writer.finish()?
        };

        for header in headers.iter().take(header_count).flatten() {
            staged_segments.push(header.clone());
            staged_segments_mirror.push(header.clone());
        }
        if let Some(source) = source {
            staged_frames.extend(source.frames.iter().copied());
        }
        let logical_start = source.map_or(0, |candidate| candidate.logical_len);
        let frame = VNextFrameSpan {
            raw_start: raw_len
                .checked_add(VNEXT_FRAME_HEADER)
                .ok_or(BankedJournalError::CorruptBankMetadata)?,
            logical_start,
            logical_len,
        };
        staged_frames.push(frame);
        staged_frames_mirror.extend(staged_frames.iter().copied());

        // This is the sole authority pivot for the entire append. A crash
        // before it leaves the old manifest-selected chain; a crash after it
        // leaves the complete newly validated chain.
        self.publish_manifest(&endpoint)?;

        let candidate = VNextRecoveryCandidate {
            manifest_copy: 0,
            endpoint_copy: 0,
            endpoint: endpoint.clone(),
            segments: staged_segments,
            frames: staged_frames,
            logical_len: logical_start
                .checked_add(logical_len)
                .ok_or(BankedJournalError::CorruptBankMetadata)?,
        };
        let mirror_candidate = VNextRecoveryCandidate {
            manifest_copy: 1,
            endpoint_copy: 0,
            endpoint,
            segments: staged_segments_mirror,
            frames: staged_frames_mirror,
            logical_len: candidate.logical_len,
        };
        staged_candidates.push(candidate);
        staged_candidates.push(mirror_candidate);
        let selected = staged_candidates[0].clone();
        self.recovery_candidates = staged_candidates;
        self.set_active_candidate(&selected, true);
        self.active_materialized = true;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn install_in_place_append(
        &mut self,
        source: &VNextRecoveryCandidate,
        header: VNextHeader,
        logical_frame_len: usize,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let raw_len = Self::candidate_raw_len(source)?;
        let logical_len = source
            .logical_len
            .checked_add(logical_frame_len)
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        let frame = VNextFrameSpan {
            raw_start: raw_len
                .checked_add(VNEXT_FRAME_HEADER)
                .ok_or(BankedJournalError::CorruptBankMetadata)?,
            logical_start: source.logical_len,
            logical_len: logical_frame_len,
        };
        let mut segments = source.segments.clone();
        let last = segments
            .last_mut()
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        *last = header.clone();
        let mut frames = source.frames.clone();
        frames
            .try_reserve_exact(1)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: 1 })?;
        frames.push(frame);
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(VNEXT_HEADER_COPIES as usize)
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: VNEXT_HEADER_COPIES as usize,
            })?;
        let candidate = VNextRecoveryCandidate {
            manifest_copy: 0,
            endpoint_copy: 0,
            endpoint: header.clone(),
            segments: segments.clone(),
            frames: frames.clone(),
            logical_len,
        };
        candidates.push(candidate);
        candidates.push(VNextRecoveryCandidate {
            manifest_copy: 1,
            endpoint_copy: 0,
            endpoint: header,
            segments,
            frames,
            logical_len,
        });
        let selected = candidates[0].clone();
        self.recovery_candidates = candidates;
        self.set_active_candidate(&selected, true);
        self.active_materialized = true;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    /// Publishes a replacement replay image in an alternate segment.
    ///
    /// This is the vNext checkpoint/compaction primitive.  Callers must supply
    /// an exact replayable replacement image; anchored recovery uses it for
    /// exact-prefix repair, while a future state-snapshot producer may use the
    /// same atomic alternate-chain publication path.
    fn checkpoint_exact(&mut self, image: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        self.require_logical_selection()?;
        let result = encode_vnext_frame(image)
            .ok_or(BankedJournalError::AllocationFailed {
                requested: image.len(),
            })
            .and_then(|framed| self.replace_exact(&framed));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Streams one canonical J10 checkpoint into an inactive segment chain.
    ///
    /// The plan's sealed digest and length are the preflight metadata. The
    /// single `write_to` pass writes the frame header, plan bytes, and
    /// sector-aligned zero padding directly through
    /// [`VNextCheckpointWriter`]. No checkpoint image or framed journal `Vec`
    /// exists at the durability boundary.
    fn stage_checkpoint(
        &mut self,
        plan: &CheckpointRecordPlan,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let result = self.stage_checkpoint_inner(plan);
        if result.is_err() {
            // A streaming stage error is ambiguous once any device operation
            // may have run.  Reopening re-enumerates manifest candidates and
            // prevents a caller from selecting stale in-memory metadata.
            self.poisoned = true;
        }
        result
    }

    fn stage_checkpoint_inner(
        &mut self,
        plan: &CheckpointRecordPlan,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;

        let logical_len = plan.record_len();
        let used =
            VNEXT_FRAME_HEADER
                .checked_add(logical_len)
                .ok_or(BankedJournalError::JournalFull {
                    current: 0,
                    additional: logical_len,
                    capacity: VNEXT_CAPACITY,
                })?;
        let framed_len = used
            .div_ceil(SECTOR_BYTES)
            .checked_mul(SECTOR_BYTES)
            .ok_or(BankedJournalError::JournalFull {
                current: 0,
                additional: used,
                capacity: VNEXT_CAPACITY,
            })?;
        if framed_len > VNEXT_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: framed_len,
                capacity: VNEXT_CAPACITY,
            });
        }
        let needed = framed_len.div_ceil(VNEXT_SEGMENT_CAPACITY).max(1);
        if needed > VNEXT_LIVE_SEGMENT_LIMIT
            || logical_len > u32::MAX as usize
            || framed_len > u32::MAX as usize
        {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: framed_len,
                capacity: VNEXT_CAPACITY,
            });
        }
        self.require_logical_selection()?;
        let preserved_candidate = self.active_candidate().cloned();

        // The outer vNext frame authenticates the complete J10 record,
        // including its trailing inner record digest. The Core derives this
        // domain during the plan's single preimage hash pass; the writer
        // recomputes it while consuming the stream and rejects any mismatch
        // before a manifest can name the chain.
        let frame_digest = plan.image_digest().bytes();

        let mut free = [0u32; VNEXT_SEGMENT_COUNT as usize];
        let mut free_len = 0usize;
        for segment in 0..VNEXT_SEGMENT_COUNT {
            if !self.active.occupied[segment as usize] {
                free[free_len] = segment;
                free_len += 1;
            }
        }
        if free_len < needed {
            return Err(BankedJournalError::JournalFull {
                current: self.active_raw_len(),
                additional: framed_len,
                capacity: VNEXT_CAPACITY,
            });
        }
        let base_generation = self
            .active
            .header
            .as_ref()
            .map_or(0, |header| header.generation);
        let first_generation = base_generation
            .checked_add(1)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        first_generation
            .checked_add((needed - 1) as u64)
            .ok_or(BankedJournalError::GenerationExhausted)?;

        // Reserve the small post-publication metadata before any inactive
        // sector is written.  Once the manifest is durable, these vectors are
        // filled within their proven capacities and installed by assignment.
        let mut staged_segments = Vec::new();
        staged_segments
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let mut staged_frames = Vec::new();
        staged_frames
            .try_reserve_exact(1)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: 1 })?;
        let mut staged_candidates = Vec::new();
        staged_candidates
            .try_reserve_exact(VNEXT_HEADER_COPIES as usize)
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: VNEXT_HEADER_COPIES as usize,
            })?;

        let (headers, header_count, endpoint) = {
            let mut writer = VNextCheckpointWriter::new(
                self,
                free,
                free_len,
                needed,
                framed_len,
                first_generation,
            )?;
            let mut frame_header = [0u8; VNEXT_FRAME_HEADER];
            frame_header[..8].copy_from_slice(&VNEXT_FRAME_MAGIC);
            frame_header[8..12].copy_from_slice(&(logical_len as u32).to_le_bytes());
            frame_header[16..48].copy_from_slice(&frame_digest);
            writer.write_raw(&frame_header)?;

            let streamed = plan.write_to(&mut writer)?;
            if streamed != logical_len {
                return Err(BankedJournalError::ReadbackMismatch);
            }
            writer.finish_frame_payload(frame_digest, logical_len)?;

            let mut padding = framed_len - used;
            let zeroes = [0u8; SECTOR_BYTES];
            while padding != 0 {
                let amount = padding.min(zeroes.len());
                writer.write_raw(&zeroes[..amount])?;
                padding -= amount;
            }
            writer.finish()?
        };

        for header in headers.iter().take(header_count).flatten() {
            staged_segments.push(header.clone());
        }
        let frame = VNextFrameSpan {
            raw_start: VNEXT_FRAME_HEADER,
            logical_start: 0,
            logical_len,
        };
        staged_frames.push(frame);

        // Staging writes only the manifest copy opposite the currently
        // selected authority root. Until the trusted anchor advances, boot
        // can still recover the old chain; after it advances, the new copy is
        // already complete. No fallible post-anchor callback is required.
        let staged_manifest_copy = self.stage_manifest(&endpoint)?;

        let candidate = VNextRecoveryCandidate {
            manifest_copy: staged_manifest_copy,
            endpoint_copy: 0,
            endpoint: endpoint.clone(),
            segments: staged_segments,
            frames: staged_frames,
            logical_len,
        };
        staged_candidates.push(candidate);
        if let Some(preserved) = preserved_candidate {
            staged_candidates.push(preserved);
        }

        let mut occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        for header in headers.iter().take(header_count).flatten() {
            occupied[header.segment as usize] = true;
        }
        self.recovery_candidates = staged_candidates;
        self.active = VNextActiveImage {
            header: Some(endpoint),
            manifest_copy: Some(staged_manifest_copy),
            occupied,
        };
        self.active_materialized = false;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn repair_exact(&mut self, offset: usize) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let result = self.repair_exact_inner(offset);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn repair_exact_inner(&mut self, offset: usize) -> Result<(), BankedJournalError<B::Error>> {
        self.require_logical_selection()?;
        let Some(source) = self.active_candidate().cloned() else {
            if offset == 0 {
                return self.flush();
            }
            return Err(BankedJournalError::InvalidRepairOffset { offset, length: 0 });
        };
        self.repair_prefix_from_candidate(&source, offset)
    }

    fn repair_exact_from_candidate(
        &mut self,
        repair: JournalRepair,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), BankedJournalError<B::Error>> {
        self.require_reopen()?;
        let result = (|| {
            let Some(requested) = candidate else {
                return self.repair_exact_inner(repair.offset());
            };
            self.revalidate_candidate(requested)?;
            let source = self
                .recovery_candidates
                .iter()
                .find(|candidate| candidate.descriptor() == requested)
                .cloned()
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            self.repair_prefix_from_candidate(&source, repair.offset())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn repair_prefix_from_candidate(
        &mut self,
        source: &VNextRecoveryCandidate,
        offset: usize,
    ) -> Result<(), BankedJournalError<B::Error>> {
        if offset > source.logical_len {
            return Err(BankedJournalError::InvalidRepairOffset {
                offset,
                length: source.logical_len,
            });
        }
        if offset == source.logical_len {
            return self.flush();
        }

        // Hash and copy the prefix in separate bounded passes. The complete
        // repair prefix is never retained as an owned Vec.
        let mut digest = Sha256::new();
        let mut hashed = 0usize;
        let mut scratch = [0u8; SECTOR_BYTES];
        while hashed < offset {
            let amount = (offset - hashed).min(scratch.len());
            self.read_candidate_at_inner(source, hashed, &mut scratch[..amount])?;
            digest.update(&scratch[..amount]);
            if let Some(telemetry) = &mut self.telemetry {
                telemetry.hash_bytes = telemetry.hash_bytes.saturating_add(amount as u64);
            }
            hashed = hashed
                .checked_add(amount)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        let frame_digest: [u8; 32] = digest.finalize().into();
        self.stage_repair_frame(source, offset, frame_digest)
    }

    fn stage_repair_frame(
        &mut self,
        source: &VNextRecoveryCandidate,
        logical_len: usize,
        frame_digest: [u8; 32],
    ) -> Result<(), BankedJournalError<B::Error>> {
        let used =
            VNEXT_FRAME_HEADER
                .checked_add(logical_len)
                .ok_or(BankedJournalError::JournalFull {
                    current: 0,
                    additional: logical_len,
                    capacity: VNEXT_CAPACITY,
                })?;
        let framed_len = used
            .div_ceil(SECTOR_BYTES)
            .checked_mul(SECTOR_BYTES)
            .ok_or(BankedJournalError::JournalFull {
                current: 0,
                additional: used,
                capacity: VNEXT_CAPACITY,
            })?;
        let needed = framed_len.div_ceil(VNEXT_SEGMENT_CAPACITY).max(1);
        if framed_len > VNEXT_CAPACITY || needed > VNEXT_LIVE_SEGMENT_LIMIT {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: framed_len,
                capacity: VNEXT_CAPACITY,
            });
        }
        let mut occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        for segment in &source.segments {
            if segment.segment >= VNEXT_SEGMENT_COUNT {
                return Err(BankedJournalError::CorruptBankMetadata);
            }
            occupied[segment.segment as usize] = true;
        }
        let mut free = [0u32; VNEXT_SEGMENT_COUNT as usize];
        let mut free_len = 0usize;
        for segment in 0..VNEXT_SEGMENT_COUNT {
            if !occupied[segment as usize] {
                free[free_len] = segment;
                free_len += 1;
            }
        }
        if free_len < needed {
            return Err(BankedJournalError::JournalFull {
                current: Self::candidate_raw_len(source)?,
                additional: framed_len,
                capacity: VNEXT_CAPACITY,
            });
        }
        let first_generation = source
            .endpoint
            .generation
            .checked_add(1)
            .ok_or(BankedJournalError::GenerationExhausted)?;
        first_generation
            .checked_add((needed - 1) as u64)
            .ok_or(BankedJournalError::GenerationExhausted)?;

        let mut staged_segments = Vec::new();
        staged_segments
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let mut staged_segments_mirror = Vec::new();
        staged_segments_mirror
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let mut staged_candidates = Vec::new();
        staged_candidates
            .try_reserve_exact(VNEXT_HEADER_COPIES as usize)
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: VNEXT_HEADER_COPIES as usize,
            })?;
        let (headers, header_count, endpoint) = {
            let mut writer = VNextCheckpointWriter::new(
                self,
                free,
                free_len,
                needed,
                framed_len,
                first_generation,
            )?;
            let mut frame_header = [0u8; VNEXT_FRAME_HEADER];
            frame_header[..8].copy_from_slice(&VNEXT_FRAME_MAGIC);
            frame_header[8..12].copy_from_slice(&(logical_len as u32).to_le_bytes());
            frame_header[16..48].copy_from_slice(&frame_digest);
            writer.write_raw(&frame_header)?;
            writer.write_candidate_logical_prefix(source, logical_len)?;
            writer.finish_frame_payload(frame_digest, logical_len)?;
            let mut padding = framed_len - used;
            let zeroes = [0u8; SECTOR_BYTES];
            while padding != 0 {
                let amount = padding.min(zeroes.len());
                writer.write_raw(&zeroes[..amount])?;
                padding -= amount;
            }
            writer.finish()?
        };
        for header in headers.iter().take(header_count).flatten() {
            staged_segments.push(header.clone());
            staged_segments_mirror.push(header.clone());
        }
        let frame = VNextFrameSpan {
            raw_start: VNEXT_FRAME_HEADER,
            logical_start: 0,
            logical_len,
        };
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(1)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: 1 })?;
        frames.push(frame);
        let mirror_frames = frames.clone();
        self.publish_manifest(&endpoint)?;
        staged_candidates.push(VNextRecoveryCandidate {
            manifest_copy: 0,
            endpoint_copy: 0,
            endpoint: endpoint.clone(),
            segments: staged_segments,
            frames,
            logical_len,
        });
        staged_candidates.push(VNextRecoveryCandidate {
            manifest_copy: 1,
            endpoint_copy: 0,
            endpoint,
            segments: staged_segments_mirror,
            frames: mirror_frames,
            logical_len,
        });
        let selected = staged_candidates[0].clone();
        self.recovery_candidates = staged_candidates;
        self.set_active_candidate(&selected, true);
        self.active_materialized = true;
        self.mark_phase(JournalIoPhase::CacheUpdated);
        Ok(())
    }

    fn replace_exact(&mut self, image: &[u8]) -> Result<(), BankedJournalError<B::Error>> {
        self.require_logical_selection()?;
        if image.len() > VNEXT_CAPACITY {
            return Err(BankedJournalError::JournalFull {
                current: 0,
                additional: image.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let needed = image.len().div_ceil(VNEXT_SEGMENT_CAPACITY).max(1);
        let mut free = [0u32; VNEXT_SEGMENT_COUNT as usize];
        let mut free_len = 0usize;
        for segment in 0..VNEXT_SEGMENT_COUNT {
            if !self.active.occupied[segment as usize] {
                free[free_len] = segment;
                free_len += 1;
            }
        }
        if free_len < needed {
            return Err(BankedJournalError::JournalFull {
                current: self.active_raw_len(),
                additional: image.len(),
                capacity: VNEXT_CAPACITY,
            });
        }
        let frames =
            decode_vnext_frame_spans(image).ok_or(BankedJournalError::CorruptBankMetadata)?;
        let logical_len = frames
            .last()
            .map(|frame| {
                frame
                    .logical_start
                    .checked_add(frame.logical_len)
                    .ok_or(BankedJournalError::CorruptBankMetadata)
            })
            .transpose()?
            .unwrap_or(0);

        // Prepare bounded metadata before the first sector write. The image
        // itself is an explicit checkpoint input; it is never retained by
        // `VNextActiveImage` or by candidate discovery.
        let mut staged_segments = Vec::new();
        staged_segments
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let mut staged_segments_mirror = Vec::new();
        staged_segments_mirror
            .try_reserve_exact(needed)
            .map_err(|_| BankedJournalError::AllocationFailed { requested: needed })?;
        let staged_frames = frames;
        let staged_frames_mirror = staged_frames.clone();
        let mut staged_candidates = Vec::new();
        staged_candidates
            .try_reserve_exact(VNEXT_HEADER_COPIES as usize)
            .map_err(|_| BankedJournalError::AllocationFailed {
                requested: VNEXT_HEADER_COPIES as usize,
            })?;
        let mut next_occupied = [false; VNEXT_SEGMENT_COUNT as usize];
        for &segment in free.iter().take(needed) {
            next_occupied[segment as usize] = true;
        }
        let mut generation = self
            .active
            .header
            .as_ref()
            .map_or(0, |header| header.generation);
        let mut previous_head = [0; 32];
        let mut endpoint = None;
        for (index, &segment) in free.iter().take(needed).enumerate() {
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
            staged_segments.push(header.clone());
            staged_segments_mirror.push(header.clone());
            previous_head = header.head;
            endpoint = Some(header);
        }
        let endpoint = endpoint.ok_or(BankedJournalError::CorruptBankMetadata)?;
        self.publish_manifest(&endpoint)?;
        staged_candidates.push(VNextRecoveryCandidate {
            manifest_copy: 0,
            endpoint_copy: 0,
            endpoint: endpoint.clone(),
            segments: staged_segments,
            frames: staged_frames,
            logical_len,
        });
        staged_candidates.push(VNextRecoveryCandidate {
            manifest_copy: 1,
            endpoint_copy: 0,
            endpoint,
            segments: staged_segments_mirror,
            frames: staged_frames_mirror,
            logical_len,
        });
        let selected = staged_candidates[0].clone();
        self.recovery_candidates = staged_candidates;
        self.set_active_candidate(&selected, true);
        self.active.occupied = next_occupied;
        self.active_materialized = true;
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
        let result = (|| {
            self.write_segment_tail(segment, payload, previous_len)?;
            self.mark_phase(JournalIoPhase::PayloadWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::PayloadFlushed);

            // Each copy is independently a complete committed superblock. A
            // crash after the first flush may expose the new prefix; a
            // corrupted first copy still leaves the previous one usable.
            self.write_sector(vnext_header_lba(segment, 0), &encoded)?;
            self.mark_phase(JournalIoPhase::HeaderWritten);
            self.flush()?;
            self.write_sector(vnext_header_lba(segment, 1), &encoded)?;
            self.flush()?;
            self.mark_phase(JournalIoPhase::HeaderFlushed);

            match self.inspect_segment(segment)? {
                VNextSegmentInspection::Valid(actual) if actual == header => {
                    self.mark_phase(JournalIoPhase::ReadbackValidated);
                    Ok(header.clone())
                }
                VNextSegmentInspection::Blank
                | VNextSegmentInspection::Invalid
                | VNextSegmentInspection::Valid(_) => Err(BankedJournalError::ReadbackMismatch),
            }
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Publishes a segment produced by the streaming checkpoint writer.
    ///
    /// The payload is already present in inactive sectors when this method is
    /// called. It is flushed before either header copy can name it. Copy 0
    /// gets a complete header-plus-payload readback; copy 1 then gets an exact
    /// header readback. The second payload pass is unnecessary here because
    /// this fresh segment is still exclusively owned by this journal writer,
    /// no manifest can select it yet, and no other operation may mutate the
    /// backend between the two reads. Ordinary discovery cannot make that
    /// immutability/single-owner proof, so it intentionally keeps the generic
    /// double-read validator below.
    fn publish_stream_segment_header(
        &mut self,
        header: &VNextHeader,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let encoded = header.encode();
        let result = (|| {
            self.mark_phase(JournalIoPhase::PayloadWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::PayloadFlushed);

            self.write_sector(vnext_header_lba(header.segment, 0), &encoded)?;
            self.mark_phase(JournalIoPhase::HeaderWritten);
            self.flush()?;
            self.validate_stream_header_copy(header, 0, true)?;

            self.write_sector(vnext_header_lba(header.segment, 1), &encoded)?;
            self.flush()?;
            self.validate_stream_header_copy(header, 1, false)?;
            self.mark_phase(JournalIoPhase::HeaderFlushed);
            self.mark_phase(JournalIoPhase::ReadbackValidated);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn validate_stream_header_copy(
        &mut self,
        expected: &VNextHeader,
        copy: u32,
        validate_payload: bool,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let mut bytes = [0u8; SECTOR_BYTES];
        self.read_sector(vnext_header_lba(expected.segment, copy), &mut bytes)?;
        let VNextHeaderInspection::Valid(header) = VNextHeader::decode(expected.segment, &bytes)
        else {
            return Err(BankedJournalError::ReadbackMismatch);
        };
        if header != *expected {
            return Err(BankedJournalError::ReadbackMismatch);
        }
        if validate_payload && !self.validate_published_segment_metadata_once(expected)? {
            return Err(BankedJournalError::ReadbackMismatch);
        }
        Ok(())
    }

    /// Publish one same-segment append without rebuilding the existing
    /// segment.  The data tail is durable before a fresh header copy can name
    /// it.  The old header copy remains usable until the manifest selects the
    /// new endpoint; only then do we mirror the new header into the old slot.
    fn publish_append_in_place(
        &mut self,
        current: &VNextHeader,
        generation: u64,
        payload: &[u8],
        endpoint_copy: u32,
    ) -> Result<(VNextHeader, u32), BankedJournalError<B::Error>> {
        let logical_len = current.logical_len.checked_add(payload.len()).ok_or(
            BankedJournalError::JournalFull {
                current: current.logical_len,
                additional: payload.len(),
                capacity: VNEXT_SEGMENT_CAPACITY,
            },
        )?;
        if logical_len > VNEXT_SEGMENT_CAPACITY || endpoint_copy >= VNEXT_HEADER_COPIES {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let (payload_digest, head) = self.hash_segment_with_suffix(current, payload)?;
        let header = VNextHeader {
            segment: current.segment,
            generation,
            first_generation: current.first_generation,
            logical_len,
            previous_head: current.previous_head,
            payload_digest,
            head,
        };
        let encoded = header.encode();
        // Write the new header to the copy which was not observed to carry
        // the manifest-selected old endpoint. This leaves the preceding
        // header intact while the manifest still names the old payload.
        let fresh_copy = 1 - endpoint_copy;
        let mirror_copy = endpoint_copy;
        let result = (|| {
            self.write_segment_append(current.segment, current.logical_len, payload)?;
            self.mark_phase(JournalIoPhase::PayloadWritten);
            self.flush()?;
            self.mark_phase(JournalIoPhase::PayloadFlushed);

            self.write_sector(vnext_header_lba(current.segment, fresh_copy), &encoded)?;
            self.mark_phase(JournalIoPhase::HeaderWritten);
            self.flush()?;
            // Before the manifest can pivot authority, prove the staged copy
            // names the exact new payload. The untouched mirror still names
            // the old endpoint if this validation fails or power cuts here.
            self.validate_exact_header_copy(current.segment, fresh_copy, &header)?;

            // Header and manifest together bind the new exact prefix.  If
            // only M0 is durable after a cut, its larger generation wins over
            // the old M1 and recovery accepts this fully staged endpoint.
            self.publish_manifest(&header)?;

            // Once authority has moved, restore two equivalent headers. A
            // failure here leaves a recoverable one-header endpoint and
            // poisons the in-memory cache so callers must reopen.
            self.write_sector(vnext_header_lba(current.segment, mirror_copy), &encoded)?;
            self.flush()?;
            self.mark_phase(JournalIoPhase::HeaderFlushed);
            self.validate_exact_header_copy(current.segment, mirror_copy, &header)?;
            self.mark_phase(JournalIoPhase::ReadbackValidated);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result.map(|()| (header, fresh_copy))
    }

    fn validate_exact_header_copy(
        &mut self,
        segment: u32,
        copy: u32,
        expected: &VNextHeader,
    ) -> Result<(), BankedJournalError<B::Error>> {
        let mut bytes = [0u8; SECTOR_BYTES];
        self.read_sector(vnext_header_lba(segment, copy), &mut bytes)?;
        let VNextHeaderInspection::Valid(header) = VNextHeader::decode(segment, &bytes) else {
            return Err(BankedJournalError::ReadbackMismatch);
        };
        if &header != expected {
            return Err(BankedJournalError::ReadbackMismatch);
        }
        if self.validate_published_segment_metadata_once(&header)? {
            Ok(())
        } else {
            Err(BankedJournalError::ReadbackMismatch)
        }
    }

    fn hash_segment_with_suffix(
        &mut self,
        current: &VNextHeader,
        suffix: &[u8],
    ) -> VNextSegmentDigests<B::Error> {
        let mut payload_digest = Sha256::new();
        let mut head_digest = Sha256::new();
        head_digest.update(current.previous_head);
        let mut remaining = current.logical_len;
        let mut sector_index = 0u32;
        while remaining != 0 {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_data_lba(current.segment) + sector_index, &mut sector)?;
            let used = remaining.min(SECTOR_BYTES);
            payload_digest.update(&sector[..used]);
            head_digest.update(&sector[..used]);
            remaining -= used;
            sector_index = sector_index
                .checked_add(1)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        payload_digest.update(suffix);
        head_digest.update(suffix);
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.hash_bytes = telemetry
                .hash_bytes
                .saturating_add((current.logical_len + suffix.len()) as u64);
        }
        Ok((
            payload_digest.finalize().into(),
            head_digest.finalize().into(),
        ))
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

    fn write_segment_append(
        &mut self,
        segment: u32,
        previous_len: usize,
        suffix: &[u8],
    ) -> Result<(), BankedJournalError<B::Error>> {
        if previous_len > VNEXT_SEGMENT_CAPACITY
            || previous_len + suffix.len() > VNEXT_SEGMENT_CAPACITY
        {
            return Err(BankedJournalError::JournalFull {
                current: previous_len,
                additional: suffix.len(),
                capacity: VNEXT_SEGMENT_CAPACITY,
            });
        }
        let mut source_offset = 0usize;
        let mut destination_offset = previous_len;
        while source_offset < suffix.len() {
            let sector_index = destination_offset / SECTOR_BYTES;
            let sector_offset = destination_offset % SECTOR_BYTES;
            let amount = (suffix.len() - source_offset).min(SECTOR_BYTES - sector_offset);
            let mut sector = [0u8; SECTOR_BYTES];
            if sector_offset != 0 || amount != SECTOR_BYTES {
                self.read_sector(
                    vnext_data_lba(segment)
                        + u32::try_from(sector_index)
                            .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                    &mut sector,
                )?;
            }
            sector[sector_offset..sector_offset + amount]
                .copy_from_slice(&suffix[source_offset..source_offset + amount]);
            self.write_sector(
                vnext_data_lba(segment)
                    + u32::try_from(sector_index)
                        .map_err(|_| BankedJournalError::CorruptBankMetadata)?,
                &sector,
            )?;
            source_offset += amount;
            destination_offset += amount;
        }
        Ok(())
    }

    fn discover_candidates(
        &mut self,
    ) -> Result<Vec<VNextRecoveryCandidate>, BankedJournalError<B::Error>> {
        let mut manifests = Vec::new();
        let mut invalid_manifest = false;
        for copy in 0..VNEXT_HEADER_COPIES {
            let mut bytes = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_manifest_lba(copy), &mut bytes)?;
            match VNextManifest::decode(&bytes) {
                VNextManifestInspection::Blank => {}
                VNextManifestInspection::Invalid => invalid_manifest = true,
                VNextManifestInspection::Valid(manifest) => manifests.push((copy, manifest)),
            }
        }
        if manifests.is_empty() {
            return if invalid_manifest {
                Err(BankedJournalError::CorruptBankMetadata)
            } else {
                Ok(Vec::new())
            };
        }

        let all_headers = self.discover_segment_headers()?;
        let mut candidates = Vec::new();
        for (manifest_copy, manifest) in manifests {
            if let Some(candidate) =
                self.build_recovery_candidate(manifest_copy, manifest.endpoint, &all_headers)?
            {
                candidates.push(candidate);
            }
        }
        if candidates.is_empty() {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        Ok(candidates)
    }

    /// Returns every header copy whose exact payload and physical hash-chain
    /// fields validate. No generation sort is performed here; a manifest
    /// candidate later names the endpoint explicitly.
    fn discover_segment_headers(
        &mut self,
    ) -> Result<Vec<(VNextHeader, u32)>, BankedJournalError<B::Error>> {
        let mut headers = Vec::new();
        for segment in 0..VNEXT_SEGMENT_COUNT {
            for copy in 0..VNEXT_HEADER_COPIES {
                let mut bytes = [0u8; SECTOR_BYTES];
                self.read_sector(vnext_header_lba(segment, copy), &mut bytes)?;
                let VNextHeaderInspection::Valid(header) = VNextHeader::decode(segment, &bytes)
                else {
                    continue;
                };
                if headers
                    .iter()
                    .any(|(existing, _): &(VNextHeader, u32)| *existing == header)
                {
                    continue;
                }
                if self.validate_segment_payload_metadata(&header)? {
                    headers.push((header, copy));
                }
            }
        }
        Ok(headers)
    }

    fn build_recovery_candidate(
        &mut self,
        manifest_copy: u32,
        endpoint: VNextHeader,
        all_headers: &[(VNextHeader, u32)],
    ) -> Result<Option<VNextRecoveryCandidate>, BankedJournalError<B::Error>> {
        let Some((endpoint_header, endpoint_copy)) = all_headers
            .iter()
            .find(|(header, _)| *header == endpoint)
            .cloned()
        else {
            return Ok(None);
        };
        let mut reverse = vec![endpoint_header];
        let mut next_head = reverse[0].previous_head;
        let mut next_generation = reverse[0].generation;
        while next_head != [0; 32] {
            let Some(previous) = all_headers.iter().find(|(header, _)| {
                header.head == next_head && header.generation < next_generation
            }) else {
                return Ok(None);
            };
            if reverse
                .iter()
                .any(|header| header.segment == previous.0.segment)
            {
                return Ok(None);
            }
            reverse.push(previous.0.clone());
            next_head = previous.0.previous_head;
            next_generation = previous.0.generation;
            if reverse.len() > VNEXT_LIVE_SEGMENT_LIMIT {
                return Ok(None);
            }
        }
        reverse.reverse();

        let Some((frames, logical_len)) = self.scan_frame_spans(&reverse)? else {
            return Ok(None);
        };
        Ok(Some(VNextRecoveryCandidate {
            manifest_copy,
            endpoint_copy,
            endpoint,
            segments: reverse,
            frames,
            logical_len,
        }))
    }

    /// Decodes frame headers and payload digests directly from the segment
    /// chain. Only sector-sized scratch is retained; discovery never builds a
    /// candidate-sized framed image.
    fn scan_frame_spans(&mut self, segments: &[VNextHeader]) -> VNextFrameScan<B::Error> {
        let raw_len = segments
            .iter()
            .try_fold(0usize, |total, segment| {
                total.checked_add(segment.logical_len)
            })
            .ok_or(BankedJournalError::CorruptBankMetadata)?;
        if raw_len > VNEXT_CAPACITY {
            return Ok(None);
        }
        let mut cursor = 0usize;
        let mut logical_start = 0usize;
        let mut spans = Vec::new();
        let maximum_frames = raw_len / SECTOR_BYTES;
        spans.try_reserve_exact(maximum_frames).map_err(|_| {
            BankedJournalError::AllocationFailed {
                requested: maximum_frames,
            }
        })?;
        while cursor < raw_len {
            let remaining = raw_len
                .checked_sub(cursor)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            if remaining < VNEXT_FRAME_HEADER {
                return Ok(None);
            }
            let mut frame_header = [0u8; VNEXT_FRAME_HEADER];
            self.read_segments_at(segments, cursor, &mut frame_header)?;
            if frame_header[..8] != VNEXT_FRAME_MAGIC
                || frame_header[12..16].iter().any(|byte| *byte != 0)
            {
                return Ok(None);
            }
            let frame_len = usize::try_from(read_u32(&frame_header, 8))
                .map_err(|_| BankedJournalError::CorruptBankMetadata)?;
            let used = VNEXT_FRAME_HEADER
                .checked_add(frame_len)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            let padded = used
                .div_ceil(SECTOR_BYTES)
                .checked_mul(SECTOR_BYTES)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            let end = cursor
                .checked_add(padded)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            if end > raw_len {
                return Ok(None);
            }
            let expected_digest: [u8; 32] = frame_header[16..48]
                .try_into()
                .map_err(|_| BankedJournalError::CorruptBankMetadata)?;
            let payload_start = cursor
                .checked_add(VNEXT_FRAME_HEADER)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            let mut digest = Sha256::new();
            let mut payload_offset = 0usize;
            let mut scratch = [0u8; SECTOR_BYTES];
            while payload_offset < frame_len {
                let amount = (frame_len - payload_offset).min(scratch.len());
                self.read_segments_at(
                    segments,
                    payload_start
                        .checked_add(payload_offset)
                        .ok_or(BankedJournalError::CorruptBankMetadata)?,
                    &mut scratch[..amount],
                )?;
                digest.update(&scratch[..amount]);
                payload_offset += amount;
            }
            if <[u8; 32]>::from(digest.finalize()) != expected_digest {
                return Ok(None);
            }
            let padding = padded - used;
            let mut padding_offset = 0usize;
            while padding_offset < padding {
                let amount = (padding - padding_offset).min(scratch.len());
                self.read_segments_at(
                    segments,
                    cursor
                        .checked_add(used)
                        .and_then(|value| value.checked_add(padding_offset))
                        .ok_or(BankedJournalError::CorruptBankMetadata)?,
                    &mut scratch[..amount],
                )?;
                if scratch[..amount].iter().any(|byte| *byte != 0) {
                    return Ok(None);
                }
                padding_offset += amount;
            }
            spans.push(VNextFrameSpan {
                raw_start: payload_start,
                logical_start,
                logical_len: frame_len,
            });
            logical_start = logical_start
                .checked_add(frame_len)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
            cursor = end;
        }
        Ok(Some((spans, logical_start)))
    }

    fn validate_segment_payload_metadata(
        &mut self,
        header: &VNextHeader,
    ) -> Result<bool, BankedJournalError<B::Error>> {
        // Reopened media is not proven immutable or single-owner. Keep the
        // payload and chain-head passes separate so a device/controller race
        // cannot combine bytes from two observations into one accepted hash.
        let mut digest = Sha256::new();
        let mut remaining = header.logical_len;
        let mut index = 0u32;
        while remaining != 0 {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_data_lba(header.segment) + index, &mut sector)?;
            let used = remaining.min(SECTOR_BYTES);
            digest.update(&sector[..used]);
            remaining -= used;
            index = index
                .checked_add(1)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        if <[u8; 32]>::from(digest.finalize()) != header.payload_digest {
            return Ok(false);
        }
        let mut head = Sha256::new();
        head.update(header.previous_head);
        // The payload must be read a second time to bind the physical chain
        // head. This remains bounded sector scratch, never a retained image.
        let mut remaining = header.logical_len;
        let mut index = 0u32;
        while remaining != 0 {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_data_lba(header.segment) + index, &mut sector)?;
            let used = remaining.min(SECTOR_BYTES);
            head.update(&sector[..used]);
            remaining -= used;
            index = index
                .checked_add(1)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        Ok(<[u8; 32]>::from(head.finalize()) == header.head)
    }

    /// Validates a freshly staged segment with one bounded payload read.
    ///
    /// This helper is deliberately narrower than
    /// [`Self::validate_segment_payload_metadata`]. The writer owns the
    /// backend exclusively, the segment is inactive and not yet manifest
    /// authoritative, and no concurrent mutation can occur between the
    /// payload write and this readback. Under those conditions one sector
    /// observation can feed both canonical hashers. It must not be reused by
    /// arbitrary recovery scans.
    fn validate_published_segment_metadata_once(
        &mut self,
        header: &VNextHeader,
    ) -> Result<bool, BankedJournalError<B::Error>> {
        if header.logical_len > VNEXT_SEGMENT_CAPACITY {
            return Ok(false);
        }
        let mut payload = Sha256::new();
        let mut head = Sha256::new();
        head.update(header.previous_head);
        let mut remaining = header.logical_len;
        let mut index = 0u32;
        while remaining != 0 {
            let mut sector = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_data_lba(header.segment) + index, &mut sector)?;
            let used = remaining.min(SECTOR_BYTES);
            payload.update(&sector[..used]);
            head.update(&sector[..used]);
            remaining -= used;
            index = index
                .checked_add(1)
                .ok_or(BankedJournalError::CorruptBankMetadata)?;
        }
        let payload_digest: [u8; 32] = payload.finalize().into();
        let head_digest: [u8; 32] = head.finalize().into();
        Ok(payload_digest == header.payload_digest && head_digest == header.head)
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
                } else {
                    Err(BankedJournalError::ConflictingGeneration {
                        generation: left.endpoint.generation.max(right.endpoint.generation),
                    })
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
        let preserved = self.active.manifest_copy.unwrap_or(1);
        if preserved >= VNEXT_HEADER_COPIES {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let pivot_copy = 1 - preserved;
        let result = (|| {
            // Keep the manifest selected by trusted recovery intact until a
            // complete new root is durable. This remains safe even when the
            // other valid manifest names a divergent chain whose segments
            // were reused while staging the new image.
            self.write_sector(vnext_manifest_lba(pivot_copy), &bytes)?;
            self.flush()?;
            let mut readback = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_manifest_lba(pivot_copy), &mut readback)?;
            if !matches!(
                VNextManifest::decode(&readback),
                VNextManifestInspection::Valid(observed) if observed == manifest
            ) {
                return Err(BankedJournalError::ReadbackMismatch);
            }
            self.write_sector(vnext_manifest_lba(preserved), &bytes)?;
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

    /// Publishes one durable replacement root while retaining the manifest
    /// selected by the current trusted anchor. Recovery can therefore choose
    /// the old or staged checkpoint solely from the anchor coordinate.
    fn stage_manifest(
        &mut self,
        endpoint: &VNextHeader,
    ) -> Result<u32, BankedJournalError<B::Error>> {
        let preserved = self.active.manifest_copy.unwrap_or(1);
        if preserved >= VNEXT_HEADER_COPIES {
            return Err(BankedJournalError::CorruptBankMetadata);
        }
        let staged_copy = 1 - preserved;
        let manifest = VNextManifest {
            endpoint: endpoint.clone(),
        };
        let bytes = manifest.encode();
        let result = (|| {
            self.write_sector(vnext_manifest_lba(staged_copy), &bytes)?;
            self.flush()?;
            let mut readback = [0u8; SECTOR_BYTES];
            self.read_sector(vnext_manifest_lba(staged_copy), &mut readback)?;
            if !matches!(
                VNextManifest::decode(&readback),
                VNextManifestInspection::Valid(observed) if observed == manifest
            ) {
                return Err(BankedJournalError::ReadbackMismatch);
            }
            Ok(staged_copy)
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

    fn require_logical_selection(&self) -> Result<(), BankedJournalError<B::Error>> {
        if self.active.header.is_none() && !self.recovery_candidates.is_empty() {
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
        let mut valid = Vec::new();
        for header in candidates {
            if self.validate_segment_payload(header.clone())? {
                valid.push(header);
            }
        }
        if valid.len() == 1 {
            return Ok(VNextSegmentInspection::Valid(
                valid.pop().expect("one validated segment"),
            ));
        }
        if valid.len() == 2 {
            if valid[0] == valid[1] {
                return Ok(VNextSegmentInspection::Valid(valid.remove(0)));
            }
            // Both header copies are independently valid but disagree. A
            // manifest must select one exact endpoint; no local generation
            // ordering may manufacture authority here.
            return Ok(VNextSegmentInspection::Invalid);
        }
        Ok(VNextSegmentInspection::Invalid)
    }

    fn validate_segment_payload(
        &mut self,
        header: VNextHeader,
    ) -> Result<bool, BankedJournalError<B::Error>> {
        self.validate_segment_payload_metadata(&header)
    }

    #[cfg(ktest)]
    fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    #[cfg(ktest)]
    fn into_backend(self) -> B {
        self.backend
    }

    fn set_telemetry(&mut self, enabled: bool) {
        self.telemetry = enabled.then(JournalIoTelemetry::default);
    }

    fn telemetry(&self) -> Option<JournalIoTelemetry> {
        self.telemetry
    }

    fn active_raw_len(&self) -> usize {
        self.active
            .header
            .as_ref()
            .and_then(|header| {
                self.recovery_candidates
                    .iter()
                    .find(|candidate| candidate.endpoint == *header)
                    .map(|candidate| {
                        candidate
                            .segments
                            .iter()
                            .try_fold(0usize, |total, segment| {
                                total.checked_add(segment.logical_len)
                            })
                            .unwrap_or(0)
                    })
            })
            .unwrap_or(0)
    }

    #[cfg(ktest)]
    fn enable_telemetry(&mut self) {
        self.set_telemetry(true);
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
        if let Err(error) = self.backend.write_sector(lba, input) {
            self.poisoned = true;
            return Err(BankedJournalError::Storage(error));
        }
        if let Some(telemetry) = &mut self.telemetry {
            telemetry.sectors_written = telemetry.sectors_written.saturating_add(1);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BankedJournalError<B::Error>> {
        if let Err(error) = self.backend.flush() {
            self.poisoned = true;
            return Err(BankedJournalError::Storage(error));
        }
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
            || bytes[cursor + 12..cursor + 16]
                .iter()
                .any(|byte| *byte != 0)
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

fn decode_vnext_frame_spans(bytes: &[u8]) -> Option<Vec<VNextFrameSpan>> {
    let mut cursor = 0usize;
    let mut logical_start = 0usize;
    let mut spans = Vec::new();
    while cursor < bytes.len() {
        if bytes.len().checked_sub(cursor)? < VNEXT_FRAME_HEADER
            || bytes[cursor..cursor + 8] != VNEXT_FRAME_MAGIC
            || bytes[cursor + 12..cursor + 16]
                .iter()
                .any(|byte| *byte != 0)
        {
            return None;
        }
        let logical_len = usize::try_from(read_u32(bytes, cursor + 8)).ok()?;
        let used = VNEXT_FRAME_HEADER.checked_add(logical_len)?;
        let padded = used.div_ceil(SECTOR_BYTES).checked_mul(SECTOR_BYTES)?;
        let end = cursor.checked_add(padded)?;
        if end > bytes.len() {
            return None;
        }
        let payload = &bytes[cursor + VNEXT_FRAME_HEADER..cursor + used];
        let digest: [u8; 32] = Sha256::digest(payload).into();
        if bytes[cursor + 16..cursor + 48] != digest
            || bytes[cursor + used..end].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        spans.push(VNextFrameSpan {
            raw_start: cursor + VNEXT_FRAME_HEADER,
            logical_start,
            logical_len,
        });
        logical_start = logical_start.checked_add(logical_len)?;
        cursor = end;
    }
    Some(spans)
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
            journal: BankedJournal::open_strict(disk)?,
        })
    }

    /// Enables or disables default-off ATA I/O diagnostics.
    ///
    /// This only resets in-memory counters; it never changes journal bytes or
    /// recovery semantics.
    pub(crate) fn set_telemetry(&mut self, enabled: bool) {
        self.journal.set_telemetry(enabled);
    }

    /// Returns the enabled journal counters and current replay-image usage.
    pub(crate) fn telemetry(&self) -> Option<JournalIoSnapshot> {
        self.journal.telemetry().map(|counters| JournalIoSnapshot {
            counters,
            image_bytes: self.journal.active_logical_len() as u64,
            capacity_bytes: JOURNAL_CAPACITY as u64,
        })
    }
}

impl DurableJournalBackend for AtaPioJournal {
    type Error = AtaPioJournalError;

    fn append_and_sync(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.journal.append_exact(record.bytes())
    }
}

impl StreamingJournalBackend for AtaPioJournal {
    type Error = AtaPioJournalError;

    fn stage_checkpoint(&mut self, plan: &CheckpointRecordPlan) -> Result<(), Self::Error> {
        self.journal.stage_checkpoint(plan)
    }
}

impl OstdBootJournal for AtaPioJournal {
    type RecoveryError = AtaPioJournalError;

    fn recovery_candidates(&mut self) -> Result<Vec<RecoveryCandidate>, Self::RecoveryError> {
        self.journal.recovery_candidates()
    }

    fn select_recovery_candidate(
        &mut self,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), Self::RecoveryError> {
        self.journal.select_candidate(candidate)
    }

    fn read_recovery_at(
        &mut self,
        candidate: RecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), Self::RecoveryError> {
        self.journal.read_candidate_at(candidate, offset, output)
    }

    fn revalidate_recovery_candidate(
        &mut self,
        candidate: RecoveryCandidate,
    ) -> Result<(), Self::RecoveryError> {
        self.journal.revalidate_candidate(candidate)
    }

    fn repair_and_sync(
        &mut self,
        repair: JournalRepair,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), Self::RecoveryError> {
        self.journal.repair_exact_from_candidate(repair, candidate)
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

    /// Enables or disables default-off ATA I/O diagnostics.
    ///
    /// This only resets in-memory counters; it never changes journal bytes or
    /// recovery semantics.
    pub(crate) fn set_telemetry(&mut self, enabled: bool) {
        self.journal.set_telemetry(enabled);
    }

    /// Returns the enabled journal counters and current replay-image usage.
    pub(crate) fn telemetry(&self) -> Option<JournalIoSnapshot> {
        self.journal.telemetry().map(|counters| JournalIoSnapshot {
            counters,
            image_bytes: self.journal.active_raw_len() as u64,
            capacity_bytes: VNEXT_CAPACITY as u64,
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

impl CompactingJournalBackend for AtaPioJournalVNext {
    fn checkpoint_capacity_bytes(&self) -> usize {
        VNEXT_CAPACITY
    }

    fn replace_with_checkpoint(&mut self, checkpoint: &JournalRecord) -> Result<(), Self::Error> {
        self.journal.checkpoint_exact(checkpoint.bytes())
    }
}

impl StreamingJournalBackend for AtaPioJournalVNext {
    type Error = AtaPioJournalError;

    fn stage_checkpoint(&mut self, plan: &CheckpointRecordPlan) -> Result<(), Self::Error> {
        self.journal.stage_checkpoint(plan)
    }
}

impl OstdBootJournal for AtaPioJournalVNext {
    type RecoveryError = AtaPioJournalError;

    fn recovery_candidates(&mut self) -> Result<Vec<RecoveryCandidate>, Self::RecoveryError> {
        self.journal.recovery_candidates()
    }

    fn select_recovery_candidate(
        &mut self,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), Self::RecoveryError> {
        self.journal.select_candidate(candidate)
    }

    fn read_recovery_at(
        &mut self,
        candidate: RecoveryCandidate,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), Self::RecoveryError> {
        self.journal.read_candidate_at(candidate, offset, output)
    }

    fn revalidate_recovery_candidate(
        &mut self,
        candidate: RecoveryCandidate,
    ) -> Result<(), Self::RecoveryError> {
        self.journal.revalidate_candidate(candidate)
    }

    fn repair_and_sync(
        &mut self,
        repair: JournalRepair,
        candidate: Option<RecoveryCandidate>,
    ) -> Result<(), Self::RecoveryError> {
        self.journal.repair_exact_from_candidate(repair, candidate)
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
        let bytes = self
            .banks
            .read_all_image()
            .map_err(AtaDoubleBankError::Banked)?;
        let generation = if self.banks.active.bank.is_some() {
            self.banks.active.generation
        } else {
            self.banks
                .recovery_candidates
                .iter()
                .map(|candidate| candidate.header.generation)
                .max()
                .unwrap_or(0)
        };
        if generation == 0 {
            return Ok(None);
        }
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(Some(AtaDoubleBankSnapshot {
            revision: generation,
            digest,
            bytes,
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
        // This facade is an explicitly non-CSER raw cell. It retains the
        // legacy compatibility ordering needed by its standalone revision
        // protocol; the CSER recovery path never calls this method.
        self.banks
            .read_all_image()
            .map_err(AtaDoubleBankError::Banked)?;
        let active = self.banks.active;
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

    use cser_core::{
        BootGeneration, CatalogSet, CommandRequest, CoreLimits, DeviceGeneration, Engine,
        Freshness, JournalGeneration, ProviderCoordinate, ProviderGeneration, ProviderId,
        RegistryInstance, VerifierBinding, VerifierGeneration, WorldId, standard_catalog,
    };
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

    fn production_open(
        backend: MemoryDisk,
    ) -> Result<BankedJournal<MemoryDisk>, BankedJournalError<MemoryError>> {
        BankedJournal::open_strict(backend)
    }

    fn inject_invalid_bank(journal: &mut BankedJournal<MemoryDisk>, bank: u32) {
        let mut corrupt = [0u8; SECTOR_BYTES];
        corrupt[..10].copy_from_slice(b"not-a-bank");
        journal
            .backend_mut()
            .write_sector(bank_header_lba(bank), &corrupt)
            .expect("inject malformed bank header");
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
        inject_invalid_bank(&mut journal, 0);

        assert!(matches!(
            journal.read_active_strict(),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn strict_double_bank_rejects_a_valid_header_with_corrupt_payload() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish baseline");
        let bank = journal.active.bank.expect("published bank");
        journal.backend_mut().sectors[bank_data_lba(bank) as usize][0] ^= 0xff;

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
        inject_invalid_bank(&mut journal, 1);

        let selected = journal
            .read_active_strict()
            .expect("valid predecessor remains authoritative");
        assert_eq!(selected.logical_len, b"committed".len());
        assert_eq!(
            journal.read_all_image().expect("read predecessor"),
            b"committed"
        );
    }

    #[ktest]
    fn production_open_rejects_blank_left_invalid_right() {
        let mut journal = journal();
        inject_invalid_bank(&mut journal, 1);

        assert!(matches!(
            production_open(journal.into_backend()),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn production_open_rejects_invalid_left_blank_right() {
        let mut journal = journal();
        inject_invalid_bank(&mut journal, 0);

        assert!(matches!(
            production_open(journal.into_backend()),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn production_open_keeps_valid_peer_after_malformed_bank() {
        let mut journal = journal();
        journal
            .append_exact(b"committed")
            .expect("publish valid peer");
        inject_invalid_bank(&mut journal, 1);

        let mut reopened =
            production_open(journal.into_backend()).expect("valid peer remains authoritative");
        assert!(reopened.active.bank.is_none());
        assert_eq!(
            reopened
                .read_all_image()
                .expect("read selected physical peer"),
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

        // A deterministic fill profile makes the fixed two-bank rewrite
        // visible: committing the first 64 KiB in 512-byte records still
        // writes 8,384 sectors, while metadata-only publication additionally
        // reads each source prefix before writing its inactive successor.
        for record in 1..=BANK_DATA_SECTORS {
            journal
                .append_exact(&vec![record as u8; SECTOR_BYTES])
                .expect("publish fill record");
        }

        let telemetry = journal.telemetry().expect("telemetry enabled");
        assert_eq!(telemetry.sectors_written, 8_384);
        assert_eq!(telemetry.sectors_read, 16_512);
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
    fn pio_journal_failed_append_requires_reopen() {
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
        assert!(matches!(
            journal.read_all_image(),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = BankedJournal::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("old bank remains"),
            b"committed"
        );
    }

    #[ktest]
    fn pio_journal_failed_repair_requires_reopen() {
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
        assert!(matches!(
            journal.read_all_image(),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = BankedJournal::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("old bank remains"),
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
        assert_eq!(reopened.active.logical_len, 0);
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

    #[ktest]
    fn pio_journal_reopen_retains_both_valid_banks_until_logical_selection() {
        let mut journal = journal();
        journal.append_exact(b"first").expect("first bank");
        journal.append_exact(b"-second").expect("second bank");
        let mut reopened = BankedJournal::open(journal.into_backend()).expect("reopen");

        assert_eq!(reopened.recovery_candidates.len(), 2);
        assert!(reopened.active.bank.is_none());
        let first = reopened.recovery_candidates[0].descriptor();
        let second = reopened.recovery_candidates[1].descriptor();
        assert_ne!(first, second);

        let mut first_bytes = vec![0u8; first.logical_len()];
        reopened
            .read_candidate_at(first, 0, &mut first_bytes)
            .expect("bounded first read");
        let mut second_bytes = vec![0u8; second.logical_len()];
        reopened
            .read_candidate_at(second, 0, &mut second_bytes)
            .expect("bounded second read");
        assert_eq!(first_bytes, b"first");
        assert_eq!(second_bytes, b"first-second");
    }

    fn vnext_journal() -> SegmentedJournalVNext<MemoryDisk> {
        SegmentedJournalVNext::open(MemoryDisk::fixture()).expect("open vNext memory disk")
    }

    fn streaming_checkpoint_plan(provider_count: u64) -> CheckpointRecordPlan {
        let world = WorldId::new(1).expect("world");
        let catalog = standard_catalog();
        let catalogs = CatalogSet::new(core::slice::from_ref(&catalog)).expect("catalogs");
        let freshness = Freshness::new(
            BootGeneration::new(1).expect("boot"),
            RegistryInstance::new(1).expect("registry"),
            DeviceGeneration::new(1).expect("device"),
            JournalGeneration::new(1).expect("journal"),
        );
        let verifier_generation = VerifierGeneration::new(1).expect("verifier generation");
        let mut engine = Engine::new(world, catalogs, CoreLimits::bounded_default(), freshness);
        for provider_id in 1..=provider_count {
            let provider = ProviderCoordinate::new(
                world,
                ProviderId::new(provider_id).expect("provider"),
                ProviderGeneration::new(1).expect("provider generation"),
            );
            let verifier_bindings = catalog
                .verifier_class_bindings()
                .into_iter()
                .enumerate()
                .map(|(index, class)| {
                    VerifierBinding::new(
                        class.verifier(),
                        verifier_generation,
                        class.receipt_schema(),
                        cser_core::Digest::new([0x40u8.wrapping_add(index as u8); 32]),
                    )
                    .expect("verifier binding")
                })
                .collect();
            engine
                .transact(
                    CommandRequest::RegisterProviderGeneration {
                        coordinate: provider,
                        catalog_digest: catalog.digest(),
                        verifier_bindings,
                    },
                    |_| Ok::<(), MemoryError>(()),
                )
                .expect("register provider generation");
        }
        engine
            .checkpoint_snapshot()
            .expect("checkpoint snapshot")
            .prepare_plan()
            .expect("checkpoint plan")
    }

    #[ktest]
    fn pio_vnext_streaming_checkpoint_crosses_segments_without_image_cache() {
        // With the standard catalog, 157 providers fill exactly one physical
        // segment after framing and sector alignment.  The next provider is
        // therefore the smallest fixture that exercises cross-segment writes.
        let plan = streaming_checkpoint_plan(158);
        let framed_len = plan.record_len() + VNEXT_FRAME_HEADER;
        let stored_len = framed_len.div_ceil(SECTOR_BYTES) * SECTOR_BYTES;
        assert_eq!(stored_len.div_ceil(VNEXT_SEGMENT_CAPACITY), 2);
        let mut expected = Vec::new();
        let written = plan.write_to(&mut expected).expect("encode expected plan");
        assert_eq!(written, plan.record_len());

        let mut journal = vnext_journal();
        journal
            .stage_checkpoint(&plan)
            .expect("stream checkpoint into inactive segments");
        assert!(!journal.active_materialized);
        assert!(journal.active.header.is_some());
        assert_eq!(journal.recovery_candidates.len(), 1);
        assert_eq!(journal.recovery_candidates[0].logical_len, expected.len());

        let descriptor = journal.recovery_candidates[0].descriptor();
        let mut bounded = vec![0u8; expected.len()];
        journal
            .read_candidate_at(descriptor, 0, &mut bounded)
            .expect("bounded read-at candidate");
        assert_eq!(bounded, expected);

        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("decode staged frame"),
            expected
        );
    }

    #[ktest]
    fn pio_vnext_streaming_checkpoint_flush_cut_fails_closed_before_manifest() {
        let plan = streaming_checkpoint_plan(1);
        let mut journal = vnext_journal();
        journal.backend_mut().fail_flushes_after = Some(1);
        assert!(matches!(
            journal.stage_checkpoint(&plan),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedFlushFailure
            ))
        ));
        journal.backend_mut().fail_flushes_after = None;

        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert!(reopened.recovery_candidates.is_empty());
        assert!(
            reopened
                .read_all_image()
                .expect("blank old endpoint")
                .is_empty()
        );
    }

    #[ktest]
    fn pio_vnext_streaming_checkpoint_retains_old_root_until_anchor_selection() {
        let plan = streaming_checkpoint_plan(1);
        let mut expected = Vec::new();
        plan.write_to(&mut expected).expect("checkpoint bytes");
        let mut journal = vnext_journal();
        journal.append_exact(b"anchored-old").expect("old root");
        journal
            .stage_checkpoint(&plan)
            .expect("stage replacement root");

        let mut reopened = SegmentedJournalVNext::open(journal.into_backend())
            .expect("reopen both authority candidates");
        let descriptors = reopened
            .recovery_candidates()
            .expect("enumerate both roots");
        assert_eq!(descriptors.len(), 2);
        let old = descriptors
            .iter()
            .copied()
            .find(|candidate| candidate.generation() == 1)
            .expect("old anchored root");
        let staged = descriptors
            .iter()
            .copied()
            .find(|candidate| candidate.generation() != 1)
            .expect("staged checkpoint root");

        reopened
            .select_candidate(Some(old))
            .expect("old anchor selects old root");
        assert_eq!(
            reopened.read_all_image().expect("old image"),
            b"anchored-old"
        );
        reopened
            .select_candidate(Some(staged))
            .expect("new anchor selects checkpoint root");
        assert_eq!(
            reopened.read_all_image().expect("checkpoint image"),
            expected
        );
    }

    #[ktest]
    fn pio_vnext_streaming_checkpoint_header_readback_cut_fails_closed() {
        let plan = streaming_checkpoint_plan(1);
        let mut journal = vnext_journal();
        journal.backend_mut().fail_reads_after = Some(0);
        assert!(matches!(
            journal.stage_checkpoint(&plan),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedReadFailure
            ))
        ));
        journal.backend_mut().fail_reads_after = None;

        assert!(
            SegmentedJournalVNext::open(journal.into_backend())
                .expect("reopen after header readback cut")
                .recovery_candidates
                .is_empty()
        );
    }

    #[ktest]
    fn pio_vnext_streaming_checkpoint_torn_payload_is_rejected() {
        let plan = streaming_checkpoint_plan(1);
        let mut journal = vnext_journal();
        journal
            .stage_checkpoint(&plan)
            .expect("stage candidate before torn payload");
        let endpoint = journal.active.header.clone().expect("staged endpoint");
        journal.backend_mut().sectors[vnext_data_lba(endpoint.segment) as usize][0] ^= 0xff;

        assert!(matches!(
            SegmentedJournalVNext::open(journal.into_backend()),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn pio_vnext_streaming_checkpoint_retains_ambiguous_manifest_candidates() {
        let plan = streaming_checkpoint_plan(1);
        let mut journal = vnext_journal();
        journal
            .stage_checkpoint(&plan)
            .expect("stage baseline candidate");
        let alternate_frame = encode_vnext_frame(b"alternate").expect("alternate frame");
        let alternate = journal
            .publish_segment(5, 99, 99, [0; 32], &alternate_frame, 0)
            .expect("publish alternate valid segment");
        let conflicting = VNextManifest {
            endpoint: alternate,
        }
        .encode();
        journal
            .backend_mut()
            .write_sector(vnext_manifest_lba(1), &conflicting)
            .expect("inject conflicting valid manifest");

        let reopened = SegmentedJournalVNext::open(journal.into_backend())
            .expect("retain both valid manifest candidates");
        assert_eq!(reopened.recovery_candidates.len(), 2);
        assert_ne!(
            reopened.recovery_candidates[0].descriptor(),
            reopened.recovery_candidates[1].descriptor()
        );
    }

    #[ktest]
    fn pio_vnext_divergent_manifest_reuse_preserves_selected_root_at_every_write_cut() {
        for cut in 0..=8 {
            let mut journal = vnext_journal();
            journal.append_exact(b"selected-old").expect("baseline");

            // Copy one names a valid but unselected chain in segment one.
            // Replacing the selected image is allowed to reuse that segment,
            // but copy zero must remain untouched until the new root is
            // durable in copy one.
            let alternate_frame = encode_vnext_frame(b"unselected").expect("alternate frame");
            let alternate = journal
                .publish_segment(1, 99, 99, [0; 32], &alternate_frame, 0)
                .expect("alternate segment");
            let alternate_manifest = VNextManifest {
                endpoint: alternate,
            }
            .encode();
            journal
                .backend_mut()
                .write_sector(vnext_manifest_lba(1), &alternate_manifest)
                .expect("alternate manifest");

            let mut reopened = SegmentedJournalVNext::open(journal.into_backend())
                .expect("retain divergent roots");
            let selected = reopened
                .recovery_candidates
                .iter()
                .find(|candidate| candidate.endpoint.generation == 1)
                .map(VNextRecoveryCandidate::descriptor)
                .expect("baseline descriptor");
            reopened
                .select_candidate(Some(selected))
                .expect("trusted selection");
            reopened.backend_mut().fail_writes_after = Some(cut);
            let _ = reopened.checkpoint_exact(b"replacement");
            reopened.backend_mut().fail_writes_after = None;

            let mut recovered = SegmentedJournalVNext::open(reopened.into_backend())
                .expect("one authority root always survives");
            let candidates = recovered
                .recovery_candidates()
                .expect("enumerate surviving roots");
            let authoritative = candidates
                .iter()
                .copied()
                .find(|candidate| candidate.generation() == 2)
                .or_else(|| {
                    candidates
                        .iter()
                        .copied()
                        .find(|candidate| candidate.generation() == 1)
                })
                .expect("selected old or replacement root survives");
            recovered
                .select_candidate(Some(authoritative))
                .expect("select surviving authority root");
            let image = recovered.read_all_image().expect("recover endpoint");
            assert!(
                image == b"selected-old" || image == b"replacement",
                "unexpected image at write cut {cut}"
            );
        }
    }

    #[ktest]
    fn pio_vnext_rejects_unaligned_segment_before_in_place_append() {
        let mut journal = vnext_journal();
        assert_eq!(
            journal.publish_segment(0, 1, 1, [0; 32], b"unaligned", 0),
            Err(BankedJournalError::ReadbackMismatch)
        );
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
        // Same-segment append writes its changed data sector, one fresh
        // header, both manifest copies, then the mirrored header. It reads
        // the exact header-plus-two-sector payload for both staged and mirror
        // validation reads back the pivot manifest before replacing the
        // preserved root, then validates both copies (3 + 1 + 2 + 3 sectors).
        // existing one-sector prefix is also read once to extend its digest,
        // so no committed bytes need to be cached in memory. It never copies
        // the committed prefix into another segment.
        assert_eq!(after.sectors_written - before.sectors_written, 5);
        assert_eq!(after.flushes - before.flushes, 5);
        assert_eq!(after.sectors_read - before.sectors_read, 10);
        assert!(after.hash_bytes > before.hash_bytes);
        assert_ne!(after.phase_tsc[JournalIoPhase::PayloadWritten as usize], 0);
        assert_ne!(
            after.phase_tsc[JournalIoPhase::ReadbackValidated as usize],
            0
        );
    }

    #[ktest]
    fn pio_vnext_rejects_nonzero_frame_reserved_bytes_after_resealing_outer_checksums() {
        let payload = b"canonical";
        let mut frame = encode_vnext_frame(payload).expect("canonical frame");
        assert_eq!(decode_vnext_frames(&frame).as_deref(), Some(&payload[..]));

        for (index, byte) in frame[12..16].iter_mut().enumerate() {
            *byte = (index + 1) as u8;
        }

        // Recompute and publish the segment digest and hash chain after the
        // mutation. Only the frame's noncanonical reserved bytes remain
        // invalid, so recovery must reject it at frame decoding.
        let mut journal = vnext_journal();
        let header = journal
            .publish_segment(0, 1, 1, [0; 32], &frame, 0)
            .expect("reseal outer checksums");
        journal.publish_manifest(&header).expect("publish manifest");

        assert!(matches!(
            SegmentedJournalVNext::open(journal.into_backend()),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
    }

    #[ktest]
    fn pio_vnext_unpublished_in_place_header_keeps_the_manifest_selected_prefix() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");

        // Simulate a cut after same-segment payload and one fresh header copy
        // are durable, but before either manifest copy names it. The other
        // header remains the old endpoint, so recovery must ignore the new
        // unselected prefix.
        let mut replacement = encode_vnext_frame(b"committed").expect("base frame");
        replacement.extend_from_slice(&encode_vnext_frame(b"-new-tail").expect("tail frame"));
        for (index, chunk) in replacement.chunks(SECTOR_BYTES).enumerate() {
            let mut sector = [0u8; SECTOR_BYTES];
            sector[..chunk.len()].copy_from_slice(chunk);
            journal
                .backend_mut()
                .write_sector(vnext_data_lba(0) + index as u32, &sector)
                .expect("inject replacement payload");
        }
        let replacement_header = VNextHeader {
            segment: 0,
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
            .write_sector(vnext_header_lba(0, 0), &replacement_header)
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
    fn pio_vnext_manifest_selects_the_committed_endpoint_and_ignores_inconsistent_manifest() {
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
        let reopened =
            SegmentedJournalVNext::open(reopened.into_backend()).expect("retain valid manifest");
        assert_eq!(reopened.recovery_candidates.len(), 1);
    }

    #[ktest]
    fn pio_vnext_reopen_retains_both_manifest_candidates_until_logical_selection() {
        let mut journal = vnext_journal();
        journal.append_exact(b"first").expect("first append");
        journal.append_exact(b"-second").expect("second append");
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");

        assert_eq!(reopened.recovery_candidates.len(), 2);
        assert!(reopened.active.header.is_none());
        let first = reopened.recovery_candidates[0].descriptor();
        let second = reopened.recovery_candidates[1].descriptor();
        assert_eq!(first.storage_digest(), second.storage_digest());

        let mut bytes = vec![0u8; first.logical_len()];
        reopened
            .read_candidate_at(first, 0, &mut bytes)
            .expect("bounded logical read");
        assert_eq!(bytes, b"first-second");
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
    fn pio_vnext_post_publication_readback_failure_requires_reopen() {
        let mut journal = vnext_journal();
        journal.append_exact(b"committed").expect("baseline");
        // Staged-header validation consumes three reads (H0 plus two payload
        // sectors) and manifest readback consumes two. The final H1 header
        // read then fails after every durable phase has completed.
        journal.backend_mut().fail_reads_after = Some(5);
        assert_eq!(
            journal.append_exact(b"-unread"),
            Err(BankedJournalError::Storage(
                MemoryError::InjectedReadFailure
            ))
        );
        assert!(matches!(
            journal.read_all_image(),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
        journal.backend_mut().fail_reads_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("durable endpoint"),
            b"committed-unread"
        );
    }

    #[ktest]
    fn pio_vnext_flush_failure_requires_reopen_for_old_endpoint() {
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
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("old endpoint"),
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
    fn pio_vnext_recovery_rejects_valid_four_segment_chain() {
        let mut journal = vnext_journal();
        let payload = vec![0x5a; VNEXT_SEGMENT_CAPACITY];
        let mut previous_head = [0; 32];
        let mut endpoint = None;
        for segment in 0_u32..4 {
            let generation = u64::from(segment) + 1;
            let header = journal
                .publish_segment(segment, generation, generation, previous_head, &payload, 0)
                .expect("publish valid segment");
            previous_head = header.head;
            endpoint = Some(header);
        }
        journal
            .publish_manifest(&endpoint.expect("four-segment endpoint"))
            .expect("publish valid manifest");

        assert!(matches!(
            SegmentedJournalVNext::open(journal.into_backend()),
            Err(BankedJournalError::CorruptBankMetadata)
        ));
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
    fn pio_vnext_checkpoint_reduces_replay_image_and_survives_second_reopen() {
        let mut journal = vnext_journal();
        journal.enable_telemetry();
        // Leave room for the physical frame header so each append occupies
        // exactly one segment. Three raw segment-sized payloads would require
        // a fourth sector-aligned frame fragment and must be rejected by the
        // up-front physical-capacity check.
        let payload = vec![0x5a; VNEXT_SEGMENT_CAPACITY - VNEXT_FRAME_HEADER];
        journal.append_exact(&payload).expect("first segment");
        journal.append_exact(&payload).expect("second segment");
        journal.append_exact(&payload).expect("third segment");
        let before_image = journal.read_all_image().expect("full replay image");
        let before = journal.telemetry().expect("telemetry enabled");

        journal
            .checkpoint_exact(b"committed-checkpoint")
            .expect("compact replacement");
        let after = journal.telemetry().expect("telemetry enabled");
        let compacted = journal.read_all_image().expect("compacted replay image");
        assert_eq!(compacted, b"committed-checkpoint");
        assert!(compacted.len() < before_image.len());
        // A replacement writes one alternate segment plus its metadata, not a
        // second copy of the three-segment replay image it replaces.
        assert!(after.sectors_written - before.sectors_written < 2 * BANK_DATA_SECTORS as u64);

        let mut once = SegmentedJournalVNext::open(journal.into_backend()).expect("first reopen");
        assert_eq!(once.read_all_image().expect("first replay"), compacted);
        let mut twice = SegmentedJournalVNext::open(once.into_backend()).expect("second reopen");
        assert_eq!(twice.read_all_image().expect("second replay"), compacted);
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
    fn pio_vnext_in_place_cut_before_manifest_reopens_old_endpoint() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("baseline");
        // The same-segment tail and fresh header are durable; the first
        // manifest sector is the next write and fails before authority moves.
        journal.backend_mut().fail_writes_after = Some(2);
        assert!(journal.append_exact(b"-new").is_err());
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(reopened.read_all_image().expect("old endpoint"), b"old");
    }

    #[ktest]
    fn pio_vnext_in_place_cut_after_payload_reopens_old_endpoint() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("baseline");
        // The tail itself is durable, but no staged header exists yet.
        journal.backend_mut().fail_writes_after = Some(1);
        assert!(journal.append_exact(b"-new").is_err());
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(reopened.read_all_image().expect("old endpoint"), b"old");
    }

    #[ktest]
    fn pio_vnext_in_place_cut_after_manifest_copy_zero_is_complete() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("baseline");
        // The first manifest copy and its flush complete; copy one fails.
        journal.backend_mut().fail_writes_after = Some(3);
        assert!(journal.append_exact(b"-new").is_err());
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        let image = reopened.read_all_image().expect("complete endpoint");
        assert_eq!(image, b"old-new");
    }

    #[ktest]
    fn pio_vnext_in_place_cut_after_manifest_copy_one_is_complete() {
        let mut journal = vnext_journal();
        journal.append_exact(b"old").expect("baseline");
        // Both manifest copies are durable; restoring header redundancy is
        // the next write and may fail without changing the endpoint.
        journal.backend_mut().fail_writes_after = Some(4);
        assert!(journal.append_exact(b"-new").is_err());
        journal.backend_mut().fail_writes_after = None;
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("complete endpoint"),
            b"old-new"
        );
    }

    #[ktest]
    fn pio_vnext_in_place_fill_writes_less_than_legacy_64k_fill() {
        let mut journal = vnext_journal();
        journal.enable_telemetry();

        // This is the same 128 x 512-byte logical fill measured by the
        // deployed double-bank test above. Each 512-byte raw record frames to
        // two sectors, so this occupies two vNext segments (128 KiB physical)
        // while retaining the same 64-KiB logical fill. Each append remains
        // an in-place tail update rather than a full-segment COW rewrite.
        for record in 1..=BANK_DATA_SECTORS {
            journal
                .append_exact(&vec![record as u8; SECTOR_BYTES])
                .expect("publish fill record");
        }

        let telemetry = journal.telemetry().expect("telemetry enabled");
        assert_eq!(
            journal.read_all_image().expect("full image").len(),
            JOURNAL_CAPACITY
        );
        // The legacy 64-KiB fill deterministically writes and reads 8,384
        // sectors, flushes 256 times, and hashes 8,454,144 bytes.  vNext
        // removes the cumulative payload rewrite. Crossing a segment boundary
        // copies the committed prefix into an alternate chain before the
        // single manifest pivot; exact staged-header validation also rereads
        // on every append. Metadata-only frame scanning reads more sectors,
        // but hashes only canonical frame bytes instead of repeatedly hashing
        // complete segment images. Crossing the segment boundary adds three
        // durability flushes for the alternate-chain pivot.
        // Retain the full tradeoff rather than reporting only the favorable
        // write count.
        assert_eq!(
            (
                telemetry.sectors_written,
                telemetry.sectors_read,
                telemetry.flushes,
                telemetry.hash_bytes,
            ),
            (898, 25_604, 643, 4_259_872)
        );
        assert!(telemetry.sectors_written * 8 < 8_384);
    }

    #[ktest]
    fn pio_vnext_full_preflight_keeps_old_replay_image() {
        let mut journal = vnext_journal();
        journal.enable_telemetry();
        let usable = VNEXT_SEGMENT_CAPACITY - VNEXT_FRAME_HEADER;
        journal.append_exact(&vec![0x11; usable]).expect("first");
        journal.append_exact(&vec![0x22; usable]).expect("second");
        journal.append_exact(&vec![0x33; usable]).expect("third");
        let before = journal.telemetry().expect("telemetry enabled");
        assert!(matches!(
            journal.append_exact(b"overflow"),
            Err(BankedJournalError::JournalFull { .. })
        ));
        let after = journal.telemetry().expect("telemetry enabled");
        assert_eq!(after.sectors_written, before.sectors_written);
        assert_eq!(after.flushes, before.flushes);
        let mut reopened = SegmentedJournalVNext::open(journal.into_backend()).expect("reopen");
        assert_eq!(
            reopened.read_all_image().expect("old replay").len(),
            3 * usable
        );
    }

    /// Stable production OSDK gates. Cargo-OSDK 0.18.1 filters test names by
    /// exact path suffix despite documenting substring matching, so each named
    /// gate invokes one disjoint shard of the two-bank journal regression set
    /// and yields an unambiguous pass/fail result.
    #[ktest]
    fn cser_pio_journal_safety_gate() {
        pio_journal_format_appends_exact_bytes_and_uses_two_barriers();
        pio_journal_torn_data_falls_back_to_last_committed_bank();
        pio_journal_torn_header_falls_back_to_last_committed_bank();
        strict_double_bank_rejects_a_lone_corrupt_bank();
        strict_double_bank_rejects_a_valid_header_with_corrupt_payload();
        strict_double_bank_keeps_a_valid_predecessor_after_torn_successor();
        pio_journal_repair_publishes_the_exact_prefix();
        pio_journal_capacity_is_explicit_backpressure();
        pio_journal_cache_avoids_revalidating_banks_between_appends();
    }

    #[ktest]
    fn cser_pio_journal_recovery_gate() {
        pio_journal_failed_append_requires_reopen();
        pio_journal_failed_repair_requires_reopen();
        pio_journal_reopen_revalidates_corrupted_cached_bank();
        pio_journal_repair_updates_cache_only_after_readback();
        pio_journal_reopen_retains_both_valid_banks_until_logical_selection();
    }
}

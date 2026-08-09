// SPDX-License-Identifier: MPL-2.0

//! Bounded COM3 crash-cut barrier for host-directed fault injection.
//!
//! The guest emits one authenticated barrier after a named semantic cutpoint
//! and waits for the host's matching acknowledgement. A harness that wants the
//! crash path kills QEMU after observing `BARRIER`; it intentionally sends no
//! acknowledgement. A harness that wants execution to continue sends `ACK`.
//!
//! This module is deliberately unconnected. Wiring it into a production run
//! must name only already-durable cutpoints; reaching a UART barrier never
//! makes a preceding persistence operation durable.

use core::hint::spin_loop;

use ostd::{
    arch::device::io_port::ReadWriteAccess, io::IoPort, irq::InterruptLevel, prelude::println,
    task::Task,
};
use sha2::{Digest as _, Sha256};

/// Guest COM3 base port. The QEMU profile must reserve it for the crash
/// harness and must not attach an interactive serial console.
pub(crate) const CRASH_COM3_BASE: u16 = 0x03e8;
const UART_LINE_STATUS_OFFSET: u16 = 5;
const UART_INTERRUPT_ENABLE_OFFSET: u16 = 1;
const UART_FIFO_CONTROL_OFFSET: u16 = 2;
const UART_LINE_CONTROL_OFFSET: u16 = 3;
const UART_MODEM_CONTROL_OFFSET: u16 = 4;
const UART_LSR_DATA_READY: u8 = 1 << 0;
const UART_LSR_TRANSMIT_EMPTY: u8 = 1 << 5;
const UART_LCR_DLAB: u8 = 1 << 7;
const UART_LCR_8N1: u8 = 0x03;
const UART_FCR_ENABLE_CLEAR: u8 = 0x07;
const UART_MCR_DTR_RTS: u8 = 0x03;
/// Bounded readiness polls for one byte. The crash controller supplies the
/// wall-clock deadline; this guest-side budget prevents unbounded polling.
const UART_POLL_LIMIT: u32 = 1 << 24;
const UART_POLL_BATCH: u32 = 1 << 12;
const RUN_ID_BYTES: usize = 16;
const RUN_ID_HEX_BYTES: usize = RUN_ID_BYTES * 2;
const SHA256_HEX_BYTES: usize = 64;
// A CSER1 CONFIG response contains a 64-byte catalog digest, three 32-byte
// identities, a namespace of up to 128 bytes, checksum and separators.  The
// former 128-byte barrier-sized buffer truncated a valid per-trial response
// after its first byte; keep enough bounded headroom while retaining a fixed
// non-streaming COM3 frame.
const MAX_LINE_BYTES: usize = 512;
const MAX_NAMESPACE_BYTES: usize = 128;

/// A bounded identifier for one host-directed crash run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CrashRunId([u8; RUN_ID_BYTES]);

impl CrashRunId {
    pub(crate) const fn new(bytes: [u8; RUN_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn bytes(self) -> [u8; RUN_ID_BYTES] {
        self.0
    }
}

/// Host-provided, per-row identity for the bounded QEMU experiment.
///
/// This is received over the same trusted-local COM3 control channel before
/// the guest creates an operation plan.  It is not an external receipt and
/// cannot by itself retire anything; its only role is to prevent a compiled
/// test namespace from becoming authority for a later row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExperimentIdentity {
    run_id: CrashRunId,
    catalog_digest: [u8; 32],
    authority_id: CrashRunId,
    effect_id: CrashRunId,
    namespace: [u8; MAX_NAMESPACE_BYTES],
    namespace_len: u8,
}

impl ExperimentIdentity {
    pub(crate) const fn run_id(self) -> CrashRunId {
        self.run_id
    }

    pub(crate) const fn catalog_digest(self) -> [u8; 32] {
        self.catalog_digest
    }

    pub(crate) const fn authority_id(self) -> CrashRunId {
        self.authority_id
    }
    pub(crate) const fn effect_id(self) -> CrashRunId {
        self.effect_id
    }
    pub(crate) fn namespace(&self) -> &[u8] {
        &self.namespace[..usize::from(self.namespace_len)]
    }
}

/// Semantic position at which the host may kill this QEMU instance. The value
/// is intentionally numeric so a durable journal schema can carry it without
/// depending on text labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CrashCutpoint(u16);

impl CrashCutpoint {
    pub(crate) const fn new(value: u16) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrashProbeError {
    PortBusy { port: u16 },
    TransmitTimeout,
    ReceiveTimeout,
    LineTooLong,
    InvalidAck,
    ChecksumMismatch,
    UnexpectedAck,
    InvalidConfiguration,
}

/// Per-barrier guest-side phase diagnostics. TSC values order events in the
/// guest only; they deliberately make no host wall-clock claim. A missing ACK
/// point is expected when the host kills QEMU after receiving a barrier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CrashProbeTiming {
    transmit_started_tsc: u64,
    transmit_completed_tsc: Option<u64>,
    first_ack_byte_tsc: Option<u64>,
    full_ack_frame_tsc: Option<u64>,
    matching_ack_available_tsc: Option<u64>,
    polls: u32,
    scheduler_yields: u32,
}

impl CrashProbeTiming {
    fn started() -> Self {
        Self {
            transmit_started_tsc: guest_tsc(),
            ..Self::default()
        }
    }

    pub(crate) const fn transmit_started_tsc(self) -> u64 {
        self.transmit_started_tsc
    }

    pub(crate) const fn transmit_completed_tsc(self) -> Option<u64> {
        self.transmit_completed_tsc
    }

    pub(crate) const fn first_ack_byte_tsc(self) -> Option<u64> {
        self.first_ack_byte_tsc
    }

    pub(crate) const fn full_ack_frame_tsc(self) -> Option<u64> {
        self.full_ack_frame_tsc
    }

    pub(crate) const fn matching_ack_available_tsc(self) -> Option<u64> {
        self.matching_ack_available_tsc
    }

    pub(crate) const fn polls(self) -> u32 {
        self.polls
    }

    pub(crate) const fn scheduler_yields(self) -> u32 {
        self.scheduler_yields
    }
}

/// Linear COM3 owner. This is polling-only; boot wiring owns UART setup and
/// must mask or otherwise claim any UART interrupt source.
#[derive(Debug)]
pub(crate) struct CrashProbe {
    data: IoPort<u8, ReadWriteAccess>,
    _interrupt_enable: IoPort<u8, ReadWriteAccess>,
    _fifo_control: IoPort<u8, ReadWriteAccess>,
    _line_control: IoPort<u8, ReadWriteAccess>,
    _modem_control: IoPort<u8, ReadWriteAccess>,
    line_status: IoPort<u8, ReadWriteAccess>,
    last_timing: CrashProbeTiming,
}

impl CrashProbe {
    pub(crate) fn acquire() -> Result<Self, CrashProbeError> {
        let data = IoPort::acquire(CRASH_COM3_BASE).map_err(|_| CrashProbeError::PortBusy {
            port: CRASH_COM3_BASE,
        })?;
        let interrupt_enable = IoPort::acquire(CRASH_COM3_BASE + UART_INTERRUPT_ENABLE_OFFSET)
            .map_err(|_| CrashProbeError::PortBusy {
                port: CRASH_COM3_BASE + UART_INTERRUPT_ENABLE_OFFSET,
            })?;
        let fifo_control =
            IoPort::acquire(CRASH_COM3_BASE + UART_FIFO_CONTROL_OFFSET).map_err(|_| {
                CrashProbeError::PortBusy {
                    port: CRASH_COM3_BASE + UART_FIFO_CONTROL_OFFSET,
                }
            })?;
        let line_control =
            IoPort::acquire(CRASH_COM3_BASE + UART_LINE_CONTROL_OFFSET).map_err(|_| {
                CrashProbeError::PortBusy {
                    port: CRASH_COM3_BASE + UART_LINE_CONTROL_OFFSET,
                }
            })?;
        let modem_control =
            IoPort::acquire(CRASH_COM3_BASE + UART_MODEM_CONTROL_OFFSET).map_err(|_| {
                CrashProbeError::PortBusy {
                    port: CRASH_COM3_BASE + UART_MODEM_CONTROL_OFFSET,
                }
            })?;
        let line_status =
            IoPort::acquire(CRASH_COM3_BASE + UART_LINE_STATUS_OFFSET).map_err(|_| {
                CrashProbeError::PortBusy {
                    port: CRASH_COM3_BASE + UART_LINE_STATUS_OFFSET,
                }
            })?;
        // Do not depend on firmware's UART defaults. The crash channel is a
        // polled 115200/8N1 transport, just like the separately owned COM2
        // endpoint channel. Clearing stale FIFO bytes also prevents an old
        // boot's partial ACK from being interpreted by the next boot.
        interrupt_enable.write(0);
        line_control.write(UART_LCR_DLAB);
        data.write(1);
        interrupt_enable.write(0);
        line_control.write(UART_LCR_8N1);
        fifo_control.write(UART_FCR_ENABLE_CLEAR);
        modem_control.write(UART_MCR_DTR_RTS);

        Ok(Self {
            data,
            _interrupt_enable: interrupt_enable,
            _fifo_control: fifo_control,
            _line_control: line_control,
            _modem_control: modem_control,
            line_status,
            last_timing: CrashProbeTiming::default(),
        })
    }

    /// The last barrier's phase/poll diagnostic, including one that timed out
    /// or was malformed before a matching ACK was accepted.
    pub(crate) const fn last_timing(&self) -> CrashProbeTiming {
        self.last_timing
    }

    /// Obtains the exact host-selected run namespace and catalog binding.
    /// Missing, malformed, or checksum-invalid control data is a hard error;
    /// callers must retain custody rather than fall back to a compiled id.
    pub(crate) fn experiment_identity(&mut self) -> Result<ExperimentIdentity, CrashProbeError> {
        let mut line = [0; MAX_LINE_BYTES];
        let mut timing = CrashProbeTiming::started();
        let result = (|| {
            let request_len = encode_config_hello(&mut line);
            self.write_all(&line[..request_len], &mut timing)?;
            timing.transmit_completed_tsc = Some(guest_tsc());
            let response_len = self.read_line(&mut line, &mut timing)?;
            timing.full_ack_frame_tsc = Some(guest_tsc());
            let identity = decode_config(&line[..response_len])?;
            timing.matching_ack_available_tsc = Some(guest_tsc());
            Ok(identity)
        })();
        self.last_timing = timing;
        emit_timing(
            if result.is_ok() {
                "configuration"
            } else {
                "configuration_failed"
            },
            timing,
        );
        result
    }

    /// Announces a post-condition reached by the guest and waits for a host
    /// decision to continue. Lack of an ACK is a bounded timeout for ordinary
    /// callers; a host-directed QEMU kill prevents this method from returning.
    pub(crate) fn barrier(
        &mut self,
        run_id: CrashRunId,
        cutpoint: CrashCutpoint,
    ) -> Result<(), CrashProbeError> {
        let mut line = [0; MAX_LINE_BYTES];
        let mut timing = CrashProbeTiming::started();
        let result = (|| {
            let request_len = encode_barrier(run_id, cutpoint, &mut line);
            self.write_all(&line[..request_len], &mut timing)?;
            timing.transmit_completed_tsc = Some(guest_tsc());
            emit_timing("barrier_transmitted", timing);
            let response_len = self.read_line(&mut line, &mut timing)?;
            timing.full_ack_frame_tsc = Some(guest_tsc());
            decode_ack(&line[..response_len], run_id, cutpoint)?;
            timing.matching_ack_available_tsc = Some(guest_tsc());
            Ok(())
        })();
        self.last_timing = timing;
        emit_timing(
            if result.is_ok() {
                "matching_ack"
            } else {
                "failed"
            },
            timing,
        );
        result
    }

    fn write_all(
        &mut self,
        bytes: &[u8],
        timing: &mut CrashProbeTiming,
    ) -> Result<(), CrashProbeError> {
        for byte in bytes.iter().copied() {
            self.wait_for(
                UART_LSR_TRANSMIT_EMPTY,
                CrashProbeError::TransmitTimeout,
                timing,
            )?;
            self.data.write(byte);
        }
        Ok(())
    }

    fn read_line(
        &mut self,
        output: &mut [u8; MAX_LINE_BYTES],
        timing: &mut CrashProbeTiming,
    ) -> Result<usize, CrashProbeError> {
        for (index, slot) in output.iter_mut().enumerate() {
            self.wait_for(UART_LSR_DATA_READY, CrashProbeError::ReceiveTimeout, timing)?;
            *slot = self.data.read();
            if index == 0 {
                timing.first_ack_byte_tsc = Some(guest_tsc());
            }
            if *slot == b'\n' {
                return Ok(index + 1);
            }
        }
        Err(CrashProbeError::LineTooLong)
    }

    fn wait_for(
        &self,
        mask: u8,
        timeout: CrashProbeError,
        timing: &mut CrashProbeTiming,
    ) -> Result<(), CrashProbeError> {
        let mut remaining = UART_POLL_LIMIT;
        while remaining != 0 {
            let batch = remaining.min(UART_POLL_BATCH);
            for _ in 0..batch {
                timing.polls = timing.polls.saturating_add(1);
                if self.line_status.read() & mask != 0 {
                    return Ok(());
                }
                spin_loop();
            }
            remaining -= batch;
            if remaining != 0 {
                yield_after_poll_batch(timing);
            }
        }
        Err(timeout)
    }
}

/// COM3 is used from the experiment manager task. Do not schedule from early
/// boot or an IRQ context if this small transport is ever reused elsewhere.
fn yield_after_poll_batch(timing: &mut CrashProbeTiming) {
    if Task::current().is_some() && InterruptLevel::current().is_task_context() {
        timing.scheduler_yields = timing.scheduler_yields.saturating_add(1);
        Task::yield_now();
    }
}

fn guest_tsc() -> u64 {
    ostd::arch::read_tsc()
}

fn emit_timing(result: &str, timing: CrashProbeTiming) {
    println!(
        "CRASH_PROBE_TIMING result={} transmit_started_tsc={} transmit_completed_tsc={} first_ack_byte_tsc={} full_ack_frame_tsc={} matching_ack_available_tsc={} polls={} scheduler_yields={} timing_unit=guest_tsc",
        result,
        timing.transmit_started_tsc,
        timing.transmit_completed_tsc.unwrap_or(0),
        timing.first_ack_byte_tsc.unwrap_or(0),
        timing.full_ack_frame_tsc.unwrap_or(0),
        timing.matching_ack_available_tsc.unwrap_or(0),
        timing.polls,
        timing.scheduler_yields,
    );
}

fn encode_barrier(
    run_id: CrashRunId,
    cutpoint: CrashCutpoint,
    output: &mut [u8; MAX_LINE_BYTES],
) -> usize {
    let mut cursor = 0;
    push(output, &mut cursor, b"CSER1 BARRIER ");
    push_run_id(output, &mut cursor, run_id);
    push_byte(output, &mut cursor, b' ');
    push_decimal(output, &mut cursor, cutpoint.value());
    let digest = Sha256::digest(&output[..cursor]);
    push_byte(output, &mut cursor, b' ');
    push_hex(output, &mut cursor, &digest);
    push_byte(output, &mut cursor, b'\n');
    cursor
}

fn encode_config_hello(output: &mut [u8; MAX_LINE_BYTES]) -> usize {
    let mut cursor = 0;
    push(output, &mut cursor, b"CSER1 CONFIG_HELLO");
    let digest = Sha256::digest(&output[..cursor]);
    push_byte(output, &mut cursor, b' ');
    push_hex(output, &mut cursor, &digest);
    push_byte(output, &mut cursor, b'\n');
    cursor
}

fn decode_config(line: &[u8]) -> Result<ExperimentIdentity, CrashProbeError> {
    if line.len() < 2 || line.last() != Some(&b'\n') || line[..line.len() - 1].contains(&b'\r') {
        return Err(CrashProbeError::InvalidConfiguration);
    }
    let line = &line[..line.len() - 1];
    let tokens = split_config_tokens(line)?;
    if tokens[0] != b"CSER1" || tokens[1] != b"CONFIG" {
        return Err(CrashProbeError::InvalidConfiguration);
    }
    verify_checksum(line, tokens[7]).map_err(|_| CrashProbeError::InvalidConfiguration)?;
    let run_id = parse_run_id(tokens[2]).map_err(|_| CrashProbeError::InvalidConfiguration)?;
    let catalog_digest =
        parse_hex_digest(tokens[3]).map_err(|_| CrashProbeError::InvalidConfiguration)?;
    let authority_id =
        parse_run_id(tokens[5]).map_err(|_| CrashProbeError::InvalidConfiguration)?;
    let effect_id = parse_run_id(tokens[6]).map_err(|_| CrashProbeError::InvalidConfiguration)?;
    let mut namespace = [0; MAX_NAMESPACE_BYTES];
    namespace[..tokens[4].len()].copy_from_slice(tokens[4]);
    Ok(ExperimentIdentity {
        run_id,
        catalog_digest,
        authority_id,
        effect_id,
        namespace,
        namespace_len: tokens[4].len() as u8,
    })
}

fn split_config_tokens(line: &[u8]) -> Result<[&[u8]; 8], CrashProbeError> {
    let mut tokens = [&[][..]; 8];
    let mut start = 0;
    let mut count = 0;
    for (index, byte) in line.iter().copied().enumerate() {
        if byte == b' ' {
            if index == start || count == 7 {
                return Err(CrashProbeError::InvalidConfiguration);
            }
            tokens[count] = &line[start..index];
            count += 1;
            start = index + 1;
        } else if !byte.is_ascii_graphic() {
            return Err(CrashProbeError::InvalidConfiguration);
        }
    }
    if count != 7 || start >= line.len() {
        return Err(CrashProbeError::InvalidConfiguration);
    }
    tokens[7] = &line[start..];
    // Namespace and authority are part of the checksum-bound control
    // contract even though the current compact guest plan does not yet retain
    // them as independent durable coordinates.
    if tokens[4].is_empty()
        || tokens[4].len() > 128
        || tokens[5].len() != RUN_ID_HEX_BYTES
        || tokens[6].len() != RUN_ID_HEX_BYTES
    {
        return Err(CrashProbeError::InvalidConfiguration);
    }
    let _ = parse_run_id(tokens[5])?;
    let _ = parse_run_id(tokens[6])?;
    Ok(tokens)
}

fn parse_hex_digest(token: &[u8]) -> Result<[u8; 32], CrashProbeError> {
    if token.len() != SHA256_HEX_BYTES || !token.iter().copied().all(is_lower_hex) {
        return Err(CrashProbeError::InvalidConfiguration);
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (hex_value(token[index * 2])? << 4) | hex_value(token[index * 2 + 1])?;
    }
    Ok(bytes)
}

fn decode_ack(
    line: &[u8],
    expected_run_id: CrashRunId,
    expected_cutpoint: CrashCutpoint,
) -> Result<(), CrashProbeError> {
    if line.len() < 2 || line.last() != Some(&b'\n') || line[..line.len() - 1].contains(&b'\r') {
        return Err(CrashProbeError::InvalidAck);
    }
    let line = &line[..line.len() - 1];
    let tokens = split_exact_tokens(line)?;
    if tokens[0] != b"CSER1" || tokens[1] != b"ACK" {
        return Err(CrashProbeError::InvalidAck);
    }
    verify_checksum(line, tokens[4])?;
    let run_id = parse_run_id(tokens[2])?;
    let cutpoint = parse_decimal(tokens[3])?;
    if run_id != expected_run_id || cutpoint != expected_cutpoint {
        return Err(CrashProbeError::UnexpectedAck);
    }
    Ok(())
}

fn split_exact_tokens(line: &[u8]) -> Result<[&[u8]; 5], CrashProbeError> {
    let mut tokens = [&[][..]; 5];
    let mut start = 0;
    let mut count = 0;
    for (index, byte) in line.iter().copied().enumerate() {
        if byte == b' ' {
            if index == start || count == 4 {
                return Err(CrashProbeError::InvalidAck);
            }
            tokens[count] = &line[start..index];
            count += 1;
            start = index + 1;
        } else if !byte.is_ascii_graphic() {
            return Err(CrashProbeError::InvalidAck);
        }
    }
    if count != 4 || start >= line.len() {
        return Err(CrashProbeError::InvalidAck);
    }
    tokens[4] = &line[start..];
    Ok(tokens)
}

fn verify_checksum(line: &[u8], supplied: &[u8]) -> Result<(), CrashProbeError> {
    if supplied.len() != SHA256_HEX_BYTES || !supplied.iter().copied().all(is_lower_hex) {
        return Err(CrashProbeError::InvalidAck);
    }
    let prefix_len = line
        .len()
        .checked_sub(SHA256_HEX_BYTES + 1)
        .ok_or(CrashProbeError::InvalidAck)?;
    let actual = Sha256::digest(&line[..prefix_len]);
    let mut expected = [0; SHA256_HEX_BYTES];
    encode_hex(&actual, &mut expected);
    if expected != supplied {
        return Err(CrashProbeError::ChecksumMismatch);
    }
    Ok(())
}

fn parse_run_id(token: &[u8]) -> Result<CrashRunId, CrashProbeError> {
    if token.len() != RUN_ID_HEX_BYTES || !token.iter().copied().all(is_lower_hex) {
        return Err(CrashProbeError::InvalidAck);
    }
    let mut bytes = [0; RUN_ID_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (hex_value(token[index * 2])? << 4) | hex_value(token[index * 2 + 1])?;
    }
    Ok(CrashRunId::new(bytes))
}

fn parse_decimal(token: &[u8]) -> Result<CrashCutpoint, CrashProbeError> {
    if token.is_empty()
        || token.len() > 5
        || !token.iter().copied().all(|byte| byte.is_ascii_digit())
        || (token.len() > 1 && token[0] == b'0')
    {
        return Err(CrashProbeError::InvalidAck);
    }
    let mut value = 0u16;
    for byte in token.iter().copied() {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(byte - b'0')))
            .ok_or(CrashProbeError::InvalidAck)?;
    }
    Ok(CrashCutpoint::new(value))
}

fn push(output: &mut [u8; MAX_LINE_BYTES], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn push_byte(output: &mut [u8; MAX_LINE_BYTES], cursor: &mut usize, byte: u8) {
    push(output, cursor, &[byte]);
}

fn push_run_id(output: &mut [u8; MAX_LINE_BYTES], cursor: &mut usize, run_id: CrashRunId) {
    let mut encoded = [0; RUN_ID_HEX_BYTES];
    encode_hex(&run_id.0, &mut encoded);
    push(output, cursor, &encoded);
}

fn push_decimal(output: &mut [u8; MAX_LINE_BYTES], cursor: &mut usize, value: u16) {
    let mut reversed = [0; 5];
    let mut number = value;
    let mut len = 0;
    loop {
        reversed[len] = b'0' + (number % 10) as u8;
        len += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for byte in reversed[..len].iter().rev().copied() {
        push_byte(output, cursor, byte);
    }
}

fn push_hex(output: &mut [u8; MAX_LINE_BYTES], cursor: &mut usize, input: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input.iter().copied() {
        push_byte(output, cursor, HEX[usize::from(byte >> 4)]);
        push_byte(output, cursor, HEX[usize::from(byte & 0x0f)]);
    }
}

fn encode_hex(input: &[u8], output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (byte, encoded) in input.iter().copied().zip(output.chunks_exact_mut(2)) {
        encoded[0] = HEX[usize::from(byte >> 4)];
        encoded[1] = HEX[usize::from(byte & 0x0f)];
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn hex_value(byte: u8) -> Result<u8, CrashProbeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CrashProbeError::InvalidAck),
    }
}

#[cfg(ktest)]
mod tests {
    use super::*;

    #[ktest]
    fn barrier_frame_has_a_canonical_checksum() {
        let mut line = [0; MAX_LINE_BYTES];
        let len = encode_barrier(
            CrashRunId::new([0xab; RUN_ID_BYTES]),
            CrashCutpoint::new(42),
            &mut line,
        );
        assert_eq!(line[len - 1], b'\n');
        let tokens = split_exact_tokens(&line[..len - 1]).unwrap();
        assert_eq!(tokens[1], b"BARRIER");
        verify_checksum(&line[..len - 1], tokens[4]).unwrap();
    }

    #[ktest]
    fn ack_must_match_the_exact_run_and_cutpoint() {
        let run_id = CrashRunId::new([0xcd; RUN_ID_BYTES]);
        let cutpoint = CrashCutpoint::new(7);
        let prefix = b"CSER1 ACK cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 7";
        let digest = Sha256::digest(prefix);
        let mut line = [0; MAX_LINE_BYTES];
        line[..prefix.len()].copy_from_slice(prefix);
        line[prefix.len()] = b' ';
        encode_hex(
            &digest,
            &mut line[prefix.len() + 1..prefix.len() + 1 + SHA256_HEX_BYTES],
        );
        let len = prefix.len() + 1 + SHA256_HEX_BYTES;
        line[len] = b'\n';
        assert_eq!(decode_ack(&line[..len + 1], run_id, cutpoint), Ok(()));
        assert_eq!(
            decode_ack(&line[..len + 1], run_id, CrashCutpoint::new(8)),
            Err(CrashProbeError::UnexpectedAck)
        );
    }
}

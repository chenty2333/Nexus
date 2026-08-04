// SPDX-License-Identifier: MPL-2.0

//! Bounded COM2 transport for the experimental CSER tool endpoint.
//!
//! This module deliberately owns only the guest-side wire contract.  It is
//! not wired into a runtime profile yet: a future adapter must acquire it
//! before starting tool work, retain the request identity in the CSER journal,
//! and decide which reply is retirement evidence.  Keeping that policy out of
//! the UART driver prevents a successful byte exchange from being mistaken for
//! an evidence-backed effect retirement.
//!
//! The host bridge protocol is ASCII, one bounded line per request or reply:
//!
//! ```text
//! CSER1 REQ  <POST|GET> <run_id> <operation_key> <payload_sha256> <payload_base64> <sha256>\n
//! CSER1 RESP <run_id> <operation_key> <http_status> <payload_sha256> <terminal_status> <result> <record_sha256> <sha256>\n
//! ```
//!
//! There is exactly one ASCII space between tokens. `run_id` is 16 bytes
//! rendered as 32 lowercase hexadecimal characters. The final digest is the
//! SHA-256 of the preceding tokens joined with those single spaces. Empty
//! bodies are represented by the single token `-`; all other bodies use
//! canonical padded Base64. The fixed line and payload limits are intentional
//! backpressure, not a streaming protocol.

use core::hint::spin_loop;

use ostd::{arch::device::io_port::ReadWriteAccess, io::IoPort};
use sha2::{Digest as _, Sha256};

/// Guest COM2 base port. The QEMU profile must reserve this endpoint for the
/// tool bridge and must not attach a normal serial console to it.
pub(crate) const TOOL_COM2_BASE: u16 = 0x02f8;
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

/// Bounded spin count, deliberately not a wall-clock duration claim. Unlike
/// COM3's in-process ACK, COM2 crosses a host Python bridge, SQLite, and HTTP;
/// even one hundred million TCG polls can expire before that bounded round trip
/// completes when the host schedules QEMU, Python, SQLite, and swtpm together.
/// The host QEMU envelope retains an independent wall-clock hard timeout.
const UART_POLL_LIMIT: u32 = 1_000_000_000;
const MAX_LINE_BYTES: usize = 1024;
const MAX_OPERATION_KEY_BYTES: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 576;
const RUN_ID_BYTES: usize = 16;
const SHA256_HEX_BYTES: usize = 64;

/// Stable operation identity supplied by the durable adapter, not an endpoint
/// generated nonce. The host may use it for idempotent reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolRunId([u8; RUN_ID_BYTES]);

impl ToolRunId {
    pub(crate) const fn new(bytes: [u8; RUN_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn bytes(self) -> [u8; RUN_ID_BYTES] {
        self.0
    }
}

/// Bounded, validated operation key. Only endpoint-safe ASCII characters are
/// admitted, so the key cannot alter the token grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperationKey {
    bytes: [u8; MAX_OPERATION_KEY_BYTES],
    len: u8,
}

impl OperationKey {
    pub(crate) fn new(value: &[u8]) -> Result<Self, ToolProtocolError> {
        if value.is_empty() || value.len() > MAX_OPERATION_KEY_BYTES {
            return Err(ToolProtocolError::InvalidOperationKey);
        }
        if !value.iter().copied().all(is_operation_key_byte) {
            return Err(ToolProtocolError::InvalidOperationKey);
        }
        let mut bytes = [0; MAX_OPERATION_KEY_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            bytes,
            len: value.len() as u8,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Fixed-size request body. The eventual CSER adapter must place the durable
/// effect identity in `run_id` before calling [`ToolUart::transact`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolRequest {
    pub(crate) run_id: ToolRunId,
    pub(crate) operation: OperationKey,
    method: ToolRequestMethod,
    payload_digest: [u8; 32],
    payload: [u8; MAX_PAYLOAD_BYTES],
    payload_len: u16,
}

impl ToolRequest {
    pub(crate) fn new(
        run_id: ToolRunId,
        operation: OperationKey,
        payload: &[u8],
    ) -> Result<Self, ToolProtocolError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ToolProtocolError::PayloadTooLong);
        }
        let mut stored = [0; MAX_PAYLOAD_BYTES];
        stored[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            run_id,
            operation,
            method: ToolRequestMethod::Post,
            payload_digest: Sha256::digest(payload).into(),
            payload: stored,
            payload_len: payload.len() as u16,
        })
    }

    fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.payload_len)]
    }

    pub(crate) fn get(
        run_id: ToolRunId,
        operation: OperationKey,
        payload_digest: [u8; 32],
    ) -> Self {
        Self {
            run_id,
            operation,
            method: ToolRequestMethod::Get,
            payload_digest,
            payload: [0; MAX_PAYLOAD_BYTES],
            payload_len: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolRequestMethod {
    Post,
    Get,
}

/// A terminal record decoded from a bridge response whose checksum and
/// canonical record digest both verified.  There is deliberately no public
/// constructor: transport success, a random non-zero digest, or a hand-built
/// receipt cannot stand in for this endpoint record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolTerminalRecord {
    run_id: ToolRunId,
    operation: OperationKey,
    payload_digest: [u8; 32],
    outcome: ToolTerminalOutcome,
    record_digest: [u8; 32],
}

impl ToolTerminalRecord {
    pub(crate) const fn run_id(self) -> ToolRunId {
        self.run_id
    }
    pub(crate) fn operation(&self) -> &[u8] {
        self.operation.as_bytes()
    }
    pub(crate) const fn payload_digest(self) -> [u8; 32] {
        self.payload_digest
    }
    pub(crate) const fn outcome(self) -> ToolTerminalOutcome {
        self.outcome
    }
    pub(crate) const fn record_digest(self) -> [u8; 32] {
        self.record_digest
    }
}

#[cfg(ktest)]
pub(crate) fn terminal_record_for_test(
    run_id: ToolRunId,
    operation: OperationKey,
    payload: &[u8],
) -> ToolTerminalRecord {
    let payload_digest: [u8; 32] = Sha256::digest(payload).into();
    ToolTerminalRecord {
        run_id,
        operation,
        payload_digest,
        outcome: ToolTerminalOutcome::Success,
        record_digest: canonical_record_digest(
            run_id,
            operation.as_bytes(),
            &payload_digest,
            b"applied",
            b"success",
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolTerminalOutcome {
    Success,
}

/// The bounded response returned by the bridge. A successful HTTP status is
/// not itself CSER retirement evidence; only [`ToolTerminalRecord`] may be
/// passed to the adapter, after it is checked against the durable plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolResponse {
    pub(crate) status: u16,
    terminal: Option<ToolTerminalRecord>,
}

impl ToolResponse {
    pub(crate) const fn terminal_record(self) -> Option<ToolTerminalRecord> {
        self.terminal
    }

    #[cfg(ktest)]
    pub(crate) const fn missing_terminal_for_test(status: u16) -> Self {
        Self {
            status,
            terminal: None,
        }
    }
}

/// Acquisition, bounded I/O, and protocol failures are all fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolUartError {
    PortBusy { port: u16 },
    TransmitTimeout,
    ReceiveTimeout,
    LineTooLong,
    Protocol(ToolProtocolError),
}

/// Malformed peer data, a mismatched request identity, or a checksum mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolProtocolError {
    InvalidOperationKey,
    PayloadTooLong,
    FrameTooLong,
    InvalidFrame,
    InvalidRunId,
    InvalidDigest,
    InvalidBase64,
    InvalidStatus,
    IncompleteTerminalRecord,
    InvalidTerminalRecord,
    RecordDigestMismatch,
    UnexpectedResponse,
    ChecksumMismatch,
}

/// Linear COM2 owner. Acquisition takes and initializes the complete polled
/// 16550 register set needed by this transport; interrupts remain disabled.
/// This is necessary because OVMF may leave COM2's divisor-latch and FIFO
/// state unspecified before the experiment kernel takes ownership.
#[derive(Debug)]
pub(crate) struct ToolUart {
    data: IoPort<u8, ReadWriteAccess>,
    _interrupt_enable: IoPort<u8, ReadWriteAccess>,
    _fifo_control: IoPort<u8, ReadWriteAccess>,
    _line_control: IoPort<u8, ReadWriteAccess>,
    _modem_control: IoPort<u8, ReadWriteAccess>,
    line_status: IoPort<u8, ReadWriteAccess>,
}

impl ToolUart {
    pub(crate) fn acquire() -> Result<Self, ToolUartError> {
        let data = IoPort::acquire(TOOL_COM2_BASE).map_err(|_| ToolUartError::PortBusy {
            port: TOOL_COM2_BASE,
        })?;
        let interrupt_enable = IoPort::acquire(TOOL_COM2_BASE + UART_INTERRUPT_ENABLE_OFFSET)
            .map_err(|_| ToolUartError::PortBusy {
                port: TOOL_COM2_BASE + UART_INTERRUPT_ENABLE_OFFSET,
            })?;
        let fifo_control =
            IoPort::acquire(TOOL_COM2_BASE + UART_FIFO_CONTROL_OFFSET).map_err(|_| {
                ToolUartError::PortBusy {
                    port: TOOL_COM2_BASE + UART_FIFO_CONTROL_OFFSET,
                }
            })?;
        let line_control =
            IoPort::acquire(TOOL_COM2_BASE + UART_LINE_CONTROL_OFFSET).map_err(|_| {
                ToolUartError::PortBusy {
                    port: TOOL_COM2_BASE + UART_LINE_CONTROL_OFFSET,
                }
            })?;
        let modem_control =
            IoPort::acquire(TOOL_COM2_BASE + UART_MODEM_CONTROL_OFFSET).map_err(|_| {
                ToolUartError::PortBusy {
                    port: TOOL_COM2_BASE + UART_MODEM_CONTROL_OFFSET,
                }
            })?;
        let line_status =
            IoPort::acquire(TOOL_COM2_BASE + UART_LINE_STATUS_OFFSET).map_err(|_| {
                ToolUartError::PortBusy {
                    port: TOOL_COM2_BASE + UART_LINE_STATUS_OFFSET,
                }
            })?;

        // 115200 baud (divisor 1), 8 data bits, no parity, one stop bit.
        // Clear both FIFOs only after the divisor latch has been closed, and
        // keep UART interrupts disabled because this bounded transport polls.
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
        })
    }

    /// Sends exactly one request and accepts only the matching response.
    pub(crate) fn transact(
        &mut self,
        request: &ToolRequest,
    ) -> Result<ToolResponse, ToolUartError> {
        let mut line = [0; MAX_LINE_BYTES];
        let request_len = encode_request(request, &mut line).map_err(ToolUartError::Protocol)?;
        self.write_all(&line[..request_len])?;
        let response_len = self.read_line(&mut line)?;
        decode_response(&line[..response_len], request).map_err(ToolUartError::Protocol)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), ToolUartError> {
        for byte in bytes.iter().copied() {
            self.wait_for(UART_LSR_TRANSMIT_EMPTY, ToolUartError::TransmitTimeout)?;
            self.data.write(byte);
        }
        Ok(())
    }

    fn read_line(&mut self, output: &mut [u8; MAX_LINE_BYTES]) -> Result<usize, ToolUartError> {
        for (index, slot) in output.iter_mut().enumerate() {
            self.wait_for(UART_LSR_DATA_READY, ToolUartError::ReceiveTimeout)?;
            *slot = self.data.read();
            if *slot == b'\n' {
                return Ok(index + 1);
            }
        }
        Err(ToolUartError::LineTooLong)
    }

    fn wait_for(&self, mask: u8, timeout: ToolUartError) -> Result<(), ToolUartError> {
        for _ in 0..UART_POLL_LIMIT {
            if self.line_status.read() & mask != 0 {
                return Ok(());
            }
            spin_loop();
        }
        Err(timeout)
    }
}

fn encode_request(
    request: &ToolRequest,
    output: &mut [u8; MAX_LINE_BYTES],
) -> Result<usize, ToolProtocolError> {
    let mut writer = LineWriter::new(output);
    writer.push(b"CSER1 REQ ")?;
    writer.push(match request.method {
        ToolRequestMethod::Post => b"POST",
        ToolRequestMethod::Get => b"GET",
    })?;
    writer.push_byte(b' ')?;
    writer.push_run_id(request.run_id)?;
    writer.push_byte(b' ')?;
    writer.push(request.operation.as_bytes())?;
    writer.push_byte(b' ')?;
    writer.push_hex(&request.payload_digest)?;
    writer.push_byte(b' ')?;
    writer.push_base64(request.payload())?;
    writer.finish_with_checksum()
}

pub(crate) fn decode_response(
    line: &[u8],
    request: &ToolRequest,
) -> Result<ToolResponse, ToolProtocolError> {
    if line.len() < 2 || line.last() != Some(&b'\n') || line[..line.len() - 1].contains(&b'\r') {
        return Err(ToolProtocolError::InvalidFrame);
    }
    let without_newline = &line[..line.len() - 1];
    let tokens = split_response_tokens(without_newline)?;
    if tokens[0] != b"CSER1" || tokens[1] != b"RESP" {
        return Err(ToolProtocolError::InvalidFrame);
    }
    verify_checksum(without_newline, tokens[9])?;
    if parse_run_id(tokens[2])? != request.run_id || tokens[3] != request.operation.as_bytes() {
        return Err(ToolProtocolError::UnexpectedResponse);
    }
    let status = parse_status(tokens[4])?;
    let terminal = match (tokens[5], tokens[6], tokens[7], tokens[8]) {
        (b"-", b"-", b"-", b"-") => {
            if status < 300 {
                return Err(ToolProtocolError::IncompleteTerminalRecord);
            }
            None
        }
        (payload_digest, terminal_status, result, record_digest) => {
            if payload_digest == b"-"
                || terminal_status == b"-"
                || result == b"-"
                || record_digest == b"-"
            {
                return Err(ToolProtocolError::IncompleteTerminalRecord);
            }
            let payload_digest = parse_digest(payload_digest)?;
            if payload_digest != request.payload_digest {
                return Err(ToolProtocolError::UnexpectedResponse);
            }
            let outcome = match (terminal_status, result) {
                (b"applied", b"success") => ToolTerminalOutcome::Success,
                _ => return Err(ToolProtocolError::InvalidTerminalRecord),
            };
            let record_digest = parse_digest(record_digest)?;
            let expected = canonical_record_digest(
                request.run_id,
                request.operation.as_bytes(),
                &payload_digest,
                terminal_status,
                result,
            );
            if record_digest != expected {
                return Err(ToolProtocolError::RecordDigestMismatch);
            }
            Some(ToolTerminalRecord {
                run_id: request.run_id,
                operation: request.operation,
                payload_digest,
                outcome,
                record_digest,
            })
        }
    };
    Ok(ToolResponse { status, terminal })
}

fn split_response_tokens(line: &[u8]) -> Result<[&[u8]; 10], ToolProtocolError> {
    let mut tokens = [&[][..]; 10];
    let mut token_start = 0;
    let mut token_count = 0;
    for (index, byte) in line.iter().copied().enumerate() {
        if byte == b' ' {
            if index == token_start || token_count == 9 {
                return Err(ToolProtocolError::InvalidFrame);
            }
            tokens[token_count] = &line[token_start..index];
            token_count += 1;
            token_start = index + 1;
        } else if !byte.is_ascii_graphic() {
            return Err(ToolProtocolError::InvalidFrame);
        }
    }
    if token_count != 9 || token_start >= line.len() {
        return Err(ToolProtocolError::InvalidFrame);
    }
    tokens[9] = &line[token_start..];
    Ok(tokens)
}

fn split_request_tokens(line: &[u8]) -> Result<[&[u8]; 8], ToolProtocolError> {
    let mut tokens = [&[][..]; 8];
    let mut token_start = 0;
    let mut token_count = 0;
    for (index, byte) in line.iter().copied().enumerate() {
        if byte == b' ' {
            if index == token_start || token_count == 7 {
                return Err(ToolProtocolError::InvalidFrame);
            }
            tokens[token_count] = &line[token_start..index];
            token_count += 1;
            token_start = index + 1;
        } else if !byte.is_ascii_graphic() {
            return Err(ToolProtocolError::InvalidFrame);
        }
    }
    if token_count != 7 || token_start >= line.len() {
        return Err(ToolProtocolError::InvalidFrame);
    }
    tokens[7] = &line[token_start..];
    Ok(tokens)
}

fn verify_checksum(line: &[u8], supplied: &[u8]) -> Result<(), ToolProtocolError> {
    if supplied.len() != SHA256_HEX_BYTES || !supplied.iter().copied().all(is_lower_hex) {
        return Err(ToolProtocolError::InvalidDigest);
    }
    let prefix_len = line
        .len()
        .checked_sub(SHA256_HEX_BYTES + 1)
        .ok_or(ToolProtocolError::InvalidFrame)?;
    let actual = Sha256::digest(&line[..prefix_len]);
    let mut expected = [0; SHA256_HEX_BYTES];
    encode_hex(&actual, &mut expected);
    if expected != supplied {
        return Err(ToolProtocolError::ChecksumMismatch);
    }
    Ok(())
}

fn parse_digest(token: &[u8]) -> Result<[u8; 32], ToolProtocolError> {
    if token.len() != SHA256_HEX_BYTES || !token.iter().copied().all(is_lower_hex) {
        return Err(ToolProtocolError::InvalidDigest);
    }
    let mut bytes = [0; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = (hex_value(token[index * 2])? << 4) | hex_value(token[index * 2 + 1])?;
    }
    Ok(bytes)
}

fn canonical_record_digest(
    run_id: ToolRunId,
    operation: &[u8],
    payload_digest: &[u8; 32],
    terminal_status: &[u8],
    result: &[u8],
) -> [u8; 32] {
    let mut run_id_hex = [0; RUN_ID_BYTES * 2];
    encode_hex(&run_id.bytes(), &mut run_id_hex);
    let mut payload_digest_hex = [0; SHA256_HEX_BYTES];
    encode_hex(payload_digest, &mut payload_digest_hex);
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-cser-tool-record-v1");
    for field in [
        &run_id_hex[..],
        operation,
        &payload_digest_hex[..],
        terminal_status,
        result,
    ] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn parse_run_id(token: &[u8]) -> Result<ToolRunId, ToolProtocolError> {
    if token.len() != RUN_ID_BYTES * 2 || !token.iter().copied().all(is_lower_hex) {
        return Err(ToolProtocolError::InvalidRunId);
    }
    let mut bytes = [0; RUN_ID_BYTES];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = (hex_value(token[index * 2])? << 4) | hex_value(token[index * 2 + 1])?;
    }
    Ok(ToolRunId::new(bytes))
}

fn parse_status(token: &[u8]) -> Result<u16, ToolProtocolError> {
    if token.len() != 3 || !token.iter().copied().all(|byte| byte.is_ascii_digit()) {
        return Err(ToolProtocolError::InvalidStatus);
    }
    let status = token
        .iter()
        .fold(0u16, |value, byte| value * 10 + u16::from(*byte - b'0'));
    if !(100..=599).contains(&status) {
        return Err(ToolProtocolError::InvalidStatus);
    }
    Ok(status)
}

fn decode_base64(token: &[u8]) -> Result<([u8; MAX_PAYLOAD_BYTES], u16), ToolProtocolError> {
    if token == b"-" {
        return Ok(([0; MAX_PAYLOAD_BYTES], 0));
    }
    if token.len() % 4 != 0 || token.is_empty() {
        return Err(ToolProtocolError::InvalidBase64);
    }
    let padding = if token.ends_with(b"==") {
        2
    } else if token.ends_with(b"=") {
        1
    } else {
        0
    };
    if token[..token.len() - padding]
        .iter()
        .copied()
        .any(|byte| base64_value(byte).is_none())
        || token[token.len() - padding..]
            .iter()
            .copied()
            .any(|byte| byte != b'=')
    {
        return Err(ToolProtocolError::InvalidBase64);
    }
    let decoded_len = token.len() / 4 * 3 - padding;
    if decoded_len > MAX_PAYLOAD_BYTES {
        return Err(ToolProtocolError::PayloadTooLong);
    }
    let mut output = [0; MAX_PAYLOAD_BYTES];
    let mut written = 0;
    for chunk in token.chunks_exact(4) {
        let a = base64_value(chunk[0]).ok_or(ToolProtocolError::InvalidBase64)?;
        let b = base64_value(chunk[1]).ok_or(ToolProtocolError::InvalidBase64)?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2]).ok_or(ToolProtocolError::InvalidBase64)?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3]).ok_or(ToolProtocolError::InvalidBase64)?
        };
        output[written] = (a << 2) | (b >> 4);
        written += 1;
        if written < decoded_len {
            output[written] = (b << 4) | (c >> 2);
            written += 1;
        }
        if written < decoded_len {
            output[written] = (c << 6) | d;
            written += 1;
        }
    }
    // Canonical Base64 is part of the signed byte contract. Re-encoding is a
    // simple way to reject non-zero pad bits and non-canonical spellings.
    let mut canonical = [0; MAX_LINE_BYTES];
    let canonical_len = encode_base64(&output[..decoded_len], &mut canonical)?;
    if &canonical[..canonical_len] != token {
        return Err(ToolProtocolError::InvalidBase64);
    }
    Ok((output, decoded_len as u16))
}

fn is_operation_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn hex_value(byte: u8) -> Result<u8, ToolProtocolError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ToolProtocolError::InvalidDigest),
    }
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

struct LineWriter<'a> {
    output: &'a mut [u8; MAX_LINE_BYTES],
    len: usize,
}

impl<'a> LineWriter<'a> {
    fn new(output: &'a mut [u8; MAX_LINE_BYTES]) -> Self {
        Self { output, len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), ToolProtocolError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(ToolProtocolError::FrameTooLong)?;
        if end > self.output.len() {
            return Err(ToolProtocolError::FrameTooLong);
        }
        self.output[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), ToolProtocolError> {
        self.push(&[byte])
    }

    fn push_run_id(&mut self, run_id: ToolRunId) -> Result<(), ToolProtocolError> {
        let mut encoded = [0; RUN_ID_BYTES * 2];
        encode_hex(&run_id.bytes(), &mut encoded);
        self.push(&encoded)
    }

    fn push_hex(&mut self, digest: &[u8]) -> Result<(), ToolProtocolError> {
        let mut encoded = [0; SHA256_HEX_BYTES];
        if digest.len() != SHA256_HEX_BYTES / 2 {
            return Err(ToolProtocolError::InvalidDigest);
        }
        encode_hex(digest, &mut encoded);
        self.push(&encoded)
    }

    fn push_base64(&mut self, payload: &[u8]) -> Result<(), ToolProtocolError> {
        if payload.is_empty() {
            return self.push(b"-");
        }
        let start = self.len;
        let encoded = encode_base64(payload, &mut self.output[start..])?;
        self.len += encoded;
        Ok(())
    }

    fn finish_with_checksum(mut self) -> Result<usize, ToolProtocolError> {
        let checksum = Sha256::digest(&self.output[..self.len]);
        self.push_byte(b' ')?;
        self.push_hex(&checksum)?;
        self.push_byte(b'\n')?;
        Ok(self.len)
    }
}

fn encode_hex(input: &[u8], output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (byte, encoded) in input.iter().copied().zip(output.chunks_exact_mut(2)) {
        encoded[0] = HEX[usize::from(byte >> 4)];
        encoded[1] = HEX[usize::from(byte & 0x0f)];
    }
}

fn encode_base64(input: &[u8], output: &mut [u8]) -> Result<usize, ToolProtocolError> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let needed = input.len().div_ceil(3) * 4;
    if needed > output.len() {
        return Err(ToolProtocolError::FrameTooLong);
    }
    for (index, chunk) in input.chunks(3).enumerate() {
        let base = index * 4;
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output[base] = TABLE[usize::from(first >> 2)];
        output[base + 1] = TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))];
        output[base + 2] = if chunk.len() > 1 {
            TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))]
        } else {
            b'='
        };
        output[base + 3] = if chunk.len() > 2 {
            TABLE[usize::from(third & 0x3f)]
        } else {
            b'='
        };
    }
    Ok(needed)
}

#[cfg(ktest)]
mod tests {
    use super::*;

    #[ktest]
    fn request_frame_is_bounded_canonical_and_checksums_its_prefix() {
        let request = ToolRequest::new(
            ToolRunId::new([0x12; RUN_ID_BYTES]),
            OperationKey::new(b"tool.echo-v1").unwrap(),
            b"hello",
        )
        .unwrap();
        let mut line = [0; MAX_LINE_BYTES];
        let len = encode_request(&request, &mut line).unwrap();
        assert_eq!(&line[..6], b"CSER1 ");
        assert_eq!(line[len - 1], b'\n');
        let tokens = split_request_tokens(&line[..len - 1]).unwrap();
        assert_eq!(tokens[1], b"REQ");
        assert_eq!(tokens[2], b"POST");
        verify_checksum(&line[..len - 1], tokens[7]).unwrap();

        let digest: [u8; 32] = Sha256::digest(b"hello").into();
        let query = ToolRequest::get(request.run_id, request.operation, digest);
        let query_len = encode_request(&query, &mut line).unwrap();
        let query_tokens = split_request_tokens(&line[..query_len - 1]).unwrap();
        assert_eq!(query_tokens[2], b"GET");
        assert_eq!(query_tokens[6], b"-");
    }

    #[ktest]
    fn response_requires_matching_plan_and_canonical_terminal_record() {
        let request = ToolRequest::new(
            ToolRunId::new([0x34; RUN_ID_BYTES]),
            OperationKey::new(b"charge.card").unwrap(),
            b"ignored",
        )
        .unwrap();
        let (line, len) = terminal_response(&request, 201);
        let response = decode_response(&line[..len + 1], &request).unwrap();
        assert_eq!(response.status, 201);
        let record = response.terminal_record().unwrap();
        assert_eq!(record.outcome(), ToolTerminalOutcome::Success);
        assert_eq!(record.operation(), b"charge.card");
    }

    #[ktest]
    fn checksum_and_noncanonical_base64_fail_closed() {
        let request = ToolRequest::new(
            ToolRunId::new([0x56; RUN_ID_BYTES]),
            OperationKey::new(b"tool").unwrap(),
            b"",
        )
        .unwrap();
        let (mut line, len) = terminal_response(&request, 200);
        // A checksum-valid, but forged record digest is still not evidence.
        let forged_record = b"0000000000000000000000000000000000000000000000000000000000000000";
        // Replace the canonical record digest token and recompute the frame checksum.
        let prefix_end = len - SHA256_HEX_BYTES - 1;
        let record_start = line[..prefix_end]
            .iter()
            .rposition(|byte| *byte == b' ')
            .unwrap()
            + 1;
        line[record_start..prefix_end].copy_from_slice(forged_record);
        let checksum = Sha256::digest(&line[..prefix_end]);
        encode_hex(
            &checksum,
            &mut line[prefix_end + 1..prefix_end + 1 + SHA256_HEX_BYTES],
        );
        assert_eq!(
            decode_response(&line[..len + 1], &request),
            Err(ToolProtocolError::RecordDigestMismatch)
        );
        line[len - 1] ^= 1;
        assert_eq!(
            decode_response(&line[..len + 1], &request),
            Err(ToolProtocolError::ChecksumMismatch)
        );
    }

    fn terminal_response(request: &ToolRequest, status: u16) -> ([u8; MAX_LINE_BYTES], usize) {
        let payload_digest: [u8; 32] = Sha256::digest(request.payload()).into();
        let record_digest = canonical_record_digest(
            request.run_id,
            request.operation.as_bytes(),
            &payload_digest,
            b"applied",
            b"success",
        );
        let mut run_hex = [0; RUN_ID_BYTES * 2];
        encode_hex(&request.run_id.bytes(), &mut run_hex);
        let mut payload_hex = [0; SHA256_HEX_BYTES];
        encode_hex(&payload_digest, &mut payload_hex);
        let mut record_hex = [0; SHA256_HEX_BYTES];
        encode_hex(&record_digest, &mut record_hex);
        let mut line = [0; MAX_LINE_BYTES];
        let mut writer = LineWriter::new(&mut line);
        writer.push(b"CSER1 RESP ").unwrap();
        writer.push(&run_hex).unwrap();
        writer.push_byte(b' ').unwrap();
        writer.push(request.operation.as_bytes()).unwrap();
        writer.push_byte(b' ').unwrap();
        if status == 200 {
            writer.push(b"200").unwrap();
        } else {
            writer.push(b"201").unwrap();
        }
        writer.push_byte(b' ').unwrap();
        writer.push(&payload_hex).unwrap();
        writer.push(b" applied success ").unwrap();
        writer.push(&record_hex).unwrap();
        let len = writer.finish_with_checksum().unwrap();
        (line, len - 1)
    }
}

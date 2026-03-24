//! 16550 UART serial output on COM1 (0x3F8).

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use spin::Mutex;
use uart_16550::SerialPort;

/// COM1 base port.
const COM1: u16 = 0x3F8;

struct SerialState {
    port: SerialPort,
    inited: bool,
}

impl SerialState {
    fn new() -> Self {
        // SAFETY: COM1 is a fixed legacy I/O port on x86 PC platforms.
        // Access remains CPL0-only and is serialized via the global mutex.
        let port = unsafe { SerialPort::new(COM1) };
        Self {
            port,
            inited: false,
        }
    }

    fn init_if_needed(&mut self) {
        if self.inited {
            return;
        }
        self.port.init();
        self.inited = true;
    }
}

static SERIAL: Mutex<Option<SerialState>> = Mutex::new(None);

pub fn init() {
    let mut guard = SERIAL.lock();
    if guard.is_none() {
        *guard = Some(SerialState::new());
    }
    if let Some(state) = guard.as_mut() {
        state.init_if_needed();
    }
}

pub fn _print(args: fmt::Arguments<'_>) {
    use fmt::Write;
    // Use try_lock to avoid deadlocking when called from interrupt context
    // while the lock is already held (e.g. kprintln inside an ISR that
    // interrupted a kprintln). If the lock is contended, the log line is
    // silently dropped -- this is preferable to a hard deadlock.
    let Some(mut guard) = SERIAL.try_lock() else {
        return;
    };
    if guard.is_none() {
        *guard = Some(SerialState::new());
    }
    if let Some(state) = guard.as_mut() {
        state.init_if_needed();
        let _ = state.port.write_fmt(args);
    }
}

pub fn write_bytes(bytes: &[u8]) -> usize {
    let mut guard = SERIAL.lock();
    if guard.is_none() {
        *guard = Some(SerialState::new());
    }
    let Some(state) = guard.as_mut() else {
        return 0;
    };
    state.init_if_needed();
    for &byte in bytes {
        state.port.send_raw(byte);
    }
    bytes.len()
}

pub fn read_bytes(max_len: usize) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let mut guard = SERIAL.lock();
    if guard.is_none() {
        *guard = Some(SerialState::new());
    }
    let Some(state) = guard.as_mut() else {
        return Vec::new();
    };
    state.init_if_needed();
    let mut out = Vec::new();
    let first = normalize_input_byte(state.port.receive());
    out.push(first);
    while out.len() < max_len {
        match state.port.try_receive() {
            Ok(byte) => out.push(normalize_input_byte(byte)),
            Err(_) => break,
        }
    }
    out
}

fn normalize_input_byte(byte: u8) -> u8 {
    if byte == b'\r' { b'\n' } else { byte }
}

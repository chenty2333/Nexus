//! 16550 UART serial output on COM1 (0x3F8).

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
    let mut guard = SERIAL.lock();
    if guard.is_none() {
        *guard = Some(SerialState::new());
    }
    if let Some(state) = guard.as_mut() {
        state.init_if_needed();
        let _ = state.port.write_fmt(args);
    }
}

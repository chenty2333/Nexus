//! Minimal 16550 UART serial output on COM1 (0x3F8).
//!
//! This is enough for bring-up logs and the future userspace test runner.

use core::fmt;
use spin::Mutex;

/// COM1 base port.
const COM1: u16 = 0x3F8;

static SERIAL: Mutex<SerialPort> = Mutex::new(SerialPort::new(COM1));

pub fn init() {
    SERIAL.lock().init();
}

pub fn _print(args: fmt::Arguments<'_>) {
    use fmt::Write;
    let _ = SERIAL.lock().write_fmt(args);
}

pub struct SerialPort {
    base: u16,
    inited: bool,
}

impl SerialPort {
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            inited: false,
        }
    }

    pub fn init(&mut self) {
        if self.inited {
            return;
        }
        unsafe {
            outb(self.base + 1, 0x00); // disable interrupts
            outb(self.base + 3, 0x80); // enable DLAB
            outb(self.base + 0, 0x01); // divisor low  (115200 baud)
            outb(self.base + 1, 0x00); // divisor high
            outb(self.base + 3, 0x03); // 8N1
            outb(self.base + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
            outb(self.base + 4, 0x0B); // IRQs enabled, RTS/DSR set
        }
        self.inited = true;
    }

    fn tx_ready(&self) -> bool {
        unsafe { inb(self.base + 5) & 0x20 != 0 }
    }

    fn write_byte(&mut self, b: u8) {
        while !self.tx_ready() {
            core::hint::spin_loop();
        }
        unsafe { outb(self.base, b) }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            match b {
                b'\n' => {
                    self.write_byte(b'\r');
                    self.write_byte(b'\n');
                }
                _ => self.write_byte(b),
            }
        }
        Ok(())
    }
}

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

unsafe fn inb(port: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags));
    v
}

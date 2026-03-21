use super::super::*;

const LINUX_NCCS: usize = 19;
const LINUX_VINTR: usize = 0;
const LINUX_VERASE: usize = 2;
const LINUX_VEOF: usize = 4;
const LINUX_VMIN: usize = 6;
const LINUX_VTIME: usize = 5;
const LINUX_VSTART: usize = 8;
const LINUX_VSTOP: usize = 9;
const LINUX_VSUSP: usize = 10;
const LINUX_VKILL: usize = 3;

pub(in crate::starnix) const LINUX_TCGETS: u64 = 0x5401;
pub(in crate::starnix) const LINUX_TCSETS: u64 = 0x5402;
pub(in crate::starnix) const LINUX_TCSETSW: u64 = 0x5403;
pub(in crate::starnix) const LINUX_TCSETSF: u64 = 0x5404;
pub(in crate::starnix) const LINUX_TIOCGPGRP: u64 = 0x540f;
pub(in crate::starnix) const LINUX_TIOCSPGRP: u64 = 0x5410;
pub(in crate::starnix) const LINUX_TIOCGWINSZ: u64 = 0x5413;
pub(in crate::starnix) const LINUX_TIOCSWINSZ: u64 = 0x5414;

const LINUX_ICRNL: u32 = 0x0100;
const LINUX_IXON: u32 = 0x0400;
const LINUX_OPOST: u32 = 0x0001;
const LINUX_ONLCR: u32 = 0x0004;
const LINUX_B38400: u32 = 0x000f;
const LINUX_CS8: u32 = 0x0030;
const LINUX_CREAD: u32 = 0x0080;
const LINUX_HUPCL: u32 = 0x0400;
const LINUX_ISIG: u32 = 0x0001;
const LINUX_ICANON: u32 = 0x0002;
const LINUX_ECHO: u32 = 0x0008;
const LINUX_ECHOE: u32 = 0x0010;
const LINUX_ECHOK: u32 = 0x0020;
const LINUX_ECHOCTL: u32 = 0x0200;
const LINUX_IEXTEN: u32 = 0x8000;

const LINUX_TERMIOS_BYTES: usize = 36;
const LINUX_WINSIZE_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxTermios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; LINUX_NCCS],
}

impl Default for LinuxTermios {
    fn default() -> Self {
        let mut c_cc = [0u8; LINUX_NCCS];
        c_cc[LINUX_VINTR] = 3;
        c_cc[LINUX_VKILL] = 21;
        c_cc[LINUX_VERASE] = 127;
        c_cc[LINUX_VEOF] = 4;
        c_cc[LINUX_VTIME] = 0;
        c_cc[LINUX_VMIN] = 1;
        c_cc[LINUX_VSTART] = 17;
        c_cc[LINUX_VSTOP] = 19;
        c_cc[LINUX_VSUSP] = 26;
        Self {
            c_iflag: LINUX_ICRNL | LINUX_IXON,
            c_oflag: LINUX_OPOST | LINUX_ONLCR,
            c_cflag: LINUX_B38400 | LINUX_CS8 | LINUX_CREAD | LINUX_HUPCL,
            c_lflag: LINUX_ISIG
                | LINUX_ICANON
                | LINUX_ECHO
                | LINUX_ECHOE
                | LINUX_ECHOK
                | LINUX_ECHOCTL
                | LINUX_IEXTEN,
            c_line: 0,
            c_cc,
        }
    }
}

impl LinuxTermios {
    fn encode(self) -> [u8; LINUX_TERMIOS_BYTES] {
        let mut bytes = [0u8; LINUX_TERMIOS_BYTES];
        bytes[0..4].copy_from_slice(&self.c_iflag.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.c_oflag.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.c_cflag.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.c_lflag.to_ne_bytes());
        bytes[16] = self.c_line;
        bytes[17..].copy_from_slice(&self.c_cc);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, zx_status_t> {
        if bytes.len() != LINUX_TERMIOS_BYTES {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        let mut c_cc = [0u8; LINUX_NCCS];
        c_cc.copy_from_slice(&bytes[17..]);
        Ok(Self {
            c_iflag: u32::from_ne_bytes(bytes[0..4].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            c_oflag: u32::from_ne_bytes(bytes[4..8].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            c_cflag: u32::from_ne_bytes(bytes[8..12].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            c_lflag: u32::from_ne_bytes(bytes[12..16].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            c_line: bytes[16],
            c_cc,
        })
    }

    fn canonical(self) -> bool {
        (self.c_lflag & LINUX_ICANON) != 0
    }

    fn echo(self) -> bool {
        (self.c_lflag & LINUX_ECHO) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxWinSize {
    rows: u16,
    cols: u16,
    xpixel: u16,
    ypixel: u16,
}

impl Default for LinuxWinSize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            xpixel: 0,
            ypixel: 0,
        }
    }
}

impl LinuxWinSize {
    fn encode(self) -> [u8; LINUX_WINSIZE_BYTES] {
        let mut bytes = [0u8; LINUX_WINSIZE_BYTES];
        bytes[0..2].copy_from_slice(&self.rows.to_ne_bytes());
        bytes[2..4].copy_from_slice(&self.cols.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.xpixel.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.ypixel.to_ne_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, zx_status_t> {
        if bytes.len() != LINUX_WINSIZE_BYTES {
            return Err(ZX_ERR_INVALID_ARGS);
        }
        Ok(Self {
            rows: u16::from_ne_bytes(bytes[0..2].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            cols: u16::from_ne_bytes(bytes[2..4].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            xpixel: u16::from_ne_bytes(bytes[4..6].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
            ypixel: u16::from_ne_bytes(bytes[6..8].try_into().map_err(|_| ZX_ERR_INVALID_ARGS)?),
        })
    }
}

#[derive(Debug, Default)]
struct ConsoleTtyState {
    termios: LinuxTermios,
    winsize: LinuxWinSize,
    current_line: Vec<u8>,
    ready: VecDeque<u8>,
    eof_pending: bool,
}

impl ConsoleTtyState {
    fn try_consume_ready(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.eof_pending {
            self.eof_pending = false;
            return Some(0);
        }
        if self.ready.is_empty() {
            return None;
        }
        let actual = buffer.len().min(self.ready.len());
        for dst in &mut buffer[..actual] {
            *dst = self.ready.pop_front().expect("ready byte");
        }
        Some(actual)
    }

    fn ingest_raw_bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut echo = Vec::new();
        for &byte in bytes {
            if self.termios.canonical() {
                self.ingest_canonical_byte(byte, &mut echo);
            } else {
                self.ready.push_back(byte);
                if self.termios.echo() {
                    echo.push(byte);
                }
            }
        }
        echo
    }

    fn ingest_canonical_byte(&mut self, byte: u8, echo: &mut Vec<u8>) {
        let erase = self.termios.c_cc[LINUX_VERASE];
        let eof = self.termios.c_cc[LINUX_VEOF];
        let kill = self.termios.c_cc[LINUX_VKILL];
        match byte {
            b'\n' => {
                self.current_line.push(b'\n');
                self.ready.extend(self.current_line.drain(..));
                if self.termios.echo() {
                    echo.extend_from_slice(b"\r\n");
                }
            }
            b if b == erase || b == 0x08 => {
                if self.current_line.pop().is_some() && self.termios.echo() {
                    echo.extend_from_slice(b"\x08 \x08");
                }
            }
            b if b == kill => {
                if !self.current_line.is_empty() {
                    self.current_line.clear();
                    if self.termios.echo() {
                        echo.extend_from_slice(b"^U\r\n");
                    }
                }
            }
            b if b == eof => {
                if self.current_line.is_empty() {
                    self.eof_pending = true;
                } else {
                    self.ready.extend(self.current_line.drain(..));
                }
            }
            _ => {
                self.current_line.push(byte);
                if self.termios.echo() {
                    echo.push(byte);
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::starnix) struct ConsoleFd {
    state: Arc<Mutex<ConsoleTtyState>>,
}

impl Default for ConsoleFd {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleFd {
    pub(in crate::starnix) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConsoleTtyState::default())),
        }
    }
}

impl FdOps for ConsoleFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        if buffer.is_empty() {
            return Ok(0);
        }

        loop {
            if let Some(actual) = self.state.lock().try_consume_ready(buffer) {
                return Ok(actual);
            }

            let mut raw = [0u8; 128];
            let mut actual = 0usize;
            zx_status_result(ax_console_read(&mut raw, &mut actual))?;
            let echo = {
                let mut state = self.state.lock();
                state.ingest_raw_bytes(&raw[..actual])
            };
            if !echo.is_empty() {
                let mut echoed = 0usize;
                zx_status_result(ax_console_write(&echo, &mut echoed))?;
            }
            if let Some(actual) = self.state.lock().try_consume_ready(buffer) {
                return Ok(actual);
            }
        }
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let mut actual = 0usize;
        zx_status_result(ax_console_write(buffer, &mut actual))?;
        Ok(actual)
    }

    fn seek(&self, _origin: SeekOrigin, _offset: i64) -> Result<u64, zx_status_t> {
        Err(ZX_ERR_NOT_SUPPORTED)
    }

    fn close(&self) -> Result<(), zx_status_t> {
        Ok(())
    }

    fn clone_fd(&self, _flags: FdFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        Ok(Arc::new(self.clone()))
    }

    fn wait_interest(&self) -> Option<WaitSpec> {
        None
    }

    fn ioctl(&self, session: zx_handle_t, request: u64, arg: u64) -> Result<u64, zx_status_t> {
        match request {
            LINUX_TCGETS => {
                let bytes = self.state.lock().termios.encode();
                write_guest_bytes(session, arg, &bytes)?;
                Ok(0)
            }
            LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => {
                let bytes = read_guest_bytes(session, arg, LINUX_TERMIOS_BYTES)?;
                let decoded = LinuxTermios::decode(&bytes)?;
                let mut state = self.state.lock();
                state.termios = decoded;
                if request == LINUX_TCSETSF {
                    state.current_line.clear();
                    state.ready.clear();
                    state.eof_pending = false;
                }
                Ok(0)
            }
            LINUX_TIOCGWINSZ => {
                let bytes = self.state.lock().winsize.encode();
                write_guest_bytes(session, arg, &bytes)?;
                Ok(0)
            }
            LINUX_TIOCSWINSZ => {
                let bytes = read_guest_bytes(session, arg, LINUX_WINSIZE_BYTES)?;
                let decoded = LinuxWinSize::decode(&bytes)?;
                self.state.lock().winsize = decoded;
                Ok(0)
            }
            _ => Err(ZX_ERR_NOT_SUPPORTED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_console_returns_line_after_newline() {
        let mut state = ConsoleTtyState::default();
        let echo = state.ingest_raw_bytes(b"ls");
        assert_eq!(echo, b"ls");
        let mut out = [0u8; 16];
        assert_eq!(state.try_consume_ready(&mut out), None);

        let echo = state.ingest_raw_bytes(b"\n");
        assert_eq!(echo, b"\r\n");
        let actual = state.try_consume_ready(&mut out).expect("line ready");
        assert_eq!(&out[..actual], b"ls\n");
    }

    #[test]
    fn canonical_console_honors_backspace() {
        let mut state = ConsoleTtyState::default();
        let echo = state.ingest_raw_bytes(b"ab\x7f\n");
        assert_eq!(echo, b"ab\x08 \x08\r\n");
        let mut out = [0u8; 16];
        let actual = state.try_consume_ready(&mut out).expect("line ready");
        assert_eq!(&out[..actual], b"a\n");
    }

    #[test]
    fn canonical_console_reports_eof_on_empty_line() {
        let mut state = ConsoleTtyState::default();
        let _ = state.ingest_raw_bytes(&[4]);
        let mut out = [0u8; 8];
        assert_eq!(state.try_consume_ready(&mut out), Some(0));
    }
}

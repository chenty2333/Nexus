use super::super::*;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};

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
pub(in crate::starnix) const LINUX_TIOCSCTTY: u64 = 0x540e;
pub(in crate::starnix) const LINUX_TIOCGPGRP: u64 = 0x540f;
pub(in crate::starnix) const LINUX_TIOCSPGRP: u64 = 0x5410;
pub(in crate::starnix) const LINUX_TIOCGWINSZ: u64 = 0x5413;
pub(in crate::starnix) const LINUX_TIOCSWINSZ: u64 = 0x5414;
pub(in crate::starnix) const LINUX_TIOCNOTTY: u64 = 0x5422;

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

static NEXT_TTY_ID: AtomicU64 = AtomicU64::new(1);

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

    fn map_input_byte(self, byte: u8) -> u8 {
        if byte == b'\r' && (self.c_iflag & LINUX_ICRNL) != 0 {
            b'\n'
        } else {
            byte
        }
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
struct TtyState {
    termios: LinuxTermios,
    winsize: LinuxWinSize,
    current_line: Vec<u8>,
    slave_ready: VecDeque<u8>,
    master_ready: VecDeque<u8>,
    eof_pending: bool,
}

impl TtyState {
    fn try_consume_slave_ready(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.eof_pending {
            self.eof_pending = false;
            return Some(0);
        }
        if self.slave_ready.is_empty() {
            return None;
        }
        let actual = buffer.len().min(self.slave_ready.len());
        for dst in &mut buffer[..actual] {
            *dst = self.slave_ready.pop_front().expect("slave-ready byte");
        }
        Some(actual)
    }

    fn try_consume_master_ready(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.master_ready.is_empty() {
            return None;
        }
        let actual = buffer.len().min(self.master_ready.len());
        for dst in &mut buffer[..actual] {
            *dst = self.master_ready.pop_front().expect("master-ready byte");
        }
        Some(actual)
    }

    fn ingest_master_bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut echo = Vec::new();
        for &raw_byte in bytes {
            let byte = self.termios.map_input_byte(raw_byte);
            if self.termios.canonical() {
                self.ingest_canonical_byte(byte, &mut echo);
            } else {
                self.slave_ready.push_back(byte);
                if self.termios.echo() {
                    echo.push(byte);
                }
            }
        }
        if !echo.is_empty() {
            self.master_ready.extend(echo.iter().copied());
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
                self.slave_ready.extend(self.current_line.drain(..));
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
                    self.slave_ready.extend(self.current_line.drain(..));
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

#[derive(Debug)]
pub(in crate::starnix) struct TtyCore {
    id: u64,
    state: Mutex<TtyState>,
}

impl TtyCore {
    fn new() -> Self {
        Self {
            id: NEXT_TTY_ID.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(TtyState::default()),
        }
    }

    pub(in crate::starnix) const fn id(&self) -> u64 {
        self.id
    }

    fn slave_read(&self, buffer: &mut [u8], console_bridge: bool) -> Result<usize, zx_status_t> {
        if buffer.is_empty() {
            return Ok(0);
        }

        loop {
            if let Some(actual) = self.state.lock().try_consume_slave_ready(buffer) {
                return Ok(actual);
            }
            if !console_bridge {
                return Err(ZX_ERR_SHOULD_WAIT);
            }

            let mut raw = [0u8; 128];
            let mut actual = 0usize;
            zx_status_result(ax_console_read(&mut raw, &mut actual))?;
            if actual == 0 {
                continue;
            }
            let echo = self.state.lock().ingest_master_bytes(&raw[..actual]);
            if !echo.is_empty() {
                let mut echoed = 0usize;
                zx_status_result(ax_console_write(&echo, &mut echoed))?;
            }
        }
    }

    fn slave_write(&self, buffer: &[u8], console_bridge: bool) -> Result<usize, zx_status_t> {
        self.state
            .lock()
            .master_ready
            .extend(buffer.iter().copied());
        if console_bridge {
            let mut actual = 0usize;
            zx_status_result(ax_console_write(buffer, &mut actual))?;
        }
        Ok(buffer.len())
    }

    fn master_read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.state
            .lock()
            .try_consume_master_ready(buffer)
            .ok_or(ZX_ERR_SHOULD_WAIT)
    }

    fn master_write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        let _ = self.state.lock().ingest_master_bytes(buffer);
        Ok(buffer.len())
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
                    state.slave_ready.clear();
                    state.master_ready.clear();
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

#[derive(Clone, Debug)]
pub(in crate::starnix) struct PtySlaveFd {
    core: Arc<TtyCore>,
    console_bridge: bool,
}

impl PtySlaveFd {
    fn new(core: Arc<TtyCore>, console_bridge: bool) -> Self {
        Self {
            core,
            console_bridge,
        }
    }

    pub(in crate::starnix) fn tty_id(&self) -> u64 {
        self.core.id()
    }
}

impl FdOps for PtySlaveFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        self.core.slave_read(buffer, self.console_bridge)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        self.core.slave_write(buffer, self.console_bridge)
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
        self.core.ioctl(session, request, arg)
    }
}

#[derive(Clone, Debug)]
pub(in crate::starnix) struct PtyMasterFd {
    core: Arc<TtyCore>,
}

impl PtyMasterFd {
    fn new(core: Arc<TtyCore>) -> Self {
        Self { core }
    }

    pub(in crate::starnix) fn tty_id(&self) -> u64 {
        self.core.id()
    }
}

impl FdOps for PtyMasterFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        self.core.master_read(buffer)
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, zx_status_t> {
        self.core.master_write(buffer)
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
        self.core.ioctl(session, request, arg)
    }
}

#[derive(Default)]
pub(in crate::starnix) struct PtyRegistry {
    next_id: Mutex<u32>,
    slaves: Mutex<BTreeMap<u32, Arc<PtySlaveFd>>>,
}

impl PtyRegistry {
    pub(in crate::starnix) fn new() -> Self {
        Self::default()
    }

    pub(in crate::starnix) fn allocate_pair(
        &self,
        console_bridge: bool,
    ) -> (Arc<PtyMasterFd>, Arc<PtySlaveFd>) {
        let mut next = self.next_id.lock();
        let pts_id = *next;
        *next = next.saturating_add(1);
        drop(next);

        let core = Arc::new(TtyCore::new());
        let slave = Arc::new(PtySlaveFd::new(core.clone(), console_bridge));
        let master = Arc::new(PtyMasterFd::new(core));
        self.slaves.lock().insert(pts_id, slave.clone());
        (master, slave)
    }

    pub(in crate::starnix) fn allocate_console_slave(&self) -> Arc<PtySlaveFd> {
        let (_master, slave) = self.allocate_pair(true);
        slave
    }

    fn clone_slave(&self, pts_id: u32) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let slave = self
            .slaves
            .lock()
            .get(&pts_id)
            .cloned()
            .ok_or(ZX_ERR_NOT_FOUND)?;
        slave.clone_fd(FdFlags::empty())
    }

    fn readdir(&self) -> Vec<DirectoryEntry> {
        self.slaves
            .lock()
            .keys()
            .map(|pts_id| DirectoryEntry {
                name: pts_id.to_string(),
                kind: DirectoryEntryKind::File,
            })
            .collect()
    }
}

#[derive(Clone)]
pub(in crate::starnix) struct DevPtsDirFd {
    registry: Arc<PtyRegistry>,
}

impl DevPtsDirFd {
    pub(in crate::starnix) fn new(registry: Arc<PtyRegistry>) -> Self {
        Self { registry }
    }
}

impl FdOps for DevPtsDirFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
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

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Ok(self.registry.readdir())
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let normalized = path.trim_matches('/');
        if normalized.is_empty() || normalized == "." {
            return Ok(Arc::new(self.clone()));
        }
        if normalized.contains('/') {
            return Err(ZX_ERR_NOT_FOUND);
        }
        let pts_id = normalized.parse::<u32>().map_err(|_| ZX_ERR_NOT_FOUND)?;
        self.registry.clone_slave(pts_id)
    }
}

#[derive(Clone)]
pub(in crate::starnix) struct DevDirFd {
    current_tty: Arc<Mutex<Option<Arc<PtySlaveFd>>>>,
    pts_dir: Arc<DevPtsDirFd>,
    registry: Arc<PtyRegistry>,
    null: Arc<dyn FdOps>,
    zero: Arc<dyn FdOps>,
}

impl DevDirFd {
    pub(in crate::starnix) fn new(
        current_tty: Arc<Mutex<Option<Arc<PtySlaveFd>>>>,
        registry: Arc<PtyRegistry>,
        null: Arc<dyn FdOps>,
        zero: Arc<dyn FdOps>,
    ) -> Self {
        let pts_dir = Arc::new(DevPtsDirFd::new(registry.clone()));
        Self {
            current_tty,
            pts_dir,
            registry,
            null,
            zero,
        }
    }

    fn tty(&self) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let tty = self.current_tty.lock().clone().ok_or(ZX_ERR_NOT_FOUND)?;
        tty.clone_fd(FdFlags::empty())
    }
}

impl FdOps for DevDirFd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buffer: &mut [u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
    }

    fn write(&self, _buffer: &[u8]) -> Result<usize, zx_status_t> {
        Err(ZX_ERR_NOT_FILE)
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

    fn readdir(&self) -> Result<Vec<DirectoryEntry>, zx_status_t> {
        Ok(vec![
            DirectoryEntry {
                name: String::from("tty"),
                kind: DirectoryEntryKind::File,
            },
            DirectoryEntry {
                name: String::from("ptmx"),
                kind: DirectoryEntryKind::File,
            },
            DirectoryEntry {
                name: String::from("pts"),
                kind: DirectoryEntryKind::Directory,
            },
            DirectoryEntry {
                name: String::from("null"),
                kind: DirectoryEntryKind::File,
            },
            DirectoryEntry {
                name: String::from("zero"),
                kind: DirectoryEntryKind::File,
            },
        ])
    }

    fn openat(&self, path: &str, _flags: OpenFlags) -> Result<Arc<dyn FdOps>, zx_status_t> {
        let normalized = path.trim_matches('/');
        if normalized.is_empty() || normalized == "." {
            return Ok(Arc::new(self.clone()));
        }
        let (head, tail) = normalized
            .split_once('/')
            .map_or((normalized, None), |(head, tail)| (head, Some(tail)));
        match (head, tail) {
            ("tty", None) => self.tty(),
            ("ptmx", None) => {
                let (master, _slave) = self.registry.allocate_pair(false);
                Ok(master)
            }
            ("pts", None) => Ok(self.pts_dir.clone()),
            ("pts", Some(tail)) => self.pts_dir.openat(tail, OpenFlags::READABLE),
            ("null", None) => Ok(Arc::clone(&self.null)),
            ("zero", None) => Ok(Arc::clone(&self.zero)),
            _ => Err(ZX_ERR_NOT_FOUND),
        }
    }
}

pub(in crate::starnix) fn tty_endpoint_identity(ops: &dyn FdOps) -> Option<(u64, bool)> {
    if let Some(slave) = ops.as_any().downcast_ref::<PtySlaveFd>() {
        return Some((slave.tty_id(), true));
    }
    if let Some(master) = ops.as_any().downcast_ref::<PtyMasterFd>() {
        return Some((master.tty_id(), false));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_tty_returns_line_after_newline() {
        let registry = PtyRegistry::new();
        let master = registry.allocate_pair(false).0;
        let slave = registry.slaves.lock().get(&0).cloned().expect("slave");

        assert_eq!(master.write(b"ls"), Ok(2));
        let mut out = [0u8; 16];
        assert_eq!(slave.read(&mut out), Err(ZX_ERR_SHOULD_WAIT));

        assert_eq!(master.write(b"\n"), Ok(1));
        let actual = slave.read(&mut out).expect("line ready");
        assert_eq!(&out[..actual], b"ls\n");
    }

    #[test]
    fn devpts_reexports_allocated_slave() {
        let registry = Arc::new(PtyRegistry::new());
        let (_master, _slave) = registry.allocate_pair(false);
        let pts = DevPtsDirFd::new(registry.clone());
        let reopened = pts.openat("0", OpenFlags::READABLE).expect("pts/0");
        assert!(reopened.as_any().is::<PtySlaveFd>());
    }
}

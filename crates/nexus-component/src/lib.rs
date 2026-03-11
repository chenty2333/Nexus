//! Minimal Nexus component-model contracts shared by host tools and userspace.
//!
//! This crate freezes the first component-framework wire contracts:
//! - a compact binary IR for component declarations
//! - a unified `ResolvedComponent` shape
//! - bootstrap-channel `ComponentStartInfo`
//! - tiny controller and outgoing-directory request messages

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use axle_types::zx_handle_t;

const DECL_MAGIC: &[u8; 4] = b"NXCD";
const MESSAGE_MAGIC: &[u8; 4] = b"NXCM";
const WIRE_VERSION: u16 = 1;

/// Errors returned while decoding or encoding Nexus component wire data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The byte stream ended before the expected value was fully present.
    UnexpectedEof,
    /// The bytes did not start with the expected magic.
    InvalidMagic,
    /// The bytes used an unsupported format version.
    UnsupportedVersion(u16),
    /// The decoder saw an unknown discriminant for a typed field.
    InvalidTag {
        /// Field name used for diagnostics.
        field: &'static str,
        /// Raw tag value that failed to decode.
        value: u8,
    },
    /// The bytes contained invalid UTF-8 for a string field.
    InvalidUtf8,
    /// The caller passed the wrong number of handles for a channel message.
    HandleCountMismatch {
        /// Expected handle count derived from the encoded metadata.
        expected: usize,
        /// Actual caller-supplied handle count.
        actual: usize,
    },
    /// The encoded payload had extra trailing bytes after a full decode.
    TrailingBytes,
    /// One of the encoded lengths overflowed the local platform limits.
    LengthOverflow,
}

/// Error returned by the in-memory resolver table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The component URL was malformed.
    InvalidUrl,
    /// The URL scheme is not part of the minimal resolver surface.
    UnsupportedScheme,
    /// No resolver record matched the requested URL.
    NotFound,
}

/// Supported component startup modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupMode {
    /// Start the component during initial topology assembly.
    Eager,
    /// Start the component on first routed capability use.
    Lazy,
}

/// Supported minimal capability kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityKind {
    /// A protocol routed as a namespace entry or outgoing node.
    Protocol,
    /// A directory routed as a namespace entry or outgoing node.
    Directory,
    /// A runner capability lookup.
    Runner,
    /// A resolver capability lookup.
    Resolver,
}

/// Supported resolver schemes in the phase-three minimal component model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverScheme {
    /// Boot image backed component resolution.
    Boot,
    /// Package-store backed component resolution.
    Pkg,
    /// Test-only pre-mounted local directory resolution.
    Local,
}

impl ResolverScheme {
    /// Parse a URL scheme from a component URL.
    pub fn parse(url: &str) -> Result<Self, ResolveError> {
        let (scheme, rest) = url.split_once("://").ok_or(ResolveError::InvalidUrl)?;
        if rest.is_empty() {
            return Err(ResolveError::InvalidUrl);
        }
        match scheme {
            "boot" => Ok(Self::Boot),
            "pkg" => Ok(Self::Pkg),
            "local" => Ok(Self::Local),
            _ => Err(ResolveError::UnsupportedScheme),
        }
    }
}

impl StartupMode {
    fn encode(self) -> u8 {
        match self {
            Self::Eager => 0,
            Self::Lazy => 1,
        }
    }

    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Eager),
            1 => Ok(Self::Lazy),
            _ => Err(CodecError::InvalidTag {
                field: "startup_mode",
                value,
            }),
        }
    }
}

impl CapabilityKind {
    fn encode(self) -> u8 {
        match self {
            Self::Protocol => 0,
            Self::Directory => 1,
            Self::Runner => 2,
            Self::Resolver => 3,
        }
    }

    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Protocol),
            1 => Ok(Self::Directory),
            2 => Ok(Self::Runner),
            3 => Ok(Self::Resolver),
            _ => Err(CodecError::InvalidTag {
                field: "capability_kind",
                value,
            }),
        }
    }
}

/// Component `program` stanza.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramDecl {
    /// Runner capability name to use for this program.
    pub runner: String,
    /// Binary path relative to the resolved package directory.
    pub binary: String,
    /// Process argument vector.
    pub args: Vec<String>,
    /// Process environment strings in `KEY=VALUE` form.
    pub env: Vec<String>,
}

/// A `use` declaration in the minimal component IR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseDecl {
    /// Capability kind being requested.
    pub kind: CapabilityKind,
    /// Capability name in the provider namespace.
    pub source_name: String,
    /// Namespace path where the consumer sees the capability.
    ///
    /// `runner` and `resolver` capabilities do not need a namespace path and
    /// therefore leave this as `None`.
    pub target_path: Option<String>,
}

/// Source of an `exposes` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExposeSource {
    /// Expose a capability served by the component itself.
    Self_,
    /// Expose a capability re-exported from one named child.
    Child(String),
}

/// An `exposes` declaration in the minimal component IR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposeDecl {
    /// Capability kind being exposed. The phase-three minimal model supports
    /// only `protocol` and `directory` here.
    pub kind: CapabilityKind,
    /// Source of the exposed capability.
    pub source: ExposeSource,
    /// Capability name in the source component.
    pub source_name: String,
    /// Capability name re-exported to the parent realm.
    pub target_name: String,
}

/// A child component declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildDecl {
    /// Stable child instance name.
    pub name: String,
    /// Child component URL.
    pub url: String,
    /// Child startup mode.
    pub startup: StartupMode,
}

/// Minimal component declaration IR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentDecl {
    /// Resolved or canonical component URL.
    pub url: String,
    /// Program stanza for the component.
    pub program: ProgramDecl,
    /// Capabilities used by the component.
    pub uses: Vec<UseDecl>,
    /// Capabilities exposed by the component.
    pub exposes: Vec<ExposeDecl>,
    /// Statically-declared child topology.
    pub children: Vec<ChildDecl>,
    /// Startup mode for this component instance.
    pub startup: StartupMode,
}

impl ComponentDecl {
    /// Encode this declaration into the stable binary IR.
    pub fn encode_binary(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_magic(DECL_MAGIC);
        writer.write_u16(WIRE_VERSION);
        self.encode_into(&mut writer);
        writer.finish()
    }

    /// Decode one declaration from the stable binary IR.
    pub fn decode_binary(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(DECL_MAGIC)?;
        let version = reader.read_u16()?;
        if version != WIRE_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let decl = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(decl)
    }

    fn encode_into(&self, writer: &mut Writer) {
        writer.write_string(&self.url);
        self.program.encode_into(writer);
        writer.write_vec(&self.uses, UseDecl::encode_into);
        writer.write_vec(&self.exposes, ExposeDecl::encode_into);
        writer.write_vec(&self.children, ChildDecl::encode_into);
        writer.write_u8(self.startup.encode());
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            url: reader.read_string()?,
            program: ProgramDecl::decode_from(reader)?,
            uses: reader.read_vec(UseDecl::decode_from)?,
            exposes: reader.read_vec(ExposeDecl::decode_from)?,
            children: reader.read_vec(ChildDecl::decode_from)?,
            startup: StartupMode::decode(reader.read_u8()?)?,
        })
    }
}

impl ProgramDecl {
    fn encode_into(&self, writer: &mut Writer) {
        writer.write_string(&self.runner);
        writer.write_string(&self.binary);
        writer.write_strings(&self.args);
        writer.write_strings(&self.env);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            runner: reader.read_string()?,
            binary: reader.read_string()?,
            args: reader.read_strings()?,
            env: reader.read_strings()?,
        })
    }
}

impl UseDecl {
    fn encode_into(&self, writer: &mut Writer) {
        writer.write_u8(self.kind.encode());
        writer.write_string(&self.source_name);
        writer.write_optional_string(self.target_path.as_deref());
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            kind: CapabilityKind::decode(reader.read_u8()?)?,
            source_name: reader.read_string()?,
            target_path: reader.read_optional_string()?,
        })
    }
}

impl ExposeDecl {
    fn encode_into(&self, writer: &mut Writer) {
        writer.write_u8(self.kind.encode());
        match &self.source {
            ExposeSource::Self_ => {
                writer.write_u8(0);
            }
            ExposeSource::Child(name) => {
                writer.write_u8(1);
                writer.write_string(name);
            }
        }
        writer.write_string(&self.source_name);
        writer.write_string(&self.target_name);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let kind = CapabilityKind::decode(reader.read_u8()?)?;
        let source = match reader.read_u8()? {
            0 => ExposeSource::Self_,
            1 => ExposeSource::Child(reader.read_string()?),
            value => {
                return Err(CodecError::InvalidTag {
                    field: "expose_source",
                    value,
                });
            }
        };
        Ok(Self {
            kind,
            source,
            source_name: reader.read_string()?,
            target_name: reader.read_string()?,
        })
    }
}

impl ChildDecl {
    fn encode_into(&self, writer: &mut Writer) {
        writer.write_string(&self.name);
        writer.write_string(&self.url);
        writer.write_u8(self.startup.encode());
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            name: reader.read_string()?,
            url: reader.read_string()?,
            startup: StartupMode::decode(reader.read_u8()?)?,
        })
    }
}

/// Unified resolver return shape for the minimal component framework.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedComponent {
    /// Decoded component declaration.
    pub decl: ComponentDecl,
    /// Package directory handle, when the resolved scheme carries one.
    pub package_dir: Option<zx_handle_t>,
    /// Config blob handle, when resolution attaches one.
    pub config_blob: Option<zx_handle_t>,
}

/// One namespace entry routed into a child component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceEntry {
    /// Namespace path such as `/svc/fuchsia.logger.LogSink`.
    pub path: String,
    /// Handle for the routed directory/protocol endpoint.
    pub handle: zx_handle_t,
}

/// One numbered startup handle routed into a child component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumberedHandle {
    /// Stable startup-handle number.
    pub id: u32,
    /// Handle value installed in the child.
    pub handle: zx_handle_t,
}

/// Start payload sent over the bootstrap channel to a new component instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentStartInfo {
    /// Argument vector for the started process.
    pub args: Vec<String>,
    /// Environment vector for the started process.
    pub env: Vec<String>,
    /// Routed namespace entries.
    pub namespace_entries: Vec<NamespaceEntry>,
    /// Extra numbered startup handles.
    pub numbered_handles: Vec<NumberedHandle>,
    /// Server end of the component's outgoing directory.
    pub outgoing_dir_server_end: Option<zx_handle_t>,
    /// Lifecycle controller channel.
    pub controller_channel: Option<zx_handle_t>,
}

impl ComponentStartInfo {
    /// Encode this start payload into one channel message.
    ///
    /// Handle order is stable:
    /// 1. namespace entry handles, in declaration order
    /// 2. numbered startup handles, in declaration order
    /// 3. optional outgoing directory server end
    /// 4. optional controller channel
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, MessageKind::ComponentStartInfo);
        writer.write_strings(&self.args);
        writer.write_strings(&self.env);
        writer.write_vec(&self.namespace_entries, |entry, writer| {
            writer.write_string(&entry.path);
        });
        writer.write_vec(&self.numbered_handles, |entry, writer| {
            writer.write_u32(entry.id);
        });
        writer.write_bool(self.outgoing_dir_server_end.is_some());
        writer.write_bool(self.controller_channel.is_some());

        let mut handles = Vec::new();
        for entry in &self.namespace_entries {
            handles.push(entry.handle);
        }
        for entry in &self.numbered_handles {
            handles.push(entry.handle);
        }
        if let Some(handle) = self.outgoing_dir_server_end {
            handles.push(handle);
        }
        if let Some(handle) = self.controller_channel {
            handles.push(handle);
        }

        EncodedMessage {
            bytes: writer.finish(),
            handles,
        }
    }

    /// Decode one start payload from a bootstrap-channel message.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, MessageKind::ComponentStartInfo)?;
        let args = reader.read_strings()?;
        let env = reader.read_strings()?;
        let namespace_paths = reader.read_vec(|reader| reader.read_string())?;
        let numbered_ids = reader.read_vec(|reader| reader.read_u32())?;
        let has_outgoing = reader.read_bool()?;
        let has_controller = reader.read_bool()?;
        reader.finish()?;

        let expected = namespace_paths.len()
            + numbered_ids.len()
            + usize::from(has_outgoing)
            + usize::from(has_controller);
        if handles.len() != expected {
            return Err(CodecError::HandleCountMismatch {
                expected,
                actual: handles.len(),
            });
        }

        let mut handle_index = 0usize;
        let namespace_entries = namespace_paths
            .into_iter()
            .map(|path| {
                let handle = handles[handle_index];
                handle_index += 1;
                NamespaceEntry { path, handle }
            })
            .collect();
        let numbered_handles = numbered_ids
            .into_iter()
            .map(|id| {
                let handle = handles[handle_index];
                handle_index += 1;
                NumberedHandle { id, handle }
            })
            .collect();
        let outgoing_dir_server_end = if has_outgoing {
            let handle = handles[handle_index];
            handle_index += 1;
            Some(handle)
        } else {
            None
        };
        let controller_channel = if has_controller {
            Some(handles[handle_index])
        } else {
            None
        };

        Ok(Self {
            args,
            env,
            namespace_entries,
            numbered_handles,
            outgoing_dir_server_end,
            controller_channel,
        })
    }
}

/// Minimal outgoing-directory open request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryOpenRequest {
    /// Relative path to open under the routed directory.
    pub path: String,
    /// Protocol-specific flags.
    pub flags: u32,
    /// Server end for the opened node.
    pub object: zx_handle_t,
}

impl DirectoryOpenRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, MessageKind::DirectoryOpenRequest);
        writer.write_string(&self.path);
        writer.write_u32(self.flags);
        EncodedMessage {
            bytes: writer.finish(),
            handles: alloc::vec![self.object],
        }
    }

    /// Decode this request from one channel message.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        if handles.len() != 1 {
            return Err(CodecError::HandleCountMismatch {
                expected: 1,
                actual: handles.len(),
            });
        }
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, MessageKind::DirectoryOpenRequest)?;
        let path = reader.read_string()?;
        let flags = reader.read_u32()?;
        reader.finish()?;
        Ok(Self {
            path,
            flags,
            object: handles[0],
        })
    }
}

/// Minimal controller request set for component lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerRequest {
    /// Ask the component to stop cleanly.
    Stop,
    /// Force the component to terminate.
    Kill,
}

impl ControllerRequest {
    /// Encode this request into a channel message with no handles.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, MessageKind::ControllerRequest);
        writer.write_u8(match self {
            Self::Stop => 0,
            Self::Kill => 1,
        });
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode one controller request from a channel message with no handles.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        if !handles.is_empty() {
            return Err(CodecError::HandleCountMismatch {
                expected: 0,
                actual: handles.len(),
            });
        }
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, MessageKind::ControllerRequest)?;
        let request = match reader.read_u8()? {
            0 => Self::Stop,
            1 => Self::Kill,
            value => {
                return Err(CodecError::InvalidTag {
                    field: "controller_request",
                    value,
                });
            }
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Minimal controller event set for component lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerEvent {
    /// Component termination notification.
    OnTerminated {
        /// Process-style return code or termination reason.
        return_code: i64,
    },
}

impl ControllerEvent {
    /// Encode this event into a channel message with no handles.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, MessageKind::ControllerEvent);
        match self {
            Self::OnTerminated { return_code } => {
                writer.write_u8(0);
                writer.write_i64(*return_code);
            }
        }
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode one controller event from a channel message with no handles.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        if !handles.is_empty() {
            return Err(CodecError::HandleCountMismatch {
                expected: 0,
                actual: handles.len(),
            });
        }
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, MessageKind::ControllerEvent)?;
        let event = match reader.read_u8()? {
            0 => Self::OnTerminated {
                return_code: reader.read_i64()?,
            },
            value => {
                return Err(CodecError::InvalidTag {
                    field: "controller_event",
                    value,
                });
            }
        };
        reader.finish()?;
        Ok(event)
    }
}

/// Encoded channel payload bytes plus transferred handles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedMessage {
    /// Message bytes written into the channel payload.
    pub bytes: Vec<u8>,
    /// Handles transferred alongside the byte payload.
    pub handles: Vec<zx_handle_t>,
}

/// One record in the in-memory resolver table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverRecord {
    /// Exact component URL.
    pub url: String,
    /// Resolved component shape.
    pub resolved: ResolvedComponent,
}

/// Minimal in-memory resolver table covering `boot://`, `pkg://`, and `local://`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolverTable {
    boot: Vec<ResolverRecord>,
    pkg: Vec<ResolverRecord>,
    local: Vec<ResolverRecord>,
}

impl ResolverTable {
    /// Create an empty resolver table.
    pub const fn new() -> Self {
        Self {
            boot: Vec::new(),
            pkg: Vec::new(),
            local: Vec::new(),
        }
    }

    /// Insert one resolved component record, selecting the backend by URL scheme.
    pub fn insert(&mut self, record: ResolverRecord) -> Result<(), ResolveError> {
        match ResolverScheme::parse(&record.url)? {
            ResolverScheme::Boot => self.boot.push(record),
            ResolverScheme::Pkg => self.pkg.push(record),
            ResolverScheme::Local => self.local.push(record),
        }
        Ok(())
    }

    /// Resolve one URL into the unified `ResolvedComponent` shape.
    pub fn resolve(&self, url: &str) -> Result<ResolvedComponent, ResolveError> {
        let bucket = match ResolverScheme::parse(url)? {
            ResolverScheme::Boot => &self.boot,
            ResolverScheme::Pkg => &self.pkg,
            ResolverScheme::Local => &self.local,
        };
        bucket
            .iter()
            .find(|record| record.url == url)
            .map(|record| record.resolved.clone())
            .ok_or(ResolveError::NotFound)
    }
}

#[derive(Clone, Copy)]
enum MessageKind {
    ComponentStartInfo,
    DirectoryOpenRequest,
    ControllerRequest,
    ControllerEvent,
}

impl MessageKind {
    fn encode(self) -> u8 {
        match self {
            Self::ComponentStartInfo => 1,
            Self::DirectoryOpenRequest => 2,
            Self::ControllerRequest => 3,
            Self::ControllerEvent => 4,
        }
    }
}

fn write_message_header(writer: &mut Writer, kind: MessageKind) {
    writer.write_magic(MESSAGE_MAGIC);
    writer.write_u16(WIRE_VERSION);
    writer.write_u8(kind.encode());
}

fn expect_message_header(reader: &mut Reader<'_>, kind: MessageKind) -> Result<(), CodecError> {
    reader.expect_magic(MESSAGE_MAGIC)?;
    let version = reader.read_u16()?;
    if version != WIRE_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }
    let actual = reader.read_u8()?;
    if actual != kind.encode() {
        return Err(CodecError::InvalidTag {
            field: "message_kind",
            value: actual,
        });
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn write_magic(&mut self, magic: &[u8; 4]) {
        self.bytes.extend_from_slice(magic);
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_bool(&mut self, value: bool) {
        self.write_u8(u8::from(value));
    }

    fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_string(&mut self, value: &str) {
        self.write_len(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn write_optional_string(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.write_bool(true);
                self.write_string(value);
            }
            None => self.write_bool(false),
        }
    }

    fn write_strings(&mut self, values: &[String]) {
        self.write_len(values.len());
        for value in values {
            self.write_string(value);
        }
    }

    fn write_vec<T>(&mut self, values: &[T], encode: fn(&T, &mut Writer)) {
        self.write_len(values.len());
        for value in values {
            encode(value, self);
        }
    }

    fn write_len(&mut self, len: usize) {
        self.write_u32(u32::try_from(len).expect("component wire length must fit in u32"));
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn finish(&self) -> Result<(), CodecError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }

    fn expect_magic(&mut self, magic: &[u8; 4]) -> Result<(), CodecError> {
        let bytes = self.read_exact(4)?;
        if bytes == magic {
            Ok(())
        } else {
            Err(CodecError::InvalidMagic)
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(CodecError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let bytes = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_bool(&mut self) -> Result<bool, CodecError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(CodecError::InvalidTag {
                field: "bool",
                value,
            }),
        }
    }

    fn read_u16(&mut self) -> Result<u16, CodecError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i64(&mut self) -> Result<i64, CodecError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(i64::from_le_bytes(bytes))
    }

    fn read_len(&mut self) -> Result<usize, CodecError> {
        usize::try_from(self.read_u32()?).map_err(|_| CodecError::LengthOverflow)
    }

    fn read_string(&mut self) -> Result<String, CodecError> {
        let len = self.read_len()?;
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::InvalidUtf8)
    }

    fn read_optional_string(&mut self) -> Result<Option<String>, CodecError> {
        if self.read_bool()? {
            Ok(Some(self.read_string()?))
        } else {
            Ok(None)
        }
    }

    fn read_strings(&mut self) -> Result<Vec<String>, CodecError> {
        self.read_vec(|reader| reader.read_string())
    }

    fn read_vec<T>(
        &mut self,
        decode: impl Fn(&mut Reader<'a>) -> Result<T, CodecError>,
    ) -> Result<Vec<T>, CodecError> {
        let len = self.read_len()?;
        let mut values = Vec::new();
        values
            .try_reserve(len)
            .map_err(|_| CodecError::LengthOverflow)?;
        for _ in 0..len {
            values.push(decode(self)?);
        }
        Ok(values)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn sample_decl() -> ComponentDecl {
        ComponentDecl {
            url: "boot://root".to_string(),
            program: ProgramDecl {
                runner: "elf".to_string(),
                binary: "bin/root".to_string(),
                args: alloc::vec!["--verbose".to_string()],
                env: alloc::vec!["RUST_LOG=debug".to_string()],
            },
            uses: alloc::vec![
                UseDecl {
                    kind: CapabilityKind::Protocol,
                    source_name: "nexus.logger.LogSink".to_string(),
                    target_path: Some("/svc/nexus.logger.LogSink".to_string()),
                },
                UseDecl {
                    kind: CapabilityKind::Runner,
                    source_name: "elf".to_string(),
                    target_path: None,
                },
            ],
            exposes: alloc::vec![ExposeDecl {
                kind: CapabilityKind::Protocol,
                source: ExposeSource::Self_,
                source_name: "nexus.echo.Echo".to_string(),
                target_name: "nexus.echo.Echo".to_string(),
            }],
            children: alloc::vec![ChildDecl {
                name: "echo".to_string(),
                url: "local://echo".to_string(),
                startup: StartupMode::Lazy,
            }],
            startup: StartupMode::Eager,
        }
    }

    #[test]
    fn component_decl_round_trips_binary_ir() {
        let decl = sample_decl();
        let bytes = decl.encode_binary();
        let decoded = ComponentDecl::decode_binary(&bytes).expect("decode decl");
        assert_eq!(decoded, decl);
    }

    #[test]
    fn start_info_round_trips_channel_message() {
        let start = ComponentStartInfo {
            args: alloc::vec!["/pkg/bin/echo".to_string(), "hello".to_string()],
            env: alloc::vec!["TERM=dumb".to_string()],
            namespace_entries: alloc::vec![
                NamespaceEntry {
                    path: "/svc/nexus.echo.Echo".to_string(),
                    handle: 11,
                },
                NamespaceEntry {
                    path: "/pkg".to_string(),
                    handle: 12,
                },
            ],
            numbered_handles: alloc::vec![NumberedHandle { id: 1, handle: 21 }],
            outgoing_dir_server_end: Some(31),
            controller_channel: Some(41),
        };
        let encoded = start.encode_channel_message();
        let decoded = ComponentStartInfo::decode_channel_message(&encoded.bytes, &encoded.handles)
            .expect("decode start info");
        assert_eq!(decoded, start);
    }

    #[test]
    fn resolver_table_routes_by_scheme() {
        let mut table = ResolverTable::new();
        let root = sample_decl();
        table
            .insert(ResolverRecord {
                url: root.url.clone(),
                resolved: ResolvedComponent {
                    decl: root.clone(),
                    package_dir: Some(7),
                    config_blob: None,
                },
            })
            .expect("insert boot");
        let local_decl = ComponentDecl {
            url: "local://echo".to_string(),
            ..sample_decl()
        };
        table
            .insert(ResolverRecord {
                url: local_decl.url.clone(),
                resolved: ResolvedComponent {
                    decl: local_decl.clone(),
                    package_dir: None,
                    config_blob: Some(13),
                },
            })
            .expect("insert local");

        let boot = table.resolve("boot://root").expect("resolve boot");
        let local = table.resolve("local://echo").expect("resolve local");
        assert_eq!(boot.decl.url, "boot://root");
        assert_eq!(boot.package_dir, Some(7));
        assert_eq!(local.decl.url, "local://echo");
        assert_eq!(local.config_blob, Some(13));
        assert_eq!(
            table.resolve("http://bad"),
            Err(ResolveError::UnsupportedScheme)
        );
    }

    #[test]
    fn directory_request_requires_one_handle() {
        let request = DirectoryOpenRequest {
            path: "svc/nexus.echo.Echo".to_string(),
            flags: 3,
            object: 9,
        };
        let encoded = request.encode_channel_message();
        let decoded =
            DirectoryOpenRequest::decode_channel_message(&encoded.bytes, &encoded.handles)
                .expect("decode request");
        assert_eq!(decoded, request);
    }
}

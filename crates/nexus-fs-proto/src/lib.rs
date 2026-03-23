#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Minimal filesystem service wire contract shared by clients and servers.
//!
//! Version one intentionally keeps the protocol surface small while carrying
//! the identity fields needed for later recovery and reconnect work:
//! - `session_id`
//! - `open_file_id`
//! - `node_id`
//! - `flags`

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use axle_types::{zx_handle_t, zx_status_t};

const MESSAGE_MAGIC: &[u8; 4] = b"NXFS";
const WIRE_VERSION: u16 = 1;

/// Errors returned while decoding or encoding Nexus FS wire data.
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

/// One encoded channel message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedMessage {
    /// Message bytes written into the channel payload.
    pub bytes: Vec<u8>,
    /// Handles transferred alongside the byte payload.
    pub handles: Vec<zx_handle_t>,
}

/// Stable identity carried by one remote object handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectIdentity {
    /// Session identifier for reconnect and recovery.
    pub session_id: u64,
    /// Open-file-description identifier.
    pub open_file_id: u64,
    /// Logical node identifier.
    pub node_id: u64,
}

impl ObjectIdentity {
    /// Build one identity triple.
    pub const fn new(session_id: u64, open_file_id: u64, node_id: u64) -> Self {
        Self {
            session_id,
            open_file_id,
            node_id,
        }
    }

    fn encode(self, writer: &mut Writer) {
        writer.write_u64(self.session_id);
        writer.write_u64(self.open_file_id);
        writer.write_u64(self.node_id);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            session_id: reader.read_u64()?,
            open_file_id: reader.read_u64()?,
            node_id: reader.read_u64()?,
        })
    }
}

/// Type of the opened remote node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// Regular file-like object.
    File,
    /// Directory object.
    Directory,
    /// Protocol/service endpoint carried over a channel.
    Service,
    /// Socket-like object.
    Socket,
    /// Pure pseudo node.
    Pseudo,
}

impl NodeKind {
    fn encode(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => 1,
            Self::Service => 2,
            Self::Socket => 3,
            Self::Pseudo => 4,
        }
    }

    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::File),
            1 => Ok(Self::Directory),
            2 => Ok(Self::Service),
            3 => Ok(Self::Socket),
            4 => Ok(Self::Pseudo),
            value => Err(CodecError::InvalidTag {
                field: "node_kind",
                value,
            }),
        }
    }
}

/// Description returned for one newly opened or cloned object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDescriptor {
    /// Stable object identity.
    pub identity: ObjectIdentity,
    /// Server-selected open flags for this description.
    pub flags: u32,
    /// Concrete node kind.
    pub kind: NodeKind,
}

impl NodeDescriptor {
    /// Build one node descriptor.
    pub const fn new(identity: ObjectIdentity, flags: u32, kind: NodeKind) -> Self {
        Self {
            identity,
            flags,
            kind,
        }
    }

    fn encode(self, writer: &mut Writer) {
        self.identity.encode(writer);
        writer.write_u32(self.flags);
        writer.write_u8(self.kind.encode());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            identity: ObjectIdentity::decode(reader)?,
            flags: reader.read_u32()?,
            kind: NodeKind::decode(reader.read_u8()?)?,
        })
    }
}

/// One directory entry returned by a remote directory listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntryRecord {
    /// Entry name relative to the listed directory.
    pub name: String,
    /// Concrete node kind for the entry.
    pub kind: NodeKind,
}

impl DirEntryRecord {
    /// Build one directory entry record.
    pub fn new(name: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }

    fn encode(&self, writer: &mut Writer) {
        writer.write_string(&self.name);
        writer.write_u8(self.kind.encode());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            name: reader.read_string()?,
            kind: NodeKind::decode(reader.read_u8()?)?,
        })
    }
}

/// Describe the object bound to a fresh channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescribeResponse {
    /// Completion status.
    pub status: zx_status_t,
    /// Descriptor for the opened node when `status == ZX_OK`.
    pub descriptor: NodeDescriptor,
}

impl DescribeResponse {
    /// Encode this response into one channel message with no handles.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::DescribeResponse);
        writer.write_i32(self.status);
        self.descriptor.encode(&mut writer);
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this response from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::DescribeResponse)?;
        let response = Self {
            status: reader.read_i32()?,
            descriptor: NodeDescriptor::decode(&mut reader)?,
        };
        reader.finish()?;
        Ok(response)
    }
}

/// Read directory entries from one remote directory object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadDirRequest {
    /// Identity of the directory being listed.
    pub object: ObjectIdentity,
    /// Request flags. Version one reserves this field.
    pub flags: u32,
}

impl ReadDirRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::ReadDirRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this request from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::ReadDirRequest)?;
        let request = Self {
            object: ObjectIdentity::decode(&mut reader)?,
            flags: reader.read_u32()?,
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Result of a remote directory listing call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadDirResponse {
    /// Completion status.
    pub status: zx_status_t,
    /// Directory entries returned by the server.
    pub entries: Vec<DirEntryRecord>,
}

impl ReadDirResponse {
    /// Encode this response into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::ReadDirResponse);
        writer.write_i32(self.status);
        writer.write_len(self.entries.len());
        for entry in &self.entries {
            entry.encode(&mut writer);
        }
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this response from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::ReadDirResponse)?;
        let status = reader.read_i32()?;
        let entry_count = reader.read_len()?;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(DirEntryRecord::decode(&mut reader)?);
        }
        reader.finish()?;
        Ok(Self { status, entries })
    }
}

/// Open one relative path beneath a directory handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    /// Directory handle identity used as the open anchor.
    pub object: ObjectIdentity,
    /// Open flags requested by the client.
    pub flags: u32,
    /// Relative path beneath the directory.
    pub path: String,
    /// Server end for the opened object channel.
    pub opened_object: zx_handle_t,
}

impl OpenRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::OpenRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        writer.write_string(&self.path);
        EncodedMessage {
            bytes: writer.finish(),
            handles: alloc::vec![self.opened_object],
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
        expect_message_header(&mut reader, FsMessageKind::OpenRequest)?;
        let request = Self {
            object: ObjectIdentity::decode(&mut reader)?,
            flags: reader.read_u32()?,
            path: reader.read_string()?,
            opened_object: handles[0],
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Clone one remote object into a fresh channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloneRequest {
    /// Identity of the object being cloned.
    pub object: ObjectIdentity,
    /// Requested open flags for the cloned description.
    pub flags: u32,
    /// Server end for the cloned object channel.
    pub cloned_object: zx_handle_t,
}

impl CloneRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::CloneRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        EncodedMessage {
            bytes: writer.finish(),
            handles: alloc::vec![self.cloned_object],
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
        expect_message_header(&mut reader, FsMessageKind::CloneRequest)?;
        let request = Self {
            object: ObjectIdentity::decode(&mut reader)?,
            flags: reader.read_u32()?,
            cloned_object: handles[0],
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Read bytes from one remote object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    /// Identity of the object being read.
    pub object: ObjectIdentity,
    /// Request flags. Version one reserves this field.
    pub flags: u32,
    /// Maximum number of bytes requested.
    pub max_bytes: u32,
}

impl ReadRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::ReadRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        writer.write_u32(self.max_bytes);
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this request from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::ReadRequest)?;
        let request = Self {
            object: ObjectIdentity::decode(&mut reader)?,
            flags: reader.read_u32()?,
            max_bytes: reader.read_u32()?,
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Result of a remote read call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResponse {
    /// Completion status.
    pub status: zx_status_t,
    /// Bytes returned by the server.
    pub bytes: Vec<u8>,
    /// Byte count carried by the bulk VMO path, when present.
    pub bulk_len: u32,
    /// Optional VMO handle carrying the bulk read payload.
    pub vmo: Option<zx_handle_t>,
}

impl ReadResponse {
    /// Build one inline-byte response.
    pub fn inline(status: zx_status_t, bytes: Vec<u8>) -> Self {
        Self {
            status,
            bytes,
            bulk_len: 0,
            vmo: None,
        }
    }

    /// Build one VMO-backed bulk response.
    pub fn bulk(status: zx_status_t, bulk_len: u32, vmo: zx_handle_t) -> Self {
        Self {
            status,
            bytes: Vec::new(),
            bulk_len,
            vmo: Some(vmo),
        }
    }

    /// Encode this response into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::ReadResponse);
        writer.write_i32(self.status);
        writer.write_u32(self.bulk_len);
        writer.write_bytes(&self.bytes);
        EncodedMessage {
            bytes: writer.finish(),
            handles: self.vmo.into_iter().collect(),
        }
    }

    /// Decode this response from one channel message.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, FsMessageKind::ReadResponse)?;
        let status = reader.read_i32()?;
        let bulk_len = reader.read_u32()?;
        let payload = reader.read_bytes()?;
        let expected_handles = usize::from(bulk_len != 0);
        if handles.len() != expected_handles {
            return Err(CodecError::HandleCountMismatch {
                expected: expected_handles,
                actual: handles.len(),
            });
        }
        if bulk_len != 0 && !payload.is_empty() {
            return Err(CodecError::TrailingBytes);
        }
        let response = Self {
            status,
            bytes: payload,
            bulk_len,
            vmo: handles.first().copied(),
        };
        reader.finish()?;
        Ok(response)
    }
}

/// Write bytes to one remote object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRequest {
    /// Identity of the object being written.
    pub object: ObjectIdentity,
    /// Request flags. Version one reserves this field.
    pub flags: u32,
    /// Bytes to write.
    pub bytes: Vec<u8>,
    /// Byte count carried by the bulk VMO path, when present.
    pub bulk_len: u32,
    /// Optional VMO handle carrying the bulk write payload.
    pub vmo: Option<zx_handle_t>,
}

impl WriteRequest {
    /// Build one inline-byte write request.
    pub fn inline(object: ObjectIdentity, flags: u32, bytes: Vec<u8>) -> Self {
        Self {
            object,
            flags,
            bytes,
            bulk_len: 0,
            vmo: None,
        }
    }

    /// Build one VMO-backed bulk write request.
    pub fn bulk(object: ObjectIdentity, flags: u32, bulk_len: u32, vmo: zx_handle_t) -> Self {
        Self {
            object,
            flags,
            bytes: Vec::new(),
            bulk_len,
            vmo: Some(vmo),
        }
    }

    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::WriteRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        writer.write_u32(self.bulk_len);
        writer.write_bytes(&self.bytes);
        EncodedMessage {
            bytes: writer.finish(),
            handles: self.vmo.into_iter().collect(),
        }
    }

    /// Decode this request from one channel message.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, FsMessageKind::WriteRequest)?;
        let object = ObjectIdentity::decode(&mut reader)?;
        let flags = reader.read_u32()?;
        let bulk_len = reader.read_u32()?;
        let bytes = reader.read_bytes()?;
        let expected_handles = usize::from(bulk_len != 0);
        if handles.len() != expected_handles {
            return Err(CodecError::HandleCountMismatch {
                expected: expected_handles,
                actual: handles.len(),
            });
        }
        if bulk_len != 0 && !bytes.is_empty() {
            return Err(CodecError::TrailingBytes);
        }
        let request = Self {
            object,
            flags,
            bytes,
            bulk_len,
            vmo: handles.first().copied(),
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Result of a remote write call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteResponse {
    /// Completion status.
    pub status: zx_status_t,
    /// Number of bytes accepted by the server.
    pub actual: u32,
}

impl WriteResponse {
    /// Encode this response into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::WriteResponse);
        writer.write_i32(self.status);
        writer.write_u32(self.actual);
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this response from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::WriteResponse)?;
        let response = Self {
            status: reader.read_i32()?,
            actual: reader.read_u32()?,
        };
        reader.finish()?;
        Ok(response)
    }
}

/// Close one remote open file description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseRequest {
    /// Identity of the object being closed.
    pub object: ObjectIdentity,
    /// Request flags. Version one reserves this field.
    pub flags: u32,
}

impl CloseRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::CloseRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this request from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::CloseRequest)?;
        let request = Self {
            object: ObjectIdentity::decode(&mut reader)?,
            flags: reader.read_u32()?,
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Request a read-only VMO backing handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetVmoRequest {
    /// Identity of the object being mapped.
    pub object: ObjectIdentity,
    /// Requested VMO flags.
    pub flags: u32,
}

impl GetVmoRequest {
    /// Encode this request into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        let mut writer = Writer::new();
        write_message_header(&mut writer, FsMessageKind::GetVmoRequest);
        self.object.encode(&mut writer);
        writer.write_u32(self.flags);
        EncodedMessage {
            bytes: writer.finish(),
            handles: Vec::new(),
        }
    }

    /// Decode this request from one channel message.
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
        expect_message_header(&mut reader, FsMessageKind::GetVmoRequest)?;
        let request = Self {
            object: ObjectIdentity::decode(&mut reader)?,
            flags: reader.read_u32()?,
        };
        reader.finish()?;
        Ok(request)
    }
}

/// Result of a `GetVmo` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetVmoResponse {
    /// Completion status.
    pub status: zx_status_t,
    /// Returned VMO handle when present.
    pub vmo: Option<zx_handle_t>,
}

impl GetVmoResponse {
    /// Encode this response into one channel message.
    pub fn encode_channel_message(&self) -> EncodedMessage {
        EncodedMessage {
            bytes: {
                let mut writer = Writer::new();
                write_message_header(&mut writer, FsMessageKind::GetVmoResponse);
                writer.write_i32(self.status);
                writer.write_bool(self.vmo.is_some());
                writer.finish()
            },
            handles: self.vmo.into_iter().collect(),
        }
    }

    /// Decode this response from one channel message.
    pub fn decode_channel_message(
        bytes: &[u8],
        handles: &[zx_handle_t],
    ) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        expect_message_header(&mut reader, FsMessageKind::GetVmoResponse)?;
        let status = reader.read_i32()?;
        let has_vmo = reader.read_bool()?;
        reader.finish()?;
        let vmo = match (has_vmo, handles) {
            (false, []) => None,
            (true, [handle]) => Some(*handle),
            (false, actual) => {
                return Err(CodecError::HandleCountMismatch {
                    expected: 0,
                    actual: actual.len(),
                });
            }
            (true, actual) => {
                return Err(CodecError::HandleCountMismatch {
                    expected: 1,
                    actual: actual.len(),
                });
            }
        };
        Ok(Self { status, vmo })
    }
}

/// Kind tag stored in the FS wire header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsMessageKind {
    /// `DescribeResponse`
    DescribeResponse,
    /// `ReadDirRequest`
    ReadDirRequest,
    /// `ReadDirResponse`
    ReadDirResponse,
    /// `OpenRequest`
    OpenRequest,
    /// `CloneRequest`
    CloneRequest,
    /// `ReadRequest`
    ReadRequest,
    /// `ReadResponse`
    ReadResponse,
    /// `WriteRequest`
    WriteRequest,
    /// `WriteResponse`
    WriteResponse,
    /// `CloseRequest`
    CloseRequest,
    /// `GetVmoRequest`
    GetVmoRequest,
    /// `GetVmoResponse`
    GetVmoResponse,
}

impl FsMessageKind {
    fn encode(self) -> u8 {
        match self {
            Self::DescribeResponse => 1,
            Self::ReadDirRequest => 2,
            Self::ReadDirResponse => 3,
            Self::OpenRequest => 4,
            Self::CloneRequest => 5,
            Self::ReadRequest => 6,
            Self::ReadResponse => 7,
            Self::WriteRequest => 8,
            Self::WriteResponse => 9,
            Self::CloseRequest => 10,
            Self::GetVmoRequest => 11,
            Self::GetVmoResponse => 12,
        }
    }

    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::DescribeResponse),
            2 => Ok(Self::ReadDirRequest),
            3 => Ok(Self::ReadDirResponse),
            4 => Ok(Self::OpenRequest),
            5 => Ok(Self::CloneRequest),
            6 => Ok(Self::ReadRequest),
            7 => Ok(Self::ReadResponse),
            8 => Ok(Self::WriteRequest),
            9 => Ok(Self::WriteResponse),
            10 => Ok(Self::CloseRequest),
            11 => Ok(Self::GetVmoRequest),
            12 => Ok(Self::GetVmoResponse),
            value => Err(CodecError::InvalidTag {
                field: "message_kind",
                value,
            }),
        }
    }
}

fn write_message_header(writer: &mut Writer, kind: FsMessageKind) {
    writer.write_magic(MESSAGE_MAGIC);
    writer.write_u16(WIRE_VERSION);
    writer.write_u8(kind.encode());
}

fn expect_message_header(reader: &mut Reader<'_>, kind: FsMessageKind) -> Result<(), CodecError> {
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

/// Decode only the message kind from one FS wire payload.
pub fn decode_message_kind(bytes: &[u8]) -> Result<FsMessageKind, CodecError> {
    let mut reader = Reader::new(bytes);
    reader.expect_magic(MESSAGE_MAGIC)?;
    let version = reader.read_u16()?;
    if version != WIRE_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }
    FsMessageKind::decode(reader.read_u8()?)
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

    fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_len(&mut self, len: usize) {
        self.write_u32(u32::try_from(len).expect("fs wire length must fit in u32"));
    }

    fn write_string(&mut self, value: &str) {
        self.write_len(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn write_bytes(&mut self, value: &[u8]) {
        self.write_len(value.len());
        self.bytes.extend_from_slice(value);
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

    fn read_u64(&mut self) -> Result<u64, CodecError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_i32(&mut self) -> Result<i32, CodecError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_len(&mut self) -> Result<usize, CodecError> {
        usize::try_from(self.read_u32()?).map_err(|_| CodecError::LengthOverflow)
    }

    fn read_string(&mut self) -> Result<String, CodecError> {
        let len = self.read_len()?;
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::InvalidUtf8)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.read_len()?;
        let bytes = self.read_exact(len)?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn open_request_round_trips() {
        let request = OpenRequest {
            object: ObjectIdentity::new(7, 11, 13),
            flags: 0x55,
            path: "svc/echo".to_string(),
            opened_object: 99,
        };
        let encoded = request.encode_channel_message();
        let decoded =
            OpenRequest::decode_channel_message(&encoded.bytes, &encoded.handles).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn describe_response_round_trips() {
        let response = DescribeResponse {
            status: 0,
            descriptor: NodeDescriptor::new(ObjectIdentity::new(1, 2, 3), 0x40, NodeKind::Service),
        };
        let encoded = response.encode_channel_message();
        let decoded = DescribeResponse::decode_channel_message(&encoded.bytes, &encoded.handles)
            .expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn read_and_write_messages_round_trip() {
        let read = ReadRequest {
            object: ObjectIdentity::new(9, 8, 7),
            flags: 0,
            max_bytes: 128,
        };
        let read_encoded = read.encode_channel_message();
        assert_eq!(
            ReadRequest::decode_channel_message(&read_encoded.bytes, &read_encoded.handles)
                .expect("decode read"),
            read
        );

        let write = WriteRequest::inline(ObjectIdentity::new(5, 4, 3), 1, alloc::vec![1, 2, 3, 4]);
        let write_encoded = write.encode_channel_message();
        assert_eq!(
            WriteRequest::decode_channel_message(&write_encoded.bytes, &write_encoded.handles)
                .expect("decode write"),
            write
        );
    }

    #[test]
    fn bulk_read_and_write_messages_round_trip() {
        let read = ReadResponse::bulk(0, 8192, 77);
        let read_encoded = read.encode_channel_message();
        assert_eq!(
            ReadResponse::decode_channel_message(&read_encoded.bytes, &read_encoded.handles)
                .expect("decode bulk read"),
            read
        );

        let write = WriteRequest::bulk(ObjectIdentity::new(5, 4, 3), 0, 4096, 66);
        let write_encoded = write.encode_channel_message();
        assert_eq!(
            WriteRequest::decode_channel_message(&write_encoded.bytes, &write_encoded.handles)
                .expect("decode bulk write"),
            write
        );
    }

    #[test]
    fn get_vmo_response_tracks_optional_handle() {
        let with_handle = GetVmoResponse {
            status: 0,
            vmo: Some(42),
        };
        let encoded = with_handle.encode_channel_message();
        let decoded =
            GetVmoResponse::decode_channel_message(&encoded.bytes, &encoded.handles).expect("ok");
        assert_eq!(decoded, with_handle);

        let without_handle = GetVmoResponse {
            status: -2,
            vmo: None,
        };
        let encoded = without_handle.encode_channel_message();
        let decoded =
            GetVmoResponse::decode_channel_message(&encoded.bytes, &encoded.handles).expect("ok");
        assert_eq!(decoded, without_handle);
    }

    #[test]
    fn readdir_messages_round_trip() {
        let request = ReadDirRequest {
            object: ObjectIdentity::new(11, 22, 33),
            flags: 7,
        };
        let encoded = request.encode_channel_message();
        let decoded =
            ReadDirRequest::decode_channel_message(&encoded.bytes, &encoded.handles).expect("ok");
        assert_eq!(decoded, request);

        let response = ReadDirResponse {
            status: 0,
            entries: alloc::vec![
                DirEntryRecord::new("manifests", NodeKind::Directory),
                DirEntryRecord::new("root.nxcd", NodeKind::File),
            ],
        };
        let encoded = response.encode_channel_message();
        let decoded =
            ReadDirResponse::decode_channel_message(&encoded.bytes, &encoded.handles).expect("ok");
        assert_eq!(decoded, response);
    }
}

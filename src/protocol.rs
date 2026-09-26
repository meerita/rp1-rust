//! Low-level RP-1 protocol wire types and codec.
//!
//! This module owns the `rp1-spec` `v0.6.0` framing and codec contract for
//! the request lifetime subset: the validated header and metadata types,
//! the handshake payload types, the failure classification including the
//! deadline exceeded and cancelled classes, the withdrawal frame, the
//! incremental decoder, and the encoder.
//!
//! It does not own transport, connection policy, request state, or any client
//! API. `decode` and `encode` are pure functions over byte slices and
//! validated values.

/// The public specification revision this module implements.
pub const SPEC_REVISION: &str = "v0.6.0";

/// The fixed length of the frame header in bytes.
pub const HEADER_LENGTH: usize = 20;

/// The maximum total length of a frame in bytes before negotiation.
pub const MAX_FRAME_SIZE: u64 = 65_536;

/// The maximum length of the metadata region in bytes before negotiation.
pub const MAX_METADATA_SIZE: u16 = 4_096;

/// The opcode protocol version 0 assigns to the handshake.
pub const HANDSHAKE_OPCODE: u16 = 0x0001;

/// The opcode protocol version 0 assigns to the liveness operation.
pub const PING_OPCODE: u16 = 0x0002;

/// The opcode protocol version 0 assigns to the value read.
pub const GET_OPCODE: u16 = 0x0003;

/// The opcode protocol version 0 assigns to the byte write.
pub const SET_OPCODE: u16 = 0x0004;

/// The opcode protocol version 0 assigns to the key delete.
pub const DEL_OPCODE: u16 = 0x0005;

/// The opcode protocol version 0 assigns to the presence read.
pub const EXISTS_OPCODE: u16 = 0x0006;

/// The lowest value a responder may state as the negotiated maximum frame
/// size.
pub const MINIMUM_NEGOTIATED_FRAME_SIZE: u64 = 65_536;

/// The lowest value a responder may state as the negotiated maximum metadata
/// size.
pub const MINIMUM_NEGOTIATED_METADATA_SIZE: u16 = 4_096;

/// The highest value the one-byte header `version` field can carry.
const HIGHEST_HEADER_VERSION: u16 = 255;

/// The capability identifier that gates the withdrawal frame kind and the
/// cancelled error class.
pub const CANCELLATION_CAPABILITY_ID: u16 = 0x0002;

/// The capability identifier that gates the deadline metadata entry and the
/// deadline exceeded error class.
pub const DEADLINES_CAPABILITY_ID: u16 = 0x0004;

/// The metadata identifier of the optional deadline entry, carrying a
/// little-endian `u32` count of microseconds.
pub const DEADLINE_METADATA_ID: u16 = 0x0001;

/// The state a connection occupies when it reads a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// The transport is connected and the handshake is not complete.
    PreNegotiation,
    /// The handshake response has been read.
    Negotiated,
    /// The transport closed or the connection became unusable.
    Terminal,
}

/// The size bounds in force when a receiver reads a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The maximum total length of a frame in bytes.
    pub frame_size: u64,
    /// The maximum length of the metadata region in bytes.
    pub metadata_size: u16,
}

impl Limits {
    /// The constants in force before the handshake completes.
    pub const PRE_NEGOTIATION: Self = Self {
        frame_size: MAX_FRAME_SIZE,
        metadata_size: MAX_METADATA_SIZE,
    };
}

/// The connection context a receiver decodes a frame under.
#[derive(Debug, Clone, Copy)]
pub struct Admission<'a> {
    /// The peer that is decoding.
    pub role: Role,
    /// The connection state the receiver occupies.
    pub state: ConnectionState,
    /// The size bounds in force.
    pub limits: Limits,
    /// The request ids in flight at the receiver.
    pub in_flight: &'a [u64],
    /// The capability identifiers in the accepted set of the connection.
    ///
    /// Capability-gated wire behavior is admitted only when the accepted
    /// set names its capability: the withdrawal frame needs cancellation,
    /// and the deadline exceeded and cancelled classes need deadlines and
    /// cancellation respectively. An empty set admits none of them.
    pub capabilities: &'a [u16],
}

impl Default for Admission<'_> {
    fn default() -> Self {
        Self {
            role: Role::Server,
            state: ConnectionState::Negotiated,
            limits: Limits::PRE_NEGOTIATION,
            in_flight: &[],
            capabilities: &[],
        }
    }
}

/// The peer that is decoding a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The client peer.
    Client,
    /// The server peer.
    Server,
}

/// The protocol version field of a frame header.
///
/// Only `0` is valid at this revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version(u8);

impl Version {
    /// Returns the wire value of the field.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Returns whether this version is assigned by this revision.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 == 0
    }
}

/// The kind of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A request opened by the client.
    Request,
    /// A response sent by the server.
    Response,
    /// An error sent by the server.
    Error,
    /// A withdrawal sent by the client, gated by the cancellation
    /// capability. It names the request to withdraw, carries an empty
    /// payload and an empty metadata region, and produces no frame of its
    /// own.
    Withdrawal,
}

impl Kind {
    /// Returns the wire value of the field.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Error => 3,
            Self::Withdrawal => 7,
        }
    }

    /// Returns the peer that sends this kind.
    #[must_use]
    pub const fn sender(self) -> Role {
        match self {
            Self::Request | Self::Withdrawal => Role::Client,
            Self::Response | Self::Error => Role::Server,
        }
    }

    /// Returns the assigned kind for a wire value, or `None` when unassigned.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Error),
            7 => Some(Self::Withdrawal),
            _ => None,
        }
    }

    /// Returns whether a frame of this kind names a request for a failure of
    /// `scope`.
    #[must_use]
    pub const fn names_a_request_for_scope(self, scope: FailureScope) -> bool {
        match self {
            Self::Request | Self::Response | Self::Withdrawal => true,
            Self::Error => matches!(scope, FailureScope::RequestScoped),
        }
    }
}

/// The reserved flags field of a frame header.
///
/// Every bit is reserved at this revision and must be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    /// Returns the wire value of the field.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Returns whether every reserved bit is clear.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// The request identity field of a frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(u64);

impl RequestId {
    /// Returns the wire value of the field.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns whether this is the reserved request id, which names no request.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        self.0 == 0
    }
}

/// The opcode field of a request frame.
///
/// The six values this revision assigns are the handshake and the five
/// ungated operations. Every other value is unassigned and answered with
/// the unsupported operation class for that request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode(u16);

impl Opcode {
    /// Returns the wire value of the field.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Returns whether the opcode is assigned by this revision.
    #[must_use]
    pub const fn is_assigned(value: u16) -> bool {
        matches!(
            value,
            HANDSHAKE_OPCODE | PING_OPCODE | GET_OPCODE | SET_OPCODE | DEL_OPCODE | EXISTS_OPCODE
        )
    }
}

/// The result code field of a response frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    /// The operation ran and produced its answer.
    Success,
    /// The key the request named does not exist.
    Absent,
    /// The key holds a value the responder keeps outside memory.
    ValueHeldOutsideMemory,
}

impl ResultCode {
    /// Returns the wire value of the code.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::Success => 0x0000,
            Self::Absent => 0x0001,
            Self::ValueHeldOutsideMemory => 0x0004,
        }
    }

    /// Returns the assigned result code for a wire value, or `None` when
    /// unassigned.
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Success),
            0x0001 => Some(Self::Absent),
            0x0004 => Some(Self::ValueHeldOutsideMemory),
            _ => None,
        }
    }
}

/// The error class field of an error frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// The receiver could not parse the frame.
    MalformedRequest,
    /// The frame names a protocol version the receiver does not implement.
    UnsupportedProtocolVersion,
    /// The receiver does not serve the named operation.
    UnsupportedOperation,
    /// The receiver parsed the request and rejects a value it carries.
    InvalidArgument,
    /// A frame exceeds the maximum frame size in force.
    ResourceLimit,
    /// The request carried a deadline whose duration had passed before the
    /// responder began the work it names. Gated by the deadlines
    /// capability; without it this class is treated as unassigned.
    DeadlineExceeded,
    /// The request was withdrawn before it committed. Gated by the
    /// cancellation capability; without it this class is treated as
    /// unassigned.
    Cancelled,
    /// The receiver could not admit the resources the request needs.
    Overloaded,
    /// The receiver met a condition it did not anticipate.
    InternalError,
    /// The frame breaks the contract so that what follows cannot be trusted.
    ProtocolViolation,
    /// The request names a key held in a representation the operation does
    /// not act on.
    WrongType,
}

impl ErrorClass {
    /// Returns the wire value of the class.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::MalformedRequest => 0x0001,
            Self::UnsupportedProtocolVersion => 0x0002,
            Self::UnsupportedOperation => 0x0003,
            Self::InvalidArgument => 0x0004,
            Self::ResourceLimit => 0x0005,
            Self::DeadlineExceeded => 0x0006,
            Self::Cancelled => 0x0007,
            Self::Overloaded => 0x0008,
            Self::InternalError => 0x000B,
            Self::ProtocolViolation => 0x000C,
            Self::WrongType => 0x000E,
        }
    }

    /// Returns the failure scope the class carries.
    #[must_use]
    pub const fn scope(self) -> FailureScope {
        match self {
            Self::MalformedRequest
            | Self::UnsupportedProtocolVersion
            | Self::ResourceLimit
            | Self::ProtocolViolation => FailureScope::ConnectionFatal,
            Self::UnsupportedOperation
            | Self::InvalidArgument
            | Self::DeadlineExceeded
            | Self::Cancelled
            | Self::Overloaded
            | Self::InternalError
            | Self::WrongType => FailureScope::RequestScoped,
        }
    }

    /// Returns the name of the class as the failure registry states it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed request",
            Self::UnsupportedProtocolVersion => "unsupported protocol version",
            Self::UnsupportedOperation => "unsupported operation",
            Self::InvalidArgument => "invalid argument",
            Self::ResourceLimit => "resource limit",
            Self::DeadlineExceeded => "deadline exceeded",
            Self::Cancelled => "cancelled",
            Self::Overloaded => "overloaded",
            Self::InternalError => "internal error",
            Self::ProtocolViolation => "protocol violation",
            Self::WrongType => "wrong type",
        }
    }

    /// Returns the assigned class for a wire value, or `None` when unassigned.
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::MalformedRequest),
            0x0002 => Some(Self::UnsupportedProtocolVersion),
            0x0003 => Some(Self::UnsupportedOperation),
            0x0004 => Some(Self::InvalidArgument),
            0x0005 => Some(Self::ResourceLimit),
            0x0006 => Some(Self::DeadlineExceeded),
            0x0007 => Some(Self::Cancelled),
            0x0008 => Some(Self::Overloaded),
            0x000B => Some(Self::InternalError),
            0x000C => Some(Self::ProtocolViolation),
            0x000E => Some(Self::WrongType),
            _ => None,
        }
    }
}

/// The scope of a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureScope {
    /// The request fails and the connection keeps serving.
    RequestScoped,
    /// This frame retires no request and the connection becomes unusable.
    ConnectionFatal,
}

impl FailureScope {
    /// Returns the name of the scope as the fixture corpus states it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RequestScoped => "request-scoped",
            Self::ConnectionFatal => "connection-fatal",
        }
    }
}

/// A classified protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    class: ErrorClass,
    scope: FailureScope,
}

impl Failure {
    /// Builds a failure from a class and a scope.
    #[must_use]
    pub const fn new(class: ErrorClass, scope: FailureScope) -> Self {
        Self { class, scope }
    }

    /// Builds the malformed request failure.
    #[must_use]
    pub const fn malformed_request() -> Self {
        Self::new(ErrorClass::MalformedRequest, FailureScope::ConnectionFatal)
    }

    /// Builds the unsupported protocol version failure.
    #[must_use]
    pub const fn unsupported_protocol_version() -> Self {
        Self::new(
            ErrorClass::UnsupportedProtocolVersion,
            FailureScope::ConnectionFatal,
        )
    }

    /// Builds the unsupported operation failure.
    #[must_use]
    pub const fn unsupported_operation() -> Self {
        Self::new(
            ErrorClass::UnsupportedOperation,
            FailureScope::RequestScoped,
        )
    }

    /// Builds the invalid argument failure.
    #[must_use]
    pub const fn invalid_argument() -> Self {
        Self::new(ErrorClass::InvalidArgument, FailureScope::RequestScoped)
    }

    /// Builds the resource limit failure.
    #[must_use]
    pub const fn resource_limit() -> Self {
        Self::new(ErrorClass::ResourceLimit, FailureScope::ConnectionFatal)
    }

    /// Builds the protocol violation failure.
    #[must_use]
    pub const fn protocol_violation() -> Self {
        Self::new(ErrorClass::ProtocolViolation, FailureScope::ConnectionFatal)
    }

    /// Returns the error class of the failure.
    #[must_use]
    pub const fn class(self) -> ErrorClass {
        self.class
    }

    /// Returns the scope of the failure.
    #[must_use]
    pub const fn scope(self) -> FailureScope {
        self.scope
    }
}

/// One entry of the metadata region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataEntry<'a> {
    identifier: u16,
    value: &'a [u8],
}

impl<'a> MetadataEntry<'a> {
    /// Builds an entry from its identifier and opaque value bytes.
    #[must_use]
    pub const fn new(identifier: u16, value: &'a [u8]) -> Self {
        Self { identifier, value }
    }

    /// Returns the entry identifier.
    #[must_use]
    pub const fn identifier(self) -> u16 {
        self.identifier
    }

    /// Returns the opaque value bytes.
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }

    /// Returns whether the identifier lies in the required range.
    #[must_use]
    pub const fn is_required(self) -> bool {
        self.identifier & 0x8000 != 0
    }
}

/// The metadata region of a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataRegion<'a> {
    entries: Vec<MetadataEntry<'a>>,
}

impl<'a> MetadataRegion<'a> {
    /// Returns the entries in wire order.
    #[must_use]
    pub fn entries(&self) -> &[MetadataEntry<'a>] {
        &self.entries
    }

    /// Parses a region whose entries must fill it exactly.
    fn parse(region: &'a [u8]) -> Option<Self> {
        let mut entries = Vec::new();
        let mut rest = region;
        while !rest.is_empty() {
            let identifier = read_u16_le(rest, 0)?;
            let value_length = read_u16_le(rest, 2)?;
            let entry_length = 4usize.checked_add(usize::from(value_length))?;
            if entry_length > rest.len() {
                return None;
            }
            let value = rest.get(4..entry_length)?;
            entries.push(MetadataEntry::new(identifier, value));
            rest = rest.get(entry_length..)?;
        }
        Some(Self { entries })
    }
}

/// One entry of a handshake capability region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityEntry<'a> {
    identifier: u16,
    value: &'a [u8],
}

impl<'a> CapabilityEntry<'a> {
    /// Builds an entry from its identifier and opaque value bytes.
    #[must_use]
    pub const fn new(identifier: u16, value: &'a [u8]) -> Self {
        Self { identifier, value }
    }

    /// Returns the entry identifier.
    #[must_use]
    pub const fn identifier(self) -> u16 {
        self.identifier
    }

    /// Returns the opaque value bytes.
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// A validated region of handshake capability entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEntries<'a> {
    entries: Vec<CapabilityEntry<'a>>,
}

impl<'a> CapabilityEntries<'a> {
    /// Builds a region from entries in wire order.
    #[must_use]
    pub const fn new(entries: Vec<CapabilityEntry<'a>>) -> Self {
        Self { entries }
    }

    /// Returns the entries in wire order.
    #[must_use]
    pub fn entries(&self) -> &[CapabilityEntry<'a>] {
        &self.entries
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Parses a region whose entries must fill it exactly.
    fn parse(region: &'a [u8]) -> Option<Self> {
        let mut entries = Vec::new();
        let mut rest = region;
        while !rest.is_empty() {
            let identifier = read_u16_le(rest, 0)?;
            let value_length = read_u16_le(rest, 2)?;
            let entry_length = 4usize.checked_add(usize::from(value_length))?;
            if entry_length > rest.len() {
                return None;
            }
            let value = rest.get(4..entry_length)?;
            entries.push(CapabilityEntry::new(identifier, value));
            rest = rest.get(entry_length..)?;
        }
        Some(Self { entries })
    }

    /// Checks that the identifiers strictly ascend.
    fn check_ascending(&self) -> Result<(), Failure> {
        let mut previous: Option<u16> = None;
        for entry in &self.entries {
            if let Some(previous_identifier) = previous {
                if entry.identifier <= previous_identifier {
                    return Err(Failure::malformed_request());
                }
            }
            previous = Some(entry.identifier);
        }
        Ok(())
    }
}

/// The versions and capabilities an offerer proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeOffer<'a> {
    /// The lowest protocol version the offerer accepts.
    pub minimum_protocol_version: u16,
    /// The highest protocol version the offerer accepts.
    pub maximum_protocol_version: u16,
    /// The capability identifiers the offerer offered.
    pub capability_ids: &'a [u16],
}

impl HandshakeOffer<'_> {
    /// Returns whether `version` lies inside the offered range.
    #[must_use]
    pub const fn contains_version(&self, version: u16) -> bool {
        version >= self.minimum_protocol_version && version <= self.maximum_protocol_version
    }

    /// Returns whether the offerer offered `identifier`.
    #[must_use]
    pub fn offers_capability(&self, identifier: u16) -> bool {
        self.capability_ids.contains(&identifier)
    }
}

/// The validated handshake request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest<'a> {
    client_maximum_protocol_version: u16,
    client_minimum_protocol_version: u16,
    client_desired_maximum_frame_size: u32,
    capability_count: u16,
    capability_entries: CapabilityEntries<'a>,
}

impl<'a> HandshakeRequest<'a> {
    /// The fixed length of the request head in bytes.
    pub const HEAD_LENGTH: usize = 10;

    /// Builds a handshake request from its parts.
    #[must_use]
    pub fn new(
        client_maximum_protocol_version: u16,
        client_minimum_protocol_version: u16,
        client_desired_maximum_frame_size: u32,
        capability_entries: CapabilityEntries<'a>,
    ) -> Self {
        let capability_count = u16::try_from(capability_entries.count()).unwrap_or(u16::MAX);
        Self {
            client_maximum_protocol_version,
            client_minimum_protocol_version,
            client_desired_maximum_frame_size,
            capability_count,
            capability_entries,
        }
    }

    /// Decodes and validates a handshake request payload as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns a connection-fatal malformed request failure when the payload
    /// is shorter than its head, its version range maximum is below its
    /// minimum, its entries do not fill the payload exactly, its entries are
    /// not strictly ascending, or its declared count disagrees with the
    /// entries.
    pub fn decode(payload: &'a [u8]) -> Result<Self, Failure> {
        if payload.len() < Self::HEAD_LENGTH {
            return Err(Failure::malformed_request());
        }
        let client_maximum_protocol_version =
            read_u16_le(payload, 0).ok_or_else(Failure::malformed_request)?;
        let client_minimum_protocol_version =
            read_u16_le(payload, 2).ok_or_else(Failure::malformed_request)?;
        let client_desired_maximum_frame_size =
            read_u32_le(payload, 4).ok_or_else(Failure::malformed_request)?;
        let capability_count = read_u16_le(payload, 8).ok_or_else(Failure::malformed_request)?;
        if client_maximum_protocol_version < client_minimum_protocol_version {
            return Err(Failure::malformed_request());
        }
        let tail = payload
            .get(Self::HEAD_LENGTH..)
            .ok_or_else(Failure::malformed_request)?;
        let capability_entries =
            CapabilityEntries::parse(tail).ok_or_else(Failure::malformed_request)?;
        capability_entries.check_ascending()?;
        if usize::from(capability_count) != capability_entries.count() {
            return Err(Failure::malformed_request());
        }
        Ok(Self {
            client_maximum_protocol_version,
            client_minimum_protocol_version,
            client_desired_maximum_frame_size,
            capability_count,
            capability_entries,
        })
    }

    /// Encodes the request, deriving the capability count from the entries.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.client_maximum_protocol_version.to_le_bytes());
        out.extend_from_slice(&self.client_minimum_protocol_version.to_le_bytes());
        out.extend_from_slice(&self.client_desired_maximum_frame_size.to_le_bytes());
        let count = u16::try_from(self.capability_entries.count()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for entry in self.capability_entries.entries() {
            out.extend_from_slice(&entry.identifier().to_le_bytes());
            let value_length = u16::try_from(entry.value().len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&value_length.to_le_bytes());
            out.extend_from_slice(entry.value());
        }
        out
    }

    /// Returns the highest proposed version, which is also the version the
    /// offerer accepts as an upper bound.
    #[must_use]
    pub const fn client_maximum_protocol_version(&self) -> u16 {
        self.client_maximum_protocol_version
    }

    /// Returns the lowest proposed version.
    #[must_use]
    pub const fn client_minimum_protocol_version(&self) -> u16 {
        self.client_minimum_protocol_version
    }

    /// Returns the desired maximum frame size.
    #[must_use]
    pub const fn client_desired_maximum_frame_size(&self) -> u32 {
        self.client_desired_maximum_frame_size
    }

    /// Returns the declared capability count.
    #[must_use]
    pub const fn capability_count(&self) -> u16 {
        self.capability_count
    }

    /// Returns the capability entries.
    #[must_use]
    pub const fn capability_entries(&self) -> &CapabilityEntries<'a> {
        &self.capability_entries
    }

    /// Returns the highest version this request names that `supported` also
    /// supports, or `None` when the two sets do not intersect.
    #[must_use]
    pub fn highest_mutual_version(&self, supported: &[u16]) -> Option<u16> {
        supported
            .iter()
            .copied()
            .filter(|version| {
                *version >= self.client_minimum_protocol_version
                    && *version <= self.client_maximum_protocol_version
            })
            .max()
    }
}

/// The validated handshake response payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse<'a> {
    negotiated_protocol_version: u16,
    negotiated_maximum_frame_size: u32,
    negotiated_maximum_metadata_size: u16,
    accepted_capability_count: u16,
    accepted_capability_entries: CapabilityEntries<'a>,
}

impl<'a> HandshakeResponse<'a> {
    /// The fixed length of the response head in bytes.
    pub const HEAD_LENGTH: usize = 10;

    /// Builds a handshake response from its parts, deriving the accepted
    /// count from the entries.
    #[must_use]
    pub fn new(
        negotiated_protocol_version: u16,
        negotiated_maximum_frame_size: u32,
        negotiated_maximum_metadata_size: u16,
        accepted_capability_entries: CapabilityEntries<'a>,
    ) -> Self {
        let accepted_capability_count =
            u16::try_from(accepted_capability_entries.count()).unwrap_or(u16::MAX);
        Self {
            negotiated_protocol_version,
            negotiated_maximum_frame_size,
            negotiated_maximum_metadata_size,
            accepted_capability_count,
            accepted_capability_entries,
        }
    }

    /// Decodes and validates a handshake response payload against the offer
    /// it answers, as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns a connection-fatal malformed request failure when the payload
    /// is shorter than its head, its entries do not fill the payload exactly,
    /// its entries are not strictly ascending, its declared count disagrees
    /// with the entries, the negotiated version lies outside the offered
    /// range or above the header width, or a negotiated bound lies below its
    /// floor. Returns a connection-fatal protocol violation when an accepted
    /// entry names a capability the offer did not offer.
    pub fn decode(payload: &'a [u8], offer: &HandshakeOffer<'_>) -> Result<Self, Failure> {
        if payload.len() < Self::HEAD_LENGTH {
            return Err(Failure::malformed_request());
        }
        let negotiated_protocol_version =
            read_u16_le(payload, 0).ok_or_else(Failure::malformed_request)?;
        let negotiated_maximum_frame_size =
            read_u32_le(payload, 2).ok_or_else(Failure::malformed_request)?;
        let negotiated_maximum_metadata_size =
            read_u16_le(payload, 6).ok_or_else(Failure::malformed_request)?;
        let accepted_capability_count =
            read_u16_le(payload, 8).ok_or_else(Failure::malformed_request)?;
        let tail = payload
            .get(Self::HEAD_LENGTH..)
            .ok_or_else(Failure::malformed_request)?;
        let accepted_capability_entries =
            CapabilityEntries::parse(tail).ok_or_else(Failure::malformed_request)?;
        accepted_capability_entries.check_ascending()?;
        if usize::from(accepted_capability_count) != accepted_capability_entries.count() {
            return Err(Failure::malformed_request());
        }
        if negotiated_protocol_version > HIGHEST_HEADER_VERSION {
            return Err(Failure::malformed_request());
        }
        if !offer.contains_version(negotiated_protocol_version) {
            return Err(Failure::malformed_request());
        }
        if u64::from(negotiated_maximum_frame_size) < MINIMUM_NEGOTIATED_FRAME_SIZE {
            return Err(Failure::malformed_request());
        }
        if negotiated_maximum_metadata_size < MINIMUM_NEGOTIATED_METADATA_SIZE {
            return Err(Failure::malformed_request());
        }
        for entry in accepted_capability_entries.entries() {
            if !offer.offers_capability(entry.identifier()) {
                return Err(Failure::protocol_violation());
            }
        }
        Ok(Self {
            negotiated_protocol_version,
            negotiated_maximum_frame_size,
            negotiated_maximum_metadata_size,
            accepted_capability_count,
            accepted_capability_entries,
        })
    }

    /// Encodes the response, deriving the accepted count from the entries.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.negotiated_protocol_version.to_le_bytes());
        out.extend_from_slice(&self.negotiated_maximum_frame_size.to_le_bytes());
        out.extend_from_slice(&self.negotiated_maximum_metadata_size.to_le_bytes());
        let count = u16::try_from(self.accepted_capability_entries.count()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for entry in self.accepted_capability_entries.entries() {
            out.extend_from_slice(&entry.identifier().to_le_bytes());
            let value_length = u16::try_from(entry.value().len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&value_length.to_le_bytes());
            out.extend_from_slice(entry.value());
        }
        out
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub const fn negotiated_protocol_version(&self) -> u16 {
        self.negotiated_protocol_version
    }

    /// Returns the negotiated maximum frame size.
    #[must_use]
    pub const fn negotiated_maximum_frame_size(&self) -> u32 {
        self.negotiated_maximum_frame_size
    }

    /// Returns the negotiated maximum metadata size.
    #[must_use]
    pub const fn negotiated_maximum_metadata_size(&self) -> u16 {
        self.negotiated_maximum_metadata_size
    }

    /// Returns the declared accepted capability count.
    #[must_use]
    pub const fn accepted_capability_count(&self) -> u16 {
        self.accepted_capability_count
    }

    /// Returns the accepted capability entries.
    #[must_use]
    pub const fn accepted_capability_entries(&self) -> &CapabilityEntries<'a> {
        &self.accepted_capability_entries
    }

    /// Returns the size bounds the response puts in force.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        Limits {
            frame_size: self.negotiated_maximum_frame_size as u64,
            metadata_size: self.negotiated_maximum_metadata_size,
        }
    }
}

/// The payload of an admitted frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    /// Opaque bytes whose layout a result or operation defines.
    Opaque(&'a [u8]),
    /// A value held outside memory, carrying its logical length.
    Warm {
        /// The length in bytes of the value the key holds.
        logical_length: u64,
    },
    /// The structured detail and human-readable text of an error frame.
    Error {
        /// The structure defined by the error class.
        detail: &'a [u8],
        /// Human-readable text, not contractual.
        text: &'a [u8],
    },
}

/// The validated header of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    version: Version,
    kind: Kind,
    flags: Flags,
    code: u16,
    metadata_length: u16,
    payload_length: u32,
    request_id: RequestId,
}

impl Header {
    /// Returns the protocol version field.
    #[must_use]
    pub const fn version(self) -> Version {
        self.version
    }

    /// Returns the frame kind.
    #[must_use]
    pub const fn kind(self) -> Kind {
        self.kind
    }

    /// Returns the reserved flags field.
    #[must_use]
    pub const fn flags(self) -> Flags {
        self.flags
    }

    /// Returns the raw `code` field.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.code
    }

    /// Returns the declared metadata region length.
    #[must_use]
    pub const fn metadata_length(self) -> u16 {
        self.metadata_length
    }

    /// Returns the declared payload length.
    #[must_use]
    pub const fn payload_length(self) -> u32 {
        self.payload_length
    }

    /// Returns the request identity field.
    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }
}

/// An admitted frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    header: Header,
    metadata: MetadataRegion<'a>,
    payload: Payload<'a>,
    retires: RequestId,
}

impl<'a> Frame<'a> {
    /// Returns the frame header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the metadata region.
    #[must_use]
    pub const fn metadata(&self) -> &MetadataRegion<'a> {
        &self.metadata
    }

    /// Returns the payload.
    #[must_use]
    pub const fn payload(&self) -> &Payload<'a> {
        &self.payload
    }

    /// Returns the request id this frame retires, or the reserved id when it
    /// retires none.
    #[must_use]
    pub const fn retires(&self) -> RequestId {
        self.retires
    }
}

/// The outcome of decoding at the head of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<'a> {
    /// Fewer bytes are held than the receiver needs.
    Need(usize),
    /// A frame was admitted.
    Frame(Frame<'a>),
    /// The frame was refused with a classified failure.
    Failure {
        /// The class and scope of the failure.
        failure: Failure,
        /// The number of input bytes the frame occupies.
        consumed: usize,
    },
}

/// A frame a caller asks the encoder to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outgoing<'a> {
    /// The frame kind.
    pub kind: Kind,
    /// The raw `code` field.
    pub code: u16,
    /// The request identity field.
    pub request_id: u64,
    /// The metadata entries, which must be strictly ascending.
    pub metadata: &'a [(u16, &'a [u8])],
    /// The payload to write.
    pub payload: OutgoingPayload<'a>,
}

/// The payload a caller asks the encoder to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutgoingPayload<'a> {
    /// Opaque bytes.
    Opaque(&'a [u8]),
    /// A value held outside memory, written as its logical length.
    Warm(u64),
    /// The structured detail and text of an error frame.
    Error {
        /// The structure defined by the error class.
        detail: &'a [u8],
        /// Human-readable text, not contractual.
        text: &'a [u8],
    },
}

/// A refusal by the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The metadata identifiers are not strictly ascending.
    MetadataNotAscending,
    /// The frame's total length exceeds the maximum frame size.
    FrameTooLarge,
    /// The metadata region exceeds the maximum metadata size.
    MetadataTooLarge,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::MetadataNotAscending => "metadata identifiers must be strictly ascending",
            Self::FrameTooLarge => "frame exceeds the maximum frame size",
            Self::MetadataTooLarge => "metadata region exceeds the maximum metadata size",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for EncodeError {}

/// Decodes one frame from the head of `input` under a connection context.
///
/// The `in_flight` slice of the admission holds the request ids in flight at
/// the receiver and is read by the correlation checks.
#[must_use]
pub fn decode<'a>(input: &'a [u8], admission: Admission<'_>) -> Step<'a> {
    let admitted = match admit(
        input,
        admission.role,
        admission.limits,
        admission.capabilities,
    ) {
        Ok(admitted) => admitted,
        Err(step) => return step,
    };
    let raw = admitted.raw;
    let kind = admitted.kind;
    let total_len = admitted.total_len;
    if let Err(failure) = check_connection_state(admission.state, kind, raw.code) {
        return step_for(failure, total_len, input.len());
    }
    let correlation = match correlate(
        kind,
        raw.code,
        raw.request_id,
        admission.in_flight,
        admission.capabilities,
    ) {
        Ok(correlation) => correlation,
        Err(failure) => return step_for(failure, total_len, input.len()),
    };
    if let Err(failure) = check_metadata_order(&admitted.metadata) {
        return step_for(failure, total_len, input.len());
    }
    let Some(payload_bytes) = input.get(admitted.metadata_end..total_len) else {
        return step_for(Failure::malformed_request(), total_len, input.len());
    };
    let payload = match read_payload(correlation, raw.payload_length, payload_bytes) {
        Ok(payload) => payload,
        Err(failure) => return step_for(failure, total_len, input.len()),
    };
    let retires = retires_for(kind, correlation, raw.request_id);
    let header = Header {
        version: Version(raw.version),
        kind,
        flags: Flags(raw.flags),
        code: raw.code,
        metadata_length: raw.metadata_length,
        payload_length: raw.payload_length,
        request_id: RequestId(raw.request_id),
    };
    Step::Frame(Frame {
        header,
        metadata: admitted.metadata,
        payload,
        retires,
    })
}

/// The header-derived state an admitted frame carries forward.
struct Admitted<'a> {
    raw: RawHeader,
    kind: Kind,
    metadata: MetadataRegion<'a>,
    total_len: usize,
    metadata_end: usize,
}

/// Runs the frame admission checks from the header through the direction
/// check, returning the frame's total length and parsed metadata region.
fn admit<'a>(
    input: &'a [u8],
    role: Role,
    limits: Limits,
    capabilities: &[u16],
) -> Result<Admitted<'a>, Step<'a>> {
    let Some(raw) = RawHeader::parse(input) else {
        return Err(Step::Need(HEADER_LENGTH));
    };
    if raw.version != 0 {
        return Err(Step::Failure {
            failure: Failure::unsupported_protocol_version(),
            consumed: input.len(),
        });
    }
    let Some(kind) = Kind::from_wire(raw.kind) else {
        return Err(Step::Failure {
            failure: Failure::protocol_violation(),
            consumed: input.len(),
        });
    };
    let Some(frame_total) = total_length(raw.metadata_length, raw.payload_length) else {
        return Err(Step::Failure {
            failure: Failure::resource_limit(),
            consumed: input.len(),
        });
    };
    if frame_total > limits.frame_size {
        return Err(Step::Failure {
            failure: Failure::resource_limit(),
            consumed: input.len(),
        });
    }
    if raw.flags != 0 {
        return Err(Step::Failure {
            failure: Failure::protocol_violation(),
            consumed: input.len(),
        });
    }
    if raw.metadata_length > limits.metadata_size {
        return Err(Step::Failure {
            failure: Failure::malformed_request(),
            consumed: input.len(),
        });
    }
    let Ok(total_len) = usize::try_from(frame_total) else {
        return Err(Step::Failure {
            failure: Failure::resource_limit(),
            consumed: input.len(),
        });
    };
    if input.len() < total_len {
        return Err(Step::Need(total_len));
    }
    let Some(metadata_end) = HEADER_LENGTH.checked_add(usize::from(raw.metadata_length)) else {
        return Err(Step::Failure {
            failure: Failure::malformed_request(),
            consumed: input.len(),
        });
    };
    let Some(metadata_bytes) = input.get(HEADER_LENGTH..metadata_end) else {
        return Err(Step::Failure {
            failure: Failure::malformed_request(),
            consumed: input.len(),
        });
    };
    let Some(metadata) = MetadataRegion::parse(metadata_bytes) else {
        return Err(Step::Failure {
            failure: Failure::malformed_request(),
            consumed: input.len(),
        });
    };
    if kind == Kind::Withdrawal && (raw.metadata_length != 0 || raw.payload_length != 0) {
        return Err(Step::Failure {
            failure: Failure::malformed_request(),
            consumed: input.len(),
        });
    }
    if kind.sender() == role {
        return Err(Step::Failure {
            failure: Failure::protocol_violation(),
            consumed: input.len(),
        });
    }
    if kind == Kind::Withdrawal && !capabilities.contains(&CANCELLATION_CAPABILITY_ID) {
        return Err(Step::Failure {
            failure: Failure::protocol_violation(),
            consumed: input.len(),
        });
    }
    Ok(Admitted {
        raw,
        kind,
        metadata,
        total_len,
        metadata_end,
    })
}

/// Encodes a frame and returns its exact bytes.
///
/// # Errors
///
/// Returns [`EncodeError::MetadataNotAscending`] when the metadata
/// identifiers are not strictly ascending, [`EncodeError::MetadataTooLarge`]
/// when the metadata region exceeds the maximum metadata size, and
/// [`EncodeError::FrameTooLarge`] when the total length exceeds the maximum
/// frame size or a payload field cannot be represented.
pub fn encode(outgoing: &Outgoing<'_>) -> Result<Vec<u8>, EncodeError> {
    encode_with_max(outgoing, MAX_FRAME_SIZE, MAX_METADATA_SIZE)
}

/// Encodes a frame under explicit size bounds and returns its exact bytes.
///
/// The bounds are the effective limits in force on the connection that
/// sends the frame, typically the stricter of the negotiated and local
/// caps. The pre-negotiation constants apply before the handshake.
///
/// # Errors
///
/// Returns the same variants as [`encode`], evaluated against the given
/// bounds instead of the pre-negotiation constants.
pub fn encode_with_max(
    outgoing: &Outgoing<'_>,
    max_frame_size: u64,
    max_metadata_size: u16,
) -> Result<Vec<u8>, EncodeError> {
    let metadata_length = checked_metadata_length_with_max(outgoing.metadata, max_metadata_size)?;
    let payload = encode_payload(outgoing.payload)?;
    let payload_length = u32::try_from(payload.len()).map_err(|_| EncodeError::FrameTooLarge)?;
    let frame_total = u64::try_from(HEADER_LENGTH)
        .ok()
        .and_then(|header| header.checked_add(metadata_length))
        .and_then(|total| total.checked_add(u64::from(payload_length)))
        .ok_or(EncodeError::FrameTooLarge)?;
    if frame_total > max_frame_size {
        return Err(EncodeError::FrameTooLarge);
    }
    let metadata_len = u16::try_from(metadata_length).map_err(|_| EncodeError::MetadataTooLarge)?;
    let mut out = Vec::new();
    out.push(0);
    out.push(outgoing.kind.value());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&outgoing.code.to_le_bytes());
    out.extend_from_slice(&metadata_len.to_le_bytes());
    out.extend_from_slice(&payload_length.to_le_bytes());
    out.extend_from_slice(&outgoing.request_id.to_le_bytes());
    for (identifier, value) in outgoing.metadata {
        out.extend_from_slice(&identifier.to_le_bytes());
        let value_len = u16::try_from(value.len()).map_err(|_| EncodeError::MetadataTooLarge)?;
        out.extend_from_slice(&value_len.to_le_bytes());
        out.extend_from_slice(value);
    }
    out.extend_from_slice(&payload);
    Ok(out)
}

/// The decision the `code` and correlation checks produce for one frame.
#[derive(Debug, Clone, Copy)]
enum Correlation {
    /// A request frame carrying the handshake opcode.
    HandshakeRequest,
    /// A request frame carrying one of the five operation opcodes.
    OperationRequest(u16),
    /// A response frame carrying an assigned result code.
    Response(ResultCode),
    /// An error frame carrying an assigned class of this scope.
    Error(FailureScope),
    /// A withdrawal frame naming the request to withdraw. It never enters
    /// flight at the receiver and retires nothing.
    Withdrawal,
}

/// The raw fields of a frame header.
struct RawHeader {
    version: u8,
    kind: u8,
    flags: u16,
    code: u16,
    metadata_length: u16,
    payload_length: u32,
    request_id: u64,
}

impl RawHeader {
    /// Parses the 20 header bytes, or returns `None` when fewer are present.
    fn parse(input: &[u8]) -> Option<Self> {
        Some(Self {
            version: input.first().copied()?,
            kind: input.get(1).copied()?,
            flags: read_u16_le(input, 2)?,
            code: read_u16_le(input, 4)?,
            metadata_length: read_u16_le(input, 6)?,
            payload_length: read_u32_le(input, 8)?,
            request_id: read_u64_le(input, 12)?,
        })
    }
}

/// Computes the total frame length in a 64-bit width.
fn total_length(metadata_length: u16, payload_length: u32) -> Option<u64> {
    u64::try_from(HEADER_LENGTH)
        .ok()?
        .checked_add(u64::from(metadata_length))?
        .checked_add(u64::from(payload_length))
}

/// Wraps a failure with the number of bytes its frame occupies.
fn step_for<'a>(failure: Failure, total_len: usize, input_len: usize) -> Step<'a> {
    let consumed = if failure.scope() == FailureScope::RequestScoped {
        total_len
    } else {
        input_len
    };
    Step::Failure { failure, consumed }
}

/// Applies the connection-state rule to an admitted frame's kind and code.
///
/// The check runs before the opcode assignment, so a frame the connection
/// state forbids is a protocol violation rather than the class its code alone
/// would produce.
const fn check_connection_state(
    state: ConnectionState,
    kind: Kind,
    code: u16,
) -> Result<(), Failure> {
    let is_handshake = matches!(kind, Kind::Request) && code == HANDSHAKE_OPCODE;
    match state {
        ConnectionState::PreNegotiation => {
            let responder_terminal =
                (matches!(kind, Kind::Response) && code == 0) || matches!(kind, Kind::Error);
            if is_handshake || responder_terminal {
                Ok(())
            } else {
                Err(Failure::protocol_violation())
            }
        }
        ConnectionState::Negotiated => {
            if is_handshake {
                Err(Failure::protocol_violation())
            } else {
                Ok(())
            }
        }
        ConnectionState::Terminal => Err(Failure::protocol_violation()),
    }
}

/// Runs the code and correlation checks that follow the direction check.
fn correlate(
    kind: Kind,
    code: u16,
    request_id: u64,
    in_flight: &[u64],
    capabilities: &[u16],
) -> Result<Correlation, Failure> {
    match kind {
        Kind::Request => {
            if request_id == 0 {
                return Err(Failure::protocol_violation());
            }
            if in_flight.contains(&request_id) {
                return Err(Failure::protocol_violation());
            }
            if code == HANDSHAKE_OPCODE {
                Ok(Correlation::HandshakeRequest)
            } else if Opcode::is_assigned(code) {
                Ok(Correlation::OperationRequest(code))
            } else {
                Err(Failure::unsupported_operation())
            }
        }
        Kind::Response => {
            if request_id == 0 {
                return Err(Failure::protocol_violation());
            }
            if !in_flight.contains(&request_id) {
                return Err(Failure::protocol_violation());
            }
            let result = ResultCode::from_wire(code).ok_or_else(Failure::protocol_violation)?;
            Ok(Correlation::Response(result))
        }
        Kind::Error => {
            let class = ErrorClass::from_wire(code).ok_or_else(Failure::protocol_violation)?;
            if class == ErrorClass::DeadlineExceeded
                && !capabilities.contains(&DEADLINES_CAPABILITY_ID)
            {
                return Err(Failure::protocol_violation());
            }
            if class == ErrorClass::Cancelled && !capabilities.contains(&CANCELLATION_CAPABILITY_ID)
            {
                return Err(Failure::protocol_violation());
            }
            let scope = class.scope();
            if scope == FailureScope::RequestScoped {
                if request_id == 0 {
                    return Err(Failure::protocol_violation());
                }
                if !in_flight.contains(&request_id) {
                    return Err(Failure::protocol_violation());
                }
            }
            Ok(Correlation::Error(scope))
        }
        Kind::Withdrawal => {
            if code != 0 {
                return Err(Failure::protocol_violation());
            }
            if request_id == 0 {
                return Err(Failure::protocol_violation());
            }
            Ok(Correlation::Withdrawal)
        }
    }
}

/// Checks metadata entry order and the required identifier range.
fn check_metadata_order(metadata: &MetadataRegion<'_>) -> Result<(), Failure> {
    let mut previous: Option<u16> = None;
    for entry in metadata.entries() {
        if let Some(previous_identifier) = previous {
            if entry.identifier() <= previous_identifier {
                return Err(Failure::invalid_argument());
            }
        }
        if entry.is_required() {
            return Err(Failure::invalid_argument());
        }
        previous = Some(entry.identifier());
    }
    Ok(())
}

/// Checks the request payload of one of the five ungated operations.
///
/// `PING` carries no payload; `GET`, `DEL` and `EXISTS` carry the key
/// alone with no structural check; `SET` carries a `u32` key length
/// followed by the key and the derived value. A short `SET` head or a
/// key length overrunning the payload is a malformed request.
fn check_operation_request(
    opcode: u16,
    payload_length: u32,
    payload: &[u8],
) -> Result<Payload<'_>, Failure> {
    if opcode == PING_OPCODE {
        if payload_length != 0 {
            return Err(Failure::malformed_request());
        }
        return Ok(Payload::Opaque(&[]));
    }
    if opcode == SET_OPCODE {
        if payload.len() < 4 {
            return Err(Failure::malformed_request());
        }
        let key_length = read_u32_le(payload, 0).ok_or_else(Failure::malformed_request)?;
        let head = 4usize
            .checked_add(usize::try_from(key_length).map_err(|_| Failure::malformed_request())?)
            .ok_or_else(Failure::malformed_request)?;
        if head > payload.len() {
            return Err(Failure::malformed_request());
        }
        return Ok(Payload::Opaque(payload));
    }
    Ok(Payload::Opaque(payload))
}

/// Checks the payload layout of an admitted frame.
fn read_payload(
    correlation: Correlation,
    payload_length: u32,
    payload: &[u8],
) -> Result<Payload<'_>, Failure> {
    match correlation {
        Correlation::HandshakeRequest | Correlation::Response(ResultCode::Success) => {
            Ok(Payload::Opaque(payload))
        }
        Correlation::Withdrawal => {
            if payload_length != 0 {
                return Err(Failure::malformed_request());
            }
            Ok(Payload::Opaque(payload))
        }
        Correlation::OperationRequest(opcode) => {
            check_operation_request(opcode, payload_length, payload)
        }
        Correlation::Response(ResultCode::Absent) => {
            if payload_length != 0 {
                return Err(Failure::malformed_request());
            }
            Ok(Payload::Opaque(&[]))
        }
        Correlation::Response(ResultCode::ValueHeldOutsideMemory) => {
            if payload_length != 8 {
                return Err(Failure::malformed_request());
            }
            let logical_length = read_u64_le(payload, 0).ok_or_else(Failure::malformed_request)?;
            Ok(Payload::Warm { logical_length })
        }
        Correlation::Error(_) => {
            if payload_length < 2 {
                return Err(Failure::malformed_request());
            }
            let detail_length = read_u16_le(payload, 0).ok_or_else(Failure::malformed_request)?;
            let detail_end = usize::from(detail_length)
                .checked_add(2)
                .ok_or_else(Failure::malformed_request)?;
            let detail = payload
                .get(2..detail_end)
                .ok_or_else(Failure::malformed_request)?;
            let text = payload
                .get(detail_end..)
                .ok_or_else(Failure::malformed_request)?;
            Ok(Payload::Error { detail, text })
        }
    }
}

/// Returns the request id an admitted frame retires.
const fn retires_for(kind: Kind, correlation: Correlation, request_id: u64) -> RequestId {
    match kind {
        Kind::Response => RequestId(request_id),
        Kind::Withdrawal | Kind::Request => RequestId(0),
        Kind::Error => {
            if matches!(correlation, Correlation::Error(FailureScope::RequestScoped)) {
                RequestId(request_id)
            } else {
                RequestId(0)
            }
        }
    }
}

/// Sums the encoded metadata region and enforces the given bound.
fn checked_metadata_length_with_max(
    metadata: &[(u16, &[u8])],
    max_metadata_size: u16,
) -> Result<u64, EncodeError> {
    let mut previous: Option<u16> = None;
    let mut length: u64 = 0;
    for (identifier, value) in metadata {
        if let Some(previous_identifier) = previous {
            if *identifier <= previous_identifier {
                return Err(EncodeError::MetadataNotAscending);
            }
        }
        let value_length = u64::try_from(value.len()).map_err(|_| EncodeError::MetadataTooLarge)?;
        let entry_length = 4u64
            .checked_add(value_length)
            .ok_or(EncodeError::MetadataTooLarge)?;
        length = length
            .checked_add(entry_length)
            .ok_or(EncodeError::MetadataTooLarge)?;
        previous = Some(*identifier);
    }
    if length > u64::from(max_metadata_size) {
        return Err(EncodeError::MetadataTooLarge);
    }
    Ok(length)
}

/// Encodes a payload from its parts.
fn encode_payload(payload: OutgoingPayload<'_>) -> Result<Vec<u8>, EncodeError> {
    match payload {
        OutgoingPayload::Opaque(bytes) => Ok(bytes.to_vec()),
        OutgoingPayload::Warm(logical_length) => Ok(logical_length.to_le_bytes().to_vec()),
        OutgoingPayload::Error { detail, text } => {
            let detail_length =
                u16::try_from(detail.len()).map_err(|_| EncodeError::FrameTooLarge)?;
            let mut out = Vec::new();
            out.extend_from_slice(&detail_length.to_le_bytes());
            out.extend_from_slice(detail);
            out.extend_from_slice(text);
            Ok(out)
        }
    }
}

/// Reads a little-endian `u16` at `offset`, or `None` when out of bounds.
fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    let array: [u8; 2] = slice.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

/// Reads a little-endian `u32` at `offset`, or `None` when out of bounds.
fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    let array: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

/// Reads a little-endian `u64` at `offset`, or `None` when out of bounds.
fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let array: [u8; 8] = slice.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in text.as_bytes().chunks_exact(2) {
            let [hi, lo] = chunk else {
                return out;
            };
            out.push((nibble(*hi) << 4) | nibble(*lo));
        }
        out
    }

    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte.wrapping_sub(b'0'),
            b'a'..=b'f' => byte.wrapping_sub(b'a').wrapping_add(10),
            b'A'..=b'F' => byte.wrapping_sub(b'A').wrapping_add(10),
            _ => 0,
        }
    }

    fn frame_with_metadata(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let outgoing = Outgoing {
            kind: Kind::Response,
            code: 0,
            request_id: 1,
            metadata: entries,
            payload: OutgoingPayload::Opaque(&[]),
        };
        encode(&outgoing).unwrap_or_default()
    }

    fn decode_at<'a>(input: &'a [u8], role: Role, in_flight: &[u64]) -> Step<'a> {
        decode(
            input,
            Admission {
                role,
                state: ConnectionState::Negotiated,
                limits: Limits::PRE_NEGOTIATION,
                in_flight,
                capabilities: &[],
            },
        )
    }

    fn decode_with<'a>(
        input: &'a [u8],
        role: Role,
        in_flight: &[u64],
        capabilities: &[u16],
    ) -> Step<'a> {
        decode(
            input,
            Admission {
                role,
                state: ConnectionState::Negotiated,
                limits: Limits::PRE_NEGOTIATION,
                in_flight,
                capabilities,
            },
        )
    }

    #[test]
    fn assigned_kinds_convert_and_unassigned_kinds_refuse() {
        assert_eq!(Kind::from_wire(1), Some(Kind::Request));
        assert_eq!(Kind::from_wire(2), Some(Kind::Response));
        assert_eq!(Kind::from_wire(3), Some(Kind::Error));
        assert_eq!(Kind::from_wire(7), Some(Kind::Withdrawal));
        assert_eq!(Kind::from_wire(0), None);
        assert_eq!(Kind::from_wire(4), None);
        assert_eq!(Kind::from_wire(8), None);
        assert_eq!(Kind::from_wire(u8::MAX), None);
        assert_eq!(Kind::Request.value(), 1);
        assert_eq!(Kind::Withdrawal.value(), 7);
        assert_eq!(Kind::Request.sender(), Role::Client);
        assert_eq!(Kind::Withdrawal.sender(), Role::Client);
        assert_eq!(Kind::Response.sender(), Role::Server);
        assert_eq!(Kind::Error.sender(), Role::Server);
        assert!(Kind::Response.names_a_request_for_scope(FailureScope::ConnectionFatal));
        assert!(Kind::Withdrawal.names_a_request_for_scope(FailureScope::RequestScoped));
        assert!(Kind::Error.names_a_request_for_scope(FailureScope::RequestScoped));
        assert!(!Kind::Error.names_a_request_for_scope(FailureScope::ConnectionFatal));
    }

    #[test]
    fn assigned_result_codes_convert_and_unassigned_refuse() {
        assert_eq!(ResultCode::from_wire(0), Some(ResultCode::Success));
        assert_eq!(ResultCode::from_wire(1), Some(ResultCode::Absent));
        assert_eq!(
            ResultCode::from_wire(4),
            Some(ResultCode::ValueHeldOutsideMemory)
        );
        assert_eq!(ResultCode::Success.value(), 0);
        assert_eq!(ResultCode::Absent.value(), 1);
        assert_eq!(ResultCode::ValueHeldOutsideMemory.value(), 4);
        for value in [2u16, 3, 5, u16::MAX] {
            assert_eq!(ResultCode::from_wire(value), None);
        }
    }

    #[test]
    fn assigned_error_classes_convert_and_unassigned_refuse() {
        let assigned = [
            (
                ErrorClass::MalformedRequest,
                0x0001,
                FailureScope::ConnectionFatal,
            ),
            (
                ErrorClass::UnsupportedProtocolVersion,
                0x0002,
                FailureScope::ConnectionFatal,
            ),
            (
                ErrorClass::UnsupportedOperation,
                0x0003,
                FailureScope::RequestScoped,
            ),
            (
                ErrorClass::InvalidArgument,
                0x0004,
                FailureScope::RequestScoped,
            ),
            (
                ErrorClass::ResourceLimit,
                0x0005,
                FailureScope::ConnectionFatal,
            ),
            (
                ErrorClass::DeadlineExceeded,
                0x0006,
                FailureScope::RequestScoped,
            ),
            (ErrorClass::Cancelled, 0x0007, FailureScope::RequestScoped),
            (ErrorClass::Overloaded, 0x0008, FailureScope::RequestScoped),
            (
                ErrorClass::InternalError,
                0x000B,
                FailureScope::RequestScoped,
            ),
            (
                ErrorClass::ProtocolViolation,
                0x000C,
                FailureScope::ConnectionFatal,
            ),
            (ErrorClass::WrongType, 0x000E, FailureScope::RequestScoped),
        ];
        for (class, value, scope) in assigned {
            assert_eq!(ErrorClass::from_wire(value), Some(class));
            assert_eq!(class.value(), value);
            assert_eq!(class.scope(), scope);
            assert_eq!(Failure::new(class, scope).class(), class);
            assert_eq!(Failure::new(class, scope).scope(), scope);
        }
        assert_eq!(ErrorClass::MalformedRequest.name(), "malformed request");
        assert_eq!(ErrorClass::DeadlineExceeded.name(), "deadline exceeded");
        assert_eq!(ErrorClass::Cancelled.name(), "cancelled");
        assert_eq!(
            ErrorClass::UnsupportedOperation.name(),
            "unsupported operation"
        );
        assert_eq!(ErrorClass::WrongType.name(), "wrong type");
        for value in [0u16, 0x0009, 0x000A, 0x000D, 0x000F, u16::MAX] {
            assert_eq!(ErrorClass::from_wire(value), None);
        }
    }

    #[test]
    fn reserved_request_id_is_refused_on_a_frame_that_names_a_request() {
        let bytes = from_hex("0002000000000000000000000000000000000000");
        match decode_at(&bytes, Role::Client, &[]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(matches!(other, Step::Need(_)), "expected failure"),
        }
    }

    #[test]
    fn fatal_class_error_frame_allows_the_reserved_request_id() {
        let bytes = from_hex("000300000c0000000200000000000000000000000000");
        let step = decode_at(&bytes, Role::Client, &[]);
        assert!(
            matches!(&step, Step::Frame(_)),
            "expected frame, got {step:?}"
        );
        if let Step::Frame(frame) = step {
            assert_eq!(frame.header().code(), 0x000C);
            assert_eq!(frame.retires().value(), 0);
            assert_eq!(
                frame.payload(),
                &Payload::Error {
                    detail: &[],
                    text: &[]
                }
            );
        }
    }

    #[test]
    fn metadata_ascending_entries_admit() {
        let bytes = frame_with_metadata(&[(1, &[]), (2, &[0xff])]);
        let step = decode_at(&bytes, Role::Client, &[1]);
        assert!(
            matches!(&step, Step::Frame(_)),
            "expected frame, got {step:?}"
        );
        if let Step::Frame(frame) = step {
            assert_eq!(frame.metadata().entries().len(), 2);
            assert_eq!(
                frame.metadata().entries().first().map(|e| e.identifier()),
                Some(1)
            );
        }
    }

    #[test]
    fn metadata_duplicate_and_descent_refuse() {
        for text in [
            "00020000000008000000000001000000000000000100000001000000",
            "00020000000008000000000001000000000000000200000001000000",
        ] {
            let bytes = from_hex(text);
            match decode_at(&bytes, Role::Client, &[1]) {
                Step::Failure { failure, consumed } => {
                    assert_eq!(failure.class(), ErrorClass::InvalidArgument);
                    assert_eq!(failure.scope(), FailureScope::RequestScoped);
                    assert_eq!(consumed, bytes.len());
                }
                other => assert!(matches!(other, Step::Need(_)), "expected failure"),
            }
        }
    }

    #[test]
    fn metadata_region_must_fill_exactly() {
        let bytes = from_hex("0002000000000600000000000100000000000000010000000200");
        match decode_at(&bytes, Role::Client, &[1]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::MalformedRequest);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(matches!(other, Step::Need(_)), "expected failure"),
        }
    }

    #[test]
    fn unassigned_optional_identifier_is_skipped() {
        let bytes = from_hex("000200000000070000000000010000000000000001000300aabbcc");
        let step = decode_at(&bytes, Role::Client, &[1]);
        assert!(
            matches!(&step, Step::Frame(_)),
            "expected frame, got {step:?}"
        );
    }

    #[test]
    fn unassigned_required_identifier_is_refused() {
        let bytes = from_hex("000200000000040000000000010000000000000000800000");
        match decode_at(&bytes, Role::Client, &[1]) {
            Step::Failure { failure, consumed } => {
                assert_eq!(failure.class(), ErrorClass::InvalidArgument);
                assert_eq!(failure.scope(), FailureScope::RequestScoped);
                assert_eq!(consumed, 24);
            }
            other => assert!(matches!(other, Step::Need(_)), "expected failure"),
        }
    }

    #[test]
    fn widest_length_arithmetic_fits_u64() {
        let expected = 20u64
            .checked_add(u64::from(u16::MAX))
            .and_then(|value| value.checked_add(u64::from(u32::MAX)));
        assert_eq!(total_length(u16::MAX, u32::MAX), expected);
        assert!(expected.is_some_and(|total| total > MAX_FRAME_SIZE));
    }

    #[test]
    fn minimal_response_decodes() {
        let bytes = from_hex("0002000000000000000000000100000000000000");
        let step = decode_at(&bytes, Role::Client, &[1]);
        assert!(
            matches!(&step, Step::Frame(_)),
            "expected frame, got {step:?}"
        );
        if let Step::Frame(frame) = step {
            assert_eq!(frame.header().kind(), Kind::Response);
            assert_eq!(frame.header().code(), 0);
            assert_eq!(frame.header().request_id().value(), 1);
            assert_eq!(frame.retires().value(), 1);
        }
    }

    #[test]
    fn fragmented_input_returns_need() {
        let bytes = from_hex("0002000000000000000000000100000000000000");
        let short = bytes.get(..10).unwrap_or(&bytes);
        assert!(matches!(
            decode_at(short, Role::Client, &[1]),
            Step::Need(20)
        ));
        let body = from_hex("0002000000000300000000000100000000000000aabbcc");
        let truncated = body.get(..body.len().saturating_sub(1)).unwrap_or(&body);
        assert!(matches!(
            decode_at(truncated, Role::Client, &[1]),
            Step::Need(23)
        ));
    }

    #[test]
    fn encoder_round_trips_every_payload_shape() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            Outgoing {
                kind: Kind::Response,
                code: 0,
                request_id: 1,
                metadata: &[],
                payload: OutgoingPayload::Opaque(&[]),
            },
            Outgoing {
                kind: Kind::Response,
                code: 1,
                request_id: 1,
                metadata: &[],
                payload: OutgoingPayload::Opaque(&[]),
            },
            Outgoing {
                kind: Kind::Response,
                code: 4,
                request_id: 1,
                metadata: &[],
                payload: OutgoingPayload::Warm(4096),
            },
            Outgoing {
                kind: Kind::Response,
                code: 0,
                request_id: 1,
                metadata: &[(1, &[0x0a, 0x0b])],
                payload: OutgoingPayload::Opaque(&[]),
            },
            Outgoing {
                kind: Kind::Error,
                code: 3,
                request_id: 1,
                metadata: &[],
                payload: OutgoingPayload::Error {
                    detail: &[],
                    text: b"ok",
                },
            },
            Outgoing {
                kind: Kind::Error,
                code: 14,
                request_id: 1,
                metadata: &[],
                payload: OutgoingPayload::Error {
                    detail: &[0x01],
                    text: &[],
                },
            },
        ];
        for outgoing in cases {
            let bytes = encode(&outgoing)?;
            let step = decode_at(&bytes, Role::Client, &[1]);
            assert!(
                matches!(&step, Step::Frame(_)),
                "round trip failed: {step:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn handshake_request_encode_derives_the_capability_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let entries = vec![
            CapabilityEntry::new(1, &[0xaa]),
            CapabilityEntry::new(4, &[]),
        ];
        let request = HandshakeRequest::new(0, 0, 65_536, CapabilityEntries::new(entries));
        let payload = request.encode();
        assert_eq!(payload.get(8..10), Some(&[2u8, 0][..]), "capability count");
        let decoded = HandshakeRequest::decode(&payload)
            .map_err(|failure| format!("request decode failed: {}", failure.class().name()))?;
        assert_eq!(decoded.capability_count(), 2);
        assert_eq!(decoded.capability_entries().count(), 2);
        assert_eq!(
            decoded
                .capability_entries()
                .entries()
                .first()
                .map(|entry| entry.identifier()),
            Some(1)
        );
        assert_eq!(decoded.encode(), payload, "re-encode is stable");
        Ok(())
    }

    #[test]
    fn handshake_response_encode_derives_the_accepted_capability_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = from_hex("0000000001000010010001000000");
        let offer = HandshakeOffer {
            minimum_protocol_version: 0,
            maximum_protocol_version: 0,
            capability_ids: &[1],
        };
        let response = HandshakeResponse::decode(&payload, &offer)
            .map_err(|failure| format!("response decode failed: {}", failure.class().name()))?;
        assert_eq!(response.accepted_capability_count(), 1);
        assert_eq!(response.negotiated_protocol_version(), 0);
        assert_eq!(response.negotiated_maximum_frame_size(), 65_536);
        assert_eq!(response.negotiated_maximum_metadata_size(), 4_096);
        assert_eq!(response.encode(), payload, "re-encode is stable");
        Ok(())
    }

    fn request_bytes(code: u16) -> Vec<u8> {
        let set_empty: &[u8] = &[0, 0, 0, 0];
        let payload: &[u8] = if code == SET_OPCODE { set_empty } else { &[] };
        let outgoing = Outgoing {
            kind: Kind::Request,
            code,
            request_id: 7,
            metadata: &[],
            payload: OutgoingPayload::Opaque(payload),
        };
        encode(&outgoing).unwrap_or_default()
    }

    #[test]
    fn the_five_operation_opcodes_admit() {
        assert_eq!(SPEC_REVISION, "v0.6.0");
        for code in [
            PING_OPCODE,
            GET_OPCODE,
            SET_OPCODE,
            DEL_OPCODE,
            EXISTS_OPCODE,
        ] {
            let bytes = request_bytes(code);
            match decode_at(&bytes, Role::Server, &[]) {
                Step::Frame(frame) => {
                    assert_eq!(frame.header().code(), code);
                    assert_eq!(frame.retires().value(), 0);
                }
                other => assert!(
                    matches!(other, Step::Need(_)),
                    "opcode {code:#06x} should admit, got {other:?}"
                ),
            }
        }
        assert!(Opcode::is_assigned(PING_OPCODE));
        assert!(Opcode::is_assigned(EXISTS_OPCODE));
        assert!(!Opcode::is_assigned(0x0000));
        assert!(!Opcode::is_assigned(0x0007));
    }

    #[test]
    fn unassigned_opcodes_refuse_per_request_with_the_session_open() {
        for code in [0x0000, 0x0007] {
            let bytes = request_bytes(code);
            match decode_at(&bytes, Role::Server, &[]) {
                Step::Failure { failure, consumed } => {
                    assert_eq!(failure.class(), ErrorClass::UnsupportedOperation);
                    assert_eq!(failure.scope(), FailureScope::RequestScoped);
                    assert_eq!(consumed, bytes.len());
                }
                other => assert!(
                    matches!(other, Step::Need(_)),
                    "opcode {code:#06x} should refuse, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn a_withdrawal_encodes_to_its_exact_bytes() {
        let outgoing = Outgoing {
            kind: Kind::Withdrawal,
            code: 0,
            request_id: 1,
            metadata: &[],
            payload: OutgoingPayload::Opaque(&[]),
        };
        let bytes = encode(&outgoing).unwrap_or_default();
        assert_eq!(bytes, from_hex("0007000000000000000000000100000000000000"));
    }

    #[test]
    fn a_withdrawal_admits_and_retires_nothing() {
        let bytes = from_hex("0007000000000000000000000100000000000000");
        match decode_with(&bytes, Role::Server, &[], &[CANCELLATION_CAPABILITY_ID]) {
            Step::Frame(frame) => {
                assert_eq!(frame.header().kind(), Kind::Withdrawal);
                assert_eq!(frame.header().code(), 0);
                assert_eq!(frame.header().request_id().value(), 1);
                assert_eq!(frame.retires().value(), 0);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_withdrawal_with_a_nonzero_code_is_a_protocol_violation() {
        let outgoing = Outgoing {
            kind: Kind::Withdrawal,
            code: 1,
            request_id: 1,
            metadata: &[],
            payload: OutgoingPayload::Opaque(&[]),
        };
        let bytes = encode(&outgoing).unwrap_or_default();
        match decode_with(&bytes, Role::Server, &[], &[CANCELLATION_CAPABILITY_ID]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_withdrawal_with_a_payload_or_metadata_is_malformed() {
        let with_payload = from_hex("000700000000000001000000010000000000000000");
        match decode_with(
            &with_payload,
            Role::Server,
            &[],
            &[CANCELLATION_CAPABILITY_ID],
        ) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::MalformedRequest);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
        let outgoing = Outgoing {
            kind: Kind::Withdrawal,
            code: 0,
            request_id: 1,
            metadata: &[(1, &[0x0a])],
            payload: OutgoingPayload::Opaque(&[]),
        };
        let with_metadata = encode(&outgoing).unwrap_or_default();
        match decode_with(
            &with_metadata,
            Role::Server,
            &[],
            &[CANCELLATION_CAPABILITY_ID],
        ) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::MalformedRequest);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_withdrawal_naming_the_reserved_id_is_a_protocol_violation() {
        let bytes = from_hex("0007000000000000000000000000000000000000");
        match decode_with(&bytes, Role::Server, &[], &[CANCELLATION_CAPABILITY_ID]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_withdrawal_for_an_unknown_id_admits_without_a_frame() {
        let bytes = from_hex("0007000000000000000000000300000000000000");
        match decode_with(&bytes, Role::Server, &[], &[CANCELLATION_CAPABILITY_ID]) {
            Step::Frame(frame) => {
                assert_eq!(frame.header().request_id().value(), 3);
                assert_eq!(frame.retires().value(), 0);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_withdrawal_without_cancellation_is_a_protocol_violation() {
        let bytes = from_hex("0007000000000000000000000100000000000000");
        match decode_at(&bytes, Role::Server, &[]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
    }

    #[test]
    fn gated_error_classes_need_their_capability() {
        let deadline = from_hex("00030000060000000200000001000000000000000000");
        match decode_at(&deadline, Role::Client, &[1]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
        match decode_with(&deadline, Role::Client, &[1], &[DEADLINES_CAPABILITY_ID]) {
            Step::Frame(frame) => {
                assert_eq!(frame.header().code(), 0x0006);
                assert_eq!(frame.retires().value(), 1);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let cancelled = from_hex("00030000070000000200000001000000000000000000");
        match decode_at(&cancelled, Role::Client, &[1]) {
            Step::Failure { failure, .. } => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
        match decode_with(
            &cancelled,
            Role::Client,
            &[1],
            &[CANCELLATION_CAPABILITY_ID],
        ) {
            Step::Frame(frame) => {
                assert_eq!(frame.header().code(), 0x0007);
                assert_eq!(frame.retires().value(), 1);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_deadline_entry_encodes_to_its_exact_bytes() {
        let deadline = 10_000u32.to_le_bytes();
        let outgoing = Outgoing {
            kind: Kind::Request,
            code: PING_OPCODE,
            request_id: 1,
            metadata: &[(DEADLINE_METADATA_ID, &deadline)],
            payload: OutgoingPayload::Opaque(&[]),
        };
        let bytes = encode(&outgoing).unwrap_or_default();
        assert_eq!(
            bytes,
            from_hex("00010000020008000000000001000000000000000100040010270000")
        );
        match decode_with(&bytes, Role::Server, &[], &[DEADLINES_CAPABILITY_ID]) {
            Step::Frame(frame) => {
                assert_eq!(frame.metadata().entries().len(), 1);
                assert_eq!(
                    frame.metadata().entries().first().map(|e| e.identifier()),
                    Some(DEADLINE_METADATA_ID)
                );
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_wrong_length_deadline_entry_still_admits() {
        let bytes = from_hex("0001000002000600000000000100000000000000010002000a0b");
        match decode_with(&bytes, Role::Server, &[], &[DEADLINES_CAPABILITY_ID]) {
            Step::Frame(frame) => {
                assert_eq!(frame.metadata().entries().len(), 1);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_deadline_entry_without_the_capability_still_admits() {
        let bytes = from_hex("00010000020008000000000001000000000000000100040010270000");
        match decode_at(&bytes, Role::Server, &[]) {
            Step::Frame(frame) => {
                assert_eq!(frame.metadata().entries().len(), 1);
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }
}

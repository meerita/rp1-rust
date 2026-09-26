//! Connection configuration and the version 0 handshake.
//!
//! A connection becomes usable only after the handshake completes. This
//! module owns the public configuration, the connect path, the handshake
//! exchange as untrusted input, the negotiated session state the
//! connection exposes, and the explicit lifecycle state of the connection.
//!
//! It owns no command surface. A connection negotiates and closes; it runs
//! no operation.

mod dispatch;

use std::fmt;

use dispatch::{InFlightRegistry, RequestIdAllocator};

use crate::protocol::{
    self, Admission, CapabilityEntries, ErrorClass, Failure, HANDSHAKE_OPCODE, HandshakeOffer,
    HandshakeRequest, HandshakeResponse, Kind, Limits, MAX_FRAME_SIZE,
    MINIMUM_NEGOTIATED_FRAME_SIZE, MINIMUM_NEGOTIATED_METADATA_SIZE, Outgoing, OutgoingPayload,
    Payload, Role, Step,
};
use crate::transport::{AnyTransport, TokioTransport};

/// The request id the handshake request carries.
const HANDSHAKE_REQUEST_ID: u64 = 1;

/// The most bytes one read may move while the handshake is in progress.
const READ_CHUNK: usize = 4_096;

/// The versions and capabilities this implementation offers.
const OFFER: HandshakeOffer<'_> = HandshakeOffer {
    minimum_protocol_version: 0,
    maximum_protocol_version: 0,
    capability_ids: &[],
};

/// The desired maximum frame size a configuration proposes by default.
const DEFAULT_DESIRED_MAXIMUM_FRAME_SIZE: u32 = 65_536;

/// The default local cap on the negotiated maximum frame size.
const DEFAULT_LOCAL_MAXIMUM_FRAME_SIZE: u64 = MINIMUM_NEGOTIATED_FRAME_SIZE;

/// The default local cap on the negotiated maximum metadata size.
const DEFAULT_LOCAL_MAXIMUM_METADATA_SIZE: u16 = MINIMUM_NEGOTIATED_METADATA_SIZE;

/// A failure a connection configuration can describe before any connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionConfigError {
    /// The endpoint is empty.
    EmptyEndpoint,
    /// The desired maximum frame size lies below the protocol floor.
    FrameSizeBelowFloor {
        /// The proposed value.
        proposed: u32,
    },
    /// The local maximum frame size lies below the protocol floor.
    LocalFrameSizeBelowFloor {
        /// The proposed value.
        proposed: u64,
    },
    /// The local maximum metadata size lies below the protocol floor.
    LocalMetadataSizeBelowFloor {
        /// The proposed value.
        proposed: u16,
    },
}

impl fmt::Display for ConnectionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEndpoint => formatter.write_str("the endpoint is empty"),
            Self::FrameSizeBelowFloor { proposed } => {
                write!(
                    formatter,
                    "the desired maximum frame size {proposed} is below the floor 65536"
                )
            }
            Self::LocalFrameSizeBelowFloor { proposed } => {
                write!(
                    formatter,
                    "the local maximum frame size {proposed} is below the floor 65536"
                )
            }
            Self::LocalMetadataSizeBelowFloor { proposed } => {
                write!(
                    formatter,
                    "the local maximum metadata size {proposed} is below the floor 4096"
                )
            }
        }
    }
}

impl std::error::Error for ConnectionConfigError {}

/// The typed configuration a connection is opened from.
///
/// The desired maximum frame size is the proposal the handshake carries;
/// the negotiated value derives from it and the responder ceiling. The
/// local maximum frame and metadata sizes are this client's own caps: a
/// handshake that negotiates above either is refused locally and the
/// connection never becomes usable. The local caps never raise a
/// negotiated bound; the effective bound in force is the stricter of the
/// two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    endpoint: String,
    desired_maximum_frame_size: u32,
    local_maximum_frame_size: u64,
    local_maximum_metadata_size: u16,
}

impl ConnectionConfig {
    /// Builds a configuration for `endpoint` with the protocol defaults.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            desired_maximum_frame_size: DEFAULT_DESIRED_MAXIMUM_FRAME_SIZE,
            local_maximum_frame_size: DEFAULT_LOCAL_MAXIMUM_FRAME_SIZE,
            local_maximum_metadata_size: DEFAULT_LOCAL_MAXIMUM_METADATA_SIZE,
        }
    }

    /// Sets the desired maximum frame size the handshake proposes.
    ///
    /// A proposal above the local maximum frame size risks a local refusal:
    /// when the negotiated value exceeds the local cap the handshake fails
    /// and no connection is returned.
    #[must_use]
    pub const fn desired_maximum_frame_size(mut self, value: u32) -> Self {
        self.desired_maximum_frame_size = value;
        self
    }

    /// Sets the local cap on the negotiated maximum frame size.
    #[must_use]
    pub const fn local_maximum_frame_size(mut self, value: u64) -> Self {
        self.local_maximum_frame_size = value;
        self
    }

    /// Sets the local cap on the negotiated maximum metadata size.
    #[must_use]
    pub const fn local_maximum_metadata_size(mut self, value: u16) -> Self {
        self.local_maximum_metadata_size = value;
        self
    }

    /// Returns the endpoint the configuration names.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the desired maximum frame size the handshake will propose.
    #[must_use]
    pub const fn desired_maximum_frame_size_value(&self) -> u32 {
        self.desired_maximum_frame_size
    }

    /// Returns the local cap on the negotiated maximum frame size.
    #[must_use]
    pub const fn local_maximum_frame_size_value(&self) -> u64 {
        self.local_maximum_frame_size
    }

    /// Returns the local cap on the negotiated maximum metadata size.
    #[must_use]
    pub const fn local_maximum_metadata_size_value(&self) -> u16 {
        self.local_maximum_metadata_size
    }

    /// Validates the configuration before any connection is opened.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionConfigError::EmptyEndpoint`] when the endpoint is
    /// empty, [`ConnectionConfigError::FrameSizeBelowFloor`] when the
    /// desired maximum frame size lies below the protocol floor, and the
    /// local variants when a local cap lies below its protocol floor.
    pub fn validate(&self) -> Result<(), ConnectionConfigError> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectionConfigError::EmptyEndpoint);
        }
        if u64::from(self.desired_maximum_frame_size) < MINIMUM_NEGOTIATED_FRAME_SIZE {
            return Err(ConnectionConfigError::FrameSizeBelowFloor {
                proposed: self.desired_maximum_frame_size,
            });
        }
        if self.local_maximum_frame_size < MINIMUM_NEGOTIATED_FRAME_SIZE {
            return Err(ConnectionConfigError::LocalFrameSizeBelowFloor {
                proposed: self.local_maximum_frame_size,
            });
        }
        if self.local_maximum_metadata_size < MINIMUM_NEGOTIATED_METADATA_SIZE {
            return Err(ConnectionConfigError::LocalMetadataSizeBelowFloor {
                proposed: self.local_maximum_metadata_size,
            });
        }
        Ok(())
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::new("127.0.0.1:6379")
    }
}

/// A failure that prevents a connection from becoming usable.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The configuration was invalid before any connection was opened.
    InvalidConfiguration(ConnectionConfigError),
    /// The transport failed to establish or failed during the handshake.
    Transport(std::io::Error),
    /// The peer violated the protocol or sent a malformed handshake.
    HandshakeFailure(Failure),
    /// The peer closed the transport before the handshake completed.
    ClosedDuringHandshake,
    /// The negotiated maximum frame size exceeded the local cap, so the
    /// handshake was refused locally and no connection was returned.
    NegotiatedFrameSizeAboveLocal {
        /// The value the handshake response stated.
        negotiated: u64,
        /// The local cap the configuration states.
        local: u64,
    },
    /// The negotiated maximum metadata size exceeded the local cap, so the
    /// handshake was refused locally and no connection was returned.
    NegotiatedMetadataSizeAboveLocal {
        /// The value the handshake response stated.
        negotiated: u16,
        /// The local cap the configuration states.
        local: u16,
    },
    /// The peer sent a frame that is not the handshake response.
    UnexpectedFrame,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(error) => {
                write!(formatter, "invalid configuration: {error}")
            }
            Self::Transport(error) => write!(formatter, "transport failure: {error}"),
            Self::HandshakeFailure(failure) => {
                write!(formatter, "handshake failed: {}", failure.class().name())
            }
            Self::ClosedDuringHandshake => {
                formatter.write_str("the peer closed during the handshake")
            }
            Self::NegotiatedFrameSizeAboveLocal { negotiated, local } => {
                write!(
                    formatter,
                    "the negotiated maximum frame size {negotiated} exceeds the local cap {local}"
                )
            }
            Self::NegotiatedMetadataSizeAboveLocal { negotiated, local } => {
                write!(
                    formatter,
                    "the negotiated maximum metadata size {negotiated} exceeds the local cap {local}"
                )
            }
            Self::UnexpectedFrame => formatter.write_str("the peer sent an unexpected frame"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::HandshakeFailure(_)
            | Self::ClosedDuringHandshake
            | Self::NegotiatedFrameSizeAboveLocal { .. }
            | Self::NegotiatedMetadataSizeAboveLocal { .. }
            | Self::UnexpectedFrame => None,
        }
    }
}

/// The state the connection owns after negotiation.
#[derive(Debug)]
struct Negotiated {
    protocol_version: u16,
    maximum_frame_size: u64,
    maximum_metadata_size: u16,
    accepted_capabilities: Vec<u16>,
    local_maximum_frame_size: u64,
    local_maximum_metadata_size: u16,
}

/// The lifecycle state of a connection.
///
/// A connection is usable only after the handshake completes. Closing runs
/// while an explicit shutdown is in progress. Closed, failed, and unusable
/// are terminal: a connection that reaches one never becomes usable again.
///
/// The states map onto the protocol connection states as follows: usable
/// and closing are the negotiated state, and closed, failed, and unusable
/// are the terminal state. The three terminal states keep why the session
/// ended: closed after an orderly shutdown, failed after a transport
/// failure, unusable after a failure that made continued protocol
/// operation unsafe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// The handshake completed and the connection accepts no new work yet
    /// runs no command; it is open and has not entered shutdown or failure.
    Usable,
    /// An explicit shutdown started and the transport close is pending.
    Closing,
    /// An orderly shutdown completed.
    Closed,
    /// The transport failed.
    Failed,
    /// Continued protocol operation became unsafe. The establishment path
    /// reports such a failure through [`ConnectError`] and returns no
    /// connection, so this state is first reached by failures detected
    /// after establishment.
    Unusable,
}

impl ConnectionState {
    /// Returns the protocol connection state this lifecycle state occupies.
    #[must_use]
    pub const fn protocol_state(self) -> protocol::ConnectionState {
        match self {
            Self::Usable | Self::Closing => protocol::ConnectionState::Negotiated,
            Self::Closed | Self::Failed | Self::Unusable => protocol::ConnectionState::Terminal,
        }
    }

    /// Returns whether the connection is usable.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Usable)
    }
}

/// A usable protocol version 0 connection.
///
/// A `Connection` is returned only after the handshake completes. It owns
/// its transport and its negotiated session state. It exposes no command;
/// a later revision adds the command surface.
///
/// Dropping a `Connection` without calling [`Connection::close`] closes
/// the transport without waiting and releases local resources. It sends
/// no protocol exchange and rolls nothing back. Callers that need a
/// deterministic shutdown call `close`.
#[derive(Debug)]
pub struct Connection {
    transport: AnyTransport,
    negotiated: Negotiated,
    state: ConnectionState,
}

impl Connection {
    /// Opens a transport to the configured endpoint and completes the
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::InvalidConfiguration`] when the configuration
    /// is invalid, [`ConnectError::Transport`] when the transport fails,
    /// [`ConnectError::ClosedDuringHandshake`] when the peer closes before
    /// the handshake completes, [`ConnectError::NegotiatedFrameSizeAboveLocal`]
    /// or [`ConnectError::NegotiatedMetadataSizeAboveLocal`] when the
    /// negotiated bound exceeds the local cap, and
    /// [`ConnectError::HandshakeFailure`] or [`ConnectError::UnexpectedFrame`]
    /// when the peer's response is not a valid handshake response.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self, ConnectError> {
        config
            .validate()
            .map_err(ConnectError::InvalidConfiguration)?;
        let transport = TokioTransport::connect(config.endpoint())
            .await
            .map_err(ConnectError::Transport)?;
        Self::establish(AnyTransport::Tcp(transport), config).await
    }

    /// Runs the handshake over an already established transport.
    async fn establish(
        mut transport: AnyTransport,
        config: &ConnectionConfig,
    ) -> Result<Self, ConnectError> {
        let mut allocator = RequestIdAllocator::new();
        let mut in_flight = InFlightRegistry::new();
        let handshake_id = allocator.allocate();
        if handshake_id != HANDSHAKE_REQUEST_ID {
            return Err(ConnectError::HandshakeFailure(Failure::protocol_violation()));
        }
        if in_flight.insert(handshake_id).is_err() {
            return Err(ConnectError::HandshakeFailure(Failure::protocol_violation()));
        }
        let frame = build_handshake_request(config, handshake_id)?;
        write_all(&mut transport, &frame).await?;
        let negotiated = read_handshake_response(&mut transport, config, handshake_id).await?;
        let _ = in_flight.retire(handshake_id);
        let live = in_flight.live_ids();
        if in_flight.contains(handshake_id)
            || !in_flight.is_empty()
            || in_flight.len() != live.len()
            || !live.is_empty()
        {
            return Err(ConnectError::HandshakeFailure(Failure::protocol_violation()));
        }
        if negotiated.maximum_frame_size > config.local_maximum_frame_size_value() {
            let _ = transport.shutdown().await;
            return Err(ConnectError::NegotiatedFrameSizeAboveLocal {
                negotiated: negotiated.maximum_frame_size,
                local: config.local_maximum_frame_size_value(),
            });
        }
        if negotiated.maximum_metadata_size > config.local_maximum_metadata_size_value() {
            let _ = transport.shutdown().await;
            return Err(ConnectError::NegotiatedMetadataSizeAboveLocal {
                negotiated: negotiated.maximum_metadata_size,
                local: config.local_maximum_metadata_size_value(),
            });
        }
        Ok(Self {
            transport,
            negotiated,
            state: ConnectionState::Usable,
        })
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.negotiated.protocol_version
    }

    /// Returns the negotiated maximum frame size.
    #[must_use]
    pub const fn maximum_frame_size(&self) -> u64 {
        self.negotiated.maximum_frame_size
    }

    /// Returns the negotiated maximum metadata size.
    #[must_use]
    pub const fn maximum_metadata_size(&self) -> u16 {
        self.negotiated.maximum_metadata_size
    }

    /// Returns the local cap on the negotiated maximum frame size.
    #[must_use]
    pub const fn local_maximum_frame_size(&self) -> u64 {
        self.negotiated.local_maximum_frame_size
    }

    /// Returns the local cap on the negotiated maximum metadata size.
    #[must_use]
    pub const fn local_maximum_metadata_size(&self) -> u16 {
        self.negotiated.local_maximum_metadata_size
    }

    /// Returns the effective maximum frame size: the stricter of the
    /// negotiated bound and the local cap.
    ///
    /// Establishment refuses a handshake that negotiates above the local
    /// cap, so on a usable connection the effective bound equals the
    /// negotiated one. Later request admission reads this bound rather
    /// than the negotiated value alone.
    #[must_use]
    pub const fn effective_maximum_frame_size(&self) -> u64 {
        if self.negotiated.maximum_frame_size < self.negotiated.local_maximum_frame_size {
            self.negotiated.maximum_frame_size
        } else {
            self.negotiated.local_maximum_frame_size
        }
    }

    /// Returns the effective maximum metadata size: the stricter of the
    /// negotiated bound and the local cap.
    #[must_use]
    pub const fn effective_maximum_metadata_size(&self) -> u16 {
        if self.negotiated.maximum_metadata_size < self.negotiated.local_maximum_metadata_size {
            self.negotiated.maximum_metadata_size
        } else {
            self.negotiated.local_maximum_metadata_size
        }
    }

    /// Returns the accepted capability identifiers.
    #[must_use]
    pub fn accepted_capabilities(&self) -> &[u16] {
        &self.negotiated.accepted_capabilities
    }

    /// Returns the lifecycle state of the connection.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Returns whether the connection is usable. This is false after close.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.state.is_usable()
    }

    /// Closes the connection.
    ///
    /// Closing stops admission, shuts the transport down, and moves the
    /// connection to [`ConnectionState::Closed`]. When the transport
    /// shutdown fails, the connection moves to [`ConnectionState::Failed`]
    /// instead and the error is returned. Closing an already closed
    /// connection succeeds without touching the transport.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error, leaving the connection in
    /// the failed state.
    pub async fn close(&mut self) -> Result<(), std::io::Error> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }
        self.state = ConnectionState::Closing;
        match self.transport.shutdown().await {
            Ok(()) => {
                self.state = ConnectionState::Closed;
                Ok(())
            }
            Err(error) => {
                self.state = ConnectionState::Failed;
                Err(error)
            }
        }
    }
}

/// Builds the handshake request frame the offerer sends first.
fn build_handshake_request(
    config: &ConnectionConfig,
    request_id: u64,
) -> Result<Vec<u8>, ConnectError> {
    let request = HandshakeRequest::new(
        0,
        0,
        config.desired_maximum_frame_size_value(),
        CapabilityEntries::new(Vec::new()),
    );
    let payload = request.encode();
    let outgoing = Outgoing {
        kind: Kind::Request,
        code: HANDSHAKE_OPCODE,
        request_id,
        metadata: &[],
        payload: OutgoingPayload::Opaque(&payload),
    };
    protocol::encode(&outgoing)
        .map_err(|_| ConnectError::HandshakeFailure(Failure::resource_limit()))
}

/// Writes every byte of `bytes`, tolerating short writes.
async fn write_all(transport: &mut AnyTransport, bytes: &[u8]) -> Result<(), ConnectError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = bytes.get(offset..).unwrap_or(&[]);
        let written = transport
            .write(remaining)
            .await
            .map_err(ConnectError::Transport)?;
        if written == 0 {
            return Err(ConnectError::Transport(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "the transport wrote no bytes",
            )));
        }
        offset = offset.checked_add(written).ok_or_else(|| {
            ConnectError::Transport(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the transport reported too many bytes written",
            ))
        })?;
    }
    Ok(())
}

/// Reads frames until the handshake response arrives and owns its values.
///
/// The read buffer grows only with bytes actually received and never past
/// the stricter of the pre-negotiation protocol bound and the local cap.
async fn read_handshake_response(
    transport: &mut AnyTransport,
    config: &ConnectionConfig,
    handshake_id: u64,
) -> Result<Negotiated, ConnectError> {
    let buffer_cap = config.local_maximum_frame_size_value().min(MAX_FRAME_SIZE);
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        let admission = Admission {
            role: Role::Client,
            state: protocol::ConnectionState::PreNegotiation,
            limits: Limits::PRE_NEGOTIATION,
            in_flight: std::slice::from_ref(&handshake_id),
        };
        match protocol::decode(&buffer, admission) {
            Step::Frame(frame) => return interpret_response(&frame, config),
            Step::Failure { failure, .. } => return Err(ConnectError::HandshakeFailure(failure)),
            Step::Need(required) => {
                let bound = usize::try_from(buffer_cap).unwrap_or(usize::MAX);
                if required > bound || buffer.len() >= bound {
                    return Err(ConnectError::HandshakeFailure(Failure::resource_limit()));
                }
                let mut chunk = [0u8; READ_CHUNK];
                let read = transport
                    .read(&mut chunk)
                    .await
                    .map_err(ConnectError::Transport)?;
                if read == 0 {
                    return Err(ConnectError::ClosedDuringHandshake);
                }
                let part = chunk.get(..read).unwrap_or(&[]);
                buffer.extend_from_slice(part);
            }
        }
    }
}

/// Interprets the admitted terminal frame of the handshake.
fn interpret_response(
    frame: &protocol::Frame<'_>,
    config: &ConnectionConfig,
) -> Result<Negotiated, ConnectError> {
    let header = frame.header();
    match header.kind() {
        Kind::Response if header.code() == 0 => {
            let Payload::Opaque(payload) = frame.payload() else {
                return Err(ConnectError::UnexpectedFrame);
            };
            let response = HandshakeResponse::decode(payload, &OFFER)
                .map_err(ConnectError::HandshakeFailure)?;
            Ok(Negotiated {
                protocol_version: response.negotiated_protocol_version(),
                maximum_frame_size: u64::from(response.negotiated_maximum_frame_size()),
                maximum_metadata_size: response.negotiated_maximum_metadata_size(),
                accepted_capabilities: response
                    .accepted_capability_entries()
                    .entries()
                    .iter()
                    .map(|entry| entry.identifier())
                    .collect(),
                local_maximum_frame_size: config.local_maximum_frame_size_value(),
                local_maximum_metadata_size: config.local_maximum_metadata_size_value(),
            })
        }
        Kind::Error => {
            let failure = ErrorClass::from_wire(header.code())
                .map_or_else(Failure::protocol_violation, |class| {
                    Failure::new(class, class.scope())
                });
            Err(ConnectError::HandshakeFailure(failure))
        }
        _ => Err(ConnectError::UnexpectedFrame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorClass, FailureScope};
    use crate::transport::InMemoryTransport;

    /// Builds a handshake response payload.
    fn response_payload(
        version: u16,
        frame_size: u32,
        metadata_size: u16,
        entries: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&version.to_le_bytes());
        payload.extend_from_slice(&frame_size.to_le_bytes());
        payload.extend_from_slice(&metadata_size.to_le_bytes());
        let count = u16::try_from(entries.len()).unwrap_or(u16::MAX);
        payload.extend_from_slice(&count.to_le_bytes());
        for (identifier, value) in entries {
            payload.extend_from_slice(&identifier.to_le_bytes());
            let value_length = u16::try_from(value.len()).unwrap_or(u16::MAX);
            payload.extend_from_slice(&value_length.to_le_bytes());
            payload.extend_from_slice(value);
        }
        payload
    }

    /// Wraps a handshake response payload in a success response frame.
    fn response_frame(
        version: u16,
        frame_size: u32,
        metadata_size: u16,
        entries: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let payload = response_payload(version, frame_size, metadata_size, entries);
        let outgoing = Outgoing {
            kind: Kind::Response,
            code: 0,
            request_id: HANDSHAKE_REQUEST_ID,
            metadata: &[],
            payload: OutgoingPayload::Opaque(&payload),
        };
        protocol::encode(&outgoing).unwrap_or_default()
    }

    fn memory(inbound: &[u8], read_step: usize, write_step: usize) -> AnyTransport {
        AnyTransport::Memory(InMemoryTransport::new(inbound, read_step, write_step))
    }

    #[test]
    fn the_lifecycle_states_map_onto_the_protocol_states() {
        use crate::protocol::ConnectionState as ProtocolState;
        assert_eq!(
            ConnectionState::Usable.protocol_state(),
            ProtocolState::Negotiated
        );
        assert_eq!(
            ConnectionState::Closing.protocol_state(),
            ProtocolState::Negotiated
        );
        assert_eq!(
            ConnectionState::Closed.protocol_state(),
            ProtocolState::Terminal
        );
        assert_eq!(
            ConnectionState::Failed.protocol_state(),
            ProtocolState::Terminal
        );
        assert_eq!(
            ConnectionState::Unusable.protocol_state(),
            ProtocolState::Terminal
        );
        assert!(ConnectionState::Usable.is_usable());
        assert!(!ConnectionState::Closing.is_usable());
        assert!(!ConnectionState::Closed.is_usable());
        assert!(!ConnectionState::Failed.is_usable());
        assert!(!ConnectionState::Unusable.is_usable());
    }

    #[tokio::test]
    async fn close_moves_a_usable_connection_to_closed() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let mut connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.state(), ConnectionState::Usable);
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Closed);
        assert!(!connection.is_usable());
        Ok(())
    }

    #[tokio::test]
    async fn a_second_close_succeeds_without_touching_the_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let mut connection = Connection::establish(transport, &config).await?;
        connection.close().await?;
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Closed);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_shutdown_moves_the_connection_to_failed()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let inbound = response_frame(0, 65_536, 4_096, &[]);
        let transport =
            AnyTransport::Memory(InMemoryTransport::new(&inbound, 4_096, 4_096).fail_on_shutdown());
        let mut connection = Connection::establish(transport, &config).await?;
        assert!(connection.close().await.is_err());
        assert_eq!(connection.state(), ConnectionState::Failed);
        assert!(!connection.is_usable());
        Ok(())
    }

    #[test]
    fn an_empty_endpoint_is_refused() {
        let config = ConnectionConfig::new("   ");
        assert_eq!(config.validate(), Err(ConnectionConfigError::EmptyEndpoint));
    }

    #[test]
    fn a_frame_size_below_the_floor_is_refused() {
        let config = ConnectionConfig::new("127.0.0.1:6379").desired_maximum_frame_size(1_000);
        assert_eq!(
            config.validate(),
            Err(ConnectionConfigError::FrameSizeBelowFloor { proposed: 1_000 })
        );
    }

    #[test]
    fn a_local_frame_size_below_the_floor_is_refused() {
        let config = ConnectionConfig::new("127.0.0.1:6379").local_maximum_frame_size(1_000);
        assert_eq!(
            config.validate(),
            Err(ConnectionConfigError::LocalFrameSizeBelowFloor { proposed: 1_000 })
        );
    }

    #[test]
    fn a_local_metadata_size_below_the_floor_is_refused() {
        let config = ConnectionConfig::new("127.0.0.1:6379").local_maximum_metadata_size(1_000);
        assert_eq!(
            config.validate(),
            Err(ConnectionConfigError::LocalMetadataSizeBelowFloor { proposed: 1_000 })
        );
    }

    #[test]
    fn the_default_local_caps_are_the_protocol_floors() {
        let config = ConnectionConfig::new("127.0.0.1:6379");
        assert_eq!(config.local_maximum_frame_size_value(), 65_536);
        assert_eq!(config.local_maximum_metadata_size_value(), 4_096);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn the_default_configuration_is_valid() {
        assert_eq!(ConnectionConfig::new("127.0.0.1:6379").validate(), Ok(()));
    }

    #[test]
    fn the_first_frame_is_the_handshake_request() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("127.0.0.1:6379");
        let frame = build_handshake_request(&config, HANDSHAKE_REQUEST_ID)?;
        assert_eq!(frame.first().copied(), Some(0), "version");
        assert_eq!(frame.get(1).copied(), Some(1), "REQUEST");
        assert_eq!(
            frame.get(4..6),
            Some(&HANDSHAKE_OPCODE.to_le_bytes()[..]),
            "handshake opcode"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_valid_handshake_yields_a_usable_connection() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.protocol_version(), 0);
        assert_eq!(connection.maximum_frame_size(), 65_536);
        assert_eq!(connection.maximum_metadata_size(), 4_096);
        assert!(connection.accepted_capabilities().is_empty());
        assert_eq!(connection.state(), ConnectionState::Usable);
        assert!(connection.is_usable());
        Ok(())
    }

    #[tokio::test]
    async fn a_fragmented_and_partially_written_handshake_completes()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 1, 1);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.protocol_version(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_response_below_the_frame_floor_is_malformed()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 1_000, 4_096, &[]), 4_096, 4_096);
        match Connection::establish(transport, &config).await {
            Err(ConnectError::HandshakeFailure(failure)) => {
                assert_eq!(failure.class(), ErrorClass::MalformedRequest);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => return Err(format!("expected a malformed handshake, got {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_version_outside_the_offer_is_malformed() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(1, 65_536, 4_096, &[]), 4_096, 4_096);
        match Connection::establish(transport, &config).await {
            Err(ConnectError::HandshakeFailure(failure)) => {
                assert_eq!(failure.class(), ErrorClass::MalformedRequest);
            }
            other => return Err(format!("expected a malformed handshake, got {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_accepted_unoffered_capability_is_a_protocol_violation()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[(1, &[])]), 4_096, 4_096);
        match Connection::establish(transport, &config).await {
            Err(ConnectError::HandshakeFailure(failure)) => {
                assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
                assert_eq!(failure.scope(), FailureScope::ConnectionFatal);
            }
            other => return Err(format!("expected a protocol violation, got {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_usable_connection_exposes_local_and_effective_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory")
            .desired_maximum_frame_size(131_072)
            .local_maximum_frame_size(131_072)
            .local_maximum_metadata_size(8_192);
        let transport = memory(&response_frame(0, 131_072, 8_192, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.maximum_frame_size(), 131_072);
        assert_eq!(connection.maximum_metadata_size(), 8_192);
        assert_eq!(connection.local_maximum_frame_size(), 131_072);
        assert_eq!(connection.local_maximum_metadata_size(), 8_192);
        assert_eq!(connection.effective_maximum_frame_size(), 131_072);
        assert_eq!(connection.effective_maximum_metadata_size(), 8_192);
        Ok(())
    }

    #[tokio::test]
    async fn a_negotiated_frame_size_above_the_local_cap_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory").desired_maximum_frame_size(131_072);
        assert_eq!(config.local_maximum_frame_size_value(), 65_536);
        let transport = memory(&response_frame(0, 131_072, 4_096, &[]), 4_096, 4_096);
        match Connection::establish(transport, &config).await {
            Err(ConnectError::NegotiatedFrameSizeAboveLocal { negotiated, local }) => {
                assert_eq!(negotiated, 131_072);
                assert_eq!(local, 65_536);
            }
            other => return Err(format!("expected a local refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_negotiated_metadata_size_above_the_local_cap_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 8_192, &[]), 4_096, 4_096);
        match Connection::establish(transport, &config).await {
            Err(ConnectError::NegotiatedMetadataSizeAboveLocal { negotiated, local }) => {
                assert_eq!(negotiated, 8_192);
                assert_eq!(local, 4_096);
            }
            other => return Err(format!("expected a local refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_transport_that_closes_during_the_handshake_is_reported()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&[], 4_096, 4_096);
        match Connection::establish(transport, &config).await {
            Err(ConnectError::ClosedDuringHandshake) => Ok(()),
            other => Err(format!("expected a closed handshake, got {other:?}").into()),
        }
    }

    #[tokio::test]
    async fn a_partial_write_moves_every_byte() -> Result<(), Box<dyn std::error::Error>> {
        let mut transport = memory(&[], 1, 1);
        write_all(&mut transport, b"handshake").await?;
        match &transport {
            AnyTransport::Memory(memory) => {
                assert_eq!(memory.written(), b"handshake".as_slice());
            }
            AnyTransport::Tcp(_) => return Err("expected the in-memory transport".into()),
        }
        Ok(())
    }
}

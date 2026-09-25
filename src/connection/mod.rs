//! Connection configuration and the version 0 handshake.
//!
//! A connection becomes usable only after the handshake completes. This
//! module owns the public configuration, the connect path, the handshake
//! exchange as untrusted input, and the negotiated session state the
//! connection exposes.
//!
//! It owns no command surface. A connection negotiates and closes; it runs
//! no operation.

use std::fmt;

use crate::protocol::{
    self, Admission, CapabilityEntries, ConnectionState, ErrorClass, Failure, HANDSHAKE_OPCODE,
    HandshakeOffer, HandshakeRequest, HandshakeResponse, Kind, Limits, MAX_FRAME_SIZE,
    MINIMUM_NEGOTIATED_FRAME_SIZE, Outgoing, OutgoingPayload, Payload, Role, Step,
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
        }
    }
}

impl std::error::Error for ConnectionConfigError {}

/// The typed configuration a connection is opened from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    endpoint: String,
    desired_maximum_frame_size: u32,
}

impl ConnectionConfig {
    /// Builds a configuration for `endpoint` with the protocol defaults.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            desired_maximum_frame_size: DEFAULT_DESIRED_MAXIMUM_FRAME_SIZE,
        }
    }

    /// Sets the desired maximum frame size the handshake proposes.
    #[must_use]
    pub const fn desired_maximum_frame_size(mut self, value: u32) -> Self {
        self.desired_maximum_frame_size = value;
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

    /// Returns the local maximum metadata size in force.
    #[must_use]
    pub const fn maximum_metadata_size(&self) -> u16 {
        protocol::MAX_METADATA_SIZE
    }

    /// Validates the configuration before any connection is opened.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionConfigError::EmptyEndpoint`] when the endpoint is
    /// empty and [`ConnectionConfigError::FrameSizeBelowFloor`] when the
    /// desired maximum frame size lies below the protocol floor.
    pub fn validate(&self) -> Result<(), ConnectionConfigError> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectionConfigError::EmptyEndpoint);
        }
        if u64::from(self.desired_maximum_frame_size) < MINIMUM_NEGOTIATED_FRAME_SIZE {
            return Err(ConnectionConfigError::FrameSizeBelowFloor {
                proposed: self.desired_maximum_frame_size,
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
            Self::UnexpectedFrame => formatter.write_str("the peer sent an unexpected frame"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::HandshakeFailure(_) | Self::ClosedDuringHandshake | Self::UnexpectedFrame => None,
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
}

/// The lifecycle state of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    /// The handshake completed and the connection is usable.
    Negotiated,
    /// The connection was closed.
    Closed,
}

/// A usable protocol version 0 connection.
///
/// A `Connection` is returned only after the handshake completes. It owns
/// its transport and its negotiated session state. It exposes no command;
/// a later revision adds the command surface.
#[derive(Debug)]
pub struct Connection {
    transport: AnyTransport,
    negotiated: Negotiated,
    lifecycle: Lifecycle,
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
    /// the handshake completes, and [`ConnectError::HandshakeFailure`] or
    /// [`ConnectError::UnexpectedFrame`] when the peer's response is not a
    /// valid handshake response.
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
        let frame = build_handshake_request(config)?;
        write_all(&mut transport, &frame).await?;
        let negotiated = read_handshake_response(&mut transport).await?;
        Ok(Self {
            transport,
            negotiated,
            lifecycle: Lifecycle::Negotiated,
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

    /// Returns the accepted capability identifiers.
    #[must_use]
    pub fn accepted_capabilities(&self) -> &[u16] {
        &self.negotiated.accepted_capabilities
    }

    /// Returns whether the connection is usable. This is false after close.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Negotiated)
    }

    /// Closes the connection.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error.
    pub async fn close(mut self) -> Result<(), std::io::Error> {
        self.lifecycle = Lifecycle::Closed;
        self.transport.shutdown().await
    }
}

/// Builds the handshake request frame the offerer sends first.
fn build_handshake_request(config: &ConnectionConfig) -> Result<Vec<u8>, ConnectError> {
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
        request_id: HANDSHAKE_REQUEST_ID,
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
async fn read_handshake_response(transport: &mut AnyTransport) -> Result<Negotiated, ConnectError> {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        let admission = Admission {
            role: Role::Client,
            state: ConnectionState::PreNegotiation,
            limits: Limits::PRE_NEGOTIATION,
            in_flight: &[HANDSHAKE_REQUEST_ID],
        };
        match protocol::decode(&buffer, admission) {
            Step::Frame(frame) => return interpret_response(&frame),
            Step::Failure { failure, .. } => return Err(ConnectError::HandshakeFailure(failure)),
            Step::Need(required) => {
                let bound = usize::try_from(MAX_FRAME_SIZE).unwrap_or(usize::MAX);
                if required > bound {
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
fn interpret_response(frame: &protocol::Frame<'_>) -> Result<Negotiated, ConnectError> {
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
    fn the_default_configuration_is_valid() {
        assert_eq!(ConnectionConfig::new("127.0.0.1:6379").validate(), Ok(()));
    }

    #[test]
    fn the_first_frame_is_the_handshake_request() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("127.0.0.1:6379");
        let frame = build_handshake_request(&config)?;
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

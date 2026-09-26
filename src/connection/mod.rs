//! Connection configuration, the version 0 handshake, and the core commands.
//!
//! A connection becomes usable only after the handshake completes. This
//! module owns the public configuration, the connect path, the handshake
//! exchange as untrusted input, the negotiated session state the
//! connection exposes, the explicit lifecycle state of the connection,
//! and the five core operations through typed binary-safe methods.

mod dispatch;
mod driver;

use std::fmt;
use std::sync::Arc;

use dispatch::{InFlightRegistry, RequestIdAllocator};
use driver::{DriverError, Submit};

use crate::command;
use crate::protocol::{
    self, Admission, CapabilityEntries, ErrorClass, Failure, FailureScope, HANDSHAKE_OPCODE,
    HandshakeOffer, HandshakeRequest, HandshakeResponse, Kind, Limits, MAX_FRAME_SIZE,
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

/// The default bound on concurrent in-flight requests.
const DEFAULT_MAXIMUM_IN_FLIGHT: usize = 64;

/// The minimum bound on concurrent in-flight requests.
const MINIMUM_MAXIMUM_IN_FLIGHT: usize = 1;

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
    /// The maximum in-flight bound lies below the minimum of 1.
    InFlightBoundBelowMinimum {
        /// The proposed value.
        proposed: usize,
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
            Self::InFlightBoundBelowMinimum { proposed } => {
                write!(
                    formatter,
                    "the maximum in-flight bound {proposed} is below the minimum 1"
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
///
/// The maximum in-flight bound caps how many requests may be admitted at
/// once on one connection. A full connection applies backpressure by
/// waiting while usable; failure or shutdown wakes every waiter with a
/// structured error. The default of 64 aligns with the default server
/// admission in evidence and stays proportional in bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    endpoint: String,
    desired_maximum_frame_size: u32,
    local_maximum_frame_size: u64,
    local_maximum_metadata_size: u16,
    maximum_in_flight: usize,
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
            maximum_in_flight: DEFAULT_MAXIMUM_IN_FLIGHT,
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

    /// Sets the bound on concurrent in-flight requests.
    ///
    /// The minimum is 1. A bound of 1 serializes admission without
    /// deadlock; the default of 64 keeps bookkeeping proportional to the
    /// bound.
    #[must_use]
    pub const fn maximum_in_flight(mut self, value: usize) -> Self {
        self.maximum_in_flight = value;
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

    /// Returns the bound on concurrent in-flight requests.
    #[must_use]
    pub const fn maximum_in_flight_value(&self) -> usize {
        self.maximum_in_flight
    }

    /// Validates the configuration before any connection is opened.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionConfigError::EmptyEndpoint`] when the endpoint is
    /// empty, [`ConnectionConfigError::FrameSizeBelowFloor`] when the
    /// desired maximum frame size lies below the protocol floor, the local
    /// variants when a local cap lies below its protocol floor, and
    /// [`ConnectionConfigError::InFlightBoundBelowMinimum`] when the
    /// in-flight bound lies below 1.
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
        if self.maximum_in_flight < MINIMUM_MAXIMUM_IN_FLIGHT {
            return Err(ConnectionConfigError::InFlightBoundBelowMinimum {
                proposed: self.maximum_in_flight,
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

/// The outcome of a `GET` request.
///
/// A present empty value and a missing key are different variants; the
/// caller never parses a length to tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetOutcome {
    /// The key exists and holds these value bytes, possibly empty.
    Present(Vec<u8>),
    /// The key does not exist.
    Absent,
    /// The key exists and the responder keeps its value outside memory.
    HeldOutsideMemory {
        /// The logical length in bytes of the value the key holds.
        logical_length: u64,
    },
}

/// A structured failure of one command.
///
/// Server refusal, server failure, transport failure, protocol failure,
/// local refusal, and ambiguous completion stay distinguishable where
/// the distinction affects caller behavior. Diagnostic text from the
/// server never defines the error contract.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommandError {
    /// The request exceeded a local bound before any byte was sent.
    LocalLimitExceeded {
        /// The size the request would have occupied on the wire.
        requested: u64,
        /// The effective bound in force.
        limit: u64,
    },
    /// The request could not be represented on the wire.
    InvalidRequest,
    /// The responder does not serve the named operation.
    UnsupportedOperation,
    /// The responder parsed the request and rejects a value it carries.
    InvalidArgument,
    /// The responder could not admit the resources the request needs.
    Overloaded,
    /// The key is held in a representation the operation does not act on.
    WrongType,
    /// The responder met a condition it did not anticipate.
    ///
    /// The mutation may have taken effect. A caller that must know
    /// re-reads the key. This error is never retried automatically.
    InternalError,
    /// The peer sent data that violates the contract.
    ProtocolViolation,
    /// The peer could not parse the frame.
    MalformedRequest,
    /// A frame exceeds the maximum frame size in force.
    ResourceLimit,
    /// The frame names a protocol version the receiver does not implement.
    UnsupportedProtocolVersion,
    /// The transport failed.
    Transport(std::io::Error),
    /// The connection closed with the request in flight.
    Closed,
    /// The session became unusable after a protocol violation.
    Unusable,
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalLimitExceeded { requested, limit } => write!(
                formatter,
                "the request size {requested} exceeds the effective limit {limit}"
            ),
            Self::InvalidRequest => formatter.write_str("the request cannot be represented"),
            Self::UnsupportedOperation => formatter.write_str("unsupported operation"),
            Self::InvalidArgument => formatter.write_str("invalid argument"),
            Self::Overloaded => formatter.write_str("overloaded"),
            Self::WrongType => formatter.write_str("wrong type"),
            Self::InternalError => formatter
                .write_str("internal error: the mutation may have taken effect; re-read to decide"),
            Self::ProtocolViolation => formatter.write_str("protocol violation"),
            Self::MalformedRequest => formatter.write_str("malformed request"),
            Self::ResourceLimit => formatter.write_str("resource limit"),
            Self::UnsupportedProtocolVersion => formatter.write_str("unsupported protocol version"),
            Self::Transport(error) => write!(formatter, "transport failure: {error}"),
            Self::Closed => formatter.write_str("the connection closed"),
            Self::Unusable => formatter.write_str("the session is unusable"),
        }
    }
}

impl std::error::Error for CommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl CommandError {
    /// Returns whether the mutation may have taken effect.
    ///
    /// Only the internal error class is ambiguous at this revision;
    /// transport, close, and unusable outcomes are also reported as
    /// ambiguous because no terminal response establishes completion.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(
            self,
            Self::InternalError | Self::Transport(_) | Self::Closed | Self::Unusable
        )
    }

    /// Returns the failure scope when the error carries a protocol class.
    #[must_use]
    pub const fn scope(&self) -> Option<FailureScope> {
        match self {
            Self::UnsupportedOperation
            | Self::InvalidArgument
            | Self::Overloaded
            | Self::WrongType
            | Self::InternalError => Some(FailureScope::RequestScoped),
            Self::ProtocolViolation
            | Self::MalformedRequest
            | Self::ResourceLimit
            | Self::UnsupportedProtocolVersion => Some(FailureScope::ConnectionFatal),
            _ => None,
        }
    }

    const fn from_class(class: ErrorClass) -> Self {
        match class {
            ErrorClass::MalformedRequest => Self::MalformedRequest,
            ErrorClass::UnsupportedProtocolVersion => Self::UnsupportedProtocolVersion,
            ErrorClass::UnsupportedOperation => Self::UnsupportedOperation,
            ErrorClass::InvalidArgument => Self::InvalidArgument,
            ErrorClass::ResourceLimit => Self::ResourceLimit,
            ErrorClass::Overloaded => Self::Overloaded,
            ErrorClass::InternalError => Self::InternalError,
            ErrorClass::ProtocolViolation => Self::ProtocolViolation,
            ErrorClass::WrongType => Self::WrongType,
        }
    }

    const fn from_failure(failure: Failure) -> Self {
        Self::from_class(failure.class())
    }

    const fn from_command_failure(failure: command::CommandFailure) -> Self {
        Self::from_class(failure.class())
    }

    fn from_driver(error: DriverError) -> Self {
        match error {
            DriverError::RequestFailed(failure) | DriverError::ConnectionFatal(failure) => {
                Self::from_failure(failure)
            }
            DriverError::Transport => Self::Transport(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the transport failed",
            )),
            DriverError::Closed => Self::Closed,
            DriverError::Unusable => Self::Unusable,
        }
    }
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
    /// The handshake completed; the connection accepts new requests.
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
/// its negotiated session state and carries multiplexed requests with
/// bounded admission. Clones share one session.
///
/// A clone is another handle to the same session, never a new connection.
/// Clones share admission, request identity, negotiated state, and
/// lifecycle: closing through any handle closes the session for all
/// handles, and concurrent tasks may use clones without an exclusive
/// borrow.
///
/// Dropping a `Connection` without calling [`Connection::close`] closes
/// the transport without waiting and releases local resources. It sends
/// no protocol exchange and rolls nothing back. Callers that need a
/// deterministic shutdown call `close`.
#[derive(Debug, Clone)]
pub struct Connection {
    shared: std::sync::Arc<Shared>,
}

/// The session state shared by every handle to one connection.
#[derive(Debug)]
struct Shared {
    negotiated: Negotiated,
    state: std::sync::Arc<std::sync::Mutex<ConnectionState>>,
    transport: std::sync::Mutex<Option<AnyTransport>>,
    admission: std::sync::Arc<tokio::sync::Semaphore>,
    maximum_in_flight: usize,
    submit_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<Submit>>>,
    allocator: std::sync::Mutex<RequestIdAllocator>,
    driver: std::sync::Mutex<Option<tokio::task::JoinHandle<driver::DriverExit>>>,
    shutdown_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.driver.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
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
        let bound = config.maximum_in_flight_value();
        let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(bound));
        let state = std::sync::Arc::new(std::sync::Mutex::new(ConnectionState::Usable));
        let is_tcp = matches!(transport, AnyTransport::Tcp(_));
        if is_tcp {
            let limits = Limits {
                frame_size: negotiated
                    .maximum_frame_size
                    .min(config.local_maximum_frame_size_value()),
                metadata_size: negotiated
                    .maximum_metadata_size
                    .min(config.local_maximum_metadata_size_value()),
            };
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let (submit_tx, driver_handle) = driver::spawn(
                transport,
                limits,
                Arc::clone(&state),
                Arc::clone(&admission),
                shutdown_rx,
            );
            let shared = Shared {
                negotiated,
                state,
                transport: std::sync::Mutex::new(None),
                admission,
                maximum_in_flight: bound,
                submit_tx: std::sync::Mutex::new(Some(submit_tx)),
                allocator: std::sync::Mutex::new(RequestIdAllocator::new()),
                driver: std::sync::Mutex::new(Some(driver_handle)),
                shutdown_tx: std::sync::Mutex::new(Some(shutdown_tx)),
            };
            {
                let mut allocator_guard = shared
                    .allocator
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = allocator_guard.allocate();
            }
            return Ok(Self {
                shared: std::sync::Arc::new(shared),
            });
        }
        let shared = Shared {
            negotiated,
            state,
            transport: std::sync::Mutex::new(Some(transport)),
            admission,
            maximum_in_flight: bound,
            submit_tx: std::sync::Mutex::new(None),
            allocator: std::sync::Mutex::new(RequestIdAllocator::new()),
            driver: std::sync::Mutex::new(None),
            shutdown_tx: std::sync::Mutex::new(None),
        };
        Ok(Self {
            shared: std::sync::Arc::new(shared),
        })
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        self.shared.negotiated.protocol_version
    }

    /// Returns the negotiated maximum frame size.
    #[must_use]
    pub fn maximum_frame_size(&self) -> u64 {
        self.shared.negotiated.maximum_frame_size
    }

    /// Returns the negotiated maximum metadata size.
    #[must_use]
    pub fn maximum_metadata_size(&self) -> u16 {
        self.shared.negotiated.maximum_metadata_size
    }

    /// Returns the local cap on the negotiated maximum frame size.
    #[must_use]
    pub fn local_maximum_frame_size(&self) -> u64 {
        self.shared.negotiated.local_maximum_frame_size
    }

    /// Returns the local cap on the negotiated maximum metadata size.
    #[must_use]
    pub fn local_maximum_metadata_size(&self) -> u16 {
        self.shared.negotiated.local_maximum_metadata_size
    }

    /// Returns the bound on concurrent in-flight requests.
    #[must_use]
    pub fn maximum_in_flight(&self) -> usize {
        self.shared.maximum_in_flight
    }

    /// Returns the effective maximum frame size: the stricter of the
    /// negotiated bound and the local cap.
    ///
    /// Establishment refuses a handshake that negotiates above the local
    /// cap, so on a usable connection the effective bound equals the
    /// negotiated one. Later request admission reads this bound rather
    /// than the negotiated value alone.
    #[must_use]
    pub fn effective_maximum_frame_size(&self) -> u64 {
        if self.shared.negotiated.maximum_frame_size
            < self.shared.negotiated.local_maximum_frame_size
        {
            self.shared.negotiated.maximum_frame_size
        } else {
            self.shared.negotiated.local_maximum_frame_size
        }
    }

    /// Returns the effective maximum metadata size: the stricter of the
    /// negotiated bound and the local cap.
    #[must_use]
    pub fn effective_maximum_metadata_size(&self) -> u16 {
        if self.shared.negotiated.maximum_metadata_size
            < self.shared.negotiated.local_maximum_metadata_size
        {
            self.shared.negotiated.maximum_metadata_size
        } else {
            self.shared.negotiated.local_maximum_metadata_size
        }
    }

    /// Returns the accepted capability identifiers.
    #[must_use]
    pub fn accepted_capabilities(&self) -> &[u16] {
        &self.shared.negotiated.accepted_capabilities
    }

    /// Returns the lifecycle state of the connection.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        *self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns whether the connection is usable. This is false after close.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.state().is_usable()
    }

    /// Sends a liveness probe and waits for the responder to answer.
    ///
    /// Keys and values are binary-safe on every command; `PING` names no
    /// key. Concurrent calls through clones multiplex over one session
    /// with no exclusive borrow and no submission-order consumption.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::LocalLimitExceeded`] when the request would
    /// exceed the effective bound without sending a byte,
    /// [`CommandError::UnsupportedOperation`] when the server does not
    /// serve the operation, request-scoped refusals for invalid or
    /// overloaded requests, [`CommandError::InternalError`] with preserved
    /// ambiguity when the responder reports an unexpected condition, and
    /// connection-fatal, transport, closed, or unusable errors when the
    /// session cannot serve the request.
    pub async fn ping(&self) -> Result<(), CommandError> {
        let payload = command::encode_ping();
        let (_, frame_bytes) = self.execute(command::PING_OPCODE, &payload).await?;
        let frame = self.decode_own(&frame_bytes)?;
        command::interpret_ping(&frame).map_err(CommandError::from_command_failure)
    }

    /// Reads the value of `key`, which is an opaque byte string.
    ///
    /// A present empty value and a missing key are different outcomes;
    /// the caller never parses a length to tell them apart. Arbitrary
    /// bytes round-trip untouched in both directions.
    ///
    /// # Errors
    ///
    /// Returns the same structured errors as [`Connection::ping`].
    pub async fn get(&self, key: impl AsRef<[u8]>) -> Result<GetOutcome, CommandError> {
        let payload = command::encode_key(key.as_ref());
        let (_, frame_bytes) = self.execute(command::GET_OPCODE, &payload).await?;
        let frame = self.decode_own(&frame_bytes)?;
        match command::interpret_get(&frame).map_err(CommandError::from_command_failure)? {
            command::GetOutcome::Present(value) => Ok(GetOutcome::Present(value)),
            command::GetOutcome::Absent => Ok(GetOutcome::Absent),
            command::GetOutcome::HeldOutsideMemory { logical_length } => {
                Ok(GetOutcome::HeldOutsideMemory { logical_length })
            }
        }
    }

    /// Writes `value` under `key`; both are opaque byte strings.
    ///
    /// An empty key and an empty value are ordinary values. Nothing is
    /// sent when the request would exceed the effective bound.
    ///
    /// # Errors
    ///
    /// Returns the same structured errors as [`Connection::ping`], plus
    /// [`CommandError::WrongType`] when the key holds another
    /// representation and nothing was stored.
    pub async fn set(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), CommandError> {
        let payload = command::encode_set(key.as_ref(), value.as_ref())
            .map_err(|_| CommandError::InvalidRequest)?;
        let (_, frame_bytes) = self.execute(command::SET_OPCODE, &payload).await?;
        let frame = self.decode_own(&frame_bytes)?;
        command::interpret_set(&frame).map_err(CommandError::from_command_failure)
    }

    /// Removes `key` and answers whether a key was removed.
    ///
    /// Removing a missing key answers `false`, never an error. `DEL`
    /// removes whichever representation the key holds, so it never
    /// answers the wrong type class.
    ///
    /// # Errors
    ///
    /// Returns the same structured errors as [`Connection::ping`].
    pub async fn del(&self, key: impl AsRef<[u8]>) -> Result<bool, CommandError> {
        let payload = command::encode_key(key.as_ref());
        let (_, frame_bytes) = self.execute(command::DEL_OPCODE, &payload).await?;
        let frame = self.decode_own(&frame_bytes)?;
        command::interpret_del(&frame).map_err(CommandError::from_command_failure)
    }

    /// Answers whether `key` is present, whatever representation it holds.
    ///
    /// Presence arrives as a boolean; a missing key is `false`, never an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns the same structured errors as [`Connection::ping`].
    pub async fn exists(&self, key: impl AsRef<[u8]>) -> Result<bool, CommandError> {
        let payload = command::encode_key(key.as_ref());
        let (_, frame_bytes) = self.execute(command::EXISTS_OPCODE, &payload).await?;
        let frame = self.decode_own(&frame_bytes)?;
        command::interpret_exists(&frame).map_err(CommandError::from_command_failure)
    }

    /// Executes one encoded command payload and returns the terminal frame.
    async fn execute(&self, opcode: u16, payload: &[u8]) -> Result<(u64, Vec<u8>), CommandError> {
        self.check_usable()?;
        let (effective_frame, effective_metadata) = self.effective_limits();
        let total = wire_size(payload.len());
        if total > effective_frame {
            return Err(CommandError::LocalLimitExceeded {
                requested: total,
                limit: effective_frame,
            });
        }
        let permit = self.acquire_permit().await?;
        let id = self.allocate_id()?;
        let bytes = Self::encode_request(opcode, payload, id, effective_frame, effective_metadata)?;
        self.submit(id, bytes, permit).await
    }

    /// Refuses new work unless the session is usable.
    fn check_usable(&self) -> Result<(), CommandError> {
        if self.is_usable() {
            return Ok(());
        }
        Err(match self.state() {
            ConnectionState::Closed | ConnectionState::Closing => CommandError::Closed,
            ConnectionState::Failed => CommandError::Transport(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the connection failed",
            )),
            ConnectionState::Unusable | ConnectionState::Usable => CommandError::Unusable,
        })
    }

    /// Returns the effective frame and metadata bounds in force.
    fn effective_limits(&self) -> (u64, u16) {
        (
            self.effective_maximum_frame_size(),
            self.effective_maximum_metadata_size(),
        )
    }

    /// Acquires one admission permit, waiting while usable.
    async fn acquire_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, CommandError> {
        Arc::clone(&self.shared.admission)
            .acquire_owned()
            .await
            .map_err(|_| match self.state() {
                ConnectionState::Closed | ConnectionState::Closing => CommandError::Closed,
                ConnectionState::Failed => CommandError::Transport(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "the connection failed",
                )),
                _ => CommandError::Unusable,
            })
    }

    /// Allocates the next request ID.
    fn allocate_id(&self) -> Result<u64, CommandError> {
        let id = self
            .shared
            .allocator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocate();
        if id == 0 {
            return Err(CommandError::Unusable);
        }
        Ok(id)
    }

    /// Encodes one request frame under the effective bounds.
    fn encode_request(
        opcode: u16,
        payload: &[u8],
        id: u64,
        effective_frame: u64,
        effective_metadata: u16,
    ) -> Result<Vec<u8>, CommandError> {
        let outgoing = Outgoing {
            kind: Kind::Request,
            code: opcode,
            request_id: id,
            metadata: &[],
            payload: OutgoingPayload::Opaque(payload),
        };
        crate::protocol::encode_with_max(&outgoing, effective_frame, effective_metadata).map_err(
            |error| match error {
                protocol::EncodeError::FrameTooLarge | protocol::EncodeError::MetadataTooLarge => {
                    CommandError::LocalLimitExceeded {
                        requested: wire_size(payload.len()),
                        limit: effective_frame,
                    }
                }
                protocol::EncodeError::MetadataNotAscending => CommandError::InvalidRequest,
            },
        )
    }

    /// Submits encoded bytes and waits for the terminal frame.
    async fn submit(
        &self,
        id: u64,
        bytes: Vec<u8>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(u64, Vec<u8>), CommandError> {
        let submit_tx = {
            let guard = self
                .shared
                .submit_tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.clone()
        };
        let Some(submit_tx) = submit_tx else {
            return Err(CommandError::Unusable);
        };
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let submit = Submit {
            id,
            bytes,
            completion: completion_tx,
        };
        if submit_tx.send(submit).await.is_err() {
            return Err(self.completion_lost());
        }
        let outcome = completion_rx.await.map_err(|_| self.completion_lost())?;
        match outcome {
            Ok(frame_bytes) => Ok((id, frame_bytes)),
            Err(driver_error) => Err(CommandError::from_driver(driver_error)),
        }
    }

    /// Maps a lost completion to the current lifecycle state.
    fn completion_lost(&self) -> CommandError {
        match self.state() {
            ConnectionState::Closed | ConnectionState::Closing => CommandError::Closed,
            ConnectionState::Failed => CommandError::Transport(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the connection failed",
            )),
            _ => CommandError::Unusable,
        }
    }

    /// Decodes a terminal frame the driver attributed to one request.
    fn decode_own<'a>(&self, frame_bytes: &'a [u8]) -> Result<protocol::Frame<'a>, CommandError> {
        use protocol::{Admission, ConnectionState as ProtocolState, Limits, Role};
        let request_id = frame_bytes
            .get(12..20)
            .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
            .map_or(0, u64::from_le_bytes);
        let in_flight = [request_id];
        let admission = Admission {
            role: Role::Client,
            state: ProtocolState::Negotiated,
            limits: Limits {
                frame_size: self.effective_maximum_frame_size(),
                metadata_size: self.effective_maximum_metadata_size(),
            },
            in_flight: &in_flight,
        };
        match protocol::decode(frame_bytes, admission) {
            Step::Frame(frame) => Ok(frame),
            Step::Failure { failure, .. } => Err(CommandError::from_failure(failure)),
            Step::Need(_) => Err(CommandError::ProtocolViolation),
        }
    }

    /// Closes the connection.
    ///
    /// Closing stops admission, wakes every admission waiter with a
    /// structured error, shuts the transport down, and moves the
    /// connection to [`ConnectionState::Closed`]. When the transport
    /// shutdown fails, the connection moves to [`ConnectionState::Failed`]
    /// instead and the error is returned. Closing an already terminal
    /// connection succeeds without touching the transport. A clone closes
    /// the shared session for every handle.
    ///
    /// # Errors
    ///
    /// Returns the underlying transport error, leaving the connection in
    /// the failed state.
    pub async fn close(&self) -> Result<(), std::io::Error> {
        if self.is_terminal() {
            return Ok(());
        }
        self.begin_closing();
        self.shared.admission.close();
        if self.has_driver() {
            return self.close_with_driver().await;
        }
        self.close_without_driver().await
    }

    /// Returns whether the session already reached a terminal state.
    fn is_terminal(&self) -> bool {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        matches!(
            *state,
            ConnectionState::Closed | ConnectionState::Failed | ConnectionState::Unusable
        )
    }

    /// Moves a usable session into closing.
    fn begin_closing(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = ConnectionState::Closing;
    }

    /// Returns whether a production driver owns the transport.
    fn has_driver(&self) -> bool {
        let guard = self
            .shared
            .driver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.is_some()
    }

    /// Shuts down through the driver and lands the terminal state.
    async fn close_with_driver(&self) -> Result<(), std::io::Error> {
        let shutdown_tx = {
            let mut guard = self
                .shared
                .shutdown_tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take()
        };
        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(());
        }
        let handle = {
            let mut guard = self
                .shared
                .driver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take()
        };
        let Some(handle) = handle else {
            return Ok(());
        };
        match handle.await {
            Ok(driver::DriverExit::Closed) => {
                self.finish_close(ConnectionState::Closed);
                Ok(())
            }
            Ok(driver::DriverExit::Failed) => {
                self.finish_close(ConnectionState::Failed);
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the transport failed during shutdown",
                ))
            }
            Ok(driver::DriverExit::Unusable) | Err(_) => Ok(()),
        }
    }

    /// Lands a terminal state after the driver exited, unless fatal first.
    fn finish_close(&self, next: ConnectionState) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, ConnectionState::Closing) {
            *state = next;
        }
        drop(state);
    }

    /// Shuts down a driverless test session through its transport.
    async fn close_without_driver(&self) -> Result<(), std::io::Error> {
        let transport = {
            let mut guard = self
                .shared
                .transport
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take()
        };
        let Some(mut transport) = transport else {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *state = ConnectionState::Closed;
            drop(state);
            return Ok(());
        };
        match transport.shutdown().await {
            Ok(()) => {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *state = ConnectionState::Closed;
                drop(state);
                Ok(())
            }
            Err(error) => {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *state = ConnectionState::Failed;
                drop(state);
                Err(error)
            }
        }
    }

    /// Acquires one admission permit for tests, waiting while usable.
    ///
    /// Failure or shutdown closes the admission source and wakes the
    /// waiter with an error, so no waiter survives termination.
    ///
    /// # Errors
    ///
    /// Returns [`tokio::sync::AcquireError`] when the admission source is
    /// closed by failure or shutdown.
    #[cfg(test)]
    pub async fn acquire_admission_for_test(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError> {
        std::sync::Arc::clone(&self.shared.admission)
            .acquire_owned()
            .await
    }

    /// Returns the available admission permits for tests.
    #[cfg(test)]
    #[must_use]
    pub fn admission_permits_for_test(&self) -> usize {
        self.shared.admission.available_permits()
    }

    /// Marks the session unusable for tests, simulating a fatal dispatch.
    ///
    /// The transition stops admission and allocation, wakes every waiter
    /// with an error, and lands the connection in
    /// [`ConnectionState::Unusable`]. Terminal states are sticky; a usable
    /// session never returns once it leaves usable.
    #[cfg(test)]
    pub fn mark_unusable_for_test(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(
            *state,
            ConnectionState::Closed | ConnectionState::Failed | ConnectionState::Unusable
        ) {
            return;
        }
        *state = ConnectionState::Unusable;
        drop(state);
        self.shared.admission.close();
    }
}

/// Returns the wire size of a command payload with an empty metadata region.
fn wire_size(payload_len: usize) -> u64 {
    u64::try_from(crate::protocol::HEADER_LENGTH)
        .ok()
        .and_then(|header| header.checked_add(u64::try_from(payload_len).unwrap_or(u64::MAX)))
        .unwrap_or(u64::MAX)
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
        let connection = Connection::establish(transport, &config).await?;
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
        let connection = Connection::establish(transport, &config).await?;
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
        let connection = Connection::establish(transport, &config).await?;
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

    #[test]
    fn an_in_flight_bound_below_one_is_refused() {
        let config = ConnectionConfig::new("127.0.0.1:6379").maximum_in_flight(0);
        assert_eq!(
            config.validate(),
            Err(ConnectionConfigError::InFlightBoundBelowMinimum { proposed: 0 })
        );
    }

    #[test]
    fn the_default_in_flight_bound_is_sixty_four() {
        let config = ConnectionConfig::new("127.0.0.1:6379");
        assert_eq!(config.maximum_in_flight_value(), 64);
        assert_eq!(config.validate(), Ok(()));
    }

    #[tokio::test]
    async fn clones_share_one_session() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        let peer = connection.clone();
        assert_eq!(peer.protocol_version(), connection.protocol_version());
        assert_eq!(peer.maximum_in_flight(), 64);
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Closed);
        assert_eq!(peer.state(), ConnectionState::Closed);
        assert!(!peer.is_usable());
        peer.close().await?;
        assert_eq!(peer.state(), ConnectionState::Closed);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_tasks_use_clones_without_an_exclusive_borrow()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        let first = connection.clone();
        let second = connection.clone();
        let (version, maximum, usable) = tokio::join!(
            async { first.protocol_version() },
            async { second.maximum_frame_size() },
            async { connection.is_usable() },
        );
        assert_eq!(version, 0);
        assert_eq!(maximum, 65_536);
        assert!(usable);
        Ok(())
    }

    #[tokio::test]
    async fn admission_waits_at_the_bound_and_close_wakes_waiters()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory").maximum_in_flight(2);
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.maximum_in_flight(), 2);
        assert_eq!(connection.admission_permits_for_test(), 2);
        let first = connection.acquire_admission_for_test().await?;
        let second = connection.acquire_admission_for_test().await?;
        assert_eq!(connection.admission_permits_for_test(), 0);
        let waiter = tokio::spawn({
            let connection = connection.clone();
            async move { connection.acquire_admission_for_test().await.is_err() }
        });
        tokio::task::yield_now().await;
        connection.close().await?;
        assert!(waiter.await.unwrap_or(false));
        drop(first);
        drop(second);
        assert_eq!(connection.state(), ConnectionState::Closed);
        Ok(())
    }

    #[tokio::test]
    async fn a_bound_of_one_serializes_without_deadlock() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = ConnectionConfig::new("in-memory").maximum_in_flight(1);
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.admission_permits_for_test(), 1);
        let held = connection.acquire_admission_for_test().await?;
        assert_eq!(connection.admission_permits_for_test(), 0);
        let waiter = tokio::spawn({
            let connection = connection.clone();
            async move { connection.acquire_admission_for_test().await.is_ok() }
        });
        tokio::task::yield_now().await;
        drop(held);
        assert!(waiter.await.unwrap_or(false));
        assert_eq!(connection.admission_permits_for_test(), 1);
        connection.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn permits_return_to_baseline_after_release() -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory").maximum_in_flight(3);
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        let first = connection.acquire_admission_for_test().await?;
        let second = connection.acquire_admission_for_test().await?;
        assert_eq!(connection.admission_permits_for_test(), 1);
        drop(first);
        drop(second);
        assert_eq!(connection.admission_permits_for_test(), 3);
        connection.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn close_with_no_requests_is_orderly_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.admission_permits_for_test(), 64);
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Closed);
        assert!(!connection.is_usable());
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Closed);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_close_leaves_no_waiter_and_stays_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory").maximum_in_flight(1);
        let inbound = response_frame(0, 65_536, 4_096, &[]);
        let transport =
            AnyTransport::Memory(InMemoryTransport::new(&inbound, 4_096, 4_096).fail_on_shutdown());
        let connection = Connection::establish(transport, &config).await?;
        let held = connection.acquire_admission_for_test().await?;
        let waiter = tokio::spawn({
            let connection = connection.clone();
            async move { connection.acquire_admission_for_test().await.is_err() }
        });
        tokio::task::yield_now().await;
        assert!(connection.close().await.is_err());
        assert_eq!(connection.state(), ConnectionState::Failed);
        assert!(waiter.await.unwrap_or(false));
        drop(held);
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Failed);
        Ok(())
    }

    #[tokio::test]
    async fn a_fatal_dispatch_lands_unusable_and_wakes_every_waiter()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = ConnectionConfig::new("in-memory").maximum_in_flight(1);
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        let held = connection.acquire_admission_for_test().await?;
        let waiter = tokio::spawn({
            let connection = connection.clone();
            async move { connection.acquire_admission_for_test().await.is_err() }
        });
        tokio::task::yield_now().await;
        connection.mark_unusable_for_test();
        assert_eq!(connection.state(), ConnectionState::Unusable);
        assert!(!connection.is_usable());
        assert!(waiter.await.unwrap_or(false));
        drop(held);
        assert!(connection.acquire_admission_for_test().await.is_err());
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Unusable);
        Ok(())
    }

    #[tokio::test]
    async fn repeated_failure_cycles_leave_no_residue() -> Result<(), Box<dyn std::error::Error>> {
        for _ in [0, 1, 2] {
            let config = ConnectionConfig::new("in-memory").maximum_in_flight(2);
            let inbound = response_frame(0, 65_536, 4_096, &[]);
            let transport = AnyTransport::Memory(
                InMemoryTransport::new(&inbound, 4_096, 4_096).fail_on_shutdown(),
            );
            let connection = Connection::establish(transport, &config).await?;
            assert_eq!(connection.admission_permits_for_test(), 2);
            assert!(connection.close().await.is_err());
            assert_eq!(connection.state(), ConnectionState::Failed);
        }
        let config = ConnectionConfig::new("in-memory");
        let transport = memory(&response_frame(0, 65_536, 4_096, &[]), 4_096, 4_096);
        let connection = Connection::establish(transport, &config).await?;
        assert_eq!(connection.state(), ConnectionState::Usable);
        connection.close().await?;
        assert_eq!(connection.state(), ConnectionState::Closed);
        Ok(())
    }
}

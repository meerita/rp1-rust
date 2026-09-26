//! Command payload codecs and response interpretation for the core operations.
//!
//! This module owns the `SET` structural encoding checks, the request
//! payload construction for the five ungated operations, and the mapping
//! of admitted response and error frames onto caller-visible outcomes.
//!
//! It does not own transport, request correlation, connection lifecycle,
//! or any public connection API. It runs on the multiplexed executor
//! without exposing a public surface.

#![allow(dead_code)]

use crate::protocol::{ErrorClass, FailureScope, Frame, Kind, Payload, ResultCode};

// Re-exported by the connection surface once it exists.
pub use crate::protocol::{DEL_OPCODE, EXISTS_OPCODE, GET_OPCODE, PING_OPCODE, SET_OPCODE};

/// One of the five ungated operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// The liveness operation.
    Ping,
    /// The value read.
    Get,
    /// The byte write.
    Set,
    /// The key delete.
    Del,
    /// The presence read.
    Exists,
}

impl Operation {
    /// Returns the opcode the operation carries.
    #[must_use]
    pub const fn opcode(self) -> u16 {
        match self {
            Self::Ping => PING_OPCODE,
            Self::Get => GET_OPCODE,
            Self::Set => SET_OPCODE,
            Self::Del => DEL_OPCODE,
            Self::Exists => EXISTS_OPCODE,
        }
    }
}

/// A failure to encode a `SET` request before any byte is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetEncodeError {
    /// The key does not fit in the `u32` length field.
    KeyTooLong {
        /// The length of the key in bytes.
        length: usize,
    },
    /// The encoded payload does not fit in the `u32` payload length.
    PayloadTooLarge,
}

impl std::fmt::Display for SetEncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyTooLong { length } => {
                write!(
                    formatter,
                    "the SET key length {length} exceeds the u32 range"
                )
            }
            Self::PayloadTooLarge => formatter.write_str("the SET payload exceeds the u32 range"),
        }
    }
}

impl std::error::Error for SetEncodeError {}

/// The outcome of a `GET` request.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A structured command failure that preserves the protocol class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFailure {
    class: ErrorClass,
}

impl CommandFailure {
    /// Builds a failure from its protocol class.
    #[must_use]
    pub const fn new(class: ErrorClass) -> Self {
        Self { class }
    }

    /// Builds the protocol violation failure for an unexpected result shape.
    #[must_use]
    pub const fn protocol_violation() -> Self {
        Self::new(ErrorClass::ProtocolViolation)
    }

    /// Returns the protocol class of the failure.
    #[must_use]
    pub const fn class(self) -> ErrorClass {
        self.class
    }

    /// Returns the scope of the failure.
    #[must_use]
    pub const fn scope(self) -> FailureScope {
        self.class.scope()
    }

    /// Returns whether the mutation may have taken effect.
    ///
    /// Only the internal error class is ambiguous at this revision;
    /// every other assigned class states that nothing was written.
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(self.class, ErrorClass::InternalError)
    }
}

impl std::fmt::Display for CommandFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.class.name())
    }
}

impl std::error::Error for CommandFailure {}

/// Encodes a `PING` request payload, which is always empty.
#[must_use]
pub const fn encode_ping() -> Vec<u8> {
    Vec::new()
}

/// Encodes a `GET`, `DEL` or `EXISTS` request payload, which is the key alone.
#[must_use]
pub fn encode_key(key: &[u8]) -> Vec<u8> {
    key.to_vec()
}

/// Encodes a `SET` request payload as the `u32` key length, the key, and the value.
///
/// # Errors
///
/// Returns [`SetEncodeError::KeyTooLong`] when the key does not fit in a
/// `u32`, and [`SetEncodeError::PayloadTooLarge`] when the encoded
/// payload does not fit in the `u32` payload length.
pub fn encode_set(key: &[u8], value: &[u8]) -> Result<Vec<u8>, SetEncodeError> {
    let key_length =
        u32::try_from(key.len()).map_err(|_| SetEncodeError::KeyTooLong { length: key.len() })?;
    let total = 4usize
        .checked_add(key.len())
        .and_then(|total| total.checked_add(value.len()))
        .ok_or(SetEncodeError::PayloadTooLarge)?;
    if u64::try_from(total).unwrap_or(u64::MAX) > u64::from(u32::MAX) {
        return Err(SetEncodeError::PayloadTooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&key_length.to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    Ok(out)
}

/// Splits a `SET` request payload into its key and value.
///
/// # Errors
///
/// Returns [`CommandFailure`] with the malformed request class when the
/// payload is shorter than its four-byte head or the key length
/// overruns the payload.
pub fn split_set(payload: &[u8]) -> Result<(&[u8], &[u8]), CommandFailure> {
    if payload.len() < 4 {
        return Err(CommandFailure::new(ErrorClass::MalformedRequest));
    }
    let Some(key_length) = read_u32_le(payload, 0) else {
        return Err(CommandFailure::new(ErrorClass::MalformedRequest));
    };
    let Ok(key_length) = usize::try_from(key_length) else {
        return Err(CommandFailure::new(ErrorClass::MalformedRequest));
    };
    let Some(key_end) = 4usize.checked_add(key_length) else {
        return Err(CommandFailure::new(ErrorClass::MalformedRequest));
    };
    let Some(key) = payload.get(4..key_end) else {
        return Err(CommandFailure::new(ErrorClass::MalformedRequest));
    };
    let Some(value) = payload.get(key_end..) else {
        return Err(CommandFailure::new(ErrorClass::MalformedRequest));
    };
    Ok((key, value))
}

/// Interprets an admitted frame as the answer to a `PING` request.
///
/// A success with a non-empty payload is accepted pending the contract
/// clarification for that sub-case; no refusal is implemented here.
pub fn interpret_ping(frame: &Frame<'_>) -> Result<(), CommandFailure> {
    match frame.header().kind() {
        Kind::Response => {
            let code = result_code_of(frame)?;
            if code != ResultCode::Success {
                return Err(CommandFailure::protocol_violation());
            }
            Ok(())
        }
        Kind::Error => Err(error_of(frame)),
        Kind::Request => Err(CommandFailure::protocol_violation()),
    }
}

/// Interprets an admitted frame as the answer to a `GET` request.
pub fn interpret_get(frame: &Frame<'_>) -> Result<GetOutcome, CommandFailure> {
    match frame.header().kind() {
        Kind::Response => {
            let code = result_code_of(frame)?;
            match code {
                ResultCode::Success => {
                    let Payload::Opaque(payload) = frame.payload() else {
                        return Err(CommandFailure::protocol_violation());
                    };
                    Ok(GetOutcome::Present(payload.to_vec()))
                }
                ResultCode::Absent => Ok(GetOutcome::Absent),
                ResultCode::ValueHeldOutsideMemory => {
                    let Payload::Warm { logical_length } = frame.payload() else {
                        return Err(CommandFailure::protocol_violation());
                    };
                    Ok(GetOutcome::HeldOutsideMemory {
                        logical_length: *logical_length,
                    })
                }
            }
        }
        Kind::Error => Err(error_of(frame)),
        Kind::Request => Err(CommandFailure::protocol_violation()),
    }
}

/// Interprets an admitted frame as the answer to a `SET` request.
///
/// A success with a non-empty payload is accepted pending the contract
/// clarification for that sub-case; no refusal is implemented here.
pub fn interpret_set(frame: &Frame<'_>) -> Result<(), CommandFailure> {
    match frame.header().kind() {
        Kind::Response => {
            let code = result_code_of(frame)?;
            if code != ResultCode::Success {
                return Err(CommandFailure::protocol_violation());
            }
            Ok(())
        }
        Kind::Error => Err(error_of(frame)),
        Kind::Request => Err(CommandFailure::protocol_violation()),
    }
}

/// Interprets an admitted frame as the answer to a `DEL` request.
///
/// A success answers `true` and an absent answer `false`. A success with
/// a non-empty payload is accepted pending the contract clarification
/// for that sub-case; no refusal is implemented here.
pub fn interpret_del(frame: &Frame<'_>) -> Result<bool, CommandFailure> {
    match frame.header().kind() {
        Kind::Response => {
            let code = result_code_of(frame)?;
            match code {
                ResultCode::Success => Ok(true),
                ResultCode::Absent => Ok(false),
                ResultCode::ValueHeldOutsideMemory => Err(CommandFailure::protocol_violation()),
            }
        }
        Kind::Error => Err(error_of(frame)),
        Kind::Request => Err(CommandFailure::protocol_violation()),
    }
}

/// Interprets an admitted frame as the answer to an `EXISTS` request.
///
/// A success answers `true` and an absent answer `false`. A success with
/// a non-empty payload is accepted pending the contract clarification
/// for that sub-case; no refusal is implemented here.
pub fn interpret_exists(frame: &Frame<'_>) -> Result<bool, CommandFailure> {
    interpret_del(frame)
}

/// Reads the result code of a response frame.
fn result_code_of(frame: &Frame<'_>) -> Result<ResultCode, CommandFailure> {
    ResultCode::from_wire(frame.header().code()).ok_or_else(CommandFailure::protocol_violation)
}

/// Reads the error class of an error frame without parsing its text.
fn error_of(frame: &Frame<'_>) -> CommandFailure {
    ErrorClass::from_wire(frame.header().code())
        .map_or_else(CommandFailure::protocol_violation, CommandFailure::new)
}

/// Reads a little-endian `u32` at `offset`, or `None` when out of bounds.
fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    let array: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::{
        CommandFailure, GetOutcome, encode_key, encode_ping, encode_set, interpret_del,
        interpret_exists, interpret_get, interpret_ping, interpret_set, split_set,
    };
    use crate::protocol::{
        Admission, ConnectionState, ErrorClass, FailureScope, Kind, Limits, Outgoing,
        OutgoingPayload, Role, Step, decode, encode,
    };

    fn response_bytes(kind: Kind, code: u16, payload: &[u8]) -> Vec<u8> {
        let outgoing = Outgoing {
            kind,
            code,
            request_id: 7,
            metadata: &[],
            payload: OutgoingPayload::Opaque(payload),
        };
        encode(&outgoing).unwrap_or_default()
    }

    fn decode_client<'a>(bytes: &'a [u8], in_flight: &[u64]) -> Step<'a> {
        decode(
            bytes,
            Admission {
                role: Role::Client,
                state: ConnectionState::Negotiated,
                limits: Limits::PRE_NEGOTIATION,
                in_flight,
            },
        )
    }

    fn error_response_bytes(class: u16) -> Vec<u8> {
        let outgoing = Outgoing {
            kind: Kind::Error,
            code: class,
            request_id: 7,
            metadata: &[],
            payload: OutgoingPayload::Error {
                detail: &[],
                text: b"diagnostic text is not contractual",
            },
        };
        encode(&outgoing).unwrap_or_default()
    }

    fn expect_command_failure(
        result: Result<(), CommandFailure>,
        class: ErrorClass,
        scope: FailureScope,
    ) {
        match result {
            Err(failure) => {
                assert_eq!(failure.class(), class);
                assert_eq!(failure.scope(), scope);
            }
            Ok(()) => assert!(false, "expected failure {}, got success", class.name()),
        }
    }

    #[test]
    fn ping_encodes_empty_and_maps_success() {
        assert!(encode_ping().is_empty());
        let bytes = response_bytes(Kind::Response, 0x0000, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => assert_eq!(interpret_ping(&frame), Ok(())),
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn ping_maps_every_reachable_error_class_with_scope() {
        let cases = [
            (
                ErrorClass::UnsupportedOperation,
                FailureScope::RequestScoped,
            ),
            (ErrorClass::InvalidArgument, FailureScope::RequestScoped),
            (ErrorClass::Overloaded, FailureScope::RequestScoped),
            (ErrorClass::InternalError, FailureScope::RequestScoped),
            (ErrorClass::MalformedRequest, FailureScope::ConnectionFatal),
            (ErrorClass::ResourceLimit, FailureScope::ConnectionFatal),
            (ErrorClass::ProtocolViolation, FailureScope::ConnectionFatal),
        ];
        for (class, scope) in cases {
            let bytes = error_response_bytes(class.value());
            match decode_client(&bytes, &[7]) {
                Step::Frame(frame) => {
                    expect_command_failure(interpret_ping(&frame), class, scope);
                }
                other => assert!(
                    matches!(other, Step::Need(_)),
                    "expected a frame, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn set_encodes_once_and_splits() {
        let payload = encode_set(b"key", b"value").unwrap_or_default();
        assert_eq!(payload.len(), 12);
        let head: [u8; 4] = [3, 0, 0, 0];
        assert_eq!(payload.get(..4), Some(head.as_slice()));
        match split_set(&payload) {
            Ok((key, value)) => {
                assert_eq!(key, b"key");
                assert_eq!(value, b"value");
            }
            Err(failure) => assert!(false, "expected a split, got {}", failure.class().name()),
        }
        let empty = encode_set(b"", b"").unwrap_or_default();
        assert_eq!(empty, vec![0, 0, 0, 0]);
        match split_set(&empty) {
            Ok((empty_key, empty_value)) => {
                assert!(empty_key.is_empty());
                assert!(empty_value.is_empty());
            }
            Err(failure) => assert!(
                false,
                "expected an empty split, got {}",
                failure.class().name()
            ),
        }
    }

    #[test]
    fn set_short_and_overrunning_payloads_are_malformed() {
        match split_set(&[1, 2, 3]) {
            Err(failure) => assert_eq!(failure, CommandFailure::new(ErrorClass::MalformedRequest)),
            Ok(_) => assert!(false, "expected a malformed short payload"),
        }
        match split_set(&[5, 0, 0, 0, b'a']) {
            Err(failure) => assert_eq!(failure, CommandFailure::new(ErrorClass::MalformedRequest)),
            Ok(_) => assert!(false, "expected a malformed overrun"),
        }
    }

    #[test]
    fn keys_are_binary_safe_end_to_end() {
        let key = [0x00, 0xff, 0x80, b'a', 0x00];
        let encoded = encode_key(&key);
        assert_eq!(encoded, key);
        let payload = encode_set(&key, &key).unwrap_or_default();
        match split_set(&payload) {
            Ok((decoded_key, decoded_value)) => {
                assert_eq!(decoded_key, key);
                assert_eq!(decoded_value, key);
            }
            Err(failure) => assert!(
                false,
                "expected binary round trip, got {}",
                failure.class().name()
            ),
        }
    }

    #[test]
    fn get_maps_present_empty_absent_and_held() {
        let bytes = response_bytes(Kind::Response, 0x0000, b"value");
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => assert_eq!(
                interpret_get(&frame),
                Ok(GetOutcome::Present(b"value".to_vec()))
            ),
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let bytes = response_bytes(Kind::Response, 0x0000, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => {
                assert_eq!(interpret_get(&frame), Ok(GetOutcome::Present(Vec::new())));
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let bytes = response_bytes(Kind::Response, 0x0001, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => assert_eq!(interpret_get(&frame), Ok(GetOutcome::Absent)),
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let logical = 42u64.to_le_bytes();
        let bytes = response_bytes(Kind::Response, 0x0004, &logical);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => assert_eq!(
                interpret_get(&frame),
                Ok(GetOutcome::HeldOutsideMemory { logical_length: 42 })
            ),
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn del_and_exists_map_presence_exactly() {
        let bytes = response_bytes(Kind::Response, 0x0000, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => {
                assert_eq!(interpret_del(&frame), Ok(true));
                assert_eq!(interpret_exists(&frame), Ok(true));
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let bytes = response_bytes(Kind::Response, 0x0001, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => {
                assert_eq!(interpret_del(&frame), Ok(false));
                assert_eq!(interpret_exists(&frame), Ok(false));
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn set_maps_success_and_wrong_type_without_parsing_text() {
        let bytes = response_bytes(Kind::Response, 0x0000, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => assert_eq!(interpret_set(&frame), Ok(())),
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let bytes = error_response_bytes(ErrorClass::WrongType.value());
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => match interpret_set(&frame) {
                Err(failure) => {
                    assert_eq!(failure.class(), ErrorClass::WrongType);
                    assert_eq!(failure.scope(), FailureScope::RequestScoped);
                    assert!(!failure.is_ambiguous());
                }
                Ok(()) => assert!(false, "expected wrong type"),
            },
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn internal_error_preserves_ambiguity() {
        let bytes = error_response_bytes(ErrorClass::InternalError.value());
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => {
                expect_command_failure(
                    interpret_ping(&frame),
                    ErrorClass::InternalError,
                    FailureScope::RequestScoped,
                );
                expect_command_failure(
                    interpret_set(&frame),
                    ErrorClass::InternalError,
                    FailureScope::RequestScoped,
                );
                match interpret_get(&frame) {
                    Err(failure) => {
                        assert_eq!(failure.class(), ErrorClass::InternalError);
                        assert!(failure.is_ambiguous());
                    }
                    Ok(outcome) => assert!(false, "expected ambiguity, got {outcome:?}"),
                }
                match interpret_del(&frame) {
                    Err(failure) => assert!(failure.is_ambiguous()),
                    Ok(present) => assert!(false, "expected ambiguity, got {present}"),
                }
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn unexpected_result_shapes_are_protocol_violations() {
        let bytes = response_bytes(Kind::Response, 0x0001, &[]);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => {
                assert_eq!(
                    match interpret_ping(&frame) {
                        Err(failure) => failure,
                        Ok(()) => CommandFailure::new(ErrorClass::Overloaded),
                    },
                    CommandFailure::protocol_violation()
                );
                assert_eq!(
                    match interpret_set(&frame) {
                        Err(failure) => failure,
                        Ok(()) => CommandFailure::new(ErrorClass::Overloaded),
                    },
                    CommandFailure::protocol_violation()
                );
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
        let logical = 1u64.to_le_bytes();
        let bytes = response_bytes(Kind::Response, 0x0004, &logical);
        match decode_client(&bytes, &[7]) {
            Step::Frame(frame) => match interpret_del(&frame) {
                Err(failure) => assert_eq!(failure, CommandFailure::protocol_violation()),
                Ok(present) => assert!(false, "expected a violation, got {present}"),
            },
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected a frame, got {other:?}"
            ),
        }
    }

    #[test]
    fn malformed_shapes_are_connection_fatal() {
        let outgoing = Outgoing {
            kind: Kind::Response,
            code: 0x0001,
            request_id: 7,
            metadata: &[],
            payload: OutgoingPayload::Opaque(&[0xff]),
        };
        let bytes = encode(&outgoing).unwrap_or_default();
        match decode_client(&bytes, &[7]) {
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
            kind: Kind::Response,
            code: 0x0004,
            request_id: 7,
            metadata: &[],
            payload: OutgoingPayload::Opaque(&[0x01, 0x02, 0x03]),
        };
        let bytes = encode(&outgoing).unwrap_or_default();
        match decode_client(&bytes, &[7]) {
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
    fn unassigned_codes_close_the_session() {
        let cases = [(Kind::Response, 0x0002), (Kind::Error, 0x0006)];
        for (kind, code) in cases {
            let payload: &[u8] = if kind == Kind::Error {
                &[0x00, 0x00]
            } else {
                &[]
            };
            let outgoing = Outgoing {
                kind,
                code,
                request_id: 7,
                metadata: &[],
                payload: OutgoingPayload::Opaque(payload),
            };
            let bytes = encode(&outgoing).unwrap_or_default();
            match decode_client(&bytes, &[7]) {
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
    }

    #[test]
    fn required_unassigned_metadata_fails_locally_and_keeps_serving() {
        let outgoing = Outgoing {
            kind: Kind::Response,
            code: 0x0000,
            request_id: 7,
            metadata: &[(0x8000, &[])],
            payload: OutgoingPayload::Opaque(&[]),
        };
        let bytes = encode(&outgoing).unwrap_or_default();
        match decode_client(&bytes, &[7]) {
            Step::Failure { failure, consumed } => {
                assert_eq!(failure.class(), ErrorClass::InvalidArgument);
                assert_eq!(failure.scope(), FailureScope::RequestScoped);
                assert_eq!(consumed, bytes.len());
            }
            other => assert!(
                matches!(other, Step::Need(_)),
                "expected failure, got {other:?}"
            ),
        }
    }
}

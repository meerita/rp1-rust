//! Malformed-input tests for the protocol codec.
//!
//! Every case states the exact error class and the exact failure scope the
//! contract requires, because two implementations can refuse the same bytes
//! for different reasons and one of them is wrong.

use std::error::Error;

use rp1db::protocol::{self, ErrorClass, FailureScope, Role, Step};

/// Builds a frame header.
fn header(
    version: u8,
    kind: u8,
    flags: u16,
    code: u16,
    metadata_length: u16,
    payload_length: u32,
    request_id: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(version);
    out.push(kind);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&metadata_length.to_le_bytes());
    out.extend_from_slice(&payload_length.to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out
}

/// Asserts a decode produced the exact class and scope.
fn expect_failure(
    bytes: &[u8],
    role: Role,
    in_flight: &[u64],
    class: ErrorClass,
    scope: FailureScope,
) -> Result<(), Box<dyn Error>> {
    match protocol::decode(bytes, role, in_flight) {
        Step::Failure { failure, .. } => {
            assert_eq!(failure.class(), class, "class");
            assert_eq!(failure.scope(), scope, "scope");
            Ok(())
        }
        other => Err(format!("expected failure, got {other:?}").into()),
    }
}

#[test]
fn every_truncation_reports_the_bytes_it_requires() -> Result<(), Box<dyn Error>> {
    let outgoing = protocol::Outgoing {
        kind: protocol::Kind::Response,
        code: 0,
        request_id: 1,
        metadata: &[(1, &[0xaa, 0xbb])],
        payload: protocol::OutgoingPayload::Opaque(&[1, 2, 3]),
    };
    let bytes = protocol::encode(&outgoing)?;
    for end in 0..bytes.len() {
        let prefix = bytes.get(..end).ok_or("prefix out of range")?;
        match protocol::decode(prefix, Role::Client, &[1]) {
            Step::Need(required) => assert!(required > end, "required {required} not above {end}"),
            other => {
                return Err(format!("prefix of {end} bytes was not incomplete: {other:?}").into());
            }
        }
    }
    Ok(())
}

#[test]
fn a_frame_above_the_maximum_is_a_resource_limit() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 1, 0, 0, 0, 1_000_000, 1);
    bytes.extend_from_slice(&[0; 8]);
    expect_failure(
        &bytes,
        Role::Server,
        &[],
        ErrorClass::ResourceLimit,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn a_metadata_region_that_does_not_fill_is_malformed() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 2, 0, 0, 6, 0, 1);
    bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x02, 0x00]);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::MalformedRequest,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn a_non_ascending_region_is_invalid_argument() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 2, 0, 0, 8, 0, 1);
    bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::InvalidArgument,
        FailureScope::RequestScoped,
    )
}

#[test]
fn a_reserved_kind_is_a_protocol_violation() -> Result<(), Box<dyn Error>> {
    let bytes = header(0, 4, 0, 0, 0, 0, 1);
    expect_failure(
        &bytes,
        Role::Server,
        &[],
        ErrorClass::ProtocolViolation,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn a_reserved_flag_bit_is_a_protocol_violation() -> Result<(), Box<dyn Error>> {
    let bytes = header(0, 1, 0x0001, 0, 0, 0, 1);
    expect_failure(
        &bytes,
        Role::Server,
        &[],
        ErrorClass::ProtocolViolation,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn an_unsupported_version_is_reported_as_such() -> Result<(), Box<dyn Error>> {
    let bytes = header(1, 1, 0, 0, 0, 0, 1);
    expect_failure(
        &bytes,
        Role::Server,
        &[],
        ErrorClass::UnsupportedProtocolVersion,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn an_unassigned_result_code_is_a_protocol_violation() -> Result<(), Box<dyn Error>> {
    let bytes = header(0, 2, 0, 0x0002, 0, 0, 1);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::ProtocolViolation,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn an_unassigned_error_class_is_a_protocol_violation() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 3, 0, 0x0006, 0, 2, 1);
    bytes.extend_from_slice(&[0x00, 0x00]);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::ProtocolViolation,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn an_absent_response_with_a_payload_is_malformed() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 2, 0, 0x0001, 0, 1, 1);
    bytes.push(0xff);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::MalformedRequest,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn a_warm_response_with_a_short_payload_is_malformed() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 2, 0, 0x0004, 0, 7, 1);
    bytes.extend_from_slice(&[0; 7]);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::MalformedRequest,
        FailureScope::ConnectionFatal,
    )
}

#[test]
fn an_error_payload_shorter_than_the_detail_field_is_malformed() -> Result<(), Box<dyn Error>> {
    let mut bytes = header(0, 3, 0, 0x0003, 0, 1, 1);
    bytes.push(0x00);
    expect_failure(
        &bytes,
        Role::Client,
        &[1],
        ErrorClass::MalformedRequest,
        FailureScope::ConnectionFatal,
    )
}

//! Property tests for the protocol codec.
//!
//! These exercise the decoder over generated input and fragmentation
//! permutations, so arbitrary peer input cannot panic or lose framing.

use std::error::Error;

use rp1db::protocol::{self, Kind, Outgoing, OutgoingPayload, Role, Step};

/// A deterministic xorshift64 generator, so a failure is reproducible.
struct Rng(u64);

impl Rng {
    /// Builds a generator from a seed.
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Returns the next value.
    const fn next(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state.wrapping_shl(13);
        state ^= state.wrapping_shr(7);
        state ^= state.wrapping_shl(17);
        self.0 = state;
        state
    }

    /// Returns the next byte.
    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).unwrap_or(0)
    }

    /// Returns a value below `bound`.
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next().checked_rem(bound).unwrap_or(0)
    }
}

/// Decodes under the negotiated state and the pre-negotiation bounds.
fn decode_at<'a>(bytes: &'a [u8], role: Role, in_flight: &[u64]) -> Step<'a> {
    protocol::decode(
        bytes,
        protocol::Admission {
            role,
            state: protocol::ConnectionState::Negotiated,
            limits: protocol::Limits::PRE_NEGOTIATION,
            in_flight,
            capabilities: &[],
        },
    )
}

/// Encodes a minimal response for the given request id.
fn response(request_id: u64, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let outgoing = Outgoing {
        kind: Kind::Response,
        code: 0,
        request_id,
        metadata: &[],
        payload: OutgoingPayload::Opaque(payload),
    };
    Ok(protocol::encode(&outgoing)?)
}

#[test]
fn arbitrary_bytes_never_panic_the_decoder() {
    let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);
    let in_flight = [1u64, 2, 3, 4];
    for _ in 0..5_000 {
        let length = usize::try_from(rng.below(256)).unwrap_or(0);
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(rng.byte());
        }
        let role = if rng.next() & 1 == 0 {
            Role::Client
        } else {
            Role::Server
        };
        let _ = decode_at(&bytes, role, &in_flight);
    }
}

#[test]
fn arbitrary_fragmentation_preserves_the_frame() -> Result<(), Box<dyn Error>> {
    let bytes = response(7, &[1, 2, 3])?;
    let whole = match decode_at(&bytes, Role::Client, &[7]) {
        Step::Frame(frame) => frame,
        other => return Err(format!("full frame did not decode: {other:?}").into()),
    };
    for end in 1..bytes.len() {
        let prefix = bytes.get(..end).ok_or("prefix out of range")?;
        match decode_at(prefix, Role::Client, &[7]) {
            Step::Need(required) => assert!(
                required >= end,
                "a prefix of {end} bytes asked for only {required}"
            ),
            Step::Frame(frame) => assert_eq!(frame, whole, "prefix of {end} bytes decoded early"),
            Step::Failure { failure, .. } => {
                return Err(
                    format!("a valid prefix of {end} bytes was refused: {failure:?}").into(),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn concatenated_frames_decode_in_order() -> Result<(), Box<dyn Error>> {
    let mut stream = response(1, &[])?;
    let first_len = stream.len();
    stream.extend_from_slice(&response(2, b"hello")?);
    let mut remaining = stream.as_slice();

    let first = match decode_at(remaining, Role::Client, &[1, 2]) {
        Step::Frame(frame) => frame,
        other => return Err(format!("first frame did not decode: {other:?}").into()),
    };
    assert_eq!(first.header().request_id().value(), 1);

    remaining = remaining.get(first_len..).ok_or("remaining out of range")?;
    let second = match decode_at(remaining, Role::Client, &[1, 2]) {
        Step::Frame(frame) => frame,
        other => return Err(format!("second frame did not decode: {other:?}").into()),
    };
    assert_eq!(second.header().request_id().value(), 2);
    Ok(())
}

#[test]
fn every_generated_frame_round_trips() -> Result<(), Box<dyn Error>> {
    let mut rng = Rng::new(0x0123_4567_89ab_cdef);
    for _ in 0..500 {
        let request_id = rng.next();
        if request_id == 0 {
            continue;
        }
        let payload_length = usize::try_from(rng.below(64)).unwrap_or(0);
        let mut payload = Vec::with_capacity(payload_length);
        for _ in 0..payload_length {
            payload.push(rng.byte());
        }
        let bytes = response(request_id, &payload)?;
        match decode_at(&bytes, Role::Client, &[request_id]) {
            Step::Frame(frame) => {
                assert_eq!(frame.header().request_id().value(), request_id);
                assert_eq!(frame.payload(), &protocol::Payload::Opaque(&payload));
            }
            other => return Err(format!("round trip failed for {request_id}: {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn every_refusal_carries_a_class_and_a_scope() {
    let mut rng = Rng::new(0xdead_beef_cafe_babe);
    for _ in 0..2_000 {
        let length = usize::try_from(rng.below(80)).unwrap_or(0);
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(rng.byte());
        }
        if let Step::Failure { failure, .. } = decode_at(&bytes, Role::Client, &[1]) {
            let _ = failure.class().name();
            let _ = failure.scope().name();
        }
    }
}

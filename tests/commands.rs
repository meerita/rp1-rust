//! Core command surface over synthetic TCP peers.
//!
//! Each test drives the five commands against a scripted peer that
//! implements the v0.5.0 operation semantics over a byte store, and states
//! the caller-visible outcome. Binary safety, presence exactness, local
//! refusal, and concurrent use arrive here; refusal paths and ambiguity
//! arrive in the refusal suite and permutations arrive in the
//! permutation suite.

use std::collections::HashMap;
use std::error::Error;

use rp1db::protocol::{self, ErrorClass, Kind, Outgoing, OutgoingPayload};
use rp1db::{CommandError, Connection, ConnectionConfig, GetOutcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Reads exactly one request frame: header, then the declared payload.
async fn read_request(
    socket: &mut tokio::net::TcpStream,
) -> Result<(u16, u64, Vec<u8>), std::io::Error> {
    let mut header = [0u8; 20];
    let _ = socket.read_exact(&mut header).await?;
    let code = u16::from_le_bytes([header[4], header[5]]);
    let payload_length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let request_id = u64::from_le_bytes([
        header[12], header[13], header[14], header[15], header[16], header[17], header[18],
        header[19],
    ]);
    let length = usize::try_from(payload_length).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "payload length overflow")
    })?;
    let mut payload = vec![0u8; length];
    let _ = socket.read_exact(&mut payload).await?;
    Ok((code, request_id, payload))
}

/// Sends a success response carrying `payload` for `request_id`.
async fn send_response(
    socket: &mut tokio::net::TcpStream,
    code: u16,
    request_id: u64,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let outgoing = Outgoing {
        kind: Kind::Response,
        code,
        request_id,
        metadata: &[],
        payload: OutgoingPayload::Opaque(payload),
    };
    let bytes = protocol::encode(&outgoing).unwrap_or_default();
    socket.write_all(&bytes).await?;
    socket.flush().await?;
    Ok(())
}

/// Sends an error frame carrying `class` for `request_id`.
async fn send_error(
    socket: &mut tokio::net::TcpStream,
    class: u16,
    request_id: u64,
) -> Result<(), std::io::Error> {
    let outgoing = Outgoing {
        kind: Kind::Error,
        code: class,
        request_id,
        metadata: &[],
        payload: OutgoingPayload::Error {
            detail: &[],
            text: b"scripted peer refusal",
        },
    };
    let bytes = protocol::encode(&outgoing).unwrap_or_default();
    socket.write_all(&bytes).await?;
    socket.flush().await?;
    Ok(())
}

/// Answers one request from the byte store, including scripted refusals.
fn answer(
    store: &mut HashMap<Vec<u8>, Vec<u8>>,
    code: u16,
    payload: &[u8],
) -> Result<(u16, Vec<u8>), u16> {
    if code == 0x0002 {
        return Ok((0x0000, Vec::new()));
    }
    if code == 0x0004 {
        if payload.len() < 4 {
            return Err(ErrorClass::MalformedRequest.value());
        }
        let head: [u8; 4] = payload
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .unwrap_or([0, 0, 0, 0]);
        let key_length = u32::from_le_bytes(head);
        let key_end = 4usize.saturating_add(usize::try_from(key_length).unwrap_or(usize::MAX));
        let Some(key) = payload.get(4..key_end) else {
            return Err(ErrorClass::MalformedRequest.value());
        };
        let Some(value) = payload.get(key_end..) else {
            return Err(ErrorClass::MalformedRequest.value());
        };
        if key == b"ERR:wrongtype" {
            return Err(ErrorClass::WrongType.value());
        }
        if key == b"ERR:internal" {
            return Err(ErrorClass::InternalError.value());
        }
        if key == b"ERR:overloaded" {
            return Err(ErrorClass::Overloaded.value());
        }
        if key == b"ERR:invalid" {
            return Err(ErrorClass::InvalidArgument.value());
        }
        if key == b"ERR:unsupported" {
            return Err(ErrorClass::UnsupportedOperation.value());
        }
        let _ = store.insert(key.to_vec(), value.to_vec());
        return Ok((0x0000, Vec::new()));
    }
    let key = payload;
    if key == b"ERR:internal" {
        return Err(ErrorClass::InternalError.value());
    }
    if key == b"ERR:overloaded" {
        return Err(ErrorClass::Overloaded.value());
    }
    if key == b"ERR:invalid" {
        return Err(ErrorClass::InvalidArgument.value());
    }
    if key == b"ERR:unsupported" {
        return Err(ErrorClass::UnsupportedOperation.value());
    }
    match code {
        0x0003 => store.get(key).map_or_else(
            || Ok((0x0001, Vec::new())),
            |value| Ok((0x0000, value.clone())),
        ),
        0x0005 => match store.remove(key) {
            Some(_) => Ok((0x0000, Vec::new())),
            None => Ok((0x0001, Vec::new())),
        },
        0x0006 => {
            if store.contains_key(key) {
                Ok((0x0000, Vec::new()))
            } else {
                Ok((0x0001, Vec::new()))
            }
        }
        _ => Err(ErrorClass::UnsupportedOperation.value()),
    }
}

/// Serves one connection: handshake, then commands until the peer closes.
async fn serve(socket: &mut tokio::net::TcpStream) -> Result<(), std::io::Error> {
    let mut header = [0u8; 20];
    let _ = socket.read_exact(&mut header).await?;
    let payload_length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let length = usize::try_from(payload_length).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "handshake length overflow")
    })?;
    let mut handshake = vec![0u8; length];
    let _ = socket.read_exact(&mut handshake).await?;
    let mut response = Vec::new();
    response.extend_from_slice(&0u16.to_le_bytes());
    response.extend_from_slice(&65_536u32.to_le_bytes());
    response.extend_from_slice(&4_096u16.to_le_bytes());
    response.extend_from_slice(&0u16.to_le_bytes());
    let outgoing = Outgoing {
        kind: Kind::Response,
        code: 0,
        request_id: 1,
        metadata: &[],
        payload: OutgoingPayload::Opaque(&response),
    };
    let bytes = protocol::encode(&outgoing).unwrap_or_default();
    socket.write_all(&bytes).await?;
    socket.flush().await?;
    let mut store: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    loop {
        match read_request(socket).await {
            Err(error) => {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Ok(());
                }
                return Err(error);
            }
            Ok((code, request_id, payload)) => match answer(&mut store, code, &payload) {
                Ok((result, bytes)) => {
                    send_response(socket, result, request_id, &bytes).await?;
                }
                Err(class) => {
                    send_error(socket, class, request_id).await?;
                }
            },
        }
    }
}

/// Starts a scripted peer and connects a client to it.
async fn connect_to_peer() -> Result<
    (
        Connection,
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        serve(&mut socket).await?;
        Ok::<(), std::io::Error>(())
    });
    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    Ok((connection, peer))
}

#[tokio::test]
async fn ping_set_get_del_exists_round_trip() -> Result<(), Box<dyn Error>> {
    let (connection, peer) = connect_to_peer().await?;
    connection.ping().await?;
    connection.set(b"hello", b"world").await?;
    match connection.get(b"hello").await? {
        GetOutcome::Present(value) => assert_eq!(value, b"world"),
        other => return Err(format!("expected present world, got {other:?}").into()),
    }
    assert!(connection.exists(b"hello").await?);
    assert!(connection.del(b"hello").await?);
    match connection.get(b"hello").await? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent, got {other:?}").into()),
    }
    assert!(!connection.exists(b"hello").await?);
    assert!(!connection.del(b"hello").await?);
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn present_empty_and_absent_never_conflate() -> Result<(), Box<dyn Error>> {
    let (connection, peer) = connect_to_peer().await?;
    connection.set(b"empty", b"").await?;
    match connection.get(b"empty").await? {
        GetOutcome::Present(value) => assert!(value.is_empty()),
        other => return Err(format!("expected present empty, got {other:?}").into()),
    }
    match connection.get(b"missing").await? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent, got {other:?}").into()),
    }
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn arbitrary_bytes_round_trip_untouched() -> Result<(), Box<dyn Error>> {
    let (connection, peer) = connect_to_peer().await?;
    let mut all: Vec<u8> = Vec::new();
    for value in 0..=255u16 {
        all.push(u8::try_from(value).unwrap_or(0));
    }
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0x00, 0x00, 0x00],
        vec![0xff, 0xfe, 0x80],
        b"\xff\xfe not utf-8 \x80".to_vec(),
        all.clone(),
        vec![b'a'; 1_024],
        vec![0x00; 4_096],
    ];
    for (index, key) in cases.iter().enumerate() {
        let value: Vec<u8> = key.iter().copied().rev().collect();
        let tag = format!("key-{index}").into_bytes();
        let mut tagged_key = tag.clone();
        tagged_key.extend_from_slice(key);
        connection.set(&tagged_key, &value).await?;
        match connection.get(&tagged_key).await? {
            GetOutcome::Present(round_tripped) => assert_eq!(round_tripped, value),
            other => {
                return Err(format!("expected present for case {index}, got {other:?}").into());
            }
        }
    }
    connection.set(b"", b"empty-key").await?;
    match connection.get(b"").await? {
        GetOutcome::Present(value) => assert_eq!(value, b"empty-key"),
        other => return Err(format!("expected present empty key, got {other:?}").into()),
    }
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn oversized_requests_refuse_locally_and_send_nothing() -> Result<(), Box<dyn Error>> {
    let (connection, peer) = connect_to_peer().await?;
    let large = vec![b'v'; 70_000];
    match connection.set(b"big", &large).await {
        Err(CommandError::LocalLimitExceeded { .. }) => {}
        other => return Err(format!("expected a local limit, got {other:?}").into()),
    }
    connection.ping().await?;
    match connection.get(b"big").await? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent big, got {other:?}").into()),
    }
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn concurrent_mixed_commands_need_no_exclusive_borrow() -> Result<(), Box<dyn Error>> {
    let (connection, peer) = connect_to_peer().await?;
    let first = connection.clone();
    let second = connection.clone();
    let third = connection.clone();
    let fourth = connection.clone();
    let (ping, set, get, mixed) = tokio::join!(
        first.ping(),
        second.set(b"concurrent", b"value"),
        third.get(b"missing"),
        async {
            fourth.set(b"mixed", b"1").await?;
            fourth.exists(b"mixed").await
        },
    );
    ping?;
    set?;
    match get? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent, got {other:?}").into()),
    }
    assert!(mixed?);
    match connection.get(b"concurrent").await? {
        GetOutcome::Present(value) => assert_eq!(value, b"value"),
        other => return Err(format!("expected present, got {other:?}").into()),
    }
    connection.close().await?;
    peer.abort();
    Ok(())
}

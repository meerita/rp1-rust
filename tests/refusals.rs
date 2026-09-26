//! Refusal paths and preserved ambiguity over synthetic TCP peers.
//!
//! Each test drives one reachable server refusal through the public
//! commands and states the caller-visible outcome, the failure scope,
//! and the session effect. Request-scoped refusals retire exactly one
//! request and keep the session usable; internal error preserves
//! ambiguity and is never retried automatically.

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rp1db::protocol::{self, ErrorClass, FailureScope, Kind, Outgoing, OutgoingPayload};
use rp1db::{CommandError, Connection, ConnectionConfig, ConnectionState, GetOutcome};
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

/// Serves one connection: handshake, then counted commands.
async fn serve(
    socket: &mut tokio::net::TcpStream,
    commands: Arc<AtomicUsize>,
) -> Result<(), std::io::Error> {
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
            Ok((code, request_id, payload)) => {
                let _ = commands.fetch_add(1, Ordering::SeqCst);
                match answer(&mut store, code, &payload) {
                    Ok((result, bytes)) => {
                        send_response(socket, result, request_id, &bytes).await?;
                    }
                    Err(class) => {
                        send_error(socket, class, request_id).await?;
                    }
                }
            }
        }
    }
}

/// Starts a counting peer and connects a client to it.
async fn connect_to_peer() -> Result<
    (
        Connection,
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
        Arc<AtomicUsize>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let commands = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&commands);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        serve(&mut socket, counter).await?;
        Ok::<(), std::io::Error>(())
    });
    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    Ok((connection, peer, commands))
}

/// Asserts a refusal keeps the session usable for the next request.
async fn expect_usable(connection: &Connection) -> Result<(), Box<dyn Error>> {
    assert_eq!(connection.state(), ConnectionState::Usable);
    connection.ping().await?;
    Ok(())
}

#[tokio::test]
async fn unsupported_operation_retires_one_request() -> Result<(), Box<dyn Error>> {
    let (connection, peer, commands) = connect_to_peer().await?;
    match connection.get(b"ERR:unsupported").await {
        Err(CommandError::UnsupportedOperation) => {}
        other => return Err(format!("expected unsupported, got {other:?}").into()),
    }
    match connection.get(b"ERR:unsupported").await {
        Err(error) => assert_eq!(error.scope(), Some(FailureScope::RequestScoped)),
        other => return Err(format!("expected unsupported scope, got {other:?}").into()),
    }
    expect_usable(&connection).await?;
    assert_eq!(commands.load(Ordering::SeqCst), 3);
    assert_eq!(commands.load(Ordering::SeqCst), 3);
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn invalid_argument_overloaded_and_wrong_type_stay_request_scoped()
-> Result<(), Box<dyn Error>> {
    let (connection, peer, _commands) = connect_to_peer().await?;
    match connection.get(b"ERR:invalid").await {
        Err(error) => {
            assert!(matches!(error, CommandError::InvalidArgument));
            assert_eq!(error.scope(), Some(FailureScope::RequestScoped));
            assert!(!error.is_ambiguous());
        }
        other => return Err(format!("expected invalid argument, got {other:?}").into()),
    }
    expect_usable(&connection).await?;
    match connection.get(b"ERR:overloaded").await {
        Err(error) => {
            assert!(matches!(error, CommandError::Overloaded));
            assert_eq!(error.scope(), Some(FailureScope::RequestScoped));
            assert!(!error.is_ambiguous());
        }
        other => return Err(format!("expected overloaded, got {other:?}").into()),
    }
    expect_usable(&connection).await?;
    match connection.set(b"ERR:wrongtype", b"value").await {
        Err(error) => {
            assert!(matches!(error, CommandError::WrongType));
            assert_eq!(error.scope(), Some(FailureScope::RequestScoped));
            assert!(!error.is_ambiguous());
        }
        other => return Err(format!("expected wrong type, got {other:?}").into()),
    }
    expect_usable(&connection).await?;
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn internal_error_preserves_ambiguity_without_retry() -> Result<(), Box<dyn Error>> {
    let (connection, peer, commands) = connect_to_peer().await?;
    let before = commands.load(Ordering::SeqCst);
    match connection.set(b"ERR:internal", b"value").await {
        Err(error) => {
            assert!(matches!(error, CommandError::InternalError));
            assert_eq!(error.scope(), Some(FailureScope::RequestScoped));
            assert!(error.is_ambiguous());
        }
        other => return Err(format!("expected internal error, got {other:?}").into()),
    }
    assert_eq!(commands.load(Ordering::SeqCst), before.saturating_add(1));
    expect_usable(&connection).await?;
    match connection.get(b"ERR:internal").await {
        Err(error) => assert!(error.is_ambiguous()),
        other => return Err(format!("expected ambiguity, got {other:?}").into()),
    }
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn refused_and_successful_requests_do_not_interfere() -> Result<(), Box<dyn Error>> {
    let (connection, peer, _commands) = connect_to_peer().await?;
    connection.set(b"shared", b"kept").await?;
    let first = connection.clone();
    let second = connection.clone();
    let (refused, kept) = tokio::join!(first.get(b"ERR:invalid"), second.get(b"shared"),);
    match refused {
        Err(CommandError::InvalidArgument) => {}
        other => return Err(format!("expected invalid argument, got {other:?}").into()),
    }
    match kept {
        Ok(GetOutcome::Present(value)) => assert_eq!(value, b"kept"),
        other => return Err(format!("expected kept value, got {other:?}").into()),
    }
    expect_usable(&connection).await?;
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn set_wrong_type_stores_nothing_del_never_wrong_types() -> Result<(), Box<dyn Error>> {
    let (connection, peer, _commands) = connect_to_peer().await?;
    match connection.set(b"ERR:wrongtype", b"value").await {
        Err(CommandError::WrongType) => {}
        other => return Err(format!("expected wrong type, got {other:?}").into()),
    }
    match connection.get(b"ERR:wrongtype").await? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent, got {other:?}").into()),
    }
    assert!(!connection.del(b"ERR:wrongtype").await?);
    assert!(!connection.exists(b"ERR:wrongtype").await?);
    connection.set(b"plain", b"value").await?;
    assert!(connection.exists(b"plain").await?);
    assert!(connection.del(b"plain").await?);
    connection.close().await?;
    peer.abort();
    Ok(())
}

#[tokio::test]
async fn older_servers_answer_unsupported_per_request_with_open_session()
-> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut header = [0u8; 20];
        let _ = socket.read_exact(&mut header).await?;
        let payload_length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let length = usize::try_from(payload_length).unwrap_or(0);
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
        loop {
            match read_request(&mut socket).await {
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                    return Err(error);
                }
                Ok((_code, request_id, _payload)) => {
                    send_error(
                        &mut socket,
                        ErrorClass::UnsupportedOperation.value(),
                        request_id,
                    )
                    .await?;
                }
            }
        }
    });
    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    for key in [b"a".as_slice(), b"b".as_slice()] {
        match connection.get(key).await {
            Err(CommandError::UnsupportedOperation) => {}
            other => return Err(format!("expected unsupported, got {other:?}").into()),
        }
        assert_eq!(connection.state(), ConnectionState::Usable);
    }
    match connection.ping().await {
        Err(CommandError::UnsupportedOperation) => {}
        other => return Err(format!("expected unsupported ping, got {other:?}").into()),
    }
    assert_eq!(connection.state(), ConnectionState::Usable);
    connection.close().await?;
    peer.abort();
    Ok(())
}

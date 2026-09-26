//! Connection establishment conformance, layer B.
//!
//! Each test drives `Connection` against a synthetic TCP peer and states
//! both the caller-visible outcome and the connection-state outcome. The
//! scenario identifiers are stable: a later revision adds scenarios but
//! does not change what an identifier below proves.
//!
//! ```text
//! B.hello.valid-exchange                  connect_completes_against_a_fragmenting_peer
//! B.hello.no-mutual-version               handshake_refused_without_a_mutual_version
//! B.hello.version-outside-offer           handshake_response_outside_the_offered_range_fails
//! B.hello.bound-below-floor               handshake_response_below_the_frame_floor_fails
//! B.hello.unoffered-capability            handshake_accepting_an_unoffered_capability_fails
//! B.lifecycle.frame-before-handshake      frame_before_the_handshake_is_refused
//! B.lifecycle.handshake-first-and-once    client_sends_the_handshake_first_and_only_once
//! B.transport.fragmented-handshake        connect_completes_against_a_fragmenting_peer
//! B.transport.peer-close-during-handshake peer_close_during_the_handshake_is_reported
//! B.state.usable-then-closed              usable_connection_closes_explicitly
//! B.state.failed-close                    unit: a_failed_shutdown_moves_the_connection_to_failed
//! B.state.mapping                         unit: the_lifecycle_states_map_onto_the_protocol_states
//! B.limits.local-validation               unit: a_local_frame_size_below_the_floor_is_refused
//!                                         unit: a_local_metadata_size_below_the_floor_is_refused
//! B.limits.negotiated-frame-above-local   negotiated_frame_above_the_local_cap_is_refused
//! B.limits.negotiated-metadata-above-local
//!                                         negotiated_metadata_above_the_local_cap_is_refused
//! B.limits.local-and-effective-exposed    usable_connection_reports_local_and_effective_limits
//! B.config.empty-endpoint                 an_empty_endpoint_fails_before_connecting
//! ```

use std::error::Error;
use std::io::ErrorKind;

use rp1db::protocol::{self, ErrorClass, Kind, Outgoing, OutgoingPayload};
use rp1db::{ConnectError, Connection, ConnectionConfig, ConnectionState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The request id the handshake request carries.
const REQUEST_ID: u64 = 1;

/// Builds a handshake response frame carrying a success result code.
fn response_frame(version: u16, frame_size: u32, metadata_size: u16) -> Vec<u8> {
    response_frame_with_entries(version, frame_size, metadata_size, &[])
}

/// Builds a handshake response frame carrying capability entries.
fn response_frame_with_entries(
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
    let outgoing = Outgoing {
        kind: Kind::Response,
        code: 0,
        request_id: REQUEST_ID,
        metadata: &[],
        payload: OutgoingPayload::Opaque(&payload),
    };
    protocol::encode(&outgoing).unwrap_or_default()
}

/// Builds an error frame carrying the given class.
fn error_frame(class: u16) -> Vec<u8> {
    let outgoing = Outgoing {
        kind: Kind::Error,
        code: class,
        request_id: REQUEST_ID,
        metadata: &[],
        payload: OutgoingPayload::Error {
            detail: &[],
            text: &[],
        },
    };
    protocol::encode(&outgoing).unwrap_or_default()
}

/// Reads one frame and returns its header fields.
async fn read_frame(
    socket: &mut tokio::net::TcpStream,
) -> Result<(u8, u8, u16, Vec<u8>), std::io::Error> {
    let mut header = [0u8; 20];
    let _ = socket.read_exact(&mut header).await?;
    let version = header[0];
    let kind = header[1];
    let code = u16::from_le_bytes([header[4], header[5]]);
    let payload_length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let length = usize::try_from(payload_length)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "payload length overflow"))?;
    let mut payload = vec![0u8; length];
    let _ = socket.read_exact(&mut payload).await?;
    Ok((version, kind, code, payload))
}

// Scenario B.hello.valid-exchange and B.transport.fragmented-handshake:
// a valid handshake yields a usable connection, even when the response
// arrives one byte per read. Caller outcome: a usable connection with the
// negotiated values. State outcome: usable.
#[tokio::test]
async fn connect_completes_against_a_fragmenting_peer() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 65_536, 4_096);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        for byte in &response {
            socket.write_all(std::slice::from_ref(byte)).await?;
        }
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    assert_eq!(connection.protocol_version(), 0);
    assert_eq!(connection.maximum_frame_size(), 65_536);
    assert_eq!(connection.maximum_metadata_size(), 4_096);
    assert!(connection.accepted_capabilities().is_empty());
    assert_eq!(connection.state(), ConnectionState::Usable);
    connection.close().await?;
    assert_eq!(connection.state(), ConnectionState::Closed);
    peer.await??;
    Ok(())
}

// Scenario B.hello.no-mutual-version: the peer answers the unsupported
// version class. Caller outcome: a structured handshake failure naming
// the class. State outcome: no connection exists.
#[tokio::test]
async fn handshake_refused_without_a_mutual_version() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let refusal = error_frame(ErrorClass::UnsupportedProtocolVersion.value());
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&refusal).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::HandshakeFailure(failure)) => {
            assert_eq!(failure.class(), ErrorClass::UnsupportedProtocolVersion);
        }
        other => return Err(format!("expected a version refusal, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.hello.version-outside-offer: the peer states a version above
// the offered range. Caller outcome: a malformed handshake failure.
// State outcome: no connection exists.
#[tokio::test]
async fn handshake_response_outside_the_offered_range_fails() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(1, 65_536, 4_096);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::HandshakeFailure(failure)) => {
            assert_eq!(failure.class(), ErrorClass::MalformedRequest);
        }
        other => return Err(format!("expected a malformed handshake, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.hello.bound-below-floor: the peer states a frame bound below
// the protocol floor. Caller outcome: a malformed handshake failure.
// State outcome: no connection exists.
#[tokio::test]
async fn handshake_response_below_the_frame_floor_fails() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 1_000, 4_096);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::HandshakeFailure(failure)) => {
            assert_eq!(failure.class(), ErrorClass::MalformedRequest);
        }
        other => return Err(format!("expected a malformed handshake, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.hello.unoffered-capability: the peer accepts a capability
// the offerer never offered. Caller outcome: a protocol violation
// failure. State outcome: no connection exists.
#[tokio::test]
async fn handshake_accepting_an_unoffered_capability_fails() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame_with_entries(0, 65_536, 4_096, &[(1, &[])]);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::HandshakeFailure(failure)) => {
            assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
        }
        other => return Err(format!("expected a protocol violation, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.lifecycle.frame-before-handshake: the first frame is not the
// handshake response. Caller outcome: a handshake failure naming the
// protocol violation class. State outcome: no connection exists and the
// transport is closed.
#[tokio::test]
async fn frame_before_the_handshake_is_refused() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        let outgoing = Outgoing {
            kind: Kind::Response,
            code: 1,
            request_id: REQUEST_ID,
            metadata: &[],
            payload: OutgoingPayload::Opaque(&[]),
        };
        let frame = protocol::encode(&outgoing).unwrap_or_default();
        socket.write_all(&frame).await?;
        socket.flush().await?;
        let mut probe = [0u8; 1];
        let read = socket.read(&mut probe).await?;
        assert_eq!(read, 0, "the client closes the transport after the refusal");
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::HandshakeFailure(failure)) => {
            assert_eq!(failure.class(), ErrorClass::ProtocolViolation);
        }
        other => return Err(format!("expected a protocol violation, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.lifecycle.handshake-first-and-once: the client sends the
// handshake request as the first frame and sends nothing else. Caller
// outcome: a usable connection. State outcome: usable, and the peer
// observes exactly one frame before the connection goes quiet.
#[tokio::test]
async fn client_sends_the_handshake_first_and_only_once() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 65_536, 4_096);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let (version, kind, code, payload) = read_frame(&mut socket).await?;
        if version != 0 || kind != 1 || code != 0x0001 || payload.len() < 10 {
            return Err::<(), std::io::Error>(std::io::Error::new(
                ErrorKind::InvalidData,
                "the first frame is not the handshake request",
            ));
        }
        socket.write_all(&response).await?;
        socket.flush().await?;
        let mut probe = [0u8; 1];
        match socket.try_read(&mut probe) {
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
            other => Err(std::io::Error::other(format!(
                "expected quiet after one frame, got {other:?}"
            ))),
        }
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    assert_eq!(connection.state(), ConnectionState::Usable);
    connection.close().await?;
    peer.await??;
    Ok(())
}

// Scenario B.transport.peer-close-during-handshake: the peer closes
// without answering. Caller outcome: a closed-during-handshake error.
// State outcome: no connection exists.
#[tokio::test]
async fn peer_close_during_the_handshake_is_reported() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        // Drain the handshake request so the close below produces an
        // orderly end of stream rather than a reset.
        let _ = read_frame(&mut socket).await;
        drop(socket);
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::ClosedDuringHandshake) => {}
        other => return Err(format!("expected a closed handshake, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.state.usable-then-closed: an orderly shutdown moves the
// connection from usable to closed. Caller outcome: close succeeds.
// State outcome: closed, and no longer usable.
#[tokio::test]
async fn usable_connection_closes_explicitly() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 65_536, 4_096);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        let mut probe = [0u8; 1];
        let read = socket.read(&mut probe).await?;
        assert_eq!(read, 0, "close shuts the transport down");
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    assert_eq!(connection.state(), ConnectionState::Usable);
    assert!(connection.is_usable());
    connection.close().await?;
    assert_eq!(connection.state(), ConnectionState::Closed);
    assert!(!connection.is_usable());
    peer.await??;
    Ok(())
}

// Scenario B.limits.negotiated-frame-above-local: the peer negotiates a
// frame bound above the local cap. Caller outcome: a structured local
// refusal naming both values. State outcome: no connection exists and
// the transport is closed.
#[tokio::test]
async fn negotiated_frame_above_the_local_cap_is_refused() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 131_072, 4_096);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        let mut probe = [0u8; 1];
        let read = socket.read(&mut probe).await?;
        assert_eq!(read, 0, "the client closes the transport after the refusal");
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string()).desired_maximum_frame_size(131_072);
    match Connection::connect(&config).await {
        Err(ConnectError::NegotiatedFrameSizeAboveLocal { negotiated, local }) => {
            assert_eq!(negotiated, 131_072);
            assert_eq!(local, 65_536);
        }
        other => return Err(format!("expected a local refusal, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.limits.negotiated-metadata-above-local: the peer negotiates
// a metadata bound above the local cap. Caller outcome: a structured
// local refusal naming both values. State outcome: no connection exists.
#[tokio::test]
async fn negotiated_metadata_above_the_local_cap_is_refused() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 65_536, 8_192);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    match Connection::connect(&config).await {
        Err(ConnectError::NegotiatedMetadataSizeAboveLocal { negotiated, local }) => {
            assert_eq!(negotiated, 8_192);
            assert_eq!(local, 4_096);
        }
        other => return Err(format!("expected a local refusal, got {other:?}").into()),
    }
    peer.await??;
    Ok(())
}

// Scenario B.limits.local-and-effective-exposed: a usable connection
// reports the local caps and the effective bounds. Caller outcome: a
// usable connection. State outcome: usable, with effective bounds equal
// to the negotiated values the local caps admit.
#[tokio::test]
async fn usable_connection_reports_local_and_effective_limits() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let response = response_frame(0, 131_072, 8_192);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await?;
        socket.write_all(&response).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string())
        .desired_maximum_frame_size(131_072)
        .local_maximum_frame_size(131_072)
        .local_maximum_metadata_size(8_192);
    let connection = Connection::connect(&config).await?;
    assert_eq!(connection.maximum_frame_size(), 131_072);
    assert_eq!(connection.maximum_metadata_size(), 8_192);
    assert_eq!(connection.local_maximum_frame_size(), 131_072);
    assert_eq!(connection.local_maximum_metadata_size(), 8_192);
    assert_eq!(connection.effective_maximum_frame_size(), 131_072);
    assert_eq!(connection.effective_maximum_metadata_size(), 8_192);
    connection.close().await?;
    peer.await??;
    Ok(())
}

#[tokio::test]
async fn an_empty_endpoint_fails_before_connecting() -> Result<(), Box<dyn Error>> {
    let config = ConnectionConfig::new("");
    assert!(Connection::connect(&config).await.is_err());
    Ok(())
}

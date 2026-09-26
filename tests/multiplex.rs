//! Multiplexing conformance, layer B, public surface.
//!
//! Each test drives `Connection` against a synthetic TCP peer and states
//! both the caller-visible outcome and the connection-state outcome. The
//! scenario identifiers are stable.
//!
//! ```text
//! B.multiplex.bound-default-64    default_bound_is_sixty_four_over_tcp
//! B.multiplex.bound-configured    configured_bound_is_exposed_over_tcp
//! B.multiplex.clone-shares        clones_share_one_session_over_tcp
//! B.multiplex.concurrent-clones   concurrent_clones_read_without_an_exclusive_borrow
//! B.multiplex.close-idempotent    close_is_idempotent_over_tcp
//! ```

use std::error::Error;

use rp1db::protocol::{Kind, Outgoing, OutgoingPayload};
use rp1db::{Connection, ConnectionConfig, ConnectionState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Builds a handshake response frame carrying a success result code.
fn response_frame(version: u16, frame_size: u32, metadata_size: u16) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&version.to_le_bytes());
    payload.extend_from_slice(&frame_size.to_le_bytes());
    payload.extend_from_slice(&metadata_size.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    let outgoing = Outgoing {
        kind: Kind::Response,
        code: 0,
        request_id: 1,
        metadata: &[],
        payload: OutgoingPayload::Opaque(&payload),
    };
    rp1db::protocol::encode(&outgoing).unwrap_or_default()
}

// Scenario B.multiplex.bound-default-64: a usable connection reports the
// default in-flight bound. Caller outcome: a usable connection with bound
// 64. State outcome: usable.
#[tokio::test]
async fn default_bound_is_sixty_four_over_tcp() -> Result<(), Box<dyn Error>> {
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
        let _ = socket.read(&mut probe).await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    assert_eq!(connection.maximum_in_flight(), 64);
    assert_eq!(connection.state(), ConnectionState::Usable);
    connection.close().await?;
    assert_eq!(connection.state(), ConnectionState::Closed);
    peer.await??;
    Ok(())
}

// Scenario B.multiplex.bound-configured: the configured bound is exposed.
// Caller outcome: a usable connection with the configured bound. State
// outcome: usable.
#[tokio::test]
async fn configured_bound_is_exposed_over_tcp() -> Result<(), Box<dyn Error>> {
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
        let _ = socket.read(&mut probe).await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string()).maximum_in_flight(16);
    let connection = Connection::connect(&config).await?;
    assert_eq!(connection.maximum_in_flight(), 16);
    connection.close().await?;
    peer.await??;
    Ok(())
}

// Scenario B.multiplex.clone-shares: clones share one session. Caller
// outcome: close through any handle. State outcome: closed for every
// handle, and a second close succeeds.
#[tokio::test]
async fn clones_share_one_session_over_tcp() -> Result<(), Box<dyn Error>> {
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
        let _ = socket.read(&mut probe).await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    let peer_handle = connection.clone();
    assert_eq!(
        peer_handle.protocol_version(),
        connection.protocol_version()
    );
    connection.close().await?;
    assert_eq!(connection.state(), ConnectionState::Closed);
    assert_eq!(peer_handle.state(), ConnectionState::Closed);
    assert!(!peer_handle.is_usable());
    peer_handle.close().await?;
    peer.await??;
    Ok(())
}

// Scenario B.multiplex.concurrent-clones: concurrent tasks use clones
// without an exclusive borrow. Caller outcome: every task reads the
// shared session. State outcome: usable throughout.
#[tokio::test]
async fn concurrent_clones_read_without_an_exclusive_borrow() -> Result<(), Box<dyn Error>> {
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
        let _ = socket.read(&mut probe).await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    let first = connection.clone();
    let second = connection.clone();
    let (version, bound, usable) = tokio::join!(
        async { first.protocol_version() },
        async { second.maximum_in_flight() },
        async { connection.is_usable() },
    );
    assert_eq!(version, 0);
    assert_eq!(bound, 64);
    assert!(usable);
    connection.close().await?;
    peer.await??;
    Ok(())
}

// Scenario B.multiplex.close-idempotent: closing twice succeeds. Caller
// outcome: close succeeds. State outcome: closed, still closed.
#[tokio::test]
async fn close_is_idempotent_over_tcp() -> Result<(), Box<dyn Error>> {
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
        let _ = socket.read(&mut probe).await?;
        Ok::<(), std::io::Error>(())
    });

    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    connection.close().await?;
    connection.close().await?;
    assert_eq!(connection.state(), ConnectionState::Closed);
    peer.await??;
    Ok(())
}

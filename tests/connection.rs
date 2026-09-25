//! Connection integration tests over a real TCP peer.

use std::error::Error;

use rp1db::protocol::{self, Kind, Outgoing, OutgoingPayload};
use rp1db::{Connection, ConnectionConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The request id the handshake request carries.
const REQUEST_ID: u64 = 1;

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
        request_id: REQUEST_ID,
        metadata: &[],
        payload: OutgoingPayload::Opaque(&payload),
    };
    protocol::encode(&outgoing).unwrap_or_default()
}

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
    let mut connection = Connection::connect(&config).await?;
    assert_eq!(connection.protocol_version(), 0);
    assert_eq!(connection.maximum_frame_size(), 65_536);
    assert_eq!(connection.maximum_metadata_size(), 4_096);
    assert!(connection.accepted_capabilities().is_empty());
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

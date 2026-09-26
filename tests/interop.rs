//! Black-box interoperability against a real server build, layer C.
//!
//! These tests treat the server as an external network service: they
//! launch the binary named by `RP1_SERVER_BIN`, wait for TCP readiness,
//! and exercise the happy and miss paths through the public client only.
//! No private crate is linked and no server internals are required.
//!
//! Environment inputs:
//!
//! ```text
//! RP1_SERVER_BIN   required: path to the server binary under test
//! ```
//!
//! When `RP1_SERVER_BIN` is unset the tests report the skip and succeed
//! without interop evidence; a closing gate run sets it and records the
//! exact server identity (version string, binary, and source revision)
//! in the execution record. The tests print the probed version string so
//! raw validation output carries it.
//!
//! Scenario identifiers:
//!
//! ```text
//! C.ping.black-box            black_box_ping_and_handshake
//! C.set.black-box-hit        black_box_set_get_hit
//! C.get.black-box-hit        black_box_set_get_hit
//! C.get.black-box-miss       black_box_miss_paths
//! C.del.black-box            black_box_miss_paths
//! C.exists.black-box         black_box_miss_paths
//! C.binary.black-box         black_box_binary_round_trip
//! ```

use std::error::Error;
use std::process::Stdio;
use std::time::Duration;

use rp1db::{Connection, ConnectionConfig, GetOutcome};
use tokio::net::TcpListener;

/// Returns the server binary under test, or `None` when interop is skipped.
fn server_binary() -> Option<String> {
    std::env::var("RP1_SERVER_BIN")
        .ok()
        .filter(|path| !path.trim().is_empty())
}

/// Probes the server version string for the execution record.
async fn server_version(binary: &str) -> String {
    match tokio::process::Command::new(binary)
        .arg("--version")
        .output()
        .await
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Picks an unused loopback port for one server instance.
async fn free_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Waits for TCP readiness with a bounded poll, not a fixed sleep.
async fn wait_ready(address: &str) -> Result<(), Box<dyn Error>> {
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
            drop(stream);
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(10) {
            return Err("the server did not become ready".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Starts one server instance and returns its child and address.
async fn start_server(binary: &str) -> Result<(tokio::process::Child, String), Box<dyn Error>> {
    let port = free_port().await?;
    let address = format!("127.0.0.1:{port}");
    let version = server_version(binary).await;
    println!("black-box server: binary={binary} version={version} address={address}");
    let child = tokio::process::Command::new(binary)
        .arg("--listen")
        .arg(&address)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    wait_ready(&address).await?;
    Ok((child, address))
}

/// Connects a client to one fresh server, or skips without evidence.
async fn connect_fresh() -> Result<Option<(Connection, tokio::process::Child)>, Box<dyn Error>> {
    let Some(binary) = server_binary() else {
        println!("black-box interop skipped: RP1_SERVER_BIN is unset");
        return Ok(None);
    };
    let (child, address) = start_server(&binary).await?;
    let config = ConnectionConfig::new(address);
    let connection = Connection::connect(&config).await?;
    Ok(Some((connection, child)))
}

#[tokio::test]
async fn black_box_ping_and_handshake() -> Result<(), Box<dyn Error>> {
    let Some((connection, mut child)) = connect_fresh().await? else {
        return Ok(());
    };
    assert_eq!(connection.protocol_version(), 0);
    connection.ping().await?;
    connection.close().await?;
    let _ = child.kill().await;
    Ok(())
}

#[tokio::test]
async fn black_box_set_get_hit() -> Result<(), Box<dyn Error>> {
    let Some((connection, mut child)) = connect_fresh().await? else {
        return Ok(());
    };
    connection.set(b"interop-key", b"interop-value").await?;
    match connection.get(b"interop-key").await? {
        GetOutcome::Present(value) => assert_eq!(value, b"interop-value"),
        other => return Err(format!("expected interop-value, got {other:?}").into()),
    }
    connection.close().await?;
    let _ = child.kill().await;
    Ok(())
}

#[tokio::test]
async fn black_box_miss_paths() -> Result<(), Box<dyn Error>> {
    let Some((connection, mut child)) = connect_fresh().await? else {
        return Ok(());
    };
    match connection.get(b"interop-missing").await? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent, got {other:?}").into()),
    }
    assert!(!connection.exists(b"interop-missing").await?);
    assert!(!connection.del(b"interop-missing").await?);
    connection.set(b"interop-temp", b"v").await?;
    assert!(connection.exists(b"interop-temp").await?);
    assert!(connection.del(b"interop-temp").await?);
    match connection.get(b"interop-temp").await? {
        GetOutcome::Absent => {}
        other => return Err(format!("expected absent after del, got {other:?}").into()),
    }
    connection.close().await?;
    let _ = child.kill().await;
    Ok(())
}

#[tokio::test]
async fn black_box_binary_round_trip() -> Result<(), Box<dyn Error>> {
    let Some((connection, mut child)) = connect_fresh().await? else {
        return Ok(());
    };
    let key = b"interop-\x00-binary-\xff".to_vec();
    let value = b"\x80\xfe\x00value".to_vec();
    connection.set(&key, &value).await?;
    match connection.get(&key).await? {
        GetOutcome::Present(round_tripped) => assert_eq!(round_tripped, value),
        other => return Err(format!("expected binary value, got {other:?}").into()),
    }
    connection.close().await?;
    let _ = child.kill().await;
    Ok(())
}

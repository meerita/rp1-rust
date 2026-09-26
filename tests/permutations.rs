//! Multiplexed command permutations over TCP, layer B.
//!
//! Each test submits three commands concurrently through clones and has a
//! scripted peer answer in a fixed order, proving correlation by request
//! ID alone. Scenario identifiers are stable.
//!
//! ```text
//! B.multiplex.ordered-completion-commands    submit_a_b_c_complete_a_b_c
//! B.multiplex.reverse-completion-commands    submit_a_b_c_complete_c_b_a
//! B.multiplex.permuted-completion-commands   submit_a_b_c_complete_b_c_a
//! B.multiplex.permuted-completion-commands-2 submit_a_b_c_complete_b_a_c
//! B.multiplex.fragmented-completion-commands fragmented_responses_still_dispatch_by_id
//! B.multiplex.mixed-completion-commands      mixed_commands_complete_out_of_order
//! ```
//!
//! Layer C core-profile coverage lives in the command, refusal, and
//! black-box suites:
//!
//! ```text
//! C.ping.round-trip        commands::ping_set_get_del_exists_round_trip
//! C.get.hit                commands::ping_set_get_del_exists_round_trip
//! C.get.miss               commands::ping_set_get_del_exists_round_trip
//! C.get.empty-value        commands::present_empty_and_absent_never_conflate
//! C.get.binary             commands::arbitrary_bytes_round_trip_untouched
//! C.set.binary             commands::arbitrary_bytes_round_trip_untouched
//! C.set.empty              commands::present_empty_and_absent_never_conflate
//! C.del.present-absent     commands::ping_set_get_del_exists_round_trip
//! C.exists.present-absent  commands::ping_set_get_del_exists_round_trip
//! C.errors.refusals        refusals::invalid_argument_overloaded_and_wrong_type_stay_request_scoped
//! C.errors.ambiguity       refusals::internal_error_preserves_ambiguity_without_retry
//! C.errors.older-server    refusals::older_servers_answer_unsupported_per_request_with_open_session
//! ```
//!
//! Excluded with the escalated sub-case (no receiver rule at this
//! revision for a non-empty success payload on PING, SET, DEL, or
//! EXISTS; no conforming server sends one):
//!
//! ```text
//! C.ping.non-empty-success        excluded
//! C.set.non-empty-success         excluded
//! C.del.non-empty-success         excluded
//! C.exists.non-empty-success      excluded
//! ```

use std::collections::HashMap;
use std::error::Error;

use rp1db::protocol::{self, Kind, Outgoing, OutgoingPayload};
use rp1db::{Connection, ConnectionConfig, GetOutcome};
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

/// Sends one response frame, optionally one byte per write.
async fn send_response(
    socket: &mut tokio::net::TcpStream,
    code: u16,
    request_id: u64,
    payload: &[u8],
    bytewise: bool,
) -> Result<(), std::io::Error> {
    let outgoing = Outgoing {
        kind: Kind::Response,
        code,
        request_id,
        metadata: &[],
        payload: OutgoingPayload::Opaque(payload),
    };
    let bytes = protocol::encode(&outgoing).unwrap_or_default();
    if bytewise {
        for byte in &bytes {
            socket.write_all(std::slice::from_ref(byte)).await?;
        }
    } else {
        socket.write_all(&bytes).await?;
    }
    socket.flush().await?;
    Ok(())
}

/// Serves the handshake, seeds three keys, then answers three GETs in order.
async fn serve_permutation(
    socket: &mut tokio::net::TcpStream,
    order: &[usize],
    bytewise: bool,
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
    let _ = store.insert(b"a".to_vec(), b"value-a".to_vec());
    let _ = store.insert(b"b".to_vec(), b"value-b".to_vec());
    let _ = store.insert(b"c".to_vec(), b"value-c".to_vec());
    let mut requests = Vec::new();
    while requests.len() < 3 {
        let (_, request_id, payload) = read_request(socket).await?;
        let value = store.get(&payload).cloned().unwrap_or_default();
        requests.push((request_id, value));
    }
    for position in order {
        let index = *position;
        let Some((request_id, value)) = requests.get(index) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unknown order position",
            ));
        };
        send_response(socket, 0x0000, *request_id, value, bytewise).await?;
    }
    Ok(())
}

/// Runs one permutation of three concurrent GETs over TCP.
async fn run_permutation(order: &[usize], bytewise: bool) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let order_owned = order.to_vec();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        serve_permutation(&mut socket, &order_owned, bytewise).await?;
        Ok::<(), std::io::Error>(())
    });
    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    let first = connection.clone();
    let second = connection.clone();
    let third = connection.clone();
    let (outcome_a, outcome_b, outcome_c) =
        tokio::join!(first.get(b"a"), second.get(b"b"), third.get(b"c"),);
    match outcome_a? {
        GetOutcome::Present(value) => assert_eq!(value, b"value-a"),
        other => return Err(format!("expected value-a, got {other:?}").into()),
    }
    match outcome_b? {
        GetOutcome::Present(value) => assert_eq!(value, b"value-b"),
        other => return Err(format!("expected value-b, got {other:?}").into()),
    }
    match outcome_c? {
        GetOutcome::Present(value) => assert_eq!(value, b"value-c"),
        other => return Err(format!("expected value-c, got {other:?}").into()),
    }
    assert_eq!(connection.state(), rp1db::ConnectionState::Usable);
    connection.close().await?;
    peer.abort();
    Ok(())
}

// B.multiplex.ordered-completion-commands
#[tokio::test]
async fn submit_a_b_c_complete_a_b_c() -> Result<(), Box<dyn Error>> {
    run_permutation(&[0, 1, 2], false).await
}

// B.multiplex.reverse-completion-commands
#[tokio::test]
async fn submit_a_b_c_complete_c_b_a() -> Result<(), Box<dyn Error>> {
    run_permutation(&[2, 1, 0], false).await
}

// B.multiplex.permuted-completion-commands
#[tokio::test]
async fn submit_a_b_c_complete_b_c_a() -> Result<(), Box<dyn Error>> {
    run_permutation(&[1, 2, 0], false).await
}

// B.multiplex.permuted-completion-commands-2
#[tokio::test]
async fn submit_a_b_c_complete_b_a_c() -> Result<(), Box<dyn Error>> {
    run_permutation(&[1, 0, 2], false).await
}

// B.multiplex.fragmented-completion-commands
#[tokio::test]
async fn fragmented_responses_still_dispatch_by_id() -> Result<(), Box<dyn Error>> {
    run_permutation(&[2, 0, 1], true).await
}

// B.multiplex.mixed-completion-commands: mixed operations complete in a
// rotated order with each caller receiving its own outcome.
#[tokio::test]
async fn mixed_commands_complete_out_of_order() -> Result<(), Box<dyn Error>> {
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
        let mut requests = Vec::new();
        while requests.len() < 3 {
            let (code, request_id, payload) = read_request(&mut socket).await?;
            requests.push((code, request_id, payload));
        }
        for position in [2, 0, 1] {
            let Some((code, request_id, payload)) = requests.get(position) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unknown order position",
                ));
            };
            if *code == 0x0004 {
                send_response(&mut socket, 0x0000, *request_id, &[], false).await?;
            } else if *code == 0x0003 {
                let _ = payload;
                send_response(&mut socket, 0x0000, *request_id, b"mixed-value", false).await?;
            } else {
                send_response(&mut socket, 0x0000, *request_id, &[], false).await?;
            }
        }
        Ok::<(), std::io::Error>(())
    });
    let config = ConnectionConfig::new(address.to_string());
    let connection = Connection::connect(&config).await?;
    let first = connection.clone();
    let second = connection.clone();
    let third = connection.clone();
    let (set, get, ping) = tokio::join!(
        first.set(b"mixed", b"mixed-value"),
        second.get(b"mixed"),
        third.ping(),
    );
    set?;
    match get? {
        GetOutcome::Present(value) => assert_eq!(value, b"mixed-value"),
        other => return Err(format!("expected mixed-value, got {other:?}").into()),
    }
    ping?;
    connection.close().await?;
    peer.abort();
    Ok(())
}

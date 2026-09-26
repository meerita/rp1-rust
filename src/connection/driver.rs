//! Production multiplexed driver for one connection.
//!
//! This module owns transport I/O for established sessions: serial writes,
//! incremental reads, and dispatch of terminal frames by request ID in any
//! arrival order. It does not own handshake, command encoding, response
//! interpretation, or the public connection API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use super::ConnectionState;
use super::dispatch::InFlightRegistry;
use crate::protocol::{Admission, ConnectionState as ProtocolState, Failure, Limits, Role, Step};
use crate::transport::AnyTransport;

/// One submission a caller hands to the driver.
#[derive(Debug)]
pub(super) struct Submit {
    /// The allocated request ID.
    pub(super) id: u64,
    /// The exact request frame bytes.
    pub(super) bytes: Vec<u8>,
    /// The channel for the terminal outcome.
    pub(super) completion: oneshot::Sender<Result<Vec<u8>, DriverError>>,
}

/// A driver-level failure for one request or the whole session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DriverError {
    /// A request-scoped protocol failure for exactly one request.
    RequestFailed(Failure),
    /// A connection-fatal protocol failure; the session is unusable.
    ConnectionFatal(Failure),
    /// The transport failed; the session failed.
    Transport,
    /// The connection closed with the request in flight.
    Closed,
    /// The session became unusable after a protocol violation.
    Unusable,
}

/// How the driver task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DriverExit {
    /// An explicit shutdown completed.
    Closed,
    /// The transport failed.
    Failed,
    /// A protocol violation ended the session.
    Unusable,
}

/// The most bytes one driver read may move.
const READ_CHUNK: usize = 4_096;

/// Spawns the driver task for an established session.
///
/// The live registry is empty after the handshake. The limits are the
/// effective bounds in force, and the capabilities are the accepted set of
/// the negotiated session. The state and admission are shared with the
/// connection handles. Returns the submit channel and the driver handle.
pub(super) fn spawn(
    transport: AnyTransport,
    limits: Limits,
    capabilities: Vec<u16>,
    state: Arc<Mutex<ConnectionState>>,
    admission: Arc<tokio::sync::Semaphore>,
    shutdown_rx: oneshot::Receiver<()>,
) -> (mpsc::Sender<Submit>, tokio::task::JoinHandle<DriverExit>) {
    let (submit_tx, submit_rx) = mpsc::channel(64);
    let handle = tokio::spawn(async move {
        run_driver(
            transport,
            submit_rx,
            shutdown_rx,
            limits,
            capabilities,
            state,
            admission,
        )
        .await
    });
    (submit_tx, handle)
}

/// Writes every byte of `bytes`, tolerating short writes.
async fn write_all(transport: &mut AnyTransport, bytes: &[u8]) -> std::io::Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = bytes.get(offset..).unwrap_or(&[]);
        let written = transport.write(remaining).await?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "the transport wrote no bytes",
            ));
        }
        let Some(next) = offset.checked_add(written) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the transport reported too many bytes written",
            ));
        };
        offset = next;
    }
    Ok(())
}

/// Marks the session state once; later signals keep the first outcome.
fn mark_state(state: &Arc<Mutex<ConnectionState>>, next: ConnectionState) {
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(*guard, ConnectionState::Usable | ConnectionState::Closing) {
        *guard = next;
    }
}

/// Resolves every pending waiter with `error` and releases each ID once.
fn fail_all(
    completions: &mut HashMap<u64, oneshot::Sender<Result<Vec<u8>, DriverError>>>,
    live: &mut InFlightRegistry,
    error: DriverError,
) {
    let ids: Vec<u64> = completions.keys().copied().collect();
    for id in ids {
        if let Some(sender) = completions.remove(&id) {
            let _ = sender.send(Err(error));
        }
        let _ = live.retire(id);
    }
}

/// Reads the request ID at the head of `buffer`, if a header is present.
fn header_request_id(buffer: &[u8]) -> Option<u64> {
    let slice = buffer.get(12..20)?;
    let array: [u8; 8] = slice.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

/// Returns the total frame length from a buffered header, if present.
fn frame_total_len(buffer: &[u8]) -> Option<usize> {
    use crate::protocol::HEADER_LENGTH;
    if buffer.len() < HEADER_LENGTH {
        return None;
    }
    let metadata_length = u16::from_le_bytes([*buffer.get(6)?, *buffer.get(7)?]);
    let payload_length = u32::from_le_bytes([
        *buffer.get(8)?,
        *buffer.get(9)?,
        *buffer.get(10)?,
        *buffer.get(11)?,
    ]);
    HEADER_LENGTH
        .checked_add(usize::from(metadata_length))?
        .checked_add(usize::try_from(payload_length).unwrap_or(usize::MAX))
}

/// Drains every complete buffered frame, dispatching by request ID.
///
/// Returns `None` while the session stays usable and the fatal failure
/// when a frame ended it.
fn drain_frames(
    buffer: &mut Vec<u8>,
    completions: &mut HashMap<u64, oneshot::Sender<Result<Vec<u8>, DriverError>>>,
    live: &mut InFlightRegistry,
    limits: Limits,
    capabilities: &[u16],
) -> Option<Failure> {
    loop {
        let live_ids = live.live_ids();
        let admission = Admission {
            role: Role::Client,
            state: ProtocolState::Negotiated,
            limits,
            in_flight: &live_ids,
            capabilities,
        };
        match crate::protocol::decode(buffer, admission) {
            Step::Need(_) => return None,
            Step::Frame(frame) => {
                let retiring = frame.header().request_id().value();
                let Some(total) = frame_total_len(buffer) else {
                    return Some(Failure::protocol_violation());
                };
                let frame_bytes = buffer.get(..total).unwrap_or(&[]).to_vec();
                let _ = buffer.drain(..total.min(buffer.len()));
                match completions.remove(&retiring) {
                    Some(sender) => {
                        let _ = live.retire(retiring);
                        let _ = sender.send(Ok(frame_bytes));
                    }
                    None => {
                        return Some(Failure::protocol_violation());
                    }
                }
            }
            Step::Failure { failure, consumed } => {
                if failure.scope() == crate::protocol::FailureScope::RequestScoped {
                    let Some(id) = header_request_id(buffer) else {
                        return Some(Failure::protocol_violation());
                    };
                    let total = consumed.min(buffer.len());
                    let _ = buffer.drain(..total);
                    match completions.remove(&id) {
                        Some(sender) => {
                            let _ = live.retire(id);
                            let _ = sender.send(Err(DriverError::RequestFailed(failure)));
                        }
                        None => {
                            return Some(Failure::protocol_violation());
                        }
                    }
                } else {
                    return Some(failure);
                }
            }
        }
    }
}

/// The driver loop: serial writes, incremental reads, dispatch by ID.
async fn run_driver(
    mut transport: AnyTransport,
    mut submit_rx: mpsc::Receiver<Submit>,
    mut shutdown_rx: oneshot::Receiver<()>,
    limits: Limits,
    capabilities: Vec<u16>,
    state: Arc<Mutex<ConnectionState>>,
    admission: Arc<tokio::sync::Semaphore>,
) -> DriverExit {
    let mut live = InFlightRegistry::new();
    let mut completions: HashMap<u64, oneshot::Sender<Result<Vec<u8>, DriverError>>> =
        HashMap::new();
    let mut buffer: Vec<u8> = Vec::new();
    let mut submit_closed = false;
    loop {
        tokio::select! {
            biased;
            result = &mut shutdown_rx => {
                let _ = result;
                fail_all(&mut completions, &mut live, DriverError::Closed);
                mark_state(&state, ConnectionState::Closed);
                admission.close();
                let shutdown = transport.shutdown().await;
                if shutdown.is_ok() {
                    return DriverExit::Closed;
                }
                mark_state(&state, ConnectionState::Failed);
                return DriverExit::Failed;
            }
            submit = submit_rx.recv(), if !submit_closed => {
                if let Some(submit) = submit {
                    if live.insert(submit.id).is_err() {
                        let _ = submit.completion.send(Err(DriverError::Unusable));
                        fail_all(&mut completions, &mut live, DriverError::Unusable);
                        mark_state(&state, ConnectionState::Unusable);
                        admission.close();
                        return DriverExit::Unusable;
                    }
                    let _ = completions.insert(submit.id, submit.completion);
                    if write_all(&mut transport, &submit.bytes).await.is_err() {
                        fail_all(&mut completions, &mut live, DriverError::Transport);
                        mark_state(&state, ConnectionState::Failed);
                        admission.close();
                        return DriverExit::Failed;
                    }
                } else {
                    submit_closed = true;
                    if completions.is_empty() {
                        break;
                    }
                }
            }
            result = read_chunk(&mut transport) => {
                match result {
                    Err(_) | Ok(None) => {
                        if completions.is_empty() && submit_closed {
                            break;
                        }
                        if completions.is_empty() {
                            continue;
                        }
                        fail_all(&mut completions, &mut live, DriverError::Transport);
                        mark_state(&state, ConnectionState::Failed);
                        admission.close();
                        return DriverExit::Failed;
                    }
                    Ok(Some(chunk)) => {
                        buffer.extend_from_slice(&chunk);
                        if let Some(failure) = drain_frames(
                            &mut buffer,
                            &mut completions,
                            &mut live,
                            limits,
                            &capabilities,
                        ) {
                            fail_all(
                                &mut completions,
                                &mut live,
                                DriverError::ConnectionFatal(failure),
                            );
                            mark_state(&state, ConnectionState::Unusable);
                            admission.close();
                            return DriverExit::Unusable;
                        }
                        if submit_closed && completions.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
        if submit_closed && completions.is_empty() {
            break;
        }
    }
    DriverExit::Closed
}

/// Reads one chunk, returning `None` at end of stream.
async fn read_chunk(transport: &mut AnyTransport) -> std::io::Result<Option<Vec<u8>>> {
    let mut chunk = [0u8; READ_CHUNK];
    match transport.read(&mut chunk).await {
        Err(error) => Err(error),
        Ok(0) => Ok(None),
        Ok(read) => Ok(Some(chunk.get(..read).unwrap_or(&[]).to_vec())),
    }
}

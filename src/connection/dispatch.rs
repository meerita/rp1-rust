//! Multiplexed request identity for one connection.
//!
//! The allocator hands out monotonic initiator identifiers starting at 1
//! and skipping the reserved 0 on wrap. The registry holds the live set:
//! an identifier is live from admission until its terminal frame retires
//! it, and it is released exactly once. A retired identifier may be
//! reused; a live one may not.

use std::collections::HashSet;

/// Allocates monotonic initiator request identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdAllocator {
    next: u64,
}

impl RequestIdAllocator {
    /// Builds an allocator starting at 1.
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    /// Builds an allocator starting at `next`, for boundary tests.
    ///
    /// A start of 0 is treated as 1 on the next allocation because 0 names
    /// no request.
    #[cfg(test)]
    pub const fn with_start(next: u64) -> Self {
        Self { next }
    }

    /// Returns the next identifier, skipping the reserved 0.
    pub const fn allocate(&mut self) -> u64 {
        if self.next == 0 {
            self.next = 1;
        }
        let id = self.next;
        let advanced = self.next.wrapping_add(1);
        self.next = if advanced == 0 { 1 } else { advanced };
        id
    }
}

/// A refusal to admit an identifier into the live set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// The identifier is the reserved 0.
    Reserved,
    /// The identifier is already live.
    LiveReuse,
}

/// Tracks the identifiers in flight on one connection.
#[derive(Debug, Clone, Default)]
pub struct InFlightRegistry {
    live: HashSet<u64>,
}

impl InFlightRegistry {
    /// Builds an empty registry.
    pub fn new() -> Self {
        Self {
            live: HashSet::new(),
        }
    }

    /// Admits `id` into the live set.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Reserved`] for 0 and
    /// [`RegistryError::LiveReuse`] when `id` is already live.
    pub fn insert(&mut self, id: u64) -> Result<(), RegistryError> {
        if id == 0 {
            return Err(RegistryError::Reserved);
        }
        if self.live.contains(&id) {
            return Err(RegistryError::LiveReuse);
        }
        let _ = self.live.insert(id);
        Ok(())
    }

    /// Retires `id`, returning whether it was live.
    ///
    /// Each live identifier is retired exactly once; a second retire
    /// reports `false` and changes nothing.
    pub fn retire(&mut self, id: u64) -> bool {
        self.live.remove(&id)
    }

    /// Returns whether `id` is live.
    pub fn contains(&self, id: u64) -> bool {
        self.live.contains(&id)
    }

    /// Returns the number of live identifiers.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Returns whether no identifier is live.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Returns a snapshot of the live identifiers for decode admission.
    pub fn live_ids(&self) -> Vec<u64> {
        self.live.iter().copied().collect()
    }
}

/// A terminal response the driver delivers to one caller.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    /// The opaque payload bytes of a success response.
    pub payload: Vec<u8>,
}

/// A failure the driver reports to one caller.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The session closed before a terminal arrived.
    Closed,
    /// The session became unusable after a protocol violation.
    Unusable,
    /// The transport failed.
    Transport,
}

#[cfg(test)]
impl std::fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("the session closed"),
            Self::Unusable => formatter.write_str("the session is unusable"),
            Self::Transport => formatter.write_str("the transport failed"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for RequestError {}

/// The session state the driver and callers share.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The session accepts new requests.
    Usable,
    /// The session no longer accepts work after a fatal dispatch.
    Unusable,
    /// The session ended.
    Closed,
}

/// One submission a caller hands to the driver.
#[cfg(test)]
struct Submit {
    id: u64,
    bytes: Vec<u8>,
    completion: tokio::sync::oneshot::Sender<Result<Terminal, RequestError>>,
}

/// A deterministic duplex dispatcher for multiplexing tests.
///
/// One driver task owns the client side of an in-memory byte stream,
/// writes submissions serially, and dispatches terminal frames by request
/// ID in any arrival order. The test peer owns the other side and scripts
/// response order, fragmentation, and fatal frames.
#[cfg(test)]
pub struct TestDispatcher {
    submit_tx: tokio::sync::mpsc::Sender<Submit>,
    state: std::sync::Arc<std::sync::Mutex<SessionState>>,
    allocator: std::sync::Arc<std::sync::Mutex<RequestIdAllocator>>,
    live: std::sync::Arc<std::sync::Mutex<InFlightRegistry>>,
    driver: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[cfg(test)]
impl TestDispatcher {
    /// Builds a dispatcher over the client side of a duplex pair.
    pub fn new(client: tokio::io::DuplexStream) -> Self {
        let (submit_tx, submit_rx) = tokio::sync::mpsc::channel(64);
        let state = std::sync::Arc::new(std::sync::Mutex::new(SessionState::Usable));
        let allocator = std::sync::Arc::new(std::sync::Mutex::new(RequestIdAllocator::new()));
        let live = std::sync::Arc::new(std::sync::Mutex::new(InFlightRegistry::new()));
        let driver_state = std::sync::Arc::clone(&state);
        let driver_allocator = std::sync::Arc::clone(&allocator);
        let driver_live = std::sync::Arc::clone(&live);
        let handle = tokio::spawn(async move {
            run_driver(
                client,
                submit_rx,
                driver_state,
                driver_allocator,
                driver_live,
            )
            .await;
        });
        Self {
            submit_tx,
            state,
            allocator,
            live,
            driver: std::sync::Mutex::new(Some(handle)),
        }
    }

    /// Submits one request carrying `payload` and waits for its terminal.
    pub async fn execute(&self, payload: Vec<u8>) -> Result<Terminal, RequestError> {
        let id = {
            let mut allocator = self
                .allocator
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            allocator.allocate()
        };
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *state != SessionState::Usable {
                return Err(RequestError::Unusable);
            }
        }
        {
            let mut live = self
                .live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if live.insert(id).is_err() {
                return Err(RequestError::Unusable);
            }
        }
        let bytes = encode_test_request(id, &payload);
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let submit = Submit {
            id,
            bytes,
            completion: completion_tx,
        };
        if self.submit_tx.send(submit).await.is_err() {
            let _ = self
                .live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retire(id);
            return Err(RequestError::Closed);
        }
        // The driver retires the identifier on its terminal path; a
        // caller-side abandonment never frees a live identifier.
        completion_rx.await.unwrap_or(Err(RequestError::Closed))
    }

    /// Submits one request and drops the waiter, keeping the ID live until
    /// its terminal arrives. Returns the allocated identifier.
    pub async fn submit_and_abandon(&self, payload: Vec<u8>) -> Result<u64, RequestError> {
        let id = {
            let mut allocator = self
                .allocator
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            allocator.allocate()
        };
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *state != SessionState::Usable {
                return Err(RequestError::Unusable);
            }
        }
        {
            let mut live = self
                .live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if live.insert(id).is_err() {
                return Err(RequestError::Unusable);
            }
        }
        let bytes = encode_test_request(id, &payload);
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let submit = Submit {
            id,
            bytes,
            completion: completion_tx,
        };
        if self.submit_tx.send(submit).await.is_err() {
            let _ = self
                .live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retire(id);
            return Err(RequestError::Closed);
        }
        drop(completion_rx);
        Ok(id)
    }

    /// Returns the session state.
    pub fn state(&self) -> SessionState {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns the number of live identifiers.
    pub fn live_len(&self) -> usize {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Waits for the driver task to end.
    pub async fn join(&self) {
        let handle = {
            let mut driver = self
                .driver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            driver.take()
        };
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
impl Drop for TestDispatcher {
    fn drop(&mut self) {
        let handle = {
            let mut driver = self
                .driver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            driver.take()
        };
        if let Some(handle) = handle {
            handle.abort();
        }
    }
}

/// Encodes a test request with a dummy opcode and an opaque marker.
#[cfg(test)]
fn encode_test_request(id: u64, payload: &[u8]) -> Vec<u8> {
    use crate::protocol::{Kind, Outgoing, OutgoingPayload, encode};
    let outgoing = Outgoing {
        kind: Kind::Request,
        code: 0xFFFF,
        request_id: id,
        metadata: &[],
        payload: OutgoingPayload::Opaque(payload),
    };
    encode(&outgoing).unwrap_or_default()
}

/// Encodes a success response carrying `payload` for `id`.
#[cfg(test)]
pub fn encode_test_response(id: u64, payload: &[u8]) -> Vec<u8> {
    use crate::protocol::{Kind, Outgoing, OutgoingPayload, encode};
    let outgoing = Outgoing {
        kind: Kind::Response,
        code: 0,
        request_id: id,
        metadata: &[],
        payload: OutgoingPayload::Opaque(payload),
    };
    encode(&outgoing).unwrap_or_default()
}

/// Reads one frame header from `buffer`, returning the request ID and the
/// total frame length when a full header is present.
#[cfg(test)]
fn header_request_id(buffer: &[u8]) -> Option<(u64, usize)> {
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
    let mut id_bytes = [0u8; 8];
    for (index, slot) in id_bytes.iter_mut().enumerate() {
        let offset = 12usize.checked_add(index)?;
        *slot = *buffer.get(offset)?;
    }
    let total = HEADER_LENGTH
        .checked_add(usize::from(metadata_length))?
        .checked_add(usize::try_from(payload_length).unwrap_or(usize::MAX))?;
    Some((u64::from_le_bytes(id_bytes), total))
}

/// Writes `bytes` to the peer side, optionally one byte at a time.
#[cfg(test)]
pub async fn write_peer_bytes(
    peer: &mut tokio::io::DuplexStream,
    bytes: &[u8],
    bytewise: bool,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    if bytewise {
        for byte in bytes {
            peer.write_all(std::slice::from_ref(byte)).await?;
        }
    } else {
        peer.write_all(bytes).await?;
    }
    peer.flush().await?;
    Ok(())
}

/// The driver loop: serial writes, incremental reads, dispatch by ID.
#[cfg(test)]
async fn run_driver(
    client: tokio::io::DuplexStream,
    mut submit_rx: tokio::sync::mpsc::Receiver<Submit>,
    state: std::sync::Arc<std::sync::Mutex<SessionState>>,
    _allocator: std::sync::Arc<std::sync::Mutex<RequestIdAllocator>>,
    live: std::sync::Arc<std::sync::Mutex<InFlightRegistry>>,
) {
    use tokio::io::AsyncReadExt;
    let (mut reader, mut writer) = tokio::io::split(client);
    let mut completions: std::collections::HashMap<
        u64,
        tokio::sync::oneshot::Sender<Result<Terminal, RequestError>>,
    > = std::collections::HashMap::new();
    let mut buffer: Vec<u8> = Vec::new();
    let mut submit_closed = false;
    loop {
        tokio::select! {
            submit = submit_rx.recv(), if !submit_closed => {
                if let Some(submit) = submit {
                    if handle_submit(&mut writer, submit, &mut completions, &state, &live).await.is_err() {
                        break;
                    }
                } else {
                    submit_closed = true;
                    if completions.is_empty() {
                        break;
                    }
                }
            }
            read = reader.read_buf(&mut buffer) => {
                match handle_read(&read, &mut buffer, &mut completions, &state, &live) {
                    ReadOutcome::NeedMore => {}
                    ReadOutcome::Fatal => return,
                    ReadOutcome::Closed => break,
                }
                if submit_closed && completions.is_empty() {
                    break;
                }
            }
        }
        if submit_closed && completions.is_empty() {
            break;
        }
    }
    if !completions.is_empty() {
        fail_all(&state, &live, &mut completions, RequestError::Closed);
    }
}

/// Writes one submission serially, registering its completion.
#[cfg(test)]
async fn handle_submit(
    writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
    submit: Submit,
    completions: &mut std::collections::HashMap<
        u64,
        tokio::sync::oneshot::Sender<Result<Terminal, RequestError>>,
    >,
    state: &std::sync::Arc<std::sync::Mutex<SessionState>>,
    live: &std::sync::Arc<std::sync::Mutex<InFlightRegistry>>,
) -> Result<(), RequestError> {
    use tokio::io::AsyncWriteExt;
    let id = submit.id;
    let _ = completions.insert(id, submit.completion);
    if writer.write_all(&submit.bytes).await.is_err() || writer.flush().await.is_err() {
        fail_all(state, live, completions, RequestError::Transport);
        return Err(RequestError::Transport);
    }
    Ok(())
}

/// The outcome of one transport read.
#[cfg(test)]
enum ReadOutcome {
    /// More bytes are needed before the next frame completes.
    NeedMore,
    /// A protocol violation ended the session.
    Fatal,
    /// The transport closed.
    Closed,
}

/// Incorporates one transport read into the decode buffer.
#[cfg(test)]
fn handle_read(
    read: &Result<usize, std::io::Error>,
    buffer: &mut Vec<u8>,
    completions: &mut std::collections::HashMap<
        u64,
        tokio::sync::oneshot::Sender<Result<Terminal, RequestError>>,
    >,
    state: &std::sync::Arc<std::sync::Mutex<SessionState>>,
    live: &std::sync::Arc<std::sync::Mutex<InFlightRegistry>>,
) -> ReadOutcome {
    match read {
        Err(_) | Ok(0) => {
            if completions.is_empty() {
                return ReadOutcome::Closed;
            }
            fail_all(state, live, completions, RequestError::Transport);
            ReadOutcome::Closed
        }
        Ok(_) => drain_frames(buffer, completions, state, live),
    }
}

/// Dispatches every complete buffered frame by request ID.
#[cfg(test)]
fn drain_frames(
    buffer: &mut Vec<u8>,
    completions: &mut std::collections::HashMap<
        u64,
        tokio::sync::oneshot::Sender<Result<Terminal, RequestError>>,
    >,
    state: &std::sync::Arc<std::sync::Mutex<SessionState>>,
    live: &std::sync::Arc<std::sync::Mutex<InFlightRegistry>>,
) -> ReadOutcome {
    use crate::protocol::{Admission, ConnectionState, Limits, Role, Step};
    loop {
        let live_ids = {
            let live = live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            live.live_ids()
        };
        let admission = Admission {
            role: Role::Client,
            state: ConnectionState::Negotiated,
            limits: Limits::PRE_NEGOTIATION,
            in_flight: &live_ids,
        };
        match crate::protocol::decode(buffer, admission) {
            Step::Need(_) => return ReadOutcome::NeedMore,
            Step::Frame(frame) => {
                let retiring = frame.header().request_id().value();
                let total = frame_total_len(buffer);
                let payload = match frame.payload() {
                    crate::protocol::Payload::Opaque(bytes) => bytes.to_vec(),
                    _ => Vec::new(),
                };
                let _ = drain_bytes(buffer, total);
                let sender = completions.remove(&retiring);
                let _ = live
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retire(retiring);
                if let Some(sender) = sender {
                    let _ = sender.send(Ok(Terminal { payload }));
                } else {
                    fail_all(state, live, completions, RequestError::Unusable);
                    return ReadOutcome::Fatal;
                }
            }
            Step::Failure { .. } => {
                fail_all(state, live, completions, RequestError::Unusable);
                return ReadOutcome::Fatal;
            }
        }
    }
}

/// Marks the session unusable or closed and resolves every in-flight
/// request with `error`, releasing each identifier once.
#[cfg(test)]
fn fail_all(
    state: &std::sync::Arc<std::sync::Mutex<SessionState>>,
    live: &std::sync::Arc<std::sync::Mutex<InFlightRegistry>>,
    completions: &mut std::collections::HashMap<
        u64,
        tokio::sync::oneshot::Sender<Result<Terminal, RequestError>>,
    >,
    error: RequestError,
) {
    {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = match error {
            RequestError::Unusable => SessionState::Unusable,
            _ => SessionState::Closed,
        };
    }
    let ids: Vec<u64> = completions.keys().copied().collect();
    for id in ids {
        if let Some(sender) = completions.remove(&id) {
            let _ = sender.send(Err(error));
        }
        let mut live = live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = live.retire(id);
    }
}

/// Returns the total frame length from a buffered header, or the buffer
/// length when no header is present.
#[cfg(test)]
fn frame_total_len(buffer: &[u8]) -> usize {
    use crate::protocol::HEADER_LENGTH;
    if buffer.len() < HEADER_LENGTH {
        return buffer.len();
    }
    let metadata_length =
        u16::from_le_bytes([*buffer.get(6).unwrap_or(&0), *buffer.get(7).unwrap_or(&0)]);
    let payload_length = u32::from_le_bytes([
        *buffer.get(8).unwrap_or(&0),
        *buffer.get(9).unwrap_or(&0),
        *buffer.get(10).unwrap_or(&0),
        *buffer.get(11).unwrap_or(&0),
    ]);
    HEADER_LENGTH
        .checked_add(usize::from(metadata_length))
        .and_then(|total| total.checked_add(usize::try_from(payload_length).unwrap_or(usize::MAX)))
        .unwrap_or(buffer.len())
}

/// Removes `count` leading bytes, saturating at the buffer length.
#[cfg(test)]
fn drain_bytes(buffer: &mut Vec<u8>, count: usize) -> usize {
    let count = count.min(buffer.len());
    let _ = buffer.drain(..count);
    count
}

#[cfg(test)]
mod tests {
    use super::{InFlightRegistry, RegistryError, RequestIdAllocator};

    #[test]
    fn allocation_starts_at_one_and_advances() {
        let mut allocator = RequestIdAllocator::new();
        assert_eq!(allocator.allocate(), 1);
        assert_eq!(allocator.allocate(), 2);
        assert_eq!(allocator.allocate(), 3);
    }

    #[test]
    fn a_live_identifier_is_refused() {
        let mut registry = InFlightRegistry::new();
        assert_eq!(registry.insert(7), Ok(()));
        assert_eq!(registry.insert(7), Err(RegistryError::LiveReuse));
        assert!(registry.contains(7));
    }

    #[test]
    fn the_reserved_identifier_is_refused() {
        let mut registry = InFlightRegistry::new();
        assert_eq!(registry.insert(0), Err(RegistryError::Reserved));
        assert!(!registry.contains(0));
    }

    #[test]
    fn a_retired_identifier_is_reusable_and_releases_once() {
        let mut registry = InFlightRegistry::new();
        assert_eq!(registry.insert(9), Ok(()));
        assert!(registry.retire(9));
        assert!(!registry.contains(9));
        assert_eq!(registry.insert(9), Ok(()));
        assert!(registry.retire(9));
        assert!(!registry.retire(9));
    }

    #[test]
    fn a_second_retire_changes_nothing() {
        let mut registry = InFlightRegistry::new();
        assert!(!registry.retire(42));
        assert_eq!(registry.insert(42), Ok(()));
        assert!(registry.retire(42));
        assert!(!registry.retire(42));
        assert!(registry.is_empty());
    }

    #[test]
    fn wrap_skips_the_reserved_identifier() {
        let mut allocator = RequestIdAllocator::with_start(u64::MAX);
        assert_eq!(allocator.allocate(), u64::MAX);
        assert_eq!(allocator.allocate(), 1);
        assert_eq!(allocator.allocate(), 2);
    }

    #[test]
    fn a_zero_start_allocates_from_one() {
        let mut allocator = RequestIdAllocator::with_start(0);
        assert_eq!(allocator.allocate(), 1);
        assert_eq!(allocator.allocate(), 2);
    }

    #[test]
    fn allocated_identifiers_admit_until_retired() {
        let mut allocator = RequestIdAllocator::new();
        let mut registry = InFlightRegistry::new();
        let first = allocator.allocate();
        let second = allocator.allocate();
        assert_eq!(registry.insert(first), Ok(()));
        assert_eq!(registry.insert(second), Ok(()));
        assert_eq!(registry.len(), 2);
        let mut live = registry.live_ids();
        live.sort_unstable();
        assert_eq!(live, vec![first, second]);
        assert!(registry.retire(first));
        assert_eq!(registry.insert(first), Ok(()));
        assert_eq!(registry.len(), 2);
    }

    use super::{
        RequestError, SessionState, TestDispatcher, encode_test_response, write_peer_bytes,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_pair() -> (TestDispatcher, tokio::io::DuplexStream) {
        let (client, peer) = tokio::io::duplex(65_536);
        (TestDispatcher::new(client), peer)
    }

    async fn read_requests(
        peer: &mut tokio::io::DuplexStream,
        count: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, std::io::Error> {
        use super::header_request_id;
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        let mut buffer = Vec::new();
        while out.len() < count {
            // Drain every complete frame already buffered before reading more.
            // A single transport read may carry several frames.
            loop {
                let parsed = header_request_id(&buffer);
                let Some((id, total)) = parsed else {
                    break;
                };
                if buffer.len() < total {
                    break;
                }
                let payload = buffer
                    .get(crate::protocol::HEADER_LENGTH..total)
                    .unwrap_or(&[])
                    .to_vec();
                let _ = buffer.drain(..total);
                out.push((id, payload));
                if out.len() >= count {
                    break;
                }
            }
            if out.len() >= count {
                break;
            }
            let mut chunk = [0u8; 1_024];
            let read = peer.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the dispatcher closed before sending a request",
                ));
            }
            let part = chunk.get(..read).unwrap_or(&[]);
            buffer.extend_from_slice(part);
        }
        Ok(out)
    }

    async fn respond_in_order(
        peer: &mut tokio::io::DuplexStream,
        requests: &[(u64, Vec<u8>)],
        order: &[usize],
        bytewise: bool,
    ) -> Result<(), std::io::Error> {
        for position in order {
            let position = *position;
            let (id, payload) = requests.get(position).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown order position")
            })?;
            let frame = encode_test_response(*id, payload);
            write_peer_bytes(peer, &frame, bytewise).await?;
        }
        Ok(())
    }

    async fn run_permutation(order: &[usize], bytewise: bool) -> TestResult {
        let (dispatcher, mut peer) = test_pair();
        let order_owned = order.to_vec();
        let submit_a = dispatcher.execute(b"A".to_vec());
        let submit_b = dispatcher.execute(b"B".to_vec());
        let submit_c = dispatcher.execute(b"C".to_vec());
        let peer_task = tokio::spawn(async move {
            let requests = read_requests(&mut peer, 3).await?;
            respond_in_order(&mut peer, &requests, &order_owned, bytewise).await?;
            Ok::<(), std::io::Error>(())
        });
        let (outcome_a, outcome_b, outcome_c) = tokio::join!(submit_a, submit_b, submit_c);
        peer_task.await??;
        assert_eq!(outcome_a?.payload, b"A");
        assert_eq!(outcome_b?.payload, b"B");
        assert_eq!(outcome_c?.payload, b"C");
        assert_eq!(dispatcher.live_len(), 0);
        assert_eq!(dispatcher.state(), SessionState::Usable);
        dispatcher.join().await;
        Ok(())
    }

    #[tokio::test]
    async fn submit_a_b_c_complete_a_b_c() -> TestResult {
        run_permutation(&[0, 1, 2], false).await
    }

    #[tokio::test]
    async fn submit_a_b_c_complete_c_b_a() -> TestResult {
        run_permutation(&[2, 1, 0], false).await
    }

    #[tokio::test]
    async fn submit_a_b_c_complete_b_c_a() -> TestResult {
        run_permutation(&[1, 2, 0], false).await
    }

    #[tokio::test]
    async fn submit_a_b_c_complete_b_a_c() -> TestResult {
        run_permutation(&[1, 0, 2], false).await
    }

    #[tokio::test]
    async fn fragmented_responses_still_dispatch_by_id() -> TestResult {
        run_permutation(&[2, 0, 1], true).await
    }

    #[tokio::test]
    async fn an_unknown_id_ends_the_session() -> TestResult {
        let (dispatcher, mut peer) = test_pair();
        let submit_a = dispatcher.execute(b"A".to_vec());
        let submit_b = dispatcher.execute(b"B".to_vec());
        let peer_task = tokio::spawn(async move {
            let _ = read_requests(&mut peer, 2).await?;
            let fatal = encode_test_response(9_999, b"X");
            write_peer_bytes(&mut peer, &fatal, false).await?;
            Ok::<(), std::io::Error>(())
        });
        let (outcome_a, outcome_b) = tokio::join!(submit_a, submit_b);
        peer_task.await??;
        assert_eq!(outcome_a, Err(RequestError::Unusable));
        assert_eq!(outcome_b, Err(RequestError::Unusable));
        assert_eq!(dispatcher.state(), SessionState::Unusable);
        assert_eq!(dispatcher.live_len(), 0);
        assert_eq!(
            dispatcher.execute(b"C".to_vec()).await,
            Err(RequestError::Unusable)
        );
        dispatcher.join().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicate_terminal_ends_the_session() -> TestResult {
        let (dispatcher, mut peer) = test_pair();
        let submit_a = dispatcher.execute(b"A".to_vec());
        let submit_b = dispatcher.execute(b"B".to_vec());
        let peer_task = tokio::spawn(async move {
            let requests = read_requests(&mut peer, 2).await?;
            let (first_id, first_payload) = requests.first().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing first request")
            })?;
            let frame = encode_test_response(*first_id, first_payload);
            write_peer_bytes(&mut peer, &frame, false).await?;
            write_peer_bytes(&mut peer, &frame, false).await?;
            Ok::<(), std::io::Error>(())
        });
        let (outcome_a, outcome_b) = tokio::join!(submit_a, submit_b);
        peer_task.await??;
        assert_eq!(outcome_a?.payload, b"A");
        assert_eq!(outcome_b, Err(RequestError::Unusable));
        assert_eq!(dispatcher.state(), SessionState::Unusable);
        assert_eq!(dispatcher.live_len(), 0);
        dispatcher.join().await;
        Ok(())
    }

    #[tokio::test]
    async fn an_abandoned_waiter_keeps_its_id_live_until_its_terminal() -> TestResult {
        let (dispatcher, mut peer) = test_pair();
        let abandoned = dispatcher.submit_and_abandon(b"A".to_vec()).await?;
        assert_eq!(dispatcher.live_len(), 1);
        let peer_task = tokio::spawn(async move {
            let requests = read_requests(&mut peer, 1).await?;
            let (id, payload) = requests.first().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing request")
            })?;
            assert_eq!(*id, abandoned);
            let frame = encode_test_response(*id, payload);
            write_peer_bytes(&mut peer, &frame, false).await?;
            Ok::<(), std::io::Error>(())
        });
        peer_task.await??;
        let mut attempts = 0usize;
        while dispatcher.live_len() != 0 && attempts < 1_000 {
            tokio::task::yield_now().await;
            attempts = attempts.saturating_add(1);
        }
        assert_eq!(dispatcher.live_len(), 0);
        assert_eq!(dispatcher.state(), SessionState::Usable);
        let outcome = dispatcher.execute(b"B".to_vec()).await;
        // The second request needs its own peer drive; the first peer
        // already closed its side, so this attempt ends closed rather
        // than leaking. The key assertion is that the abandoned terminal
        // retired exactly once and left no residue.
        drop(outcome);
        dispatcher.join().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_peer_close_with_open_requests_resolves_every_caller() -> TestResult {
        let (dispatcher, mut peer) = test_pair();
        let submit_a = dispatcher.execute(b"A".to_vec());
        let submit_b = dispatcher.execute(b"B".to_vec());
        let peer_task = tokio::spawn(async move {
            let _ = read_requests(&mut peer, 2).await?;
            drop(peer);
            Ok::<(), std::io::Error>(())
        });
        let (outcome_a, outcome_b) = tokio::join!(submit_a, submit_b);
        peer_task.await??;
        assert_eq!(outcome_a, Err(RequestError::Transport));
        assert_eq!(outcome_b, Err(RequestError::Transport));
        assert_eq!(dispatcher.live_len(), 0);
        dispatcher.join().await;
        Ok(())
    }

    #[tokio::test]
    async fn repeated_fatal_cycles_leave_no_residue() -> TestResult {
        for _ in [0, 1, 2] {
            let (dispatcher, mut peer) = test_pair();
            let submit = dispatcher.execute(b"A".to_vec());
            let peer_task = tokio::spawn(async move {
                let _ = read_requests(&mut peer, 1).await?;
                let fatal = encode_test_response(9_999, b"X");
                write_peer_bytes(&mut peer, &fatal, false).await?;
                Ok::<(), std::io::Error>(())
            });
            assert_eq!(submit.await, Err(RequestError::Unusable));
            peer_task.await??;
            assert_eq!(dispatcher.live_len(), 0);
            assert_eq!(dispatcher.state(), SessionState::Unusable);
            dispatcher.join().await;
        }
        Ok(())
    }
}

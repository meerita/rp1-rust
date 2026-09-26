# Changelog

This file records user-relevant changes to the `rp1db` crate.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Multiplexed request lifecycle on one connection: monotonic initiator
  identifiers from 1 with 0 skipped on wrap, a live registry that
  refuses 0 and live reuse and retires each identifier once, and
  correlation by ID in any arrival order with interleaved completion.
  One driver owns the transport in both directions and dispatches
  terminal frames into per-request completions. Unknown or duplicate
  terminal frames end the session as unusable and resolve every
  in-flight request. An abandoned waiter keeps its identifier live until
  its terminal retires it.
- Bounded admission with a `maximum_in_flight` configuration knob,
  default 64 and minimum 1, validated before any connection. A full
  connection waits while usable; failure or shutdown wakes every waiter.
  Bookkeeping stays proportional to the bound and returns to baseline on
  retire. A bound of 1 serializes without deadlock.
- Shared session handles: `Connection` is `Clone`, and a clone is
  another handle to the same session, never a new connection. Concurrent
  tasks use clones without an exclusive borrow. Close stops admission,
  resolves in-flight work, shuts the transport, and lands in closed,
  failed, or unusable as each path requires. Terminal states are sticky;
  closing an already terminal connection succeeds without touching the
  transport.
- Multiplexing conformance: deterministic duplex-peer permutation,
  admission, reuse, exhaustion, shutdown, and concurrency coverage, plus
  stable `B.multiplex.*` scenarios stating caller and state outcomes for
  ordered, reverse, permuted, fragmented, unknown-ID fatal,
  duplicate-terminal fatal, abandonment, peer close with open requests,
  bound exposure, shared clones, concurrent clones, and idempotent
  close.
- A public `ConnectionState` with the `Usable`, `Closing`, `Closed`,
  `Failed`, and `Unusable` lifecycle states. Usable and closing occupy the
  negotiated protocol state; closed, failed, and unusable occupy the
  terminal state. `Connection::state` reports the current state, and
  `Connection::close` borrows the connection, moves it through closing to
  closed on an orderly shutdown or to failed when the transport shutdown
  fails, and succeeds without effect when the connection is already
  closed. Dropping a connection without closing it closes the transport
  without waiting and releases local resources.
- Local resource limits independent of negotiation: `ConnectionConfig`
  carries a local maximum frame size and a local maximum metadata size,
  both defaulting to the protocol floors and validated before any
  connection. A handshake that negotiates above either cap is refused
  locally with a structured error and returns no connection. A usable
  connection exposes the local caps and the effective bounds, the
  stricter of the negotiated and local values, which later request
  admission will read.
- Connection establishment conformance: the integration suite drives the
  connection against synthetic TCP peers across stable `B.*` scenarios
  covering a valid exchange, version and bound negotiation, capability
  refusal, frames outside the handshake, handshake order and uniqueness,
  fragmentation, peer close, orderly shutdown, and local-limit refusal.
  Every scenario states the caller-visible outcome and the
  connection-state outcome.
- A public `ConnectionConfig` and `Connection` with an asynchronous
  `connect` that opens a transport, sends the handshake request as the
  first frame, validates the response as untrusted input, and returns a
  connection only after negotiation completes. A usable connection
  exposes the negotiated protocol version, the negotiated frame and
  metadata bounds, and the accepted capability set.
- A private transport boundary over reads and writes, implemented for
  Tokio TCP and for a deterministic in-memory transport used by tests.
- Connection, configuration, and transport tests covering a valid
  handshake, fragmented reads, partial writes, version and bound
  refusals, an accepted-but-unoffered capability, and a peer that closes
  during the handshake.

- Cargo workspace, pinned toolchain, and lint baseline for the crate.
- `make` entry points for every repository operation.
- Recorded validation campaigns, with resume and sealing.
- Dependency and supply-chain policy, enforced by an audit.
- Package metadata, an asserted package file list, and the
  MIT OR Apache-2.0 offer.
- Public documentation and governance files.
- A low-level `protocol` module implementing the `rp1-spec` `v0.4.0`
  framing, codec, handshake, and negotiation contract: validated wire
  types, an incremental decoder that reads under a connection state and the
  bounds in force, an encoder, and the frame admission order.
- The handshake request and response payload types, the capability
  entry and identifier domain, the negotiated frame and metadata bounds,
  and encode and decode for both payloads as untrusted input.
- The published `v0.4.0` fixture corpus under `tests/fixtures/`, with an
  integration test that runs all 89 fixtures in their declared directions.
- Property, malformed-input, and bounded fuzz coverage for the decoder.
- `make fuzz` runs the frame decoder fuzz target.

The crate exposes a low-level `protocol` module and a `Connection` surface
that completes the negotiation handshake. It exposes no command surface.

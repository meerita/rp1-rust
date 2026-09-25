# Changelog

This file records user-relevant changes to the `rp1db` crate.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

# Changelog

This file records user-relevant changes to the `rp1db` crate.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

The crate exposes only the low-level `protocol` module. It has no client
API.

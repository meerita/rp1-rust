# RP-1 Rust

RP-1 Rust is the official Rust client for RP-1. It is an independent
implementation of the RP-1 Native Protocol, written against the public
protocol specification.

The crate is published as `rp1db`.

## Status

Early development.

The repository builds, tests, lints, and packages the crate. The crate
implements the public RP-1 protocol specification, revision `v0.4.0`:

- A low-level `protocol` module with validated wire types, an incremental
  decoder that reads under a connection state and the bounds in force, an
  encoder, the frame admission order, and the handshake request and
  response payloads. Its behavior is checked against the published 89
  fixture corpus.
- A public `ConnectionConfig` and `Connection` with an asynchronous
  `connect` that opens a TCP connection, sends the handshake request as
  the first frame, validates the response, and returns a connection only
  after negotiation completes. A usable connection exposes the negotiated
  protocol version, the negotiated frame and metadata bounds, and the
  accepted capability set, and closes explicitly. The configuration also
  carries local frame and metadata caps, independent of the negotiated
  bounds: a handshake that negotiates above either cap is refused
  locally, and a usable connection reports the effective bounds, the
  stricter of the negotiated and local values.

The crate exposes no command surface. Revision `v0.4.0` assigns no
operation beyond the handshake, so a connection connects and runs no
operation.

Do not add `rp1db` to a project that needs a working client. This version
completes the handshake and then runs no command.

## Supported Rust version

Rust 1.85 or later.

The crate uses the 2024 edition, which requires 1.85. A change to the
minimum supported version is a compatibility change and is recorded in
the changelog.

## Build and test

Clone the repository and use the `make` entry points:

```sh
make build   # compile the crate
make smoke   # compile, check formatting, lint, run the tests
make test    # run the development validation campaign
make gate    # run the complete validation campaign
make deps    # audit the dependency graph
```

`make smoke` is the fast loop. `make test` and `make gate` record their
results and print where they wrote them.

The toolchain is pinned by `rust-toolchain.toml`. Install
[rustup](https://rustup.rs) and it selects the right version for you.

Two campaigns need a tool that the repository does not carry:

```sh
rustup toolchain install 1.85.0   # minimum supported version check
cargo install cargo-deny          # dependency audit
```

Each command that needs one of them says so and prints the install line
when it is absent.

## Documentation

The public RP-1 protocol specification is the contract this client
implements. It is the authority for wire behavior.

The `protocol` module is documented as a low-level surface. Client API
documentation and compatibility information will be published when the
client implements the protocol.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report a vulnerability through
[SECURITY.md](SECURITY.md) rather than a public issue.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this crate, as defined in the Apache-2.0 license, is licensed
as above, without additional terms or conditions.

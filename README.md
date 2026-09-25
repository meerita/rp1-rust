# RP-1 Rust

RP-1 Rust is the official Rust client for RP-1. It is an independent
implementation of the RP-1 Native Protocol, written against the public
protocol specification.

The crate is published as `rp1db`.

## Status

Early development.

The repository builds, tests, lints, and packages the crate. The crate
exposes a low-level `protocol` module that implements the framing and
codec contract of the public RP-1 protocol specification, revision
`v0.2.0`: validated wire types, an incremental decoder, an encoder, and
the frame admission order. Its behavior is checked against the published
fixture corpus.

The crate exposes no client API. There is no connection, no negotiation,
and no command surface, because revision `v0.2.0` defines no exchange and
assigns no opcode.

Do not add `rp1db` to a project that needs a working client. This version
cannot talk to an RP-1 server.

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

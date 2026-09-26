# RP-1 Rust

RP-1 Rust is the official Rust client for RP-1. It is an independent
implementation of the RP-1 Native Protocol, written against the public
protocol specification.

The crate is published as `rp1db`.

## Status

Early development.

The repository builds, tests, lints, and packages the crate. The crate
implements the public RP-1 protocol specification, revision `v0.5.0`:

- A low-level `protocol` module with validated wire types, an incremental
  decoder that reads under a connection state and the bounds in force, an
  encoder, the frame admission order, the handshake request and
  response payloads, and the five assigned operation opcodes. Its
  behavior is checked against the published 107 fixture corpus.
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
- Multiplexed request identity on one connection: monotonic initiator
  identifiers with 0 skipped, a live registry that retires on the
  terminal frame and releases once, and correlation by ID in any arrival
  order with interleaved completion. One driver owns the transport in
  both directions and dispatches terminal frames into per-request
  completions; unknown or duplicate terminal frames end the session and
  resolve every in-flight request.
- Bounded admission with a `maximum_in_flight` configuration knob,
  default 64 and minimum 1. A full connection waits while usable;
  failure or shutdown wakes every waiter. Clones are additional handles
  to the same session, never new connections, and concurrent tasks use
  them without an exclusive borrow. Close stops admission, resolves
  in-flight work from send-state evidence, shuts the transport, and
  lands in closed, failed, or unusable as each path requires. Terminal
  states are sticky.
- The five core commands as typed binary-safe async methods: `ping`,
  `get`, `set`, `del`, and `exists`. Keys and values are opaque byte
  strings; empty keys and empty values are ordinary values, and a
  present empty value never conflates with a missing key. `GET` answers
  a three-state outcome (present with the value bytes, absent, or held
  outside memory with the logical length); `DEL` and `EXISTS` answer
  presence as a boolean; `SET` and `PING` answer unit on success.
  Oversized requests refuse locally with nothing sent. Every reachable
  server refusal maps to its structured outcome with scope: unsupported
  operation, invalid argument, overloaded, and wrong type retire one
  request and keep the session usable, while internal error preserves
  ambiguity instead of resolving it. Servers at earlier revisions answer
  each command with unsupported operation per request and the session
  keeps serving.
- Conformance evidence: the 107-fixture corpus, deterministic
  duplex-peer permutation coverage, TCP permutation runs through `PING`
  and `GET` in every scripted order, synthetic-peer refusal and
  ambiguity suites, and black-box happy and miss paths against an
  identified server build. Layer C passes subject to one recorded
  exclusion: a success response carrying a payload the operation does
  not define (non-empty `PING`, `SET`, `DEL`, or `EXISTS` success) has
  no receiver rule at this revision, so no scenario runs for it and the
  client accepts it without refusal pending clarification.

Do not add `rp1db` to a project that needs a stable client. The API is
pre-1.0 and the command surface covers the five core operations.

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

The `protocol` module is documented as a low-level surface. The
`Connection` methods document outcomes, errors, binary safety,
concurrency, limits, ambiguity, and shutdown. Compatibility notes state
the older-server behavior and the recorded exclusion.

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

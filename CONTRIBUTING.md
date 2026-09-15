# Contributing to RP-1 Rust

Thank you for your interest in RP-1 Rust.

This document states what the repository expects from a change. Read
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) as well.

## Before you start

RP-1 Rust is the official Rust client for RP-1 and an independent
implementation of the RP-1 Native Protocol. It implements the public
protocol specification. It does not reproduce, depend on, or infer
behavior from any RP-1 server implementation.

The crate is in early development and exposes no public API yet. Open an
issue before you write a large change, so that the work is not wasted.

## Toolchain

`rust-toolchain.toml` pins the development toolchain. Install
[rustup](https://rustup.rs) and it selects the right version.

Two validation campaigns need a tool that the repository does not carry:

```sh
rustup toolchain install 1.85.0   # minimum supported version check
cargo install cargo-deny          # dependency audit
```

The crate itself supports Rust 1.85 and later. The pinned development
toolchain and the minimum supported version are separate contracts. Do
not raise either one as a side effect of another change.

## Build, test, and validate

```sh
make build   # compile the crate
make smoke   # compile, check formatting, lint, run the tests
make test    # development validation campaign
make gate    # complete validation campaign
make deps    # dependency audit
```

Use `make smoke` while you work. Run `make test` before you push, and
`make gate` before you ask for a review.

`make test` and `make gate` record what they ran, against which revision,
under which toolchain and platform, with which result. They print where
they wrote the record. A campaign seals only when every required segment
passes, under one set of inputs, with a working tree that carries nothing
the recorded revision does not.

## Code

- Write safe Rust. Unsafe code needs a measured reason and a proof
  obligation stated at the block.
- Keep failures explicit and typed. Do not flatten an error into a
  string, and do not panic on caller input, peer input, or a transport
  failure.
- Treat keys, values, and payloads as bytes. The protocol is binary.
- Keep buffers, queues, and in-flight work bounded.
- Validate anything a peer controls before you act on it, and before you
  allocate in proportion to it.
- Add the test with the behavior it protects. A fix for a defect comes
  with the test that reproduces it.
- Keep comments to what the code cannot say. Explain an invariant, an
  ordering requirement, or a measured tradeoff.

`make smoke` enforces formatting and the lint baseline. The baseline is
strict on purpose. Do not weaken a lint to make code pass.

## Dependencies

The published crate carries no dependency unless the change that adds it
states what it provides, what it replaces, and why this crate should not
own that code. Git sources, unknown registries, and path dependencies
outside the repository are rejected by the audit.

Development tooling may depend on more, as long as nothing leaks into the
published crate.

## Branches and commits

`master` is the integration branch. Work on a topic branch that starts
from `master`, and name it after its objective:

```text
feature/   new capability or public surface
fix/       defect correction
chore/     repository, tooling, and maintenance work
docs/      documentation only
perf/      measured performance work
refactor/  internal change with no behavior change
```

Write commit subjects as prose imperative sentences, for example
`Reject metadata that exceeds the negotiated limit`. This repository does
not use Conventional Commits.

A commit message states what changed, why it changed, the contract it
preserves, and the validation that ran with its exact commands and
results. It stands on its own for a reader who has only the repository.

Do not add AI, agent, or tool attribution to a commit, a pull request, or
a comment.

## Pull requests

Open a pull request against `master`. Open it as a draft, and mark it
ready when the change is complete and validated.

State in the description what changed, why, and what you ran. Name any
known gap rather than leaving it to be found.

A pull request that changes behavior updates the documentation that owns
that behavior in the same change.

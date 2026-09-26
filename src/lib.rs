//! Official Rust client for RP-1.
//!
//! `rp1db` is an independent implementation of the RP-1 Native Protocol.
//! The public RP-1 protocol specification is the contract this crate
//! implements.
//!
//! This crate is in early development. It exposes a low-level protocol
//! module that implements the `rp1-spec` `v0.4.0` framing, codec, handshake,
//! and negotiation contract, and a connection surface that opens a usable
//! protocol version 0 connection through the handshake, carries
//! multiplexed request identity with bounded admission and shared handles,
//! and closes with per-request resolution. It runs no command
//! yet.

pub mod connection;
pub mod protocol;

mod transport;

pub use connection::{
    ConnectError, Connection, ConnectionConfig, ConnectionConfigError, ConnectionState,
};

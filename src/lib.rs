//! Official Rust client for RP-1.
//!
//! `rp1db` is an independent implementation of the RP-1 Native Protocol.
//! The public RP-1 protocol specification is the contract this crate
//! implements.
//!
//! This crate is in early development. It exposes a low-level protocol
//! module that implements the `rp1-spec` `v0.5.0` framing, codec, handshake,
//! negotiation, and operation contract, and a connection surface that opens
//! a usable protocol version 0 connection through the handshake, carries
//! multiplexed requests with bounded admission and shared handles, closes
//! with per-request resolution, and runs the five core commands (`PING`,
//! `GET`, `SET`, `DEL`, `EXISTS`) through typed binary-safe async methods
//! with structured outcomes and errors.

pub mod connection;
pub mod protocol;

mod command;
mod transport;

pub use connection::{
    CommandError, ConnectError, Connection, ConnectionConfig, ConnectionConfigError,
    ConnectionState, GetOutcome,
};

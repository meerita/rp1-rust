//! Fuzzes the frame decoder with arbitrary bytes.
//!
//! The decoder must be total over arbitrary input: every byte string yields
//! either a frame or a bounded, classified failure, and never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rp1db::protocol::{self, Role};

fuzz_target!(|data: &[u8]| {
    let _ = protocol::decode(data, Role::Client, &[1, 2, 3]);
    let _ = protocol::decode(data, Role::Server, &[]);
});

//! Owns the evidence identity that a segment result is valid under.
//!
//! A passing result proves something only about the inputs that produced it.
//! This module states those inputs. It does not decide whether two identities
//! match, and it does not own record layout.

use std::path::Path;

use crate::error::Result;
use crate::json::Object;
use crate::process;

/// The material inputs a segment result depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceIdentity {
    pub subject_revision: String,
    pub campaign_definition: String,
    pub toolchain: String,
    pub target: String,
    pub features: String,
}

impl EvidenceIdentity {
    /// Reads the identity fields the host reports.
    pub fn resolve(
        repository_root: &Path,
        subject_revision: &str,
        campaign_definition: &str,
    ) -> Result<Self> {
        let toolchain = process::capture("rustc", &["--version"], repository_root)?;
        let target = host_target(repository_root)?;
        Ok(Self {
            subject_revision: subject_revision.to_owned(),
            campaign_definition: campaign_definition.to_owned(),
            toolchain,
            target,
            features: "default".to_owned(),
        })
    }

    /// Encodes the identity as a single comparable value.
    pub fn digest(&self) -> String {
        digest(&format!(
            "{}|{}|{}|{}|{}",
            self.subject_revision,
            self.campaign_definition,
            self.toolchain,
            self.target,
            self.features
        ))
    }

    pub fn to_json(&self) -> Object {
        let mut object = Object::new();
        object.string("subject_revision", &self.subject_revision);
        object.string("campaign_definition", &self.campaign_definition);
        object.string("toolchain", &self.toolchain);
        object.string("target", &self.target);
        object.string("features", &self.features);
        object.string("digest", &self.digest());
        object
    }
}

/// Reads the host target triple from the compiler.
fn host_target(repository_root: &Path) -> Result<String> {
    let verbose = process::capture("rustc", &["--version", "--verbose"], repository_root)?;
    for line in verbose.lines() {
        if let Some(value) = line.strip_prefix("host: ") {
            return Ok(value.trim().to_owned());
        }
    }
    Ok(String::new())
}

/// Produces a stable 64 bit digest of a definition string.
///
/// The digest detects a changed input. It is not a security primitive and no
/// part of the runner treats it as one.
pub fn digest(value: &str) -> String {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::{EvidenceIdentity, digest};

    fn identity() -> EvidenceIdentity {
        EvidenceIdentity {
            subject_revision: "a3d13ed3c3a74f34ec9799a163c5f68887b724fc".to_owned(),
            campaign_definition: "0123456789abcdef".to_owned(),
            toolchain: "rustc 1.98.0".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            features: "default".to_owned(),
        }
    }

    #[test]
    fn digests_differ_for_different_inputs() {
        assert_ne!(digest("a"), digest("b"));
        assert_eq!(digest("a"), digest("a"));
    }

    #[test]
    fn a_changed_toolchain_changes_the_identity_digest() {
        let baseline = identity();
        let mut upgraded = identity();
        upgraded.toolchain = "rustc 1.99.0".to_owned();

        assert_ne!(baseline.digest(), upgraded.digest());
    }

    #[test]
    fn a_changed_revision_changes_the_identity_digest() {
        let baseline = identity();
        let mut moved = identity();
        moved.subject_revision = "3635f71000000000000000000000000000000000".to_owned();

        assert_ne!(baseline.digest(), moved.digest());
    }
}

//! Owns the repository facts a record binds its evidence to.
//!
//! This module does not own record layout or campaign composition.

use std::path::{Path, PathBuf};

use crate::error::{Result, failed};
use crate::process;

const COMMIT_IDENTITY_LENGTH: usize = 40;

/// Locates the repository root that the campaign validates.
pub fn root(start: &Path) -> Result<PathBuf> {
    let output = process::capture("git", &["rev-parse", "--show-toplevel"], start)?;
    if output.is_empty() {
        return failed("the repository root could not be resolved");
    }
    Ok(PathBuf::from(output))
}

/// Resolves the revision under test to an immutable commit identity.
///
/// A record that stored a moving name such as `HEAD` would not state which
/// source it validated, so a resolved value that is not a commit identity is
/// a failure rather than a fallback.
pub fn subject_revision(repository_root: &Path) -> Result<String> {
    let revision = process::capture("git", &["rev-parse", "HEAD"], repository_root)?;
    if is_commit_identity(&revision) {
        Ok(revision)
    } else {
        failed(format!(
            "`git rev-parse HEAD` returned `{revision}`, which is not a commit identity"
        ))
    }
}

/// Reports whether a string is a full commit identity.
pub fn is_commit_identity(value: &str) -> bool {
    value.len() == COMMIT_IDENTITY_LENGTH && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::is_commit_identity;

    #[test]
    fn rejects_moving_revision_names() {
        assert!(!is_commit_identity("HEAD"));
        assert!(!is_commit_identity("master"));
        assert!(!is_commit_identity("working tree"));
        assert!(!is_commit_identity("latest"));
    }

    #[test]
    fn rejects_abbreviated_and_malformed_identities() {
        assert!(!is_commit_identity("3635f71"));
        assert!(!is_commit_identity(&"z".repeat(40)));
        assert!(!is_commit_identity(""));
    }

    #[test]
    fn accepts_a_full_commit_identity() {
        assert!(is_commit_identity(
            "a3d13ed3c3a74f34ec9799a163c5f68887b724fc"
        ));
    }
}

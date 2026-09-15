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

/// Lists the working-tree changes that the recorded revision does not carry.
///
/// Git omits ignored paths, so internal working files never appear here. A
/// modified tracked file does, and so does an untracked file that a fresh
/// clone of the recorded revision would not contain.
pub fn working_tree_changes(repository_root: &Path) -> Result<Vec<String>> {
    let output = process::capture("git", &["status", "--porcelain"], repository_root)?;
    Ok(output
        .lines()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect())
}

/// Reports whether a string is a full commit identity.
pub fn is_commit_identity(value: &str) -> bool {
    value.len() == COMMIT_IDENTITY_LENGTH && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{is_commit_identity, subject_revision, working_tree_changes};
    use crate::error::Result;
    use crate::process;
    use crate::testing::TempDir;

    fn git(root: &Path, args: &[&str]) -> Result<String> {
        process::capture("git", args, root)
    }

    /// Builds a repository with one tracked file and one ignored directory.
    fn repository(label: &str) -> Result<TempDir> {
        let temp = TempDir::new(label)?;
        let root = temp.path();

        let _ = git(root, &["init", "--quiet"])?;
        let _ = git(root, &["config", "user.name", "Test"])?;
        let _ = git(root, &["config", "user.email", "test@example.com"])?;

        fs::write(root.join(".gitignore"), "ignored/\n")?;
        fs::write(root.join("tracked.txt"), "original\n")?;
        let _ = git(root, &["add", "."])?;
        let _ = git(root, &["commit", "--quiet", "-m", "Add the first file"])?;

        Ok(temp)
    }

    #[test]
    fn an_ignored_file_does_not_make_the_tree_dirty() -> Result<()> {
        let temp = repository("repo-ignored")?;
        fs::create_dir_all(temp.path().join("ignored"))?;
        fs::write(temp.path().join("ignored").join("record.txt"), "evidence\n")?;

        assert!(
            working_tree_changes(temp.path())?.is_empty(),
            "internal working files are not repository changes"
        );
        Ok(())
    }

    #[test]
    fn a_modified_tracked_file_makes_the_tree_dirty() -> Result<()> {
        let temp = repository("repo-tracked")?;
        fs::write(temp.path().join("tracked.txt"), "changed\n")?;

        let changes = working_tree_changes(temp.path())?;

        assert_eq!(changes.len(), 1);
        assert!(
            changes
                .first()
                .is_some_and(|change| change.contains("tracked.txt")),
            "{changes:?}"
        );
        Ok(())
    }

    #[test]
    fn the_recorded_revision_is_a_commit_identity() -> Result<()> {
        let temp = repository("repo-revision")?;

        let revision = subject_revision(temp.path())?;

        assert!(is_commit_identity(&revision), "{revision}");
        assert_ne!(revision, "HEAD");
        Ok(())
    }

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

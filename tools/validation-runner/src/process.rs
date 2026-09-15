//! Owns short command invocations whose output the runner reads.
//!
//! Segment execution does not use this module. Segment output goes to a
//! record file instead of into memory.

use std::path::Path;
use std::process::Command;

use crate::error::{Result, failed};

/// Runs a command and returns its trimmed standard output.
///
/// Fails when the command cannot start or reports a non-zero status.
pub fn capture(program: &str, args: &[&str], working_dir: &Path) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(working_dir)
        .output()?;

    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return failed(format!(
            "`{} {}` failed: {}",
            program,
            args.join(" "),
            detail.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

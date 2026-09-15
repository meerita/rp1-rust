//! Owns the on-disk run record: its directory, manifest, journal, raw
//! evidence, and summary.
//!
//! This module writes what a later reader needs to audit a campaign. It does
//! not decide what a campaign contains and it does not execute anything.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{Result, failed};
use crate::json::Object;

/// The directory that holds run records. Git ignores it, and no build, test,
/// or packaging operation reads from it.
pub const RECORDS_DIRECTORY: &str = "runs";

const MANIFEST_FILE: &str = "manifest.json";
const JOURNAL_FILE: &str = "journal.jsonl";
const SUMMARY_FILE: &str = "summary.md";
const SEGMENTS_DIRECTORY: &str = "segments";

/// The highest sequence number one date can hold.
const MAX_SEQUENCE: u32 = 99;

/// One campaign record on disk.
#[derive(Clone, Debug)]
pub struct RunRecord {
    root: PathBuf,
    identifier: String,
}

impl RunRecord {
    /// Creates the next record directory for a tier and date.
    ///
    /// The directory name carries the date and a sequence number, so two
    /// campaigns on one day never share a record.
    pub fn create(records_root: &Path, tier: &str, date: &str, topic: &str) -> Result<Self> {
        let tier_root = records_root.join(tier);
        fs::create_dir_all(&tier_root)?;

        let sequence = next_sequence(&tier_root, date)?;
        let identifier = format!("{date}-{sequence:02}-{topic}");
        let root = tier_root.join(&identifier);
        fs::create_dir_all(root.join(SEGMENTS_DIRECTORY))?;

        Ok(Self { root, identifier })
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes the manifest. A campaign calls this before any segment runs.
    pub fn write_manifest(&self, manifest: &Object) -> Result<()> {
        let mut file = File::create(self.root.join(MANIFEST_FILE))?;
        writeln!(file, "{}", manifest.encode())?;
        file.sync_all()?;
        Ok(())
    }

    /// Appends one journal entry and flushes it to disk.
    ///
    /// Entries are only ever added. A later attempt never edits or removes an
    /// earlier one, so the record keeps the failure that preceded a fix.
    pub fn append_journal(&self, entry: &Object) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join(JOURNAL_FILE))?;
        writeln!(file, "{}", entry.encode())?;
        file.sync_all()?;
        Ok(())
    }

    /// Counts the attempts a segment already has in this record.
    pub fn attempts_for(&self, segment: &str) -> Result<u32> {
        let path = self.root.join(JOURNAL_FILE);
        if !path.exists() {
            return Ok(0);
        }

        let marker = format!("\"segment\":\"{segment}\"");
        let journal = fs::read_to_string(path)?;
        let attempts = journal
            .lines()
            .filter(|line| line.contains(&marker))
            .count();

        u32::try_from(attempts).map_or_else(
            |_| failed("this record holds more attempts than it can count"),
            Ok,
        )
    }

    /// The file that holds the raw output of one attempt.
    pub fn evidence_path(&self, segment: &str, attempt: u32) -> PathBuf {
        self.root
            .join(SEGMENTS_DIRECTORY)
            .join(evidence_name(segment, attempt))
    }

    /// The same file, named as the journal records it.
    pub fn evidence_reference(segment: &str, attempt: u32) -> String {
        format!("{SEGMENTS_DIRECTORY}/{}", evidence_name(segment, attempt))
    }

    pub fn write_summary(&self, body: &str) -> Result<()> {
        let mut file = File::create(self.root.join(SUMMARY_FILE))?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE)
    }

    #[cfg(test)]
    pub fn journal_path(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE)
    }
}

fn evidence_name(segment: &str, attempt: u32) -> String {
    format!("{segment}-{attempt:02}.txt")
}

/// Finds the next unused sequence number for a date inside a tier directory.
fn next_sequence(tier_root: &Path, date: &str) -> Result<u32> {
    let prefix = format!("{date}-");
    let mut highest = 0_u32;

    for entry in fs::read_dir(tier_root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(sequence) = rest.get(..2).and_then(|digits| digits.parse::<u32>().ok()) else {
            continue;
        };
        highest = highest.max(sequence);
    }

    match highest.checked_add(1) {
        Some(next) if next <= MAX_SEQUENCE => Ok(next),
        _ => failed(format!(
            "this date already holds {MAX_SEQUENCE} records for this tier"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::RunRecord;
    use crate::error::Result;
    use crate::json::Object;
    use crate::testing::TempDir;

    fn entry(segment: &str) -> Object {
        let mut object = Object::new();
        object.string("segment", segment);
        object
    }

    #[test]
    fn records_for_one_date_take_successive_sequence_numbers() -> Result<()> {
        let temp = TempDir::new("record-sequence")?;

        let first = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;
        let second = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;

        assert_eq!(first.identifier(), "2026-09-15-01-repository");
        assert_eq!(second.identifier(), "2026-09-15-02-repository");
        Ok(())
    }

    #[test]
    fn journal_entries_are_only_ever_appended() -> Result<()> {
        let temp = TempDir::new("record-journal")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;

        record.append_journal(&entry("unit-tests"))?;
        record.append_journal(&entry("msrv"))?;
        record.append_journal(&entry("unit-tests"))?;

        let journal = std::fs::read_to_string(record.journal_path())?;
        let lines: Vec<&str> = journal.lines().collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines.first(), Some(&"{\"segment\":\"unit-tests\"}"));
        assert_eq!(lines.get(1), Some(&"{\"segment\":\"msrv\"}"));
        assert_eq!(record.attempts_for("unit-tests")?, 2);
        assert_eq!(record.attempts_for("msrv")?, 1);
        assert_eq!(record.attempts_for("deps")?, 0);
        Ok(())
    }
}

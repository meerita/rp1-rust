//! Owns the on-disk run record: its directory, manifest, journal, raw
//! evidence, and summary.
//!
//! This module writes what a later reader needs to audit a campaign. It does
//! not decide what a campaign contains and it does not execute anything.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{Result, failed};
use crate::json::{self, Object};

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

    /// Opens an existing record directory.
    pub fn open(root: PathBuf) -> Result<Self> {
        let Some(identifier) = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
        else {
            return failed("a record directory must have a name");
        };
        if !root.is_dir() {
            return failed(format!("`{identifier}` is not a record directory"));
        }
        Ok(Self { root, identifier })
    }

    /// Finds the most recent record for a tier.
    pub fn latest(records_root: &Path, tier: &str) -> Result<Option<Self>> {
        let tier_root = records_root.join(tier);
        if !tier_root.is_dir() {
            return Ok(None);
        }

        let mut names: Vec<String> = Vec::new();
        for entry in fs::read_dir(&tier_root)? {
            let entry = entry?;
            if entry.path().is_dir() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();

        match names.into_iter().next_back() {
            Some(name) => Ok(Some(Self::open(tier_root.join(name))?)),
            None => Ok(None),
        }
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

    /// Reads every journal entry in the order it was recorded.
    pub fn entries(&self) -> Result<Vec<JournalEntry>> {
        let path = self.root.join(JOURNAL_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let journal = fs::read_to_string(path)?;
        let mut entries = Vec::new();
        for line in journal.lines().filter(|line| !line.trim().is_empty()) {
            entries.push(JournalEntry::parse(line)?);
        }
        Ok(entries)
    }

    /// Counts the attempts a segment already has in this record.
    pub fn attempts_for(&self, segment: &str) -> Result<u32> {
        let attempts = self
            .entries()?
            .iter()
            .filter(|entry| entry.segment == segment)
            .count();

        u32::try_from(attempts).map_or_else(
            |_| failed("this record holds more attempts than it can count"),
            Ok,
        )
    }

    /// Reads the most recent attempt recorded for a segment.
    pub fn last_entry_for(&self, segment: &str) -> Result<Option<JournalEntry>> {
        Ok(self
            .entries()?
            .into_iter()
            .rfind(|entry| entry.segment == segment))
    }

    /// Reads the evidence identity this record already holds results under.
    ///
    /// A record with no entries holds no identity yet, so any campaign may
    /// continue into it.
    pub fn recorded_identity(&self) -> Result<Option<String>> {
        Ok(self
            .entries()?
            .into_iter()
            .next_back()
            .map(|entry| entry.evidence_identity))
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

/// One recorded attempt, read back from the journal.
#[derive(Clone, Debug)]
pub struct JournalEntry {
    pub segment: String,
    pub attempt: u32,
    pub status: String,
    pub evidence_identity: String,
    pub evidence: String,
}

impl JournalEntry {
    fn parse(line: &str) -> Result<Self> {
        let fields = json::parse_flat_object(line)?;
        let Some(segment) = json::string_field(&fields, "segment") else {
            return failed("a journal entry must name its segment");
        };
        let Some(status) = json::string_field(&fields, "status") else {
            return failed("a journal entry must state its status");
        };
        let Some(identity) = json::string_field(&fields, "evidence_identity") else {
            return failed("a journal entry must state the identity it holds under");
        };
        let attempt = json::number_field(&fields, "attempt").unwrap_or(0);
        let Ok(attempt) = u32::try_from(attempt) else {
            return failed("a journal entry states an attempt number it cannot hold");
        };

        Ok(Self {
            segment: segment.to_owned(),
            attempt,
            status: status.to_owned(),
            evidence_identity: identity.to_owned(),
            evidence: json::string_field(&fields, "evidence")
                .unwrap_or_default()
                .to_owned(),
        })
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

    fn entry(segment: &str, attempt: u32) -> Object {
        let mut object = Object::new();
        object.string("segment", segment);
        object.number("attempt", u64::from(attempt));
        object.string("status", "pass");
        object.string("evidence_identity", "identity");
        object.string("evidence", "segments/evidence.txt");
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

        record.append_journal(&entry("unit-tests", 1))?;
        record.append_journal(&entry("msrv", 1))?;
        record.append_journal(&entry("unit-tests", 2))?;

        let journal = std::fs::read_to_string(record.journal_path())?;

        assert_eq!(journal.lines().count(), 3);
        let entries = record.entries()?;
        assert_eq!(
            entries.first().map(|entry| entry.segment.as_str()),
            Some("unit-tests")
        );
        assert_eq!(
            entries.get(1).map(|entry| entry.segment.as_str()),
            Some("msrv")
        );
        assert_eq!(
            record
                .last_entry_for("unit-tests")?
                .map(|entry| entry.attempt),
            Some(2)
        );
        assert_eq!(record.recorded_identity()?.as_deref(), Some("identity"));
        assert_eq!(record.attempts_for("unit-tests")?, 2);
        assert_eq!(record.attempts_for("msrv")?, 1);
        assert_eq!(record.attempts_for("deps")?, 0);
        Ok(())
    }
}

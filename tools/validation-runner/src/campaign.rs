//! Owns what a campaign contains and how it executes.
//!
//! This module defines the segments, decides which ones a tier requires,
//! writes the manifest before anything runs, and records each attempt when
//! that attempt ends. It does not own the record layout, process execution,
//! or the evidence identity fields.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Result, failed};
use crate::identity::{self, EvidenceIdentity};
use crate::json::Object;
use crate::record::{JournalEntry, RunRecord};
use crate::segment::{self, Status, Step};

/// The wall-clock budget one segment attempt may use.
pub const SEGMENT_BUDGET: Duration = Duration::from_secs(120);

/// The campaign this runner executes.
pub const CAMPAIGN_TYPE: &str = "repository-validation";

/// The evidence level a campaign produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Dev,
    Gate,
}

impl Tier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Gate => "gate",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "dev" => Ok(Self::Dev),
            "gate" => Ok(Self::Gate),
            other => failed(format!(
                "`{other}` is not a tier this runner executes. Use `dev` or `gate`."
            )),
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A host capability a segment needs before it can prove anything.
#[derive(Clone, Debug)]
pub struct Prerequisite {
    probe: Step,
    remedy: String,
}

/// One segment of the campaign.
#[derive(Clone, Debug)]
pub struct SegmentDefinition {
    id: &'static str,
    purpose: &'static str,
    tiers: &'static [Tier],
    prerequisite: Option<Prerequisite>,
    steps: Vec<Step>,
}

impl SegmentDefinition {
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Renders the segment as the digest input that identifies its definition.
    fn definition_line(&self) -> String {
        let commands: Vec<String> = self.steps.iter().map(Step::display).collect();
        format!("{}::{}", self.id, commands.join(" && "))
    }
}

/// Every segment this runner knows how to execute.
pub fn definition() -> Vec<SegmentDefinition> {
    vec![
        SegmentDefinition {
            id: "build-and-lint",
            purpose: "the workspace compiles, is formatted, and lints clean",
            tiers: &[Tier::Dev, Tier::Gate],
            prerequisite: None,
            steps: vec![
                Step::new("cargo", &["build", "--workspace", "--all-targets"]),
                Step::new("cargo", &["fmt", "--all", "--check"]),
                Step::new("cargo", &["clippy", "--workspace", "--all-targets"]),
            ],
        },
        SegmentDefinition {
            id: "unit-tests",
            purpose: "the crate and the runner pass their unit tests",
            tiers: &[Tier::Dev, Tier::Gate],
            prerequisite: None,
            steps: vec![Step::new("cargo", &["test", "--workspace"])],
        },
        SegmentDefinition {
            id: "msrv",
            purpose: "the published crate compiles on its declared minimum Rust version",
            tiers: &[Tier::Dev, Tier::Gate],
            prerequisite: Some(Prerequisite {
                probe: Step::new("cargo", &["+1.85.0", "--version"]),
                remedy: "install it with `rustup toolchain install 1.85.0`".to_owned(),
            }),
            steps: vec![Step::new(
                "cargo",
                &["+1.85.0", "check", "--package", "rp1db"],
            )],
        },
        SegmentDefinition {
            id: "deps",
            purpose: "the dependency graph satisfies the committed supply-chain policy",
            tiers: &[Tier::Dev, Tier::Gate],
            prerequisite: Some(Prerequisite {
                probe: Step::new("cargo", &["deny", "--version"]),
                remedy: "install it with `cargo install cargo-deny`".to_owned(),
            }),
            steps: vec![
                Step::new("cargo", &["deny", "check"]),
                Step::new("/bin/sh", &["-c", LOCAL_PATH_CHECK]),
            ],
        },
    ]
}

/// Fails when a tracked manifest declares a path dependency that leaves the
/// repository. A dependency outside the checkout cannot be resolved from a
/// clean clone, and it is the shape a private dependency would take.
const LOCAL_PATH_CHECK: &str = concat!(
    "if git ls-files -z '*Cargo.toml' | xargs -0 grep -lE ",
    "'path[[:space:]]*=[[:space:]]*\"[^\"]*[.][.]'; then ",
    "echo 'a manifest declares a path dependency that leaves the repository'; ",
    "exit 1; fi"
);

/// The segments a tier requires, in execution order.
pub fn required(tier: Tier) -> Vec<SegmentDefinition> {
    definition()
        .into_iter()
        .filter(|segment| segment.tiers.contains(&tier))
        .collect()
}

/// A digest of the required segment definitions.
///
/// A changed command changes this value, so evidence recorded under the old
/// definition is visibly evidence for a different campaign.
pub fn definition_digest(segments: &[SegmentDefinition]) -> String {
    let lines: Vec<String> = segments
        .iter()
        .map(SegmentDefinition::definition_line)
        .collect();
    identity::digest(&lines.join("\n"))
}

/// What one segment attempt produced inside a campaign.
#[derive(Clone, Debug)]
pub struct SegmentResult {
    pub id: &'static str,
    pub attempt: u32,
    pub status: Status,
    pub duration: Duration,
    pub note: Option<String>,
    pub evidence: String,
    pub identity: String,
}

/// The state a campaign record is in when it closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Partial,
    Sealed,
    Failed,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Partial => "partial",
            Self::Sealed => "sealed",
            Self::Failed => "failed",
        }
    }
}

/// Whether the working tree matches the revision the record names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeState {
    Clean,
    Modified(Vec<String>),
}

/// One segment result as the seal check reads it.
#[derive(Clone, Debug)]
pub struct FinalResult {
    pub id: String,
    pub status: Status,
    pub identity: String,
}

/// Decides whether a set of results seals, and states why when it does not.
///
/// Sealing is the point of the record. Every condition below is a refusal
/// that keeps a later reader from treating incomplete work as proof.
pub fn seal_state(
    required: &[String],
    finals: &[FinalResult],
    identity: &str,
    tree: &TreeState,
) -> (State, Vec<String>) {
    let mut reasons = Vec::new();

    let blocked: Vec<String> = finals
        .iter()
        .filter(|result| !result.status.holds())
        .map(|result| format!("{} is {}", result.id, result.status.as_str()))
        .collect();

    let missing: Vec<String> = required
        .iter()
        .filter(|id| !finals.iter().any(|result| &result.id == *id))
        .cloned()
        .collect();

    let mismatched: Vec<String> = finals
        .iter()
        .filter(|result| result.status.holds() && result.identity != identity)
        .map(|result| format!("{} holds under a different evidence identity", result.id))
        .collect();

    if !blocked.is_empty() {
        reasons.extend(blocked);
        return (State::Failed, reasons);
    }

    if !missing.is_empty() {
        reasons.push(format!("no result for {}", missing.join(", ")));
    }
    reasons.extend(mismatched);

    if let TreeState::Modified(changes) = tree {
        reasons.push(format!(
            "the working tree carries {} change(s) that the recorded revision does not",
            changes.len()
        ));
    }

    if reasons.is_empty() {
        (State::Sealed, reasons)
    } else {
        (State::Partial, reasons)
    }
}

/// What a campaign produced.
#[derive(Clone, Debug)]
pub struct Report {
    pub results: Vec<SegmentResult>,
    pub state: State,
    pub reasons: Vec<String>,
}

impl Report {
    /// Reports whether every segment holds, whether it ran or was reused.
    pub fn every_segment_holds(&self) -> bool {
        self.results.iter().all(|result| result.status.holds())
    }

    pub fn reused(&self) -> usize {
        self.results
            .iter()
            .filter(|result| !result.status.executed())
            .count()
    }
}

/// One execution of a campaign against one record.
pub struct Campaign {
    pub tier: Tier,
    pub topic: String,
    pub subject_revision: String,
    pub identity: EvidenceIdentity,
    pub segments: Vec<SegmentDefinition>,
    pub budget: Duration,
    pub working_dir: PathBuf,
    pub environment: Object,
    pub created: String,
    pub resume: bool,
    pub tree_state: TreeState,
}

impl Campaign {
    /// Writes the manifest, runs or reuses every segment, and records each
    /// attempt as it ends.
    ///
    /// An interrupted campaign leaves every completed attempt on disk,
    /// because nothing is held back for a final write.
    pub fn execute(&self, record: &RunRecord, now: &dyn Fn() -> Result<String>) -> Result<Report> {
        record.write_manifest(&self.manifest(record))?;
        let identity = self.identity.digest();

        let mut results = Vec::with_capacity(self.segments.len());
        for definition in &self.segments {
            let attempt = record.attempts_for(definition.id())?.checked_add(1);
            let Some(attempt) = attempt else {
                return failed("this record holds more attempts than it can count");
            };

            let started = now()?;
            let prior = record.last_entry_for(definition.id())?;
            let result = if let Some(prior) = self.reusable(prior.as_ref(), &identity) {
                reuse(definition.id(), attempt, prior, &identity)
            } else {
                let evidence = record.evidence_path(definition.id(), attempt);
                let outcome = self.attempt(definition, &evidence)?;
                SegmentResult {
                    id: definition.id(),
                    attempt,
                    status: outcome.status,
                    duration: outcome.duration,
                    note: outcome.note,
                    evidence: RunRecord::evidence_reference(definition.id(), attempt),
                    identity: identity.clone(),
                }
            };

            record.append_journal(&self.journal_entry(&result, &started))?;
            results.push(result);
        }

        let required: Vec<String> = self
            .segments
            .iter()
            .map(|definition| definition.id().to_owned())
            .collect();
        let finals: Vec<FinalResult> = results
            .iter()
            .map(|result| FinalResult {
                id: result.id.to_owned(),
                status: result.status,
                identity: result.identity.clone(),
            })
            .collect();
        let (state, reasons) = seal_state(&required, &finals, &identity, &self.tree_state);

        let report = Report {
            results,
            state,
            reasons,
        };
        record.write_summary(&self.summary(record, &report))?;
        Ok(report)
    }

    /// Decides whether a prior attempt still proves what this campaign needs.
    ///
    /// Only a result that holds, under the same evidence identity, may be
    /// reused. A failed, timed out, skipped, or missing result runs again,
    /// and so does one recorded under any other identity.
    fn reusable<'a>(
        &self,
        prior: Option<&'a JournalEntry>,
        identity: &str,
    ) -> Option<&'a JournalEntry> {
        if !self.resume {
            return None;
        }

        let prior = prior?;
        let status = Status::parse(&prior.status)?;
        if status.holds() && prior.evidence_identity == identity {
            Some(prior)
        } else {
            None
        }
    }

    fn attempt(&self, definition: &SegmentDefinition, evidence: &Path) -> Result<segment::Outcome> {
        if let Some(prerequisite) = &definition.prerequisite
            && !segment::probe(&prerequisite.probe, &self.working_dir)
        {
            let note = format!(
                "`{}` is not available on this host, so this segment did not run. {}",
                prerequisite.probe.display(),
                prerequisite.remedy
            );
            std::fs::write(evidence, format!("[{note}]\n"))?;
            return Ok(segment::Outcome {
                status: Status::Skipped,
                duration: Duration::ZERO,
                note: Some(note),
            });
        }

        segment::execute(&definition.steps, self.budget, &self.working_dir, evidence)
    }

    fn manifest(&self, record: &RunRecord) -> Object {
        let required: Vec<String> = self
            .segments
            .iter()
            .map(|definition| definition.id().to_owned())
            .collect();

        let mut manifest = Object::new();
        manifest.string("campaign", record.identifier());
        manifest.string("type", CAMPAIGN_TYPE);
        manifest.string("topic", &self.topic);
        manifest.string("tier", self.tier.as_str());
        manifest.string("subject_revision", &self.subject_revision);
        manifest.strings("required_segments", &required);
        manifest.object("evidence_identity", &self.identity.to_json());
        manifest.number("segment_budget_seconds", self.budget.as_secs());
        manifest.object("environment", &self.environment);
        manifest.string("created", &self.created);
        manifest
    }

    fn journal_entry(&self, result: &SegmentResult, started: &str) -> Object {
        let mut entry = Object::new();
        entry.string("segment", result.id);
        entry.number("attempt", u64::from(result.attempt));
        entry.string("started", started);
        entry.number("duration_ms", duration_millis(result.duration));
        entry.string("status", result.status.as_str());
        entry.string("subject_revision", &self.subject_revision);
        entry.string("evidence_identity", &self.identity.digest());
        entry.string("evidence", &result.evidence);
        if let Some(note) = &result.note {
            entry.string("note", note);
        }
        entry
    }

    fn summary(&self, record: &RunRecord, report: &Report) -> String {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("# {}", record.identifier()));
        lines.push(String::new());
        lines.push(format!("Type: {CAMPAIGN_TYPE}"));
        lines.push(format!("Tier: {}", self.tier));
        lines.push(format!("Revision: {}", self.subject_revision));
        lines.push(format!("Evidence identity: {}", self.identity.digest()));
        lines.push(format!("State: {}", report.state.as_str()));
        lines.push(String::new());

        lines.push("| Segment | Attempt | Status | Seconds |".to_owned());
        lines.push("| --- | --- | --- | --- |".to_owned());
        for result in &report.results {
            lines.push(format!(
                "| {} | {} | {} | {:.1} |",
                result.id,
                result.attempt,
                result.status.as_str(),
                result.duration.as_secs_f64()
            ));
        }

        if !report.reasons.is_empty() {
            lines.push(String::new());
            lines.push("## Why this record does not seal".to_owned());
            lines.push(String::new());
            for reason in &report.reasons {
                lines.push(format!("- {reason}"));
            }
        }

        let notes: Vec<&SegmentResult> = report
            .results
            .iter()
            .filter(|result| result.note.is_some())
            .collect();
        if !notes.is_empty() {
            lines.push(String::new());
            lines.push("## Notes".to_owned());
            lines.push(String::new());
            for result in notes {
                if let Some(note) = &result.note {
                    lines.push(format!("- {}: {note}", result.id));
                }
            }
        }

        lines.push(String::new());
        lines.push("## Segments".to_owned());
        lines.push(String::new());
        for definition in &self.segments {
            lines.push(format!("- {}: {}", definition.id(), definition.purpose));
        }

        lines.push(String::new());
        lines.push("## Scope".to_owned());
        lines.push(String::new());
        lines.push(
            "This record covers the segments listed above at the stated revision and".to_owned(),
        );
        lines.push(
            "evidence identity. It states nothing about any other revision, any other".to_owned(),
        );
        lines.push("input, or any segment it does not list.".to_owned());
        lines.push(String::new());

        lines.join("\n")
    }
}

/// Builds the entry that records a reused result.
///
/// A reused result is marked `cached` and points at the evidence that
/// already exists. It is never reported as newly executed.
fn reuse(id: &'static str, attempt: u32, prior: &JournalEntry, identity: &str) -> SegmentResult {
    SegmentResult {
        id,
        attempt,
        status: Status::Cached,
        duration: Duration::ZERO,
        note: Some(format!(
            "reused the result recorded by attempt {}",
            prior.attempt
        )),
        evidence: prior.evidence.clone(),
        identity: identity.to_owned(),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use super::{
        Campaign, FinalResult, Prerequisite, SegmentDefinition, State, Tier, TreeState,
        definition_digest, required, seal_state,
    };
    use crate::error::Result;
    use crate::identity::EvidenceIdentity;
    use crate::json::Object;
    use crate::record::RunRecord;
    use crate::segment::{Status, Step};
    use crate::testing::TempDir;

    const REVISION: &str = "a3d13ed3c3a74f34ec9799a163c5f68887b724fc";
    const OTHER_REVISION: &str = "3635f71000000000000000000000000000000000";

    fn segment(id: &'static str, steps: Vec<Step>) -> SegmentDefinition {
        SegmentDefinition {
            id,
            purpose: "test segment",
            tiers: &[Tier::Dev, Tier::Gate],
            prerequisite: None,
            steps,
        }
    }

    fn identity(revision: &str, toolchain: &str) -> EvidenceIdentity {
        EvidenceIdentity {
            subject_revision: revision.to_owned(),
            campaign_definition: "definition".to_owned(),
            toolchain: toolchain.to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            features: "default".to_owned(),
        }
    }

    fn campaign(working_dir: &std::path::Path, segments: Vec<SegmentDefinition>) -> Campaign {
        Campaign {
            tier: Tier::Dev,
            topic: "repository".to_owned(),
            subject_revision: REVISION.to_owned(),
            identity: identity(REVISION, "rustc 1.98.0"),
            segments,
            budget: Duration::from_secs(30),
            working_dir: working_dir.to_path_buf(),
            environment: Object::new(),
            created: "2026-09-15T00:00:00Z".to_owned(),
            resume: false,
            tree_state: TreeState::Clean,
        }
    }

    fn clock() -> impl Fn() -> Result<String> {
        || Ok("2026-09-15T00:00:00Z".to_owned())
    }

    /// A step that records every run in a counter file, so a test can tell a
    /// reused result from an executed one.
    fn counting_step(marker: &std::path::Path) -> Step {
        Step::new(
            "/bin/sh",
            &["-c", &format!("echo ran >> {}", marker.display())],
        )
    }

    fn runs(marker: &std::path::Path) -> usize {
        fs::read_to_string(marker).map_or(0, |body| body.lines().count())
    }

    fn finals(entries: &[(&str, Status, &str)]) -> Vec<FinalResult> {
        entries
            .iter()
            .map(|(id, status, identity)| FinalResult {
                id: (*id).to_owned(),
                status: *status,
                identity: (*identity).to_owned(),
            })
            .collect()
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn the_manifest_exists_before_the_first_segment_runs() -> Result<()> {
        let temp = TempDir::new("campaign-manifest")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;
        let manifest = record.manifest_path();

        let probe = Step::new(
            "/bin/sh",
            &["-c", &format!("test -f {}", manifest.display())],
        );
        let campaign = campaign(temp.path(), vec![segment("manifest-probe", vec![probe])]);

        let report = campaign.execute(&record, &clock())?;

        assert!(report.every_segment_holds());
        assert!(manifest.exists());
        Ok(())
    }

    #[test]
    fn each_segment_is_recorded_before_the_next_one_runs() -> Result<()> {
        let temp = TempDir::new("campaign-incremental")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;
        let journal = record.journal_path();

        let first = segment("first", vec![Step::new("/bin/sh", &["-c", "true"])]);
        let second = segment(
            "second",
            vec![Step::new(
                "/bin/sh",
                &[
                    "-c",
                    &format!("grep -q '\"segment\":\"first\"' {}", journal.display()),
                ],
            )],
        );

        let report = campaign(temp.path(), vec![first, second]).execute(&record, &clock())?;

        assert!(
            report.every_segment_holds(),
            "the second segment only passes when the first was already on disk"
        );
        Ok(())
    }

    #[test]
    fn a_failed_attempt_and_a_later_passing_attempt_both_stay_in_the_journal() -> Result<()> {
        let temp = TempDir::new("campaign-attempts")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;

        let failing = vec![segment(
            "flaky",
            vec![Step::new("/bin/sh", &["-c", "exit 1"])],
        )];
        let passing = vec![segment(
            "flaky",
            vec![Step::new("/bin/sh", &["-c", "true"])],
        )];

        let first = campaign(temp.path(), failing).execute(&record, &clock())?;
        let second = campaign(temp.path(), passing).execute(&record, &clock())?;

        assert_eq!(first.state, State::Failed);
        assert_eq!(second.state, State::Sealed);
        assert_eq!(record.attempts_for("flaky")?, 2);

        let journal = fs::read_to_string(record.journal_path())?;
        let lines: Vec<&str> = journal.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("\"status\":\"fail\"")),
            "the earlier failure stays in the record"
        );
        assert!(
            lines
                .get(1)
                .is_some_and(|line| line.contains("\"status\":\"pass\"")),
            "the later pass is a separate entry"
        );
        assert!(
            lines
                .first()
                .is_some_and(|line| line.contains("\"attempt\":1")),
            "attempts are numbered in order"
        );
        assert!(
            lines
                .get(1)
                .is_some_and(|line| line.contains("\"attempt\":2"))
        );
        Ok(())
    }

    #[test]
    fn a_segment_over_its_budget_is_recorded_as_a_timeout() -> Result<()> {
        let temp = TempDir::new("campaign-timeout")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;

        let mut campaign = campaign(
            temp.path(),
            vec![segment(
                "slow",
                vec![Step::new("/bin/sh", &["-c", "sleep 30"])],
            )],
        );
        campaign.budget = Duration::from_millis(200);

        let report = campaign.execute(&record, &clock())?;

        assert_eq!(report.state, State::Failed);
        assert_eq!(
            report.results.first().map(|result| result.status),
            Some(Status::Timeout)
        );

        let journal = fs::read_to_string(record.journal_path())?;
        assert!(journal.contains("\"status\":\"timeout\""), "{journal}");
        assert!(!journal.contains("\"status\":\"fail\""), "{journal}");
        Ok(())
    }

    #[test]
    fn an_interrupted_campaign_keeps_every_completed_attempt() -> Result<()> {
        let temp = TempDir::new("campaign-interrupted")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;

        let mut campaign = campaign(
            temp.path(),
            vec![
                segment("completed", vec![Step::new("/bin/sh", &["-c", "true"])]),
                segment(
                    "interrupted",
                    vec![Step::new("/bin/sh", &["-c", "sleep 30"])],
                ),
            ],
        );
        campaign.budget = Duration::from_millis(200);

        let report = campaign.execute(&record, &clock())?;

        assert_eq!(report.state, State::Failed);
        let journal = fs::read_to_string(record.journal_path())?;
        assert!(journal.contains("\"segment\":\"completed\""), "{journal}");
        assert!(journal.contains("\"status\":\"pass\""), "{journal}");
        assert!(
            record.evidence_path("completed", 1).exists(),
            "raw output of the completed segment survives"
        );
        Ok(())
    }

    #[test]
    fn a_missing_host_prerequisite_is_recorded_as_skipped() -> Result<()> {
        let temp = TempDir::new("campaign-prerequisite")?;
        let record = RunRecord::create(temp.path(), "dev", "2026-09-15", "repository")?;

        let mut definition = segment("needs-tool", vec![Step::new("/bin/sh", &["-c", "true"])]);
        definition.prerequisite = Some(Prerequisite {
            probe: Step::new("rp1-no-such-program", &[]),
            remedy: "install the tool".to_owned(),
        });

        let report = campaign(temp.path(), vec![definition]).execute(&record, &clock())?;

        assert_eq!(
            report.results.first().map(|result| result.status),
            Some(Status::Skipped)
        );
        assert!(!report.every_segment_holds(), "a skip is not evidence");
        assert_eq!(report.state, State::Failed);
        Ok(())
    }

    #[test]
    fn a_changed_command_changes_the_definition_digest() {
        let baseline = vec![segment("one", vec![Step::new("/bin/sh", &["-c", "true"])])];
        let changed = vec![segment("one", vec![Step::new("/bin/sh", &["-c", "false"])])];

        assert_ne!(definition_digest(&baseline), definition_digest(&changed));
    }

    #[test]
    fn every_defined_tier_requires_the_declared_segments() {
        let dev: Vec<&str> = required(Tier::Dev)
            .iter()
            .map(SegmentDefinition::id)
            .collect();

        assert_eq!(dev, vec!["build-and-lint", "unit-tests", "msrv", "deps"]);

        let gate: Vec<&str> = required(Tier::Gate)
            .iter()
            .map(SegmentDefinition::id)
            .collect();

        assert_eq!(gate, vec!["build-and-lint", "unit-tests", "msrv", "deps"]);
    }

    #[test]
    fn the_local_path_check_rejects_a_manifest_that_leaves_the_repository() -> Result<()> {
        let temp = TempDir::new("local-paths")?;
        let root = temp.path();

        let _ = crate::process::capture("git", &["init", "--quiet"], root)?;
        fs::write(
            root.join("Cargo.toml"),
            "[dependencies]\nprivate = { path = \"../../private/crate\" }\n",
        )?;
        let _ = crate::process::capture("git", &["add", "."], root)?;

        let record = RunRecord::create(root, "gate", "2026-09-15", "repository")?;
        let report = campaign(
            root,
            vec![segment(
                "local-paths",
                vec![Step::new("/bin/sh", &["-c", super::LOCAL_PATH_CHECK])],
            )],
        )
        .execute(&record, &clock())?;

        assert_eq!(
            report.results.first().map(|result| result.status),
            Some(Status::Fail),
            "a path dependency outside the repository stops the audit"
        );
        Ok(())
    }

    #[test]
    fn a_resumed_campaign_marks_a_reused_segment_cached_and_does_not_run_it() -> Result<()> {
        let temp = TempDir::new("resume-cached")?;
        let record = RunRecord::create(temp.path(), "gate", "2026-09-15", "repository")?;
        let marker = temp.path().join("runs.txt");

        let first = campaign(
            temp.path(),
            vec![segment("counted", vec![counting_step(&marker)])],
        )
        .execute(&record, &clock())?;
        assert_eq!(
            first.results.first().map(|result| result.status),
            Some(Status::Pass)
        );
        assert_eq!(runs(&marker), 1);

        let mut resumed = campaign(
            temp.path(),
            vec![segment("counted", vec![counting_step(&marker)])],
        );
        resumed.resume = true;
        let second = resumed.execute(&record, &clock())?;

        assert_eq!(
            second.results.first().map(|result| result.status),
            Some(Status::Cached)
        );
        assert_eq!(second.reused(), 1);
        assert_eq!(runs(&marker), 1, "a reused segment does not execute again");
        assert!(second.every_segment_holds());
        assert_eq!(second.state, State::Sealed);

        let journal = fs::read_to_string(record.journal_path())?;
        assert!(journal.contains("\"status\":\"cached\""), "{journal}");
        Ok(())
    }

    #[test]
    fn a_changed_revision_invalidates_cache_and_the_segment_runs_again() -> Result<()> {
        let temp = TempDir::new("resume-revision")?;
        let record = RunRecord::create(temp.path(), "gate", "2026-09-15", "repository")?;
        let marker = temp.path().join("runs.txt");

        let _ = campaign(
            temp.path(),
            vec![segment("counted", vec![counting_step(&marker)])],
        )
        .execute(&record, &clock())?;

        let mut resumed = campaign(
            temp.path(),
            vec![segment("counted", vec![counting_step(&marker)])],
        );
        resumed.resume = true;
        resumed.subject_revision = OTHER_REVISION.to_owned();
        resumed.identity = identity(OTHER_REVISION, "rustc 1.98.0");

        let report = resumed.execute(&record, &clock())?;

        assert_eq!(
            report.results.first().map(|result| result.status),
            Some(Status::Pass)
        );
        assert_eq!(
            runs(&marker),
            2,
            "a new revision is not proven by old evidence"
        );
        Ok(())
    }

    #[test]
    fn a_changed_toolchain_invalidates_cache_with_the_revision_unchanged() -> Result<()> {
        let temp = TempDir::new("resume-toolchain")?;
        let record = RunRecord::create(temp.path(), "gate", "2026-09-15", "repository")?;
        let marker = temp.path().join("runs.txt");

        let _ = campaign(
            temp.path(),
            vec![segment("counted", vec![counting_step(&marker)])],
        )
        .execute(&record, &clock())?;

        let mut resumed = campaign(
            temp.path(),
            vec![segment("counted", vec![counting_step(&marker)])],
        );
        resumed.resume = true;
        resumed.identity = identity(REVISION, "rustc 1.99.0");

        let report = resumed.execute(&record, &clock())?;

        assert_eq!(
            report.results.first().map(|result| result.status),
            Some(Status::Pass)
        );
        assert_eq!(
            runs(&marker),
            2,
            "evidence identity is more than the revision"
        );
        Ok(())
    }

    #[test]
    fn a_failed_or_timed_out_result_is_never_reused() -> Result<()> {
        let temp = TempDir::new("resume-failed")?;
        let record = RunRecord::create(temp.path(), "gate", "2026-09-15", "repository")?;

        let failing = campaign(
            temp.path(),
            vec![segment(
                "counted",
                vec![Step::new("/bin/sh", &["-c", "exit 1"])],
            )],
        )
        .execute(&record, &clock())?;
        assert_eq!(failing.state, State::Failed);

        let mut resumed = campaign(
            temp.path(),
            vec![segment(
                "counted",
                vec![Step::new("/bin/sh", &["-c", "true"])],
            )],
        );
        resumed.resume = true;
        let report = resumed.execute(&record, &clock())?;

        assert_eq!(
            report.results.first().map(|result| result.status),
            Some(Status::Pass),
            "a failed result runs again instead of being reused"
        );
        Ok(())
    }

    #[test]
    fn a_working_tree_that_carries_changes_refuses_to_seal() {
        let (state, reasons) = seal_state(
            &ids(&["one"]),
            &finals(&[("one", Status::Pass, "identity")]),
            "identity",
            &TreeState::Modified(vec![" M src/lib.rs".to_owned()]),
        );

        assert_eq!(state, State::Partial);
        assert!(reasons.iter().any(|reason| reason.contains("working tree")));
    }

    #[test]
    fn a_clean_working_tree_with_every_segment_holding_seals() {
        let (state, reasons) = seal_state(
            &ids(&["one", "two"]),
            &finals(&[
                ("one", Status::Pass, "identity"),
                ("two", Status::Cached, "identity"),
            ]),
            "identity",
            &TreeState::Clean,
        );

        assert_eq!(state, State::Sealed);
        assert!(reasons.is_empty());
    }

    #[test]
    fn a_missing_required_segment_refuses_to_seal() {
        let (state, reasons) = seal_state(
            &ids(&["one", "two"]),
            &finals(&[("one", Status::Pass, "identity")]),
            "identity",
            &TreeState::Clean,
        );

        assert_eq!(state, State::Partial);
        assert!(reasons.iter().any(|reason| reason.contains("two")));
    }

    #[test]
    fn a_failed_segment_refuses_to_seal() {
        let (state, reasons) = seal_state(
            &ids(&["one"]),
            &finals(&[("one", Status::Fail, "identity")]),
            "identity",
            &TreeState::Clean,
        );

        assert_eq!(state, State::Failed);
        assert!(reasons.iter().any(|reason| reason.contains("fail")));
    }

    #[test]
    fn a_timed_out_segment_refuses_to_seal() {
        let (state, _) = seal_state(
            &ids(&["one"]),
            &finals(&[("one", Status::Timeout, "identity")]),
            "identity",
            &TreeState::Clean,
        );

        assert_eq!(state, State::Failed);
    }

    #[test]
    fn a_skipped_segment_refuses_to_seal() {
        let (state, _) = seal_state(
            &ids(&["one"]),
            &finals(&[("one", Status::Skipped, "identity")]),
            "identity",
            &TreeState::Clean,
        );

        assert_eq!(state, State::Failed);
    }

    #[test]
    fn results_under_more_than_one_evidence_identity_refuse_to_seal() {
        let (state, reasons) = seal_state(
            &ids(&["one", "two"]),
            &finals(&[
                ("one", Status::Pass, "identity"),
                ("two", Status::Cached, "another identity"),
            ]),
            "identity",
            &TreeState::Clean,
        );

        assert_eq!(state, State::Partial);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("different evidence identity"))
        );
    }
}

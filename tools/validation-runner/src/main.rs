//! Records RP-1 Rust validation campaigns.
//!
//! The runner executes a campaign segment by segment, writes its manifest
//! before anything runs, and appends one journal entry as each attempt ends.
//! An execution with no durable record is not evidence, so every recorded
//! campaign leaves a record even when it is interrupted.
//!
//! This tool is repository infrastructure. It is not part of the published
//! crate and never enters its dependency graph.

mod campaign;
mod error;
mod identity;
mod json;
mod process;
mod record;
mod repo;
mod segment;
#[cfg(test)]
mod testing;
mod time;

use std::env;
use std::path::Path;
use std::process::ExitCode;

use campaign::{Campaign, SEGMENT_BUDGET, State, Tier, TreeState};
use error::{Result, failed};
use identity::EvidenceIdentity;
use json::Object;
use record::RunRecord;
use segment::Status;
use time::Utc;

const DEFAULT_TOPIC: &str = "repository";

const USAGE: &str = "usage: validation-runner run --tier <dev|gate> [--topic <topic>] [--resume]";

fn main() -> ExitCode {
    match execute() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("validation-runner: {error}");
            ExitCode::FAILURE
        }
    }
}

struct Arguments {
    tier: Tier,
    topic: String,
    resume: bool,
}

fn execute() -> Result<ExitCode> {
    let arguments = parse(env::args().skip(1).collect())?;

    let working_dir = env::current_dir()?;
    let repository_root = repo::root(&working_dir)?;
    let subject_revision = repo::subject_revision(&repository_root)?;

    let segments = campaign::required(arguments.tier);
    let definition = campaign::definition_digest(&segments);
    let identity = EvidenceIdentity::resolve(&repository_root, &subject_revision, &definition)?;

    let now = Utc::now()?;
    let records_root = repository_root.join(record::RECORDS_DIRECTORY);
    let (record, resuming) = select_record(&arguments, &records_root, &identity.digest(), now)?;

    let tree_state = match repo::working_tree_changes(&repository_root)?.as_slice() {
        [] => TreeState::Clean,
        changes => TreeState::Modified(changes.to_vec()),
    };

    let campaign = Campaign {
        tier: arguments.tier,
        topic: arguments.topic,
        subject_revision,
        identity,
        segments,
        budget: SEGMENT_BUDGET,
        working_dir: repository_root.clone(),
        environment: environment(&repository_root)?,
        created: now.timestamp()?,
        resume: resuming,
        tree_state,
    };

    let started = std::time::Instant::now();
    let report = campaign.execute(&record, &|| Utc::now()?.timestamp())?;
    let elapsed = started.elapsed();

    print_report(&campaign, &record, &report, elapsed, &repository_root);

    Ok(if closes(arguments.tier, &report) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Reports whether the campaign satisfied what its tier asks of it.
///
/// A gate campaign closes only when it seals. A development campaign closes
/// when every segment holds, because a working tree under change is the
/// ordinary state during development.
fn closes(tier: Tier, report: &campaign::Report) -> bool {
    match tier {
        Tier::Gate => report.state == State::Sealed,
        Tier::Dev => report.every_segment_holds(),
    }
}

/// Chooses the record this run writes into.
///
/// Resume continues the most recent record for the tier. A record that
/// already holds results under another evidence identity is not continued,
/// because a record that mixed two identities could not state which one it
/// proves.
fn select_record(
    arguments: &Arguments,
    records_root: &Path,
    identity: &str,
    now: Utc,
) -> Result<(RunRecord, bool)> {
    let create = || {
        RunRecord::create(
            records_root,
            arguments.tier.as_str(),
            &now.date()?,
            &arguments.topic,
        )
    };

    if !arguments.resume {
        return Ok((create()?, false));
    }

    let Some(existing) = RunRecord::latest(records_root, arguments.tier.as_str())? else {
        println!("No campaign to resume. Recording a new one.");
        return Ok((create()?, false));
    };

    match existing.recorded_identity()? {
        Some(recorded) if recorded != identity => {
            println!(
                "The most recent campaign holds results under another evidence identity. \
                 Recording a new one."
            );
            Ok((create()?, false))
        }
        _ => Ok((existing, true)),
    }
}

fn parse(arguments: Vec<String>) -> Result<Arguments> {
    let mut tier = None;
    let mut topic = DEFAULT_TOPIC.to_owned();
    let mut resume = false;
    let mut rest = arguments.into_iter();

    match rest.next().as_deref() {
        Some("run") => {}
        Some(other) => return failed(format!("`{other}` is not a command. {USAGE}")),
        None => return failed(USAGE),
    }

    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--tier" => match rest.next() {
                Some(value) => tier = Some(Tier::parse(&value)?),
                None => return failed(format!("`--tier` needs a value. {USAGE}")),
            },
            "--topic" => match rest.next() {
                Some(value) => topic = value,
                None => return failed(format!("`--topic` needs a value. {USAGE}")),
            },
            "--resume" => resume = true,
            other => return failed(format!("`{other}` is not an option. {USAGE}")),
        }
    }

    let Some(tier) = tier else {
        return failed(format!("`--tier` is required. {USAGE}"));
    };
    Ok(Arguments {
        tier,
        topic,
        resume,
    })
}

fn environment(repository_root: &Path) -> Result<Object> {
    let mut environment = Object::new();
    environment.string("os", env::consts::OS);
    environment.string("arch", env::consts::ARCH);
    environment.string(
        "rustc",
        &process::capture("rustc", &["--version"], repository_root)?,
    );
    environment.string(
        "cargo",
        &process::capture("cargo", &["--version"], repository_root)?,
    );
    Ok(environment)
}

fn print_report(
    campaign: &Campaign,
    record: &RunRecord,
    report: &campaign::Report,
    elapsed: std::time::Duration,
    repository_root: &Path,
) {
    let passed = report
        .results
        .iter()
        .filter(|result| result.status.holds())
        .count();
    let blockers: Vec<String> = report
        .results
        .iter()
        .filter(|result| !result.status.holds())
        .map(|result| format!("{} ({})", result.id, result.status.as_str()))
        .collect();

    println!("Campaign: {}", record.identifier());
    println!("Type: {}", campaign::CAMPAIGN_TYPE);
    println!("Tier: {}", campaign.tier);
    println!("Revision: {}", campaign.subject_revision);
    println!(
        "Segments: {passed}/{} valid, {} reused",
        report.results.len(),
        report.reused()
    );
    println!("Duration: {:.1}s", elapsed.as_secs_f64());
    println!("Status: {}", report.state.as_str());
    println!(
        "Blockers: {}",
        if blockers.is_empty() {
            "none".to_owned()
        } else {
            blockers.join(", ")
        }
    );
    println!("Record: {}", display_record(record, repository_root));

    for reason in &report.reasons {
        println!("  does not seal: {reason}");
    }

    for result in &report.results {
        if result.status == Status::Skipped
            && let Some(note) = &result.note
        {
            println!("  {}: {note}", result.id);
        }
    }
}

fn display_record(record: &RunRecord, repository_root: &Path) -> String {
    record
        .root()
        .strip_prefix(repository_root)
        .unwrap_or_else(|_| record.root())
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{Arguments, parse};
    use crate::campaign::Tier;
    use crate::error::Result;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_a_tier_and_the_default_topic() -> Result<()> {
        let parsed: Arguments = parse(arguments(&["run", "--tier", "gate"]))?;
        assert_eq!(parsed.tier, Tier::Gate);
        assert_eq!(parsed.topic, "repository");
        assert!(!parsed.resume);
        Ok(())
    }

    #[test]
    fn rejects_an_unknown_tier() {
        assert!(parse(arguments(&["run", "--tier", "publication"])).is_err());
    }

    #[test]
    fn requires_a_tier() {
        assert!(parse(arguments(&["run"])).is_err());
    }

    #[test]
    fn accepts_a_resume_request() -> Result<()> {
        let parsed = parse(arguments(&["run", "--tier", "gate", "--resume"]))?;
        assert!(parsed.resume);
        Ok(())
    }
}

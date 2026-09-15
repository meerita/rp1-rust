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

use campaign::{Campaign, SEGMENT_BUDGET, Tier};
use error::{Result, failed};
use identity::EvidenceIdentity;
use json::Object;
use record::RunRecord;
use segment::Status;
use time::Utc;

const DEFAULT_TOPIC: &str = "repository";

const USAGE: &str = "usage: validation-runner run --tier <dev|gate> [--topic <topic>]";

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
    let record = RunRecord::create(
        &repository_root.join(record::RECORDS_DIRECTORY),
        arguments.tier.as_str(),
        &now.date()?,
        &arguments.topic,
    )?;

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
    };

    let started = std::time::Instant::now();
    let report = campaign.execute(&record, &|| Utc::now()?.timestamp())?;
    let elapsed = started.elapsed();

    print_report(&campaign, &record, &report, elapsed, &repository_root);

    Ok(if report.every_segment_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn parse(arguments: Vec<String>) -> Result<Arguments> {
    let mut tier = None;
    let mut topic = DEFAULT_TOPIC.to_owned();
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
            "--resume" => {
                return failed(
                    "this runner cannot resume a campaign yet. \
                     Run the campaign again to record a new one.",
                );
            }
            other => return failed(format!("`{other}` is not an option. {USAGE}")),
        }
    }

    let Some(tier) = tier else {
        return failed(format!("`--tier` is required. {USAGE}"));
    };
    Ok(Arguments { tier, topic })
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
        .filter(|result| result.status.is_pass())
        .count();
    let blockers: Vec<String> = report
        .results
        .iter()
        .filter(|result| !result.status.is_pass())
        .map(|result| format!("{} ({})", result.id, result.status.as_str()))
        .collect();

    println!("Campaign: {}", record.identifier());
    println!("Type: {}", campaign::CAMPAIGN_TYPE);
    println!("Tier: {}", campaign.tier);
    println!("Revision: {}", campaign.subject_revision);
    println!(
        "Segments: {passed}/{} valid, 0 reused",
        report.results.len()
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
    fn refuses_resume_until_it_is_implemented() {
        assert!(parse(arguments(&["run", "--tier", "gate", "--resume"])).is_err());
    }
}

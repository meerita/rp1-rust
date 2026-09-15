//! Owns segment execution and the wall-clock budget.
//!
//! A segment is the unit of execution, failure, and evidence. This module
//! runs one attempt and preserves its raw output. It does not own campaign
//! composition, journal entries, or the record layout.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::Result;

/// How often a running attempt is checked against its budget.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The outcome of one segment attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Timeout,
    Skipped,
    Cached,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Timeout => "timeout",
            Self::Skipped => "skipped",
            Self::Cached => "cached",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pass" => Some(Self::Pass),
            "fail" => Some(Self::Fail),
            "timeout" => Some(Self::Timeout),
            "skipped" => Some(Self::Skipped),
            "cached" => Some(Self::Cached),
            _ => None,
        }
    }

    /// Reports whether the status is evidence that the segment holds.
    ///
    /// A reused result counts. A skipped segment does not, because nothing
    /// ran and nothing was proven.
    pub const fn holds(self) -> bool {
        matches!(self, Self::Pass | Self::Cached)
    }

    /// Reports whether this attempt executed rather than reused evidence.
    pub const fn executed(self) -> bool {
        !matches!(self, Self::Cached)
    }
}

/// One command inside a segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    program: String,
    args: Vec<String>,
}

impl Step {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            args: args.iter().map(|argument| (*argument).to_owned()).collect(),
        }
    }

    /// Renders the command as a reader can retype it.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }

    fn command(&self, working_dir: &Path) -> Command {
        let mut command = Command::new(&self.program);
        let _ = command.args(&self.args).current_dir(working_dir);
        command
    }
}

/// What one attempt produced.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub status: Status,
    pub duration: Duration,
    pub note: Option<String>,
}

/// Runs every step of one segment attempt under one shared budget.
///
/// Steps run in order and the attempt stops at the first step that does not
/// report success. Raw output from every step lands in `evidence`, including
/// the output of a step that failed or was stopped at the budget.
pub fn execute(
    steps: &[Step],
    budget: Duration,
    working_dir: &Path,
    evidence: &Path,
) -> Result<Outcome> {
    let mut log = File::create(evidence)?;
    let started = Instant::now();

    for step in steps {
        writeln!(log, "$ {}", step.display())?;
        log.flush()?;

        let remaining = budget.checked_sub(started.elapsed());
        let Some(remaining) = remaining else {
            return timed_out(&mut log, step, started.elapsed());
        };

        let outcome = run_step(step, remaining, working_dir, &log)?;
        match outcome {
            StepResult::Passed => {}
            StepResult::Failed(note) => {
                writeln!(log, "[{note}]")?;
                log.flush()?;
                return Ok(Outcome {
                    status: Status::Fail,
                    duration: started.elapsed(),
                    note: Some(note),
                });
            }
            StepResult::TimedOut => return timed_out(&mut log, step, started.elapsed()),
        }
    }

    Ok(Outcome {
        status: Status::Pass,
        duration: started.elapsed(),
        note: None,
    })
}

/// Reports whether a probe command starts and reports success.
pub fn probe(step: &Step, working_dir: &Path) -> bool {
    step.command(working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

enum StepResult {
    Passed,
    Failed(String),
    TimedOut,
}

fn run_step(
    step: &Step,
    remaining: Duration,
    working_dir: &Path,
    log: &File,
) -> Result<StepResult> {
    let stdout = log.try_clone()?;
    let stderr = log.try_clone()?;

    let spawned = step
        .command(working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn();

    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return Ok(StepResult::Failed(format!(
                "`{}` could not start: {error}",
                step.display()
            )));
        }
    };

    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(if status.success() {
                StepResult::Passed
            } else {
                StepResult::Failed(format!(
                    "`{}` reported {}",
                    step.display(),
                    describe_exit(status.code())
                ))
            });
        }

        if started.elapsed() >= remaining {
            child.kill()?;
            let _ = child.wait()?;
            return Ok(StepResult::TimedOut);
        }

        thread::sleep(POLL_INTERVAL);
    }
}

fn timed_out(log: &mut File, step: &Step, duration: Duration) -> Result<Outcome> {
    let note = format!("`{}` exceeded the segment budget", step.display());
    writeln!(log, "[{note}]")?;
    log.flush()?;
    Ok(Outcome {
        status: Status::Timeout,
        duration,
        note: Some(note),
    })
}

fn describe_exit(code: Option<i32>) -> String {
    code.map_or_else(
        || "termination by signal".to_owned(),
        |code| format!("exit status {code}"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use super::{Status, Step, execute};
    use crate::error::Result;
    use crate::testing::TempDir;

    #[test]
    fn a_passing_segment_records_every_step() -> Result<()> {
        let temp = TempDir::new("segment-pass")?;
        let evidence = temp.path().join("evidence.txt");
        let steps = [
            Step::new("/bin/sh", &["-c", "echo first"]),
            Step::new("/bin/sh", &["-c", "echo second"]),
        ];

        let outcome = execute(&steps, Duration::from_secs(30), temp.path(), &evidence)?;
        let raw = fs::read_to_string(&evidence)?;

        assert_eq!(outcome.status, Status::Pass);
        assert!(raw.contains("first"), "{raw}");
        assert!(raw.contains("second"), "{raw}");
        Ok(())
    }

    #[test]
    fn a_failing_step_stops_the_segment_and_keeps_its_output() -> Result<()> {
        let temp = TempDir::new("segment-fail")?;
        let evidence = temp.path().join("evidence.txt");
        let steps = [
            Step::new("/bin/sh", &["-c", "echo before; exit 3"]),
            Step::new("/bin/sh", &["-c", "echo unreachable"]),
        ];

        let outcome = execute(&steps, Duration::from_secs(30), temp.path(), &evidence)?;
        let raw = fs::read_to_string(&evidence)?;

        assert_eq!(outcome.status, Status::Fail);
        assert!(raw.contains("before"), "{raw}");
        assert!(!raw.contains("unreachable"), "{raw}");
        Ok(())
    }

    #[test]
    fn a_segment_over_its_budget_records_timeout_rather_than_failure() -> Result<()> {
        let temp = TempDir::new("segment-timeout")?;
        let evidence = temp.path().join("evidence.txt");
        let steps = [Step::new("/bin/sh", &["-c", "sleep 30"])];

        let outcome = execute(&steps, Duration::from_millis(200), temp.path(), &evidence)?;

        assert_eq!(outcome.status, Status::Timeout);
        assert_ne!(outcome.status, Status::Fail);
        assert!(outcome.duration < Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn a_missing_program_fails_the_segment_with_the_reason() -> Result<()> {
        let temp = TempDir::new("segment-missing")?;
        let evidence = temp.path().join("evidence.txt");
        let steps = [Step::new("rp1-no-such-program", &[])];

        let outcome = execute(&steps, Duration::from_secs(30), temp.path(), &evidence)?;

        assert_eq!(outcome.status, Status::Fail);
        assert!(
            outcome
                .note
                .is_some_and(|note| note.contains("could not start")),
            "a failing segment records why it failed"
        );
        Ok(())
    }
}

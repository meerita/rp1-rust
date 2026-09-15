//! Owns the runner error type.
//!
//! This module does not own campaign definitions, execution, or records.

use std::fmt;
use std::io;

/// A failure that stops the runner.
#[derive(Debug)]
pub enum Error {
    /// A filesystem or process operation failed.
    Io(io::Error),
    /// The runner could not establish a fact that a record requires.
    Runner(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Runner(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Runner(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Builds a runner failure from a message.
pub fn failed<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Runner(message.into()))
}

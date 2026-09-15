//! Owns UTC timestamps for run records.
//!
//! Record identifiers and journal entries need a date and a timestamp that
//! read the same on every host. This module does not own record layout.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, failed};

const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_MINUTE: u64 = 60;

/// Days from 0000-03-01 to 1970-01-01, the shift the civil-date algorithm uses.
const EPOCH_SHIFT_DAYS: i64 = 719_468;

/// Days in one 400 year era.
const DAYS_PER_ERA: i64 = 146_097;

/// A point in time with second resolution, in UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utc {
    seconds: u64,
}

impl Utc {
    /// Reads the current time.
    ///
    /// Fails when the host clock is set before the Unix epoch, because no
    /// record identifier can be derived from it.
    pub fn now() -> Result<Self> {
        let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return failed("the host clock reports a time before 1970-01-01");
        };
        Ok(Self {
            seconds: elapsed.as_secs(),
        })
    }

    #[cfg(test)]
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self { seconds }
    }

    /// Formats the calendar date as `YYYY-MM-DD`.
    pub fn date(self) -> Result<String> {
        let (year, month, day) = self.civil()?;
        Ok(format!("{year:04}-{month:02}-{day:02}"))
    }

    /// Formats the instant as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn timestamp(self) -> Result<String> {
        let (year, month, day) = self.civil()?;
        let Some(seconds_of_day) = self.seconds.checked_rem(SECONDS_PER_DAY) else {
            return failed("a timestamp could not be derived from the host clock");
        };
        let (hour, minute, second) = split_day(seconds_of_day)?;
        Ok(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    }

    fn civil(self) -> Result<(i64, u32, u32)> {
        let Some(days) = self.seconds.checked_div(SECONDS_PER_DAY) else {
            return failed("a calendar date could not be derived from the host clock");
        };
        let Ok(days) = i64::try_from(days) else {
            return failed("the host clock reports a time the runner cannot represent");
        };
        let Some(civil) = civil_from_days(days) else {
            return failed("the host clock reports a date the runner cannot represent");
        };
        Ok(civil)
    }
}

fn split_day(seconds_of_day: u64) -> Result<(u64, u64, u64)> {
    let parts = (|| {
        let hour = seconds_of_day.checked_div(SECONDS_PER_HOUR)?;
        let remainder = seconds_of_day.checked_rem(SECONDS_PER_HOUR)?;
        let minute = remainder.checked_div(SECONDS_PER_MINUTE)?;
        let second = remainder.checked_rem(SECONDS_PER_MINUTE)?;
        Some((hour, minute, second))
    })();
    let Some(parts) = parts else {
        return failed("a time of day could not be derived from the host clock");
    };
    Ok(parts)
}

/// Converts a day count since 1970-01-01 into a proleptic Gregorian date.
///
/// Returns `None` when an intermediate value cannot be represented, which no
/// clock value in the supported range produces.
fn civil_from_days(days: i64) -> Option<(i64, u32, u32)> {
    let shifted = days.checked_add(EPOCH_SHIFT_DAYS)?;
    let era_base = if shifted >= 0 {
        shifted
    } else {
        shifted.checked_sub(DAYS_PER_ERA.checked_sub(1)?)?
    };
    let era = era_base.checked_div(DAYS_PER_ERA)?;
    let day_of_era = shifted.checked_sub(era.checked_mul(DAYS_PER_ERA)?)?;

    let year_of_era = day_of_era
        .checked_sub(day_of_era.checked_div(1_460)?)?
        .checked_add(day_of_era.checked_div(36_524)?)?
        .checked_sub(day_of_era.checked_div(146_096)?)?
        .checked_div(365)?;

    let shifted_year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let leap_days = year_of_era
        .checked_div(4)?
        .checked_sub(year_of_era.checked_div(100)?)?;
    let day_of_year =
        day_of_era.checked_sub(year_of_era.checked_mul(365)?.checked_add(leap_days)?)?;

    let month_position = day_of_year
        .checked_mul(5)?
        .checked_add(2)?
        .checked_div(153)?;
    let day = day_of_year
        .checked_sub(
            month_position
                .checked_mul(153)?
                .checked_add(2)?
                .checked_div(5)?,
        )?
        .checked_add(1)?;
    let month = if month_position < 10 {
        month_position.checked_add(3)?
    } else {
        month_position.checked_sub(9)?
    };
    let year = if month <= 2 {
        shifted_year.checked_add(1)?
    } else {
        shifted_year
    };

    Some((year, u32::try_from(month).ok()?, u32::try_from(day).ok()?))
}

#[cfg(test)]
mod tests {
    use super::Utc;
    use crate::error::Result;

    #[test]
    fn formats_the_unix_epoch() -> Result<()> {
        let instant = Utc::from_unix_seconds(0);
        assert_eq!(instant.date()?, "1970-01-01");
        assert_eq!(instant.timestamp()?, "1970-01-01T00:00:00Z");
        Ok(())
    }

    #[test]
    fn formats_a_leap_day() -> Result<()> {
        // 2024-02-29T12:34:56Z
        let instant = Utc::from_unix_seconds(1_709_210_096);
        assert_eq!(instant.date()?, "2024-02-29");
        assert_eq!(instant.timestamp()?, "2024-02-29T12:34:56Z");
        Ok(())
    }

    #[test]
    fn formats_a_date_after_a_century_boundary() -> Result<()> {
        // 2026-09-15T00:00:00Z
        let instant = Utc::from_unix_seconds(1_789_430_400);
        assert_eq!(instant.date()?, "2026-09-15");
        Ok(())
    }
}

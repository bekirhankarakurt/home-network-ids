//! Packet timestamps and RFC 3339 formatting without a date-time dependency.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Serialize, Serializer};

/// Microseconds since the Unix epoch, as carried by capture files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Builds a timestamp from whole seconds and microseconds.
    pub fn from_secs_micros(secs: u64, micros: u64) -> Self {
        Self(secs.saturating_mul(1_000_000).saturating_add(micros))
    }

    /// Current wall-clock time.
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self(u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
    }

    /// Whole seconds since the epoch.
    pub fn secs(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Time elapsed since `earlier`, saturating at zero.
    pub fn since(self, earlier: Self) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }

    /// This timestamp moved back by `d`, saturating at the epoch.
    #[must_use]
    pub fn minus(self, d: Duration) -> Self {
        Self(
            self.0
                .saturating_sub(u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
        )
    }
}

/// Converts days since 1970-01-01 to a proleptic Gregorian (year, month, day).
///
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

impl fmt::Display for Timestamp {
    /// Formats as `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.secs();
        let micros = self.0 % 1_000_000;
        let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
            rem / 3600,
            (rem / 60) % 60,
            rem % 60
        )
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc3339() {
        assert_eq!(Timestamp(0).to_string(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            Timestamp::from_secs_micros(1_709_210_096, 42).to_string(),
            "2024-02-29T12:34:56.000042Z"
        );
        assert_eq!(
            Timestamp::from_secs_micros(951_782_400, 0).to_string(),
            "2000-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn arithmetic_saturates() {
        let t = Timestamp(5);
        assert_eq!(t.since(Timestamp(10)), Duration::ZERO);
        assert_eq!(t.minus(Duration::from_secs(1)), Timestamp(0));
    }
}

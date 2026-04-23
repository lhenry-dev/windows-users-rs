use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::user::types::InvalidUserProperty;

pub trait TryIntoTimestamp {
    fn try_into_timestamp(self) -> Result<u32, InvalidUserProperty>;
}

impl TryIntoTimestamp for DateTime<Utc> {
    fn try_into_timestamp(self) -> Result<u32, InvalidUserProperty> {
        u32::try_from(self.timestamp())
            .map_err(|_| InvalidUserProperty::Timestamp(self.timestamp()))
    }
}

pub trait TryIntoSeconds {
    fn try_into_seconds(self) -> Result<u32, InvalidUserProperty>;
}

impl TryIntoSeconds for Duration {
    fn try_into_seconds(self) -> Result<u32, InvalidUserProperty> {
        u32::try_from(self.as_secs()).map_err(|_| InvalidUserProperty::Seconds(self.as_secs()))
    }
}

pub trait TryIntoDateTime {
    fn try_into_date_time(self) -> Result<DateTime<Utc>, InvalidUserProperty>;
}

impl TryIntoDateTime for u32 {
    fn try_into_date_time(self) -> Result<DateTime<Utc>, InvalidUserProperty> {
        DateTime::<Utc>::from_timestamp(self.into(), 0)
            .ok_or_else(|| InvalidUserProperty::Timestamp(self.into()))
    }
}

pub trait IntoDuration {
    fn into_duration(self) -> Duration;
}

impl IntoDuration for u32 {
    fn into_duration(self) -> Duration {
        Duration::from_secs(self.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_try_into_timestamp_ok() {
        let dt = Utc.timestamp_opt(1_000_000, 0).unwrap();
        let ts = dt.try_into_timestamp().unwrap();

        assert_eq!(ts, 1_000_000u32);
    }

    #[test]
    fn test_try_into_seconds_ok() {
        let duration = Duration::from_secs(3600);
        let seconds = duration.try_into_seconds().unwrap();

        assert_eq!(seconds, 3600u32);
    }

    #[test]
    fn test_try_into_date_time_ok() {
        let timestamp = 1_000_000u32;
        let dt = timestamp.try_into_date_time().unwrap();

        assert_eq!(dt, Utc.timestamp_opt(1_000_000, 0).unwrap());
    }
}

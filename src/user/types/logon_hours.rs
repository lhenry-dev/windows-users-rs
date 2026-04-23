use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LogonHoursError {
    #[error("hour must be in range 0..23, got {0}")]
    InvalidHour(u8),

    #[error("invalid range: start ({start}) must be < end ({end}) and end <= 24")]
    InvalidRange { start: u8, end: u8 },
}

#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Day {
    Sunday = 0,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
}

/// Represents the logon hours for a user, allowing you to specify which hours of the week a user is allowed to log on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogonHours {
    bytes: [u8; 21],
}

impl From<*mut u8> for LogonHours {
    fn from(ptr: *mut u8) -> Self {
        if ptr.is_null() {
            Self::allow_all()
        } else {
            Self::from_ptr(ptr)
        }
    }
}

impl From<LogonHours> for Vec<u8> {
    fn from(value: LogonHours) -> Self {
        value.bytes.to_vec()
    }
}

impl LogonHours {
    /// Number of hours in a full week.
    ///
    /// The value represents the total discrete time slots tracked by
    /// the Windows logon-hours bitmap:
    /// - 7 days per week
    /// - 24 hours per day
    ///
    /// Total: `7 × 24 = 168` time units.
    pub const UNITS_PER_WEEK: u32 = 168;

    /// Size in bytes of the Windows logon-hours bitmap.
    ///
    /// The Windows API represents weekly logon permissions as a
    /// 168-bit bitmap (one bit per hour), packed into 21 bytes:
    /// `168 bits / 8 = 21 bytes`.
    ///
    /// This constant defines the exact buffer size required by
    /// `USER_INFO_1020`.
    pub const LEN: usize = 21;

    /// Creates a `LogonHours` value where all hours of the week are allowed.
    ///
    /// This initializes the internal bitmap to all bits set (`0xFF`),
    /// meaning unrestricted access across all days and hours.
    pub fn allow_all() -> Self {
        Self { bytes: [0xFF; 21] }
    }

    /// Creates a `LogonHours` value where all hours of the week are denied.
    ///
    /// This initializes the internal bitmap to all bits cleared (`0x00`),
    /// meaning no logon is permitted at any time.
    pub fn deny_all() -> Self {
        Self { bytes: [0x00; 21] }
    }

    /// Creates a `LogonHours` instance from a raw 21-byte bitmap.
    ///
    /// This constructor assumes the provided buffer is already in the
    /// Windows logon-hours format.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 21-byte array representing the weekly logon bitmap.
    pub fn new(bytes: [u8; 21]) -> Self {
        Self { bytes }
    }

    fn from_ptr(ptr: *const u8) -> Self {
        let bytes = unsafe { std::slice::from_raw_parts(ptr, Self::LEN) };
        let mut array = [0u8; Self::LEN];
        array.copy_from_slice(bytes);
        Self { bytes: array }
    }

    /// Returns the raw Windows logon-hours bitmap.
    ///
    /// The returned slice is exactly 21 bytes long and represents
    /// 168 bits of weekly access permissions.
    ///
    /// # Format
    ///
    /// Each bit corresponds to a specific `(day, hour)` pair:
    /// - 0 = denied
    /// - 1 = allowed
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn index(day: Day, hour: u8) -> usize {
        (day as usize) * 24 + (hour as usize)
    }

    /// Sets whether a specific hour is allowed or denied for logon.
    ///
    /// # Arguments
    ///
    /// * `day` - Day of the week
    /// * `hour` - Hour of the day (0–23)
    /// * `allowed` - `true` to allow logon, `false` to deny
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - `hour >= 24`
    pub fn set(&mut self, day: Day, hour: u8, allowed: bool) -> Result<(), LogonHoursError> {
        if hour >= 24 {
            return Err(LogonHoursError::InvalidHour(hour));
        }

        let i = Self::index(day, hour);
        let byte = i / 8;
        let bit = i % 8;

        if allowed {
            self.bytes[byte] |= 1 << bit;
        } else {
            self.bytes[byte] &= !(1 << bit);
        }

        Ok(())
    }

    /// Checks whether a specific hour is allowed for logon.
    ///
    /// # Arguments
    ///
    /// * `day` - Day of the week
    /// * `hour` - Hour of the day (0–23)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if logon is allowed
    /// - `Ok(false)` if denied
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - `hour >= 24`
    pub fn is_allowed(&self, day: Day, hour: u8) -> Result<bool, LogonHoursError> {
        if hour >= 24 {
            return Err(LogonHoursError::InvalidHour(hour));
        }

        let i = Self::index(day, hour);
        let byte = i / 8;
        let bit = i % 8;

        Ok((self.bytes[byte] & (1 << bit)) != 0)
    }

    /// Allows a contiguous range of hours on a given day.
    ///
    /// The range is **half-open**: `[start, end)`
    ///
    /// # Arguments
    ///
    /// * `day` - Day of the week
    /// * `start` - Starting hour (inclusive)
    /// * `end` - Ending hour (exclusive)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - `start >= end`
    /// - `end > 24`
    pub fn allow_range(&mut self, day: Day, start: u8, end: u8) -> Result<(), LogonHoursError> {
        if start >= end || end > 24 {
            return Err(LogonHoursError::InvalidRange { start, end });
        }

        for h in start..end {
            self.set(day, h, true)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_is_allowed() {
        let mut hours = LogonHours::deny_all();
        assert!(!hours.is_allowed(Day::Monday, 9).unwrap());
        hours.set(Day::Monday, 9, true).unwrap();
        assert!(hours.is_allowed(Day::Monday, 9).unwrap());
        hours.set(Day::Monday, 9, false).unwrap();
        assert!(!hours.is_allowed(Day::Monday, 9).unwrap());
    }

    #[test]
    fn test_allow_range() {
        let mut hours = LogonHours::deny_all();
        hours.allow_range(Day::Friday, 9, 12).unwrap();
        assert!(hours.is_allowed(Day::Friday, 9).unwrap());
        assert!(hours.is_allowed(Day::Friday, 10).unwrap());
        assert!(hours.is_allowed(Day::Friday, 11).unwrap());
        assert!(!hours.is_allowed(Day::Friday, 12).unwrap());
    }

    #[test]
    fn test_allow_all() {
        let hours = LogonHours::allow_all();
        let days = [
            Day::Monday,
            Day::Tuesday,
            Day::Wednesday,
            Day::Thursday,
            Day::Friday,
            Day::Saturday,
            Day::Sunday,
        ];
        for day in days {
            for hour in 0..24 {
                assert!(hours.is_allowed(day, hour).unwrap());
            }
        }
    }

    #[test]
    fn test_new_preserves_bits() {
        let mut bytes = [0u8; 21];

        let day = Day::Monday;
        let hour = 2;

        let index = (day as usize) * 24 + (hour as usize);
        let byte = index / 8;
        let bit = index % 8;

        bytes[byte] |= 1 << bit;

        let hours = LogonHours::new(bytes);

        assert!(hours.is_allowed(day, hour).unwrap());
    }
}

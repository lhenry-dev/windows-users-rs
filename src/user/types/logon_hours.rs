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
            LogonHours::allow_all()
        } else {
            LogonHours::from_ptr(ptr)
        }
    }
}

impl From<LogonHours> for Vec<u8> {
    fn from(value: LogonHours) -> Vec<u8> {
        value.bytes.to_vec()
    }
}

impl LogonHours {
    /// Total number of hours in a week (7 days * 24 hours).
    pub const UNITS_PER_WEEK: u32 = 168;

    /// Number of bytes required to represent logon hours (7 days * 24 hours = 168 bits = 21 bytes).
    pub const LEN: usize = 21;

    /// Creates a LogonHours with all hours allowed.
    pub fn allow_all() -> Self {
        Self { bytes: [0xFF; 21] }
    }

    /// Creates a LogonHours with all hours denied.
    pub fn deny_all() -> Self {
        Self { bytes: [0x00; 21] }
    }

    /// Creates a LogonHours from a raw 21-byte array.
    pub fn new(bytes: [u8; 21]) -> Self {
        Self { bytes }
    }

    /// Creates a LogonHours from a pointer to a 21-byte array.
    fn from_ptr(ptr: *const u8) -> Self {
        let bytes = unsafe { std::slice::from_raw_parts(ptr, Self::LEN) };
        let mut array = [0u8; Self::LEN];
        array.copy_from_slice(bytes);
        Self { bytes: array }
    }

    #[inline]
    fn index(day: Day, hour: u8) -> usize {
        (day as usize) * 24 + (hour as usize)
    }

    /// Sets whether a specific hour on a specific day is allowed for logon.
    pub fn set(&mut self, day: Day, hour: u8, allowed: bool) {
        assert!(hour < 24, "hour must be 0..23");

        let i = Self::index(day, hour);
        let byte = i / 8;
        let bit = i % 8;

        if allowed {
            self.bytes[byte] |= 1 << bit;
        } else {
            self.bytes[byte] &= !(1 << bit);
        }
    }

    /// Checks if a specific hour on a specific day is allowed for logon.
    pub fn is_allowed(&self, day: Day, hour: u8) -> bool {
        assert!(hour < 24, "hour must be 0..23");

        let i = Self::index(day, hour);
        let byte = i / 8;
        let bit = i % 8;

        (self.bytes[byte] & (1 << bit)) != 0
    }

    /// Allows a range of hours on a specific day for logon.
    pub fn allow_range(&mut self, day: Day, start: u8, end: u8) {
        assert!(start < end && end <= 24, "Invalid hour range");
        for h in start..end {
            self.set(day, h, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_is_allowed() {
        let mut hours = LogonHours::deny_all();
        assert!(!hours.is_allowed(Day::Monday, 9));
        hours.set(Day::Monday, 9, true);
        assert!(hours.is_allowed(Day::Monday, 9));
        hours.set(Day::Monday, 9, false);
        assert!(!hours.is_allowed(Day::Monday, 9));
    }

    #[test]
    fn test_allow_range() {
        let mut hours = LogonHours::deny_all();
        hours.allow_range(Day::Friday, 9, 12);
        assert!(hours.is_allowed(Day::Friday, 9));
        assert!(hours.is_allowed(Day::Friday, 10));
        assert!(hours.is_allowed(Day::Friday, 11));
        assert!(!hours.is_allowed(Day::Friday, 12));
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
                assert!(hours.is_allowed(day, hour));
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

        assert!(hours.is_allowed(day, hour));
    }
}

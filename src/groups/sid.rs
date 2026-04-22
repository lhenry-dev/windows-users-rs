use crate::{
    error::WindowsUsersError,
    utils::{lookup_account_sid, str_to_psid},
};

pub mod well_known_sid;

/// A Windows Security Identifier (SID).
///
/// This is a lightweight wrapper around a well-known SID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sid {
    sid: &'static str,
}

impl Sid {
    /// Returns the raw SID string.
    pub const fn as_str(&self) -> &'static str {
        self.sid
    }

    /// Resolves the SID to a Windows account/group name.
    pub fn name(&self) -> Result<String, WindowsUsersError> {
        lookup_account_sid(None, str_to_psid(self.sid)?.as_psid()).map(|(name, _, _)| name)
    }
}

#[cfg(test)]
mod tests {
    use crate::well_known_sid::{ADMINISTRATORS, GUESTS, USERS};

    #[test]
    fn test_sid_as_str() {
        assert_eq!(ADMINISTRATORS.as_str(), "S-1-5-32-544");
        assert_eq!(USERS.as_str(), "S-1-5-32-545");
        assert_eq!(GUESTS.as_str(), "S-1-5-32-546");
    }
}

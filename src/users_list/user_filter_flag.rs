use bitflags::bitflags;
use windows::Win32::NetworkManagement::NetManagement::{
    FILTER_INTERDOMAIN_TRUST_ACCOUNT, FILTER_NORMAL_ACCOUNT, FILTER_SERVER_TRUST_ACCOUNT,
    FILTER_TEMP_DUPLICATE_ACCOUNT, FILTER_WORKSTATION_TRUST_ACCOUNT, NET_USER_ENUM_FILTER_FLAGS,
};

bitflags! {
    /// Flags used for NetUserEnum `filter` parameter
    ///
    /// Specifies which types of user accounts to include in enumeration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UserFilterFlags: u32 {
        /// Temporary duplicate account (local representation of a domain account)
        const TEMP_DUPLICATE_ACCOUNT = FILTER_TEMP_DUPLICATE_ACCOUNT.0;
        /// Normal user account
        const NORMAL_ACCOUNT = FILTER_NORMAL_ACCOUNT.0;
        /// Interdomain trust account
        const INTERDOMAIN_TRUST_ACCOUNT = FILTER_INTERDOMAIN_TRUST_ACCOUNT.0;
        /// Workstation or member server trust account
        const WORKSTATION_TRUST_ACCOUNT = FILTER_WORKSTATION_TRUST_ACCOUNT.0;
        /// Backup domain controller / server trust account
        const SERVER_TRUST_ACCOUNT = FILTER_SERVER_TRUST_ACCOUNT.0;
    }
}

impl From<UserFilterFlags> for NET_USER_ENUM_FILTER_FLAGS {
    fn from(flags: UserFilterFlags) -> Self {
        NET_USER_ENUM_FILTER_FLAGS(flags.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::NetManagement::{
        FILTER_NORMAL_ACCOUNT, FILTER_TEMP_DUPLICATE_ACCOUNT,
    };

    #[test]
    fn test_single_flag_normal_account() {
        let value = FILTER_NORMAL_ACCOUNT.0;

        let flags = UserFilterFlags::from_bits(value).unwrap();

        assert!(flags.contains(UserFilterFlags::NORMAL_ACCOUNT));
        assert_eq!(flags.bits(), value);
    }

    #[test]
    fn test_multiple_flags() {
        let value = FILTER_NORMAL_ACCOUNT.0 | FILTER_TEMP_DUPLICATE_ACCOUNT.0;

        let flags = UserFilterFlags::from_bits(value).unwrap();

        assert!(flags.contains(UserFilterFlags::NORMAL_ACCOUNT));
        assert!(flags.contains(UserFilterFlags::TEMP_DUPLICATE_ACCOUNT));
    }

    #[test]
    fn test_round_trip_conversion() {
        let flags = UserFilterFlags::NORMAL_ACCOUNT | UserFilterFlags::SERVER_TRUST_ACCOUNT;

        let raw: NET_USER_ENUM_FILTER_FLAGS = flags.into();
        let back = UserFilterFlags::from_bits(raw.0).unwrap();

        assert_eq!(flags, back);
    }

    #[test]
    fn test_invalid_bits_return_none() {
        let invalid = 0xFFFF_FFFF;

        let result = UserFilterFlags::from_bits(invalid);

        assert!(result.is_none());
    }

    #[test]
    fn test_from_bits_truncate() {
        let invalid = 0xFFFF_FFFF;

        let flags = UserFilterFlags::from_bits_truncate(invalid);

        assert!(flags.contains(UserFilterFlags::NORMAL_ACCOUNT) || flags.is_empty());
    }
}

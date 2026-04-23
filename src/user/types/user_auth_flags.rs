use bitflags::bitflags;
use windows::Win32::NetworkManagement::NetManagement::{
    AF_OP, AF_OP_ACCOUNTS, AF_OP_COMM, AF_OP_PRINT, AF_OP_SERVER,
};

use crate::user::types::InvalidUserProperty;

bitflags! {
    /// Operator privileges flags from `usri3_auth_flags`
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UserAuthFlags: u32 {
        /// No special authentication flags
        const OP_PRINT = AF_OP_PRINT.0;
        /// Operator for communications flag
        const OP_COMM = AF_OP_COMM.0;
        /// Operator for server flag
        const OP_SERVER = AF_OP_SERVER.0;
        /// Operator for accounts flag
        const OP_ACCOUNTS = AF_OP_ACCOUNTS.0;
    }
}

impl TryFrom<AF_OP> for UserAuthFlags {
    type Error = InvalidUserProperty;

    fn try_from(value: AF_OP) -> Result<Self, Self::Error> {
        Self::from_bits(value.0).ok_or(InvalidUserProperty::AfOp(value.0))
    }
}

impl From<UserAuthFlags> for AF_OP {
    fn from(flags: UserAuthFlags) -> Self {
        Self(flags.bits())
    }
}

pub trait ToUserAuthFlags {
    fn to_auth_flags(self) -> Option<UserAuthFlags>;
}

impl ToUserAuthFlags for AF_OP {
    fn to_auth_flags(self) -> Option<UserAuthFlags> {
        UserAuthFlags::try_from(self).ok().filter(|f| !f.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::NetManagement::{
        AF_OP, AF_OP_ACCOUNTS, AF_OP_COMM, AF_OP_PRINT, AF_OP_SERVER,
    };

    #[test]
    fn test_try_from_single_flag_print() {
        let op = AF_OP(AF_OP_PRINT.0);

        let flags = UserAuthFlags::try_from(op).unwrap();

        assert!(flags.contains(UserAuthFlags::OP_PRINT));
        assert_eq!(flags.bits(), AF_OP_PRINT.0);
    }

    #[test]
    fn test_try_from_single_flag_comm() {
        let op = AF_OP(AF_OP_COMM.0);

        let flags = UserAuthFlags::try_from(op).unwrap();

        assert!(flags.contains(UserAuthFlags::OP_COMM));
        assert_eq!(flags.bits(), AF_OP_COMM.0);
    }

    #[test]
    fn test_try_from_multiple_flags() {
        let combined = AF_OP(AF_OP_PRINT.0 | AF_OP_COMM.0);

        let flags = UserAuthFlags::try_from(combined).unwrap();

        assert!(flags.contains(UserAuthFlags::OP_PRINT));
        assert!(flags.contains(UserAuthFlags::OP_COMM));
        assert_eq!(flags.bits(), AF_OP_PRINT.0 | AF_OP_COMM.0);
    }

    #[test]
    fn test_from_user_auth_flags_to_af_op() {
        let flags = UserAuthFlags::OP_SERVER | UserAuthFlags::OP_ACCOUNTS;

        let op: AF_OP = flags.into();

        assert_eq!(op.0, AF_OP_SERVER.0 | AF_OP_ACCOUNTS.0);
    }

    #[test]
    fn test_round_trip_conversion() {
        let original = AF_OP(AF_OP_PRINT.0 | AF_OP_SERVER.0);

        let flags = UserAuthFlags::try_from(original).unwrap();
        let back: AF_OP = flags.into();

        assert_eq!(original.0, back.0);
    }

    #[test]
    fn test_invalid_bits_return_error() {
        let invalid = AF_OP(0xFFFF);

        let result = UserAuthFlags::try_from(invalid);

        assert!(result.is_err());
        matches!(result, Err(InvalidUserProperty::AfOp(0xFFFF)));
    }
}

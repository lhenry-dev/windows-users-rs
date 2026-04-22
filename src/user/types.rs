pub mod logon_hours;
pub mod sid_type;
pub mod user_account_flags;
pub mod user_auth_flags;
pub mod user_privilege;

use thiserror::Error;

pub use self::logon_hours::LogonHours;
pub use self::sid_type::SidType;
pub use self::user_account_flags::UserAccountFlags;
pub use self::user_auth_flags::UserAuthFlags;
pub use self::user_privilege::UserPrivilege;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InvalidUserProperty {
    /// Indicates that an invalid value was used for `USER_PRIV`.
    #[error("Invalid USER_PRIV value: {0}")]
    UserPriv(u32),
    /// Indicates that an invalid value was used for `USER_ACCOUNT_FLAGS`.
    #[error("Invalid USER_ACCOUNT_FLAGS value: {0}")]
    UserAccountFlags(u32),
    /// Indicates that an invalid value was used for `AF_OP`.
    #[error("Invalid AF_OP value: {0}")]
    AfOp(u32),
    /// Indicates that an invalid value was used for `SID_NAME_USE`.
    #[error("Invalid SID_NAME_USE value: {0}")]
    SidType(i32),
}

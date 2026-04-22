use bitflags::bitflags;
use windows::Win32::NetworkManagement::NetManagement::{
    UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_DONT_REQUIRE_PREAUTH,
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED, UF_HOMEDIR_REQUIRED, UF_INTERDOMAIN_TRUST_ACCOUNT,
    UF_LOCKOUT, UF_NORMAL_ACCOUNT, UF_NOT_DELEGATED, UF_PASSWD_CANT_CHANGE, UF_PASSWD_NOTREQD,
    UF_PASSWORD_EXPIRED, UF_SCRIPT, UF_SERVER_TRUST_ACCOUNT, UF_SMARTCARD_REQUIRED,
    UF_TEMP_DUPLICATE_ACCOUNT, UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, UF_USE_DES_KEY_ONLY, UF_WORKSTATION_TRUST_ACCOUNT,
    USER_ACCOUNT_FLAGS,
};

use crate::user::types::InvalidUserProperty;

bitflags! {
    /// User account flags from `usri3_flags`
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UserAccountFlags: u32 {
        /// Script flag
        const SCRIPT = UF_SCRIPT.0;
        /// Account disabled flag
        const ACCOUNTDISABLE = UF_ACCOUNTDISABLE.0;
        /// Home directory required flag
        const HOMEDIR_REQUIRED = UF_HOMEDIR_REQUIRED.0;
        /// Password not required flag
        const PASSWD_NOTREQD = UF_PASSWD_NOTREQD.0;
        /// Password can't change flag
        const PASSWD_CANT_CHANGE = UF_PASSWD_CANT_CHANGE.0;
        /// Account locked out flag
        const LOCKOUT = UF_LOCKOUT.0;
        /// Don't expire password flag
        const DONT_EXPIRE_PASSWD = UF_DONT_EXPIRE_PASSWD.0;
        /// Encrypted text password allowed flag
        const ENCRYPTED_TEXT_PASSWORD_ALLOWED = UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED.0;
        /// Not delegated flag
        const NOT_DELEGATED = UF_NOT_DELEGATED.0;
        /// Smartcard required flag
        const SMARTCARD_REQUIRED = UF_SMARTCARD_REQUIRED.0;
        /// Use DES key only flag
        const USE_DES_KEY_ONLY = UF_USE_DES_KEY_ONLY.0;
        /// Don't require preauthentication flag
        const DONT_REQUIRE_PREAUTH = UF_DONT_REQUIRE_PREAUTH.0;
        /// Trusted for delegation flag
        const TRUSTED_FOR_DELEGATION = UF_TRUSTED_FOR_DELEGATION.0;
        /// Password expired flag
        const PASSWORD_EXPIRED = UF_PASSWORD_EXPIRED.0;
        /// Trusted to authenticate for delegation flag
        const TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION.0;

        /// Account types (mutually exclusive, typically only one set)

        ///  Normal account flag
        const NORMAL_ACCOUNT = UF_NORMAL_ACCOUNT;
        /// Temporary duplicate account flag
        const TEMP_DUPLICATE_ACCOUNT = UF_TEMP_DUPLICATE_ACCOUNT;
        /// Workstation trust account flag
        const WORKSTATION_TRUST_ACCOUNT = UF_WORKSTATION_TRUST_ACCOUNT;
        /// Server trust account flag
        const SERVER_TRUST_ACCOUNT = UF_SERVER_TRUST_ACCOUNT;
        /// Interdomain trust account flag
        const INTERDOMAIN_TRUST_ACCOUNT = UF_INTERDOMAIN_TRUST_ACCOUNT;
    }
}

impl Default for UserAccountFlags {
    fn default() -> Self {
        UserAccountFlags::SCRIPT | UserAccountFlags::NORMAL_ACCOUNT
    }
}

impl TryFrom<USER_ACCOUNT_FLAGS> for UserAccountFlags {
    type Error = InvalidUserProperty;

    fn try_from(value: USER_ACCOUNT_FLAGS) -> Result<Self, Self::Error> {
        UserAccountFlags::from_bits(value.0).ok_or(InvalidUserProperty::UserAccountFlags(value.0))
    }
}

impl From<UserAccountFlags> for USER_ACCOUNT_FLAGS {
    fn from(flags: UserAccountFlags) -> Self {
        Self(flags.bits())
    }
}

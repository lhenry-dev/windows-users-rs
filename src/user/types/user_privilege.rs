use windows::Win32::NetworkManagement::NetManagement::{
    USER_PRIV, USER_PRIV_ADMIN, USER_PRIV_GUEST, USER_PRIV_USER,
};

use crate::user::types::InvalidUserProperty;

/// User privilege levels from `usri3_priv`
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UserPrivilege {
    /// Guest user privilege level.
    #[default]
    Guest,
    /// Standard user privilege level.
    User,
    /// Administrator user privilege level.
    Admin,
}

impl TryFrom<USER_PRIV> for UserPrivilege {
    type Error = InvalidUserProperty;

    fn try_from(value: USER_PRIV) -> Result<Self, Self::Error> {
        match value {
            USER_PRIV_GUEST => Ok(UserPrivilege::Guest),
            USER_PRIV_USER => Ok(UserPrivilege::User),
            USER_PRIV_ADMIN => Ok(UserPrivilege::Admin),
            _ => Err(InvalidUserProperty::UserPriv(value.0)),
        }
    }
}

impl From<UserPrivilege> for USER_PRIV {
    fn from(privilege: UserPrivilege) -> Self {
        match privilege {
            UserPrivilege::Guest => USER_PRIV_GUEST,
            UserPrivilege::User => USER_PRIV_USER,
            UserPrivilege::Admin => USER_PRIV_ADMIN,
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::NetworkManagement::NetManagement::{
        USER_PRIV, USER_PRIV_ADMIN, USER_PRIV_GUEST, USER_PRIV_USER,
    };

    use crate::UserPrivilege;

    #[test]
    fn test_user_privilege_enum_is_exhaustive() {
        let cases = [
            (USER_PRIV_GUEST, UserPrivilege::Guest),
            (USER_PRIV_USER, UserPrivilege::User),
            (USER_PRIV_ADMIN, UserPrivilege::Admin),
        ];

        for (raw, expected_enum) in cases {
            let parsed = UserPrivilege::try_from(raw).expect("Expected valid USER_PRIV value");
            assert_eq!(parsed, expected_enum, "Unexpected UserPrivilege variant");

            let roundtrip_raw: USER_PRIV = parsed.into();
            assert_eq!(
                roundtrip_raw, raw,
                "Roundtrip USER_PRIV conversion mismatch"
            );
        }

        assert!(
            UserPrivilege::try_from(USER_PRIV(999)).is_err(),
            "Expected invalid USER_PRIV value to fail"
        );
    }
}

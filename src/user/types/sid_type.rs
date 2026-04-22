use windows::Win32::Security::SID_NAME_USE;

use crate::user::types::InvalidUserProperty;

/// SID name usage types (`SID_NAME_USE`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidType {
    /// A user SID.
    User,
    /// A group SID.
    Group,
    /// A domain SID.
    Domain,
    /// An alias SID.
    Alias,
    /// A well-known group SID.
    WellKnownGroup,
    /// A deleted account SID.
    DeletedAccount,
    /// An invalid SID.
    Invalid,
    /// An unknown SID type.
    Unknown,
    /// A computer SID.
    Computer,
    /// A mandatory integrity label SID.
    Label,
    /// A logon session SID.
    LogonSession,
}

impl TryFrom<SID_NAME_USE> for SidType {
    type Error = InvalidUserProperty;

    fn try_from(value: SID_NAME_USE) -> Result<Self, Self::Error> {
        match value {
            SID_NAME_USE(1) => Ok(SidType::User),
            SID_NAME_USE(2) => Ok(SidType::Group),
            SID_NAME_USE(3) => Ok(SidType::Domain),
            SID_NAME_USE(4) => Ok(SidType::Alias),
            SID_NAME_USE(5) => Ok(SidType::WellKnownGroup),
            SID_NAME_USE(6) => Ok(SidType::DeletedAccount),
            SID_NAME_USE(7) => Ok(SidType::Invalid),
            SID_NAME_USE(8) => Ok(SidType::Unknown),
            SID_NAME_USE(9) => Ok(SidType::Computer),
            SID_NAME_USE(10) => Ok(SidType::Label),
            SID_NAME_USE(11) => Ok(SidType::LogonSession),
            _ => Err(InvalidUserProperty::SidType(value.0)),
        }
    }
}

impl From<SidType> for SID_NAME_USE {
    fn from(value: SidType) -> Self {
        match value {
            SidType::User => SID_NAME_USE(1),
            SidType::Group => SID_NAME_USE(2),
            SidType::Domain => SID_NAME_USE(3),
            SidType::Alias => SID_NAME_USE(4),
            SidType::WellKnownGroup => SID_NAME_USE(5),
            SidType::DeletedAccount => SID_NAME_USE(6),
            SidType::Invalid => SID_NAME_USE(7),
            SidType::Unknown => SID_NAME_USE(8),
            SidType::Computer => SID_NAME_USE(9),
            SidType::Label => SID_NAME_USE(10),
            SidType::LogonSession => SID_NAME_USE(11),
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::SID_NAME_USE;

    use crate::SidType;

    #[test]
    fn test_sid_type_enum_is_exhaustive() {
        let expected = [
            SidType::User,
            SidType::Group,
            SidType::Domain,
            SidType::Alias,
            SidType::WellKnownGroup,
            SidType::DeletedAccount,
            SidType::Invalid,
            SidType::Unknown,
            SidType::Computer,
            SidType::Label,
            SidType::LogonSession,
        ];

        for (index, expected_enum) in expected.into_iter().enumerate() {
            let raw_value = (index + 1) as i32;
            let raw = SID_NAME_USE(raw_value);
            let parsed = SidType::try_from(raw).expect("Expected valid SID_NAME_USE value");
            assert_eq!(parsed, expected_enum, "Unexpected SidType variant");

            let roundtrip_raw: SID_NAME_USE = parsed.into();
            assert_eq!(
                roundtrip_raw, raw,
                "Roundtrip SID_NAME_USE conversion mismatch"
            );
        }

        assert!(
            SidType::try_from(SID_NAME_USE(0)).is_err(),
            "Expected SID_NAME_USE(0) to fail"
        );
        assert!(
            SidType::try_from(SID_NAME_USE(12)).is_err(),
            "Expected SID_NAME_USE(12) to fail"
        );
    }
}

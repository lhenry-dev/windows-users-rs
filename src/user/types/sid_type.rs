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
            SID_NAME_USE(1) => Ok(Self::User),
            SID_NAME_USE(2) => Ok(Self::Group),
            SID_NAME_USE(3) => Ok(Self::Domain),
            SID_NAME_USE(4) => Ok(Self::Alias),
            SID_NAME_USE(5) => Ok(Self::WellKnownGroup),
            SID_NAME_USE(6) => Ok(Self::DeletedAccount),
            SID_NAME_USE(7) => Ok(Self::Invalid),
            SID_NAME_USE(8) => Ok(Self::Unknown),
            SID_NAME_USE(9) => Ok(Self::Computer),
            SID_NAME_USE(10) => Ok(Self::Label),
            SID_NAME_USE(11) => Ok(Self::LogonSession),
            _ => Err(InvalidUserProperty::SidType(value.0)),
        }
    }
}

impl From<SidType> for SID_NAME_USE {
    fn from(value: SidType) -> Self {
        match value {
            SidType::User => Self(1),
            SidType::Group => Self(2),
            SidType::Domain => Self(3),
            SidType::Alias => Self(4),
            SidType::WellKnownGroup => Self(5),
            SidType::DeletedAccount => Self(6),
            SidType::Invalid => Self(7),
            SidType::Unknown => Self(8),
            SidType::Computer => Self(9),
            SidType::Label => Self(10),
            SidType::LogonSession => Self(11),
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
            let raw_value = i32::try_from(index + 1).expect("Expected index to fit in i32");
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

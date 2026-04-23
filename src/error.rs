use std::string::FromUtf16Error;

use thiserror::Error;
use windows::Win32::NetworkManagement::NetManagement::{
    USER_ACCT_EXPIRES_PARMNUM, USER_AUTH_FLAGS_PARMNUM, USER_CODE_PAGE_PARMNUM,
    USER_COMMENT_PARMNUM, USER_COUNTRY_CODE_PARMNUM, USER_FLAGS_PARMNUM, USER_FULL_NAME_PARMNUM,
    USER_HOME_DIR_DRIVE_PARMNUM, USER_HOME_DIR_PARMNUM, USER_LAST_LOGOFF_PARMNUM,
    USER_LAST_LOGON_PARMNUM, USER_LOGON_HOURS_PARMNUM, USER_LOGON_SERVER_PARMNUM,
    USER_MAX_STORAGE_PARMNUM, USER_NAME_PARMNUM, USER_NUM_LOGONS_PARMNUM,
    USER_PAD_PW_COUNT_PARMNUM, USER_PARMS_PARMNUM, USER_PASSWORD_AGE_PARMNUM,
    USER_PASSWORD_PARMNUM, USER_PRIMARY_GROUP_PARMNUM, USER_PRIV_PARMNUM, USER_PROFILE_PARMNUM,
    USER_SCRIPT_PATH_PARMNUM, USER_UNITS_PER_WEEK_PARMNUM, USER_USR_COMMENT_PARMNUM,
    USER_WORKSTATIONS_PARMNUM,
};

use crate::user::types::InvalidUserProperty;

/// Deriving common traits to automatically implement error handling functionality.
#[derive(Error, Debug)]
pub enum WindowsUsersError {
    /// Error returned when `CoInitializeEx` fails during COM initialization.
    #[error("CoInitializeEx failed: {0}")]
    CoInitializeExFailed(String),
    /// A general Windows API error wrapped from the `windows_result` crate.
    #[error(transparent)]
    WindowsError(#[from] windows::core::Error),
    /// Windows API error with parameter information.
    #[error("Windows error at parameter {parm}: {source}")]
    WindowsErrorWithParmnum {
        /// The parameter that caused the error.
        parm: ParmnumError,
        /// The source Windows error.
        #[source]
        source: windows::core::Error,
    },
    /// Error returned when converting a UTF-16 string to a Rust `String` fails.
    #[error(transparent)]
    Utf16ConversionError(#[from] FromUtf16Error),
    /// Error returned when an invalid user property value is encountered during conversion.
    #[error(transparent)]
    UserTypeError(#[from] InvalidUserProperty),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParmnumError {
    #[error("USER_NAME_PARMNUM (usri*_name)")]
    UserName,
    #[error("USER_PASSWORD_PARMNUM (usri*_password)")]
    UserPassword,
    #[error("USER_PASSWORD_AGE_PARMNUM (usri*_password_age)")]
    UserPasswordAge,
    #[error("USER_PRIV_PARMNUM (usri*_priv)")]
    UserPriv,
    #[error("USER_HOME_DIR_PARMNUM (usri*_home_dir)")]
    UserHomeDir,
    #[error("USER_COMMENT_PARMNUM (usri*_comment)")]
    UserComment,
    #[error("USER_FLAGS_PARMNUM (usri*_flags)")]
    UserFlags,
    #[error("USER_SCRIPT_PATH_PARMNUM (usri*_script_path)")]
    UserScriptPath,
    #[error("USER_AUTH_FLAGS_PARMNUM (usri*_auth_flags)")]
    UserAuthFlags,
    #[error("USER_FULL_NAME_PARMNUM (usri*_full_name)")]
    UserFullName,
    #[error("USER_USR_COMMENT_PARMNUM (usri*_usr_comment)")]
    UserUsrComment,
    #[error("USER_PARMS_PARMNUM (usri*_parms)")]
    UserParms,
    #[error("USER_WORKSTATIONS_PARMNUM (usri*_workstations)")]
    UserWorkstations,
    #[error("USER_LAST_LOGON_PARMNUM (usri*_last_logon)")]
    UserLastLogon,
    #[error("USER_LAST_LOGOFF_PARMNUM (usri*_last_logoff)")]
    UserLastLogoff,
    #[error("USER_ACCT_EXPIRES_PARMNUM (usri*_acct_expires)")]
    UserAcctExpires,
    #[error("USER_MAX_STORAGE_PARMNUM (usri*_max_storage)")]
    UserMaxStorage,
    #[error("USER_UNITS_PER_WEEK_PARMNUM (usri*_units_per_week)")]
    UserUnitsPerWeek,
    #[error("USER_LOGON_HOURS_PARMNUM (usri*_logon_hours)")]
    UserLogonHours,
    #[error("USER_PAD_PW_COUNT_PARMNUM (usri*_bad_pw_count)")]
    UserBadPwCount,
    #[error("USER_NUM_LOGONS_PARMNUM (usri*_num_logons)")]
    UserNumLogons,
    #[error("USER_LOGON_SERVER_PARMNUM (usri*_logon_server)")]
    UserLogonServer,
    #[error("USER_COUNTRY_CODE_PARMNUM (usri*_country_code)")]
    UserCountryCode,
    #[error("USER_CODE_PAGE_PARMNUM (usri*_code_page)")]
    UserCodePage,
    #[error("USER_PRIMARY_GROUP_PARMNUM (usri*_primary_group_id)")]
    UserPrimaryGroup,
    #[error("USER_PROFILE_PARMNUM (usri*_profile)")]
    UserProfile,
    #[error("USER_HOME_DIR_DRIVE_PARMNUM (usri*_home_dir_drive)")]
    UserHomeDirDrive,
    #[error("Parmnum inconnu : {0}")]
    Unknown(u32),
}

impl From<u32> for ParmnumError {
    fn from(value: u32) -> Self {
        match value {
            USER_NAME_PARMNUM => Self::UserName,
            USER_PASSWORD_PARMNUM => Self::UserPassword,
            USER_PASSWORD_AGE_PARMNUM => Self::UserPasswordAge,
            USER_PRIV_PARMNUM => Self::UserPriv,
            USER_HOME_DIR_PARMNUM => Self::UserHomeDir,
            USER_COMMENT_PARMNUM => Self::UserComment,
            USER_FLAGS_PARMNUM => Self::UserFlags,
            USER_SCRIPT_PATH_PARMNUM => Self::UserScriptPath,
            USER_AUTH_FLAGS_PARMNUM => Self::UserAuthFlags,
            USER_FULL_NAME_PARMNUM => Self::UserFullName,
            USER_USR_COMMENT_PARMNUM => Self::UserUsrComment,
            USER_PARMS_PARMNUM => Self::UserParms,
            USER_WORKSTATIONS_PARMNUM => Self::UserWorkstations,
            USER_LAST_LOGON_PARMNUM => Self::UserLastLogon,
            USER_LAST_LOGOFF_PARMNUM => Self::UserLastLogoff,
            USER_ACCT_EXPIRES_PARMNUM => Self::UserAcctExpires,
            USER_MAX_STORAGE_PARMNUM => Self::UserMaxStorage,
            USER_UNITS_PER_WEEK_PARMNUM => Self::UserUnitsPerWeek,
            USER_LOGON_HOURS_PARMNUM => Self::UserLogonHours,
            USER_PAD_PW_COUNT_PARMNUM => Self::UserBadPwCount,
            USER_NUM_LOGONS_PARMNUM => Self::UserNumLogons,
            USER_LOGON_SERVER_PARMNUM => Self::UserLogonServer,
            USER_COUNTRY_CODE_PARMNUM => Self::UserCountryCode,
            USER_CODE_PAGE_PARMNUM => Self::UserCodePage,
            USER_PRIMARY_GROUP_PARMNUM => Self::UserPrimaryGroup,
            USER_PROFILE_PARMNUM => Self::UserProfile,
            USER_HOME_DIR_DRIVE_PARMNUM => Self::UserHomeDirDrive,
            other => Self::Unknown(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_mappings_sample() {
        let cases = vec![
            (USER_NAME_PARMNUM, ParmnumError::UserName),
            (USER_PASSWORD_PARMNUM, ParmnumError::UserPassword),
            (USER_PASSWORD_AGE_PARMNUM, ParmnumError::UserPasswordAge),
            (USER_PRIV_PARMNUM, ParmnumError::UserPriv),
            (USER_HOME_DIR_PARMNUM, ParmnumError::UserHomeDir),
            (USER_COMMENT_PARMNUM, ParmnumError::UserComment),
            (USER_FLAGS_PARMNUM, ParmnumError::UserFlags),
            (USER_SCRIPT_PATH_PARMNUM, ParmnumError::UserScriptPath),
            (USER_AUTH_FLAGS_PARMNUM, ParmnumError::UserAuthFlags),
            (USER_FULL_NAME_PARMNUM, ParmnumError::UserFullName),
            (USER_USR_COMMENT_PARMNUM, ParmnumError::UserUsrComment),
            (USER_PARMS_PARMNUM, ParmnumError::UserParms),
            (USER_WORKSTATIONS_PARMNUM, ParmnumError::UserWorkstations),
            (USER_LAST_LOGON_PARMNUM, ParmnumError::UserLastLogon),
            (USER_LAST_LOGOFF_PARMNUM, ParmnumError::UserLastLogoff),
            (USER_ACCT_EXPIRES_PARMNUM, ParmnumError::UserAcctExpires),
            (USER_MAX_STORAGE_PARMNUM, ParmnumError::UserMaxStorage),
            (USER_UNITS_PER_WEEK_PARMNUM, ParmnumError::UserUnitsPerWeek),
            (USER_LOGON_HOURS_PARMNUM, ParmnumError::UserLogonHours),
            (USER_PAD_PW_COUNT_PARMNUM, ParmnumError::UserBadPwCount),
            (USER_NUM_LOGONS_PARMNUM, ParmnumError::UserNumLogons),
            (USER_LOGON_SERVER_PARMNUM, ParmnumError::UserLogonServer),
            (USER_COUNTRY_CODE_PARMNUM, ParmnumError::UserCountryCode),
            (USER_CODE_PAGE_PARMNUM, ParmnumError::UserCodePage),
            (USER_PRIMARY_GROUP_PARMNUM, ParmnumError::UserPrimaryGroup),
            (USER_PROFILE_PARMNUM, ParmnumError::UserProfile),
            (USER_HOME_DIR_DRIVE_PARMNUM, ParmnumError::UserHomeDirDrive),
            (USER_FULL_NAME_PARMNUM, ParmnumError::UserFullName),
            (USER_PROFILE_PARMNUM, ParmnumError::UserProfile),
            (USER_CODE_PAGE_PARMNUM, ParmnumError::UserCodePage),
        ];

        for (input, expected) in cases {
            assert_eq!(ParmnumError::from(input), expected);
        }
    }

    #[test]
    fn test_unknown_value() {
        let unknown = 999_999;

        assert_eq!(ParmnumError::from(unknown), ParmnumError::Unknown(unknown));
    }
}

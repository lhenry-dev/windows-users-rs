use std::{collections::HashSet, time::Duration};

use chrono::{DateTime, Utc};
use getset::{Getters, Setters};
use typed_builder::TypedBuilder;
use windows::{
    Win32::{
        NetworkManagement::NetManagement::{AF_OP, USER_INFO_3, USER_INFO_4},
        Security::PSID,
    },
    core::PWSTR,
};

use crate::{
    error::WindowsUsersError,
    user::types::user_auth_flags::ToUserAuthFlags,
    utils::{
        IntoDuration, PWSTRExt, ToWideString, ToWideStringOption, TryIntoDateTime, into_hashset,
        psid_to_string,
        times::{TryIntoSeconds, TryIntoTimestamp},
    },
};

pub use self::types::{LogonHours, SidType, UserAccountFlags, UserAuthFlags, UserPrivilege};

pub mod operations;
pub mod types;

const DOMAIN_GROUP_RID_USERS: u32 = 513;

/// Represents detailed information about a Windows user account.
/// Rust-native version of `USER_INFO_3`, with appropriate types and semantics.
#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct User {
    /// User account name (up to 20 characters, no forbidden symbols).
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    name: String,
    /// Optional user account password.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    password: Option<String>,
    /// Time in seconds since the password was last set.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    password_age: Option<Duration>,
    /// Privilege level of the user.
    ///
    /// ⚠️ This field is **not** meant to be set directly.
    /// User permissions are determined through **group membership**, not by
    /// manually assigning a privilege level on the user itself.
    ///
    /// To grant or modify a user's permissions, add them to the appropriate
    /// group using [`crate::add_users_to_group`].
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    priv_level: UserPrivilege,
    /// Path to the user's home directory.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    home_dir: Option<String>,
    /// Comment about the user account.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    comment: Option<String>,
    /// User account flags (bitmask defining account settings).
    #[builder(default, setter(into))]
    #[getset(get = "pub", set = "pub")]
    flags: UserAccountFlags,
    /// Path to the user's logon script.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    script_path: Option<String>,
    /// Logon authorization flags.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    auth_flags: Option<UserAuthFlags>,
    /// Full name of the user.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    full_name: Option<String>,
    /// Additional comment about the user.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    user_comment: Option<String>,
    /// Optional custom parameters.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    parms: Option<String>,
    /// List of workstations the user can log on to, separated by commas.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    workstations: Option<HashSet<String>>,
    /// Time of last successful logon.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    last_logon: Option<DateTime<Utc>>,
    /// Time of last logoff.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    last_logoff: Option<DateTime<Utc>>,
    /// Account expiration time.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    acct_expires: Option<DateTime<Utc>>,
    /// Maximum allowed storage for the user (bytes).
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    max_storage: Option<u32>,
    /// Number of time units in a week (used with `logon_hours`).
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    units_per_week: Option<u32>,
    /// Allowed logon hours as a bitmap (21 bytes, 168 bits = 7 days × 24 hours).
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    logon_hours: Option<LogonHours>,
    /// Number of failed login attempts.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    bad_pw_count: Option<u32>,
    /// Number of successful logons.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    num_logons: Option<u32>,
    /// Server handling the user's logon.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    logon_server: Option<String>,
    /// User’s country or region code.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    country_code: Option<u32>,
    /// Code page used for character encoding.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    code_page: Option<u32>,
    /// Unique user identifier.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    user_id: Option<u32>,
    /// Unique user identifier.
    #[builder(default, setter(skip))]
    #[getset(get = "pub", set = "pub")]
    user_sid: Option<String>,
    /// Identifier of the user's primary group.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    primary_group_id: Option<u32>,
    /// Path to the user's profile.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    profile: Option<String>,
    /// Drive letter to the user's home directory (e.g., "H:").
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    home_dir_drive: Option<String>,
    /// Indicates whether the password is expired.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    password_expired: Option<bool>,
}

impl TryFrom<&USER_INFO_3> for User {
    type Error = WindowsUsersError;

    fn try_from(user: &USER_INFO_3) -> Result<Self, WindowsUsersError> {
        unsafe {
            Ok(Self {
                name: user.usri3_name.to_string()?,
                password: None, // Password is not retrievable
                password_age: if user.usri3_password_age != 0 {
                    Some(Duration::from_secs(user.usri3_password_age.into()))
                } else {
                    None
                },
                priv_level: user.usri3_priv.try_into()?,
                home_dir: user.usri3_home_dir.to_optional_string(),
                comment: user.usri3_comment.to_optional_string(),
                flags: user.usri3_flags.try_into()?,
                script_path: user.usri3_script_path.to_optional_string(),
                auth_flags: user
                    .usri3_auth_flags
                    .try_into()
                    .ok()
                    .filter(|f: &UserAuthFlags| !f.is_empty()),
                full_name: user.usri3_full_name.to_optional_string(),
                user_comment: user.usri3_usr_comment.to_optional_string(),
                parms: user.usri3_parms.to_optional_string(),
                workstations: user.usri3_workstations.to_optional_hashset(),
                last_logon: if user.usri3_last_logon != 0 {
                    Some(user.usri3_last_logon.try_into_date_time()?)
                } else {
                    None
                },
                last_logoff: if user.usri3_last_logoff != 0 {
                    Some(user.usri3_last_logoff.try_into_date_time()?)
                } else {
                    None
                },
                acct_expires: if user.usri3_acct_expires == u32::MAX {
                    None
                } else {
                    Some(user.usri3_acct_expires.try_into_date_time()?)
                },
                max_storage: user.usri3_max_storage.into(),
                units_per_week: user.usri3_units_per_week.into(),
                logon_hours: if user.usri3_logon_hours.is_null() {
                    None
                } else {
                    Some(user.usri3_logon_hours.into())
                },
                bad_pw_count: user.usri3_bad_pw_count.into(),
                num_logons: user.usri3_num_logons.into(),
                logon_server: user.usri3_logon_server.to_optional_string(),
                country_code: if user.usri3_country_code != 0 {
                    Some(user.usri3_country_code)
                } else {
                    None
                },
                code_page: if user.usri3_code_page != 0 {
                    Some(user.usri3_code_page)
                } else {
                    None
                },
                user_id: user.usri3_user_id.into(),
                user_sid: None,
                primary_group_id: user.usri3_primary_group_id.into(),
                profile: user.usri3_profile.to_optional_string(),
                home_dir_drive: user.usri3_home_dir_drive.to_optional_string(),
                password_expired: (user.usri3_password_expired != 0).into(),
            })
        }
    }
}

impl TryFrom<&USER_INFO_4> for User {
    type Error = WindowsUsersError;

    fn try_from(user: &USER_INFO_4) -> Result<Self, WindowsUsersError> {
        unsafe {
            Ok(Self {
                name: user.usri4_name.to_string()?,
                password: None,
                password_age: if user.usri4_password_age != 0 {
                    Some(user.usri4_password_age.into_duration())
                } else {
                    None
                },
                priv_level: user.usri4_priv.try_into()?,
                home_dir: user.usri4_home_dir.to_optional_string(),
                comment: user.usri4_comment.to_optional_string(),
                flags: user.usri4_flags.try_into()?,
                script_path: user.usri4_script_path.to_optional_string(),
                auth_flags: user.usri4_auth_flags.to_auth_flags(),
                full_name: user.usri4_full_name.to_optional_string(),
                user_comment: user.usri4_usr_comment.to_optional_string(),
                parms: user.usri4_parms.to_optional_string(),
                workstations: user.usri4_workstations.to_optional_hashset(),
                last_logon: if user.usri4_last_logon != 0 {
                    Some(user.usri4_last_logon.try_into_date_time()?)
                } else {
                    None
                },
                last_logoff: if user.usri4_last_logoff != 0 {
                    Some(user.usri4_last_logoff.try_into_date_time()?)
                } else {
                    None
                },
                acct_expires: if user.usri4_acct_expires == u32::MAX {
                    None
                } else {
                    Some(user.usri4_acct_expires.try_into_date_time()?)
                },
                max_storage: user.usri4_max_storage.into(),
                units_per_week: user.usri4_units_per_week.into(),
                logon_hours: if user.usri4_logon_hours.is_null() {
                    None
                } else {
                    Some(user.usri4_logon_hours.into())
                },
                bad_pw_count: user.usri4_bad_pw_count.into(),
                num_logons: user.usri4_num_logons.into(),
                logon_server: user.usri4_logon_server.to_optional_string(),
                country_code: if user.usri4_country_code != 0 {
                    Some(user.usri4_country_code)
                } else {
                    None
                },
                code_page: if user.usri4_code_page != 0 {
                    Some(user.usri4_code_page)
                } else {
                    None
                },
                user_id: None,
                user_sid: Some(psid_to_string(user.usri4_user_sid)?),
                primary_group_id: user.usri4_primary_group_id.into(),
                profile: user.usri4_profile.to_optional_string(),
                home_dir_drive: user.usri4_home_dir_drive.to_optional_string(),
                password_expired: (user.usri4_password_expired != 0).into(),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserInfo4Buffer {
    pub user_info: USER_INFO_4,
    _strings: Vec<Vec<u16>>,
    _buffers: Vec<Vec<u8>>,
}

impl User {
    /// Converts the `User` instance into a `USER_INFO_4` structure
    pub fn to_user_info_4(&self) -> UserInfo4Buffer {
        let mut string_storage: Vec<Vec<u16>> = Vec::new();
        let mut buffer_storage: Vec<Vec<u8>> = Vec::new();

        let push_string = |s: Option<Vec<u16>>, storage: &mut Vec<Vec<u16>>| -> PWSTR {
            s.map_or_else(PWSTR::null, |mut vec| {
                let ptr = vec.as_mut_ptr();
                storage.push(vec);
                PWSTR(ptr)
            })
        };

        let push_buffer = |b: Option<Vec<u8>>, storage: &mut Vec<Vec<u8>>| -> *mut u8 {
            b.map_or(std::ptr::null_mut(), |mut vec| {
                let ptr = vec.as_mut_ptr();
                storage.push(vec);
                ptr
            })
        };

        let workstations_str = self
            .workstations
            .as_ref()
            .map(|ws| ws.iter().cloned().collect::<Vec<_>>().join(","))
            .unwrap_or_default();

        let user_info = USER_INFO_4 {
            usri4_name: push_string(Some(self.name.to_wide()), &mut string_storage),
            usri4_password: push_string(
                self.password.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_password_age: self
                .password_age
                .map(|d| d.try_into_seconds().unwrap_or_default())
                .unwrap_or_default(),
            usri4_priv: self.priv_level.into(),
            usri4_home_dir: push_string(
                self.home_dir.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_comment: push_string(self.comment.as_ref().to_wide_option(), &mut string_storage),
            usri4_flags: self.flags.into(),
            usri4_script_path: push_string(
                self.script_path.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_auth_flags: self.auth_flags.map(AF_OP::from).unwrap_or_default(),
            usri4_full_name: push_string(
                self.full_name.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_usr_comment: push_string(
                self.user_comment.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_parms: push_string(self.parms.as_ref().to_wide_option(), &mut string_storage),
            usri4_workstations: push_string(Some(workstations_str.to_wide()), &mut string_storage),
            usri4_last_logon: self
                .last_logon
                .map_or(u32::MAX, |d| d.try_into_timestamp().unwrap_or_default()),
            usri4_last_logoff: self
                .last_logoff
                .map_or(u32::MAX, |d| d.try_into_timestamp().unwrap_or_default()),
            usri4_acct_expires: self
                .acct_expires
                .map_or(u32::MAX, |d| d.try_into_timestamp().unwrap_or_default()),
            usri4_max_storage: self.max_storage.unwrap_or_default(),
            usri4_units_per_week: self.units_per_week.unwrap_or(LogonHours::UNITS_PER_WEEK),
            usri4_logon_hours: push_buffer(
                self.logon_hours.clone().map(Into::into),
                &mut buffer_storage,
            ),
            usri4_bad_pw_count: self.bad_pw_count.unwrap_or_default(),
            usri4_num_logons: self.num_logons.unwrap_or_default(),
            usri4_logon_server: push_string(
                self.logon_server.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_country_code: self.country_code.unwrap_or_default(),
            usri4_code_page: self.code_page.unwrap_or_default(),
            usri4_user_sid: PSID(std::ptr::null_mut()),
            usri4_primary_group_id: self.primary_group_id.unwrap_or(DOMAIN_GROUP_RID_USERS),
            usri4_profile: push_string(self.profile.as_ref().to_wide_option(), &mut string_storage),
            usri4_home_dir_drive: push_string(
                self.home_dir_drive.as_ref().to_wide_option(),
                &mut string_storage,
            ),
            usri4_password_expired: u32::from(self.password_expired.unwrap_or(false)),
        };

        UserInfo4Buffer {
            user_info,
            _strings: string_storage,
            _buffers: buffer_storage,
        }
    }
}

/// Struct for updating Windows user accounts.
#[derive(Debug, Clone, TypedBuilder)]
pub struct UserUpdate {
    /// User account name (up to 20 characters, no forbidden symbols).
    #[builder(default, setter(strip_option, into))]
    pub(crate) name: Option<String>,
    /// Optional user account password.
    #[builder(default, setter(strip_option, into))]
    pub(crate) password: Option<String>,
    /// Path to the user's home directory.
    #[builder(default, setter(strip_option, into))]
    pub(crate) home_dir: Option<String>,
    /// Comment about the user account.
    #[builder(default, setter(strip_option, into))]
    pub(crate) comment: Option<String>,
    /// User account flags (bitmask defining account settings).
    #[builder(default, setter(strip_option, into))]
    pub(crate) flags: Option<UserAccountFlags>,
    /// Path to the user's logon script.
    #[builder(default, setter(strip_option, into))]
    pub(crate) script_path: Option<String>,
    /// Full name of the user.
    #[builder(default, setter(strip_option, into))]
    pub(crate) full_name: Option<String>,
    /// Additional comment about the user.
    #[builder(default, setter(strip_option, into))]
    pub(crate) user_comment: Option<String>,
    /// List of workstations the user can log on to, separated by commas.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(into_hashset(items))))]
    pub(crate) workstations: Option<HashSet<String>>,
    /// Account expiration time.
    #[builder(default, setter(strip_option, into))]
    pub(crate) acct_expires: Option<DateTime<Utc>>,
    /// Allowed logon hours as a bitmap (21 bytes, 168 bits = 7 days × 24 hours).
    #[builder(default, setter(strip_option, into))]
    pub(crate) logon_hours: Option<LogonHours>,
    /// User’s country or region code.
    #[builder(default, setter(strip_option, into))]
    pub(crate) country_code: Option<u32>,
    /// Identifier of the user's primary group.
    #[builder(default, setter(strip_option, into))]
    pub(crate) primary_group_id: Option<u32>,
    /// Path to the user's profile.
    #[builder(default, setter(strip_option, into))]
    pub(crate) profile: Option<String>,
    /// Drive letter to the user's home directory (e.g., "H:").
    #[builder(default, setter(strip_option, into))]
    pub(crate) home_dir_drive: Option<String>,
}

impl From<User> for UserUpdate {
    fn from(user: User) -> Self {
        Self {
            name: Some(user.name),
            password: user.password,
            home_dir: user.home_dir,
            comment: user.comment,
            flags: Some(user.flags),
            script_path: user.script_path,
            full_name: user.full_name,
            user_comment: user.user_comment,
            workstations: user.workstations,
            acct_expires: user.acct_expires,
            logon_hours: user.logon_hours,
            country_code: user.country_code,
            primary_group_id: user.primary_group_id,
            profile: user.profile,
            home_dir_drive: user.home_dir_drive,
        }
    }
}

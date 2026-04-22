use std::collections::HashSet;

use chrono::{DateTime, Utc};
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserSetInfo, USER_INFO_0, USER_INFO_1, USER_INFO_2, USER_INFO_3, USER_INFO_4, USER_INFO_21,
    USER_INFO_22, USER_INFO_1003, USER_INFO_1005, USER_INFO_1006, USER_INFO_1007, USER_INFO_1008,
    USER_INFO_1009, USER_INFO_1010, USER_INFO_1011, USER_INFO_1012, USER_INFO_1014, USER_INFO_1017,
    USER_INFO_1020, USER_INFO_1024, USER_INFO_1051, USER_INFO_1052, USER_INFO_1053,
};
use windows::core::{PCWSTR, PWSTR};

use crate::UserAccountFlags;
use crate::utils::net_api_result_with_index;
use crate::{error::WindowsUsersError, utils::to_wide};

trait NetUserInfoLevel {
    const LEVEL: u32;
}

fn set_user_info<T: NetUserInfoLevel>(
    server_name: Option<&str>,
    username: &str,
    info: &mut T,
) -> Result<(), WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(to_wide(s).as_ptr()))
        .unwrap_or_default();

    let username_w = to_wide(username);
    let mut parm_err = 0;

    let status = unsafe {
        NetUserSetInfo(
            server_name,
            PCWSTR(username_w.as_ptr()),
            T::LEVEL,
            info as *mut T as *mut u8,
            Some(&mut parm_err),
        )
    };

    net_api_result_with_index(status, parm_err)
}

impl NetUserInfoLevel for USER_INFO_0 {
    const LEVEL: u32 = 0;
}

/// Renames a user on the local machine.
pub fn set_user_name(
    server_name: Option<&str>,
    old_name: &str,
    new_name: &str,
) -> Result<(), WindowsUsersError> {
    let mut new_name_w = to_wide(new_name);

    let mut info = USER_INFO_0 {
        usri0_name: PWSTR(new_name_w.as_mut_ptr()),
    };

    set_user_info(server_name, old_name, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1 {
    const LEVEL: u32 = 1;
}

impl NetUserInfoLevel for USER_INFO_2 {
    const LEVEL: u32 = 2;
}

impl NetUserInfoLevel for USER_INFO_3 {
    const LEVEL: u32 = 3;
}

impl NetUserInfoLevel for USER_INFO_4 {
    const LEVEL: u32 = 4;
}

impl NetUserInfoLevel for USER_INFO_21 {
    const LEVEL: u32 = 21;
}

impl NetUserInfoLevel for USER_INFO_22 {
    const LEVEL: u32 = 22;
}

impl NetUserInfoLevel for USER_INFO_1003 {
    const LEVEL: u32 = 1003;
}

/// Sets a user's password on the local machine.
pub fn set_user_password(
    server_name: Option<&str>,
    username: &str,
    new_password: &str,
) -> Result<(), WindowsUsersError> {
    let mut password_w = to_wide(new_password);

    let mut info = USER_INFO_1003 {
        usri1003_password: PWSTR(password_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1005 {
    const LEVEL: u32 = 1005;
}

impl NetUserInfoLevel for USER_INFO_1006 {
    const LEVEL: u32 = 1006;
}

/// Sets the user's home directory path.
pub fn set_user_home_directory(
    server_name: Option<&str>,
    username: &str,
    home_dir: &str,
) -> Result<(), WindowsUsersError> {
    let mut home_dir_w = to_wide(home_dir);

    let mut info = USER_INFO_1006 {
        usri1006_home_dir: PWSTR(home_dir_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1007 {
    const LEVEL: u32 = 1007;
}

/// Sets a comment associated with the user account.
pub fn set_user_comment(
    server_name: Option<&str>,
    username: &str,
    comment: &str,
) -> Result<(), WindowsUsersError> {
    let mut comment_w = to_wide(comment);

    let mut info = USER_INFO_1007 {
        usri1007_comment: PWSTR(comment_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1008 {
    const LEVEL: u32 = 1008;
}

/// Sets user account attributes (UF_* flags).
pub fn set_user_flags(
    server_name: Option<&str>,
    username: &str,
    flags: UserAccountFlags,
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1008 {
        usri1008_flags: flags.into(),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1009 {
    const LEVEL: u32 = 1009;
}

/// Sets the user's logon script path.
pub fn set_user_script_path(
    server_name: Option<&str>,
    username: &str,
    script_path: &str,
) -> Result<(), WindowsUsersError> {
    let mut script_path_w = to_wide(script_path);

    let mut info = USER_INFO_1009 {
        usri1009_script_path: PWSTR(script_path_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1010 {
    const LEVEL: u32 = 1010;
}

impl NetUserInfoLevel for USER_INFO_1011 {
    const LEVEL: u32 = 1011;
}

/// Sets the user's full name.
pub fn set_user_full_name(
    server_name: Option<&str>,
    username: &str,
    full_name: &str,
) -> Result<(), WindowsUsersError> {
    let mut full_name_w = to_wide(full_name);

    let mut info = USER_INFO_1011 {
        usri1011_full_name: PWSTR(full_name_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1012 {
    const LEVEL: u32 = 1012;
}

/// Sets a comment associated with the user.
pub fn set_user_user_comment(
    server_name: Option<&str>,
    username: &str,
    usr_comment: &str,
) -> Result<(), WindowsUsersError> {
    let mut usr_comment_w = to_wide(usr_comment);

    let mut info = USER_INFO_1012 {
        usri1012_usr_comment: PWSTR(usr_comment_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1014 {
    const LEVEL: u32 = 1014;
}

/// Sets the workstations from which the user can log on.
pub fn set_user_workstations(
    server_name: Option<&str>,
    username: &str,
    workstations: HashSet<String>,
) -> Result<(), WindowsUsersError> {
    let workstations_str = workstations.iter().cloned().collect::<Vec<_>>().join(",");

    let mut workstations_w = to_wide(&workstations_str);

    let mut info = USER_INFO_1014 {
        usri1014_workstations: PWSTR(workstations_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1017 {
    const LEVEL: u32 = 1017;
}

/// Sets the account expiration time (seconds since 1970, or TIMEQ_FOREVER).
pub fn set_user_account_expiration(
    server_name: Option<&str>,
    username: &str,
    acct_expires: DateTime<Utc>,
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1017 {
        usri1017_acct_expires: acct_expires.timestamp() as u32,
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1020 {
    const LEVEL: u32 = 1020;
}

/// Sets the hours during which the user can log on.
pub fn set_user_logon_hours(
    server_name: Option<&str>,
    username: &str,
    units_per_week: u32,
    logon_hours: Vec<u8>,
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1020 {
        usri1020_units_per_week: units_per_week,
        usri1020_logon_hours: logon_hours.as_ptr() as *mut u8,
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1024 {
    const LEVEL: u32 = 1024;
}

/// Sets the user's country/region code.
pub fn set_user_country_code(
    server_name: Option<&str>,
    username: &str,
    country_code: u32,
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1024 {
        usri1024_country_code: country_code,
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1051 {
    const LEVEL: u32 = 1051;
}

/// Sets the user's primary global group RID.
pub fn set_user_primary_group(
    server_name: Option<&str>,
    username: &str,
    primary_group_id: u32,
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1051 {
        usri1051_primary_group_id: primary_group_id,
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1052 {
    const LEVEL: u32 = 1052;
}

/// Sets the user's profile path.
pub fn set_user_profile(
    server_name: Option<&str>,
    username: &str,
    profile: &str,
) -> Result<(), WindowsUsersError> {
    let mut profile_w = to_wide(profile);

    let mut info = USER_INFO_1052 {
        usri1052_profile: PWSTR(profile_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1053 {
    const LEVEL: u32 = 1053;
}

/// Sets the drive letter assigned to the user's home directory.
pub fn set_user_home_dir_drive(
    server_name: Option<&str>,
    username: &str,
    home_dir_drive: &str,
) -> Result<(), WindowsUsersError> {
    let mut home_dir_drive_w = to_wide(home_dir_drive);

    let mut info = USER_INFO_1053 {
        usri1053_home_dir_drive: PWSTR(home_dir_drive_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

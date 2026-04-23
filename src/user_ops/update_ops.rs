use chrono::{DateTime, Utc};
use windows::Win32::NetworkManagement::NetManagement::{
    NetUserSetInfo, USER_INFO_0, USER_INFO_1, USER_INFO_2, USER_INFO_3, USER_INFO_4, USER_INFO_21,
    USER_INFO_22, USER_INFO_1003, USER_INFO_1005, USER_INFO_1006, USER_INFO_1007, USER_INFO_1008,
    USER_INFO_1009, USER_INFO_1010, USER_INFO_1011, USER_INFO_1012, USER_INFO_1014, USER_INFO_1017,
    USER_INFO_1020, USER_INFO_1024, USER_INFO_1051, USER_INFO_1052, USER_INFO_1053,
};
use windows::core::{PCWSTR, PWSTR};

use crate::UserAccountFlags;
use crate::error::WindowsUsersError;
use crate::utils::{ToWideString, TryIntoTimestamp, net_api_result_with_index};

trait NetUserInfoLevel {
    const LEVEL: u32;
}

fn set_user_info<T: NetUserInfoLevel>(
    server_name: Option<&str>,
    username: &str,
    info: &mut T,
) -> Result<(), WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(s.to_wide().as_ptr()))
        .unwrap_or_default();

    let username_w = username.to_wide();
    let mut parm_err = 0;

    let status = unsafe {
        NetUserSetInfo(
            server_name,
            PCWSTR(username_w.as_ptr()),
            T::LEVEL,
            std::ptr::from_mut::<T>(info).cast::<u8>(),
            Some(&raw mut parm_err),
        )
    };

    net_api_result_with_index(status, parm_err)
}

impl NetUserInfoLevel for USER_INFO_0 {
    const LEVEL: u32 = 0;
}

/// Renames a user on the local machine.
///
/// This function updates the account name using `NetUserSetInfo` level 0.
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
/// * `old_name` - Current username.
/// * `new_name` - New username.
///
/// # Returns
///
/// Returns `Ok(())` when the rename succeeds.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The new name is invalid or already taken
/// - The API call fails
/// - The caller does not have sufficient privileges
///
/// # Security
///
/// ⚠️ Requires **administrative privileges**.
pub fn set_user_name(
    server_name: Option<&str>,
    old_name: &str,
    new_name: &str,
) -> Result<(), WindowsUsersError> {
    let mut new_name_w = new_name.to_wide();

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

/// Sets a user's password.
///
/// This function updates the account password using level 1003.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - Target account.
/// * `new_password` - New password.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - Password policy is violated
/// - The user does not exist
/// - The API call fails
///
/// # Security
///
/// ⚠️ Requires appropriate privileges.
pub fn set_user_password(
    server_name: Option<&str>,
    username: &str,
    new_password: &str,
) -> Result<(), WindowsUsersError> {
    let mut password_w = new_password.to_wide();

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
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - Target account.
/// * `home_dir` - Path to the home directory.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if the API call fails or parameters are invalid.
pub fn set_user_home_directory(
    server_name: Option<&str>,
    username: &str,
    home_dir: &str,
) -> Result<(), WindowsUsersError> {
    let mut home_dir_w = home_dir.to_wide();

    let mut info = USER_INFO_1006 {
        usri1006_home_dir: PWSTR(home_dir_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1007 {
    const LEVEL: u32 = 1007;
}

/// Sets the descriptive comment for a user account.
///
/// This function updates the account comment using `NetUserSetInfo` level 1007.
/// This field is typically used for administrative notes (e.g. role, purpose).
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
/// * `username` - The account name to update.
/// * `comment` - The comment string to associate with the account.
///
/// # Returns
///
/// Returns `Ok(())` when the update succeeds.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The comment is invalid or too long
/// - The API call fails (`NetUserSetInfo`)
/// - The caller does not have sufficient privileges
///
/// # Notes
///
/// This maps to the `usri1007_comment` field.
pub fn set_user_comment(
    server_name: Option<&str>,
    username: &str,
    comment: &str,
) -> Result<(), WindowsUsersError> {
    let mut comment_w = comment.to_wide();

    let mut info = USER_INFO_1007 {
        usri1007_comment: PWSTR(comment_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1008 {
    const LEVEL: u32 = 1008;
}

/// Sets user account control flags (UF_*).
///
/// This function updates account behavior flags such as:
/// - account disabled
/// - password never expires
/// - user cannot change password
///
/// Uses `NetUserSetInfo` level 1008.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name to update.
/// * `flags` - Bitflags representing account properties.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - Flags are invalid or unsupported
/// - The API call fails
///
/// # Notes
///
/// Flags are converted into native `UF_*` values internally.
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

/// Sets the logon script path for a user.
///
/// This function defines the script executed at user logon
/// using `NetUserSetInfo` level 1009.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `script_path` - Path to the logon script.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The path is invalid
/// - The API call fails
///
/// # Notes
///
/// The path is interpreted relative to the domain/script directory
/// depending on system configuration.
pub fn set_user_script_path(
    server_name: Option<&str>,
    username: &str,
    script_path: &str,
) -> Result<(), WindowsUsersError> {
    let mut script_path_w = script_path.to_wide();

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

/// Sets the user's full display name.
///
/// This updates the "Full Name" field visible in user management tools,
/// using `NetUserSetInfo` level 1011.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `full_name` - The display name to assign.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The value is invalid
/// - The API call fails
pub fn set_user_full_name(
    server_name: Option<&str>,
    username: &str,
    full_name: &str,
) -> Result<(), WindowsUsersError> {
    let mut full_name_w = full_name.to_wide();

    let mut info = USER_INFO_1011 {
        usri1011_full_name: PWSTR(full_name_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1012 {
    const LEVEL: u32 = 1012;
}

/// Sets the user-specific comment field.
///
/// This is distinct from the standard account comment and is stored
/// in `usri1012_usr_comment`.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `usr_comment` - The user-specific comment.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if the operation fails.
///
/// # Notes
///
/// Rarely used in practice; differs from `set_user_comment`.
pub fn set_user_user_comment(
    server_name: Option<&str>,
    username: &str,
    usr_comment: &str,
) -> Result<(), WindowsUsersError> {
    let mut usr_comment_w = usr_comment.to_wide();

    let mut info = USER_INFO_1012 {
        usri1012_usr_comment: PWSTR(usr_comment_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1014 {
    const LEVEL: u32 = 1014;
}

/// Sets the list of workstations allowed to log on to the account.
///
/// This restriction controls from which machines the user is permitted
/// to authenticate. It maps to the `usri1014_workstations` field in the
/// Windows `USER_INFO_1014` structure.
///
/// The value is stored as a comma-separated string of workstation names.
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
/// * `username` - The account name to update.
/// * `workstations` - Set of workstation names allowed for logon.
///
/// # Returns
///
/// Returns `Ok(())` when the operation succeeds.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The workstation list is invalid or too large
/// - The API call fails (`NetUserSetInfo`)
/// - The caller does not have sufficient privileges
///
/// # Notes
///
/// - An empty set typically removes workstation restrictions (system-dependent behavior).
/// - Internally converted into a comma-separated string.
pub fn set_user_workstations(
    server_name: Option<&str>,
    username: &str,
    workstations: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), WindowsUsersError> {
    let workstations_str = workstations
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect::<Vec<String>>()
        .join(",");

    let mut workstations_w = workstations_str.to_wide();

    let mut info = USER_INFO_1014 {
        usri1014_workstations: PWSTR(workstations_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1017 {
    const LEVEL: u32 = 1017;
}

/// Sets the account expiration date.
///
/// This function defines when the account becomes invalid using
/// `NetUserSetInfo` level 1017.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `acct_expires` - Expiration date (UTC).
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The timestamp is invalid
/// - The API call fails
///
/// # Notes
///
/// - Converted to a UNIX timestamp (seconds since 1970)
/// - Use special values (e.g. `TIMEQ_FOREVER`) for no expiration
pub fn set_user_account_expiration(
    server_name: Option<&str>,
    username: &str,
    acct_expires: DateTime<Utc>,
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1017 {
        usri1017_acct_expires: acct_expires.try_into_timestamp()?,
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1020 {
    const LEVEL: u32 = 1020;
}

/// Sets allowed logon hours for a user.
///
/// This function restricts when a user can authenticate using
/// `NetUserSetInfo` level 1020.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `units_per_week` - Number of time units in a week (typically 168)
/// * `logon_hours` - Bitmask defining allowed hours
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The user does not exist
/// - The bitmask format is invalid
/// - The API call fails
///
/// # Notes
///
/// The format must match Windows expectations (bit-level encoding).
pub fn set_user_logon_hours(
    server_name: Option<&str>,
    username: &str,
    units_per_week: u32,
    logon_hours: &[u8],
) -> Result<(), WindowsUsersError> {
    let mut info = USER_INFO_1020 {
        usri1020_units_per_week: units_per_week,
        usri1020_logon_hours: logon_hours.as_ptr().cast_mut(),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1024 {
    const LEVEL: u32 = 1024;
}

/// Sets the user's country or region code.
///
/// This updates localization-related metadata using
/// `NetUserSetInfo` level 1024.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `country_code` - Numeric country/region code.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if the operation fails.
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

/// Sets the primary group RID for the user.
///
/// This determines the user's primary group association
/// using `NetUserSetInfo` level 1051.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `primary_group_id` - RID of the primary group.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The group does not exist
/// - The API call fails
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

/// Sets the user profile path.
///
/// This function defines the profile directory location
/// using `NetUserSetInfo` level 1052.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `profile` - Path to the profile directory.
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if the operation fails.
pub fn set_user_profile(
    server_name: Option<&str>,
    username: &str,
    profile: &str,
) -> Result<(), WindowsUsersError> {
    let mut profile_w = profile.to_wide();

    let mut info = USER_INFO_1052 {
        usri1052_profile: PWSTR(profile_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

impl NetUserInfoLevel for USER_INFO_1053 {
    const LEVEL: u32 = 1053;
}

/// Sets the drive letter assigned to the user's home directory.
///
/// This function updates the drive mapping (e.g. "H:")
/// using `NetUserSetInfo` level 1053.
///
/// # Arguments
///
/// * `server_name` - Optional target server.
/// * `username` - The account name.
/// * `home_dir_drive` - Drive letter (e.g. "H:")
///
/// # Returns
///
/// Returns `Ok(())` on success.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The value is invalid
/// - The API call fails
pub fn set_user_home_dir_drive(
    server_name: Option<&str>,
    username: &str,
    home_dir_drive: &str,
) -> Result<(), WindowsUsersError> {
    let mut home_dir_drive_w = home_dir_drive.to_wide();

    let mut info = USER_INFO_1053 {
        usri1053_home_dir_drive: PWSTR(home_dir_drive_w.as_mut_ptr()),
    };

    set_user_info(server_name, username, &mut info)
}

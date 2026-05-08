use chrono::{DateTime, Utc};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetInfo, NetUserSetInfo, USER_INFO_0, USER_INFO_1, USER_INFO_1003,
    USER_INFO_1006, USER_INFO_1007, USER_INFO_1008, USER_INFO_1009, USER_INFO_1011, USER_INFO_1012,
    USER_INFO_1014, USER_INFO_1017, USER_INFO_1020, USER_INFO_1024, USER_INFO_1051, USER_INFO_1052,
    USER_INFO_1053,
};
use windows::core::{PCWSTR, PWSTR};

use crate::error::WindowsUsersError;
use crate::user_ops::update_ops::net_user_info_level::NetUserInfoLevel;
use crate::utils::{ToWideString, TryIntoTimestamp, net_api_result, net_api_result_with_index};
use crate::{UserAccountFlags, UserManager};

mod net_user_info_level;

impl UserManager {
    fn set_user_info<T: NetUserInfoLevel>(
        &self,
        username: &str,
        info: &mut T,
    ) -> Result<(), WindowsUsersError> {
        let server_name = self.server;

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

    /// Renames a user on the local machine.
    ///
    /// This function updates the account name using `NetUserSetInfo` level 0.
    ///
    /// # Arguments
    ///
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
    pub fn rename_user(&self, old_name: &str, new_name: &str) -> Result<(), WindowsUsersError> {
        let mut new_name_w = new_name.to_wide();

        let mut info = USER_INFO_0 {
            usri0_name: PWSTR(new_name_w.as_mut_ptr()),
        };

        self.set_user_info(old_name, &mut info)
    }

    /// Sets a user's password.
    ///
    /// This function updates the account password using level 1003.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        new_password: &str,
    ) -> Result<(), WindowsUsersError> {
        let mut password_w = new_password.to_wide();

        let mut info = USER_INFO_1003 {
            usri1003_password: PWSTR(password_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the user's home directory path.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        home_dir: &str,
    ) -> Result<(), WindowsUsersError> {
        let mut home_dir_w = home_dir.to_wide();

        let mut info = USER_INFO_1006 {
            usri1006_home_dir: PWSTR(home_dir_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the descriptive comment for a user account.
    ///
    /// This function updates the account comment using `NetUserSetInfo` level 1007.
    /// This field is typically used for administrative notes (e.g. role, purpose).
    ///
    /// # Arguments
    ///
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
    pub fn set_user_comment(&self, username: &str, comment: &str) -> Result<(), WindowsUsersError> {
        let mut comment_w = comment.to_wide();

        let mut info = USER_INFO_1007 {
            usri1007_comment: PWSTR(comment_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
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
        &self,
        username: &str,
        flags: UserAccountFlags,
    ) -> Result<(), WindowsUsersError> {
        let mut info = USER_INFO_1008 {
            usri1008_flags: flags.into(),
        };

        self.set_user_info(username, &mut info)
    }

    fn get_user_flags(&self, username: &str) -> Result<UserAccountFlags, WindowsUsersError> {
        let server_name = self.server;

        let username_w = username.to_wide();

        let mut buffer = std::ptr::null_mut();

        let status =
            unsafe { NetUserGetInfo(server_name, PCWSTR(username_w.as_ptr()), 1, &raw mut buffer) };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status)?;

        let flags = unsafe {
            let ui1 = &*(buffer as *const USER_INFO_1);
            ui1.usri1_flags
        };

        Ok(UserAccountFlags::try_from(flags)?)
    }

    /// Adds user account control flags (UF_*).
    ///
    /// This function retrieves the current account flags and adds the specified
    /// flags using a bitwise OR operation. It allows enabling additional account
    /// properties without affecting existing ones.
    ///
    /// Typical use cases include:
    /// - disabling an account
    /// - setting "password never expires"
    /// - preventing the user from changing their password
    ///
    /// Internally, this function:
    /// 1. Calls `NetUserGetInfo` (level 1) to retrieve current flags
    /// 2. Combines them with the provided flags
    /// 3. Calls `NetUserSetInfo` (level 1008) to apply the update
    ///
    /// # Arguments
    ///
    /// * `username` - The account name to update.
    /// * `flags` - Bitflags to add to the existing account properties.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - The flags cannot be retrieved or converted
    /// - The update operation fails
    pub fn add_user_flags(
        &self,
        username: &str,
        flags: UserAccountFlags,
    ) -> Result<(), WindowsUsersError> {
        let current = self.get_user_flags(username)?;
        self.set_user_flags(username, current | flags)
    }

    /// Removes user account control flags (UF_*).
    ///
    /// This function retrieves the current account flags and removes the specified
    /// flags using a bitwise AND NOT operation. It allows disabling specific account
    /// properties without affecting others.
    ///
    /// Typical use cases include:
    /// - enabling an account
    /// - clearing "password never expires"
    /// - allowing the user to change their password
    ///
    /// Internally, this function:
    /// 1. Calls `NetUserGetInfo` (level 1) to retrieve current flags
    /// 2. Combines them with the provided flags using a bitwise AND NOT operation
    /// 3. Calls `NetUserSetInfo` (level 1008) to apply the update
    ///
    /// # Arguments
    ///
    /// * `username` - The account name to update.
    /// * `flags` - Bitflags to remove from the existing account properties.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - The flags cannot be retrieved or converted
    /// - The update operation fails
    pub fn remove_user_flags(
        &self,
        username: &str,
        flags: UserAccountFlags,
    ) -> Result<(), WindowsUsersError> {
        let current = self.get_user_flags(username)?;
        self.set_user_flags(username, current & !flags)
    }

    /// Sets the logon script path for a user.
    ///
    /// This function defines the script executed at user logon
    /// using `NetUserSetInfo` level 1009.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        script_path: &str,
    ) -> Result<(), WindowsUsersError> {
        let mut script_path_w = script_path.to_wide();

        let mut info = USER_INFO_1009 {
            usri1009_script_path: PWSTR(script_path_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the user's full display name.
    ///
    /// This updates the "Full Name" field visible in user management tools,
    /// using `NetUserSetInfo` level 1011.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        full_name: &str,
    ) -> Result<(), WindowsUsersError> {
        let mut full_name_w = full_name.to_wide();

        let mut info = USER_INFO_1011 {
            usri1011_full_name: PWSTR(full_name_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the user-specific comment field.
    ///
    /// This is distinct from the standard account comment and is stored
    /// in `usri1012_usr_comment`.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        usr_comment: &str,
    ) -> Result<(), WindowsUsersError> {
        let mut usr_comment_w = usr_comment.to_wide();

        let mut info = USER_INFO_1012 {
            usri1012_usr_comment: PWSTR(usr_comment_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
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
        &self,
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

        self.set_user_info(username, &mut info)
    }

    /// Sets the account expiration date.
    ///
    /// This function defines when the account becomes invalid using
    /// `NetUserSetInfo` level 1017.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        acct_expires: DateTime<Utc>,
    ) -> Result<(), WindowsUsersError> {
        let mut info = USER_INFO_1017 {
            usri1017_acct_expires: acct_expires.try_into_timestamp()?,
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets allowed logon hours for a user.
    ///
    /// This function restricts when a user can authenticate using
    /// `NetUserSetInfo` level 1020.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        units_per_week: u32,
        logon_hours: &[u8],
    ) -> Result<(), WindowsUsersError> {
        let mut info = USER_INFO_1020 {
            usri1020_units_per_week: units_per_week,
            usri1020_logon_hours: logon_hours.as_ptr().cast_mut(),
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the user's country or region code.
    ///
    /// This updates localization-related metadata using
    /// `NetUserSetInfo` level 1024.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        country_code: u32,
    ) -> Result<(), WindowsUsersError> {
        let mut info = USER_INFO_1024 {
            usri1024_country_code: country_code,
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the primary group RID for the user.
    ///
    /// This determines the user's primary group association
    /// using `NetUserSetInfo` level 1051.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        primary_group_id: u32,
    ) -> Result<(), WindowsUsersError> {
        let mut info = USER_INFO_1051 {
            usri1051_primary_group_id: primary_group_id,
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the user profile path.
    ///
    /// This function defines the profile directory location
    /// using `NetUserSetInfo` level 1052.
    ///
    /// # Arguments
    ///
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
    pub fn set_user_profile(&self, username: &str, profile: &str) -> Result<(), WindowsUsersError> {
        let mut profile_w = profile.to_wide();

        let mut info = USER_INFO_1052 {
            usri1052_profile: PWSTR(profile_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
    }

    /// Sets the drive letter assigned to the user's home directory.
    ///
    /// This function updates the drive mapping (e.g. "H:")
    /// using `NetUserSetInfo` level 1053.
    ///
    /// # Arguments
    ///
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
        &self,
        username: &str,
        home_dir_drive: &str,
    ) -> Result<(), WindowsUsersError> {
        let mut home_dir_drive_w = home_dir_drive.to_wide();

        let mut info = USER_INFO_1053 {
            usri1053_home_dir_drive: PWSTR(home_dir_drive_w.as_mut_ptr()),
        };

        self.set_user_info(username, &mut info)
    }
}

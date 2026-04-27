use windows::{
    Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetUserAdd, NetUserChangePassword, NetUserDel, NetUserGetInfo,
        USER_INFO_4,
    },
    core::PCWSTR,
};

use crate::{
    LogonHours, User, UserManager, UserUpdate,
    error::WindowsUsersError,
    utils::{ToWideString, net_api_result, net_api_result_with_index},
};

pub mod update_ops;

impl UserManager {
    /// Adds a new user to the local machine.
    ///
    /// This function creates a local account from the provided [`User`] payload
    /// using `NetUserAdd` level 4.
    ///
    /// # Arguments
    ///
    /// * `user` - The user definition to create.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the account is created successfully.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The account creation API call fails (`NetUserAdd`)
    /// - A provided field is invalid
    /// - The account already exists
    /// - The caller does not have sufficient privileges
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn add_user(&self, user: &User) -> Result<(), WindowsUsersError> {
        let server_name_p = self.server;

        let mut info = user.to_user_info_4();

        let mut parm_err = 0;

        let status = unsafe {
            NetUserAdd(
                server_name_p,
                4,
                std::ptr::from_mut::<USER_INFO_4>(&mut info.user_info) as *const u8,
                Some(&raw mut parm_err),
            )
        };

        net_api_result_with_index(status, parm_err)?;

        Ok(())
    }

    /// Adds a user only if it does not already exist.
    ///
    /// This function checks whether the user already exists on the target machine.
    /// If the user is found, the function does nothing and returns `Ok(false)`.
    /// Otherwise, it creates the account using [`add_user`] and returns `Ok(true)`.
    ///
    /// # Arguments
    ///
    /// * `user` - The user definition to create if absent.
    ///
    /// # Returns
    ///
    /// Returns:
    /// - `Ok(true)` if the user was created
    /// - `Ok(false)` if the user already existed and no action was taken
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The existence check fails unexpectedly (rare, see notes below)
    /// - The account creation fails (`NetUserAdd`)
    /// - The caller does not have sufficient privileges
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges** when creating the user.
    pub fn add_user_if_not_exists(&self, user: &User) -> Result<bool, WindowsUsersError> {
        if self.user_exists(user.name()) {
            Ok(false)
        } else {
            self.add_user(user)?;
            Ok(true)
        }
    }

    /// Ensures that a user exists and matches the provided definition.
    ///
    /// This function implements a **create-or-update** behavior:
    ///
    /// - If the user does not exist, it is created using [`add_user`]
    /// - If the user already exists, it is updated using [`update_user`]
    ///
    /// # Arguments
    ///
    /// * `user` - The desired user state
    ///
    /// # Returns
    ///
    /// Returns:
    /// - `Ok(true)` if the user was created
    /// - `Ok(false)` if the user already existed and was updated
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The update operation fails (`NetUserSetInfo`, group updates, etc.)
    /// - The creation operation fails (`NetUserAdd`)
    /// - The caller does not have sufficient privileges
    ///
    /// # Behavior
    ///
    /// This function is **idempotent**: calling it multiple times with the same
    /// input should converge to the same user state.
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges** for both creation and update operations.
    pub fn add_user_or_update(&self, user: &User) -> Result<bool, WindowsUsersError> {
        if self.user_exists(user.name()) {
            self.update_user(user.name(), &UserUpdate::from(user.clone()))?;
            Ok(false)
        } else {
            self.add_user(user)?;
            Ok(true)
        }
    }

    /// Deletes a user from the local machine.
    ///
    /// This function removes an existing local account identified by `username`
    /// using `NetUserDel`.
    ///
    /// # Arguments
    ///
    /// * `username` - The account name to delete.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the account is deleted successfully.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - The deletion API call fails (`NetUserDel`)
    /// - The caller does not have sufficient privileges
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn delete_user(&self, username: &str) -> Result<(), WindowsUsersError> {
        let server_name = self.server;

        let username_w = username.to_wide();

        let status = unsafe { NetUserDel(server_name, PCWSTR(username_w.as_ptr())) };

        net_api_result(status)
    }

    /// Changes a user's password on the local machine.
    ///
    /// This function changes the password of `username` by validating
    /// `old_password` and replacing it with `new_password`.
    ///
    /// # Arguments
    ///
    /// * `username` - The target account name.
    /// * `old_password` - The current password used for validation.
    /// * `new_password` - The new password to set.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the password is changed successfully.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The username or old password is incorrect
    /// - The new password does not satisfy policy constraints
    /// - The API call fails (`NetUserChangePassword`)
    ///
    /// # Security
    ///
    /// Does not necessarily require administrative privileges when changing
    /// the caller's own password with valid credentials.
    pub fn change_user_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WindowsUsersError> {
        let server_name = self.server;

        let username_w = username.to_wide();
        let old_pw_w = old_password.to_wide();
        let new_pw_w = new_password.to_wide();

        let status = unsafe {
            NetUserChangePassword(
                server_name,
                PCWSTR(username_w.as_ptr()),
                PCWSTR(old_pw_w.as_ptr()),
                PCWSTR(new_pw_w.as_ptr()),
            )
        };

        net_api_result(status)
    }

    /// Updates an existing user on the local machine.
    ///
    /// This function updates account properties for `username` with a full
    /// `USER_INFO_4` payload generated from [`UserUpdate`].
    ///
    /// # Arguments
    ///
    /// * `username` - The account name to update.
    /// * `settings` - The update payload applied to the target account.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the update succeeds.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - One or more fields are invalid
    /// - The update API call fails (`NetUserSetInfo`)
    /// - The caller does not have sufficient privileges
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn update_user(
        &self,
        username: &str,
        settings: &UserUpdate,
    ) -> Result<(), WindowsUsersError> {
        if let Some(ref password) = settings.password {
            self.set_user_password(username, password)?;
        }

        if let Some(ref home_dir) = settings.home_dir {
            self.set_user_home_directory(username, home_dir)?;
        }

        if let Some(ref comment) = settings.comment {
            self.set_user_comment(username, comment)?;
        }

        if let Some(flags) = settings.flags {
            self.set_user_flags(username, flags)?;
        }

        if let Some(ref script_path) = settings.script_path {
            self.set_user_script_path(username, script_path)?;
        }

        if let Some(ref full_name) = settings.full_name {
            self.set_user_full_name(username, full_name)?;
        }

        if let Some(ref user_comment) = settings.user_comment {
            self.set_user_user_comment(username, user_comment)?;
        }

        if let Some(ref workstations) = settings.workstations {
            self.set_user_workstations(username, workstations)?;
        }

        if let Some(acct_expires) = settings.acct_expires {
            self.set_user_account_expiration(username, acct_expires)?;
        }

        if let Some(ref logon_hours) = settings.logon_hours {
            self.set_user_logon_hours(
                username,
                LogonHours::UNITS_PER_WEEK,
                logon_hours.clone().as_bytes(),
            )?;
        }

        if let Some(country_code) = settings.country_code {
            self.set_user_country_code(username, country_code)?;
        }

        if let Some(primary_group_id) = settings.primary_group_id {
            self.set_user_primary_group(username, primary_group_id)?;
        }

        if let Some(ref profile) = settings.profile {
            self.set_user_profile(username, profile)?;
        }

        if let Some(ref home_dir_drive) = settings.home_dir_drive {
            self.set_user_home_dir_drive(username, home_dir_drive)?;
        }

        if let Some(ref name) = settings.name {
            self.set_user_name(username, name)?;
        }

        Ok(())
    }

    /// Gets a single user from the local machine.
    ///
    /// This function retrieves a local account by name using `NetUserGetInfo`
    /// level 4 and converts it into a [`User`] value.
    ///
    /// # Arguments
    ///
    /// * `username` - The account name to retrieve.
    ///
    /// # Returns
    ///
    /// Returns the fetched [`User`] on success.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - The API call fails (`NetUserGetInfo`)
    /// - Returned data cannot be converted into [`User`]
    pub fn get_user(&self, username: &str) -> Result<User, WindowsUsersError> {
        let server_name = self.server;

        let username_w = username.to_wide();

        let mut buffer = std::ptr::null_mut();

        let status =
            unsafe { NetUserGetInfo(server_name, PCWSTR(username_w.as_ptr()), 4, &raw mut buffer) };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status)?;

        let user = unsafe {
            let ui4 = &*(buffer as *const USER_INFO_4);
            User::try_from(ui4)?
        };

        Ok(user)
    }

    /// Checks if a user exists on the local machine.
    ///
    /// This function queries `NetUserGetInfo` level 0 and maps success to `true`.
    /// Any failure is interpreted as `false`.
    ///
    /// # Arguments
    ///
    /// * `username` - The account name to probe.
    ///
    /// # Returns
    ///
    /// Returns `true` if the user can be retrieved, otherwise `false`.
    ///
    /// # Errors
    ///
    /// This function does not return errors directly.
    pub fn user_exists(&self, username: &str) -> bool {
        let server_name = self.server;

        let username_w = username.to_wide();

        let mut buffer = std::ptr::null_mut();

        let status =
            unsafe { NetUserGetInfo(server_name, PCWSTR(username_w.as_ptr()), 0, &raw mut buffer) };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status).is_ok()
    }
}

use crate::error::WindowsUsersError;
use crate::{User, UserAccountFlags, UserManager, UserUpdate};

impl User {
    /// Adds a new user to the local machine.
    ///
    /// This function creates a local account from the provided [`User`] payload
    /// using `NetUserAdd` level 4.
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
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
    pub fn add(&self, mgr: &UserManager) -> Result<(), WindowsUsersError> {
        mgr.add_user(self)
    }

    /// Adds a user only if it does not already exist.
    ///
    /// This function checks whether the user already exists on the target machine.
    /// If the user is found, the function does nothing and returns `Ok(false)`.
    /// Otherwise, it creates the account using [`UserManager::add_user`] and returns `Ok(true)`.
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
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
    pub fn add_if_not_exists(&self, mgr: &UserManager) -> Result<bool, WindowsUsersError> {
        mgr.add_user_if_not_exists(self)
    }

    /// Ensures that a user exists and matches the provided definition.
    ///
    /// This function implements a **create-or-update** behavior:
    ///
    /// - If the user does not exist, it is created using [`UserManager::add_user`]
    /// - If the user already exists, it is updated using [`UserManager::update_user`]
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
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
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges** for both creation and update operations.
    pub fn add_or_update(&self, mgr: &UserManager) -> Result<bool, WindowsUsersError> {
        mgr.add_user_or_update(self)
    }

    /// Deletes a user from the local machine.
    ///
    /// This function removes an existing local account identified by `username`
    /// using `NetUserDel`.
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
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
    pub fn delete(self, mgr: &UserManager) -> Result<(), WindowsUsersError> {
        mgr.delete_user(&self.name)?;
        Ok(())
    }

    /// Updates an existing user on the local machine.
    ///
    /// This function updates account properties for `username` with a full
    /// `USER_INFO_4` payload generated from [`UserUpdate`].
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
    /// * `settings` - A reference to [`UserUpdate`] containing updated values.
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
    pub fn update(
        &mut self,
        mgr: &UserManager,
        settings: &UserUpdate,
    ) -> Result<(), WindowsUsersError> {
        mgr.update_user(&self.name, settings)?;

        if let Some(name) = &settings.name {
            self.name.clone_from(name);
        }
        if let Some(password) = &settings.password {
            self.password = Some(password.clone());
        }
        if let Some(home_dir) = &settings.home_dir {
            self.home_dir = Some(home_dir.clone());
        }
        if let Some(comment) = &settings.comment {
            self.comment = Some(comment.clone());
        }
        if let Some(flags) = &settings.flags {
            self.flags = *flags;
        }
        if let Some(script_path) = &settings.script_path {
            self.script_path = Some(script_path.clone());
        }
        if let Some(full_name) = &settings.full_name {
            self.full_name = Some(full_name.clone());
        }
        if let Some(user_comment) = &settings.user_comment {
            self.user_comment = Some(user_comment.clone());
        }
        if let Some(workstations) = &settings.workstations {
            self.workstations = Some(workstations.clone());
        }
        if let Some(acct_expires) = &settings.acct_expires {
            self.acct_expires = Some(*acct_expires);
        }
        if let Some(logon_hours) = &settings.logon_hours {
            self.logon_hours = Some(logon_hours.clone());
        }
        if let Some(country_code) = &settings.country_code {
            self.country_code = Some(*country_code);
        }
        if let Some(profile) = &settings.profile {
            self.profile = Some(profile.clone());
        }
        if let Some(home_dir_drive) = &settings.home_dir_drive {
            self.home_dir_drive = Some(home_dir_drive.clone());
        }

        Ok(())
    }

    /// Checks if a user exists on the local machine.
    ///
    /// This function queries `NetUserGetInfo` level 0 and maps success to `true`.
    /// Any failure is interpreted as `false`.
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
    ///
    /// # Returns
    ///
    /// Returns `true` if the user can be retrieved, otherwise `false`.
    ///
    /// # Errors
    ///
    /// This function does not return errors directly.
    pub fn exists(&self, mgr: &UserManager) -> bool {
        mgr.user_exists(&self.name)
    }

    /// Enables or disables a user account.
    ///
    /// This function toggles the `ACCOUNTDISABLE` flag depending on the value
    /// of `enable`:
    ///
    /// - `true`  → removes the flag (account is enabled)
    /// - `false` → sets the flag (account is disabled)
    ///
    /// # Arguments
    ///
    /// * `mgr` - The [`UserManager`] used to perform the operation (defines the target server).
    /// * `enable` - Whether the account should be enabled.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - The update operation fails
    pub fn enable(&mut self, mgr: &UserManager, enable: bool) -> Result<(), WindowsUsersError> {
        mgr.enable_user(&self.name, enable)?;
        self.flags.set(UserAccountFlags::ACCOUNTDISABLE, !enable);
        Ok(())
    }
}

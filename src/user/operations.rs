use crate::error::WindowsUsersError;
use crate::user_ops::{add_user_if_not_exists, add_user_or_update};
use crate::{User, UserUpdate, add_user, delete_user, update_user, user_exists};

impl User {
    /// Creates and registers an account from the current instance's properties.
    ///
    /// # Arguments
    ///
    /// * `server_name` - Optional target server. If `None`, the local machine is used.
    ///
    /// # Returns
    ///
    /// Returns a [`Result<(), WindowsUsersError>`]. If the user is successfully created,
    /// it returns `Ok(())`. Otherwise, it returns a [`WindowsUsersError`].
    ///
    /// # Errors
    ///
    /// May return a [`WindowsUsersError`] if there is a failure during:
    /// - Windows API call (`NetUserAdd`)
    /// - Invalid parameters
    /// - Permission issues
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn add(&self, server_name: Option<&str>) -> Result<(), WindowsUsersError> {
        add_user(server_name, self)
    }

    /// Adds a user only if it does not already exist.
    ///
    /// This function checks whether the user already exists on the target machine.
    /// If the user is found, the function does nothing and returns `Ok(false)`.
    /// Otherwise, it creates the account using [`add_user`] and returns `Ok(true)`.
    ///
    /// # Arguments
    ///
    /// * `server_name` - Optional target server. If `None`, the local machine is used.
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
    pub fn add_if_not_exists(&self, server_name: Option<&str>) -> Result<bool, WindowsUsersError> {
        add_user_if_not_exists(server_name, self)
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
    /// * `server_name` - Optional target server. If `None`, the local machine is used.
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
    pub fn add_or_update(&self, server_name: Option<&str>) -> Result<bool, WindowsUsersError> {
        add_user_or_update(server_name, self)
    }

    /// Removes the user identified by [`User::name`].
    ///
    /// # Arguments
    ///
    /// * `server_name` - Optional target server. If `None`, the local machine is used.
    ///
    /// # Returns
    ///
    /// Returns a [`Result<(), WindowsUsersError>`]. If the user is successfully deleted,
    /// it returns `Ok(())`. Otherwise, it returns a [`WindowsUsersError`].
    ///
    /// # Errors
    ///
    /// May return a [`WindowsUsersError`] if there is a failure during:
    /// - Windows API call (`NetUserDel`)
    /// - User not found
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn delete(self, server_name: Option<&str>) -> Result<(), WindowsUsersError> {
        delete_user(server_name, &self.name)?;
        Ok(())
    }

    /// Modifies an existing account using the provided [`UserUpdate`] struct.
    /// After a successful update, the current instance is also updated to reflect the changes.
    ///
    /// # Arguments
    ///
    /// * `server_name` - Optional target server. If `None`, the local machine is used.
    /// * `settings` - A reference to [`UserUpdate`] containing updated values.
    ///
    /// # Returns
    ///
    /// Returns a [`Result<(), WindowsUsersError>`]. If the update succeeds,
    /// it returns `Ok(())`. Otherwise, it returns a [`WindowsUsersError`].
    ///
    /// # Errors
    ///
    /// May return a [`WindowsUsersError`] if there is a failure during:
    /// - Windows API call (`NetUserSetInfo`)
    /// - Invalid fields
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn update(
        &mut self,
        server_name: Option<&str>,
        settings: &UserUpdate,
    ) -> Result<(), WindowsUsersError> {
        update_user(server_name, &self.name, settings)?;

        if let Some(name) = &settings.name {
            self.name = name.clone();
        }
        if let Some(password) = &settings.password {
            self.password = Some(password.clone());
        }
        // if let Some(priv_level) = &settings.priv_level {
        //     self.priv_level = *priv_level;
        // }
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
        // if let Some(auth_flags) = &settings.auth_flags {
        //     self.auth_flags = Some(*auth_flags);
        // }
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

    /// Checks whether this user exists on the system.
    ///
    /// # Arguments
    ///
    /// * `server_name` - Optional target server. If `None`, the local machine is used.
    ///
    /// # Returns
    ///
    /// Returns `true` if the user exists, otherwise `false`.
    ///
    /// # Errors
    ///
    /// Does not return errors. Failures are interpreted as "user does not exist".
    pub fn exists(&self, server_name: Option<&str>) -> bool {
        user_exists(server_name, &self.name)
    }
}

use windows_users::{User, WindowsUsersError};

#[must_use]
pub struct AutoRemoveUserResult {
    pub _guard: AutoRemoveUser,
    pub added_or_changed: bool,
}

impl AutoRemoveUser {
    fn make_result(
        server_name: Option<&str>,
        user: &User,
        should_remove: bool,
    ) -> AutoRemoveUserResult {
        assert!(
            user.exists(server_name),
            "User should exist after operation"
        );

        AutoRemoveUserResult {
            _guard: AutoRemoveUser {
                server_name: server_name.map(|s| s.into()),
                user: user.clone(),
                should_remove,
            },
            added_or_changed: should_remove,
        }
    }
}

pub struct AutoRemoveUser {
    pub server_name: Option<String>,
    pub user: User,
    should_remove: bool,
}

impl Drop for AutoRemoveUser {
    fn drop(&mut self) {
        if self.should_remove {
            self.user
                .clone()
                .delete(self.server_name.as_deref())
                .unwrap_or_else(|_| panic!("Failed to remove user '{}'", self.user.name()));
        }
    }
}

impl AutoRemoveUser {
    pub fn add(
        server_name: Option<&str>,
        user: &User,
    ) -> Result<AutoRemoveUserResult, WindowsUsersError> {
        user.add(server_name)?;

        Ok(Self::make_result(server_name, user, true))
    }

    pub fn add_if_not_exists(
        server_name: Option<&str>,
        user: &User,
    ) -> Result<AutoRemoveUserResult, WindowsUsersError> {
        let added = user.add_if_not_exists(server_name)?;

        Ok(Self::make_result(server_name, user, added))
    }

    pub fn add_or_update(
        server_name: Option<&str>,
        user: &User,
    ) -> Result<AutoRemoveUserResult, WindowsUsersError> {
        let changed = user.add_or_update(server_name)?;

        Ok(Self::make_result(server_name, user, changed))
    }
}

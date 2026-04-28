use windows_users::{User, UserManager, UserUpdate, WindowsUsersError};

#[must_use]
pub struct AutoRemoveUserResult<'a> {
    pub _guard: AutoRemoveUser<'a>,
    pub added_or_changed: bool,
}

impl<'a> AutoRemoveUser<'a> {
    fn make_result(
        mgr: &'a UserManager,
        user: &User,
        should_remove: bool,
    ) -> AutoRemoveUserResult<'a> {
        assert!(user.exists(mgr), "User should exist after operation");

        AutoRemoveUserResult {
            _guard: AutoRemoveUser {
                mgr,
                user: user.clone(),
                should_remove,
            },
            added_or_changed: should_remove,
        }
    }
}

pub struct AutoRemoveUser<'a> {
    mgr: &'a UserManager,
    user: User,
    should_remove: bool,
}

impl Drop for AutoRemoveUser<'_> {
    fn drop(&mut self) {
        if self.should_remove {
            self.user
                .clone()
                .delete(self.mgr)
                .unwrap_or_else(|_| panic!("Failed to remove user '{}'", self.user.name()));
        }
    }
}

impl<'a> AutoRemoveUser<'a> {
    pub fn add(
        mgr: &'a UserManager,
        user: &User,
    ) -> Result<AutoRemoveUserResult<'a>, WindowsUsersError> {
        user.add(mgr)?;
        Ok(Self::make_result(mgr, user, true))
    }

    pub fn add_if_not_exists(
        mgr: &'a UserManager,
        user: &User,
    ) -> Result<AutoRemoveUserResult<'a>, WindowsUsersError> {
        let added = user.add_if_not_exists(mgr)?;

        Ok(Self::make_result(mgr, user, added))
    }

    pub fn add_or_update(
        mgr: &'a UserManager,
        user: &User,
    ) -> Result<AutoRemoveUserResult<'a>, WindowsUsersError> {
        let changed = user.add_or_update(mgr)?;

        Ok(Self::make_result(mgr, user, changed))
    }
}

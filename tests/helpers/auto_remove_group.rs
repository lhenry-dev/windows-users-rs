use windows_users::{Group, UserManager, WindowsUsersError};

#[must_use]
pub struct AutoRemoveGroupResult<'a> {
    pub _guard: AutoRemoveGroup<'a>,
}

impl<'a> AutoRemoveGroup<'a> {
    fn make_result(
        mgr: &'a UserManager,
        group: &Group,
        should_remove: bool,
    ) -> AutoRemoveGroupResult<'a> {
        assert!(
            mgr.group_exists(group.name()),
            "Group should exist after operation"
        );

        AutoRemoveGroupResult {
            _guard: AutoRemoveGroup {
                mgr,
                group: group.clone(),
                should_remove,
            },
        }
    }
}

pub struct AutoRemoveGroup<'a> {
    mgr: &'a UserManager,
    group: Group,
    should_remove: bool,
}

impl Drop for AutoRemoveGroup<'_> {
    fn drop(&mut self) {
        if self.should_remove {
            self.mgr
                .delete_group(self.group.name())
                .unwrap_or_else(|_| panic!("Failed to remove group '{}'", self.group.name()));
        }
    }
}

impl<'a> AutoRemoveGroup<'a> {
    pub fn add(
        mgr: &'a UserManager,
        group: &Group,
    ) -> Result<AutoRemoveGroupResult<'a>, WindowsUsersError> {
        mgr.create_group(group)?;
        Ok(Self::make_result(mgr, group, true))
    }
}

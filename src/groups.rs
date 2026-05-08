use windows::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_2, NetLocalGroupAdd,
    NetLocalGroupDel, NetLocalGroupEnum, NetLocalGroupGetInfo, NetLocalGroupGetMembers,
    NetLocalGroupSetInfo, NetUserGetLocalGroups,
};
use windows::{
    Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_MEMBERS_INFO_3, NetApiBufferFree, NetLocalGroupAddMembers,
        NetLocalGroupDelMembers,
    },
    core::{PCWSTR, PWSTR},
};

use crate::error::WindowsUsersError;
use crate::user::types::InvalidUserProperty;
use crate::utils::{ToWideString, ToWideStringOption, net_api_result, net_api_result_with_index};

use crate::UserManager;
pub use crate::groups::types::{Group, GroupMember};

pub mod sid;
mod types;

impl UserManager {
    /// Lists all local groups on the machine.
    ///
    /// This function enumerates local groups with `NetLocalGroupEnum` level 1
    /// and converts each row into a [`Group`].
    ///
    /// # Returns
    ///
    /// Returns a vector containing all local groups returned by the enumeration call.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The enumeration API call fails (`NetLocalGroupEnum`)
    /// - Any returned entry cannot be converted into [`Group`]
    pub fn list_groups(&self) -> Result<Vec<Group>, WindowsUsersError> {
        let server_name = self.server;

        let mut buffer = std::ptr::null_mut();
        let mut entries_read = 0;
        let mut total_entries = 0;
        let mut resume_handle = 0;

        let status = unsafe {
            NetLocalGroupEnum(
                server_name,
                1,
                &raw mut buffer,
                u32::MAX,
                &raw mut entries_read,
                &raw mut total_entries,
                Some(&raw mut resume_handle),
            )
        };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status)?;

        if entries_read == 0 || buffer.is_null() {
            return Ok(Vec::new());
        }

        let groups = unsafe {
            std::slice::from_raw_parts(buffer as *const LOCALGROUP_INFO_1, entries_read as usize)
                .iter()
                .map(Group::try_from)
                .collect::<Result<Vec<_>, _>>()
        }?;

        Ok(groups)
    }

    /// Lists members belonging to a local group.
    ///
    /// This function fetches the membership of `group` with
    /// `NetLocalGroupGetMembers` level 2 and converts each row into a [`GroupMember`].
    ///
    /// # Arguments
    /// * `group` - The local group name whose members should be listed.
    ///
    /// # Returns
    ///
    /// Returns a vector of members for the target group.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The target group does not exist
    /// - The API call fails (`NetLocalGroupGetMembers`)
    /// - Any returned entry cannot be converted into [`GroupMember`]
    pub fn list_group_members(&self, group: &str) -> Result<Vec<GroupMember>, WindowsUsersError> {
        let server_name = self.server;

        let group_w = group.to_wide();

        let mut buffer = std::ptr::null_mut();
        let mut entries_read = 0;
        let mut total_entries = 0;
        let mut resume_handle = 0;

        let status = unsafe {
            NetLocalGroupGetMembers(
                server_name,
                PCWSTR(group_w.as_ptr()),
                2,
                &raw mut buffer,
                u32::MAX,
                &raw mut entries_read,
                &raw mut total_entries,
                Some(&raw mut resume_handle),
            )
        };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status)?;

        if entries_read == 0 || buffer.is_null() {
            return Ok(Vec::new());
        }

        let members = unsafe {
            std::slice::from_raw_parts(
                buffer as *const LOCALGROUP_MEMBERS_INFO_2,
                entries_read as usize,
            )
            .iter()
            .map(GroupMember::try_from)
            .collect::<Result<Vec<_>, _>>()
        }?;

        Ok(members)
    }

    /// Lists local groups that a user belongs to.
    ///
    /// This function retrieves the set of local groups for `username`
    /// using `NetUserGetLocalGroups` level 0.
    ///
    /// Both direct and indirect group memberships are included
    /// (via `LG_INCLUDE_INDIRECT`), meaning:
    /// - groups the user is explicitly a member of
    /// - groups inherited through nested memberships
    ///
    /// # Arguments
    ///
    /// * `username` - The account name whose group memberships should be listed.
    ///
    /// # Returns
    ///
    /// Returns a vector of group names the user belongs to.
    ///
    /// If the user is not a member of any group, an empty vector is returned.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user does not exist
    /// - The API call fails (`NetUserGetLocalGroups`)
    pub fn list_user_groups(&self, username: &str) -> Result<Vec<String>, WindowsUsersError> {
        let server_name = self.server;

        let username_w = username.to_wide();

        let mut buffer = std::ptr::null_mut();
        let mut entries_read = 0;
        let mut total_entries = 0;

        let status = unsafe {
            NetUserGetLocalGroups(
                server_name,
                PCWSTR(username_w.as_ptr()),
                0,
                LG_INCLUDE_INDIRECT,
                &raw mut buffer,
                u32::MAX,
                &raw mut entries_read,
                &raw mut total_entries,
            )
        };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status)?;

        if entries_read == 0 || buffer.is_null() {
            return Ok(Vec::new());
        }

        let groups = unsafe {
            std::slice::from_raw_parts(buffer as *const LOCALGROUP_INFO_1, entries_read as usize)
                .iter()
                .filter_map(|group_info| group_info.lgrpi1_name.to_string().ok())
                .collect()
        };

        Ok(groups)
    }

    /// Adds users to a local group on the machine.
    ///
    /// This function adds `usernames` to `group` using `NetLocalGroupAddMembers`
    /// with `LOCALGROUP_MEMBERS_INFO_3`.
    ///
    /// # Arguments
    /// * `usernames` - Slice of user accounts to add to the group.
    /// * `group` - Target local group name.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the membership is added successfully.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user or group does not exist
    /// - The user is already a member
    /// - The API call fails (`NetLocalGroupAddMembers`)
    /// - The caller does not have sufficient privileges
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn add_users_to_group(
        &self,
        usernames: &[&str],
        group: &str,
    ) -> Result<(), WindowsUsersError> {
        let server_name = self.server;

        let group_w = group.to_wide();
        let mut users_w: Vec<Vec<u16>> = usernames.iter().map(|u| u.to_wide()).collect();

        let members: Vec<LOCALGROUP_MEMBERS_INFO_3> = users_w
            .iter_mut()
            .map(|u| LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: PWSTR(u.as_mut_ptr()),
            })
            .collect();

        let status = unsafe {
            NetLocalGroupAddMembers(
                server_name,
                PCWSTR(group_w.as_ptr()),
                3,
                members.as_ptr().cast::<u8>(),
                u32::try_from(members.len())
                    .map_err(|_| InvalidUserProperty::InvalidGroupMembersLen(members.len()))?,
            )
        };

        net_api_result(status)
    }

    /// Removes users from a local group on the machine.
    ///
    /// This function removes `usernames` from `group` using `NetLocalGroupDelMembers`
    /// with `LOCALGROUP_MEMBERS_INFO_3`.
    ///
    /// # Arguments
    /// * `usernames` - Slice of user accounts to remove from the group.
    /// * `group` - Target local group name.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the membership is removed successfully.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The user or group does not exist
    /// - The user is not a member of the group
    /// - The API call fails (`NetLocalGroupDelMembers`)
    /// - The caller does not have sufficient privileges
    ///
    /// # Security
    ///
    /// ⚠️ Requires **administrative privileges**.
    pub fn remove_users_from_group(
        &self,
        usernames: &[&str],
        group: &str,
    ) -> Result<(), WindowsUsersError> {
        let server_name = self.server;

        let group_w = group.to_wide();
        let mut users_w: Vec<Vec<u16>> = usernames.iter().map(|u| u.to_wide()).collect();

        let members: Vec<LOCALGROUP_MEMBERS_INFO_3> = users_w
            .iter_mut()
            .map(|u| LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: PWSTR(u.as_mut_ptr()),
            })
            .collect();

        let status = unsafe {
            NetLocalGroupDelMembers(
                server_name,
                PCWSTR(group_w.as_ptr()),
                3,
                members.as_ptr().cast::<u8>(),
                u32::try_from(members.len())
                    .map_err(|_| InvalidUserProperty::InvalidGroupMembersLen(members.len()))?,
            )
        };

        net_api_result(status)
    }

    /// Creates a local group on the target machine.
    ///
    /// This function uses the Windows `NetLocalGroupAdd` API to create a new
    /// local security group.
    ///
    /// # Arguments
    ///
    /// * `group` - The group definition to create.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the group is successfully created.
    ///
    /// # Errors
    ///
    /// Returns `WindowsUsersError` if:
    /// - The group already exists
    /// - The API call fails (`NetLocalGroupAdd`)
    /// - Invalid group data is provided
    pub fn create_group(&self, group: &Group) -> Result<(), WindowsUsersError> {
        let group_name = group.name().to_wide();
        let comment_wide = group.comment().to_wide_option();

        let group_info = LOCALGROUP_INFO_1 {
            lgrpi1_name: PWSTR(group_name.as_ptr() as _),
            lgrpi1_comment: comment_wide
                .as_ref()
                .map(|v| PWSTR(v.as_ptr() as _))
                .unwrap_or(PWSTR::null()),
        };

        let mut parm_err = 0;

        let status = unsafe {
            NetLocalGroupAdd(
                self.server,
                1,
                &group_info as *const _ as _,
                Some(&raw mut parm_err),
            )
        };

        net_api_result_with_index(status, parm_err)?;

        Ok(())
    }

    /// Deletes a local group from the target machine.
    ///
    /// This function uses the Windows `NetLocalGroupDel` API to remove a local
    /// security group.
    ///
    /// # Arguments
    ///
    /// * `group_name` - The name of the group to delete.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the group is successfully deleted.
    ///
    /// # Errors
    ///
    /// Returns `WindowsUsersError` if:
    /// - The group does not exist
    /// - The API call fails (`NetLocalGroupDel`)
    /// - The caller lacks required privileges
    pub fn delete_group(&self, group_name: &str) -> Result<(), WindowsUsersError> {
        let group_name_w = group_name.to_wide();

        let status = unsafe { NetLocalGroupDel(self.server, PCWSTR(group_name_w.as_ptr())) };

        net_api_result(status)
    }

    /// Retrieves a local group from the machine.
    ///
    /// This function queries the Windows local group database using
    /// `NetLocalGroupGetInfo` level 1 and converts the result into a [`Group`].
    ///
    /// # Arguments
    ///
    /// * `group_name` - The name of the group to retrieve.
    ///
    /// # Returns
    ///
    /// Returns the [`Group`] if the group exists.
    ///
    /// # Errors
    ///
    /// Returns a [`WindowsUsersError`] if:
    /// - The group does not exist
    /// - The API call fails (`NetLocalGroupGetInfo`)
    /// - The returned data cannot be converted into [`Group`]
    pub fn get_group(&self, group_name: &str) -> Result<Group, WindowsUsersError> {
        let server_name = self.server;
        let group_name_w = group_name.to_wide();

        let mut buffer = std::ptr::null_mut();

        let status = unsafe {
            NetLocalGroupGetInfo(
                server_name,
                PCWSTR(group_name_w.as_ptr()),
                1,
                &raw mut buffer,
            )
        };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status)?;

        let group = unsafe {
            let info = &*(buffer as *const LOCALGROUP_INFO_1);
            Group::try_from(info)?
        };

        Ok(group)
    }

    /// Checks if a local group exists on the machine.
    ///
    /// This function queries the local group database using
    /// `NetLocalGroupGetInfo` level 1.
    ///
    /// Any successful retrieval means the group exists.
    /// Any failure is interpreted as non-existence or inaccessible group.
    ///
    /// # Arguments
    ///
    /// * `group_name` - The name of the group to check.
    ///
    /// # Returns
    ///
    /// Returns:
    /// - `true` if the group exists
    /// - `false` if the group does not exist or cannot be accessed
    ///
    /// # Notes
    ///
    /// This function does not allocate or convert group data,
    /// it only checks for existence.
    pub fn group_exists(&self, group_name: &str) -> bool {
        let server_name = self.server;

        let group_name_w = group_name.to_wide();

        let mut buffer = std::ptr::null_mut();

        let status = unsafe {
            NetLocalGroupGetInfo(
                server_name,
                PCWSTR(group_name_w.as_ptr()),
                1,
                &raw mut buffer,
            )
        };

        let _guard = scopeguard::guard(buffer, |buf| {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf.cast())) };
            }
        });

        net_api_result(status).is_ok()
    }

    /// Updates an existing local group on the machine.
    ///
    /// This function updates a local security group using
    /// `NetLocalGroupSetInfo` level 1.
    ///
    /// Only the fields provided in [`Group`] are applied.
    ///
    /// # Arguments
    ///
    /// * `group` - The group definition containing updated values.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the group is successfully updated.
    ///
    /// # Errors
    ///
    /// Returns `WindowsUsersError` if:
    /// - The group does not exist
    /// - The API call fails (`NetLocalGroupSetInfo`)
    /// - Invalid group data is provided
    pub fn update_group(&self, group: &Group) -> Result<(), WindowsUsersError> {
        let group_name = group.name().to_wide();
        let comment_wide = group.comment().to_wide_option();

        let group_info = LOCALGROUP_INFO_1 {
            lgrpi1_name: PWSTR(group_name.as_ptr() as _),
            lgrpi1_comment: comment_wide
                .as_ref()
                .map(|v| PWSTR(v.as_ptr() as _))
                .unwrap_or(PWSTR::null()),
        };

        let mut parm_err = 0;

        let status = unsafe {
            NetLocalGroupSetInfo(
                self.server,
                PCWSTR(group_name.as_ptr()),
                1,
                &group_info as *const _ as _,
                Some(&raw mut parm_err),
            )
        };

        net_api_result_with_index(status, parm_err)?;

        Ok(())
    }
}

use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_2, NetLocalGroupEnum, NetLocalGroupGetMembers,
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
use crate::utils::{ToWideString, net_api_result};

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
}

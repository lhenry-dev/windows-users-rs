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

use crate::utils::net_api_result;
use crate::{error::WindowsUsersError, utils::to_wide};

pub use crate::groups::types::{Group, GroupMember};

pub mod sid;
mod types;

/// Lists all local groups on the machine.
///
/// This function enumerates local groups with `NetLocalGroupEnum` level 1
/// and converts each row into a [`Group`].
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
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
pub fn list_groups(server_name: Option<&str>) -> Result<Vec<Group>, WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(to_wide(s).as_ptr()))
        .unwrap_or_default();

    let mut buffer = std::ptr::null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;
    let mut resume_handle = 0;

    let status = unsafe {
        NetLocalGroupEnum(
            server_name,
            1,
            &mut buffer,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            Some(&mut resume_handle),
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
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
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
pub fn list_group_members(
    server_name: Option<&str>,
    group: &str,
) -> Result<Vec<GroupMember>, WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(to_wide(s).as_ptr()))
        .unwrap_or_default();

    let group_w = to_wide(group);

    let mut buffer = std::ptr::null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;
    let mut resume_handle = 0;

    let status = unsafe {
        NetLocalGroupGetMembers(
            server_name,
            PCWSTR(group_w.as_ptr()),
            2,
            &mut buffer,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            Some(&mut resume_handle),
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

/// Adds a user to a local group on the machine.
///
/// This function adds `username` to `group` using `NetLocalGroupAddMembers`
/// with `LOCALGROUP_MEMBERS_INFO_3`.
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
/// * `username` - User account to add to the group.
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
pub fn add_user_to_group(
    server_name: Option<&str>,
    username: &str,
    group: &str,
) -> Result<(), WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(to_wide(s).as_ptr()))
        .unwrap_or_default();

    let mut user_w = to_wide(username);
    let group_w = to_wide(group);

    let mut member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: PWSTR(user_w.as_mut_ptr()),
    };

    let status = unsafe {
        NetLocalGroupAddMembers(
            server_name,
            PCWSTR(group_w.as_ptr()),
            3,
            &mut member as *mut LOCALGROUP_MEMBERS_INFO_3 as *const u8,
            1,
        )
    };

    net_api_result(status)
}

/// Removes a user from a local group on the machine.
///
/// This function removes `username` from `group` using `NetLocalGroupDelMembers`
/// with `LOCALGROUP_MEMBERS_INFO_3`.
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
/// * `username` - User account to remove from the group.
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
pub fn remove_user_from_group(
    server_name: Option<&str>,
    username: &str,
    group: &str,
) -> Result<(), WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(to_wide(s).as_ptr()))
        .unwrap_or_default();

    let mut user_w = to_wide(username);
    let group_w = to_wide(group);

    let mut member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: PWSTR(user_w.as_mut_ptr()),
    };

    let status = unsafe {
        NetLocalGroupDelMembers(
            server_name,
            PCWSTR(group_w.as_ptr()),
            3,
            &mut member as *mut LOCALGROUP_MEMBERS_INFO_3 as *const u8,
            1,
        )
    };

    net_api_result(status)
}

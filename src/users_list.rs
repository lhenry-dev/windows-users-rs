use windows::{
    Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetUserEnum, USER_INFO_3},
    core::PCWSTR,
};

use crate::{
    User,
    error::WindowsUsersError,
    utils::{ToWideString, net_api_result},
};

pub use self::user_filter_flag::UserFilterFlags;

mod user_filter_flag;

/// Counts the number of user accounts on the local machine.
///
/// This function enumerates local normal accounts via `NetUserEnum`
/// and returns the number of entries read in the current enumeration call.
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
///
/// # Returns
///
/// Returns the number of normal user accounts found by the enumeration call.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if `NetUserEnum` fails.
pub fn count_users(
    server_name: Option<&str>,
    filter: UserFilterFlags,
) -> Result<u32, WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(s.to_wide().as_ptr()))
        .unwrap_or_default();

    let mut buffer = std::ptr::null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;
    let mut resume_handle = 0;

    let status = unsafe {
        NetUserEnum(
            server_name,
            3,
            filter.into(),
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

    Ok(entries_read)
}

/// Lists users on the local machine.
///
/// This function enumerates local normal accounts via `NetUserEnum` level 3
/// and converts each entry into a [`User`].
///
/// # Arguments
///
/// * `server_name` - Optional target server. If `None`, the local machine is used.
///
/// # Returns
///
/// Returns a vector containing all users returned by the enumeration call.
///
/// # Errors
///
/// Returns a [`WindowsUsersError`] if:
/// - The enumeration API call fails (`NetUserEnum`)
/// - Any entry cannot be converted into [`User`]
pub fn list_users(
    server_name: Option<&str>,
    filter: UserFilterFlags,
) -> Result<Vec<User>, WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(s.to_wide().as_ptr()))
        .unwrap_or_default();

    let mut buffer = std::ptr::null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;
    let mut resume_handle = 0;

    let status = unsafe {
        NetUserEnum(
            server_name,
            3,
            filter.into(),
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

    let users = unsafe {
        std::slice::from_raw_parts(buffer as *const USER_INFO_3, entries_read as usize)
            .iter()
            .map(User::try_from)
            .collect::<Result<Vec<_>, _>>()
    }?;

    Ok(users)
}

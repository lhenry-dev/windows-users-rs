#![crate_type = "lib"]
#![forbid(missing_debug_implementations)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg(target_os = "windows")]

mod constants;
mod error;
mod groups;
mod user;
mod user_ops;
mod users_list;
mod utils;

pub use error::WindowsUsersError;
pub use groups::{
    Group, GroupMember, add_users_to_group, list_group_members, list_groups,
    remove_users_from_group, sid::Sid, sid::well_known_sid,
};
pub use user::{
    LogonHours, SidType, User, UserAccountFlags, UserAuthFlags, UserPrivilege, UserUpdate,
};
pub use user_ops::update_ops::{
    set_user_account_expiration, set_user_comment, set_user_country_code, set_user_flags,
    set_user_full_name, set_user_home_dir_drive, set_user_home_directory, set_user_logon_hours,
    set_user_name, set_user_password, set_user_primary_group, set_user_profile,
    set_user_script_path, set_user_user_comment, set_user_workstations,
};
pub use user_ops::{
    add_user, change_user_password, delete_user, get_user, update_user, user_exists,
};
pub use users_list::{UserFilterFlags, count_users, list_users};

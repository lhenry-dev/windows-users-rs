#![crate_type = "lib"]
#![forbid(missing_debug_implementations)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg(target_os = "windows")]

mod constants;
mod error;
mod groups;
mod user;
mod user_manager;
mod user_ops;
mod users_list;
mod utils;

pub use error::WindowsUsersError;
pub use groups::{Group, GroupMember, sid::Sid, sid::well_known_sid};
pub use user::{
    LogonHours, SidType, User, UserAccountFlags, UserAuthFlags, UserPrivilege, UserUpdate,
};
pub use user_manager::UserManager;
pub use users_list::UserFilterFlags;

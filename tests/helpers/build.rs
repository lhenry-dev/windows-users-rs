use std::collections::HashSet;

use chrono::Utc;
use windows_users::{LogonHours, User, UserAccountFlags};

pub fn build_full_user(name: &str) -> User {
    User::builder()
        .name(name)
        .password("P@ssw0rd123!")
        .home_dir("C:\\Users\\Default")
        .comment("Generated user")
        .flags(UserAccountFlags::default())
        .script_path("C:\\Windows\\System32\\logon.cmd")
        .full_name("Default User")
        .user_comment("Created by build_full_user")
        .workstations(HashSet::from(["WORKSTATION1"]))
        .acct_expires(Utc::now() + chrono::Duration::days(30))
        .logon_hours(LogonHours::allow_all())
        .country_code(100u32)
        .code_page(65001u32)
        .primary_group_id(513u32)
        .profile("C:\\Users\\Default")
        .home_dir_drive("C:")
        .password_expired(false)
        .build()
}

pub fn build_full_user_alt(name: &str) -> User {
    User::builder()
        .name(name)
        .password("Str0ng!AltPass#456")
        .home_dir("D:\\Profiles\\CustomUser")
        .comment("Alternate generated user")
        .flags(UserAccountFlags::default())
        .script_path("D:\\Scripts\\startup.bat")
        .full_name("Alternate User")
        .user_comment("Created by build_full_user_alt")
        .workstations(HashSet::from(["WS-ALT-01", "WS-ALT-02"]))
        .acct_expires(Utc::now() + chrono::Duration::days(90))
        .logon_hours(LogonHours::deny_all())
        .country_code(33u32)
        .primary_group_id(513u32)
        .profile("D:\\Profiles\\AltUser")
        .home_dir_drive("D:")
        .build()
}

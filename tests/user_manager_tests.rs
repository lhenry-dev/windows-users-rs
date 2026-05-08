use windows_users::{UserFilterFlags, UserManager};

use crate::helpers::{
    auto_remove_user::AutoRemoveUser, build::build_full_user, constants::USER_NAME,
};

mod helpers;

#[test]
fn test_list_users_local_vs_remote_are_consistent() {
    let local = UserManager::local();

    let hostname = hostname::get()
        .expect("Failed to get hostname")
        .to_string_lossy()
        .to_string();
    let remote_server = format!(r"\\{}", hostname);
    let remote = UserManager::remote(&remote_server);

    let user_name = format!("{USER_NAME}_1");
    let user = build_full_user(&user_name);

    let _guard = AutoRemoveUser::add(&local, &user).expect("Failed to add user");

    let local_count = local
        .count_users(UserFilterFlags::NORMAL_ACCOUNT)
        .expect("Failed to count users (local)");

    let local_users = local
        .list_users(UserFilterFlags::NORMAL_ACCOUNT)
        .expect("Failed to list users (local)");

    let remote_count = remote
        .count_users(UserFilterFlags::NORMAL_ACCOUNT)
        .expect("Failed to count users (remote)");

    let remote_users = remote
        .list_users(UserFilterFlags::NORMAL_ACCOUNT)
        .expect("Failed to list users (remote)");

    assert_eq!(
        local_count, remote_count,
        "User count should match between local and remote"
    );

    assert_eq!(
        local_users.len(),
        remote_users.len(),
        "User list length should match between local and remote"
    );

    for user in &local_users {
        assert!(
            remote_users.iter().any(|u| u.name() == user.name()),
            "User '{}' should exist in remote listing",
            user.name()
        );
    }

    assert!(
        local_users.iter().any(|u| u.name() == &user_name),
        "Expected user to exist in local list"
    );

    assert!(
        remote_users.iter().any(|u| u.name() == &user_name),
        "Expected user to exist in remote list"
    );
}

use windows_users::{UserFilterFlags, count_users, list_users};

use crate::helpers::{
    auto_remove_user::AutoRemoveUser, build::build_full_user, constants::USER_NAME,
};

mod helpers;

#[test]
fn test_list_users_and_count_users_are_consistent() {
    let user_name = format!("{USER_NAME}_1");
    let user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(None, &user).expect("Failed to add user");

    let count = count_users(None, UserFilterFlags::NORMAL_ACCOUNT).expect("Failed to count users");
    let users = list_users(None, UserFilterFlags::NORMAL_ACCOUNT).expect("Failed to list users");

    assert_eq!(
        count as usize,
        users.len(),
        "Count should match listed users"
    );
    assert!(
        users.iter().any(|candidate| candidate.name() == &user_name),
        "Expected user to be present in listed users"
    );
}

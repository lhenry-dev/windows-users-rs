use windows_users::{UserManager, UserUpdate};

use crate::helpers::{
    auto_remove_user::AutoRemoveUser,
    build::{build_full_user, build_full_user_alt},
    constants::USER_NAME,
    utils::assert_user_eq,
};

mod helpers;

#[test]
fn test_add_and_get_user_with_full_payload() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_2");
    let user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    let fetched = user_manager
        .get_user(&user_name)
        .expect("Failed to fetch user");

    assert_user_eq(&fetched, &user);
}

#[test]
fn test_add_user_if_not_exists() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_3");
    let user = build_full_user(&user_name);

    let auto_remove_user_result = AutoRemoveUser::add_if_not_exists(&user_manager, &user).unwrap();
    assert!(auto_remove_user_result.added_or_changed);
    let auto_remove_user_result = AutoRemoveUser::add_if_not_exists(&user_manager, &user).unwrap();
    assert!(!auto_remove_user_result.added_or_changed);
}

#[test]
fn test_add_user_or_update() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_4");
    let user = build_full_user(&user_name);

    let auto_remove_user_result =
        AutoRemoveUser::add_or_update(&user_manager, &user).expect("Failed to add or update user");
    assert!(
        auto_remove_user_result.added_or_changed,
        "User should be added"
    );

    let updated_user = build_full_user_alt(&user_name);
    let auto_remove_user_result =
        AutoRemoveUser::add_or_update(&user_manager, &updated_user).expect("Failed to update user");
    assert!(
        !auto_remove_user_result.added_or_changed,
        "Rule should be updated"
    );

    let updated_user = user_manager
        .get_user(&user_name)
        .expect("Failed to fetch updated user");
    assert_user_eq(&updated_user, &updated_user);
}

#[test]
fn test_user_exists_returns_true_for_created_user() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_5");
    let user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    assert!(
        user_manager.user_exists(&user_name),
        "Expected user_exists to return true for an existing user"
    );
}

#[test]
fn test_user_exists_returns_false_for_missing_user() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_6");

    assert!(
        !user_manager.user_exists(&user_name),
        "Expected user_exists to return false for a missing user"
    );
}

#[test]
fn test_update_user_changes_only_requested_fields() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_7");
    let mut user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    let new_full_name = "Updated Full Name";
    let new_comment = "Updated comment";
    let settings = UserUpdate::builder()
        .full_name(new_full_name)
        .comment(new_comment)
        .build();

    user.update(&user_manager, &settings)
        .expect("Failed to update user with new API");

    let fetched = user_manager
        .get_user(&user_name)
        .expect("Failed to fetch updated user");
    user.set_full_name(Some(new_full_name.to_string()));
    user.set_comment(Some(new_comment.to_string()));

    assert_user_eq(&fetched, &user);
}

#[test]
fn test_update_full_user_to_new_full_user() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_8");

    let mut user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    let new_user = build_full_user_alt(&user_name);

    user.update(&user_manager, &new_user.clone().into())
        .expect("Failed to fully update user");

    let fetched = user_manager
        .get_user(&user_name)
        .expect("Failed to fetch updated user");

    assert_user_eq(&fetched, &new_user);
}

#[test]
fn test_update_user_fails_for_missing_user() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_9");
    let settings = UserUpdate::builder().full_name("Should Fail").build();

    let result = user_manager.update_user(&user_name, &settings);

    assert!(
        result.is_err(),
        "Expected update_user to fail for missing user"
    );
}

#[test]
fn test_change_user_password_accepts_current_password() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_10");
    let user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    user_manager
        .change_user_password(&user_name, "P@ssw0rd123!", "N3wP@ssw0rd!")
        .expect("Failed to change user password");
}

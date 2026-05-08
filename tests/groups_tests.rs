use windows_users::{Group, UserManager, well_known_sid};

use crate::helpers::{
    auto_remove_group::AutoRemoveGroup, auto_remove_user::AutoRemoveUser, build::build_full_user,
    constants::USER_NAME,
};

mod helpers;

#[test]
fn test_list_groups_returns_non_empty_result() {
    let user_manager = UserManager::local();
    let groups = user_manager.list_groups().expect("Failed to list groups");

    assert!(!groups.is_empty(), "Expected at least one local group");
    assert!(
        groups.iter().all(|group| !group.name().is_empty()),
        "Expected every listed group to have a non-empty name"
    );
}

#[test]
fn test_list_group_members_returns_valid_sid_type_range() {
    let user_manager = UserManager::local();
    let groups = user_manager.list_groups().expect("Failed to list groups");

    let mut checked_any_member = false;
    for group in groups {
        let members = match user_manager.list_group_members(group.name()) {
            Ok(members) => members,
            Err(_) => continue,
        };

        for member in members {
            checked_any_member = true;
            assert!(
                (1..=11).contains(member.sid_type()),
                "Expected sid_type to be in SID_NAME_USE range"
            );
            assert!(
                !member.name().is_empty(),
                "Expected group member to have a non-empty name"
            );
            assert!(
                member.sid().starts_with("S-1-"),
                "Expected group member SID to be in string SID format"
            );
        }
    }

    assert!(
        checked_any_member,
        "Expected to validate at least one local group member"
    );
}

#[test]
fn test_add_and_remove_user_from_group_roundtrip() {
    let user_manager = UserManager::local();
    let user_name = format!("{USER_NAME}_g");
    let user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    let group_name = well_known_sid::USERS.name(&user_manager).unwrap();

    let _ = user_manager.remove_users_from_group(&[&user_name], &group_name);
    user_manager
        .add_users_to_group(&[&user_name], &group_name)
        .expect("Failed to add user to group");

    let members_after_add = user_manager
        .list_group_members(&group_name)
        .expect("Failed to list group members after add");
    assert!(
        members_after_add
            .iter()
            .any(|member| member.name().eq_ignore_ascii_case(&user_name)),
        "Expected user to be present in group after add"
    );

    let user_groups = user_manager
        .list_user_groups(&user_name)
        .expect("Failed to list user groups");
    assert!(
        user_groups
            .iter()
            .any(|group| group.eq_ignore_ascii_case(&group_name)),
        "Expected group to be present in user's group list after add"
    );

    user_manager
        .remove_users_from_group(&[&user_name], &group_name)
        .expect("Failed to remove user from group");
    let members_after_remove = user_manager
        .list_group_members(&group_name)
        .expect("Failed to list group members after remove");
    assert!(
        !members_after_remove
            .iter()
            .any(|member| member.name().eq_ignore_ascii_case(&user_name)),
        "Expected user to be absent from group after remove"
    );
}

#[test]
fn test_add_and_remove_group_roundtrip() {
    let user_manager = UserManager::local();

    let user_name = format!("{USER_NAME}_9");
    let user = build_full_user(&user_name);
    let _user_guard = AutoRemoveUser::add(&user_manager, &user).expect("Failed to add user");

    let group_name = format!("{USER_NAME}_1");
    let group = Group::builder()
        .name(&group_name)
        .comment("Temporary test group")
        .build();

    let _group_guard = AutoRemoveGroup::add(&user_manager, &group).expect("Failed to add group");

    assert!(
        user_manager.group_exists(&group_name),
        "Expected group to exist after creation"
    );

    let fetched_group = user_manager
        .get_group(&group_name)
        .expect("Failed to fetch group after creation");
    assert_eq!(
        fetched_group.name(),
        &group_name,
        "Fetched group name should match created group name"
    );

    user_manager
        .add_users_to_group(&[&user_name], &group_name)
        .expect("Failed to add user to group");
    let members_after_add = user_manager
        .list_group_members(&group_name)
        .expect("Failed to list group members");
    assert!(
        members_after_add
            .iter()
            .any(|m| m.name().eq_ignore_ascii_case(&user_name)),
        "Expected user to be present in group after add"
    );

    user_manager
        .remove_users_from_group(&[&user_name], &group_name)
        .expect("Failed to remove user from group");
    let members_after_remove = user_manager
        .list_group_members(&group_name)
        .expect("Failed to list group members");
    assert!(
        !members_after_remove
            .iter()
            .any(|m| m.name().eq_ignore_ascii_case(&user_name)),
        "Expected user to be absent from group after removal"
    );
}

#[test]
fn test_update_group_updates_comment() {
    let user_manager = UserManager::local();

    let group_name = format!("{USER_NAME}_update");
    let group = Group::builder()
        .name(&group_name)
        .comment("Initial comment")
        .build();

    let _group_guard = AutoRemoveGroup::add(&user_manager, &group).expect("Failed to create group");

    assert!(
        user_manager.group_exists(&group_name),
        "Group should exist after creation"
    );

    let updated_group = Group::builder()
        .name(&group_name)
        .comment("Updated comment")
        .build();

    user_manager
        .update_group(&updated_group)
        .expect("Failed to update group");

    let fetched = user_manager
        .get_group(&group_name)
        .expect("Failed to fetch group after update");

    assert_eq!(
        fetched.comment(),
        &Some("Updated comment".to_string()),
        "Expected group comment to be updated"
    );
}

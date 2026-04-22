use windows_users::{
    add_user_to_group, list_group_members, list_groups, remove_user_from_group, well_known_sid,
};

use crate::helpers::{
    auto_remove_user::AutoRemoveUser, build::build_full_user, constants::USER_NAME,
};

mod helpers;

#[test]
fn test_list_groups_returns_non_empty_result() {
    let groups = list_groups(None).expect("Failed to list groups");

    assert!(!groups.is_empty(), "Expected at least one local group");
    assert!(
        groups.iter().all(|group| !group.name().is_empty()),
        "Expected every listed group to have a non-empty name"
    );
}

#[test]
fn test_list_group_members_returns_valid_sid_type_range() {
    let groups = list_groups(None).expect("Failed to list groups");

    let mut checked_any_member = false;
    for group in groups {
        let members = match list_group_members(None, group.name()) {
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
    let user_name = format!("{USER_NAME}_g");
    let user = build_full_user(&user_name);
    let _guard = AutoRemoveUser::add(None, &user).expect("Failed to add user");

    let group_name = well_known_sid::GUESTS.name().unwrap();

    let _ = remove_user_from_group(None, &user_name, &group_name);
    add_user_to_group(None, &user_name, &group_name).expect("Failed to add user to group");

    let members_after_add =
        list_group_members(None, &group_name).expect("Failed to list group members after add");
    assert!(
        members_after_add
            .iter()
            .any(|member| member.name().eq_ignore_ascii_case(&user_name)),
        "Expected user to be present in group after add"
    );

    remove_user_from_group(None, &user_name, &group_name)
        .expect("Failed to remove user from group");
    let members_after_remove =
        list_group_members(None, &group_name).expect("Failed to list group members after remove");
    assert!(
        !members_after_remove
            .iter()
            .any(|member| member.name().eq_ignore_ascii_case(&user_name)),
        "Expected user to be absent from group after remove"
    );
}

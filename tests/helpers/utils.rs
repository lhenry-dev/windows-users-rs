use chrono::TimeZone;
use chrono::{DateTime, Utc};
use windows_users::User;

fn truncate_to_seconds(dt: &DateTime<Utc>) -> DateTime<Utc> {
    Utc.timestamp_opt(dt.timestamp(), 0).unwrap()
}

pub fn assert_user_eq(actual: &User, expected: &User) {
    assert_eq!(actual.name(), expected.name(), "Name mismatch");
    assert_eq!(
        actual.priv_level(),
        expected.priv_level(),
        "Privilege level mismatch"
    );
    assert_eq!(actual.flags(), expected.flags(), "Flags mismatch");

    // if let Some(password) = expected.password() {
    //     assert_eq!(
    //         actual.password(),
    //         &Some(password.clone()),
    //         "Password mismatch"
    //     );
    // }
    if let Some(age) = expected.password_age() {
        assert_eq!(actual.password_age(), &Some(*age), "Password age mismatch");
    }
    if let Some(home) = expected.home_dir() {
        assert_eq!(actual.home_dir(), &Some(home.clone()), "Home dir mismatch");
    }
    if let Some(comment) = expected.comment() {
        assert_eq!(actual.comment(), &Some(comment.clone()), "Comment mismatch");
    }
    if let Some(script) = expected.script_path() {
        assert_eq!(
            actual.script_path(),
            &Some(script.clone()),
            "Script path mismatch"
        );
    }
    if let Some(auth) = expected.auth_flags() {
        assert_eq!(actual.auth_flags(), &Some(*auth), "Auth flags mismatch");
    }
    if let Some(full_name) = expected.full_name() {
        assert_eq!(
            actual.full_name(),
            &Some(full_name.clone()),
            "Full name mismatch"
        );
    }
    if let Some(user_comment) = expected.user_comment() {
        assert_eq!(
            actual.user_comment(),
            &Some(user_comment.clone()),
            "User comment mismatch"
        );
    }
    // if let Some(parms) = expected.parms() {
    //     assert_eq!(actual.parms(), &Some(parms.clone()), "Parms mismatch");
    // }
    if let Some(workstations) = expected.workstations() {
        assert_eq!(
            actual.workstations(),
            &Some(workstations.clone()),
            "Workstations mismatch"
        );
    }
    if let Some(last_logon) = expected.last_logon() {
        assert_eq!(
            actual
                .last_logon()
                .map(|dt: DateTime<Utc>| truncate_to_seconds(&dt)),
            Some(truncate_to_seconds(last_logon)),
            "Last logon mismatch"
        );
    }
    if let Some(last_logoff) = expected.last_logoff() {
        assert_eq!(
            actual
                .last_logoff()
                .map(|dt: DateTime<Utc>| truncate_to_seconds(&dt)),
            Some(truncate_to_seconds(last_logoff)),
            "Last logoff mismatch"
        );
    }
    if let Some(expires) = expected.acct_expires() {
        assert_eq!(
            actual
                .acct_expires()
                .map(|dt: DateTime<Utc>| truncate_to_seconds(&dt)),
            Some(truncate_to_seconds(expires)),
            "Account expiration mismatch"
        );
    }
    if let Some(storage) = expected.max_storage() {
        assert_eq!(
            actual.max_storage(),
            &Some(*storage),
            "Max storage mismatch"
        );
    }
    if let Some(units) = expected.units_per_week() {
        assert_eq!(
            actual.units_per_week(),
            &Some(*units),
            "Units per week mismatch"
        );
    }
    if let Some(hours) = expected.logon_hours() {
        assert_eq!(
            actual.logon_hours(),
            &Some(hours.clone()),
            "Logon hours mismatch"
        );
    }
    if let Some(bad_pw) = expected.bad_pw_count() {
        assert_eq!(
            actual.bad_pw_count(),
            &Some(*bad_pw),
            "Bad password count mismatch"
        );
    }
    if let Some(num) = expected.num_logons() {
        assert_eq!(actual.num_logons(), &Some(*num), "Logon count mismatch");
    }
    if let Some(server) = expected.logon_server() {
        assert_eq!(
            actual.logon_server(),
            &Some(server.clone()),
            "Logon server mismatch"
        );
    }
    if let Some(country) = expected.country_code() {
        assert_eq!(
            actual.country_code(),
            &Some(*country),
            "Country code mismatch"
        );
    }
    if let Some(code_page) = expected.code_page() {
        assert_eq!(actual.code_page(), &Some(*code_page), "Code page mismatch");
    }
    if let Some(user_id) = expected.user_id() {
        assert_eq!(actual.user_id(), &Some(*user_id), "User ID mismatch");
    }
    if let Some(sid) = expected.user_sid() {
        assert_eq!(actual.user_sid(), &Some(sid.clone()), "User SID mismatch");
    }
    if let Some(group_id) = expected.primary_group_id() {
        assert_eq!(
            actual.primary_group_id(),
            &Some(*group_id),
            "Primary group ID mismatch"
        );
    }
    if let Some(profile) = expected.profile() {
        assert_eq!(actual.profile(), &Some(profile.clone()), "Profile mismatch");
    }
    if let Some(drive) = expected.home_dir_drive() {
        assert_eq!(
            actual.home_dir_drive(),
            &Some(drive.clone()),
            "Home dir drive mismatch"
        );
    }
    if let Some(expired) = expected.password_expired() {
        assert_eq!(
            actual.password_expired(),
            &Some(*expired),
            "Password expired mismatch"
        );
    }
}

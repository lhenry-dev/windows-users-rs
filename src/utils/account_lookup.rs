use windows::{
    Win32::{
        Foundation::ERROR_INSUFFICIENT_BUFFER,
        Security::{LookupAccountSidW, PSID, SID_NAME_USE},
    },
    core::{PCWSTR, PWSTR},
};

use crate::{SidType, WindowsUsersError, utils::ToWideString};

#[cfg(test)]
use {crate::utils::sid::psid_to_string, windows::Win32::Security::LookupAccountNameW};

fn is_insufficient_buffer(e: &windows::core::Error) -> bool {
    e.code().0 == ERROR_INSUFFICIENT_BUFFER.0 as i32
}

pub fn lookup_account_sid(
    server_name: Option<&str>,
    psid: PSID,
) -> Result<(String, String, SidType), WindowsUsersError> {
    let server_name = server_name
        .map(|s| PCWSTR(s.to_wide().as_ptr()))
        .unwrap_or_default();
    let mut name_len = 256;
    let mut domain_len = 256;

    loop {
        let mut name = vec![0; name_len as usize];
        let mut domain = vec![0; domain_len as usize];
        let mut sid_name_use = SID_NAME_USE(0);

        let result = unsafe {
            LookupAccountSidW(
                server_name,
                psid,
                Some(PWSTR(name.as_mut_ptr())),
                &raw mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &raw mut domain_len,
                &raw mut sid_name_use,
            )
        };

        match result {
            Ok(()) => {}
            Err(e) if is_insufficient_buffer(&e) => continue,
            Err(e) => return Err(WindowsUsersError::WindowsError(e)),
        }

        return Ok((
            String::from_utf16_lossy(&name[..name_len as usize]),
            String::from_utf16_lossy(&domain[..domain_len as usize]),
            sid_name_use.try_into()?,
        ));
    }
}

/// Returns account's `SID`, domain name and type, respectively.
#[cfg(test)]
pub fn lookup_account_name(
    server_name: Option<&str>,
    account_name: &str,
) -> Result<(String, String, SidType), WindowsUsersError> {
    use crate::utils::ToWideString;

    let server_name = server_name
        .map(|s| PCWSTR(s.to_wide().as_ptr()))
        .unwrap_or_default();

    let mut sid_len = 256;
    let mut domain_len = 256;

    loop {
        let mut sid_buffer = vec![0u8; sid_len as usize];
        let psid = PSID(sid_buffer.as_mut_ptr().cast());

        let mut domain = vec![0; domain_len as usize];
        let mut sid_name_use = SID_NAME_USE(0);

        let result = unsafe {
            LookupAccountNameW(
                server_name,
                PCWSTR(account_name.to_wide().as_ptr()),
                Some(psid),
                &raw mut sid_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &raw mut domain_len,
                &raw mut sid_name_use,
            )
        };

        match result {
            Ok(()) => {
                let str_sid = psid_to_string(psid)?;

                return Ok((
                    str_sid,
                    String::from_utf16_lossy(&domain[..domain_len as usize]),
                    sid_name_use.try_into()?,
                ));
            }
            Err(e) if is_insufficient_buffer(&e) => {}
            Err(e) => return Err(WindowsUsersError::WindowsError(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        SidType,
        utils::{
            account_lookup::{lookup_account_name, lookup_account_sid},
            sid::str_to_psid,
        },
    };

    #[test]
    fn sid_name_sid_roundtrip_known_sids() {
        struct TestSid {
            sid: &'static str,
            expected_names: &'static [&'static str],
            domain: &'static str,
            sid_type: SidType,
        }

        let cases = [
            TestSid {
                sid: "S-1-5-32-546", // Guests
                expected_names: &["Guests", "Invités"],
                domain: "BUILTIN",
                sid_type: SidType::Alias,
            },
            TestSid {
                sid: "S-1-5-32-545", // Users
                expected_names: &["Users", "Utilisateurs"],
                domain: "BUILTIN",
                sid_type: SidType::Alias,
            },
            TestSid {
                sid: "S-1-5-32-544", // Administrators
                expected_names: &["Administrators", "Administrateurs"],
                domain: "BUILTIN",
                sid_type: SidType::Alias,
            },
        ];

        for case in cases {
            // SID → name
            let (name, domain, sid_type) =
                lookup_account_sid(None, str_to_psid(case.sid).unwrap().as_psid())
                    .expect("LookupAccountSidW failed");

            assert!(case.expected_names.contains(&name.as_str()));
            assert_eq!(domain, case.domain);
            assert_eq!(sid_type, case.sid_type);

            // Name → SID
            let (converted_sid, converted_domain, converted_type) =
                lookup_account_name(None, &name).expect("LookupAccountNameW failed");

            assert_eq!(converted_sid, case.sid);
            assert_eq!(converted_domain, case.domain);
            assert_eq!(converted_type, case.sid_type);
        }
    }
}

use scopeguard::guard;
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::core::PCWSTR;
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::PSID,
    },
    core::PWSTR,
};

use crate::error::WindowsUsersError;
use crate::utils::ToWideString;

pub fn psid_to_string(psid: PSID) -> Result<String, WindowsUsersError> {
    let mut str_sid: PWSTR = PWSTR(std::ptr::null_mut());
    unsafe {
        ConvertSidToStringSidW(psid, &raw mut str_sid)?;
    }

    let _str_sid_guard = guard(str_sid, |ptr| unsafe {
        if !ptr.0.is_null() {
            LocalFree(Some(HLOCAL(ptr.as_ptr().cast::<std::ffi::c_void>())));
        }
    });

    let str_sid = unsafe { str_sid.to_string() }?;

    Ok(str_sid)
}

pub struct OwnedSid {
    sid: PSID,
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        unsafe {
            if !self.sid.0.is_null() {
                LocalFree(Some(HLOCAL(self.sid.0)));
            }
        }
    }
}

impl OwnedSid {
    pub fn as_psid(&self) -> PSID {
        self.sid
    }
}

pub fn str_to_psid(sid: &str) -> Result<OwnedSid, WindowsUsersError> {
    let mut psid = PSID(std::ptr::null_mut());

    unsafe {
        ConvertStringSidToSidW(PCWSTR(sid.to_wide().as_ptr()), &raw mut psid)?;
    }

    Ok(OwnedSid { sid: psid })
}

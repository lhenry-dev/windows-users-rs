use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows::Win32::NetworkManagement::NetManagement::NERR_Success;
use windows::core::HRESULT;

use crate::error::{ParmnumError, WindowsUsersError};

pub fn net_api_result_with_index(
    status: u32,
    parm_err: u32,
) -> std::result::Result<(), WindowsUsersError> {
    if status == NERR_Success {
        return Ok(());
    }

    let windows_error = windows::core::Error::from_hresult(HRESULT::from_win32(status));

    if status == ERROR_INVALID_PARAMETER.0 {
        return Err(WindowsUsersError::WindowsErrorWithParmnum {
            parm: ParmnumError::from(parm_err),
            source: windows_error,
        });
    }

    Err(WindowsUsersError::WindowsError(windows_error))
}

pub fn net_api_result(status: u32) -> std::result::Result<(), WindowsUsersError> {
    if status == NERR_Success {
        return Ok(());
    }

    let windows_error = windows::core::Error::from_hresult(HRESULT::from_win32(status));

    Err(WindowsUsersError::WindowsError(windows_error))
}

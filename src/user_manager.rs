use windows::core::PCWSTR;

use crate::utils::ToWideString;

/// Provides an interface to manage Windows user accounts on either
/// the **local machine** or a **remote server**.
///
/// This struct encapsulates the target server as a wide string pointer
/// (`PCWSTR`) compatible with Windows API calls such as `NetUserAdd`,
/// `NetUserDel`, and `NetUserSetInfo`.
///
/// # Local vs Remote
///
/// - [`UserManager::local`] targets the current machine
/// - [`UserManager::remote`] targets a specific machine (e.g. `"\\\\SERVER01"`)
///
/// # Examples
///
/// ```rust
/// use windows_users::UserManager;
///
/// let local = UserManager::local();
///
/// let remote = UserManager::remote(r"\\SERVER01");
/// ```
#[derive(Debug, Clone)]
pub struct UserManager {
    _server_wide: Option<Vec<u16>>,
    pub(crate) server: PCWSTR,
}

impl UserManager {
    /// Creates a [`UserManager`] targeting a **remote machine**.
    ///
    /// The provided server name is converted to UTF-16 and stored internally
    /// to ensure the pointer remains valid for all subsequent Windows API calls.
    ///
    /// # Arguments
    ///
    /// * `server` - The target machine name (e.g. `"\\\\SERVER01"`)
    pub fn remote(server: &str) -> Self {
        let wide = server.to_wide();
        let ptr = PCWSTR(wide.as_ptr());

        Self {
            _server_wide: Some(wide),
            server: ptr,
        }
    }

    /// Creates a [`UserManager`] targeting the **local machine**.
    ///
    /// This uses a null pointer internally, as required by Windows APIs
    /// to indicate "current machine".
    pub fn local() -> Self {
        Self {
            _server_wide: None,
            server: PCWSTR::null(),
        }
    }
}

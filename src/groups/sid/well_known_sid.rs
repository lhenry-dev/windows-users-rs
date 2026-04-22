//! <https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids>
//!
//! Well-known Windows local group SIDs.
//!
//! These SIDs are stable across all Windows systems.

use crate::groups::sid::Sid;

/// Builtin Administrators group.
pub const ADMINISTRATORS: Sid = Sid {
    sid: "S-1-5-32-544",
};

/// Builtin Users group.
pub const USERS: Sid = Sid {
    sid: "S-1-5-32-545",
};

/// Builtin Guests group.
pub const GUESTS: Sid = Sid {
    sid: "S-1-5-32-546",
};

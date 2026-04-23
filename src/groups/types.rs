use getset::{Getters, Setters};
use typed_builder::TypedBuilder;
use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_2,
};

use crate::{WindowsUsersError, utils::psid_to_string};

/// Representation of a Windows local group.
#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct Group {
    /// The name of the group.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    name: String,
    /// The comment associated with the group.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    comment: Option<String>,
}

impl TryFrom<&LOCALGROUP_INFO_1> for Group {
    type Error = WindowsUsersError;

    fn try_from(group: &LOCALGROUP_INFO_1) -> Result<Self, WindowsUsersError> {
        unsafe {
            Ok({
                Self {
                    name: group.lgrpi1_name.to_string()?,
                    comment: group
                        .lgrpi1_comment
                        .to_string()
                        .ok()
                        .filter(|s| !s.is_empty()),
                }
            })
        }
    }
}

/// Representation of a member of a Windows local group.
#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct GroupMember {
    /// The name of the member.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    name: String,
    /// The domain of the member.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    domain: String,
    /// The sid type of the member.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    sid_type: i32,
    /// The sid of the member.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    sid: String,
}

impl TryFrom<&LOCALGROUP_MEMBERS_INFO_2> for GroupMember {
    type Error = WindowsUsersError;

    fn try_from(member: &LOCALGROUP_MEMBERS_INFO_2) -> Result<Self, WindowsUsersError> {
        unsafe {
            let full_name = member.lgrmi2_domainandname.to_string()?;

            let (domain, name) = match full_name.split_once('\\') {
                Some((d, n)) => (d.to_string(), n.to_string()),
                None => (String::new(), full_name),
            };

            Ok({
                Self {
                    name,
                    domain,
                    sid_type: member.lgrmi2_sidusage.0,
                    sid: psid_to_string(member.lgrmi2_sid)?,
                }
            })
        }
    }
}

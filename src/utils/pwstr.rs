use std::collections::HashSet;

use windows::core::PWSTR;

pub trait PWSTRExt {
    fn to_optional_string(self) -> Option<String>;
    fn to_optional_hashset(&self) -> Option<HashSet<String>>;
}

impl PWSTRExt for PWSTR {
    fn to_optional_string(self) -> Option<String> {
        unsafe { self.to_string().ok().filter(|s| !s.is_empty()) }
    }

    fn to_optional_hashset(&self) -> Option<HashSet<String>> {
        self.to_optional_string().map(|s| {
            s.split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
    }
}

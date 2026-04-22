use std::{collections::HashSet, hash::Hash};

pub fn into_hashset<T, U>(items: impl IntoIterator<Item = T>) -> HashSet<U>
where
    T: Into<U>,
    U: Eq + Hash,
{
    items.into_iter().map(Into::into).collect()
}

pub fn option_to_wide(s: &Option<String>) -> Option<Vec<u16>> {
    match s {
        Some(str) if !str.is_empty() => Some(to_wide(str)),
        _ => None,
    }
}

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

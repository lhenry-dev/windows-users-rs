use std::{collections::HashSet, hash::Hash};

pub use pwstr::*;
pub use sid::*;
pub use times::*;
pub use wide::*;
pub use windows_result::*;

pub mod account_lookup;
pub mod pwstr;
pub mod sid;
pub mod times;
pub mod wide;
pub mod windows_result;

pub fn into_hashset<T, U>(items: impl IntoIterator<Item = T>) -> HashSet<U>
where
    T: Into<U>,
    U: Eq + Hash,
{
    items.into_iter().map(Into::into).collect()
}

pub fn some_if<T>(cond: bool, value: T) -> Option<T> {
    if cond { Some(value) } else { None }
}

use std::{collections::HashSet, hash::Hash};

pub use account_lookup::*;
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

pub trait ToWideString {
    fn to_wide(&self) -> Vec<u16>;
}

pub trait ToWideStringOption {
    fn to_wide_option(&self) -> Option<Vec<u16>>;
}

impl ToWideString for str {
    fn to_wide(&self) -> Vec<u16> {
        self.encode_utf16().chain(Some(0)).collect()
    }
}

impl<T> ToWideStringOption for Option<T>
where
    T: AsRef<str>,
{
    fn to_wide_option(&self) -> Option<Vec<u16>> {
        match self {
            Some(value) if !value.as_ref().is_empty() => Some(value.as_ref().to_wide()),
            _ => None,
        }
    }
}

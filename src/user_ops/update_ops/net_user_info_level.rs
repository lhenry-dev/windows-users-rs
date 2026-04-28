use windows::Win32::NetworkManagement::NetManagement::{
    USER_INFO_0, USER_INFO_1, USER_INFO_2, USER_INFO_3, USER_INFO_4, USER_INFO_21, USER_INFO_22,
    USER_INFO_1003, USER_INFO_1005, USER_INFO_1006, USER_INFO_1007, USER_INFO_1008, USER_INFO_1009,
    USER_INFO_1010, USER_INFO_1011, USER_INFO_1012, USER_INFO_1014, USER_INFO_1017, USER_INFO_1020,
    USER_INFO_1024, USER_INFO_1051, USER_INFO_1052, USER_INFO_1053,
};

pub trait NetUserInfoLevel {
    const LEVEL: u32;
}

impl NetUserInfoLevel for USER_INFO_0 {
    const LEVEL: u32 = 0;
}

impl NetUserInfoLevel for USER_INFO_1 {
    const LEVEL: u32 = 1;
}

impl NetUserInfoLevel for USER_INFO_2 {
    const LEVEL: u32 = 2;
}

impl NetUserInfoLevel for USER_INFO_3 {
    const LEVEL: u32 = 3;
}

impl NetUserInfoLevel for USER_INFO_4 {
    const LEVEL: u32 = 4;
}

impl NetUserInfoLevel for USER_INFO_21 {
    const LEVEL: u32 = 21;
}

impl NetUserInfoLevel for USER_INFO_22 {
    const LEVEL: u32 = 22;
}

impl NetUserInfoLevel for USER_INFO_1003 {
    const LEVEL: u32 = 1003;
}

impl NetUserInfoLevel for USER_INFO_1005 {
    const LEVEL: u32 = 1005;
}

impl NetUserInfoLevel for USER_INFO_1006 {
    const LEVEL: u32 = 1006;
}

impl NetUserInfoLevel for USER_INFO_1007 {
    const LEVEL: u32 = 1007;
}

impl NetUserInfoLevel for USER_INFO_1008 {
    const LEVEL: u32 = 1008;
}

impl NetUserInfoLevel for USER_INFO_1009 {
    const LEVEL: u32 = 1009;
}

impl NetUserInfoLevel for USER_INFO_1010 {
    const LEVEL: u32 = 1010;
}

impl NetUserInfoLevel for USER_INFO_1011 {
    const LEVEL: u32 = 1011;
}

impl NetUserInfoLevel for USER_INFO_1012 {
    const LEVEL: u32 = 1012;
}

impl NetUserInfoLevel for USER_INFO_1014 {
    const LEVEL: u32 = 1014;
}

impl NetUserInfoLevel for USER_INFO_1017 {
    const LEVEL: u32 = 1017;
}

impl NetUserInfoLevel for USER_INFO_1020 {
    const LEVEL: u32 = 1020;
}

impl NetUserInfoLevel for USER_INFO_1024 {
    const LEVEL: u32 = 1024;
}

impl NetUserInfoLevel for USER_INFO_1051 {
    const LEVEL: u32 = 1051;
}

impl NetUserInfoLevel for USER_INFO_1052 {
    const LEVEL: u32 = 1052;
}

impl NetUserInfoLevel for USER_INFO_1053 {
    const LEVEL: u32 = 1053;
}

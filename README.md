<div align="center">

<h1>Windows Users</h1>

[![Crates.io](https://img.shields.io/crates/v/windows_users)](https://crates.io/crates/windows_users)
[![Build Status](https://img.shields.io/github/actions/workflow/status/lhenry-dev/windows-users-rs/ci.yml?branch=main)](https://github.com/lhenry-dev/windows-users-rs/actions/workflows/ci.yml?branch=main)
[![Dependency Status](https://deps.rs/repo/github/lhenry-dev/windows-users-rs/status.svg)](https://deps.rs/repo/github/lhenry-dev/windows-users-rs)
[![Documentation](https://docs.rs/windows_users/badge.svg)](https://docs.rs/windows_users)
[![License](https://img.shields.io/crates/l/windows_users)](https://crates.io/crates/windows_users)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-dea584.svg?logo=rust)](https://github.com/rust-lang/rust/releases/tag/1.88.0)
[![codecov](https://codecov.io/gh/lhenry-dev/windows-users-rs/graph/badge.svg?token=WD7I8BR389)](https://codecov.io/gh/lhenry-dev/windows-users-rs)

---

**A Rust crate for managing Windows users and groups using the Windows API in Rust.**

</div>

## Features

- Create, update, delete, and fetch local users
- Check if a user exists and change user passwords
- Add or remove users from local groups
- List local groups and group members
- List and count users with `UserFilterFlags`

## Installation

Add this to your `Cargo.toml`:

```toml
[target.'cfg(windows)'.dependencies]
windows_users = "0.1.0"
```

## Usage Examples

### Creating and Managing a User

```rust
use windows_users::{add_user, delete_user, user_exists, update_user, User, UserUpdate};

let username = "DemoUser";

// Create a new user
let user = User::builder()
    .name(username)
    .password("P@ssw0rd123!")
    .full_name("Demo User")
    .comment("Created from windows_users")
    .build();

// Add the user
match add_user(None, &user) {
    Ok(_) => println!("User created"),
    Err(e) => eprintln!("Failed to create user: {e}"),
}

// Verify the user exists
match user_exists(None, username) {
    true => println!("User exists"),
    false => eprintln!("User does not exist or check failed"),
}

let settings = UserUpdate::builder()
    .comment("Updated comment")
    .full_name("Demo User Updated")
    .build();

// Update the user
match update_user(None, username, &settings) {
    Ok(_) => println!("User updated"),
    Err(e) => eprintln!("Failed to update user: {e}"),
}

// Delete the user
match delete_user(None, username) {
    Ok(_) => println!("User deleted"),
    Err(e) => eprintln!("Failed to delete user: {e}"),
}
```

### Using Struct Methods

```rust
use windows_users::{User, UserUpdate};

// Create a new user
let mut user = User::builder()
    .name("DemoUserMethods")
    .password("P@ssw0rd123!")
    .build();

// Add the user
match user.add(None) {
    Ok(_) => println!("User created"),
    Err(e) => eprintln!("Failed to create user: {e}"),
}

// Verify the user exists
match user.exists(None) {
    true => println!("User exists"),
    false => eprintln!("User does not exist or check failed"),
};

let update = UserUpdate::builder()
    .comment("Updated via struct method")
    .build();

// Update the user
match user.update(None, &update) {
    Ok(_) => println!("User updated"),
    Err(e) => eprintln!("Failed to update user: {e}"),
}

// Delete the user
match user.delete(None) {
    Ok(_) => println!("User deleted"),
    Err(e) => eprintln!("Failed to delete user: {e}"),
}
```

### Managing Group Membership

```rust
use windows_users::{add_users_to_group, list_group_members, remove_users_from_group};

let username = ["DemoUser"];
let group = "Users";

match add_users_to_group(None, &username, group) {
    Ok(_) => println!("User added to group"),
    Err(e) => eprintln!("Failed to add user to group: {e}"),
}

match list_group_members(None, group) {
    Ok(members) => {
        for member in members {
            println!("{}\\{}", member.domain(), member.name());
        }
    }
    Err(e) => eprintln!("Failed to list members: {e}"),
}

match remove_users_from_group(None, &username, group) {
    Ok(_) => println!("User removed from group"),
    Err(e) => eprintln!("Failed to remove user from group: {e}"),
}
```

### Listing Local Users

```rust
use windows_users::{count_users, list_users, UserFilterFlags};

match count_users(None, UserFilterFlags::NORMAL_ACCOUNT) {
    Ok(count) => println!("Normal accounts: {count}"),
    Err(e) => eprintln!("Failed to count users: {e}"),
}

match list_users(None, UserFilterFlags::NORMAL_ACCOUNT) {
    Ok(users) => {
        for user in users {
            println!("User: {}", user.name());
        }
    }
    Err(e) => eprintln!("Failed to list users: {e}"),
}
```

## Requirements

- Windows 7 or later
- Administrative privileges for certain operations

## Support

For issues and questions:

- Open an issue on GitHub
- Check the [documentation](https://docs.rs/windows_users)

# License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

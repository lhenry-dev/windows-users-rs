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

**A Rust crate for managing local Windows users and groups using the Windows API in Rust.**

</div>

## Features

- Create, update, delete, and fetch local users
- Create, update, delete, and query local groups
- Add or remove users from local groups
- Support for local and remote machine management
- Well-known SID helpers (`Users`, `Administrators`, etc.)
- User enumeration with `UserFilterFlags`

## Installation

Add this to your `Cargo.toml`:

```toml
[target.'cfg(windows)'.dependencies]
windows_users = "0.1.0"
```

## Usage Examples

### Create a manager

```rust
use windows_users::UserManager;

// Local machine
let mgr = UserManager::local();

// Remote machine
let mgr = UserManager::remote(r"\\SERVER01");
```

### Creating a User and Assigning a Group

On Windows, creating a local user account is often not enough by itself.  
A user should usually be added to a local group so Windows can determine which permissions and capabilities the account has.

The most common groups are:

- **Users** → standard account with basic access to the machine
- **Administrators** → elevated account with full system privileges

In most applications, adding the account to the **Users** group is the recommended and safest default.

```rust
use windows_users::{UserManager, User, well_known_sid};

let mgr = UserManager::local();

let username = "DemoUser1";

// Create the user
let user = User::builder()
    .name(username)
    .password("P@ssw0rd123!")
    .full_name("Demo User")
    .comment("User created with group assignment")
    .build();

match mgr.add_user(&user) {
    Ok(_) => println!("User created"),
    Err(e) => {
        eprintln!("Failed to create user: {e}");
        return;
    }
}

// Add the user to the standard Users group
let users_group = well_known_sid::USERS.name(&mgr).unwrap();

match mgr.add_users_to_group(&[username], &users_group) {
    Ok(_) => println!("User added to Users group"),
    Err(e) => eprintln!("Failed to add user to group: {e}"),
}

// Delete the user
match mgr.delete_user(username) {
    Ok(_) => println!("User deleted"),
    Err(e) => eprintln!("Failed to delete user: {e}"),
}
```

### Creating and Managing a User

```rust
use windows_users::{UserManager, User, UserUpdate};

let mgr = UserManager::local();

let username = "DemoUser2";

// Create a new user
let user = User::builder()
    .name(username)
    .password("P@ssw0rd123!")
    .full_name("Demo User")
    .comment("Created from windows_users")
    .build();

// Add the user
match mgr.add_user(&user) {
    Ok(_) => println!("User created"),
    Err(e) => eprintln!("Failed to create user: {e}"),
}

// Verify the user exists
match mgr.user_exists(username) {
    true => println!("User exists"),
    false => eprintln!("User does not exist or check failed"),
}

let settings = UserUpdate::builder()
    .comment("Updated comment")
    .full_name("Demo User Updated")
    .build();

// Update the user
match mgr.update_user(username, &settings) {
    Ok(_) => println!("User updated"),
    Err(e) => eprintln!("Failed to update user: {e}"),
}

// Delete the user
match mgr.delete_user(username) {
    Ok(_) => println!("User deleted"),
    Err(e) => eprintln!("Failed to delete user: {e}"),
}
```

### Using Struct Methods

```rust
use windows_users::{UserManager, User, UserUpdate};

let mgr = UserManager::local();

// Create a new user
let mut user = User::builder()
    .name("DemoUserMethods")
    .password("P@ssw0rd123!")
    .build();

// Add the user
match user.add(&mgr) {
    Ok(_) => println!("User created"),
    Err(e) => eprintln!("Failed to create user: {e}"),
}

// Verify the user exists
match user.exists(&mgr) {
    true => println!("User exists"),
    false => eprintln!("User does not exist or check failed"),
};

let update = UserUpdate::builder()
    .comment("Updated via struct method")
    .build();

// Update the user
match user.update(&mgr, &update) {
    Ok(_) => println!("User updated"),
    Err(e) => eprintln!("Failed to update user: {e}"),
}

// Delete the user
match user.delete(&mgr) {
    Ok(_) => println!("User deleted"),
    Err(e) => eprintln!("Failed to delete user: {e}"),
}
```

### Managing Group Membership

```rust
use windows_users::{UserManager, well_known_sid} ;

let mgr = UserManager::local();

let username = ["DemoUser"];
let group_name = well_known_sid::USERS.name(&mgr).unwrap();

match mgr.add_users_to_group(&username, &group_name) {
    Ok(_) => println!("User added to group"),
    Err(e) => eprintln!("Failed to add user to group: {e}"),
}

match mgr.list_group_members(&group_name) {
    Ok(members) => {
        for member in members {
            println!("{}\\{}", member.domain(), member.name());
        }
    }
    Err(e) => eprintln!("Failed to list members: {e}"),
}

match mgr.remove_users_from_group(&username, &group_name) {
    Ok(_) => println!("User removed from group"),
    Err(e) => eprintln!("Failed to remove user from group: {e}"),
}
```

### Listing Local Users

```rust
use windows_users::{UserFilterFlags, UserManager};

let mgr = UserManager::local();

match mgr.count_users(UserFilterFlags::NORMAL_ACCOUNT) {
    Ok(count) => println!("Normal accounts: {count}"),
    Err(e) => eprintln!("Failed to count users: {e}"),
}

match mgr.list_users(UserFilterFlags::NORMAL_ACCOUNT) {
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

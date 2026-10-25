//! The part of flint without UI: SSH and SFTP, the terminal emulator, the
//! vault and the account with sync. The desktop and mobile apps share it.

pub mod account;
pub mod app;
pub mod connection;
pub mod forward;
pub mod route;
pub mod shell;
pub mod ssh;
pub mod ssh_target;
pub mod term_emulator;
pub mod vault;

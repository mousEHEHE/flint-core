//! The part of flint without UI: SSH and SFTP, the terminal emulator, the
//! vault and the account with sync. The desktop and mobile apps share it.

pub mod account;
mod agent_forward;
pub mod app;
pub mod connection;
pub mod forward;
pub mod local_shell;
pub mod ppk;
pub mod proxy_command;
pub mod route;
pub mod shell;
pub mod ssh;
pub mod ssh_target;
pub mod term_emulator;
pub mod vault;

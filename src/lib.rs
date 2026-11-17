#[cfg(not(unix))]
compile_error!(
    "ssh-mcp-rs v0.1 supports Unix only; config/key permission checks must not be bypassed"
);
pub mod audit;
pub mod config;
pub mod policy;
pub mod server;
pub mod ssh;

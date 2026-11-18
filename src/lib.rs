#[cfg(not(unix))]
compile_error!(
    "ssh-mcp-rs v0.1 supports Unix only; config/key permission checks must not be bypassed"
);
pub mod audit;
pub mod config;
pub mod policy;
pub mod policy_engine;
pub mod server;
pub mod session;
pub mod ssh;
pub mod transfers;
pub mod upstream_compat;
mod upstream_paths;

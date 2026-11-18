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
mod upstream_awk;
pub mod upstream_compat;
mod upstream_elevation;
mod upstream_forbidden;
mod upstream_heads;
mod upstream_interpreters;
mod upstream_native;
mod upstream_nested;
mod upstream_paths;
mod upstream_readers;
mod upstream_shell;
mod upstream_write_targets;

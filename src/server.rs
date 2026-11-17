use crate::{
    audit::{Audit, digest},
    config::Config,
    policy,
    policy_engine::{self, CommandClass},
    session::Sessions,
    ssh::Connection,
    transfers,
};
use anyhow::{Context, Result, bail, ensure};
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct SshMcp {
    config: Arc<RwLock<Arc<Config>>>,
    config_path: Arc<PathBuf>,
    loaded_sha256: Arc<RwLock<String>>,
    audit: Arc<Audit>,
    semaphore: Arc<Semaphore>,
    max_concurrent_calls: u32,
    sessions: Arc<Sessions>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandArgs {
    profile: Option<String>,
    command: String,
    cwd: Option<String>,
    session: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DownloadArgs {
    profile: Option<String>,
    remote_path: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadArgs {
    profile: Option<String>,
    remote_path: String,
    content: String,
    #[serde(default)]
    overwrite: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenSessionArgs {
    profile: Option<String>,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    command: Option<String>,
    ttl_ms: Option<u64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionArgs {
    profile: Option<String>,
    name: String,
    lines: Option<usize>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignalArgs {
    profile: Option<String>,
    pid: u32,
    signal: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListArgs {
    profile: Option<String>,
    remote_path: String,
    max_entries: Option<usize>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileArgs {
    profile: Option<String>,
    remote_path: String,
    local_name: String,
    #[serde(default)]
    overwrite: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReloadArgs {
    profile: Option<String>,
    action: String,
}
impl SshMcp {
    pub fn new(config_path: PathBuf) -> Result<Self> {
        let (config, bytes) = Config::load_snapshot(&config_path)?;
        let file_sha = digest(&bytes);
        let audit = Audit::open(config.defaults.audit_path.as_deref())?;
        let limit = config.defaults.max_concurrent_calls;
        Ok(Self {
            config: Arc::new(RwLock::new(Arc::new(config))),
            config_path: Arc::new(config_path),
            loaded_sha256: Arc::new(RwLock::new(file_sha)),
            audit: Arc::new(audit),
            semaphore: Arc::new(Semaphore::new(limit)),
            max_concurrent_calls: limit as u32,
            sessions: Arc::new(Sessions::new()),
        })
    }

    fn current(&self) -> Result<Arc<Config>> {
        Ok(self
            .config
            .read()
            .map_err(|_| anyhow::anyhow!("config lock poisoned"))?
            .clone())
    }

    async fn reload_config(&self, arguments: Value) -> Result<Value> {
        let args: ReloadArgs = serde_json::from_value(arguments.clone())?;
        ensure!(
            matches!(args.action.as_str(), "status" | "reload"),
            "action must be status or reload"
        );
        // Lock admission BEFORE taking any authorization snapshot. A concurrent
        // reload must never leave a later call using previously revoked permissions.
        let permits = if args.action == "reload" {
            self.max_concurrent_calls
        } else {
            1
        };
        let _permit = self
            .semaphore
            .try_acquire_many(permits)
            .context("BUSY: reload requires an idle server; retry after active commands finish")?;
        let old = self.current()?;
        let loaded = self
            .loaded_sha256
            .read()
            .map_err(|_| anyhow::anyhow!("config hash lock poisoned"))?
            .clone();
        if args.action == "status" {
            let disk = crate::config::private_file(&self.config_path)
                .and_then(|()| Ok(digest(&std::fs::read(&*self.config_path)?)))
                .ok();
            return Ok(json!({"configured":true,"profiles":old.profiles.len(),
                "loadedSha256":loaded,"fileSha256":disk,"fileChanged":disk.as_ref().is_some_and(|hash| hash != &loaded),
                "activeSessions":self.sessions.count().await}));
        }
        // The *previous* configuration authorizes the reload. A new file cannot approve itself.
        let profile = old.profile(args.profile.as_deref())?;
        policy::authorize_write(profile)?;
        policy_engine::authorize(
            &old,
            profile,
            "reload-config",
            CommandClass::Destructive,
            None,
            false,
        )?;
        let id = uuid::Uuid::new_v4().to_string();
        let hash = digest(&serde_json::to_vec(&arguments)?);
        self.audit
            .record(&id, "reload_config", &profile.name, &hash, "attempt")?;
        let result = async {
            ensure!(self.sessions.count().await == 0, "BUSY: close active sessions before config reload");
            let (next, before) = Config::load_snapshot(&self.config_path)?;
            ensure!(next.defaults.audit_path == old.defaults.audit_path, "auditPath change requires service restart");
            ensure!(next.defaults.max_concurrent_calls == old.defaults.max_concurrent_calls, "maxConcurrentCalls change requires service restart");
            ensure!(std::fs::read(&*self.config_path)? == before, "config changed during reload; retry after settling");
            let count = next.profiles.len();
            *self.config.write().map_err(|_| anyhow::anyhow!("config lock poisoned"))? = Arc::new(next);
            *self.loaded_sha256.write().map_err(|_| anyhow::anyhow!("config hash lock poisoned"))? = digest(&before);
            Ok(json!({"reloaded":true,"profiles":count,"loadedSha256":digest(&before),"activeSessions":0}))
        }.await;
        self.audit.record(
            &id,
            "reload_config",
            &profile.name,
            &hash,
            if result.is_ok() {
                "succeeded"
            } else {
                "failed"
            },
        )?;
        result
    }

    async fn execute(&self, name: &str, arguments: Value) -> Result<Value> {
        if name == "reload_config" {
            return self.reload_config(arguments).await;
        }
        let _permit = self
            .semaphore
            .try_acquire()
            .context("BUSY: concurrency limit reached; no operation started")?;
        let config = self.current()?;
        if name == "list_connections" {
            ensure!(
                arguments.as_object().is_some_and(|a| a.is_empty()),
                "list_connections takes no arguments"
            );
            return Ok(json!({"profiles": config.profiles.iter().map(|p| json!({
                "name": p.name, "host": p.host, "port": p.port, "user": p.user,
                "readOnly": p.read_only, "role": p.role, "group": policy_engine::tier(p), "allowPrivileged": p.allow_privileged, "approvalPolicy": match p.approval_policy {
                    crate::config::ApprovalPolicy::Deny => "deny",
                    crate::config::ApprovalPolicy::ClientConfirmation => "client-confirmation",
                },
                "connectionMode": "per-call; sessions supported"
            })).collect::<Vec<_>>() }));
        }
        if name == "list_sessions" {
            ensure!(
                arguments.as_object().is_some_and(|a| a.is_empty()),
                "list_sessions takes no arguments"
            );
            return Ok(self.sessions.list().await);
        }
        ensure!(
            [
                "read_command",
                "run_command",
                "privileged_command",
                "sftp_download",
                "sftp_upload",
                "sftp_list",
                "sftp_upload_file",
                "sftp_download_file",
                "open_session",
                "close_session",
                "read_session_output",
                "signal_process"
            ]
            .contains(&name),
            "unknown tool"
        );
        let profile = config.profile(arguments.get("profile").and_then(Value::as_str))?;
        let id = uuid::Uuid::new_v4().to_string();
        let hash = digest(&serde_json::to_vec(&arguments)?);
        self.audit
            .record(&id, name, &profile.name, &hash, "attempt")?;
        let result = async {
            if matches!(
                name,
                "run_command"
                    | "privileged_command"
                    | "reload_config"
                    | "sftp_upload"
                    | "sftp_upload_file"
                    | "sftp_download_file"
                    | "open_session"
                    | "close_session"
                    | "signal_process"
            ) {
                policy::authorize_write(profile)?;
            }
            match name {
                "open_session" => {
                    let args: OpenSessionArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    let class = if args.kind == "background" {
                        policy_engine::classify(args.command.as_deref().unwrap_or(""))?
                    } else {
                        CommandClass::Destructive
                    };
                    policy_engine::authorize(
                        &config,
                        profile,
                        args.command.as_deref().unwrap_or("session:interactive"),
                        class,
                        None,
                        false,
                    )?;
                    self.sessions
                        .open(
                            &args.name,
                            &args.kind,
                            profile,
                            &config.defaults,
                            args.command.as_deref(),
                            args.ttl_ms,
                        )
                        .await
                }
                "close_session" => {
                    let args: SessionArgs = serde_json::from_value(arguments)?;
                    ensure!(args.lines.is_none(), "close_session does not accept lines");
                    let _ = args.profile;
                    policy_engine::authorize(
                        &config,
                        profile,
                        "session:close",
                        CommandClass::Destructive,
                        None,
                        false,
                    )?;
                    self.sessions.close(&args.name, profile).await
                }
                "read_session_output" => {
                    let args: SessionArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    self.sessions.output(&args.name, profile, args.lines).await
                }
                "privileged_command" => {
                    ensure!(
                        profile.allow_privileged,
                        "PRIVILEGED_DENIED: allowPrivileged must be enabled for this profile"
                    );
                    let args: CommandArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    ensure!(
                        args.session.is_none(),
                        "privileged_command cannot attach to an existing session"
                    );
                    policy_engine::classify(&args.command)?; // deny unconditional forbidden invocations
                    policy_engine::authorize(
                        &config,
                        profile,
                        &args.command,
                        CommandClass::Privileged,
                        None,
                        false,
                    )?;
                    let shell = policy::shell_command(&args.command, args.cwd.as_deref())?;
                    // sudo -n never prompts for a password; OS sudoers is a second, independent gate.
                    self.with_connection(profile, Operation::Command(format!("sudo -n -- {shell}")))
                        .await
                }
                "read_command" | "run_command" => {
                    let args: CommandArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    if name == "read_command" {
                        ensure!(
                            args.session.is_none(),
                            "read_command does not attach to sessions"
                        );
                    }
                    let classification = if name == "read_command" {
                        policy::read_command(&args.command)?;
                        CommandClass::ReadOnly
                    } else {
                        policy_engine::classify(&args.command)?
                    };
                    policy_engine::authorize(
                        &config,
                        profile,
                        &args.command,
                        classification,
                        None,
                        false,
                    )?;
                    if let Some(session) = args.session {
                        ensure!(args.cwd.is_none(), "session controls its own cwd");
                        let output = self
                            .sessions
                            .run(&session, profile, &args.command, &config.defaults)
                            .await?;
                        return Ok(serde_json::to_value(output)?);
                    }
                    let command = if name == "read_command" {
                        policy::read_command(&args.command)?
                    } else {
                        args.command
                    };
                    let command = policy::shell_command(&command, args.cwd.as_deref())?;
                    self.with_connection(profile, Operation::Command(command))
                        .await
                }
                "signal_process" => {
                    let args: SignalArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    ensure!(
                        (2..=4_194_304).contains(&args.pid),
                        "invalid pid; PID 1 is never allowed"
                    );
                    ensure!(
                        matches!(args.signal.as_str(), "INT" | "TERM" | "KILL"),
                        "signal must be INT, TERM or KILL"
                    );
                    policy_engine::authorize(
                        &config,
                        profile,
                        &format!("signal:{} {}", args.signal, args.pid),
                        CommandClass::Destructive,
                        None,
                        false,
                    )?;
                    let command = policy::shell_command(
                        &format!("kill -{} {}", args.signal, args.pid),
                        None,
                    )?;
                    self.with_connection(profile, Operation::Command(command))
                        .await
                }
                "sftp_list" => {
                    let args: ListArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    policy_engine::authorize(
                        &config,
                        profile,
                        "sftp:list",
                        CommandClass::ReadOnly,
                        Some(&args.remote_path),
                        false,
                    )?;
                    let max = args.max_entries.unwrap_or(100);
                    ensure!(
                        (1..=1000).contains(&max),
                        "maxEntries must be between 1 and 1000"
                    );
                    self.with_connection(profile, Operation::List(args.remote_path, max))
                        .await
                }
                "sftp_upload_file" | "sftp_download_file" => {
                    let args: FileArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    transfers::local_destination(&config.defaults, &args.local_name)?;
                    policy_engine::authorize(
                        &config,
                        profile,
                        if name == "sftp_upload_file" {
                            "sftp:upload-file"
                        } else {
                            "sftp:download-file"
                        },
                        CommandClass::Destructive,
                        Some(&args.remote_path),
                        name == "sftp_upload_file",
                    )?;
                    if name == "sftp_upload_file" {
                        self.with_connection(
                            profile,
                            Operation::UploadFile(
                                args.remote_path,
                                args.local_name,
                                args.overwrite,
                            ),
                        )
                        .await
                    } else {
                        self.with_connection(
                            profile,
                            Operation::DownloadFile(
                                args.remote_path,
                                args.local_name,
                                args.overwrite,
                            ),
                        )
                        .await
                    }
                }
                "sftp_download" => {
                    let args: DownloadArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    policy_engine::authorize(
                        &config,
                        profile,
                        "sftp:download",
                        CommandClass::ReadOnly,
                        Some(&args.remote_path),
                        false,
                    )?;
                    self.with_connection(profile, Operation::Download(args.remote_path))
                        .await
                }
                "sftp_upload" => {
                    let args: UploadArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    policy_engine::authorize(
                        &config,
                        profile,
                        "sftp:upload",
                        CommandClass::Destructive,
                        Some(&args.remote_path),
                        true,
                    )?;
                    ensure!(
                        args.content.len() <= config.defaults.transfer_max_bytes,
                        "TRANSFER_TOO_LARGE"
                    );
                    self.with_connection(
                        profile,
                        Operation::Upload(args.remote_path, args.content, args.overwrite),
                    )
                    .await
                }
                _ => bail!("unknown tool"),
            }
        }
        .await;
        let phase = match &result {
            Ok(value) if value.get("ok") == Some(&Value::Bool(false)) => "failed",
            Ok(_) => "succeeded",
            Err(_) => "failed",
        };
        self.audit
            .record(&id, name, &profile.name, &hash, phase)
            .context("AUDIT_ERROR: operation may already have executed; do not retry blindly")?;
        result
    }

    async fn with_connection(
        &self,
        profile: &crate::config::Profile,
        operation: Operation,
    ) -> Result<Value> {
        let config = self.current()?;
        let timeout_ms = if matches!(
            &operation,
            Operation::UploadFile(..) | Operation::DownloadFile(..)
        ) {
            config.defaults.transfer_timeout_ms
        } else {
            config.defaults.command_timeout_ms
        };
        let connection = Connection::connect(profile, &config.defaults).await?;
        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms + 3000),
            async {
                match operation {
                    Operation::Command(command) => Ok(serde_json::to_value(connection.command(&command, &config.defaults).await?)?),
                    Operation::Download(path) => {
                        let content = connection.download(&path, config.defaults.transfer_max_bytes).await?;
                        Ok(json!({"remotePath": path, "bytes": content.len(), "content": content}))
                    }
                    Operation::Upload(path, content, overwrite) => {
                        connection.upload(&path, content.as_bytes(), overwrite).await?;
                        Ok(json!({"remotePath": path, "bytes": content.len(), "sha256": digest(content.as_bytes()), "overwrite": overwrite, "atomic": false}))
                    }
                    Operation::List(path, max) => transfers::list(&connection, &path, max).await,
                    Operation::UploadFile(path, name, overwrite) => transfers::upload_file(&connection, &config.defaults, &name, &path, overwrite).await,
                    Operation::DownloadFile(path, name, overwrite) => transfers::download_file(&connection, &config.defaults, &path, &name, overwrite).await,
                }
            }
        ).await;
        connection.close().await;
        result.context(
            "OPERATION_TIMEOUT: remote effects may be incomplete; verify before retrying a write",
        )?
    }
}
enum Operation {
    Command(String),
    Download(String),
    Upload(String, String, bool),
    List(String, usize),
    UploadFile(String, String, bool),
    DownloadFile(String, String, bool),
}

pub fn tools() -> Vec<Tool> {
    let profile = json!({"type":"string", "description":"Configured SSH profile. Uses defaultProfile when omitted."});
    let command_properties = json!({
        "profile":profile,
        "command":{"type":"string", "minLength":1, "maxLength":16384, "description":"Exact remote command. Never include passwords or tokens."},
        "cwd":{"type":"string", "description":"Optional absolute working directory. Not a filesystem sandbox."},
        "session":{"type":"string", "description":"Optional existing interactive session name; preserves cwd and shell environment."}
    });
    let mut stateless_properties = command_properties.clone();
    stateless_properties
        .as_object_mut()
        .expect("command schema")
        .remove("session");
    let mut entries = vec![
        tool(
            "list_connections",
            "List configured hosts and write policies.",
            true,
            false,
            json!({}),
            json!([]),
        ),
        tool(
            "list_sessions",
            "List active interactive/background sessions; no SSH connection.",
            true,
            false,
            json!({}),
            json!([]),
        ),
        tool(
            "read_command",
            "Execute narrow allowlisted read-only commands. No shells or mutation.",
            true,
            true,
            stateless_properties.clone(),
            json!(["command"]),
        ),
        tool(
            "run_command",
            "Execute arbitrary shell command or send a command to an interactive session. Writes may persist after timeout; requires client-managed confirmation.",
            false,
            true,
            command_properties.clone(),
            json!(["command"]),
        ),
        tool(
            "open_session",
            "Open a persistent interactive shell or start a background command. Requires a write-enabled profile. Sessions have a finite TTL.",
            false,
            true,
            json!({"profile":profile,"name":{"type":"string"},"type":{"type":"string","enum":["interactive","background"]},"command":{"type":"string","description":"Required for background sessions only."},"ttlMs":{"type":"integer","minimum":1000,"maximum":3600000}}),
            json!(["name", "type"]),
        ),
        tool(
            "close_session",
            "Close a session and best-effort signal a background job. Never claim remote process termination without evidence.",
            false,
            true,
            json!({"profile":profile,"name":{"type":"string"}}),
            json!(["name"]),
        ),
        tool(
            "read_session_output",
            "Read bounded recent stdout/stderr from a background session.",
            true,
            true,
            json!({"profile":profile,"name":{"type":"string"},"lines":{"type":"integer","minimum":1,"maximum":500}}),
            json!(["name"]),
        ),
        tool(
            "signal_process",
            "Send INT, TERM or KILL to a positive remote PID over SSH. Destructive and write-gated.",
            false,
            true,
            json!({"profile":profile,"pid":{"type":"integer","minimum":2},"signal":{"type":"string","enum":["INT","TERM","KILL"]}}),
            json!(["pid", "signal"]),
        ),
        tool(
            "sftp_download",
            "Read bounded UTF-8 remote file. No local file is created.",
            true,
            true,
            json!({"profile":profile,"remotePath":{"type":"string"}}),
            json!(["remotePath"]),
        ),
        tool(
            "sftp_upload",
            "Write bounded UTF-8 remote file. Existing destinations refused unless overwrite=true; not atomic.",
            false,
            true,
            json!({"profile":profile,"remotePath":{"type":"string"},"content":{"type":"string"},"overwrite":{"type":"boolean","default":false}}),
            json!(["remotePath", "content"]),
        ),
    ];
    entries.extend([
        tool("sftp_list", "List remote directory entries with a bounded response; read-only.", true, true,
            json!({"profile":profile,"remotePath":{"type":"string"},"maxEntries":{"type":"integer","minimum":1,"maximum":1000}}), json!(["remotePath"])),
        tool("sftp_upload_file", "Stream a binary file from the private server-side transferRoot to the remote SSH host; content never enters model context. Requires write confirmation.", false, true,
            json!({"profile":profile,"remotePath":{"type":"string"},"localName":{"type":"string","description":"A single filename inside the private transferRoot; not a path."},"overwrite":{"type":"boolean","default":false}}), json!(["remotePath","localName"])),
        tool("sftp_download_file", "Stream a remote binary file into private server-side transferRoot, atomically publishing the local destination; requires write confirmation.", false, true,
            json!({"profile":profile,"remotePath":{"type":"string"},"localName":{"type":"string","description":"Single filename inside the private transferRoot."},"overwrite":{"type":"boolean","default":false}}), json!(["remotePath","localName"])),
    ]);
    entries.extend([
        tool("privileged_command", "Run the exact command using noninteractive sudo -n; only when allowPrivileged=true and the remote sudoers policy grants it. Always write-classified.", false, true,
            stateless_properties, json!(["command"])),
        tool("reload_config", "Inspect configuration status or atomically reload private config. Reload requires a write-enabled profile, no active sessions, and an idle server; audit/concurrency changes require restart.", false, false,
            json!({"profile":profile,"action":{"type":"string","enum":["status","reload"]}}), json!(["action"])),
    ]);
    entries.shrink_to_fit();
    entries
}
fn tool(
    name: &'static str,
    description: &'static str,
    read: bool,
    open: bool,
    props: Value,
    required: Value,
) -> Tool {
    serde_json::from_value(json!({
        "name":name, "description":description,
        "inputSchema":{"type":"object","properties":props,"required":required,"additionalProperties":false},
        "annotations":{"readOnlyHint":read,"destructiveHint":!read,"openWorldHint":open,"idempotentHint":read}
    })).expect("static tool schema is valid")
}

impl ServerHandler for SshMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
            .with_instructions("Use read_command only for its documented grammar. Arbitrary commands, sessions, signals and uploads are write tools. The authenticated client manages confirmation; the server never attests human approval or calls elicitation/create. Never automatically retry uncertain writes.")
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(serde_json::from_value(json!({"tools": tools()})).expect("static tool list"))
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools().into_iter().find(|t| t.name == name)
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let result = match self.execute(&request.name, arguments).await {
            Ok(value) => {
                let mut result =
                    CallToolResult::success(vec![ContentBlock::text(value.to_string())]);
                result.is_error = Some(value.get("ok") == Some(&Value::Bool(false)));
                result.structured_content = Some(value);
                result
            }
            Err(error) => CallToolResult::error(vec![ContentBlock::text(format!("{error:#}"))]),
        };
        Ok(result.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tools_have_truthful_annotations_and_fixed_schemas() {
        let definitions = serde_json::to_value(tools()).unwrap();
        assert_eq!(definitions.as_array().unwrap().len(), 15);
        for tool in definitions.as_array().unwrap() {
            let write = matches!(
                tool["name"].as_str().unwrap(),
                "run_command"
                    | "privileged_command"
                    | "reload_config"
                    | "sftp_upload"
                    | "sftp_upload_file"
                    | "sftp_download_file"
                    | "open_session"
                    | "close_session"
                    | "signal_process"
            );
            assert_eq!(tool["annotations"]["readOnlyHint"], !write);
            assert_eq!(tool["annotations"]["destructiveHint"], write);
            assert_eq!(tool["annotations"]["idempotentHint"], !write);
            assert!(tool["annotations"]["openWorldHint"].is_boolean());
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }
    #[test]
    fn caller_cannot_self_approve() {
        for field in ["approved", "confirmation", "approvalPolicy"] {
            let mut input = json!({"command":"id"});
            input[field] = json!(true);
            assert!(serde_json::from_value::<CommandArgs>(input).is_err());
        }
    }
}

use crate::{
    audit::{Audit, digest},
    config::Config,
    policy,
    session::Sessions,
    ssh::Connection,
};
use anyhow::{Context, Result, bail, ensure};
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct SshMcp {
    config: Arc<Config>,
    audit: Arc<Audit>,
    semaphore: Arc<Semaphore>,
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
impl SshMcp {
    pub fn new(config: Config) -> Result<Self> {
        let audit = Audit::open(config.defaults.audit_path.as_deref())?;
        let limit = config.defaults.max_concurrent_calls;
        Ok(Self {
            config: Arc::new(config),
            audit: Arc::new(audit),
            semaphore: Arc::new(Semaphore::new(limit)),
            sessions: Arc::new(Sessions::new()),
        })
    }

    async fn execute(&self, name: &str, arguments: Value) -> Result<Value> {
        if name == "list_connections" {
            ensure!(
                arguments.as_object().is_some_and(|a| a.is_empty()),
                "list_connections takes no arguments"
            );
            return Ok(
                json!({"profiles": self.config.profiles.iter().map(|p| json!({
                "name": p.name, "host": p.host, "port": p.port, "user": p.user,
                "readOnly": p.read_only, "approvalPolicy": match p.approval_policy {
                    crate::config::ApprovalPolicy::Deny => "deny",
                    crate::config::ApprovalPolicy::ClientConfirmation => "client-confirmation",
                },
                "connectionMode": "per-call; sessions supported"
            })).collect::<Vec<_>>() }),
            );
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
                "sftp_download",
                "sftp_upload",
                "open_session",
                "close_session",
                "read_session_output",
                "signal_process"
            ]
            .contains(&name),
            "unknown tool"
        );
        let profile = self
            .config
            .profile(arguments.get("profile").and_then(Value::as_str))?;
        let id = uuid::Uuid::new_v4().to_string();
        let hash = digest(&serde_json::to_vec(&arguments)?);
        self.audit
            .record(&id, name, &profile.name, &hash, "attempt")?;
        let result = async {
            if matches!(
                name,
                "run_command" | "sftp_upload" | "open_session" | "close_session" | "signal_process"
            ) {
                policy::authorize_write(profile)?;
            }
            let _permit = self
                .semaphore
                .try_acquire()
                .context("BUSY: concurrency limit reached; no operation started")?;
            match name {
                "open_session" => {
                    let args: OpenSessionArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    self.sessions
                        .open(
                            &args.name,
                            &args.kind,
                            profile,
                            &self.config.defaults,
                            args.command.as_deref(),
                            args.ttl_ms,
                        )
                        .await
                }
                "close_session" => {
                    let args: SessionArgs = serde_json::from_value(arguments)?;
                    ensure!(args.lines.is_none(), "close_session does not accept lines");
                    let _ = args.profile;
                    self.sessions.close(&args.name, profile).await
                }
                "read_session_output" => {
                    let args: SessionArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    self.sessions.output(&args.name, profile, args.lines).await
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
                    if let Some(session) = args.session {
                        ensure!(args.cwd.is_none(), "session controls its own cwd");
                        let output = self
                            .sessions
                            .run(&session, profile, &args.command, &self.config.defaults)
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
                    let command = policy::shell_command(
                        &format!("kill -{} {}", args.signal, args.pid),
                        None,
                    )?;
                    self.with_connection(profile, Operation::Command(command))
                        .await
                }
                "sftp_download" => {
                    let args: DownloadArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    self.with_connection(profile, Operation::Download(args.remote_path))
                        .await
                }
                "sftp_upload" => {
                    let args: UploadArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    ensure!(
                        args.content.len() <= self.config.defaults.transfer_max_bytes,
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
        let connection = Connection::connect(profile, &self.config.defaults).await?;
        let result = tokio::time::timeout(
            Duration::from_millis(self.config.defaults.command_timeout_ms + 3000),
            async {
                match operation {
                    Operation::Command(command) => Ok(serde_json::to_value(connection.command(&command, &self.config.defaults).await?)?),
                    Operation::Download(path) => {
                        let content = connection.download(&path, self.config.defaults.transfer_max_bytes).await?;
                        Ok(json!({"remotePath": path, "bytes": content.len(), "content": content}))
                    }
                    Operation::Upload(path, content, overwrite) => {
                        connection.upload(&path, content.as_bytes(), overwrite).await?;
                        Ok(json!({"remotePath": path, "bytes": content.len(), "sha256": digest(content.as_bytes()), "overwrite": overwrite, "atomic": false}))
                    }
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
}

pub fn tools() -> Vec<Tool> {
    let profile = json!({"type":"string", "description":"Configured SSH profile. Uses defaultProfile when omitted."});
    let command_properties = json!({
        "profile":profile,
        "command":{"type":"string", "minLength":1, "maxLength":16384, "description":"Exact remote command. Never include passwords or tokens."},
        "cwd":{"type":"string", "description":"Optional absolute working directory. Not a filesystem sandbox."},
        "session":{"type":"string", "description":"Optional existing interactive session name; preserves cwd and shell environment."}
    });
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
            command_properties.clone(),
            json!(["command"]),
        ),
        tool(
            "run_command",
            "Execute arbitrary shell command or send a command to an interactive session. Writes may persist after timeout; requires client-managed confirmation.",
            false,
            true,
            command_properties,
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
        assert_eq!(definitions.as_array().unwrap().len(), 10);
        for tool in definitions.as_array().unwrap() {
            let write = matches!(
                tool["name"].as_str().unwrap(),
                "run_command" | "sftp_upload" | "open_session" | "close_session" | "signal_process"
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

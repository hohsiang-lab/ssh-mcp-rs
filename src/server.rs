use crate::{
    audit::{Audit, digest},
    config::Config,
    policy,
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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandArgs {
    profile: Option<String>,
    command: String,
    cwd: Option<String>,
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

impl SshMcp {
    pub fn new(config: Config) -> Result<Self> {
        let audit = Audit::open(config.defaults.audit_path.as_deref())?;
        let limit = config.defaults.max_concurrent_calls;
        Ok(Self {
            config: Arc::new(config),
            audit: Arc::new(audit),
            semaphore: Arc::new(Semaphore::new(limit)),
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
                "connectionMode": "per-call"
            })).collect::<Vec<_>>() }),
            );
        }
        ensure!(
            [
                "read_command",
                "run_command",
                "sftp_download",
                "sftp_upload"
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
            // All authorization and validation happen BEFORE SSH connection or side effects.
            if matches!(name, "run_command" | "sftp_upload") { policy::authorize_write(profile)?; }
            let operation = match name {
                "read_command" | "run_command" => {
                    let args: CommandArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    let command = if name == "read_command" { policy::read_command(&args.command)? } else { args.command };
                    let command = policy::shell_command(&command, args.cwd.as_deref())?;
                    Operation::Command(command)
                }
                "sftp_download" => {
                    let args: DownloadArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    Operation::Download(args.remote_path)
                }
                "sftp_upload" => {
                    let args: UploadArgs = serde_json::from_value(arguments)?;
                    let _ = args.profile;
                    policy::path(&args.remote_path)?;
                    ensure!(args.content.len() <= self.config.defaults.transfer_max_bytes, "TRANSFER_TOO_LARGE");
                    Operation::Upload(args.remote_path, args.content, args.overwrite)
                }
                _ => bail!("unknown tool"),
            };
            let _permit = self.semaphore.try_acquire().context("BUSY: concurrency limit reached; no operation started")?;
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
            result.context("OPERATION_TIMEOUT: remote effects may be incomplete; verify before retrying a write")?
        }.await;
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
}
enum Operation {
    Command(String),
    Download(String),
    Upload(String, String, bool),
}

pub fn tools() -> Vec<Tool> {
    let profile = json!({"type":"string", "description":"Configured SSH profile. Uses defaultProfile when omitted."});
    let command_properties = json!({
        "profile": profile,
        "command":{"type":"string", "minLength":1, "maxLength":16384, "description":"Exact remote command. Never include passwords or tokens."},
        "cwd":{"type":"string", "description":"Optional absolute working directory. Not a filesystem sandbox."}
    });
    let entries = [
        (
            "list_connections",
            "List configured SSH hosts and their read/write policies. Does not connect to hosts or return key material.",
            true,
            false,
            false,
            json!({}),
            json!([]),
        ),
        (
            "read_command",
            "Run a narrow read-only command: uname, id, pwd, uptime, whoami, ls, cat, df, git --version, gh --version. No shell operators or general git/gh subcommands; use run_command for those.",
            true,
            false,
            true,
            command_properties.clone(),
            json!(["command"]),
        ),
        (
            "run_command",
            "Execute the exact arbitrary shell command over SSH. May write/delete files, commit/push Git, create PRs with gh, access the network or change services. Requires a write-enabled profile and client-managed confirmation. No automatic retry: effects may persist after timeout. cwd is not a sandbox.",
            false,
            true,
            true,
            command_properties,
            json!(["command"]),
        ),
        (
            "sftp_download",
            "Read a bounded UTF-8 remote file via SFTP. No local file is created. Do not request credentials or private keys unless explicitly needed.",
            true,
            false,
            true,
            json!({"profile":profile,"remotePath":{"type":"string","description":"Absolute remote file path."}}),
            json!(["remotePath"]),
        ),
        (
            "sftp_upload",
            "Write UTF-8 content via SFTP. New files use 0600. By default existing destinations are refused. overwrite=true truncates the destination (including symlink targets); uploads are not atomic and a failed upload can leave partial data. Requires a write-enabled profile and client-managed confirmation.",
            false,
            true,
            true,
            json!({"profile":profile,"remotePath":{"type":"string","description":"Absolute remote destination."},"content":{"type":"string","description":"Exact UTF-8 content to write."},"overwrite":{"type":"boolean","default":false,"description":"Explicitly allow replacing an existing destination; may follow symlinks."}}),
            json!(["remotePath", "content"]),
        ),
    ];
    entries.into_iter().map(|(name, description, read, destructive, open, properties, required)| {
        serde_json::from_value(json!({
            "name": name, "description": description,
            "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
            "annotations":{"readOnlyHint":read,"destructiveHint":destructive,"openWorldHint":open,"idempotentHint":read}
        })).expect("static tool schema is valid")
    }).collect()
}

impl ServerHandler for SshMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
            .with_instructions("Use read_command only for its documented grammar. All arbitrary commands and uploads are write tools. The authenticated client manages confirmation; the server never attests human approval and never calls elicitation/create. Honor errors and do not automatically retry failed writes.")
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(serde_json::from_value(json!({"tools": tools()})).expect("static tool list is valid"))
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
    fn writes_never_advertise_readonly_or_idempotence() {
        let definitions = serde_json::to_value(tools()).unwrap();
        for tool in definitions.as_array().unwrap() {
            let write = matches!(
                tool["name"].as_str().unwrap(),
                "run_command" | "sftp_upload"
            );
            assert_eq!(tool["annotations"]["readOnlyHint"], !write);
            assert_eq!(tool["annotations"]["destructiveHint"], write);
            assert_eq!(tool["annotations"]["idempotentHint"], !write);
            assert!(tool["annotations"]["openWorldHint"].is_boolean());
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }
    #[test]
    fn caller_cannot_self_approve_or_add_a_session() {
        for field in ["approved", "confirmation", "session", "approvalPolicy"] {
            let mut input = json!({"command":"id"});
            input[field] = json!(true);
            assert!(serde_json::from_value::<CommandArgs>(input).is_err());
        }
    }
}

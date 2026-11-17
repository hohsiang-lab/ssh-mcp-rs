use crate::{
    config::{Defaults, Profile},
    policy,
    ssh::{CommandOutput, Connection},
};
use anyhow::{Context, Result, bail, ensure};
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf, client};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, task::JoinHandle};

type Writer = ChannelWriteHalf<client::Msg>;
const MAX_SESSIONS: usize = 8;
const MAX_AGE_MS: u64 = 3_600_000;
const DEFAULT_AGE_MS: u64 = 600_000;

pub struct Sessions {
    active: Arc<Mutex<HashMap<String, Arc<Entry>>>>,
}
struct Entry {
    profile: String,
    kind: &'static str,
    expires: Instant,
    state: State,
}
enum State {
    Interactive(Mutex<Interactive>),
    Background {
        writer: Writer,
        output: Arc<Mutex<BackgroundOutput>>,
        task: Mutex<Option<JoinHandle<()>>>,
    },
}
struct Interactive {
    connection: Arc<Connection>,
    reader: ChannelReadHalf,
    writer: Writer,
}
#[derive(Default)]
struct BackgroundOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    done: bool,
    truncated: bool,
}
fn push_bounded(dst: &mut Vec<u8>, chunk: &[u8], cap: usize, truncated: &mut bool) {
    if chunk.len() >= cap {
        dst.clear();
        dst.extend_from_slice(&chunk[chunk.len() - cap..]);
        *truncated = true;
    } else {
        let excess = dst.len().saturating_add(chunk.len()).saturating_sub(cap);
        if excess > 0 {
            dst.drain(..excess);
            *truncated = true;
        }
        dst.extend_from_slice(chunk);
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}
impl Sessions {
    pub fn new() -> Self {
        let active: Arc<Mutex<HashMap<String, Arc<Entry>>>> = Arc::new(Mutex::new(HashMap::new()));
        let weak = Arc::downgrade(&active);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(active) = weak.upgrade() else { break };
                let expired = {
                    let mut entries = active.lock().await;
                    let names = entries
                        .iter()
                        .filter(|(_, e)| Instant::now() >= e.expires)
                        .map(|(name, _)| name.clone())
                        .collect::<Vec<_>>();
                    names
                        .iter()
                        .filter_map(|name| entries.remove(name))
                        .collect::<Vec<_>>()
                };
                for entry in expired {
                    Self::stop(entry).await;
                }
            }
        });
        Self { active }
    }

    pub async fn list(&self) -> Value {
        let entries = self.active.lock().await;
        json!({"sessions": entries.iter().map(|(name, item)| json!({
            "name":name, "profile":item.profile, "type":item.kind,
            "expiresInMs": item.expires.saturating_duration_since(Instant::now()).as_millis()
        })).collect::<Vec<_>>()})
    }

    pub async fn count(&self) -> usize {
        self.active.lock().await.len()
    }

    pub async fn open(
        &self,
        name: &str,
        kind: &str,
        profile: &Profile,
        defaults: &Defaults,
        command: Option<&str>,
        ttl_ms: Option<u64>,
    ) -> Result<Value> {
        validate_name(name)?;
        policy::authorize_write(profile)?;
        ensure!(
            matches!(kind, "interactive" | "background"),
            "invalid session type"
        );
        if kind == "background" {
            policy::validate_command(command.context("background session requires a command")?)?;
        } else {
            ensure!(
                command.is_none(),
                "interactive session does not accept an opening command"
            );
        }
        let ttl = ttl_ms.unwrap_or(DEFAULT_AGE_MS);
        ensure!(
            (1000..=MAX_AGE_MS).contains(&ttl),
            "ttlMs must be between 1000 and 3600000"
        );
        {
            let entries = self.active.lock().await;
            ensure!(!entries.contains_key(name), "session name already exists");
            ensure!(
                entries.len() < MAX_SESSIONS,
                "SESSION_LIMIT: maximum active sessions reached"
            );
        }
        let connection = Arc::new(Connection::connect(profile, defaults).await?);
        let entry = if kind == "interactive" {
            let channel = connection.open_shell().await?;
            let (reader, writer) = channel.split();
            Entry {
                profile: profile.name.clone(),
                kind: "interactive",
                expires: Instant::now() + Duration::from_millis(ttl),
                state: State::Interactive(Mutex::new(Interactive {
                    connection,
                    reader,
                    writer,
                })),
            }
        } else {
            let cmd = policy::shell_command(command.unwrap(), None)?;
            let channel = connection.open_exec(&cmd).await?;
            let (mut reader, writer) = channel.split();
            let output = Arc::new(Mutex::new(BackgroundOutput::default()));
            let saved = output.clone();
            let cap = defaults.command_max_output_bytes;
            let task = tokio::spawn(async move {
                while let Some(message) = reader.wait().await {
                    let mut state = saved.lock().await;
                    match message {
                        ChannelMsg::Data { data } => {
                            let mut truncated = state.truncated;
                            push_bounded(&mut state.stdout, &data, cap, &mut truncated);
                            state.truncated = truncated;
                        }
                        ChannelMsg::ExtendedData { data, .. } => {
                            let mut truncated = state.truncated;
                            push_bounded(&mut state.stderr, &data, cap, &mut truncated);
                            state.truncated = truncated;
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            state.exit_status = Some(exit_status)
                        }
                        _ => {}
                    }
                }
                saved.lock().await.done = true;
                connection.close().await;
            });
            Entry {
                profile: profile.name.clone(),
                kind: "background",
                expires: Instant::now() + Duration::from_millis(ttl),
                state: State::Background {
                    writer,
                    output,
                    task: Mutex::new(Some(task)),
                },
            }
        };
        let mut entries = self.active.lock().await;
        if entries.contains_key(name) || entries.len() >= MAX_SESSIONS {
            drop(entries);
            Self::stop(Arc::new(entry)).await;
            bail!("session name already exists or limit reached");
        }
        entries.insert(name.to_owned(), Arc::new(entry));
        Ok(json!({"name":name,"profile":profile.name,"type":kind,"ttlMs":ttl}))
    }

    async fn get(&self, name: &str, profile: &Profile) -> Result<Arc<Entry>> {
        validate_name(name)?;
        let entry = self
            .active
            .lock()
            .await
            .get(name)
            .cloned()
            .context("session not found")?;
        ensure!(
            entry.profile == profile.name,
            "POLICY_DENIED: session belongs to a different profile"
        );
        ensure!(
            Instant::now() < entry.expires,
            "session expired; close and reopen"
        );
        Ok(entry)
    }

    pub async fn run(
        &self,
        name: &str,
        profile: &Profile,
        command: &str,
        defaults: &Defaults,
    ) -> Result<CommandOutput> {
        policy::authorize_write(profile)?;
        policy::validate_command(command)?;
        let entry = self.get(name, profile).await?;
        let State::Interactive(inner) = &entry.state else {
            bail!("run_command only accepts interactive sessions")
        };
        let mut interactive = inner.lock().await;
        let result = interactive.run(command, defaults).await?;
        if result.timed_out || result.remote_process_may_continue {
            drop(interactive);
            let _ = self.close(name, profile).await;
        }
        Ok(result)
    }

    pub async fn output(
        &self,
        name: &str,
        profile: &Profile,
        lines: Option<usize>,
    ) -> Result<Value> {
        let entry = self.get(name, profile).await?;
        let State::Background { output, .. } = &entry.state else {
            bail!("read_session_output requires a background session")
        };
        let state = output.lock().await;
        let count = lines.unwrap_or(30);
        ensure!((1..=500).contains(&count), "lines must be within 1..500");
        let tail = |b: &[u8]| {
            let raw = String::from_utf8_lossy(b);
            raw.lines()
                .rev()
                .take(count)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(
            json!({"name":name,"running":!state.done,"exitStatus":state.exit_status,
            "stdout":tail(&state.stdout),"stderr":tail(&state.stderr),"truncated":state.truncated}),
        )
    }

    pub async fn close(&self, name: &str, profile: &Profile) -> Result<Value> {
        validate_name(name)?;
        let removed = {
            let mut entries = self.active.lock().await;
            let entry = entries.get(name).context("session not found")?;
            ensure!(
                entry.profile == profile.name,
                "POLICY_DENIED: session belongs to a different profile"
            );
            entries.remove(name).context("session disappeared")?
        };
        let may_continue = match &removed.state {
            State::Interactive(_) => false,
            State::Background { output, .. } => !output.lock().await.done,
        };
        Self::stop(removed).await;
        Ok(json!({"name":name,"closed":true,"remoteProcessMayContinue":may_continue}))
    }

    async fn stop(entry: Arc<Entry>) {
        match &entry.state {
            State::Interactive(inner) => {
                let state = inner.lock().await;
                let _ = tokio::time::timeout(Duration::from_secs(1), state.writer.close()).await;
                state.connection.close().await;
            }
            State::Background { writer, task, .. } => {
                let _ =
                    tokio::time::timeout(Duration::from_secs(1), writer.signal(russh::Sig::TERM))
                        .await;
                let mut task = task.lock().await;
                if let Some(handle) = task.take() {
                    // Avoid orphaning the reader indefinitely. Signal is best-effort.
                    let mut handle = handle;
                    if tokio::time::timeout(Duration::from_secs(2), &mut handle)
                        .await
                        .is_err()
                    {
                        let _ = writer.signal(russh::Sig::KILL).await;
                        handle.abort();
                    }
                }
            }
        }
    }
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid session name"
    );
    Ok(())
}

impl Interactive {
    async fn run(&mut self, command: &str, defaults: &Defaults) -> Result<CommandOutput> {
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let start = format!("__MCP_BEGIN_{marker}__");
        let end = format!("__MCP_END_{marker}__:");
        let payload = format!(
            "printf '\\n{start}\\n'\n{command}\n__mcp_status=$?\nprintf '\\n{end}%s\\n' \"$__mcp_status\"\n"
        );
        self.writer.data_bytes(payload.into_bytes()).await?;
        let mut pending = Vec::<u8>::new();
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut found_start = false;
        let mut truncated = false;
        let mut status = None;
        let cap = defaults.command_max_output_bytes;
        let wait =
            tokio::time::timeout(Duration::from_millis(defaults.command_timeout_ms), async {
                loop {
                    match self.reader.wait().await {
                        Some(ChannelMsg::Data { data }) => {
                            pending.extend_from_slice(&data);
                            if !found_start {
                                if let Some(i) = find_bytes(&pending, start.as_bytes()) {
                                    pending.drain(..i + start.len());
                                    found_start = true;
                                } else {
                                    let keep = start.len().saturating_sub(1);
                                    if pending.len() > keep {
                                        pending.drain(..pending.len() - keep);
                                    }
                                    continue;
                                }
                            }
                            if let Some(i) = find_bytes(&pending, end.as_bytes()) {
                                let after = i + end.len();
                                if let Some(nl) = pending[after..].iter().position(|b| *b == b'\n')
                                {
                                    push_bounded(&mut stdout, &pending[..i], cap, &mut truncated);
                                    let code = String::from_utf8_lossy(&pending[after..after + nl]);
                                    status = code.trim().parse::<u32>().ok();
                                    break;
                                }
                            }
                            let keep = end.len() + 16;
                            if pending.len() > keep {
                                let consumed = pending.len() - keep;
                                push_bounded(
                                    &mut stdout,
                                    &pending[..consumed],
                                    cap,
                                    &mut truncated,
                                );
                                pending.drain(..consumed);
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            push_bounded(&mut stderr, &data, cap, &mut truncated);
                        }
                        Some(ChannelMsg::ExitStatus { .. }) => {}
                        None => break,
                        _ => {}
                    }
                }
            })
            .await;
        let timed_out = wait.is_err();
        if timed_out {
            let _ = self.writer.signal(russh::Sig::TERM).await;
        }
        Ok(CommandOutput {
            ok: status == Some(0) && !timed_out,
            stdout: String::from_utf8_lossy(&stdout)
                .trim_start_matches('\n')
                .trim_end_matches('\n')
                .into(),
            stderr: String::from_utf8_lossy(&stderr).into(),
            exit_status: status,
            timed_out,
            truncated,
            remote_process_may_continue: timed_out || status.is_none(),
        })
    }
}
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_session_names() {
        assert!(validate_name("build-1").is_ok());
        for name in ["", "../other", "x y", "x\n"] {
            assert!(validate_name(name).is_err());
        }
    }
    #[test]
    fn rolling_output_is_bounded() {
        let mut buf = vec![b'x'; 5];
        let mut truncated = false;
        push_bounded(&mut buf, b"abcdef", 5, &mut truncated);
        assert_eq!(&buf, b"bcdef");
        assert!(truncated);
    }
}

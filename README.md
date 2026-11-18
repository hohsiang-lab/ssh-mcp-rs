# ssh-mcp-rs

A native Rust SSH MCP server inspired by [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp), with write actions designed for ChatGPT's **client-managed tool confirmation** instead of server-initiated form elicitation.

Built with the official Rust MCP SDK (`rmcp`), `russh`, and `russh-sftp`. The server does not invoke a local `ssh` binary or require Node.js. Git, `gh`, and other commands execute on the configured SSH host and must be installed/authenticated there.

**v0.2 implements all 15 tool names, not full upstream security/configuration parity.** It supports stateless commands, persistent POSIX-shell sessions, background jobs and signals, text and streaming binary SFTP, explicit noninteractive sudo, and validated configuration reload. SSH agent/password authentication, quotas, and output-secret redaction remain outside this implementation. The role/tier matrix and denylist remain Rust-native; the original upstream classifier is bundled in the standalone Rust binary using embedded QuickJS (no Node.js required). The pinned upstream classification and unconditional-denial behavior are verified against 5,991 test probes. See [scope and migration](docs/migration.md) and [upstream classifier provenance](docs/upstream-classifier.md).

## Install without building

Download a published Linux or macOS binary for x86_64 or ARM64 from [GitHub Releases](https://github.com/hohsiang-lab/ssh-mcp-rs/releases), verify it against `SHA256SUMS`, extract it, and install the `ssh-mcp-rs` executable. No repository clone, Rust toolchain, or local build is needed. See [download/install commands and release instructions](docs/releases.md).

Release archives include the configuration example and documentation. SSH credentials, a verified host fingerprint, and an authenticated MCP transport still need configuration. Adding the workflow does not itself publish a release; maintainers must push a matching version tag.

## Approval model: what changes, and what does not

Upstream can ask the MCP client to approve an action using `elicitation/create`. A client without that capability cannot answer, producing `APPROVAL_UNAVAILABLE`. This server **does not send an elicitation request**.

Instead, read and write operations have separate tools. Every tool explicitly declares `readOnlyHint`, `destructiveHint`, `openWorldHint`, and `idempotentHint`. Arbitrary commands and uploads are marked as writes with potentially destructive effects. ChatGPT applies its own confirmation and app-permission behavior before calling them.

**Annotations are hints, not authorization, a mandatory prompt switch, or cryptographic evidence that a person approved a call.** The server cannot determine whether ChatGPT displayed a prompt. Its audit records explicitly say `approvalEvidence: "not-attested"`. Do not send a model-writable `approved: true` parameter; unknown fields are rejected.

Server-side policy remains separate:

- `readOnly = true` (default): all write operations are denied, regardless of client behavior.
- `readOnly = false` alone: writes are still denied by the default `approvalPolicy = "deny"`.
- `readOnly = false` **and** `approvalPolicy = "client-confirmation"`: the operator explicitly delegates per-call confirmation to a trusted authenticated client. Calls reaching this endpoint can write without any additional server prompt. Do not expose it to an untrusted client or assume the name provides an independent approval gate.

For independent, server-verifiable approval on every call, leave writes denied: an out-of-band approval service would be needed and is not implemented here. A non-root SSH account and OS/GitHub permissions, not tool annotations or `cwd`, define the actual blast radius.

Official references, checked 2026-11-17:

- [ChatGPT custom MCP servers](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)
- [Define tools and safety annotations](https://developers.openai.com/plugins/plan/tools)
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server)

## Command authorization: upstream policy and original classifier

The native policy layer mirrors upstream's **default role × host group matrix**. A profile has
`role = "operator"` by default; set `group` explicitly for production. If absent, names
containing `prod`, `staging` or delimited `dev/local/test/sandbox` select that tier;
unrecognised names are treated as **prod** rather than dev.

| Role | prod | staging | dev |
| --- | --- | --- | --- |
| viewer | read-only | read-only | read-only, safe |
| operator | read-only, safe | + destructive | + destructive |
| admin | read-only, safe, destructive | + privileged | + privileged |

The command classifier is the **upstream v2.26.0 implementation** (commit
`e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f`), vendored and embedded in
QuickJS without requiring Node.js at runtime. All **5,991 upstream differential
probes** match exactly, including the `read-only`, `safe`, `destructive`,
`privileged`, and forbidden verdicts. `read_command` admits commands only when
that classifier returns `read-only`; `run_command` retains its static
write/confirmation contract, even when a command is classified `safe`.

Upstream's `safe` classification **does not mean no side effects**: upstream
classifies operations including `git push`, `cargo build` and some `kubectl`
commands as `safe`. This classification does not override SSH privileges,
server-level read-only settings, or client confirmation. Never treat shell
classification alone as a sandbox or an authentication boundary.

Custom role bindings replace **one role/tier cell**, not the entire role. Denylist
patterns add regex restrictions to raw/normalized command forms and SFTP remote
paths; rules are validated at startup and on `reload_config`. Never-allowed
families cannot be turned off.

```toml
[[profiles]]
name = "prod-deploy"
# ... host, SSH key, verified hostKeySha256 and user are required
role = "operator"
group = "prod"
readOnly = false
approvalPolicy = "client-confirmation"

[policy]
denylist = ['^terraform\\s+destroy', 'authorized_keys$']

[policy.roleBindings.operator]
prod = ["read-only", "safe"]
```

**Both gates apply:** the role/tier rules do not override `readOnly=true` or
`approvalPolicy="deny"`. `run_command`, even for a command classified
`read-only` or `safe`, still requires a write-enabled profile and the
**client-managed confirmation workflow** because the MCP tool has static
write annotations. No server-verified human approval is implied. Custom
classes cannot elevate the remote SSH account's real OS privileges.

## Tools

| Tool | Behavior | Read-only | Potentially destructive |
| --- | --- | :---: | :---: |
| `list_connections` | List configured hosts/policies; no SSH connection or key material | Yes | No |
| `read_command` | Commands upstream v2.26.0 classifies `read-only`; parsed arguments are quoted before SSH execution | Yes | No |
| `run_command` | Exact arbitrary shell command, optional absolute `cwd` | No | Yes |
| `sftp_download` | Read bounded UTF-8 content; does not create a local file | Yes | No |
| `sftp_upload` | Write UTF-8 content; existing destination refused unless `overwrite=true` | No | Yes |
| `list_sessions` | List named active sessions and expiry | Yes | No |
| `open_session` | Start persistent POSIX-shell interactive or background SSH command (TTL 1s–1h) | No | Yes |
| `close_session` | Close a session; background termination is best-effort | No | Yes |
| `read_session_output` | Read bounded recent background stdout/stderr and completion status | Yes | No |
| `signal_process` | Send INT/TERM/KILL to a validated remote PID, excluding PID 1 | No | Yes |
| `sftp_list` | List up to 1,000 remote directory entries | Yes | No |
| `sftp_upload_file` | Stream a local binary artifact from private transferRoot to remote | No | Yes |
| `sftp_download_file` | Stream a remote file into private transferRoot with atomic local publication | No | Yes |
| `privileged_command` | Explicitly enabled sudo -n helper; remote sudoers still applies | No | Yes |
| `reload_config` | Report loaded-file status or validate and reload settings while idle | No | Yes |

The read-only grammar follows the pinned upstream version. `git status`,
`git log`, `docker ps`, `grep -n`, etc. are permitted with upstream-approved
arguments. `git --version` and `gh --version` are `safe` in upstream and
therefore are not permitted by `read_command`; use `run_command` instead.
All `run_command` calls retain write-profile checks and client confirmation.

Examples of `run_command` arguments:

```json
{"profile":"dev","cwd":"/srv/work/project","command":"git status --short"}
```

```json
{"profile":"dev","cwd":"/srv/work/project","command":"git add src && git commit -m 'fix: handle timeout'"}
```

```json
{"profile":"dev","cwd":"/srv/work/project","command":"git push -u origin fix/timeout && gh pr create --fill"}
```

`cwd` is a convenience, **not** a sandbox. Stateless calls connect separately; named interactive sessions keep a persistent POSIX `/bin/sh -s` channel (even when the login shell is fish), preserving cwd and exported variables. For a session use `open_session` with `type=interactive`, then `run_command` with `session=<name>` and no `cwd`. Use `type=background` with `command` for long jobs and `read_session_output` to poll. Sessions expire automatically (default 10 minutes, maximum 1 hour), with a cap of eight. `close_session` and `signal_process` are write-gated and cannot guarantee remote process termination; check the remote PID after sending a signal.

## Build from source and configure

The committed lockfile is used for repeatable dependency resolution. Development validation uses Rust 1.98.1 on Linux amd64. Rust 1.89 is the declared minimum but is not separately tested. The release workflow builds and smoke-tests Linux and macOS x86_64/ARM64 archives; the full isolated SSH integration suite remains Linux-only. See [platform requirements](docs/releases.md) for prebuilt packages. Windows is explicitly unsupported.

```sh
cargo build --release --locked
install -d -m 700 "$HOME/.config/ssh-mcp-rs"
cp config.example.toml "$HOME/.config/ssh-mcp-rs/config.toml"
chmod 600 "$HOME/.config/ssh-mcp-rs/config.toml"
# Edit host, user, absolute keyRef, and the verified host fingerprint.
./target/release/ssh-mcp-rs \
  --config "$HOME/.config/ssh-mcp-rs/config.toml" --check-config
```

Config and private-key files must be owned by the service user, be regular non-symlink files, and have no group/other access. Their immediate parent directories cannot be group/world writable or symlinks. Protect the entire configuration/key path against other users; these checks are not a filesystem sandbox. `keyRef` must be absolute; `~` is not expanded. For encrypted keys, set `passphraseEnv` to an environment-variable name. Never put private-key contents or passphrases in tool arguments or Git.

Obtain the server's OpenSSH SHA256 host-key fingerprint through a trusted administrator/console channel, for example on the SSH host:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

A network `ssh-keyscan` alone does not authenticate a host. Unknown or changed fingerprints are denied; host certificates are not implemented.

## stdio: existing secure MCP tunnel

Use this process as the tunnel's MCP subprocess; preserve the tunnel's existing authenticated boundary. There is no need to run an HTTP listener for stdio:

```json
{
  "mcpServers": {
    "ssh-mcp-rs": {
      "command": "/absolute/path/ssh-mcp-rs",
      "args": ["--config", "/absolute/path/config.toml"]
    }
  }
}
```

This is a generic MCP subprocess example, **not** a claim that every tunnel uses this exact configuration shape. Adapt it to the installed tunnel's documented configuration. stdout is reserved for MCP; diagnostics/audit go to stderr or `auditPath`.

## Streamable HTTP

```sh
# Inject SSH_MCP_HTTP_TOKEN from a protected environment/secret manager.
# Use a randomly generated token of at least 32 bytes, not a literal example token.
./target/release/ssh-mcp-rs --config /absolute/path/config.toml \
  --transport http --bind 127.0.0.1:8080
```

`/mcp` requires `Authorization: Bearer ...` on every request. `/health` returns only `ok`. Binding to a non-loopback address is refused. HTTP body size is bounded; browser Origin headers are refused; the SDK validates Host against its loopback allowlist. A tunnel/reverse proxy must preserve authentication and send a loopback upstream Host. Do not disable those controls to make a public proxy work.

Native OAuth/DCR is **not implemented**. ChatGPT HTTP connection therefore needs an existing authenticated gateway capable of injecting the backend bearer header; the recommended current deployment is stdio through the existing authenticated MCP tunnel. Possession of the HTTP token grants access to all profiles configured in that process: it is a single-principal deployment, not a multi-tenant authorization system.

## Privileged commands and config reload

`privileged_command` requires both the normal write policy and profile-level
`allowPrivileged = true` (default false). It executes `sudo -n -- sh -c ...`,
never requests or accepts a sudo password, and refuses existing sessions.
The remote sudoers policy must allow the exact elevated invocation. `cwd` is
applied inside the elevated shell. A failed sudo or nonzero command is a tool error.

**This helper flag is not an OS security boundary:** arbitrary `run_command`
already has all permissions of the SSH account and could invoke sudo directly.
Use a non-root account and OS sudoers for real privilege restrictions; no tool
annotation or `allowPrivileged=false` makes a root account unprivileged.

`reload_config` takes `action: "status"` or `action: "reload"`. Status reports
loaded/on-disk SHA256 and managed session count, never config contents.
The single tool is conservatively write-classified even for status calls.
Reload accepts no caller-supplied path: it uses the original startup config file.
It authorizes against the currently loaded profile, takes exclusive command
admission, validates the new file and key permissions, and applies one snapshot.
Failures preserve the previous settings; parsing errors never echo config text.
A newly revoked profile is denied on its next call, even if the disk file is later
edited to allow it again: a still-authorized profile must perform that reload.

Reload refuses with `BUSY` while commands/transfers or managed sessions are active.
Close sessions first; changing `auditPath` or `maxConcurrentCalls` requires a service
restart. Reload does not terminate or roll back detached remote processes. Session
TTL governs persistent SSH channels rather than the shorter per-command timeout.

## Binary file transfers (optional)

Create a **dedicated private directory** on the MCP server host (owned by the service user, mode 0700, no symlink or writable ancestors), separate from credentials, configs and audit logs. Configure:

```toml
[defaults]
transferRoot = "/srv/mcp-transfers"
transferFileMaxBytes = 268435456
transferTimeoutMs = 300000
```

Use `sftp_upload_file({"profile":"dev","localName":"artifact.tar.gz","remotePath":"/srv/app/artifact.tar.gz"})` to stream local artifact bytes to the SSH destination. Use `sftp_download_file` for the reverse direction. `localName` is a **single filename**, never an absolute/local path, and the server checks for symlink/hardlink escape. Both tools are write-classified because they can modify files. By default existing destinations are refused; set `overwrite=true` deliberately. Local downloads use a temporary 0600 file and an atomic publish; remote uploads are not atomic. Transfers have an **overall** timeout, with failed local download staging files removed even on cancellation.

**The local directory belongs to the MCP server process, not the ChatGPT device or model context.** `sftp_list` does not require transferRoot and is read-only. Directory responses are capped at 1,000 entries (the underlying SFTP library may buffer the directory listing before truncation).

## Timeouts, transfers, and auditing

Commands have bounded connection time, execution time, concurrency and combined stdout/stderr bytes. Over-limit output is drained but not retained. A timeout attempts TERM and channel closure; the remote process may continue, and the result says so. Cancellation or a lost connection is not a rollback. Never automatically retry a write after an uncertain result.

Uploads are **not atomic**. `overwrite=true` truncates the destination and may follow a symlink; a failure can leave a partial file. New files use mode 0600; existing permissions are not rewritten by the client. Prefer writing a new staging file and explicitly publishing it after validation when atomicity is required. Text-transfer limits are separate from the optional binary-file limits.

Audit entries contain request IDs, profile/tool names, timestamps, argument SHA256 and attempt/result phases; they omit raw commands and payloads. This is a correlation log, not independently durable or tamper-proof human-approval evidence. Command/file **results are not automatically redacted**: avoid fetching secrets, and apply least-privilege file access on the SSH host.

## Tests

```sh
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
python3 tests/integration.py
```

The integration script uses a temporary, high-port loopback `sshd`, fresh keys, temporary config/files and a local bare Git remote. It does not alter the system sshd configuration, production MCP settings, GitHub credentials or repositories. Prerequisites: Python 3, OpenSSH client/server, Git, `gh`, and noninteractive sudo permitted for the isolated test account (CI runs as root). On Debian CI the ephemeral container also needs `/run/sshd`. Test fixtures live under the current user's home to satisfy OpenSSH StrictModes and are removed on exit. The user must be allowed to run that isolated sshd.

Covered: MCP discovery without elicitation capabilities, tool annotations, SSH authentication and host-key rejection, command reads/writes, read-only/deny enforcement, Git add/commit/push, `gh --version`, SFTP create/download/overwrite and limits, exit status, truncation/timeouts, HTTP authentication/Host/Origin checks, sudo opt-in, rejected/accepted reloads, immediate permission revocation, exclusive reload admission, quiet background sessions, and audit hygiene.

**The real ChatGPT approval UI is a separate manual acceptance test, not proven by these automated tests.** See [ChatGPT acceptance checklist](docs/chatgpt-acceptance.md).

## License and upstream attribution

MIT. The architecture and feature inventory were informed by upstream commit `e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f`. The classifier sources are vendored from upstream v2.26.0 (commit above) and include matching forbidden-rule behavior; the rest of the Rust server remains smaller and does not claim full upstream security/feature parity. Upstream attribution and license are retained in `NOTICE` and `docs/LICENSE.upstream`.

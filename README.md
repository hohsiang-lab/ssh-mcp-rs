# ssh-mcp-rs

A native Rust SSH MCP server inspired by [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp), with write actions designed for ChatGPT's **client-managed tool confirmation** instead of server-initiated form elicitation.

Built with the official Rust MCP SDK (`rmcp`), `russh`, and `russh-sftp`. The server does not invoke a local `ssh` binary or require Node.js. Git, `gh`, and other commands execute on the configured SSH host and must be installed/authenticated there.

**v0.1 is a focused implementation, not a full upstream port or a drop-in configuration replacement.** It implements stateless commands and bounded UTF-8 SFTP transfers. Stateful/background sessions, SSH agent/password authentication, privilege escalation helpers, binary streaming, config reload, role/host-group rules, quotas, and output-secret redaction are not implemented. See [scope and migration](docs/migration.md).

## Approval model: what changes, and what does not

Upstream can ask the MCP client to approve an action using `elicitation/create`. A client without that capability cannot answer, producing `APPROVAL_UNAVAILABLE`. This server **does not send an elicitation request**.

Instead, read and write operations have separate tools. Every tool explicitly declares `readOnlyHint`, `destructiveHint`, `openWorldHint`, and `idempotentHint`. Arbitrary commands and uploads are marked as writes with potentially destructive effects. ChatGPT applies its own confirmation and app-permission behavior before calling them.

**Annotations are hints, not authorization, a mandatory prompt switch, or cryptographic evidence that a person approved a call.** The server cannot determine whether ChatGPT displayed a prompt. Its audit records explicitly say `approvalEvidence: "not-attested"`. Do not send a model-writable `approved: true` parameter; unknown fields are rejected.

Server-side policy remains separate:

- `readOnly = true` (default): both write tools are denied, regardless of client behavior.
- `readOnly = false` alone: writes are still denied by the default `approvalPolicy = "deny"`.
- `readOnly = false` **and** `approvalPolicy = "client-confirmation"`: the operator explicitly delegates per-call confirmation to a trusted authenticated client. Calls reaching this endpoint can write without any additional server prompt. Do not expose it to an untrusted client or assume the name provides an independent approval gate.

For independent, server-verifiable approval on every call, leave writes denied: an out-of-band approval service would be needed and is not implemented here. A non-root SSH account and OS/GitHub permissions, not tool annotations or `cwd`, define the actual blast radius.

Official references, checked 2026-11-17:

- [ChatGPT custom MCP servers](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)
- [Define tools and safety annotations](https://developers.openai.com/plugins/plan/tools)
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server)

## Tools

| Tool | Behavior | Read-only | Potentially destructive |
| --- | --- | :---: | :---: |
| `list_connections` | List configured hosts/policies; no SSH connection or key material | Yes | No |
| `read_command` | Narrow command grammar; never a general shell classifier | Yes | No |
| `run_command` | Exact arbitrary shell command, optional absolute `cwd` | No | Yes |
| `sftp_download` | Read bounded UTF-8 content; does not create a local file | Yes | No |
| `sftp_upload` | Write UTF-8 content; existing destination refused unless `overwrite=true` | No | Yes |

The read grammar accepts basic `uname`, `id`, `pwd`, `whoami`, `uptime`, `ls`, `cat`, and `df` forms, plus `git --version` and `gh --version`. Shell operators, substitutions, interpreters, mutable Git subcommands, and arbitrary `gh` operations are rejected. Unsupported reads can use `run_command` on an explicitly write-enabled profile, with the same client confirmation as other arbitrary commands. This conservatism avoids falsely labelling complex shell commands read-only.

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

`cwd` is a convenience, **not** a sandbox. Commands can access everything available to the SSH account. SSH connects separately for each call; shell environment and working directory do not persist. POSIX-shell remote hosts only in v0.1.

## Build and configure

The committed lockfile is used for repeatable dependency resolution. Development validation uses Rust 1.98.1 on Linux amd64. Rust 1.89 is the declared minimum but is not separately tested. macOS is a build target in principle, not an integration-tested platform in this release. Windows is explicitly unsupported.

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

## Timeouts, transfers, and auditing

Commands have bounded connection time, execution time, concurrency and combined stdout/stderr bytes. Over-limit output is drained but not retained. A timeout attempts TERM and channel closure; the remote process may continue, and the result says so. Cancellation or a lost connection is not a rollback. Never automatically retry a write after an uncertain result.

Uploads are **not atomic**. `overwrite=true` truncates the destination and may follow a symlink; a failure can leave a partial file. New files use mode 0600; existing permissions are not rewritten by the client. Prefer writing a new staging file and explicitly publishing it after validation when atomicity is required. Text transfer byte limits do not imply binary streaming support.

Audit entries contain request IDs, profile/tool names, timestamps, argument SHA256 and attempt/result phases; they omit raw commands and payloads. This is a correlation log, not independently durable or tamper-proof human-approval evidence. Command/file **results are not automatically redacted**: avoid fetching secrets, and apply least-privilege file access on the SSH host.

## Tests

```sh
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
python3 tests/integration.py
```

The integration script uses a temporary, high-port loopback `sshd`, fresh keys, temporary config/files and a local bare Git remote. It does not alter the system sshd configuration, production MCP settings, GitHub credentials or repositories. Prerequisites: Python 3, OpenSSH client/server, Git and `gh`. On Debian CI the ephemeral container also needs `/run/sshd`. Test fixtures live under the current user's home to satisfy OpenSSH StrictModes and are removed on exit. The user must be allowed to run that isolated sshd.

Covered: MCP discovery without elicitation capabilities, tool annotations, SSH authentication and host-key rejection, command reads/writes, read-only/deny enforcement, Git add/commit/push, `gh --version`, SFTP create/download/overwrite and limits, exit status, truncation/timeouts, HTTP authentication/Host/Origin checks, and audit hygiene.

**The real ChatGPT approval UI is a separate manual acceptance test, not proven by these automated tests.** See [ChatGPT acceptance checklist](docs/chatgpt-acceptance.md).

## License and upstream attribution

MIT. The architecture and feature inventory were informed by upstream commit `e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f`. The Rust implementation is deliberately smaller; it does not claim upstream security/feature parity. Upstream attribution and license are retained in `NOTICE` and `docs/LICENSE.upstream`.

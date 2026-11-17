# Initial scope and upstream migration

Reference: `tufantunc/ssh-mcp` commit `e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f` (MIT).

All 15 tool names are implemented in native Rust; this is not a line-by-line port or full behavior/security parity. Do not replace the existing service without checking its required features.

| Upstream capability | v0.2 Rust behavior |
| --- | --- |
| Host discovery | `list_connections`; policies shown, connections are per-call |
| Read-only commands | Expanded argument-checked readers including grep, head/tail, find (without -exec), and others; deliberately narrower than some upstream grammars |
| Arbitrary commands | `run_command`, optional per-call cwd or named persistent POSIX-shell session |
| Form-elicitation approval | Replaced by explicit trusted-client confirmation mode + write annotations; not server-verifiable approval |
| Text SFTP upload/download | Implemented with byte limits; upload defaults to no overwrite |
| Directory listing | `sftp_list` plus basic `read_command` ls forms |
| SSH key authentication | Implemented; encrypted private keys via passphrase environment reference |
| Host verification | Required pinned SHA256 public-key fingerprint; no accept-any or TOFU fallback |
| stdio / Streamable HTTP | Implemented; HTTP is loopback + mandatory backend bearer auth |
| Interactive/background sessions | Implemented: `open_session`, `list_sessions`, `close_session`, `read_session_output`, plus persistent POSIX-shell commands via `run_command(session=...)`; bounded TTL and output |
| SSH agent/password/certificate authentication | Not implemented |
| Sudo helper | `privileged_command`, explicit `allowPrivileged=true`, noninteractive sudo; OS sudoers remains authoritative |
| Signal-process tool | `signal_process` with explicit INT/TERM/KILL, validated PID, and write-profile confirmation |
| Binary streaming/local transferRoot | `sftp_upload_file` and `sftp_download_file` (private 0700 transferRoot, basename-only, 256 MiB default limit, local atomic publish) |
| Config hot reload | `reload_config`: validates then applies while idle; sessions must be closed, audit/concurrency changes require restart |
| Role/host-group matrix, denylist, quotas | Built-in viewer/operator/admin × prod/staging/dev matrix, custom per-tier roleBindings and Regex denylist implemented; daily command quotas not implemented. Classifier is conservative rather than full upstream parser parity |
| Output redaction | Not implemented; audit avoids raw arguments, tool output can contain secrets |
| Windows support | Not implemented; Unix process and POSIX remote shell required |
| OAuth/DCR and independent approval service | Not implemented; reuse an authenticated stdio tunnel or trusted gateway |

## Configuration differences

Unknown fields fail configuration parsing intentionally. The limited `[policy]` (denylist, roleBindings), profile role and group fields are supported; do not copy upstream auth, approvalMode, OPA, quota, session or credential-resolver settings and assume they are enforced. Use `config.example.toml` and configure an absolute keyRef plus verified hostKeySha256 explicitly.

The safe default is `readOnly=true` and `approvalPolicy="deny"`. `client-confirmation` is an explicit trust decision by the operator, not an automatic fallback when elicitation fails. Clients cannot opt themselves into it through a tool parameter.

For per-call directory changes, pass `cwd` on every `run_command`. Git and gh are remote executables: prepare their installation and repository-scoped authentication on the SSH account independently. Never transfer tokens through command arguments or tool results.

## Recommended acceptance sequence

Keep the existing deployment intact. Build and test the Rust service separately, run the real ChatGPT approval/rejection checklist, then make an explicit replacement decision. No service replacement, SSH account modification, tunnel change, production write or automatic migration is part of this initial source PR.

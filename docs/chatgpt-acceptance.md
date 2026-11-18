# ChatGPT acceptance checklist (not yet run)

Automated tests use an MCP client that advertises no elicitation capability. They prove protocol behavior and SSH effects, **not** the real ChatGPT confirmation UI.

## Before connecting

1. Build the reviewed commit. Keep the existing TypeScript service/tunnel unchanged while testing the Rust service under a separate name.
2. Use a non-root SSH account, with only the required workspace/GitHub permissions. Treat a write-enabled profile as arbitrary command execution by that account.
3. Start with `readOnly=true` and `approvalPolicy="deny"`. Configure a verified SSH host-key fingerprint and protect the config/key files.
4. Use the existing authenticated stdio tunnel pattern. HTTP requires backend bearer-token injection by a trusted gateway; the Rust server does not implement native OAuth/DCR. Do not expose an unauthenticated endpoint.
5. Refresh/discover the new app's tools. Review the actual ChatGPT app permissions/confirmation settings; tool annotations cannot force a prompt or prove a person approved.

## Read and reject tests

- Discover the currently documented tools and verify the reported server name/version.
- `read_command`: `uname -a`, `id`, `ls -l /tmp` should work. Upstream classifies `git --version` and `gh --version` as `safe`, so run those through `run_command` on an authorized profile with client confirmation.
- An arbitrary `run_command` and `sftp_upload` must return `POLICY_DENIED` on the read-only profile, even when called from a client that manages confirmation.
- Shell injection through `read_command` must be rejected.

## Explicitly opt-in to write acceptance

On a separate test account/profile only, configure `readOnly=false` and `approvalPolicy="client-confirmation"`, then restart the new service. This does not attest per-call approval; it delegates confirmation to the trusted client.

Ask ChatGPT to write a unique marker file under that account's disposable test directory using `sftp_upload`. Check the tool name, SSH profile, exact destination/content, and overwrite flag in the confirmation flow.

First reject/cancel the action. Verify no file was created and no corresponding server write-attempt audit event exists. If the host sends the call despite the intended confirmation policy, stop acceptance and return the profile to deny; do not assert server-side enforcement that does not exist.

Then approve a new action. Verify the exact bytes and 0600 permissions, a successful audit record, and no `APPROVAL_UNAVAILABLE` or `elicitation/create` request. Test an existing destination without overwrite (must fail without changing bytes) and with explicitly approved overwrite (must replace bytes).

Finally test a disposable Git branch: status, edit, commit, push and draft PR. Verify the exact remote and branch before approving network writes. Do not use production deployment or service restart as the first test.

Record the app identity, commit SHA, transport, client settings, date, actual approve/reject behavior, relevant audit IDs and file/Git evidence. Never put access tokens or SSH private keys into the report.

## Deployment decision

This checklist must pass before replacing the existing Monster MCP. For v0.2 additionally verify all 15 advertised tools, background/session lifecycle, binary transferRoot confinement, default-denied sudo, and successful/failed config reloads. Independent server-side approval, SSH agent/password auth and output-secret redaction are not provided. Migrating the service, tunnel or production SSH permissions is a separate operator action.

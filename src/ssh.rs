use crate::config::{Defaults, Profile, private_file};
use anyhow::{Context, Result, bail, ensure};
use russh::{
    ChannelMsg, Disconnect, client,
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, load_secret_key},
};
use russh_sftp::{
    client::SftpSession,
    protocol::{FileAttributes, OpenFlags},
};
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct VerifyHost {
    fingerprint: String,
}
impl client::Handler for VerifyHost {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                ensure!(
                    key.fingerprint(HashAlg::Sha256).to_string() == self.fingerprint,
                    "HOST_KEY_MISMATCH: refusing unverified SSH server"
                );
                Ok(true)
            }
            PublicKeyOrCertificate::Certificate(_) => {
                bail!("SSH host certificates are not supported in v0.1; pin a host public key")
            }
        }
    }
}

pub struct Connection {
    handle: client::Handle<VerifyHost>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_status: Option<u32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub remote_process_may_continue: bool,
}

impl Connection {
    pub async fn connect(profile: &Profile, defaults: &Defaults) -> Result<Self> {
        tokio::time::timeout(Duration::from_millis(defaults.connect_timeout_ms), async {
            private_file(&profile.key_ref)?;
            let passphrase = profile
                .passphrase_env
                .as_ref()
                .map(|name| {
                    std::env::var(name)
                        .with_context(|| format!("missing passphrase environment variable {name}"))
                })
                .transpose()?;
            let key = load_secret_key(&profile.key_ref, passphrase.as_deref())
                .context("cannot load SSH private key")?;
            let config = Arc::new(client::Config {
                inactivity_timeout: Some(Duration::from_millis(defaults.command_timeout_ms + 5000)),
                ..Default::default()
            });
            let mut handle = client::connect(
                config,
                (profile.host.as_str(), profile.port),
                VerifyHost {
                    fingerprint: profile.host_key_sha256.clone(),
                },
            )
            .await?;
            let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
            let authenticated = handle
                .authenticate_publickey(
                    profile.user.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash),
                )
                .await?
                .success();
            ensure!(authenticated, "SSH authentication failed");
            Ok(Self { handle })
        })
        .await
        .context("SSH connection/authentication timed out")?
    }

    pub async fn close(&self) {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            self.handle
                .disconnect(Disconnect::ByApplication, "request complete", "en"),
        )
        .await;
    }

    pub async fn open_shell(&self) -> Result<russh::Channel<client::Msg>> {
        let channel = self.handle.channel_open_session().await?;
        // Start an explicit POSIX shell: users may have fish or another non-POSIX login shell.
        channel.exec(true, "exec /bin/sh -s").await?;
        Ok(channel)
    }

    pub async fn open_exec(&self, command: &str) -> Result<russh::Channel<client::Msg>> {
        let channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        channel.eof().await?;
        Ok(channel)
    }

    pub async fn command(&self, command: &str, defaults: &Defaults) -> Result<CommandOutput> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        channel.eof().await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        let mut truncated = false;
        let mut remaining = defaults.command_max_output_bytes;
        let wait =
            tokio::time::timeout(Duration::from_millis(defaults.command_timeout_ms), async {
                while let Some(message) = channel.wait().await {
                    match message {
                        ChannelMsg::Data { data } => {
                            append_bounded(&mut stdout, &data, &mut remaining, &mut truncated)
                        }
                        ChannelMsg::ExtendedData { data, .. } => {
                            append_bounded(&mut stderr, &data, &mut remaining, &mut truncated)
                        }
                        ChannelMsg::ExitStatus {
                            exit_status: status,
                        } => exit_status = Some(status),
                        _ => {}
                    }
                }
            })
            .await;
        let timed_out = wait.is_err();
        if timed_out {
            // Best effort only: SSH servers may ignore signals; never claim rollback.
            let _ = tokio::time::timeout(Duration::from_secs(1), channel.signal(russh::Sig::TERM))
                .await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), channel.close()).await;
        Ok(CommandOutput {
            ok: exit_status == Some(0) && !timed_out,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_status,
            timed_out,
            truncated,
            remote_process_may_continue: timed_out || exit_status.is_none(),
        })
    }

    async fn sftp(&self) -> Result<SftpSession> {
        let channel = self.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        Ok(SftpSession::new(channel.into_stream()).await?)
    }

    pub async fn download(&self, path: &str, limit: usize) -> Result<String> {
        let sftp = self.sftp().await?;
        let file = sftp.open(path).await?;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes).await?;
        ensure!(
            bytes.len() <= limit,
            "TRANSFER_TOO_LARGE: file exceeds configured limit"
        );
        let text = String::from_utf8(bytes)
            .context("text download requires UTF-8; binary streaming is not implemented in v0.1")?;
        sftp.close().await?;
        Ok(text)
    }

    pub async fn upload(&self, path: &str, content: &[u8], overwrite: bool) -> Result<()> {
        let sftp = self.sftp().await?;
        let flags = OpenFlags::WRITE
            | OpenFlags::CREATE
            | if overwrite {
                OpenFlags::TRUNCATE
            } else {
                OpenFlags::EXCLUDE
            };
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(0o600);
        let mut file = sftp
            .open_with_flags_and_attributes(path, flags, attrs)
            .await?;
        file.write_all(content).await?;
        file.flush().await?;
        file.shutdown().await?;
        sftp.close().await?;
        Ok(())
    }
}

fn append_bounded(output: &mut Vec<u8>, data: &[u8], remaining: &mut usize, truncated: &mut bool) {
    let count = data.len().min(*remaining);
    output.extend_from_slice(&data[..count]);
    *remaining -= count;
    *truncated |= count < data.len();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_cap_is_shared_and_never_exceeded() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut left = 5;
        let mut truncated = false;
        append_bounded(&mut a, b"abc", &mut left, &mut truncated);
        append_bounded(&mut b, b"defgh", &mut left, &mut truncated);
        assert_eq!(a, b"abc");
        assert_eq!(b, b"de");
        assert_eq!(left, 0);
        assert!(truncated);
    }
}

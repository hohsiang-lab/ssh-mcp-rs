use crate::{
    config::{Defaults, private_directory},
    policy,
    ssh::Connection,
};
use anyhow::{Context, Result, ensure};
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;

/// A canceled/timeouted transfer must not leave a partial local file behind.
struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn local_destination(defaults: &Defaults, local_name: &str) -> Result<PathBuf> {
    let root = defaults
        .transfer_root
        .as_deref()
        .context("TRANSFER_DISABLED: configure defaults.transferRoot")?;
    private_directory(root)?; // Verify on every call; refuses symlinks and unsafe parents.
    ensure!(
        !local_name.is_empty() && local_name.len() <= 255,
        "localName must be a short filename"
    );
    ensure!(
        local_name != "."
            && local_name != ".."
            && !local_name.contains('/')
            && !local_name.contains('\\')
            && !local_name.chars().any(|c| c.is_control()
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
        "localName must be one plain filename (no traversal, slashes or controls)"
    );
    Ok(root.join(local_name))
}

fn open_source(path: &Path, max_bytes: u64) -> Result<(tokio::fs::File, u64)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "source must be a regular file");
    ensure!(meta.nlink() == 1, "hard-linked local sources are refused");
    ensure!(
        meta.len() <= max_bytes,
        "TRANSFER_TOO_LARGE: local source exceeds limit"
    );
    Ok((tokio::fs::File::from_std(file), meta.len()))
}

pub async fn list(connection: &Connection, path: &str, max_entries: usize) -> Result<Value> {
    policy::path(path)?;
    ensure!(
        (1..=1000).contains(&max_entries),
        "maxEntries must be within 1..1000"
    );
    let sftp = connection.sftp().await?;
    let mut dir = sftp.read_dir(path).await?;
    let mut entries = Vec::new();
    for e in dir.by_ref().take(max_entries + 1) {
        let name = e.file_name();
        if name.chars().any(char::is_control) {
            continue;
        }
        entries.push(json!({"name":name, "type":format!("{:?}", e.file_type()),
            "size":e.metadata().len()}));
    }
    let truncated = entries.len() > max_entries;
    entries.truncate(max_entries);
    sftp.close().await?;
    Ok(json!({"remotePath":path,"entries":entries,"truncated":truncated}))
}

pub async fn upload_file(
    connection: &Connection,
    defaults: &Defaults,
    local_name: &str,
    remote_path: &str,
    overwrite: bool,
) -> Result<Value> {
    policy::path(remote_path)?;
    let source = local_destination(defaults, local_name)?;
    let (mut file, size) = open_source(&source, defaults.transfer_file_max_bytes)?;
    let sftp = connection.sftp().await?;
    let flags = OpenFlags::CREATE
        | OpenFlags::WRITE
        | if overwrite {
            OpenFlags::TRUNCATE
        } else {
            OpenFlags::EXCLUDE
        };
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(0o600);
    let mut remote = sftp
        .open_with_flags_and_attributes(remote_path, flags, attrs)
        .await?;
    let mut count = 0u64;
    let mut hash = Sha256::new();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(
            count <= defaults.transfer_file_max_bytes,
            "TRANSFER_TOO_LARGE: source grew during transfer"
        );
        remote.write_all(&chunk[..n]).await?;
        hash.update(&chunk[..n]);
    }
    remote.flush().await?;
    remote.shutdown().await?;
    sftp.close().await?;
    ensure!(
        count == size,
        "local source changed during transfer; verify remote before retry"
    );
    Ok(
        json!({"remotePath":remote_path,"localName":local_name,"bytes":count,
        "sha256":format!("{:x}", hash.finalize()),"overwrite":overwrite,"atomic":false}),
    )
}

pub async fn download_file(
    connection: &Connection,
    defaults: &Defaults,
    remote_path: &str,
    local_name: &str,
    overwrite: bool,
) -> Result<Value> {
    policy::path(remote_path)?;
    let destination = local_destination(defaults, local_name)?;
    match std::fs::symlink_metadata(&destination) {
        Ok(meta) => {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "local destination must be a regular, non-symlink file"
            );
            ensure!(meta.nlink() == 1, "hard-linked local destination refused");
            ensure!(
                overwrite,
                "destination exists; set overwrite=true explicitly"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = destination
        .parent()
        .context("local destination has no parent")?;
    let temp = parent.join(format!(".transfer-{}.part", uuid::Uuid::new_v4()));
    let tempfile = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let _cleanup = RemoveOnDrop(temp.clone());
    let mut target = tokio::fs::File::from_std(tempfile);
    async {
        let sftp = connection.sftp().await?;
        let mut source = sftp.open(remote_path).await?;
        let mut bytes = 0u64;
        let mut hash = Sha256::new();
        let mut chunk = vec![0u8; CHUNK];
        loop {
            let n = source.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes += n as u64;
            ensure!(
                bytes <= defaults.transfer_file_max_bytes,
                "TRANSFER_TOO_LARGE: remote source exceeds limit"
            );
            target.write_all(&chunk[..n]).await?;
            hash.update(&chunk[..n]);
        }
        target.flush().await?;
        target.sync_all().await?;
        drop(target);
        sftp.close().await?;
        // Recheck containment immediately before publishing. Private root must remain private.
        private_directory(parent)?;
        if overwrite {
            if let Ok(meta) = std::fs::symlink_metadata(&destination) {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
                    "destination changed: refusing symlink/hardlink replacement"
                );
            }
            tokio::fs::rename(&temp, &destination).await?;
        } else {
            // Hardlink is atomic no-clobber publication on the same filesystem.
            tokio::fs::hard_link(&temp, &destination).await?;
            tokio::fs::remove_file(&temp).await?;
        }
        Ok(
            json!({"remotePath":remote_path,"localName":local_name,"bytes":bytes,
            "sha256":format!("{:x}",hash.finalize()),"overwrite":overwrite,"atomic":true}),
        )
    }
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_names_cannot_escape_transfer_root() {
        let mut d = Defaults::default();
        let root = tempfile::Builder::new()
            .prefix("ssh-mcp-test-")
            .tempdir_in(if unsafe { libc::geteuid() } == 0 {
                std::path::PathBuf::from("/root")
            } else {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            })
            .unwrap();
        d.transfer_root = Some(root.path().to_owned());
        for name in ["../x", "/tmp/x", "a/b", "a\\b", "..", ".", "\nsecret"] {
            assert!(local_destination(&d, name).is_err(), "{name}");
        }
        assert!(local_destination(&d, "artifact.tar.gz").is_ok());
    }
}

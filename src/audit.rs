use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Audit {
    file: Option<Mutex<File>>,
}
impl Audit {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let file = if let Some(path) = path {
            use std::os::unix::fs::OpenOptionsExt;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .context("cannot open audit file")?;
            crate::config::private_file(path)?;
            Some(Mutex::new(file))
        } else {
            None
        };
        Ok(Self { file })
    }
    pub fn record(
        &self,
        id: &str,
        tool: &str,
        profile: &str,
        argument_hash: &str,
        phase: &str,
    ) -> Result<()> {
        let event = json!({
            "tsUnixMs": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            "requestId": id, "tool": tool, "profile": profile,
            "argumentsSha256": argument_hash, "phase": phase,
            "approvalEvidence": "not-attested"
        });
        let mut bytes = serde_json::to_vec(&event)?;
        bytes.push(b'\n');
        if let Some(file) = &self.file {
            let mut file = file
                .lock()
                .map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
            file.write_all(&bytes)?;
            file.flush()?;
        } else {
            std::io::stderr().lock().write_all(&bytes)?;
        }
        Ok(())
    }
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_does_not_include_plaintext_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::open(Some(&path)).unwrap();
        audit
            .record(
                "test",
                "sftp_upload",
                "dev",
                &digest(b"secret payload"),
                "attempt",
            )
            .unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(!text.contains("secret payload"));
        assert!(text.contains("not-attested"));
    }
}

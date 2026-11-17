use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalPolicy {
    #[default]
    Deny,
    /// Explicitly trust the authenticated MCP client to manage human confirmation.
    /// This is NOT evidence of a per-call human approval.
    ClientConfirmation,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub key_ref: PathBuf,
    pub host_key_sha256: String,
    pub passphrase_env: Option<String>,
    #[serde(default = "default_read_only")]
    pub read_only: bool,
    #[serde(default)]
    pub approval_policy: ApprovalPolicy,
}
fn default_port() -> u16 {
    22
}
fn default_read_only() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Defaults {
    pub default_profile: Option<String>,
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub command_max_output_bytes: usize,
    pub transfer_max_bytes: usize,
    /// Optional private server-side directory for streaming binary transfers.
    pub transfer_root: Option<PathBuf>,
    pub transfer_file_max_bytes: u64,
    pub transfer_timeout_ms: u64,
    pub max_concurrent_calls: usize,
    pub audit_path: Option<PathBuf>,
}
impl Default for Defaults {
    fn default() -> Self {
        Self {
            default_profile: None,
            connect_timeout_ms: 10_000,
            command_timeout_ms: 60_000,
            command_max_output_bytes: 65_536,
            transfer_max_bytes: 1_048_576,
            transfer_root: None,
            transfer_file_max_bytes: 268_435_456,
            transfer_timeout_ms: 300_000,
            max_concurrent_calls: 4,
            audit_path: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    pub profiles: Vec<Profile>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        private_file(path)?;
        let config: Self = toml::from_str(&fs::read_to_string(path)?)
            .context("invalid configuration; this is not a drop-in upstream config")?;
        config.validate()?;
        if let Some(root) = &config.defaults.transfer_root {
            private_directory(root)?;
            ensure!(
                !path.starts_with(root),
                "transferRoot must not contain the MCP config file"
            );
            if let Some(audit) = &config.defaults.audit_path {
                ensure!(
                    !audit.starts_with(root),
                    "transferRoot must not contain audit logs"
                );
            }
            for p in &config.profiles {
                ensure!(
                    !p.key_ref.starts_with(root),
                    "transferRoot must not contain private keys"
                );
                if let Some(key_dir) = p.key_ref.parent() {
                    ensure!(
                        root != key_dir && !root.components().any(|c| c.as_os_str() == ".ssh"),
                        "transferRoot must not be the SSH-key directory or inside .ssh"
                    );
                }
            }
        }
        for profile in &config.profiles {
            private_file(&profile.key_ref)
                .with_context(|| format!("private key permissions for profile {}", profile.name))?;
        }
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.profiles.is_empty(),
            "at least one profile is required"
        );
        ensure!(
            self.profiles.len() <= 100,
            "at most 100 profiles are supported"
        );
        ensure!(
            (1..=64).contains(&self.defaults.max_concurrent_calls),
            "invalid concurrency limit"
        );
        ensure!(
            (100..=120_000).contains(&self.defaults.connect_timeout_ms),
            "invalid connection timeout"
        );
        ensure!(
            (100..=600_000).contains(&self.defaults.command_timeout_ms),
            "invalid command timeout"
        );
        ensure!(
            (1..=1_048_576).contains(&self.defaults.command_max_output_bytes),
            "invalid output limit"
        );
        ensure!(
            (1..=16_777_216).contains(&self.defaults.transfer_max_bytes),
            "invalid transfer limit"
        );
        ensure!(
            (1..=1_073_741_824).contains(&self.defaults.transfer_file_max_bytes),
            "invalid binary transfer size limit"
        );
        ensure!(
            (1000..=3_600_000).contains(&self.defaults.transfer_timeout_ms),
            "invalid binary transfer timeout"
        );
        if let Some(root) = &self.defaults.transfer_root {
            ensure!(root.is_absolute(), "transferRoot must be absolute");
            ensure!(
                !root
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "transferRoot cannot contain .."
            );
        }
        let mut names = HashSet::new();
        for p in &self.profiles {
            ensure!(
                !p.name.is_empty()
                    && p.name.len() <= 64
                    && p.name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
                "invalid profile name"
            );
            ensure!(names.insert(&p.name), "duplicate profile name");
            ensure!(
                !p.host.is_empty()
                    && p.host.len() <= 253
                    && !p.host.chars().any(char::is_whitespace)
                    && !p.host.chars().any(char::is_control),
                "invalid host"
            );
            ensure!(p.port != 0, "invalid port");
            ensure!(
                !p.user.is_empty() && !p.user.chars().any(char::is_control),
                "invalid SSH user"
            );
            ensure!(
                p.key_ref.is_absolute(),
                "keyRef must be an absolute path; no tilde expansion"
            );
            let pin = p
                .host_key_sha256
                .strip_prefix("SHA256:")
                .unwrap_or_default();
            ensure!(
                pin.len() == 43
                    && pin
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(&b)),
                "hostKeySha256 must be a verified OpenSSH SHA256 fingerprint"
            );
            if let Some(env) = &p.passphrase_env {
                ensure!(
                    !env.is_empty() && env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "invalid passphraseEnv"
                );
            }
        }
        if let Some(name) = &self.defaults.default_profile {
            ensure!(names.contains(name), "defaultProfile does not exist");
        }
        Ok(())
    }

    pub fn profile(&self, name: Option<&str>) -> Result<&Profile> {
        let name = name
            .or(self.defaults.default_profile.as_deref())
            .context("profile is required; no defaultProfile configured")?;
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .context("unknown profile")
    }
}

/// Local binary-transfer staging root must be owned by this process and private.
#[cfg(unix)]
pub fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(path.is_absolute(), "transferRoot must be absolute");
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "transferRoot and its ancestors must be real directories"
        );
        if ancestor == path {
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() },
                "transferRoot must belong to the service account"
            );
            ensure!(
                metadata.mode() & 0o077 == 0,
                "transferRoot must have permissions 0700"
            );
        } else {
            ensure!(
                metadata.mode() & 0o022 == 0,
                "transferRoot ancestor is group/world writable"
            );
        }
    }
    Ok(())
}

/// Unix-only: avoid silently degrading the config/key permission checks.
#[cfg(unix)]
pub fn private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "must be a regular, non-symlink file"
    );
    // SAFETY: geteuid has no preconditions and no memory side effects.
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "file must belong to the service user"
    );
    ensure!(
        metadata.mode() & 0o077 == 0,
        "file must not be accessible to group/others (chmod 600)"
    );
    let parent = path.parent().context("file has no parent")?;
    let parent_meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent_meta.is_dir() && !parent_meta.file_type().is_symlink(),
        "parent must be a non-symlink directory"
    );
    ensure!(
        parent_meta.mode() & 0o022 == 0,
        "parent directory must not be writable by group/others"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn sample() -> Config {
        toml::from_str(
            r#"
[[profiles]]
name = "local"
host = "127.0.0.1"
user = "developer"
keyRef = "/home/developer/.ssh/id_ed25519"
hostKeySha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#,
        )
        .unwrap()
    }
    #[test]
    fn defaults_deny_writes() {
        let c = sample();
        c.validate().unwrap();
        assert!(c.profiles[0].read_only);
        assert_eq!(c.profiles[0].approval_policy, ApprovalPolicy::Deny);
    }
    #[test]
    fn rejects_unknown_policy() {
        assert!(toml::from_str::<ApprovalPolicy>("\"auto\"").is_err());
    }
    #[test]
    fn validates_unique_names_and_limits() {
        let mut c = sample();
        c.profiles.push(c.profiles[0].clone());
        assert!(c.validate().is_err());
        let mut c = sample();
        c.defaults.command_timeout_ms = 0;
        assert!(c.validate().is_err());
        let mut c = sample();
        c.profiles[0].host_key_sha256 = "accept-any".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn rejects_unknown_config_fields() {
        assert!(toml::from_str::<Config>("profiles = []\napproved = true").is_err());
    }
    #[test]
    fn profile_never_falls_back_to_another_host() {
        let c = sample();
        assert!(c.profile(None).is_err());
        assert!(c.profile(Some("missing")).is_err());
    }
    #[test]
    fn permission_checks_reject_world_readable_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("key");
        fs::write(&p, "not a real key").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&p).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        private_file(&p).unwrap();
        let link = d.path().join("link");
        symlink(&p, &link).unwrap();
        assert!(private_file(&link).is_err());
    }
}

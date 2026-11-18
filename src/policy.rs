use crate::config::{ApprovalPolicy, Profile};
use anyhow::{Context, Result, ensure};

pub fn authorize_write(profile: &Profile) -> Result<()> {
    ensure!(!profile.read_only, "POLICY_DENIED: profile is read-only");
    ensure!(
        profile.approval_policy == ApprovalPolicy::ClientConfirmation,
        "POLICY_DENIED: writes disabled; an operator must explicitly configure client-confirmation for a trusted authenticated client"
    );
    Ok(())
}

pub fn validate_command(command: &str) -> Result<()> {
    ensure!(
        !command.trim().is_empty() && command.len() <= 16_384,
        "command must contain 1..16384 bytes"
    );
    ensure!(!command.contains('\0'), "NUL is not allowed in commands");
    Ok(())
}

pub fn path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/') && path.len() <= 4096,
        "path must be absolute and at most 4096 bytes"
    );
    ensure!(
        !path
            .chars()
            .any(|c| c.is_control()
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
        "control/bidi characters are not allowed in paths"
    );
    ensure!(
        path.trim() == path,
        "path must not have leading/trailing whitespace"
    );
    Ok(())
}

pub fn quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Upstream ssh-mcp v2.26.0 decides whether a command qualifies as read-only.
/// Quote the parsed argv before execution so this tool cannot introduce shell
/// substitutions even when the original expression contains quoted punctuation.
pub fn read_command(command: &str) -> Result<String> {
    validate_command(command)?;
    ensure!(
        crate::upstream_compat::classify(command)? == "read-only",
        "READ_ONLY_DENIED: upstream classifier requires read-only; use run_command with confirmation"
    );
    let words = shlex::split(command).context("READ_ONLY_DENIED: invalid shell quoting")?;
    ensure!(!words.is_empty(), "READ_ONLY_DENIED: empty command");
    Ok(words
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn shell_command(command: &str, cwd: Option<&str>) -> Result<String> {
    validate_command(command)?;
    let script = if let Some(cwd) = cwd {
        path(cwd)?;
        format!("cd {} && {}", quote(cwd), command)
    } else {
        command.to_owned()
    };
    Ok(format!("sh -c {}", quote(&script)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_upstream_read_only_commands() {
        for c in [
            "uname -a",
            "id",
            "ls -ld /tmp",
            "cat /etc/os-release",
            "git status --short",
            "git log --oneline -5",
            "docker ps",
        ] {
            assert!(read_command(c).is_ok(), "{c}");
        }
    }
    #[test]
    fn rejects_shell_bypasses_and_mutable_read_modes() {
        for c in [
            "id; touch /tmp/pwned",
            "id\ntouch /tmp/pwned",
            "cat $(id)",
            "echo `id`",
            "ls > /tmp/out",
            "ls | sh",
            "env sh",
            "find / -exec sh",
            "git push",
            "git --version",
            "gh --version",
            "git -c core.sshCommand=sh push",
            "gh api --method POST /x",
            "git --version && id",
            "sed -i x /tmp/a",
            "python -c x",
            "awk BEGIN{}",
            "/bin/sh",
        ] {
            assert!(read_command(c).is_err(), "{c}");
        }
    }
    #[test]
    fn no_read_argument_expansion() {
        assert_eq!(
            read_command("cat '/tmp/a * ?' ").unwrap(),
            "'cat' '/tmp/a * ?'"
        );
    }
    #[test]
    fn quote_escapes_single_quotes() {
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }
    #[test]
    fn paths_and_cwd_are_validated() {
        for p in ["relative", "/tmp/a\nfile", " /tmp/a", "/tmp/\u{202e}file"] {
            assert!(path(p).is_err());
        }
        assert!(
            shell_command("pwd", Some("/tmp/a ' b"))
                .unwrap()
                .starts_with("sh -c ")
        );
    }
    #[test]
    fn writes_require_both_explicit_permissions() {
        let mut p: Profile = toml::from_str(
            r#"name="dev"
host="localhost"
user="dev"
keyRef="/tmp/test-key"
hostKeySha256="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#,
        )
        .unwrap();
        assert!(authorize_write(&p).is_err());
        p.approval_policy = ApprovalPolicy::ClientConfirmation;
        assert!(authorize_write(&p).is_err());
        p.read_only = false;
        authorize_write(&p).unwrap();
        p.approval_policy = ApprovalPolicy::Deny;
        assert!(authorize_write(&p).is_err());
    }
}

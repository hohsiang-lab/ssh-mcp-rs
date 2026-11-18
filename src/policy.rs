use crate::config::{ApprovalPolicy, Profile};
use anyhow::{Context, Result, bail, ensure};

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

/// Restrict arguments as well as the command name. Never allow command-executing
/// flags such as find -exec, grep --exclude-from command substitutions, etc.
/// All accepted arguments are re-quoted before going to a shell.
fn read_args(args: &[String], flags: &[&str], values: &[&str], max_operands: usize) -> bool {
    let mut operands = 0usize;
    let mut options = true;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" && options {
            options = false;
            continue;
        }
        if options && flags.contains(&arg.as_str()) {
            continue;
        }
        if options && values.contains(&arg.as_str()) {
            if iter.next().is_none() {
                return false;
            }
            continue;
        }
        if options && arg.starts_with('-') {
            return false;
        }
        operands += 1;
        if operands > max_operands {
            return false;
        }
    }
    true
}

fn extended_read(program: &str, args: &[String]) -> bool {
    match program {
        // Pure display utilities, no command/alternate-output flags.
        "basename" | "dirname" | "wc" | "cut" | "comm" | "whereis" | "which" | "who" | "free"
        | "file" | "stat" | "du" => read_args(
            args,
            &[
                "-a",
                "-h",
                "-b",
                "-k",
                "-m",
                "-s",
                "-l",
                "-c",
                "-w",
                "-L",
                "-n",
                "-H",
                "-0",
                "--",
                "--bytes",
                "--human-readable",
                "--summarize",
                "--total",
            ],
            &["-f", "--format", "-t", "--printf", "-d", "--delimiter"],
            16,
        ),
        "head" | "tail" => read_args(
            args,
            &["-q", "-v", "-f", "-F", "--follow", "--quiet", "--verbose"],
            &["-n", "-c", "--lines", "--bytes"],
            32,
        ),
        "grep" | "egrep" | "fgrep" => read_args(
            args,
            &[
                "-n",
                "-i",
                "-v",
                "-r",
                "-R",
                "-F",
                "-E",
                "-w",
                "-x",
                "-l",
                "-L",
                "-c",
                "-s",
                "-h",
                "-H",
                "-q",
                "-A",
                "-B",
                "-C",
                "--line-number",
                "--ignore-case",
                "--invert-match",
                "--recursive",
                "--fixed-strings",
                "--extended-regexp",
            ],
            &[
                "-e",
                "-f",
                "--regexp",
                "--file",
                "--include",
                "--exclude",
                "--exclude-dir",
            ],
            128,
        ),
        "sort" => read_args(
            args,
            &[
                "-n",
                "-r",
                "-u",
                "-b",
                "-f",
                "-h",
                "-V",
                "--reverse",
                "--unique",
            ],
            &[],
            16,
        ),
        // Two operands mean 'outfile' in GNU/BSD uniq, so enforce one.
        "uniq" => read_args(
            args,
            &["-c", "-d", "-u", "-i", "-D"],
            &["-f", "-s", "-w"],
            1,
        ),
        "date" => args.iter().all(|a| {
            matches!(a.as_str(), "-u" | "--utc" | "-R" | "--rfc-2822")
                || (a.starts_with('+') && a.len() < 256)
        }),
        "ps" => {
            args.is_empty()
                || matches!(args,
            [a] if matches!(a.as_str(), "aux" | "-ef" | "-e" | "-A" | "ax"))
                || matches!(args, [a, _] if matches!(a.as_str(), "-p" | "-o" | "-eo"))
        }
        // Explicitly only find's read predicates; -exec/-delete/-fprint rejected.
        "find" => {
            if args.is_empty() {
                return true;
            }
            let mut i = 0usize;
            while i < args.len() {
                let a = &args[i];
                match a.as_str() {
                    "-print" | "-print0" | "-L" | "-H" | "-P" => i += 1,
                    "-maxdepth" | "-mindepth" | "-type" | "-name" | "-iname" | "-size" => {
                        if i + 1 >= args.len() {
                            return false;
                        }
                        i += 2;
                    }
                    _ if !a.starts_with('-') && !matches!(a.as_str(), "(" | ")") => i += 1,
                    _ => return false,
                }
            }
            true
        }
        _ => false,
    }
}

/// This is intentionally a small grammar, not a shell classifier. No pipes,
/// substitutions, interpreters, mutable git subcommands or gh api are allowed.
/// Parsing followed by re-quoting prevents shell expansion even inside arguments.
pub fn read_command(command: &str) -> Result<String> {
    validate_command(command)?;
    ensure!(
        !command
            .chars()
            .any(|c| c.is_control() || ";|&<>`$(){}".contains(c)),
        "READ_ONLY_DENIED: shell syntax is not accepted; use run_command with confirmation"
    );
    let words = shlex::split(command).context("invalid shell quoting")?;
    let (program, args) = words.split_first().context("empty command")?;
    let safe = match program.as_str() {
        "pwd" | "uptime" | "whoami" => args.is_empty(),
        "uname" => {
            args.is_empty()
                || (args.len() == 1 && matches!(args[0].as_str(), "-a" | "-s" | "-r" | "-m"))
        }
        "id" => {
            args.is_empty()
                || (args.len() == 1 && matches!(args[0].as_str(), "-u" | "-g" | "-un" | "-gn"))
        }
        "git" | "gh" => args == ["--version"],
        "ls" => args.iter().all(|arg| {
            arg.starts_with('/')
                || matches!(
                    arg.as_str(),
                    "--" | "-l" | "-a" | "-la" | "-al" | "-lh" | "-lah" | "-ld" | "-d" | "-n"
                )
        }),
        "cat" => !args.is_empty() && args.iter().all(|arg| arg.starts_with('/')),
        "df" => args
            .iter()
            .all(|arg| arg.starts_with('/') || matches!(arg.as_str(), "-h" | "-k" | "-i" | "-P")),
        _ => extended_read(program, args),
    };
    if !safe {
        bail!(
            "READ_ONLY_DENIED: command is outside the read-only grammar; use run_command with confirmation"
        );
    }
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
    fn accepts_basic_reads_and_version_queries() {
        for c in [
            "uname -a",
            "id",
            "ls -ld /tmp",
            "cat /etc/os-release",
            "git --version",
            "gh --version",
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
            "git status",
            "git -c core.sshCommand=sh push",
            "gh api --method POST /x",
            "git --version && id",
            "sed -i x /tmp/a",
            "python -c x",
            "awk BEGIN{}",
            "/bin/sh",
            "ls --format=anything",
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

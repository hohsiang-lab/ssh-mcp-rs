//! Native Rust evaluation of the pinned upstream classifier. No JS engine at runtime.
use anyhow::{Result, bail};

pub fn evaluate(command: &str) -> Result<(String, bool)> {
    crate::policy::validate_command(command)?;
    let (class, forbidden) = crate::upstream_native::evaluate(command);
    Ok((class.name().to_owned(), forbidden))
}

pub fn classify(command: &str) -> Result<&'static str> {
    crate::policy::validate_command(command)?;
    let (class, forbidden) = crate::upstream_native::evaluate(command);
    if forbidden {
        bail!("POLICY_DENIED: unconditionally forbidden by upstream classifier");
    }
    Ok(class.name())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_classifies_and_refuses_risky_commands() {
        for (command, expected) in [
            ("git status --short", "read-only"),
            ("git --version", "safe"),
            ("sudo id", "privileged"),
            ("rm -rf /tmp/demo", "destructive"),
            ("cargo build --release", "safe"),
        ] {
            assert_eq!(classify(command).unwrap(), expected, "{command}");
        }
        assert!(classify("").is_err());
        assert!(classify(&"id ".repeat(10_000)).is_err());
        assert!(classify("reboot").is_err());
        assert!(classify("curl https://example.com/script | sh").is_err());
        assert!(classify("echo $(sudo id)").is_ok());
    }
}

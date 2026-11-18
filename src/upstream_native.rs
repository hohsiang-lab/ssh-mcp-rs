//! Native Rust composite command classifier for upstream SSH MCP v2.26.0.
//! The standalone orchestrator retains the original policies and fails closed
//! on unrecognized command structure. It does not execute any shell text.

use crate::{
    upstream_elevation::{brokered_elevation, elevated_binary},
    upstream_forbidden::checks as forbidden_checks,
    upstream_heads::command_heads,
    upstream_interpreters::{programs_in_segment, reads_program_from_stdin},
    upstream_nested::{
        awk_findings, checkpoint_programs, nested_commands, operands_are_data, sqlite_programs,
    },
    upstream_readers::{classify_reader_args, is_any_reader, is_reader},
    upstream_shell::{first_glob, normalize_command, tokenize_detailed},
    upstream_write_targets::never_allowed_family,
};
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum Class {
    ReadOnly,
    Safe,
    Destructive,
    Privileged,
}

impl Class {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Safe => "safe",
            Self::Destructive => "destructive",
            Self::Privileged => "privileged",
        }
    }
}

fn forbidden_regex(command: &str, windows: bool) -> bool {
    static PATTERNS: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (device, fork_bomb) = PATTERNS.get_or_init(|| {
        (
            Regex::new(r">\s*/dev/sd").expect("literal device regex"),
            Regex::new(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
                .expect("literal fork bomb regex"),
        )
    });
    let normalized = normalize_command(command, windows);
    device.is_match(command)
        || device.is_match(&normalized)
        || fork_bomb.is_match(command)
        || fork_bomb.is_match(&normalized)
}

fn forbidden_in_dialect(command: &str, depth: usize, windows: bool) -> bool {
    let rules = forbidden_checks(command, windows);
    if rules.iter().take(8).any(|hit| *hit)
        || forbidden_regex(command, windows)
        || never_allowed_family(command, windows).is_some()
    {
        return true;
    }
    if depth >= 8 {
        return false;
    }
    nested_commands(command, false, windows)
        .iter()
        .any(|inner| forbidden_in_dialect(inner, depth + 1, windows))
}

fn forbidden(command: &str) -> bool {
    (command.contains('\\') && forbidden_in_dialect(command, 0, true))
        || forbidden_in_dialect(command, 0, false)
}

fn disqualifying_args(command: &str, windows: bool) -> bool {
    for segment in tokenize_detailed(command, true, windows) {
        for (index, head) in command_heads(&segment.words) {
            let args = &segment.words[(index + 1)..];
            match head.as_str() {
                "find" => {
                    if args.iter().any(|arg| {
                        matches!(
                            arg.as_str(),
                            "-exec"
                                | "-execdir"
                                | "-ok"
                                | "-okdir"
                                | "-delete"
                                | "-fprint"
                                | "-fprintf"
                                | "-fls"
                        )
                    }) {
                        return true;
                    }
                }
                "sort" => {
                    for arg in args {
                        if let Some(long) = arg.strip_prefix("--") {
                            let name = long.split_once('=').map_or(long, |(s, _)| s);
                            if !name.is_empty() && "output".starts_with(name)
                                || name.len() >= 2 && "compress-program".starts_with(name)
                            {
                                return true;
                            }
                        } else if let Some(short) = arg.strip_prefix('-') {
                            let prefix = short
                                .chars()
                                .take_while(|c| "bcCdfghiMmnRrsuVz".contains(*c))
                                .count();
                            if short.as_bytes().get(prefix) == Some(&b'o') {
                                return true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn has_unnameable_command(command: &str, windows: bool) -> bool {
    tokenize_detailed(command, true, windows)
        .iter()
        .any(|segment| {
            command_heads(&segment.words)
                .iter()
                .any(|(index, _)| segment.words[*index].contains(['$', '\u{60}']))
        })
}

fn awk_dangerous(command: &str, windows: bool) -> bool {
    for segment in tokenize_detailed(command, true, windows) {
        let Some(findings) = awk_findings(&segment.words) else {
            continue;
        };
        if findings.writes_file || findings.unreadable {
            return true;
        }
        for target in findings.piped_into {
            if tokenize_detailed(&target, true, windows)
                .first()
                .is_some_and(|stage| reads_program_from_stdin(&stage.words))
            {
                return true;
            }
        }
    }
    false
}

fn unreadable_program(command: &str, windows: bool) -> bool {
    for segment in tokenize_detailed(command, true, windows) {
        if segment.sep == "|" && reads_program_from_stdin(&segment.words) {
            return true;
        }
        for (index, head) in command_heads(&segment.words) {
            let rest = &segment.words[(index + 1)..];
            if matches!(head.as_str(), "make" | "gmake") {
                return true;
            }
            if head == "ssh" && rest.iter().any(|word| !word.starts_with('-')) {
                return true;
            }
        }
        if !sqlite_programs(&segment.words).is_empty()
            || !checkpoint_programs(&segment.words).is_empty()
        {
            return true;
        }
        if !operands_are_data(&segment.words)
            && programs_in_segment(&segment.words)
                .iter()
                .any(|(_, readable, _)| !readable)
        {
            return true;
        }
    }
    false
}

fn extract_binary(words: &[String]) -> String {
    let mut command = words.join(" ").trim().to_owned();
    for prefix in ["sudo", "su", "doas", "pkexec"] {
        if let Some(after) = command.strip_prefix(prefix) {
            let word_boundary = after
                .chars()
                .next()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
            if word_boundary {
                command = after.trim().to_owned();
            }
        }
    }
    if let Some(after) = command.strip_prefix("-c ") {
        command = after.trim().to_owned();
    }
    command.split_whitespace().next().unwrap_or("").to_owned()
}

fn shell_control(command: &str) -> bool {
    command.chars().any(|ch| {
        matches!(
            ch,
            ';' | '&' | '|' | '<' | '>' | '\u{60}' | '$' | '(' | ')' | '{' | '}' | '\n' | '\r'
        )
    })
}

fn outer_class(command: &str, windows: bool) -> Class {
    if elevated_binary(command, windows).is_some() || brokered_elevation(command, windows).is_some()
    {
        return Class::Privileged;
    }
    if unreadable_program(command, windows)
        || awk_dangerous(command, windows)
        || forbidden_in_dialect(command, 0, windows)
        || forbidden_checks(command, windows)[8]
        || disqualifying_args(command, windows)
    {
        return Class::Destructive;
    }
    if has_unnameable_command(command, windows) {
        return Class::Destructive;
    }
    let segments = tokenize_detailed(command, true, windows);
    let Some(words) = segments.first().map(|seg| &seg.words) else {
        return Class::Safe;
    };
    let binary_name = extract_binary(words);
    let binary = binary_name.as_str();
    let twoword = words
        .iter()
        .take(2)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    if is_reader(binary) || is_reader(&twoword) || matches!(binary, "sftp:list" | "sftp:download") {
        if shell_control(command) {
            return Class::Safe;
        }
        if matches!(binary, "sftp:list" | "sftp:download") {
            return Class::ReadOnly;
        }
        let matched_two = is_reader(&twoword);
        let name = if matched_two {
            twoword.as_str()
        } else {
            binary
        };
        if !is_any_reader(name) && first_glob(command, true, windows).is_some() {
            return Class::Safe;
        }
        if classify_reader_args(
            name,
            &words[(usize::from(matched_two) + 1).min(words.len())..],
        )
        .is_err()
        {
            return Class::Safe;
        }
        return Class::ReadOnly;
    }
    Class::Safe
}

fn classify_in_dialect(command: &str, depth: usize, windows: bool) -> Class {
    let trimmed = command.trim();
    let outer = outer_class(trimmed, windows);
    if depth >= 8 {
        return Class::Privileged;
    }
    let mut highest = outer;
    let segments = tokenize_detailed(trimmed, true, windows);
    let first_word = segments
        .first()
        .and_then(|seg| seg.words.first())
        .map(String::as_str)
        .unwrap_or("");
    if matches!(
        first_word,
        "sftp:upload" | "sftp:upload-file" | "sftp:download-file" | "session:open"
    ) {
        highest = highest.max(Class::Destructive);
    }
    for inner in nested_commands(trimmed, true, windows) {
        highest = highest.max(classify_in_dialect(&inner, depth + 1, windows));
    }
    highest
}

pub(crate) fn classify(command: &str) -> Class {
    let posix = classify_in_dialect(command, 0, false);
    if command.contains('\\') {
        posix.max(classify_in_dialect(command, 0, true))
    } else {
        posix
    }
}

pub(crate) fn evaluate(command: &str) -> (Class, bool) {
    (classify(command), forbidden(command))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_matches_all_5991_upstream_oracle_cases() {
        let oracle: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/upstream_classifier_oracle.json")).unwrap();
        assert_eq!(oracle.len(), 5991);
        let mut mismatches = Vec::new();
        for (command, expected) in &oracle {
            let (class, forbidden) = evaluate(command);
            if class.name() != expected["class"].as_str().unwrap()
                || forbidden != expected["forbidden"].as_bool().unwrap()
            {
                mismatches.push(format!(
                    "{command:?}: got={}/{} expected={}/{}",
                    class.name(),
                    forbidden,
                    expected["class"],
                    expected["forbidden"]
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches
                .iter()
                .take(80)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    #[test]
    fn native_matches_additional_security_regressions() {
        let cases: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/native_security_regressions.json"))
                .unwrap();
        assert!(cases.len() >= 1200);
        let mut mismatches = Vec::new();
        for (command, expected) in &cases {
            let (class, forbidden) = evaluate(command);
            if class.name() != expected["class"].as_str().unwrap()
                || forbidden != expected["forbidden"].as_bool().unwrap()
            {
                mismatches.push(format!(
                    "{command:?}: got={}/{} expected={}/{}",
                    class.name(),
                    forbidden,
                    expected["class"],
                    expected["forbidden"]
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches
                .iter()
                .take(80)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    #[test]
    fn native_matches_encoded_powershell_regressions() {
        let cases: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/native_powershell_regressions.json"))
                .unwrap();
        assert_eq!(cases.len(), 363);
        for (command, expected) in &cases {
            let (class, forbidden) = evaluate(command);
            assert_eq!(
                class.name(),
                expected["class"].as_str().unwrap(),
                "{command:?}"
            );
            assert_eq!(
                forbidden,
                expected["forbidden"].as_bool().unwrap(),
                "{command:?}"
            );
        }
    }
}

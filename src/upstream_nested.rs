//! Native extraction of shell programs carried by substitutions, wrappers and interpreters.

use crate::upstream_awk::{AwkFindings, read_awk_invocation};
use crate::upstream_heads::command_heads;
use crate::upstream_interpreters::{
    decoded_powershell, programs_in_segment, reads_program_from_stdin,
};
use crate::upstream_readers::is_reader;
use crate::upstream_shell::{shell_substitutions, tokenize_detailed};
use std::collections::HashSet;

pub(crate) fn awk_findings(words: &[String]) -> Option<AwkFindings> {
    let mut merged: Option<AwkFindings> = None;
    for (index, head) in command_heads(words) {
        if !matches!(head.as_str(), "awk" | "gawk" | "mawk" | "nawk") {
            continue;
        }
        let refs: Vec<&str> = words[(index + 1)..].iter().map(String::as_str).collect();
        let Some(found) = read_awk_invocation(&refs) else {
            continue;
        };
        if let Some(existing) = merged.as_mut() {
            existing.commands.extend(found.commands);
            existing.piped_into.extend(found.piped_into);
            existing.writes_file |= found.writes_file;
            existing.unreadable |= found.unreadable;
        } else {
            merged = Some(found);
        }
    }
    merged
}

pub(crate) fn operands_are_data(words: &[String]) -> bool {
    let heads = command_heads(words);
    !heads.is_empty() && heads.iter().all(|(_, head)| is_reader(head))
}

fn env_command_assignment(word: &str) -> Option<&str> {
    let (name, value) = word.split_once('=')?;
    if matches!(
        name,
        "GIT_SSH_COMMAND"
            | "GIT_EDITOR"
            | "GIT_SEQUENCE_EDITOR"
            | "GIT_PAGER"
            | "GIT_EXTERNAL_DIFF"
            | "SSH_ASKPASS"
            | "SUDO_ASKPASS"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "BROWSER"
    ) {
        Some(value)
    } else {
        None
    }
}

fn strip_glued_command_prefix(word: &str) -> &str {
    let eq = word.rfind('=');
    let mut paren = word.rfind('(');
    while let Some(i) = paren {
        if i > 0 && matches!(word.as_bytes()[i - 1], b'$' | b'<' | b'>') {
            paren = word[..i].rfind('(');
        } else {
            break;
        }
    }
    let cut = match (eq, paren) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        _ => None,
    };
    let remainder = if cut.is_some_and(|i| i > 0) {
        &word[(cut.unwrap_or(0) + 1)..]
    } else {
        word
    };
    remainder.trim_start_matches(['+', '!', '"', '\''])
}

pub(crate) fn sqlite_programs(words: &[String]) -> Vec<String> {
    let mut programs = Vec::new();
    for (index, head) in command_heads(words) {
        if head != "sqlite3" {
            continue;
        }
        for word in &words[(index + 1)..] {
            let suffix = word
                .strip_prefix(".shell")
                .or_else(|| word.strip_prefix(".system"));
            if let Some(suffix) = suffix
                && suffix.starts_with(char::is_whitespace)
            {
                let value = suffix.trim_start_matches(char::is_whitespace);
                if !value.is_empty() {
                    programs.push(value.to_owned());
                }
            }
        }
    }
    programs
}

pub(crate) fn checkpoint_programs(words: &[String]) -> Vec<String> {
    let mut programs = Vec::new();
    for (index, head) in command_heads(words) {
        if head != "tar" {
            continue;
        }
        for (i, word) in words.iter().enumerate().skip(index + 1) {
            if let Some((flag, cmd)) = word.split_once("=exec=") {
                if is_checkpoint_flag(flag) && !cmd.is_empty() {
                    programs.push(cmd.to_owned());
                }
                continue;
            }
            if is_checkpoint_flag(word)
                && let Some(cmd) = words.get(i + 1).and_then(|s| s.strip_prefix("exec="))
                && !cmd.is_empty()
            {
                programs.push(cmd.to_owned());
            }
        }
    }
    programs
}

fn is_checkpoint_flag(word: &str) -> bool {
    word.strip_prefix("--checkpoint-a")
        .is_some_and(|tail| tail.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
}

pub(crate) fn nested_commands(command: &str, speculative: bool, windows: bool) -> Vec<String> {
    let mut found = shell_substitutions(command);
    let segments = tokenize_detailed(command, true, windows);
    for segment in &segments {
        let words = &segment.words;
        let awk = awk_findings(words);
        if let Some(a) = &awk {
            found.extend(a.commands.clone());
            found.extend(a.piped_into.clone());
        }

        if !operands_are_data(words) {
            let mut consumed = HashSet::new();
            for (_, _, program) in programs_in_segment(words) {
                consumed.insert(program.index);
                found.push(program.program.clone());
                if matches!(program.flag.as_str(), "-EncodedCommand" | "-e")
                    && programs_in_segment(words).iter().any(|(i, _, _)| {
                        let name = words[*i].rsplit(['/', '\\']).next().unwrap_or(&words[*i]);
                        matches!(
                            name.to_ascii_lowercase().as_str(),
                            "pwsh" | "powershell" | "pwsh.exe" | "powershell.exe"
                        )
                    })
                    && let Some(decoded) = decoded_powershell(&program.program)
                {
                    found.push(decoded);
                }
            }
            if speculative && awk.is_none() {
                if let Some(first) = words.first().and_then(|w| env_command_assignment(w))
                    && first.contains(char::is_whitespace)
                {
                    found.push(first.to_owned());
                }
                for (i, word) in words.iter().enumerate().skip(1) {
                    if consumed.contains(&i) {
                        continue;
                    }
                    if word.starts_with('-') {
                        if let Some((_, value)) = word.rsplit_once('=')
                            && value.contains(char::is_whitespace)
                        {
                            found.push(value.to_owned());
                        }
                        continue;
                    }
                    let inner = strip_glued_command_prefix(word);
                    if inner.contains(char::is_whitespace) {
                        found.push(inner.to_owned());
                    }
                }
            }
        }
        let mut i = 0usize;
        while i < words.len() {
            if matches!(words[i].as_str(), "-exec" | "-execdir" | "-ok" | "-okdir")
                && i + 1 < words.len()
            {
                let rest = &words[(i + 1)..];
                let stop = rest
                    .iter()
                    .position(|word| matches!(word.as_str(), "+" | ";"));
                let command = rest[..stop.unwrap_or(rest.len())].join(" ");
                found.push(command);
                if let Some(stop) = stop {
                    i += 1 + stop;
                } else {
                    i = words.len();
                }
            }
            i += 1;
        }
        found.extend(checkpoint_programs(words));
        found.extend(sqlite_programs(words));
    }
    for pair in segments.windows(2) {
        if pair[1].sep == "|" && reads_program_from_stdin(&pair[1].words) {
            found.push(pair[0].words.join(" "));
        }
    }
    found.into_iter().filter(|s| !s.trim().is_empty()).collect()
}

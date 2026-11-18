//! Native interpreter-flag parser with declarative data pinned from upstream.

use crate::upstream_heads::command_heads;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Interpreter {
    flags: Vec<String>,
    readable: bool,
}

fn interpreters() -> &'static BTreeMap<String, Interpreter> {
    static TABLE: std::sync::OnceLock<BTreeMap<String, Interpreter>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str(include_str!("upstream_interpreter_data.json"))
            .expect("pinned interpreter table must decode")
    })
}

fn find_interpreter(word: &str) -> Option<&'static Interpreter> {
    let table = interpreters();
    if let Some(exact) = table.get(word) {
        return Some(exact);
    }
    let lower = word.to_ascii_lowercase();
    let lower = lower
        .strip_suffix(".exe")
        .or_else(|| lower.strip_suffix(".cmd"))
        .or_else(|| lower.strip_suffix(".bat"))
        .unwrap_or(&lower);
    table
        .iter()
        .find(|(name, _)| name.to_ascii_lowercase() == lower)
        .map(|(_, v)| v)
}

fn same_flag(word: &str, flag: &str, insensitive: bool) -> bool {
    if insensitive {
        word.eq_ignore_ascii_case(flag)
    } else {
        word == flag
    }
}

fn cluster_carries_flag<'a>(word: &str, flags: &'a [String], insensitive: bool) -> Option<&'a str> {
    if !word.starts_with('-')
        || word.len() < 3
        || word.len() > 4
        || !word[1..].bytes().all(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    for letter in word[1..].chars() {
        for flag in flags {
            if flag.len() == 2
                && if insensitive {
                    flag.as_bytes()[1].eq_ignore_ascii_case(&(letter as u8))
                } else {
                    flag.as_bytes()[1] == letter as u8
                }
            {
                return Some(flag);
            }
        }
    }
    None
}

pub(crate) struct Program {
    pub(crate) program: String,
    pub(crate) flag: String,
    pub(crate) index: usize,
}

fn flag_value(words: &[String], i: usize, flags: &[String], insensitive: bool) -> bool {
    if i == 0 {
        return false;
    }
    let previous = &words[i - 1];
    if previous.len() < 2
        || !previous.starts_with('-')
        || !flags.iter().any(|f| same_flag(previous, f, insensitive))
    {
        return false;
    }
    !command_heads(words)
        .iter()
        .any(|(head_idx, _)| *head_idx == i)
}

fn program_after_flag(
    words: &[String],
    from: usize,
    flags: &[String],
    insensitive: bool,
    tolerate_unknown_at_head: bool,
) -> Option<Program> {
    let tolerate_unknown =
        tolerate_unknown_at_head && command_heads(words).iter().any(|(idx, _)| *idx == from);
    for j in (from + 1)..words.len() {
        let word = &words[j];
        if let Some(flag) = flags.iter().find(|f| same_flag(word, f, insensitive)) {
            let mut k = j + 1;
            if !flag.starts_with('-') {
                while k < words.len() && (words[k].is_empty() || words[k].starts_with('-')) {
                    k += 1;
                }
            }
            return Some(Program {
                program: words.get(k)?.clone(),
                flag: flag.clone(),
                index: k,
            });
        }
        if let Some(flag) = flags
            .iter()
            .find(|f| word.starts_with(f.as_str()) && word.len() > f.len())
        {
            let remainder = &word[flag.len()..];
            if remainder.contains(char::is_whitespace) || remainder.starts_with('=') {
                return Some(Program {
                    program: remainder.trim_start_matches('=').to_owned(),
                    flag: flag.clone(),
                    index: j,
                });
            }
            return Some(Program {
                program: words.get(j + 1)?.clone(),
                flag: flag.clone(),
                index: j + 1,
            });
        }
        if let Some(flag) = cluster_carries_flag(word, flags, insensitive) {
            return Some(Program {
                program: words.get(j + 1)?.clone(),
                flag: flag.to_owned(),
                index: j + 1,
            });
        }
        if !(word.is_empty() || word.starts_with('-')) && !tolerate_unknown {
            return None;
        }
    }
    None
}

fn command_name(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

pub(crate) fn programs_in_segment(words: &[String]) -> Vec<(usize, bool, Program)> {
    let mut result = Vec::new();
    for (i, word) in words.iter().enumerate() {
        let Some(spec) = find_interpreter(command_name(word)) else {
            continue;
        };
        let insensitive = spec.flags.iter().any(|f| f == "-EncodedCommand");
        if flag_value(words, i, &spec.flags, insensitive) {
            continue;
        }
        if let Some(program) = program_after_flag(words, i, &spec.flags, insensitive, insensitive) {
            result.push((i, spec.readable, program));
        }
    }
    result
}

pub(crate) fn reads_program_from_stdin(words: &[String]) -> bool {
    command_heads(words)
        .iter()
        .any(|(idx, _)| reads_program_from_stdin_at(words, *idx))
}

fn reads_program_from_stdin_at(words: &[String], idx: usize) -> bool {
    let Some(spec) = find_interpreter(command_name(&words[idx])) else {
        return false;
    };
    let mut saw_stdin_flag = false;
    for j in (idx + 1)..words.len() {
        let word = &words[j];
        if spec.flags.iter().any(|f| word == f || word.starts_with(f)) {
            return false;
        }
        if word == "-s" {
            saw_stdin_flag = true;
            continue;
        }
        if word == "--" {
            return saw_stdin_flag || words.get(j + 1).is_none_or(|w| stdin_path(w));
        }
        if stdin_path(word) {
            return true;
        }
        if !word.starts_with('-') {
            return false;
        }
    }
    true
}

fn stdin_path(word: &str) -> bool {
    matches!(word, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

pub(crate) fn decoded_powershell(operand: &str) -> Option<String> {
    // The upstream Buffer.from(input, "base64") decoder is intentionally permissive:
    // missing padding, URL-safe alphabet, and ignored non-alphabet characters.
    // A strict base64 decoder can miss embedded privileged commands.
    let mut utf16_len = 0usize;
    let mut sample_end = 0usize;
    for (index, ch) in operand.char_indices() {
        if utf16_len + ch.len_utf16() > 65536 {
            break;
        }
        utf16_len += ch.len_utf16();
        sample_end = index + ch.len_utf8();
    }
    let sample = &operand[..sample_end];
    let mut decoded = Vec::new();
    let mut bits = 0u32;
    let mut count = 0u8;
    for byte in sample.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        bits = (bits << 6) | u32::from(sextet);
        count += 6;
        if count >= 8 {
            count -= 8;
            decoded.push((bits >> count) as u8);
            bits &= (1u32 << count) - 1;
        }
    }
    let mut utf16 = Vec::with_capacity(decoded.len() / 2);
    for pair in decoded.as_chunks::<2>().0 {
        utf16.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let result = String::from_utf16_lossy(&utf16);
    if result.contains('\u{fffd}') || result.trim().is_empty() {
        None
    } else {
        Some(result)
    }
}

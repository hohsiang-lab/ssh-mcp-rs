//! Native Rust reconstruction of the upstream wrapper and privilege-head reader.
//! This is test-only until the complete policy classifier is migrated.

use std::collections::HashSet;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct State {
    i: usize,
    operands_left: usize,
    owner: Option<String>,
    prefix: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Reading {
    pub(crate) index: i32,
    pub(crate) prefix: Option<String>,
}

fn privilege_prefix(word: &str) -> bool {
    matches!(
        word,
        "sudo"
            | "su"
            | "doas"
            | "pkexec"
            | "su-exec"
            | "gosu"
            | "sudo-rs"
            | "run0"
            | "pfexec"
            | "runuser"
            | "setpriv"
    )
}

fn wrapper(word: &str) -> bool {
    matches!(
        word,
        "env"
            | "nohup"
            | "nice"
            | "ionice"
            | "command"
            | "exec"
            | "setsid"
            | "stdbuf"
            | "timeout"
            | "chrt"
            | "taskset"
            | "xargs"
            | "watch"
            | "busybox"
            | "strace"
            | "ltrace"
            | "valgrind"
            | "flock"
            | "chroot"
            | "perf"
            | "time"
    )
}

fn wrapper_operands(word: &str) -> usize {
    usize::from(matches!(
        word,
        "flock" | "chroot" | "taskset" | "perf" | "timeout"
    ))
}

fn strip_path(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

fn unquote(word: &str) -> &str {
    if word.len() >= 2
        && ((word.starts_with('"') && word.ends_with('"'))
            || (word.starts_with('\'') && word.ends_with('\'')))
    {
        &word[1..word.len() - 1]
    } else {
        word
    }
}

fn fold_command_word(word: &str) -> String {
    let mut folded = word.to_ascii_lowercase();
    for extension in [".exe", ".cmd", ".bat"] {
        if folded.ends_with(extension) {
            folded.truncate(folded.len() - extension.len());
            break;
        }
    }
    folded
}

fn bare_numeric(word: &str) -> bool {
    let word = word.trim_end_matches(['s', 'm', 'h', 'd']);
    let (main, fraction) = word
        .split_once('.')
        .map_or((word, None), |(a, b)| (a, Some(b)));
    !main.is_empty()
        && main.bytes().all(|c| c.is_ascii_digit())
        && fraction.is_none_or(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
}

fn assignment(word: &str) -> bool {
    let Some((name, _value)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn command_lookup(word: &str) -> bool {
    word.starts_with('-')
        && word[1..].contains(['v', 'V'])
        && word[1..].chars().all(|c| matches!(c, 'p' | 'v' | 'V'))
}

fn prefix_value_flag(word: &str) -> bool {
    matches!(
        word,
        "-u" | "-g"
            | "-p"
            | "-C"
            | "-h"
            | "-r"
            | "-t"
            | "-U"
            | "-c"
            | "--user"
            | "--group"
            | "--prompt"
            | "--close-from"
            | "--host"
            | "--role"
            | "--type"
            | "--other-user"
            | "--command"
    )
}

#[derive(Clone, Copy)]
struct Options {
    values: &'static [&'static str],
    no_values: &'static [&'static str],
}

fn wrapper_options(owner: &str) -> Option<Options> {
    let (values, no_values): (&'static [&'static str], &'static [&'static str]) = match owner {
        "env" => (
            &[
                "-u",
                "--unset",
                "-C",
                "--chdir",
                "-S",
                "--split-string",
                "-P",
            ],
            &[
                "-i",
                "--ignore-environment",
                "-0",
                "--null",
                "-v",
                "--debug",
                "-",
            ],
        ),
        "nice" => (&["-n", "--adjustment"], &[]),
        "ionice" => (
            &[
                "-c",
                "--class",
                "-n",
                "--classdata",
                "-p",
                "--pid",
                "-P",
                "--pgid",
                "-u",
                "--uid",
            ],
            &["-t", "--ignore"],
        ),
        "command" => (&[], &["-p"]),
        "exec" => (&["-a"], &["-c", "-l"]),
        "setsid" => (&[], &["-c", "--ctty", "-f", "--fork", "-w", "--wait"]),
        "stdbuf" => (&["-i", "--input", "-o", "--output", "-e", "--error"], &[]),
        "timeout" => (
            &["-s", "--signal", "-k", "--kill-after"],
            &[
                "-v",
                "--verbose",
                "-f",
                "--foreground",
                "-p",
                "--preserve-status",
            ],
        ),
        "chrt" => (
            &[
                "-T",
                "--sched-runtime",
                "-P",
                "--sched-period",
                "-D",
                "--sched-deadline",
            ],
            &[
                "-a",
                "--all-tasks",
                "-b",
                "--batch",
                "-d",
                "--deadline",
                "-e",
                "--ext",
                "-f",
                "--fifo",
                "-i",
                "--idle",
                "-o",
                "--other",
                "-r",
                "--rr",
                "-R",
                "--reset-on-fork",
                "-m",
                "--max",
                "-p",
                "--pid",
                "-v",
                "--verbose",
            ],
        ),
        "taskset" => (
            &[],
            &["-a", "--all-tasks", "-p", "--pid", "-c", "--cpu-list"],
        ),
        "xargs" => (
            &[
                "-I",
                "-J",
                "-d",
                "-E",
                "-n",
                "-s",
                "-P",
                "-R",
                "-L",
                "-S",
                "-a",
                "--arg-file",
                "--delimiter",
                "--max-args",
                "--max-procs",
                "--max-chars",
                "--process-slot-var",
            ],
            &[
                "-0",
                "--null",
                "-p",
                "--interactive",
                "-r",
                "--no-run-if-empty",
                "-t",
                "--verbose",
                "-x",
                "--exit",
                "-o",
                "--open-tty",
                "--show-limits",
                "-e",
                "-i",
                "-l",
            ],
        ),
        "watch" => (
            &["-n", "--interval", "-q", "--equexit"],
            &[
                "-b",
                "--beep",
                "-c",
                "--color",
                "-C",
                "--no-color",
                "-d",
                "--differences",
                "-e",
                "--errexit",
                "-g",
                "--chgexit",
                "-p",
                "--precise",
                "-t",
                "--no-title",
                "-w",
                "--no-wrap",
                "-x",
                "--exec",
                "-r",
                "--no-rerun",
            ],
        ),
        "strace" => (
            &[
                "-o", "-e", "-p", "-s", "-S", "-u", "-U", "-a", "-b", "-I", "-X", "-P", "-E", "-O",
            ],
            &[
                "-c", "-C", "-d", "-D", "-f", "-F", "-h", "-i", "-k", "-n", "-q", "-r", "-t", "-T",
                "-v", "-V", "-w", "-x", "-y", "-z", "-Z", "-ff", "-tt", "-ttt", "-qq", "-xx",
                "-yy",
            ],
        ),
        "ltrace" => (
            &[
                "-a", "-A", "-D", "-e", "-F", "-l", "-n", "-o", "-p", "-s", "-u", "-w", "-x",
            ],
            &[
                "-b", "-c", "-C", "-d", "-f", "-h", "-i", "-L", "-r", "-S", "-t", "-tt", "-ttt",
                "-T", "-V",
            ],
        ),
        "valgrind" => (&[], &["-h", "-v", "-q", "-d", "--help", "--version"]),
        "flock" => (
            &["-w", "--wait", "--timeout", "-E", "--conflict-exit-code"],
            &[
                "-s",
                "--shared",
                "-x",
                "-e",
                "--exclusive",
                "-u",
                "--unlock",
                "-n",
                "--nb",
                "--nonblock",
                "-o",
                "--close",
                "-F",
                "--no-fork",
                "--verbose",
                "-h",
                "--help",
                "-V",
                "--version",
            ],
        ),
        "chroot" => (
            &["--userspec", "--groups", "-u", "-g", "-G"],
            &["--skip-chdir"],
        ),
        "time" => (
            &["-o", "--output", "-f", "--format"],
            &[
                "-p",
                "--portability",
                "-a",
                "--append",
                "-v",
                "--verbose",
                "-q",
                "--quiet",
            ],
        ),
        _ => return None,
    };
    Some(Options { values, no_values })
}

fn option_takes_value(owner: &str, word: &str) -> Option<bool> {
    if word == "--" || (word.starts_with("--") && word.contains('=')) {
        return Some(false);
    }
    if privilege_prefix(owner) {
        return Some(prefix_value_flag(word));
    }
    let opts = wrapper_options(owner)?;
    if opts.values.contains(&word) {
        return Some(true);
    }
    if opts.no_values.contains(&word) {
        return Some(false);
    }
    if word.starts_with("--") {
        return None;
    }
    if word.starts_with('-') && word[1..].bytes().all(|c| c.is_ascii_digit()) {
        return Some(false);
    }
    for (index, ch) in word.char_indices().skip(1) {
        let flag = format!("-{ch}");
        if opts.values.contains(&flag.as_str()) {
            return Some(index + ch.len_utf8() == word.len());
        }
        if !opts.no_values.contains(&flag.as_str()) {
            return None;
        }
    }
    Some(false)
}

fn push(stack: &mut Vec<State>, seen: &mut HashSet<State>, value: State) {
    if seen.insert(value.clone()) {
        stack.push(value);
    }
}

fn finish(readings: &mut Vec<Reading>, index: i32, prefix: Option<String>) {
    let value = Reading { index, prefix };
    if !readings.contains(&value) {
        readings.push(value);
    }
}

fn read_word(
    state: &State,
    raw: &str,
    spelled: &str,
    word: &str,
    stack: &mut Vec<State>,
    seen: &mut HashSet<State>,
    readings: &mut Vec<Reading>,
) {
    if privilege_prefix(word) {
        let mut next = state.clone();
        next.i += 1;
        next.operands_left = 0;
        next.owner = Some(word.to_owned());
        if next.prefix.is_none() {
            next.prefix = Some(spelled.to_owned());
        }
        push(stack, seen, next);
    } else if wrapper(word) {
        let mut next = state.clone();
        next.i += 1;
        next.operands_left = wrapper_operands(word);
        next.owner = Some(word.to_owned());
        push(stack, seen, next);
    } else if assignment(raw) || bare_numeric(raw) {
        let mut next = state.clone();
        next.i += 1;
        push(stack, seen, next);
    } else {
        finish(readings, state.i as i32, state.prefix.clone());
    }
}

pub(crate) fn command_readings(words: &[String]) -> Vec<Reading> {
    let mut readings = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = Vec::new();
    push(
        &mut stack,
        &mut seen,
        State {
            i: 0,
            operands_left: 0,
            owner: None,
            prefix: None,
        },
    );
    while let Some(state) = stack.pop() {
        if state.i >= words.len() {
            finish(&mut readings, -1, state.prefix);
            continue;
        }
        let raw = words[state.i].as_str();
        let spelled = strip_path(unquote(raw));
        let word = fold_command_word(spelled);
        let mut next = state.clone();
        next.i += 1;
        if raw.starts_with('-') {
            if state.owner.as_deref() == Some("command") && command_lookup(raw) {
                finish(&mut readings, -1, state.prefix);
                continue;
            }
            let takes = state
                .owner
                .as_deref()
                .map_or(Some(false), |owner| option_takes_value(owner, raw));
            let mut consumed = state.clone();
            consumed.i += 2;
            match takes {
                None => {
                    push(&mut stack, &mut seen, consumed);
                    push(&mut stack, &mut seen, next);
                }
                Some(true) => push(&mut stack, &mut seen, consumed),
                Some(false) => push(&mut stack, &mut seen, next),
            }
            continue;
        }
        if state.operands_left > 0 {
            let mut as_operand = next;
            as_operand.operands_left -= 1;
            if !bare_numeric(raw) {
                let mut non_operand = state.clone();
                non_operand.operands_left = 0;
                read_word(
                    &non_operand,
                    raw,
                    spelled,
                    &word,
                    &mut stack,
                    &mut seen,
                    &mut readings,
                );
            }
            push(&mut stack, &mut seen, as_operand);
        } else {
            read_word(
                &state,
                raw,
                spelled,
                &word,
                &mut stack,
                &mut seen,
                &mut readings,
            );
        }
    }
    readings
}

pub(crate) fn command_heads(words: &[String]) -> Vec<(usize, String)> {
    let mut heads = Vec::new();
    for reading in command_readings(words) {
        if reading.index < 0 {
            continue;
        }
        let index = reading.index as usize;
        if heads.iter().any(|(seen, _)| *seen == index) {
            continue;
        }
        let head = fold_command_word(strip_path(unquote(&words[index])));
        heads.push((index, head));
    }
    heads
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    #[test]
    fn readings_match_upstream_for_corpus() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, commandReadings, tokenizeSegments};",
        );
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        let oracle: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/upstream_classifier_oracle.json")).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            ctx.eval::<(), _>("globalThis.__readings = (s, d) => JSON.stringify(UpstreamSSH.tokenizeSegments(s, d).map(w => UpstreamSSH.commandReadings(w)));").unwrap();
            let js: rquickjs::Function = ctx.globals().get("__readings").unwrap();
            for command in oracle.keys() {
                for dialect in ["posix", "windows"] {
                    let json: String = js.call((command.as_str(), dialect)).unwrap();
                    let expected: Vec<Vec<Reading>> = serde_json::from_str(&json).unwrap();
                    let words = crate::upstream_shell::tokenize_detailed(command, true, dialect == "windows");
                    let actual: Vec<Vec<Reading>> = words.iter()
                        .map(|segment| command_readings(&segment.words))
                        .collect();
                    assert_eq!(actual, expected, "{dialect} {command:?}");
                }
            }
        });
    }
}

//! Native hard-denial command predicates from the pinned upstream policy.
//! Kept test-only until the entire classifier is native and oracle-compatible.

use crate::{upstream_heads::command_heads, upstream_shell::tokenize_detailed};

fn any_segment_runs(
    command: &str,
    windows: bool,
    predicate: impl Fn(&str, &[String]) -> bool,
) -> bool {
    tokenize_detailed(command, true, windows)
        .iter()
        .any(|segment| {
            command_heads(&segment.words)
                .iter()
                .any(|(index, head)| predicate(head, &segment.words[(index + 1)..]))
        })
}

fn invoked_words(command: &str, windows: bool) -> Vec<String> {
    let mut names = Vec::new();
    for segment in tokenize_detailed(command, true, windows) {
        for (index, head) in command_heads(&segment.words) {
            names.push(head.clone());
            if matches!(head.as_str(), "systemctl" | "init" | "telinit") {
                names.extend(
                    segment.words[(index + 1)..]
                        .iter()
                        .filter(|word| !word.starts_with('-'))
                        .map(|word| fold_command_word(word)),
                );
            }
        }
    }
    names
}

fn fold_command_word(word: &str) -> String {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let folded = name.to_ascii_lowercase();
    for suffix in [".exe", ".cmd", ".bat"] {
        if let Some(stripped) = folded.strip_suffix(suffix) {
            return stripped.to_owned();
        }
    }
    folded
}

fn pipes_download_into_shell(command: &str, windows: bool) -> bool {
    let segments = tokenize_detailed(command, true, windows);
    let stages: Vec<Vec<String>> = segments
        .iter()
        .enumerate()
        .filter(|(i, segment)| *i == 0 || segment.sep == "|")
        .map(|(_, segment)| {
            command_heads(&segment.words)
                .into_iter()
                .map(|(_, head)| head)
                .collect()
        })
        .collect();
    let first = stages.iter().position(|heads| {
        heads
            .iter()
            .any(|head| matches!(head.as_str(), "curl" | "wget"))
    });
    first.is_some_and(|i| {
        stages[(i + 1)..].iter().any(|heads| {
            heads
                .iter()
                .any(|head| matches!(head.as_str(), "sh" | "bash" | "zsh"))
        })
    })
}

fn writes_to_device(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, args| {
        head == "dd" && args.iter().any(|arg| arg.starts_with("of=/dev/"))
    })
}

fn recursive_flag(args: &[String], recursive_letters: &str) -> bool {
    args.iter().any(|arg| {
        arg.starts_with("--rec")
            || (arg.starts_with('-')
                && arg.len() > 1
                && arg[1..].bytes().all(|b| b.is_ascii_alphabetic())
                && arg[1..].chars().any(|c| recursive_letters.contains(c)))
    })
}

fn root_target(target: &str) -> bool {
    if !target.starts_with('/') {
        return false;
    }
    let mut depth = 0usize;
    for part in target.split('/').skip(1) {
        match part {
            "" | "." => {}
            ".." => depth = depth.saturating_sub(1),
            _ => depth += 1,
        }
    }
    depth == 0
}

fn world_writable_mode(mode: &str) -> bool {
    for clause in mode.split(',') {
        let digits = clause.trim_start_matches('0');
        if clause.bytes().all(|b| b >= b'0' && b <= b'7')
            && !digits.is_empty()
            && (3..=4).contains(&digits.len())
        {
            if u32::from_str_radix(clause, 8).is_ok_and(|value| value & 2 == 2) {
                return true;
            }
            continue;
        }
        let Some(op) = clause.find(['+', '=']) else {
            continue;
        };
        let classes = &clause[..op];
        let operations = &clause[(op + 1)..];
        if classes
            .bytes()
            .all(|c| matches!(c, b'a' | b'u' | b'g' | b'o'))
            && operations.bytes().all(|c| matches!(c, b'r' | b'w' | b'x'))
            && (classes.is_empty() || classes == "a" || classes.contains('o'))
            && operations.contains('w')
        {
            return true;
        }
    }
    false
}

fn deletes_root(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, args| {
        head == "rm" && recursive_flag(args, "rR") && args.iter().any(|arg| root_target(arg))
    })
}

fn formats_device(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, _| {
        head.starts_with("mkfs")
            || head.starts_with("mkswap")
            || head.starts_with("wipefs")
            || head == "mke2fs"
    })
}

fn flushes_firewall(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, args| {
        if matches!(head, "iptables" | "ip6tables") {
            if args
                .iter()
                .any(|arg| matches!(arg.as_str(), "-F" | "--flush"))
            {
                return true;
            }
            if let Some(policy) = args.iter().position(|arg| arg == "-P") {
                return args[(policy + 1)..].iter().any(|arg| arg == "ACCEPT");
            }
        }
        head == "nft" && args.first().is_some_and(|arg| arg == "flush")
    })
}

fn world_writable_root(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, args| {
        head == "chmod"
            && recursive_flag(args, "R")
            && args.iter().any(|arg| arg.starts_with('/'))
            && args.iter().any(|arg| world_writable_mode(arg))
    })
}

fn chowns_root(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, args| {
        head == "chown" && recursive_flag(args, "R") && args.iter().any(|arg| root_target(arg))
    })
}

fn deletes_absolute_path(command: &str, windows: bool) -> bool {
    any_segment_runs(command, windows, |head, args| {
        head == "rm" && recursive_flag(args, "rR") && args.iter().any(|arg| arg.starts_with('/'))
    })
}

fn checks(command: &str, windows: bool) -> Vec<bool> {
    vec![
        invoked_words(command, windows).iter().any(|word| {
            matches!(
                word.as_str(),
                "shutdown" | "reboot" | "halt" | "poweroff" | "eval"
            )
        }),
        pipes_download_into_shell(command, windows),
        writes_to_device(command, windows),
        chowns_root(command, windows),
        deletes_root(command, windows),
        formats_device(command, windows),
        flushes_firewall(command, windows),
        world_writable_root(command, windows),
        deletes_absolute_path(command, windows),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    #[test]
    fn hard_denials_match_pinned_upstream_corpus() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, invokedWords, pipesDownloadIntoShell, writesToDevice, chownsRoot, deletesRoot, formatsDevice, flushesFirewall, worldWritableRoot, deletesAbsolutePath};",
        );
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        let oracle: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/upstream_classifier_oracle.json")).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            ctx.eval::<(), _>(r#"
                globalThis.__rules = (s, d) => JSON.stringify([
                    UpstreamSSH.invokedWords(s,d).some(w=>["shutdown","reboot","halt","poweroff","eval"].includes(w)),
                    UpstreamSSH.pipesDownloadIntoShell(s,d),
                    UpstreamSSH.writesToDevice(s,d),
                    UpstreamSSH.chownsRoot(s,d),
                    UpstreamSSH.deletesRoot(s,d),
                    UpstreamSSH.formatsDevice(s,d),
                    UpstreamSSH.flushesFirewall(s,d),
                    UpstreamSSH.worldWritableRoot(s,d),
                    UpstreamSSH.deletesAbsolutePath(s,d)
                ]);
            "#).unwrap();
            let js: rquickjs::Function = ctx.globals().get("__rules").unwrap();
            for command in oracle.keys() {
                for dialect in ["posix", "windows"] {
                    let expected_json: String = js.call((command.as_str(), dialect)).unwrap();
                    let expected: Vec<bool> = serde_json::from_str(&expected_json).unwrap();
                    let actual = checks(command, dialect == "windows");
                    assert_eq!(actual, expected, "{dialect} {command:?}");
                }
            }
        });
    }
}

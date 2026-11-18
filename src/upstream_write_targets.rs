//! Lexically exact remote write targets for the upstream hard-denial rules.
//! Staged behind cfg(test) while complete native classifier parity is established.

use crate::{
    upstream_heads::command_heads, upstream_paths::find_never_allowed_write_target,
    upstream_shell::tokenize_detailed,
};

fn control(c: char) -> bool {
    c.is_whitespace() || matches!(c, ';' | '&' | '|' | '<' | '>' | '(' | ')')
}

fn read_dequoted_word(chars: &[char], start: usize, windows: bool) -> String {
    if start >= chars.len() || control(chars[start]) {
        return String::new();
    }
    let mut quote = if matches!(chars[start], '"' | '\'') {
        Some(chars[start])
    } else {
        None
    };
    let mut word = String::new();
    let mut escaped = false;
    let mut i = start + usize::from(quote.is_some());
    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            word.push(ch);
            escaped = false;
            i += 1;
            continue;
        }
        if !windows && ch == '\\' {
            if quote == Some('\'') {
                word.push(ch);
                i += 1;
                continue;
            }
            if quote == Some('"') {
                let next = chars.get(i + 1).copied();
                if next.is_none()
                    || next.is_some_and(|c| matches!(c, '$' | '\u{60}' | '"' | '\\' | '\n'))
                {
                    escaped = true;
                    i += 1;
                    continue;
                }
                word.push(ch);
                i += 1;
                continue;
            }
            escaped = true;
            i += 1;
            continue;
        }
        if let Some(marker) = quote {
            if ch == marker {
                quote = None;
            } else {
                word.push(ch);
            }
            i += 1;
            continue;
        }
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            i += 1;
            continue;
        }
        if control(ch) {
            break;
        }
        word.push(ch);
        i += 1;
    }
    word
}

fn redirect_targets(command: &str, windows: bool) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut targets = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if !windows && ch == '\\' && quote != Some('\'') {
            escaped = true;
            i += 1;
            continue;
        }
        if let Some(marker) = quote {
            if ch == marker {
                quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            i += 1;
            continue;
        }
        if ch != '>' && !(ch == '&' && chars.get(i + 1) == Some(&'>')) {
            i += 1;
            continue;
        }
        let mut j = i + if ch == '&' { 2 } else { 1 };
        if chars.get(j) == Some(&'>') {
            j += 1;
        }
        if chars.get(j) == Some(&'&') {
            j += 1;
        }
        if chars.get(j) == Some(&'|') {
            j += 1;
        }
        while chars.get(j).is_some_and(|c| c.is_whitespace()) {
            j += 1;
        }
        let target = read_dequoted_word(&chars, j, windows);
        if !target.is_empty() {
            targets.push(target);
        }
        i = j;
    }
    targets
}

fn copy_positionals(args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if matches!(arg, "-t" | "--target-directory") {
            i += 2;
            continue;
        }
        if (arg.starts_with("-t") && arg.len() > 2) || arg.starts_with("--target-directory=") {
            i += 1;
            continue;
        }
        if matches!(arg, "-m" | "-o" | "-g" | "-S" | "-Z") {
            i += 2;
            continue;
        }
        if ["mode", "owner", "group", "suffix", "context", "sparse"]
            .iter()
            .any(|name| arg.starts_with(&format!("--{name}=")))
        {
            i += 1;
            continue;
        }
        if matches!(
            arg,
            "--mode" | "--owner" | "--group" | "--suffix" | "--context" | "--sparse"
        ) {
            i += 2;
            continue;
        }
        if !arg.starts_with('-') {
            positional.push(arg.to_owned());
        }
        i += 1;
    }
    positional
}

fn write_verb_targets(command: &str, windows: bool) -> Vec<String> {
    let mut targets = Vec::new();
    for segment in tokenize_detailed(command, true, windows) {
        for (index, head) in command_heads(&segment.words) {
            let args = &segment.words[(index + 1)..];
            match head.as_str() {
                "tee" => {
                    targets.extend(args.iter().filter(|arg| !arg.starts_with('-')).cloned());
                }
                "dd" => {
                    targets.extend(
                        args.iter()
                            .filter_map(|arg| arg.strip_prefix("of=").map(ToOwned::to_owned)),
                    );
                }
                "cp" | "mv" | "install" => {
                    let positional = copy_positionals(args);
                    if head == "install"
                        && args
                            .iter()
                            .any(|arg| matches!(arg.as_str(), "-d" | "--directory"))
                    {
                        targets.extend(positional);
                        continue;
                    }
                    let t_index = args.iter().position(|arg| {
                        let value = arg.as_str();
                        matches!(value, "-t" | "--target-directory")
                            || (value.starts_with("-t") && value.len() > 2)
                            || value.starts_with("--target-directory=")
                    });
                    let mut sources = &positional[..];
                    let destination = if let Some(t) = t_index {
                        let flag = args[t].as_str();
                        if matches!(flag, "-t" | "--target-directory") {
                            args.get(t + 1)
                                .filter(|value| !value.is_empty())
                                .map(String::as_str)
                        } else if let Some((_, value)) = flag.split_once('=') {
                            Some(value)
                        } else {
                            Some(&flag[2..])
                        }
                    } else if positional.len() >= 2 {
                        sources = &positional[..positional.len() - 1];
                        positional.last().map(String::as_str)
                    } else {
                        None
                    };
                    let Some(destination) = destination.filter(|value| !value.is_empty()) else {
                        continue;
                    };
                    targets.push(destination.to_owned());
                    for source in sources {
                        let basename = source.rsplit(['/', '\\']).next().unwrap_or(source);
                        if !basename.is_empty() {
                            targets.push(format!("{destination}/{basename}"));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    targets
}

fn never_allowed_family(command: &str, windows: bool) -> Option<&'static str> {
    redirect_targets(command, windows)
        .into_iter()
        .chain(write_verb_targets(command, windows))
        .find_map(|target| find_never_allowed_write_target(&target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    #[test]
    fn write_targets_match_pinned_upstream_corpus() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, redirectTargets, writeVerbTargets, findNeverAllowedWriteFamily};",
        );
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        let oracle: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/upstream_classifier_oracle.json")).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            ctx.eval::<(), _>(
                r#"
                globalThis.__writes = (s, d) => JSON.stringify([
                    UpstreamSSH.redirectTargets(s,d),
                    UpstreamSSH.writeVerbTargets(s,d),
                    UpstreamSSH.findNeverAllowedWriteFamily(s,d)
                ]);
            "#,
            )
            .unwrap();
            let js: rquickjs::Function = ctx.globals().get("__writes").unwrap();
            for command in oracle.keys() {
                for dialect in ["posix", "windows"] {
                    let expected_json: String = js.call((command.as_str(), dialect)).unwrap();
                    let expected: serde_json::Value = serde_json::from_str(&expected_json).unwrap();
                    let windows = dialect == "windows";
                    let actual = serde_json::json!([
                        redirect_targets(command, windows),
                        write_verb_targets(command, windows),
                        never_allowed_family(command, windows)
                    ]);
                    assert_eq!(actual, expected, "{dialect} {command:?}");
                }
            }
        });
    }
}

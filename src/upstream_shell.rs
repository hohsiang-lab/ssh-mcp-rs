//! Native tokenizer and glob reader from the pinned upstream shell classifier.
//! Test-only until the complete Rust classifier replaces QuickJS.

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Segment {
    words: Vec<String>,
    sep: String,
}

fn tokenize_detailed(command: &str, honor_quotes: bool, windows: bool) -> Vec<Segment> {
    let chars: Vec<char> = command.chars().collect();
    let mut segments: Vec<Segment> = Vec::new();
    let mut pending = String::new();
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut quoted = false;
    let end_word = |words: &mut Vec<String>, current: &mut String, quoted: &mut bool| {
        if !current.is_empty() || *quoted {
            words.push(std::mem::take(current));
        }
        current.clear();
        *quoted = false;
    };
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            current.push(ch);
            escaped = false;
            i += 1;
            continue;
        }
        if let Some(marker) = quote {
            if !windows && ch == '\\' && marker == '"' {
                let next = chars.get(i + 1).copied();
                if next.is_none()
                    || next.is_some_and(|c| matches!(c, '$' | '"' | '\\' | '\n' | '\u{60}'))
                {
                    escaped = true;
                    i += 1;
                    continue;
                }
                current.push(ch);
                i += 1;
                continue;
            }
            if ch == marker {
                quote = None;
            } else {
                current.push(ch);
            }
            i += 1;
            continue;
        }
        if !windows && ch == '\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if honor_quotes && matches!(ch, '\'' | '"') {
            quote = Some(ch);
            quoted = true;
            i += 1;
            continue;
        }
        if matches!(ch, ';' | '&' | '|' | '\n') {
            end_word(&mut words, &mut current, &mut quoted);
            if !words.is_empty() {
                segments.push(Segment {
                    words: std::mem::take(&mut words),
                    sep: std::mem::take(&mut pending),
                });
            }
            pending = ch.to_string();
            i += 1;
            continue;
        }
        if ch.is_whitespace() {
            end_word(&mut words, &mut current, &mut quoted);
        } else {
            current.push(ch);
        }
        i += 1;
    }
    end_word(&mut words, &mut current, &mut quoted);
    if !words.is_empty() {
        segments.push(Segment {
            words,
            sep: pending,
        });
    }
    if quote.is_some() && honor_quotes {
        tokenize_detailed(command, false, windows)
    } else {
        segments
    }
}

fn normalize_command(command: &str, windows: bool) -> String {
    tokenize_detailed(command, true, windows)
        .iter()
        .map(|segment| {
            segment
                .words
                .iter()
                .map(|word| {
                    if word
                        .chars()
                        .any(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|'))
                    {
                        "\0"
                    } else {
                        word.as_str()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn first_glob(command: &str, honor_quotes: bool, windows: bool) -> Option<String> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut word = String::new();
    let mut glob = false;
    for ch in command.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            continue;
        }
        if let Some(marker) = quote {
            if !windows && ch == '\\' && marker == '"' {
                escaped = true;
                continue;
            }
            if ch == marker {
                quote = None;
            } else {
                word.push(ch);
            }
            continue;
        }
        if !windows && ch == '\\' {
            escaped = true;
            continue;
        }
        if honor_quotes && matches!(ch, '\'' | '"') {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if glob {
                return Some(word);
            }
            word.clear();
            glob = false;
            continue;
        }
        if matches!(ch, '*' | '?' | '[') {
            glob = true;
        }
        word.push(ch);
    }
    if honor_quotes && quote.is_some() {
        return first_glob(command, false, windows);
    }
    glob.then_some(word)
}

/// Shell substitutions that always carry another shell command.
/// Arithmetic expansion is intentionally ignored, mirroring upstream.
fn shell_substitutions(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut found = Vec::new();
    let mut i = 0usize;
    while i + 1 < chars.len() {
        let c = chars[i];
        let substitution = c == '
    use super::*;
    use rquickjs::{Context, Runtime};

    #[test]
    fn nested_shell_substitutions_match_upstream() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, nestedCommands};",
        );
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            ctx.eval::<(), _>(
                "globalThis.__nested = (s, d) => JSON.stringify(UpstreamSSH.nestedCommands(s, false, d));",
            ).unwrap();
            let reference: rquickjs::Function = ctx.globals().get("__nested").unwrap();
            let commands = [
                "echo $(sudo id)", "echo $((1+1))", "echo $(echo $(sudo id))",
                "echo $(uname -a)", "echo <(ps aux)", "echo >(sudo tee /etc/x)",
                "printf \u{60}sudo id\u{60}", "echo \u{60}\u{60}",
                "echo $( )", "echo $(echo hi", "echo $(echo (id))",
                "echo '$(sudo id)'", "echo \"$(sudo id)\"",
                "echo \u{60}ls -l\u{60} \u{60}id\u{60}",
                "cat <(cat /etc/passwd)", "echo <(echo hello | wc -l)",
            ];
            for command in commands {
                for windows in [false, true] {
                    let dialect = if windows { "windows" } else { "posix" };
                    let expected_json: String =
                        reference.call((command, dialect)).unwrap();
                    let expected: Vec<String> =
                        serde_json::from_str(&expected_json).unwrap();
                    assert_eq!(shell_substitutions(command), expected, "{dialect} {command:?}");
                }
            }
        });
    }

    #[test]
    fn tokenizer_matches_upstream_js() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, tokenizeSegmentsDetailed, normalizeUncached, firstUnquotedGlobWord};",
        );
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            ctx.eval::<(), _>(
                "globalThis.__tokenize = (s, d) => JSON.stringify(UpstreamSSH.tokenizeSegmentsDetailed(s, true, d)); \
                globalThis.__norm = (s, d) => UpstreamSSH.normalizeUncached(s, d); \
                globalThis.__glob = (s, d) => UpstreamSSH.firstUnquotedGlobWord(s, true, d);",
            ).unwrap();
            let tokenize: rquickjs::Function = ctx.globals().get("__tokenize").unwrap();
            let norm: rquickjs::Function = ctx.globals().get("__norm").unwrap();
            let glob: rquickjs::Function = ctx.globals().get("__glob").unwrap();
            let fragments = [
                "", " ", ";", "&", "|", "\n", "\r", "\\", "'", "\"", "x",
                "/", "$", "\u{60}", "*", "?", "[", "abc", "sudo", "id", "a\\b",
            ];
            let mut count = 0;
            for a in fragments {
                for b in fragments {
                    for between in ["", " ", "\t", ";", "|", "\\", "'", "\""] {
                        let command = format!("echo {a}{between}{b} file");
                        for windows in [false, true] {
                            let dialect = if windows { "windows" } else { "posix" };
                            let result: String = tokenize.call((command.as_str(), dialect)).unwrap();
                            let expected: Vec<Segment> = serde_json::from_str(&result).unwrap();
                            assert_eq!(tokenize_detailed(&command, true, windows), expected, "tokens {dialect} {command:?}");
                            let expected: String = norm.call((command.as_str(), dialect)).unwrap();
                            assert_eq!(normalize_command(&command, windows), expected, "normalized {dialect} {command:?}");
                            let expected: Option<String> = glob.call((command.as_str(), dialect)).unwrap();
                            assert_eq!(first_glob(&command, true, windows), expected, "glob {dialect} {command:?}");
                            count += 1;
                        }
                    }
                }
            }
            assert_eq!(count, fragments.len() * fragments.len() * 8 * 2);
        });
    }
}
 && chars[i + 1] == '(';
        let process = matches!(c, '<' | '>') && chars[i + 1] == '(';
        if (!substitution && !process)
            || (substitution && chars.get(i + 2) == Some(&'('))
        {
            i += 1;
            continue;
        }
        let mut depth = 0;
        let mut closed = None;
        for j in (i + 1)..chars.len() {
            if chars[j] == '(' {
                depth += 1;
            } else if chars[j] == ')' {
                depth -= 1;
                if depth == 0 {
                    closed = Some(j);
                    break;
                }
            }
        }
        if let Some(end) = closed {
            found.push(chars[(i + 2)..end].iter().collect::<String>());
            i = end + 1;
        } else {
            i += 1;
        }
    }
    // The upstream backtick regex pairs delimiters without inspecting escapes.
    let mut opening = None;
    for (index, ch) in chars.iter().enumerate() {
        if *ch != '\u{60}' {
            continue;
        }
        if let Some(start) = opening.take() {
            found.push(chars[(start + 1)..index].iter().collect::<String>());
        } else {
            opening = Some(index);
        }
    }
    found.into_iter().filter(|text| !text.trim().is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    #[test]
    fn tokenizer_matches_upstream_js() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, tokenizeSegmentsDetailed, normalizeUncached, firstUnquotedGlobWord};",
        );
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            ctx.eval::<(), _>(
                "globalThis.__tokenize = (s, d) => JSON.stringify(UpstreamSSH.tokenizeSegmentsDetailed(s, true, d)); \
                globalThis.__norm = (s, d) => UpstreamSSH.normalizeUncached(s, d); \
                globalThis.__glob = (s, d) => UpstreamSSH.firstUnquotedGlobWord(s, true, d);",
            ).unwrap();
            let tokenize: rquickjs::Function = ctx.globals().get("__tokenize").unwrap();
            let norm: rquickjs::Function = ctx.globals().get("__norm").unwrap();
            let glob: rquickjs::Function = ctx.globals().get("__glob").unwrap();
            let fragments = [
                "", " ", ";", "&", "|", "\n", "\r", "\\", "'", "\"", "x",
                "/", "$", "\u{60}", "*", "?", "[", "abc", "sudo", "id", "a\\b",
            ];
            let mut count = 0;
            for a in fragments {
                for b in fragments {
                    for between in ["", " ", "\t", ";", "|", "\\", "'", "\""] {
                        let command = format!("echo {a}{between}{b} file");
                        for windows in [false, true] {
                            let dialect = if windows { "windows" } else { "posix" };
                            let result: String = tokenize.call((command.as_str(), dialect)).unwrap();
                            let expected: Vec<Segment> = serde_json::from_str(&result).unwrap();
                            assert_eq!(tokenize_detailed(&command, true, windows), expected, "tokens {dialect} {command:?}");
                            let expected: String = norm.call((command.as_str(), dialect)).unwrap();
                            assert_eq!(normalize_command(&command, windows), expected, "normalized {dialect} {command:?}");
                            let expected: Option<String> = glob.call((command.as_str(), dialect)).unwrap();
                            assert_eq!(first_glob(&command, true, windows), expected, "glob {dialect} {command:?}");
                            count += 1;
                        }
                    }
                }
            }
            assert_eq!(count, fragments.len() * fragments.len() * 8 * 2);
        });
    }
}

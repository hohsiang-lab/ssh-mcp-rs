//! Native tokenizer and glob reader from the pinned upstream shell classifier.
//! Used by the native Rust classifier; no script engine is required.

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Segment {
    pub(crate) words: Vec<String>,
    pub(crate) sep: String,
}

pub(crate) fn tokenize_detailed(command: &str, honor_quotes: bool, windows: bool) -> Vec<Segment> {
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

pub(crate) fn normalize_command(command: &str, windows: bool) -> String {
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

pub(crate) fn first_glob(command: &str, honor_quotes: bool, windows: bool) -> Option<String> {
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
pub(crate) fn shell_substitutions(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut found = Vec::new();
    let mut i = 0usize;
    while i + 1 < chars.len() {
        let c = chars[i];
        let substitution = c == '$' && chars[i + 1] == '(';
        let process = matches!(c, '<' | '>') && chars[i + 1] == '(';
        if (!substitution && !process) || (substitution && chars.get(i + 2) == Some(&'(')) {
            i += 1;
            continue;
        }
        let mut depth = 0i32;
        let mut closed = None;
        for (j, ch) in chars.iter().enumerate().skip(i + 1) {
            if *ch == '(' {
                depth += 1;
            } else if *ch == ')' {
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
    found
        .into_iter()
        .filter(|text| !text.trim().is_empty())
        .collect()
}

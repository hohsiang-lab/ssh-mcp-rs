//! Native reader argument grammar (upstream reader-grammar.ts).
//! Staged behind cfg(test) until the full classifier is ported and verified.

use regex::Regex;

#[derive(Clone, Copy)]
enum Mode {
    Any,
    Getopt,
    Exact,
}

#[derive(Clone, Copy)]
struct Operands<'a> {
    first: &'a [&'a str],
    each: Option<&'a str>,
    max: Option<i64>,
}

#[derive(Clone, Copy)]
struct Grammar<'a> {
    mode: Mode,
    flags: &'a [&'a str],
    value_flags: &'a [&'a str],
    optional_value_flags: &'a [&'a str],
    operands: Option<Operands<'a>>,
    options_before_operands: bool,
    numeric_short: bool,
}

fn contains(flags: &[&str], word: &str) -> bool {
    flags.contains(&word)
}

fn ambiguous(name: &str, g: &Grammar<'_>) -> bool {
    u8::from(contains(g.flags, name))
        + u8::from(contains(g.value_flags, name))
        + u8::from(contains(g.optional_value_flags, name))
        > 1
}

fn short_cluster(
    word: &str,
    words: &[&str],
    index: usize,
    g: &Grammar<'_>,
) -> Result<usize, String> {
    for (byte_offset, ch) in word.char_indices().skip(1) {
        let name = format!("-{ch}");
        if ambiguous(&name, g) {
            return Err(word.to_owned());
        }
        if contains(g.flags, &name) {
            continue;
        }
        if contains(g.value_flags, &name) {
            let after = byte_offset + ch.len_utf8();
            if after < word.len() {
                return Ok(index);
            }
            if index + 1 >= words.len() {
                return Err(name);
            }
            return Ok(index + 1);
        }
        if contains(g.optional_value_flags, &name) {
            return Ok(index);
        }
        return Err(word.to_owned());
    }
    Ok(index)
}

fn matches_operand_pattern(pattern: &str, operand: &str) -> bool {
    match pattern {
        // Actual pinned upstream grammars use these two expressions.
        // The negative lookahead is not supported by Rust's regex crate.
        r"^(?!\/[^/]*\/?$)" => {
            let matches_root_level = operand.strip_prefix('/').is_some_and(|rest| {
                !rest.contains('/')
                    || rest
                        .strip_suffix('/')
                        .is_some_and(|trimmed| !trimmed.contains('/'))
            });
            !matches_root_level
        }
        r"^\+" => operand.starts_with('+'),
        _ => Regex::new(pattern).is_ok_and(|regex| regex.is_match(operand)),
    }
}

fn check_operands(operands: &[&str], rules: Option<Operands<'_>>) -> Result<(), String> {
    let Some(rules) = rules else {
        return Ok(());
    };
    for (index, operand) in operands.iter().enumerate() {
        if index == 0 && !rules.first.is_empty() && !rules.first.contains(operand) {
            return Err((*operand).to_owned());
        }
        if rules
            .each
            .is_some_and(|pattern| !matches_operand_pattern(pattern, operand))
        {
            return Err((*operand).to_owned());
        }
    }
    if let Some(max) = rules.max {
        let limit = usize::try_from(max).unwrap_or(0);
        if operands.len() > limit {
            return Err(operands[limit].to_owned());
        }
    }
    Ok(())
}

/// Returns the first refused word, or Ok(()) when all arguments are provably data.
fn matches_grammar(words: &[&str], g: &Grammar<'_>) -> Result<(), String> {
    if matches!(g.mode, Mode::Any) {
        return Ok(());
    }
    let mut operands = Vec::new();
    let mut options_ended = false;
    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        let looks_like_option = !options_ended && word.len() > 1 && word.starts_with('-');
        if g.options_before_operands && !operands.is_empty() && looks_like_option {
            return Err(word.to_owned());
        }
        if matches!(g.mode, Mode::Getopt) && !options_ended && word == "--" {
            options_ended = true;
            i += 1;
            continue;
        }
        if !looks_like_option {
            operands.push(word);
            i += 1;
            continue;
        }
        if matches!(g.mode, Mode::Getopt)
            && g.numeric_short
            && word.len() > 1
            && word.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        {
            let short = &word[..2];
            if ambiguous(word, g) || ambiguous(short, g) {
                return Err(word.to_owned());
            }
            let claimed = [word, short].iter().any(|name| {
                contains(g.flags, name)
                    || contains(g.value_flags, name)
                    || contains(g.optional_value_flags, name)
            });
            if !claimed {
                i += 1;
                continue;
            }
        }
        if matches!(g.mode, Mode::Getopt) && !word.starts_with("--") {
            i = short_cluster(word, words, i, g)? + 1;
            continue;
        }
        let (name, has_equal) = if matches!(g.mode, Mode::Getopt) {
            word.split_once('=')
                .map_or((word, false), |(name, _)| (name, true))
        } else {
            (word, false)
        };
        if ambiguous(name, g) {
            return Err(word.to_owned());
        }
        if contains(g.value_flags, name) {
            if !has_equal {
                if i + 1 >= words.len() {
                    return Err(name.to_owned());
                }
                i += 1;
            }
        } else if contains(g.optional_value_flags, name) || (contains(g.flags, name) && !has_equal)
        {
            // No extra value is consumed by an optional-value or no-value flag.
        } else {
            return Err(word.to_owned());
        }
        i += 1;
    }
    check_operands(&operands, g.operands)
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReaderSpec {
    args: String,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    value_flags: Vec<String>,
    #[serde(default)]
    optional_value_flags: Vec<String>,
    #[serde(default)]
    options_before_operands: bool,
    #[serde(default)]
    numeric_short: bool,
    operands: Option<OwnedOperands>,
}

#[derive(Clone, serde::Deserialize)]
struct OwnedOperands {
    #[serde(default)]
    first: Vec<String>,
    each: Option<String>,
    max: Option<i64>,
}

fn readers() -> &'static std::collections::BTreeMap<String, ReaderSpec> {
    static READERS: std::sync::OnceLock<std::collections::BTreeMap<String, ReaderSpec>> =
        std::sync::OnceLock::new();
    READERS.get_or_init(|| {
        serde_json::from_str(include_str!("upstream_reader_data.json"))
            .expect("pinned reader grammar must be valid")
    })
}

pub(crate) fn is_any_reader(name: &str) -> bool {
    readers().get(name).is_some_and(|r| r.args == "any")
}

pub(crate) fn is_reader(name: &str) -> bool {
    readers().contains_key(name)
}

/// Native reading of a bundled, declarative upstream reader grammar.
pub(crate) fn classify_reader_args(name: &str, words: &[String]) -> Result<(), String> {
    let spec = readers().get(name).ok_or_else(|| name.to_owned())?;
    let flags: Vec<&str> = spec.flags.iter().map(String::as_str).collect();
    let value_flags: Vec<&str> = spec.value_flags.iter().map(String::as_str).collect();
    let optional_value_flags: Vec<&str> = spec
        .optional_value_flags
        .iter()
        .map(String::as_str)
        .collect();
    let first: Vec<&str> = spec.operands.as_ref().map_or(Vec::new(), |ops| {
        ops.first.iter().map(String::as_str).collect()
    });
    let operand_rules = spec.operands.as_ref().map(|ops| Operands {
        first: &first,
        each: ops.each.as_deref(),
        max: ops.max,
    });
    let grammar = Grammar {
        mode: match spec.args.as_str() {
            "getopt" => Mode::Getopt,
            "exact" => Mode::Exact,
            _ => Mode::Any,
        },
        flags: &flags,
        value_flags: &value_flags,
        optional_value_flags: &optional_value_flags,
        operands: operand_rules,
        options_before_operands: spec.options_before_operands,
        numeric_short: spec.numeric_short,
    };
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    matches_grammar(&refs, &grammar)
}

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

fn check_operands(operands: &[&str], rules: Option<Operands<'_>>) -> Result<(), String> {
    let Some(rules) = rules else {
        return Ok(());
    };
    let matcher = match rules.each {
        Some(pattern) => Some(
            Regex::new(pattern).map_err(|_| operands.first().copied().unwrap_or("").to_owned())?,
        ),
        None => None,
    };
    for (index, operand) in operands.iter().enumerate() {
        if index == 0 && !rules.first.is_empty() && !rules.first.contains(operand) {
            return Err((*operand).to_owned());
        }
        if matcher
            .as_ref()
            .is_some_and(|regex| !regex.is_match(operand))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reader_argument_cases_match_upstream() {
        let source = include_str!("upstream_classifier.js").replace(
            "return {classifyCommand, findForbiddenMatch};",
            "return {classifyCommand, findForbiddenMatch, matchesGrammar};",
        );
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            ctx.eval::<(), _>(source).unwrap();
            let upstream: rquickjs::Object = ctx.globals().get("UpstreamSSH").unwrap();
            let _: rquickjs::Function = upstream.get("matchesGrammar").unwrap();
            ctx.eval::<(), _>("globalThis.__matchGrammar = (w, g) => JSON.stringify(UpstreamSSH.matchesGrammar(JSON.parse(w), JSON.parse(g)));").unwrap();
            let reference: rquickjs::Function = ctx.globals().get("__matchGrammar").unwrap();
            let cases = [
                (vec![], Mode::Getopt),
                (vec!["file"], Mode::Getopt),
                (vec!["-r", "-n", "42", "file"], Mode::Getopt),
                (vec!["-rn42", "file"], Mode::Getopt),
                (vec!["--color=always", "file"], Mode::Getopt),
                (vec!["--color", "file"], Mode::Getopt),
                (vec!["--", "-x"], Mode::Getopt),
                (vec!["-20", "file"], Mode::Getopt),
                (vec!["-2x", "file"], Mode::Getopt),
                (vec!["file", "-r"], Mode::Getopt),
                (vec!["--", "-x"], Mode::Exact),
                (vec!["-r", "file"], Mode::Exact),
                (vec!["--color=always"], Mode::Exact),
                (vec!["anything", "-bad"], Mode::Any),
            ];
            for (words, mode) in cases {
                for before_operands in [false, true] {
                    for numeric_short in [false, true] {
                        let grammar = Grammar {
                            mode,
                            flags: &["-r", "-2", "--short"],
                            value_flags: &["-n", "--output"],
                            optional_value_flags: &["--color"],
                            operands: Some(Operands {
                                first: &[],
                                each: None,
                                max: Some(3),
                            }),
                            options_before_operands: before_operands,
                            numeric_short,
                        };
                        let js_grammar = json!({
                            "args": match mode { Mode::Any => "any", Mode::Getopt => "getopt", Mode::Exact => "exact" },
                            "flags": grammar.flags,
                            "valueFlags": grammar.value_flags,
                            "optionalValueFlags": grammar.optional_value_flags,
                            "optionsBeforeOperands": before_operands,
                            "numericShort": numeric_short,
                            "operands": {"max": 3}
                        });
                        let expected_json: String = reference.call((
                            serde_json::to_string(&words).unwrap(),
                            js_grammar.to_string(),
                        )).unwrap();
                        let expected: serde_json::Value = serde_json::from_str(&expected_json).unwrap();
                        let got = matches_grammar(&words, &grammar);
                        assert_eq!(got.is_ok(), expected["ok"].as_bool().unwrap(), "{words:?}");
                        if let Err(word) = got {
                            assert_eq!(word, expected["word"].as_str().unwrap(), "{words:?}");
                        }
                    }
                }
            }
        });
    }
}

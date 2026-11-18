//! Native port of the pinned upstream AWK invocation interpreter.
//! Staged as test-only until the entire shell classifier has Rust parity.

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AwkFindings {
    pub(crate) commands: Vec<String>,
    pub(crate) piped_into: Vec<String>,
    pub(crate) writes_file: bool,
    pub(crate) unreadable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Nl,
    Word,
    Num,
    Str,
    Regex,
    Punct,
}

#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    text: String,
}

impl Token {
    fn new(kind: Kind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }
    fn is(&self, kind: Kind, text: &str) -> bool {
        self.kind == kind && self.text == text
    }
}

const KEYWORDS: &[&str] = &[
    "print", "printf", "if", "while", "do", "for", "return", "delete", "else", "in", "BEGIN",
    "END", "function", "exit", "next",
];
const OPERATORS: &[&str] = &[
    "**=", "|&", "&&", "||", "==", "!=", "<=", ">=", ">>", "++", "--", "+=", "-=", "*=", "/=",
    "%=", "^=", "!~", "**",
];
const NONFILE: &[&str] = &[
    "/dev/stdout",
    "/dev/stderr",
    "/dev/null",
    "/dev/fd/1",
    "/dev/fd/2",
];

fn regex_can_start(previous: Option<&Token>) -> bool {
    match previous.map(|token| token.kind) {
        None => true,
        Some(Kind::Num | Kind::Str | Kind::Regex) => false,
        Some(Kind::Word) => previous.is_some_and(|token| KEYWORDS.contains(&token.text.as_str())),
        Some(Kind::Punct) => previous
            .is_some_and(|token| ![")", "]", "++", "--", "$"].contains(&token.text.as_str())),
        Some(Kind::Nl) => true,
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}
fn is_ident_part(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

fn read_escape(source: &[char], at: usize) -> (char, usize) {
    let first = source[at];
    if ('0'..='7').contains(&first) {
        let mut n = 1;
        while n < 3 && source.get(at + n).is_some_and(|c| ('0'..='7').contains(c)) {
            n += 1;
        }
        let value: String = source[at..at + n].iter().collect();
        let number = u32::from_str_radix(&value, 8).unwrap_or(0);
        return (char::from_u32(number).unwrap_or('\0'), n);
    }
    if first == 'x' && source.get(at + 1).is_some_and(char::is_ascii_hexdigit) {
        let mut n = 1;
        while n <= 2 && source.get(at + n).is_some_and(char::is_ascii_hexdigit) {
            n += 1;
        }
        let value: String = source[at + 1..at + n].iter().collect();
        let number = u32::from_str_radix(&value, 16).unwrap_or(0);
        return (char::from_u32(number).unwrap_or('\0'), n);
    }
    let decoded = match first {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '\\' => '\\',
        '"' => '"',
        '/' => '/',
        'a' => '\u{7}',
        'b' => '\u{8}',
        'f' => '\u{c}',
        'v' => '\u{b}',
        other => other,
    };
    (decoded, 1)
}

fn lex(source: &str) -> Option<Vec<Token>> {
    let s: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == '\n' {
            tokens.push(Token::new(Kind::Nl, ""));
            i += 1;
            continue;
        }
        if matches!(c, ' ' | '\t' | '\r') {
            i += 1;
            continue;
        }
        if c == '\\' && s.get(i + 1) == Some(&'\n') {
            i += 2;
            continue;
        }
        if c == '#' {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '"' {
            let mut value = String::new();
            i += 1;
            while i < s.len() && s[i] != '"' {
                if s[i] == '\\' {
                    if i + 1 >= s.len() {
                        return None;
                    }
                    let (decoded, consumed) = read_escape(&s, i + 1);
                    value.push(decoded);
                    i += 1 + consumed;
                    continue;
                }
                if s[i] == '\n' {
                    return None;
                }
                value.push(s[i]);
                i += 1;
            }
            if i >= s.len() {
                return None;
            }
            i += 1;
            tokens.push(Token::new(Kind::Str, value));
            continue;
        }
        if c == '/' && regex_can_start(tokens.last()) {
            i += 1;
            let mut in_bracket = false;
            while i < s.len() {
                let next = s[i];
                if next == '\\' {
                    i += 2;
                    continue;
                }
                if next == '\n' {
                    return None;
                }
                if next == '[' {
                    in_bracket = true;
                } else if next == ']' {
                    in_bracket = false;
                } else if next == '/' && !in_bracket {
                    break;
                }
                i += 1;
            }
            if i >= s.len() {
                return None;
            }
            i += 1;
            tokens.push(Token::new(Kind::Regex, ""));
            continue;
        }
        if c.is_ascii_digit() || (c == '.' && s.get(i + 1).is_some_and(char::is_ascii_digit)) {
            while i < s.len() {
                let number_char = s[i];
                let numeric = number_char.is_ascii_digit()
                    || matches!(number_char, '.' | 'e' | 'E' | 'x' | 'X')
                    || ('a'..='f').contains(&number_char)
                    || ('A'..='F').contains(&number_char)
                    || matches!(number_char, '+' | '-');
                if !numeric {
                    break;
                }
                if matches!(number_char, '+' | '-')
                    && !i
                        .checked_sub(1)
                        .and_then(|j| s.get(j))
                        .is_some_and(|c| matches!(c, 'e' | 'E'))
                {
                    break;
                }
                i += 1;
            }
            tokens.push(Token::new(Kind::Num, ""));
            continue;
        }
        if is_ident_start(c) {
            let start = i;
            while i < s.len() && is_ident_part(s[i]) {
                i += 1;
            }
            tokens.push(Token::new(
                Kind::Word,
                s[start..i].iter().collect::<String>(),
            ));
            continue;
        }
        let op = OPERATORS.iter().copied().find(|op| {
            op.chars()
                .zip(s[i..].iter().copied())
                .all(|(left, right)| left == right)
                && op.chars().count() <= s.len() - i
        });
        if let Some(op) = op {
            tokens.push(Token::new(Kind::Punct, op));
            i += op.chars().count();
        } else {
            tokens.push(Token::new(Kind::Punct, c.to_string()));
            i += 1;
        }
    }
    Some(tokens)
}

fn walk(tokens: &[Token]) -> AwkFindings {
    let mut result = AwkFindings::default();
    let mut depth = 0i32;
    let mut print_depth: Option<i32> = None;
    for (i, token) in tokens.iter().enumerate() {
        match token.kind {
            Kind::Punct => match token.text.as_str() {
                "(" | "[" => {
                    depth += 1;
                    continue;
                }
                ")" | "]" => {
                    depth -= 1;
                    if print_depth.is_some_and(|d| depth < d) {
                        print_depth = None;
                    }
                    continue;
                }
                "{" | "}" | ";" => {
                    print_depth = None;
                    continue;
                }
                "@" => {
                    result.unreadable = true;
                    continue;
                }
                ">" | ">>" if print_depth == Some(depth) => {
                    if !tokens
                        .get(i + 1)
                        .is_some_and(|t| t.kind == Kind::Str && NONFILE.contains(&t.text.as_str()))
                    {
                        result.writes_file = true;
                    }
                    print_depth = None;
                    continue;
                }
                "|" | "|&" if print_depth == Some(depth) => {
                    let target = tokens.get(i + 1);
                    let after = tokens.get(i + 2);
                    if let Some(value) = target.filter(|t| t.kind == Kind::Str).filter(|_| {
                        !after.is_some_and(|t| matches!(t.kind, Kind::Str | Kind::Word))
                    }) {
                        result.piped_into.push(value.text.clone());
                    } else {
                        result.unreadable = true;
                    }
                    print_depth = None;
                    continue;
                }
                "|" | "|&" => {
                    if tokens
                        .get(i + 1)
                        .is_some_and(|t| t.is(Kind::Word, "getline"))
                    {
                        let before = i.checked_sub(1).and_then(|j| tokens.get(j));
                        let earlier = i.checked_sub(2).and_then(|j| tokens.get(j));
                        if let Some(value) = before.filter(|t| t.kind == Kind::Str).filter(|_| {
                            !earlier.is_some_and(|t| matches!(t.kind, Kind::Str | Kind::Word))
                        }) {
                            result.commands.push(value.text.clone());
                        } else {
                            result.unreadable = true;
                        }
                    }
                    continue;
                }
                _ => continue,
            },
            Kind::Nl => {
                print_depth = None;
            }
            Kind::Word if token.text == "print" || token.text == "printf" => {
                print_depth = Some(depth);
            }
            Kind::Word if token.text == "system" => {
                if !tokens.get(i + 1).is_some_and(|t| t.is(Kind::Punct, "(")) {
                    continue;
                }
                match (tokens.get(i + 2), tokens.get(i + 3)) {
                    (Some(arg), Some(close))
                        if arg.kind == Kind::Str && close.is(Kind::Punct, ")") =>
                    {
                        result.commands.push(arg.text.clone());
                    }
                    _ => result.unreadable = true,
                }
            }
            _ => {}
        }
    }
    result
}

pub(crate) fn read_awk_invocation(args: &[&str]) -> Option<AwkFindings> {
    let mut i = 0usize;
    while i < args.len() {
        let word = args[i];
        if word == "--" {
            i += 1;
            break;
        }
        if word == "-" || !word.starts_with('-') {
            break;
        }
        if matches!(word, "--version" | "--help") {
            i += 1;
            continue;
        }
        let flag = word.get(..2).unwrap_or("");
        if matches!(flag, "-F" | "-v" | "-f") {
            if flag == "-f" {
                return Some(AwkFindings {
                    unreadable: true,
                    ..Default::default()
                });
            }
            i += if word.len() == 2 { 2 } else { 1 };
            continue;
        }
        return Some(AwkFindings {
            unreadable: true,
            ..Default::default()
        });
    }
    let program = args.get(i)?;
    if program.encode_utf16().count() > 256 * 1024 {
        return Some(AwkFindings {
            unreadable: true,
            ..Default::default()
        });
    }
    let tokens = lex(program);
    Some(match tokens {
        Some(tokens) => walk(&tokens),
        None => AwkFindings {
            unreadable: true,
            ..Default::default()
        },
    })
}

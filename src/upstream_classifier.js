/*
 * Vendored tufantunc/ssh-mcp classifier, commit e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f.
 * Original authors, MIT License (see licenses/ssh-mcp-upstream-LICENSE).
 * Generated from upstream TypeScript build; do not edit manually.
 */
var UpstreamSSH = (function() {
// --- upstream remote-path.ts ---
/**
 * A remote path as a `[policy].denylist` pattern should also see it (#230).
 *
 * Lexical only: nothing is asked of the target, so a relative path stays relative and a
 * symlink is not followed. What it removes is the spelling that keeps a rule from seeing
 * a path it was written for — `//`, `/./`, `..`, a trailing separator — and it reads `\`
 * as a separator too, so a Windows target's `C:\Users\a\.ssh\authorized_keys` is also
 * seen as `C:/Users/a/.ssh/authorized_keys`. On a POSIX target a filename containing `\`
 * can then match where it did not before; that only ever widens a refusal.
 *
 * An absolute path — `/…`, or one starting with a drive letter — cannot climb above its
 * root. A relative path keeps a leading `..` it has nothing to resolve against.
 *
 * Not `node:path`: `posix.normalize` lets `..` climb above a drive root (`C:/../x` →
 * `x`) and keeps a trailing separator, and `win32.normalize` answers in backslashes —
 * while a deny rule needs one reading, in forward slashes, that never climbs.
 */
const DRIVE_LETTER = /^[A-Za-z]:$/;
function normalizeRemotePath(path) {
    const segments = path.replace(/\\/g, '/').split('/');
    let root = null;
    if (segments[0] === '') {
        root = '';
        segments.shift();
    }
    else if (DRIVE_LETTER.test(segments[0])) {
        root = segments.shift();
    }
    const kept = [];
    for (const segment of segments) {
        if (segment === '' || segment === '.')
            continue;
        if (segment === '..') {
            if (kept.length > 0 && kept[kept.length - 1] !== '..')
                kept.pop();
            else if (root === null)
                kept.push('..');
            continue;
        }
        kept.push(segment);
    }
    if (root === null)
        return kept.length > 0 ? kept.join('/') : '.';
    if (root === '')
        return kept.length > 0 ? `/${kept.join('/')}` : '/';
    return kept.length > 0 ? `${root}/${kept.join('/')}` : `${root}/`;
}
/**
 * The same path as Win32 would resolve it, for a denylist that must not depend on how
 * the caller spelled the file (#230).
 *
 * Every transformation here was measured over SFTP on the Windows test VM (Windows 11
 * build 26200): the spellings below reached the same file as the canonical one, so a
 * rule that caught one spelling and not the other was a bypass, not a distinction.
 *
 * - `\` is read as `/`, as above.
 * - A trailing run of dots and spaces is dropped from every segment (`authorized_keys.`
 *   and `authorized_keys..` are the same file). A segment that is nothing but dots
 *   (`a.../b`) therefore disappears, the way Win32 reads it.
 * - A `::` suffix is cut (`authorized_keys::$DATA` is the file's default stream, not a
 *   different file). A single `:` is left alone: that names a different stream, and the
 *   measurement showed it does not reach the same bytes.
 * - A drive-relative spelling (`C:x/…`, resolved against the drive's current directory
 *   on Windows) is rooted at the drive. Where it actually resolves depends on process
 *   state this server cannot see; rooting is the fail-closed reading.
 * - `\\?\` and `\\.\` device prefixes are dropped. SFTP itself rejects them, but a rule
 *   should not have to know that.
 * - A UNC spelling keeps its root (`\\server\share\…` → `//server/share/…`), which the
 *   plain reading collapses; `..` cannot climb above the share.
 *
 * Case is deliberately untouched — the engine tests this reading case-insensitively,
 * which also covers a case-variant spelling of an otherwise identical path.
 *
 * Two Windows equivalences remain outside any lexical reading, because resolving them
 * needs the target's own directory state, and are documented residuals in the README:
 * 8.3 short names (`AUTHOR~1`), and symlinks.
 *
 * On a POSIX target these readings can only widen a refusal: a file genuinely named
 * `authorized_keys.` is a different file there, but refusing it is the safe direction,
 * exactly as with `\` above.
 */
function normalizeRemotePathForWindows(path) {
    let slashed = path.replace(/\\/g, '/');
    if (slashed.startsWith('//?/') || slashed.startsWith('//./'))
        slashed = slashed.slice(4);
    const segments = slashed.split('/');
    let root = null;
    let rest = segments;
    if (segments[0] === '' && segments[1] === '') {
        // A UNC root: the share is as high as `..` may climb.
        root = `//${segments[2] ?? ''}/${segments[3] ?? ''}`;
        rest = segments.slice(4);
    }
    else if (segments[0] === '') {
        root = '/';
        rest = segments.slice(1);
    }
    else if (/^[A-Za-z]:/.test(segments[0])) {
        const drive = segments[0].slice(0, 2);
        const after = segments[0].slice(2);
        root = drive;
        rest = after === '' ? segments.slice(1) : [after, ...segments.slice(1)];
    }
    const kept = [];
    for (const segment of rest) {
        if (segment === '' || segment === '.')
            continue;
        if (segment === '..') {
            if (kept.length > 0 && kept[kept.length - 1] !== '..')
                kept.pop();
            else if (root === null)
                kept.push('..');
            continue;
        }
        const plain = segment.split('::')[0].replace(/[ .]+$/, '');
        if (plain === '')
            continue;
        kept.push(plain);
    }
    if (root === null)
        return kept.length > 0 ? kept.join('/') : '.';
    if (root === '/')
        return kept.length > 0 ? `/${kept.join('/')}` : '/';
    return kept.length > 0 ? `${root}/${kept.join('/')}` : `${root}/`;
}
// --- upstream never-allowed-writes.ts ---
/**
 * The `/etc` families are prefix matches with no boundary: `/etc/crontab` sits under
 * `/etc/cron` the same way `/etc/cron.d/x` does, which is how the redirect regex this
 * module replaces always read it. A sibling that merely starts like the directory
 * (`/etc/cronography`) fires too — over-refusal in the fail-closed direction this
 * engine takes everywhere else.
 */
const NEVER_DIRS = ['/etc/cron', '/etc/systemd'];
/** The keys family: any path whose last two segments are `.ssh/authorized_keys`. */
const KEYS_TAIL = '/.ssh/authorized_keys';
/**
 * The refusal wording for a family, defined once because two check sites quote it:
 * the classifier's ForbiddenRule label and the engine's built-in deny reason.
 */
function neverAllowedWriteLabel(target) {
    switch (target) {
        case '/etc/cron': return 'writing to /etc/cron';
        case '/etc/systemd': return 'writing to /etc/systemd';
        case 'authorized_keys': return "writing to any user's authorized_keys";
    }
}
function familyOf(path) {
    for (const dir of NEVER_DIRS) {
        if (path.startsWith(dir))
            return dir;
    }
    if (path.endsWith(KEYS_TAIL) || path === KEYS_TAIL.slice(1))
        return 'authorized_keys';
    return null;
}
/**
 * Whether `path` names one of the never-allowed write targets, in any spelling the
 * path readings resolve.
 *
 * The same three readings `[policy].denylist` sees (#230): the path as given; a
 * lexically normalized reading (`//`, `/./`, `..`, trailing separators, `\` as a
 * separator); and the Windows reading of it, case-insensitively — so `Authorized_Keys.`,
 * `authorized_keys::$DATA` and backslash spellings reach the same refusal. On a POSIX
 * target some of those are different files; refusing them is the safe direction, the
 * same trade the operator denylist already makes.
 *
 * What this does not do is resolve anything on the target: a relative path stays
 * relative, symlinks are not followed, and an 8.3 short name is not expanded (#230's
 * documented residuals, inherited here).
 */
function findNeverAllowedWriteTarget(path) {
    return familyOf(path)
        ?? familyOf(normalizeRemotePath(path))
        ?? familyOf(normalizeRemotePathForWindows(path).toLowerCase());
}
// --- upstream awk.ts ---
/**
 * Reading an awk program well enough to classify what it does (#184).
 *
 * awk is the one interpreter this codebase could not fit into the `INTERPRETERS`
 * table, and two review rounds produced five attempts that were each holed by
 * the next. The two reasons are structural, and neither is fixed by adding a
 * flag to a table:
 *
 * 1. **The program is a positional operand, not a flag's value.** For `sh -c` or
 *    `python3 -c` the flag is the evidence that the interpreter was *invoked*;
 *    awk has none, so nothing in the argument list separates running awk from
 *    naming it. Keying on any word that says "awk" made `readlink -f /usr/bin/awk`
 *    and `man awk` destructive. The answer is to key on the segment's *command
 *    word* — which is what the caller does before reaching this module.
 * 2. **The four implementations disagree about which flags consume a value.**
 *    gawk consumes for `-i` and `-W`; mawk consumes for `-W` and rejects `-i`;
 *    busybox consumes for `-W`; and BWK awk — `awk` on macOS, the BSDs and
 *    Debian's `original-awk` — ignores an unknown option *without* consuming it
 *    and runs the next operand as the program. A table that skips a word awk did
 *    not skip hands this module the data file instead of the program. So only
 *    the three flags all four agree consume a value are skipped — plus the two
 *    that run no program at all — and any other flag makes the program's
 *    position unknowable, which is reported as `unreadable`.
 *
 * The rest is a small lexer. It exists because the escapes cannot be found with
 * a regex: `awk 'NR>1'` and `awk '{print $1 > $2}'` differ only in whether the
 * `>` follows an output statement, which is exactly awk's own rule and is why
 * `print (a>b)` needs its parentheses. Three of the five earlier holes were in a
 * regex trying to approximate that, and a fourth was the quadratic backtracking
 * that approximation needed.
 *
 * Single pass, no backtracking: a 211KB program of repeated `print` tokens is
 * the seed that caught the quadratic, and it is in the tests.
 */
/** Command words that run an awk program. `busybox awk` arrives here as `awk`. */
const AWK_NAMES = new Set(['awk', 'gawk', 'mawk', 'nawk']);
/**
 * The only flags all four implementations agree consume a following word.
 *
 * `-f` is here to be *recognised*, not to be followed: its value is a program
 * file this process cannot read, so seeing it ends the read as `unreadable`.
 */
const VALUE_FLAGS = new Set(['-F', '-v', '-f']);
/**
 * The size past which a program is refused rather than read.
 *
 * Chosen to sit above the 211KB regression seed that documents the quadratic
 * this module replaced — that shape still has to be lexed for the cost test to
 * mean anything — and far below the sizes where a linear pass is nonetheless a
 * stall: a 1MB program of `system()` calls measured 2.1s on the one thread that
 * serves every tool call. No awk one-liner comes near either number.
 */
const MAX_PROGRAM_CHARS = 256 * 1024;
/** Flags that take no value and run no program, so `awk --version` stays quiet. */
const INFO_FLAGS = new Set(['--version', '--help']);
/**
 * Redirection targets that are not a file write.
 *
 * `print > "/dev/stderr"` is an ordinary idiom for separating diagnostics from
 * output, and gating it would put a prompt on scripts that write nothing.
 */
const NON_FILE_TARGETS = new Set(['/dev/stdout', '/dev/stderr', '/dev/null', '/dev/fd/1', '/dev/fd/2']);
/** Fresh object rather than a shared constant: the arrays are ones a caller could push to. */
const unreadable = () => ({ commands: [], pipedInto: [], writesFile: false, unreadable: true });
/** Operators that are two or three characters, longest first so `>>` beats `>`. */
const OPERATORS = [
    // No `>>=`: awk has no shift operators at all — gawk exposes shifts as the
    // `lshift()`/`rshift()` functions, so there is nothing to assign through.
    // Verified on BWK awk 20200816: `x>>=1` is a syntax error. `**=` is genuine.
    '**=',
    '|&', '&&', '||', '==', '!=', '<=', '>=', '>>', '++', '--',
    '+=', '-=', '*=', '/=', '%=', '^=', '!~', '**',
];
/**
 * Operators grouped by first character, so a punctuation token costs one lookup.
 *
 * The scan used to slice two fresh strings per punctuation character and run two
 * `Array.find`s over the whole table. Measured, that made punctuation the
 * lexer's most expensive input by 8x over identifiers and 81x over whitespace —
 * and `?:,~$` is both the cheapest program to write and the one that matched
 * nothing, so it took the slowest path on every character.
 */
const OPERATORS_BY_FIRST = new Map();
for (const op of OPERATORS) {
    const bucket = OPERATORS_BY_FIRST.get(op[0]);
    if (bucket)
        bucket.push(op);
    else
        OPERATORS_BY_FIRST.set(op[0], [op]);
}
/**
 * Words after which no operand has ended, so a following `/` opens a regex.
 *
 * Reserved words only. An earlier version listed `and`, `or`, `not`, `case`,
 * `func`, `getline` and the built-in function names, and every one of those was
 * a hole: none is reserved in POSIX awk, BWK awk, mawk or busybox awk, so
 * `BEGIN{not=2; x = not / system("sudo id") / 3}` is a *division* that real awk
 * evaluates — measured on BWK awk 20200816, `not` is an ordinary variable and
 * the program prints 0.666667 after running the command. Treating the `/` as a
 * regex open swallowed the `system()` call as pattern text and the program
 * classified `safe`.
 *
 * `getline` is out for the mirror reason: it yields a value, so an operand
 * *has* ended and `getline / 2` divides.
 *
 * The failure directions are not symmetric, which is why this list is short.
 * Lexing a regex as division reads the region as code and can only over-report;
 * lexing code as a regex hides whatever is inside it. When in doubt, leave the
 * word out.
 */
const AWK_KEYWORDS = new Set([
    'print', 'printf', 'if', 'while', 'do', 'for', 'return', 'delete',
    'else', 'in', 'BEGIN', 'END', 'function', 'exit', 'next',
]);
/**
 * Whether a `/` here starts a regex rather than division.
 *
 * awk's own rule, and the same one every JavaScript lexer needs: a `/` after
 * something that can end an operand divides; anywhere else it opens a regex.
 * Getting this wrong matters in both directions — `awk '/a>b/{print}'` hides a
 * `>` inside a regex, and `awk '{print a/b}'` must not swallow the rest of the
 * program as one.
 */
function regexCanStart(previous) {
    if (previous === undefined)
        return true;
    if (previous.k === 'num' || previous.k === 'str' || previous.k === 'regex')
        return false;
    if (previous.k === 'word')
        return AWK_KEYWORDS.has(previous.v);
    if (previous.k === 'punct')
        return ![')', ']', '++', '--', '$'].includes(previous.v);
    return true;
}
const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z_0-9]/;
const DIGIT = /[0-9]/;
const SIMPLE_ESCAPES = {
    n: '\n'.slice(0), t: '\t', r: '\r',
    '\\': '\\', '"': '"', '/': '/',
    a: '\x07', b: '\b', f: '\f', v: '\v',
};
const OCTAL = /[0-7]/;
const HEX = /[0-9a-fA-F]/;
/**
 * Decode one escape sequence, returning its value and how many source
 * characters it consumed (not counting the backslash).
 *
 * `\ddd` and `\xhh` are the reason this is not a single-character switch. Every
 * awk decodes them, and they change the bytes that reach the shell: measured on
 * BWK awk 20200816, `awk 'BEGIN{system("\\145cho OCTAL_RAN")}'` runs `echo`
 * and `print "\\163udo"` prints `sudo`. Reading them literally meant the string
 * pushed into `commands` was not the command that runs, so `system("\\163udo id")`
 * classified `safe` — and the same spelling slipped past the never-allowed list,
 * which tests the raw text.
 *
 * `\xhh` is gawk's, and BWK awk decodes it too; mawk does not. Decoding it is
 * the over-reporting direction on the implementations that do not, which is the
 * one to fail in.
 *
 * Anything else is the character itself, which is what every implementation
 * does with an unknown escape. That keeps `FS="\\."` — an extremely common
 * idiom — from being read as something this module cannot model.
 */
function readEscape(source, at) {
    const c = source[at];
    if (OCTAL.test(c)) {
        let digits = c;
        while (digits.length < 3 && OCTAL.test(source[at + digits.length] ?? '')) {
            digits += source[at + digits.length];
        }
        return { value: String.fromCharCode(parseInt(digits, 8)), consumed: digits.length };
    }
    if (c === 'x' && HEX.test(source[at + 1] ?? '')) {
        let digits = '';
        while (digits.length < 2 && HEX.test(source[at + 1 + digits.length] ?? '')) {
            digits += source[at + 1 + digits.length];
        }
        return { value: String.fromCharCode(parseInt(digits, 16)), consumed: digits.length + 1 };
    }
    return { value: SIMPLE_ESCAPES[c] ?? c, consumed: 1 };
}
/**
 * Tokenize an awk program, or return null when it cannot be read.
 *
 * An unterminated string or regex returns null rather than a best guess: the
 * remainder of the program would be lexed in the wrong mode, and a wrong mode is
 * how a `system()` call hides. Failing closed there is the whole point.
 */
function lex(source) {
    const tokens = [];
    let i = 0;
    const n = source.length;
    while (i < n) {
        const c = source[i];
        if (c === '\n') {
            tokens.push({ k: 'nl' });
            i++;
            continue;
        }
        if (c === ' ' || c === '\t' || c === '\r') {
            i++;
            continue;
        }
        // A backslash-newline is a continuation: it joins the lines rather than
        // terminating the statement, so no `nl` token is emitted.
        if (c === '\\' && source[i + 1] === '\n') {
            i += 2;
            continue;
        }
        if (c === '#') {
            while (i < n && source[i] !== '\n')
                i++;
            continue;
        }
        if (c === '"') {
            let value = '';
            i++;
            while (i < n && source[i] !== '"') {
                if (source[i] === '\\') {
                    if (i + 1 >= n)
                        return null;
                    const escape = readEscape(source, i + 1);
                    value += escape.value;
                    i += 1 + escape.consumed;
                    continue;
                }
                // A bare newline inside a string is not legal awk, and treating it as
                // one would let the rest of the program be read as string content.
                if (source[i] === '\n')
                    return null;
                value += source[i];
                i++;
            }
            if (i >= n)
                return null;
            i++;
            tokens.push({ k: 'str', v: value });
            continue;
        }
        if (c === '/' && regexCanStart(tokens[tokens.length - 1])) {
            i++;
            let inBracket = false;
            while (i < n) {
                const r = source[i];
                if (r === '\\') {
                    i += 2;
                    continue;
                }
                if (r === '\n')
                    return null;
                // A `/` inside a bracket expression is literal — `/[/]/` is a valid
                // regex matching a slash, and ending the token there would leave the
                // rest of the program lexed as code that is really pattern text.
                if (r === '[')
                    inBracket = true;
                else if (r === ']')
                    inBracket = false;
                else if (r === '/' && !inBracket)
                    break;
                i++;
            }
            if (i >= n)
                return null;
            i++;
            tokens.push({ k: 'regex' });
            continue;
        }
        if (DIGIT.test(c) || (c === '.' && DIGIT.test(source[i + 1] ?? ''))) {
            while (i < n && /[0-9.eExXa-fA-F+-]/.test(source[i])) {
                // `1e+5` continues, but `1+5` is two tokens and an operator.
                if ((source[i] === '+' || source[i] === '-') && !/[eE]/.test(source[i - 1] ?? ''))
                    break;
                i++;
            }
            tokens.push({ k: 'num' });
            continue;
        }
        if (IDENT_START.test(c)) {
            const start = i;
            while (i < n && IDENT_PART.test(source[i]))
                i++;
            tokens.push({ k: 'word', v: source.slice(start, i) });
            continue;
        }
        const candidates = OPERATORS_BY_FIRST.get(c);
        const op = candidates?.find((o) => source.startsWith(o, i));
        if (op !== undefined) {
            tokens.push({ k: 'punct', v: op });
            i += op.length;
            continue;
        }
        tokens.push({ k: 'punct', v: c });
        i++;
    }
    return tokens;
}
/**
 * Walk the tokens and record what the program does.
 *
 * The output-statement state is the whole reason this is a parser rather than a
 * scan: `>` is a redirection only while an unparenthesised `print`/`printf`
 * argument list is open, which is why `awk 'NR>1'` compares and
 * `awk '{print $1 > $2}'` writes.
 */
function walk(tokens) {
    const commands = [];
    const pipedInto = [];
    let writesFile = false;
    let unreadable = false;
    let depth = 0;
    /** Paren depth at which an output statement is open; -1 when none is. */
    let printDepth = -1;
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        if (t.k === 'punct') {
            if (t.v === '(' || t.v === '[') {
                depth++;
                continue;
            }
            if (t.v === ')' || t.v === ']') {
                depth--;
                if (printDepth >= 0 && depth < printDepth)
                    printDepth = -1;
                continue;
            }
            // A statement boundary closes any open output statement.
            if (t.v === '{' || t.v === '}' || t.v === ';') {
                printDepth = -1;
                continue;
            }
            // gawk's indirect call (`f="system"; @f("sudo id")`) and its `@load` /
            // `@include` directives. What `@` reaches is chosen at run time or lives
            // in another file, so neither is readable from here.
            if (t.v === '@') {
                unreadable = true;
                continue;
            }
            if (printDepth >= 0 && depth === printDepth) {
                if (t.v === '>' || t.v === '>>') {
                    const target = tokens[i + 1];
                    // A literal target can be recognised as a terminal; anything computed
                    // is a file write whose name is not known here, which is still a file
                    // write.
                    if (!(target?.k === 'str' && NON_FILE_TARGETS.has(target.v)))
                        writesFile = true;
                    printDepth = -1;
                    continue;
                }
                if (t.v === '|' || t.v === '|&') {
                    // A single literal, with nothing concatenated onto it. awk joins
                    // adjacent strings into the command it runs, so reading only the first
                    // classified a *shorter* command than the one that executes — the one
                    // shape in this module that could lower a class rather than raise it.
                    // Measured: `print "x" | "id" "; sudo sh"` came out `safe`.
                    const target = tokens[i + 1];
                    const after = tokens[i + 2];
                    if (target?.k === 'str' && after?.k !== 'str' && after?.k !== 'word') {
                        pipedInto.push(target.v);
                    }
                    else {
                        unreadable = true;
                    }
                    printDepth = -1;
                    continue;
                }
            }
            // `"cmd" | getline` runs a command outside any output statement, so it is
            // read here rather than in the block above.
            if (t.v === '|' || t.v === '|&') {
                const after = tokens[i + 1];
                if (after?.k === 'word' && after.v === 'getline') {
                    const before = tokens[i - 1];
                    const earlier = tokens[i - 2];
                    // Same single-literal rule as the print pipe above: `"sudo" " id" |
                    // getline` runs `sudo id`, and reading only the last literal classified
                    // ` id`.
                    if (before?.k === 'str' && earlier?.k !== 'str' && earlier?.k !== 'word') {
                        commands.push(before.v);
                    }
                    else {
                        unreadable = true;
                    }
                }
            }
            continue;
        }
        if (t.k === 'nl') {
            printDepth = -1;
            continue;
        }
        if (t.k === 'word') {
            if (t.v === 'print' || t.v === 'printf') {
                printDepth = depth;
                continue;
            }
            if (t.v === 'system') {
                const open = tokens[i + 1];
                if (open?.k !== 'punct' || open.v !== '(')
                    continue;
                const arg = tokens[i + 2];
                const close = tokens[i + 3];
                // Only a single string literal is readable. `system("rm " f)` is a real
                // shell command whose text is assembled at run time, and guessing at it
                // would be worse than saying it cannot be read.
                if (arg?.k === 'str' && close?.k === 'punct' && close.v === ')')
                    commands.push(arg.v);
                else
                    unreadable = true;
                continue;
            }
        }
    }
    return { commands, pipedInto, writesFile, unreadable };
}
/**
 * Read an awk invocation's arguments and report what its program does.
 *
 * `args` are the words after the command word, already unquoted by the caller's
 * tokenizer. Returns null when the invocation runs no program at all — `awk`
 * alone, or `awk --version` — which is not the same as finding nothing
 * dangerous in one.
 */
function readAwkInvocation(args) {
    let i = 0;
    while (i < args.length) {
        const word = args[i];
        if (word === '--') {
            i++;
            break;
        }
        // A bare `-` is stdin as a data file, not a flag.
        if (word === '-' || !word.startsWith('-'))
            break;
        if (INFO_FLAGS.has(word)) {
            i++;
            continue;
        }
        const flag = word.slice(0, 2);
        if (VALUE_FLAGS.has(flag)) {
            // `-f prog.awk` puts the program in a file this process cannot read, and
            // `-f-` reads it from stdin, which is no more readable.
            if (flag === '-f')
                return unreadable();
            // Separate value (`-F ':'`) consumes the next word; attached (`-F:`) does not.
            i += word.length === 2 ? 2 : 1;
            continue;
        }
        // Every other flag: see the module comment. The implementations disagree
        // about whether it consumes the next word, so which operand is the program
        // is no longer knowable, and guessing is what opened two of the five holes.
        return unreadable();
    }
    const program = args[i];
    if (program === undefined)
        return null;
    // Bounded before lexing. The per-call cost is linear, but linear over an
    // unbounded input is still a stall on the one thread that serves every tool
    // call: with `commandMaxChars = 0` — the config spelling of unlimited — a 1MB
    // program of `system()` calls measured 2.1s. The default cap of 5000 chars
    // keeps this unreachable; an operator who lifted it gets a prompt instead of a
    // pause, which is the answer this module already gives for "we cannot read it".
    if (program.length > MAX_PROGRAM_CHARS)
        return unreadable();
    const tokens = lex(program);
    if (tokens === null)
        return unreadable();
    return walk(tokens);
}
// --- upstream reader-grammar.ts ---
/**
 * Deciding whether a reader's arguments are provably data, not more commands.
 *
 * `READERS` in the classifier grants `read-only` to any command whose first
 * word is allowlisted, without looking at the words after it. That is safe
 * only because a later stage rejects shell metacharacters, but `cat -- "$x"`
 * and `cat $(id)` both clear that gate today; only the outer shell-control
 * scan (or the caller's own audit) stands between an allowlisted reader and
 * an argument that isn't data. This module is the piece that closes that gap
 * for readers whose flags are simple enough to describe with a grammar: given
 * the argv words that follow the command name and a description of what the
 * binary accepts, say whether every word is an option this grammar
 * recognises, a value an option consumes, or an operand that satisfies the
 * `operands` shape. Nothing here decides *class* — that stays the caller's
 * job, together with the correctness conditions in the design doc (an
 * optional-argument flag never goes in `valueFlags`; an option is listed only
 * if every implementation the command name can resolve to reads it the same
 * way).
 *
 * Pure and side-effect free: no filesystem, no `classifier.ts` import. The
 * table that wires this into a command's class is a later task.
 */
/**
 * Does every word in `words` come from what `grammar` describes?
 *
 * The scan is word-by-word, left to right, mirroring how getopt (or, for
 * `exact`, the binary's own hand-rolled parser) actually reads argv: a lone
 * `-` is always an operand (stdin), and everything left over after options
 * are stripped is checked against `operands`. `--` ends option parsing for
 * every later word under `getopt` only — an `exact` parser keeps evaluating
 * its option words after `--` (measured: GNU `find -- d -fprint /tmp/x`
 * wrote the file), so there `--` is refused as an unrecognised word rather
 * than treated as end-of-checks.
 */
function matchesGrammar(words, grammar) {
    if (grammar.args === 'any') {
        return { ok: true };
    }
    const flags = new Set(grammar.flags ?? []);
    const valueFlags = new Set(grammar.valueFlags ?? []);
    const optionalValueFlags = new Set(grammar.optionalValueFlags ?? []);
    const operands = [];
    let optionsEnded = false;
    for (let i = 0; i < words.length; i++) {
        const word = words[i];
        // A lone '-' is stdin, not an option — and once '--' has been seen,
        // nothing looks like an option any more.
        const looksLikeOption = !optionsEnded && word.length > 1 && word.startsWith('-');
        // POSIX option order, opt-in per entry — and ahead of the getopt `--`
        // branch below on purpose: `--` is itself an option-looking word, and an
        // implementation that does not permute (macOS uniq's `+`-prefixed
        // optstring, BSD ifconfig) has already stopped option scanning at the
        // first operand, so it reads `--` as an operand — uniq's is the OUTFILE
        // it overwrites (a file literally named `--`), ifconfig's is an interface
        // configuration word. A permuting implementation (GNU) would treat the
        // same word as the terminator it spells, so the word cannot be judged one
        // way for both: `optionsBeforeOperands` refuses it, and only entries
        // where some implementation does not permute set the flag.
        if (grammar.optionsBeforeOperands && operands.length > 0 && looksLikeOption) {
            return { ok: false, word };
        }
        // getopt only. An `exact` parser never hands `--` this meaning: find
        // keeps reading primaries after it, so accepting `--` there would end
        // the checks at exactly the word an attacker can hide behind.
        if (grammar.args === 'getopt' && !optionsEnded && word === '--') {
            optionsEnded = true; // every later word is an operand, `--` itself is not one
            continue;
        }
        if (!looksLikeOption) {
            operands.push(word);
            continue;
        }
        // git's `-<n>` revision limit (`-20`): a whole word of digits, accepted
        // as a no-value option before any cluster or long-option parsing sees it.
        // `-2x` is not all digits, so it falls through to the cluster path below
        // and is refused unless its characters are listed. getopt style only.
        //
        // An explicit entry always wins over this shortcut, but only the leading
        // `-<digit>` *character* is effective: the cluster parser below reads
        // getopt's way, one character at a time, and never the whole word. An
        // entry naming just `-20` therefore does not make `-20` pass — the
        // shortcut stands down (the word is "explicitly listed") and the cluster
        // parser then refuses it unless `-2` is listed too. Fail-closed, which is
        // the right failure for a listing the binary would not read that way.
        // Ambiguity is refused here as well, the same as every other path —
        // otherwise a name the caller listed in more than one list would be
        // silently accepted through this shortcut instead of being caught.
        if (grammar.args === 'getopt' && grammar.numericShort && /^-\d+$/.test(word)) {
            const shortChar = word.slice(0, 2); // '-' + first digit
            if (isAmbiguousName(word, flags, valueFlags, optionalValueFlags) ||
                isAmbiguousName(shortChar, flags, valueFlags, optionalValueFlags)) {
                return { ok: false, word };
            }
            const explicitlyListed = flags.has(word) ||
                valueFlags.has(word) ||
                optionalValueFlags.has(word) ||
                flags.has(shortChar) ||
                valueFlags.has(shortChar) ||
                optionalValueFlags.has(shortChar);
            if (!explicitlyListed) {
                continue; // no explicit entry claims this digit — take the numeric shortcut
            }
            // An explicit entry claims this word or its leading digit character:
            // fall through to ordinary short-cluster parsing below, which applies
            // it correctly (including consuming a separate value word for a
            // `valueFlags` entry, which this shortcut must never do).
        }
        if (grammar.args === 'getopt' && !word.startsWith('--')) {
            // Short cluster: read character by character, the way getopt does.
            const cluster = matchShortCluster(word, words, i, flags, valueFlags, optionalValueFlags);
            if (!cluster.ok)
                return cluster;
            i = cluster.nextIndex; // the `for` loop's own i++ then lands on the next unread word
            continue;
        }
        // A long option (getopt) or any '-'-prefixed word (exact — there is no
        // separate short-cluster path, so this is also where '-n' is checked).
        // Only getopt splits '=value' off the name; exact matches the raw word,
        // so '--name=value' matches only if that whole string was listed.
        const eqIndex = grammar.args === 'getopt' ? word.indexOf('=') : -1;
        const name = eqIndex === -1 ? word : word.slice(0, eqIndex);
        // A name in more than one of the three lists is a grammar bug, not a
        // call this matcher can make on the binary's behalf — accepting it would
        // have to pick a side (does it take a value, an optional value, or
        // none?), and picking wrong is exactly the hole the correctness
        // conditions warn about. Refuse rather than guess.
        if (isAmbiguousName(name, flags, valueFlags, optionalValueFlags)) {
            return { ok: false, word };
        }
        if (valueFlags.has(name)) {
            if (eqIndex !== -1) {
                continue; // '--name=value': the value is attached, nothing left to consume
            }
            if (i + 1 >= words.length) {
                return { ok: false, word: name }; // a value flag with nothing after it
            }
            i++; // consume the next word as the value
            continue;
        }
        if (optionalValueFlags.has(name)) {
            // Bare, or (getopt) '--name=value' with the value already attached to
            // this same word via `name`/`eqIndex` above. Either way there is
            // nothing left to consume, and the next word is never touched.
            continue;
        }
        if (flags.has(name) && eqIndex === -1) {
            continue; // a no-value flag never accepts an attached '=value'
        }
        return { ok: false, word };
    }
    return checkOperands(operands, grammar.operands);
}
/**
 * True when `name` appears in more than one of the three option lists — the
 * ambiguity the correctness conditions require every path to refuse.
 */
function isAmbiguousName(name, flags, valueFlags, optionalValueFlags) {
    const inFlags = flags.has(name);
    const inValueFlags = valueFlags.has(name);
    const inOptionalValueFlags = optionalValueFlags.has(name);
    return ((inFlags && inValueFlags) || (inFlags && inOptionalValueFlags) || (inValueFlags && inOptionalValueFlags));
}
/**
 * Reads one getopt-style short-option cluster (`-rn5`) character by
 * character. `flags` characters just continue the scan; a `valueFlags`
 * character takes the rest of the word as its value, or the next word if
 * the rest is empty; an `optionalValueFlags` character takes the rest of the
 * word as its value if there is any, never the next word, and either way
 * ends the scan of this word; anything else refuses the whole cluster.
 *
 * Returns the index the outer loop's own `i++` should land past — unchanged
 * when the value was attached, optional, or there was none to take,
 * `index + 1` only when a required value flag consumed the next word.
 */
function matchShortCluster(word, words, index, flags, valueFlags, optionalValueFlags) {
    for (let c = 1; c < word.length; c++) {
        const ch = '-' + word[c];
        // Same ambiguity refusal as the long/exact path, checked first so a
        // char present in more than one list is refused here too, not silently
        // treated as belonging to just one of them (which the long/exact path
        // would not do either).
        if (isAmbiguousName(ch, flags, valueFlags, optionalValueFlags))
            return { ok: false, word };
        if (flags.has(ch))
            continue;
        if (valueFlags.has(ch)) {
            const rest = word.slice(c + 1);
            if (rest.length > 0)
                return { ok: true, nextIndex: index };
            if (index + 1 >= words.length)
                return { ok: false, word: ch };
            return { ok: true, nextIndex: index + 1 };
        }
        if (optionalValueFlags.has(ch)) {
            // The rest of the word (if any) is this option's value; the scan of
            // this word ends here either way, and the next word is never consumed.
            return { ok: true, nextIndex: index };
        }
        return { ok: false, word };
    }
    return { ok: true, nextIndex: index };
}
/**
 * Checks the operands collected from a pass over `words` against `rules`.
 * `first` is checked only against `operands[0]` — a reader with no operands
 * at all has nothing to violate it with — `each` against every operand, and
 * `max` last, since going over budget is a property of the whole list rather
 * than of any one word.
 */
function checkOperands(operands, rules) {
    if (!rules)
        return { ok: true };
    for (let i = 0; i < operands.length; i++) {
        const operand = operands[i];
        if (i === 0 && rules.first && !rules.first.includes(operand)) {
            return { ok: false, word: operand };
        }
        if (rules.each) {
            // A caller's /g or /y regex makes RegExp#test stateful: lastIndex
            // carries over from the previous call, so without resetting it here
            // one operand's match position can leak into the next — accepting an
            // operand that should be refused, or the reverse. Reset before every
            // test so each operand is checked fresh, the way a plain (non-sticky,
            // non-global) pattern already behaves.
            rules.each.lastIndex = 0;
            if (!rules.each.test(operand)) {
                return { ok: false, word: operand };
            }
        }
    }
    if (rules.max !== undefined) {
        // A `max` that isn't a non-negative integer (NaN, 1.5, -1, ...) can't be
        // compared against a count safely: `length > NaN` is always false,
        // which would accept any number of operands, and a fractional max reads
        // back out of the operands array at a non-existent index. Treat any
        // such value as the strictest possible bound — no operand is safe to
        // let through under a limit that couldn't be checked — rather than let
        // a malformed grammar entry accept (or silently under-report) unbounded
        // operands.
        const validMax = Number.isInteger(rules.max) && rules.max >= 0;
        const limit = validMax ? rules.max : 0;
        if (operands.length > limit) {
            return { ok: false, word: operands[limit] };
        }
    }
    return { ok: true };
}
// --- upstream classifier.ts ---
/**
 * Anything through which the shell can start a second command.
 *
 * This gate decides whether an allowlisted binary counts as read-only, and the
 * allowlist only vouches for the binary — never for what a shell might run
 * beside it. It used to test /[>;|]/, which let `ls $(touch /tmp/x)` through as
 * read-only: `ls` is allowlisted, no listed metacharacter appears, and the
 * remote shell expands the substitution and runs the inner command anyway
 * (GHSA-r8hm-vpm8-cfh6).
 *
 * Listing every dangerous construct is a losing game — `$()`, backticks,
 * `<(...)`, `${x:=...}`, `&&`, a bare newline — so this refuses every character
 * with syntactic meaning to the shell instead, and `$` wholesale rather than
 * just `$(`. The cost is that `echo $HOME` is no longer classified read-only.
 * That is the right trade for the tool whose entire promise is that it cannot
 * write: run-command still accepts it under policy.
 */
const SHELL_CONTROL_CHARS = /[;&|<>`$(){}\n\r]/;
/**
 * The first word in `command` carrying an unquoted, unescaped shell glob
 * character — `*`, `?` or `[` — or null when no word does.
 *
 * A glob character is not a shell control character (it starts no command),
 * so `SHELL_CONTROL_CHARS` rightly ignores it — but the host shell expands
 * it before the binary sees argv, and the grammar matcher reads dequoted
 * words, where `find -name '*.conf'` and `find -name *.conf` have become the
 * same string. They are not the same command: the quoted word is one operand
 * of data, the unquoted one expands to every matching filename and turns one
 * counted operand into several real ones (`uniq /root/.ssh/id_ed25519*`
 * counted one operand; measured on debian:12, the expansion made the `.pub`
 * uniq's OUTFILE and it was overwritten with the private key). This scan
 * keeps the tokeniser's own quote and escape state, so the judgement happens
 * at the one layer that can still tell the two apart.
 *
 * Deliberately word-scoped and whole-command: a glob inside `$()` or
 * backticks never reaches this helper's caller (those carry
 * SHELL_CONTROL_CHARS and return early), and a glob in the command word
 * itself makes the allowlist lookup miss, so the caller — the allowlist
 * branch, which only runs when the command words matched a READERS key
 * exactly — never sees one either.
 */
function firstUnquotedGlobWord(command, honorQuotes = true, dialect = 'posix') {
    let quote = null;
    let escaped = false;
    let word = '';
    let globInWord = false;
    for (const ch of command) {
        if (escaped) {
            // A backslash-quoted glob character is data the shell passes through.
            word += ch;
            escaped = false;
            continue;
        }
        if (quote) {
            // Backslash is literal inside single quotes; inside double quotes it
            // escapes — the same distinction the tokeniser makes.
            if (dialect === 'posix' && ch === '\\' && quote === '"') {
                escaped = true;
                continue;
            }
            if (ch === quote)
                quote = null;
            else
                word += ch;
            continue;
        }
        if (dialect === 'posix' && ch === '\\') {
            escaped = true;
            continue;
        }
        if (honorQuotes && (ch === '"' || ch === "'")) {
            quote = ch;
            continue;
        }
        if (/\s/.test(ch)) {
            if (globInWord)
                return word;
            word = '';
            globInWord = false;
            continue;
        }
        if (ch === '*' || ch === '?' || ch === '[')
            globInWord = true;
        word += ch;
    }
    // A quote left open at the end is not a command a shell would run, and the
    // tokeniser re-reads such a string with quotes demoted to text (see
    // `tokenizeSegmentsDetailed`). Judge it the same way here: in that reading
    // the glob character is unquoted.
    if (honorQuotes && quote !== null)
        return firstUnquotedGlobWord(command, false, dialect);
    return globInWord ? word : null;
}
/**
 * The binaries this classifier will vouch for, and what it vouches for about them.
 *
 * Three questions, kept apart because one Set answering all of them is how #217
 * turned the interpreter carrier scan off for two verbs by adding them to a list
 * about classes:
 *
 *   readOnly         does this binary only read?  -> decides the class
 *   operandsAreData  can its operands hide a command?  -> decides whether the
 *                    carrier scan runs
 *   grammar          which of its argv words does `matchesGrammar` accept?  ->
 *                    decides `read-only` versus `safe`
 *
 * `readOnly` and `operandsAreData` are `true` for every entry today. The value is
 * not the contents but that the type will not let the next person add a name
 * without answering all three.
 *
 * `grammar` decides only that one boundary, not the class outright: a command
 * whose grammar rejects falls no lower than `safe`, and `DISQUALIFYING_ARGS`
 * still runs before the allowlist branch, so it can still raise a rejected — or
 * an accepted — reader past `safe` (`sort -o /tmp/x /etc/passwd` is
 * `destructive` regardless of what `sort`'s grammar says). An `'any'` grammar
 * accepts every word and carries an `audit` string saying why that trust is
 * believed sound; every other entry lists the flags and operand shape its
 * grammar accepts, and starts with none of either — see `reader-grammar.ts`.
 *
 * Two mechanisms answer the second question outside this table and are not
 * affected by it — `DISQUALIFYING_ARGS` and `FIND_EXEC_FLAGS` — which is why
 * `find` can carry `operandsAreData: true` while `find … -exec sudo id +` is
 * still `privileged`.
 *
 * The two-word entries are looked up only for the class: `operandsAreData` reads
 * a single word, so those rows never reach the second question. Their `grammar`
 * reads the words after the two-word prefix (`classifyOuter` applies the offset).
 */
const READERS = {
    // arp: `-a`/`-e`/`-n`/`-v` only display; `-H`/`-t` (hardware type) and `-i`
    // (interface) filter the display, not set anything. Excludes `-d` (deletes an
    // entry), `-s`/`-S` (adds one — BSD man synopsis) and `-f` (loads entries from
    // a file — net-tools arp(8)). Measured: busybox --help + `arp -a`; macOS man
    // arp read; net-tools arp(8) documented only (die.net). Windows 11 build
    // 26200 measurement: `arp.exe` accepts the slash form (`/a` measured),
    // `/d`/`/s` inferred (not run — a state-changing form is never executed to
    // confirm it) as delete/add. A `/X` switch is an operand under this POSIX
    // grammar and cannot be told apart from a path like `/etc`; `each` refuses
    // any single-segment `/word` operand, with or without a trailing slash
    // (see the design's Windows section) — the trailing-slash tolerance of
    // `arp /d/`-style forms cannot be measured without running a state-changing
    // form, so it is refused fail-closed. The cost is that a legitimate
    // slash-form display like `arp /a` also falls to `safe`.
    "arp": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-a', '-e', '-n', '-v'],
            valueFlags: ['-H', '-t', '-i'],
            operands: { max: 1, each: /^(?!\/[^/]*\/?$)/ } } },
    "basename": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: pure string manipulation of its argument; no filesystem access at all' } },
    "cat": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured GNU/busybox/BSD: writes file contents to stdout; BSD's -l is a transient advisory lock on cat's own stdout fd, not a lasting write, and clears at exit" } },
    "comm": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: compares two sorted files and prints the differences; no output-file operand or flag' } },
    "cut": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured GNU/BSD: extracts byte/field ranges to stdout; --output-delimiter only changes what's printed, not where" } },
    // date: `-u`/`--utc`/`--universal` and `-R`/`--rfc-2822`/`--rfc-email` only
    // change display format; `-r`/`--reference` reads a file's mtime (GNU) or an
    // epoch value (BSD); `--rfc-3339` picks a display format; `-v` (BSD) only
    // shows the adjusted time ("not actually set", man). `-I`/`--iso-8601` is
    // optional-value (getopt's `::`): it IS listed, in `optionalValueFlags`, so a
    // bare `-I`/`--iso-8601` or an attached form (`-Iseconds`, `--iso-8601=date`)
    // stays read-only — the matcher just never consumes a following SEPARATE
    // word as its value. A bare `+FMT` operand is accepted (`max: 1`, `each:
    // /^\+/`); excludes `-s`/`--set` (sets the clock),
    // `-d`/`--date` (read the same way on GNU/busybox but historically set the
    // kernel DST flag on BSD — man HISTORY / FreeBSD "added and then removed
    // again" — dropped because implementations disagree) and BSD-only
    // `-D`/`-f`/`-j`/`-n`. Measured: GNU d12+trixie --help, busybox (`date -d
    // 2020-01-01` displayed), macOS man; FreeBSD date(1) documented only.
    "date": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-u', '--utc', '--universal', '-R', '--rfc-2822', '--rfc-email'],
            valueFlags: ['-r', '--reference', '--rfc-3339', '-v'],
            optionalValueFlags: ['-I', '--iso-8601'],
            operands: { max: 1, each: /^\+/ } } },
    "df": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: reports space usage read from mounted filesystems; --output= selects columns to print, not a file' } },
    // diff: comparison/output-format flags only, plus value flags that read or
    // match (`-D`/`--ifdef` merges to stdout, not a file). `-C`/`-U` ARE
    // required-value (`valueFlags`) — GNU, BSD and busybox all take the short
    // form with a count, attached or as a separate word; only the long
    // spellings `--context`/`--unified`/`--color` are optional-value
    // (`optionalValueFlags`: bare or `=value`, never a separate word). Moved
    // here from the design round's 'any' guess: `-l`/`--paginate` pipes output
    // through
    // `/usr/bin/pr` — measured on debian:12, removing `/usr/bin/pr` turns it into
    // "subsidiary program '/usr/bin/pr' not found", and it runs the absolute path
    // regardless of PATH, so it is excluded rather than listed. Measured: GNU
    // --help (d12 + trixie 3.10) and the -l behaviour; BSD man (also has -l);
    // busybox --help (no -l).
    "diff": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-q', '--brief', '-s', '--report-identical-files', '-c', '-u', '-e', '--ed', '-n', '--rcs',
                '-y', '--side-by-side', '--left-column', '--suppress-common-lines', '-p', '--show-c-function',
                '-t', '--expand-tabs', '-T', '--initial-tab', '--suppress-blank-empty', '-r', '--recursive',
                '--no-dereference', '-N', '--new-file', '--unidirectional-new-file', '--ignore-file-name-case',
                '--no-ignore-file-name-case', '-i', '--ignore-case', '-E', '--ignore-tab-expansion', '-b',
                '--ignore-space-change', '-w', '--ignore-all-space', '-B', '--ignore-blank-lines', '-a', '--text',
                '--strip-trailing-cr', '-d', '--minimal'],
            valueFlags: ['-C', '-U', '-W', '--width', '--tabsize', '-F', '--show-function-line', '-I',
                '--ignore-matching-lines', '-D', '--ifdef', '--label', '-x', '--exclude', '-X', '--exclude-from',
                '-S', '--starting-file', '--from-file', '--to-file', '--line-format'],
            optionalValueFlags: ['--context', '--unified', '--color'],
            operands: { max: 2 } } },
    "dig": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured BIND 9.10.6 (BSD): sends a DNS query and prints the answer; writes nothing locally (DNS egress tracked separately)' } },
    "dirname": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: pure string manipulation of its argument; no filesystem access at all' } },
    "docker images": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured docker CLI 29.7.2 --help: lists local images from the daemon; every option only changes what is listed, no state change' } }, // two-word: class only
    "docker inspect": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured docker CLI 29.7.2 --help: prints low-level JSON about an object; no state change" } }, // two-word: class only
    "docker logs": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured docker CLI 29.7.2 --help: prints a container's captured output; no state change" } }, // two-word: class only
    "docker ps": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured docker CLI 29.7.2 --help: lists containers; no state change' } }, // two-word: class only
    "docker stats": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured docker CLI 29.7.2 --help: streams live resource-usage numbers; no state change' } }, // two-word: class only
    "du": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: walks a directory tree and reports disk usage; no write mode' } },
    "echo": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: writes its arguments to stdout only; a file write needs shell redirection, which the outer gate already refuses' } },
    "false": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU: exits 1 immediately; no I/O of any kind' } },
    // file: display/format flags, plus value flags that name what to read (a list
    // of files, a magic database, an exclusion). Excludes `-C`/`--compile`, which
    // was **measured to write**: on the local macOS file 5.41, `file -C -m
    // /usr/share/file/magic/magic` created `magic.mgc` (2256 bytes) in a
    // throwaway directory. GNU is documented only (file(1), die.net 5.04: "-C …
    // is the only option that creates a file") — GNU file is absent from every
    // measured image (see spec Question 3). Also excludes `-z`/`-Z`
    // (uncompress/uncompress-noreport — audit.md lists them as no-value):
    // libmagic may run an external decompressor program when it isn't built
    // against the matching decompression library (documented, not measured;
    // the contract forbids executing another program), so they stay off this
    // list even though audit.md's own per-entry table has them. No
    // optional-value option in this set; `-p`/`--preserve-date` is excluded as
    // unnecessary rather than unsafe.
    "file": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-b', '--brief', '-c', '--checking-printout', '-i', '--mime', '--mime-type', '--mime-encoding',
                '-k', '--keep-going', '-L', '--dereference', '-h', '--no-dereference', '-n', '--no-buffer',
                '-r', '--raw', '-s', '--special-files', '-0', '--print0'],
            valueFlags: ['-f', '--files-from', '-m', '--magic-file', '-M', '-e', '--exclude', '-F', '--separator'] } },
    // find: `exact` because find parses its own predicates rather than through
    // getopt and recognises no clustering or abbreviation — measured, `find .
    // -exe` is "unknown predicate `-exe`". No-value predicates/operators plus
    // value predicates that read metadata to test against; `-printf` writes to
    // stdout, not a file (its file-writing sibling `-fprintf` is excluded, see
    // below). Excludes the writing/executing family — `-delete`, `-exec`,
    // `-execdir`, `-ok`, `-okdir` (also caught by DISQUALIFYING_ARGS first),
    // `-fprint`, `-fprint0`, `-fprintf`, `-fls` (write to a file) — and a handful
    // of read-only-but-unnecessary predicates left out rather than
    // exhaustively listed (`-files0-from`, `-quit`, `-prune`, `-fstype`,
    // `-newerXY`, `-regextype`, `-D`). No operand rule: start paths and `(`/`)`
    // pass through as operands, and the Windows `find.exe` measurement in the
    // design round found it read-only, so no `each` rule is needed here.
    // Measured: GNU d12 --help; busybox (`find /tmp/t -name '*.conf' -type f`
    // ran; `-ls`/`-printf` are absent from busybox find, which refuses them
    // itself, fail-closed); BSD man.
    "find": { readOnly: true, operandsAreData: true, grammar: { args: 'exact',
            flags: ['-H', '-L', '-P', '-print', '-print0', '-ls', '-not', '-a', '-and', '-o', '-or', '-true', '-false',
                '-empty', '-xdev', '-mount', '-depth', '-daystart', '-executable', '-readable', '-writable'],
            valueFlags: ['-name', '-iname', '-path', '-ipath', '-wholename', '-iwholename', '-regex', '-iregex',
                '-type', '-perm', '-user', '-group', '-uid', '-gid', '-size', '-mtime', '-mmin', '-atime', '-amin',
                '-ctime', '-cmin', '-newer', '-anewer', '-cnewer', '-links', '-inum', '-maxdepth', '-mindepth',
                '-printf'] } },
    "free": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (procps free(1)): reports memory usage parsed from /proc; every option only changes units or format' } },
    // git branch: listing/display flags plus optional-value flags kept out of
    // valueFlags (rule 1; `--contains HEAD`'s operand is refused by `max: 0`
    // anyway — an accepted cost). `--sort=<key>` is the one required-value flag.
    // `max: 0` excludes the operand form: a bare `git branch NAME` CREATES a
    // branch (measured, `refs/heads/side` was created), so no operand budget is
    // safe to grant here. Excludes `-d`/`-D` (deletes; `git branch -D main`
    // measured elsewhere in this advisory round), `-m`/`-M` (moves/renames —
    // already blocked by `max: 0` since both need an operand) and
    // `--edit-description` (opens an editor). Measured: git 2.55.0 on macOS
    // (`git branch side` + `git for-each-ref`; `--help`).
    "git branch": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-a', '--all', '-r', '--remotes', '-v', '--verbose', '-q', '--quiet', '--list', '--show-current'],
            valueFlags: ['--sort'],
            optionalValueFlags: ['--color', '--contains', '--merged', '--no-merged'],
            operands: { max: 0 } } },
    // git diff: display/format flags, plus `-M`/`--find-renames`,
    // `-C`/`--find-copies`, `-U`/`--unified`, `--color`, `--word-diff` and
    // `--stat` as optional-value (`optionalValueFlags`): `-U5` and `--unified=5` both stay
    // read-only (the attached value is fine); only a following SEPARATE word is
    // never consumed as the value, which is why the plain `-u` still exists as
    // the no-value form. `--diff-filter`/`-S`/`-G`/`-O` all read or search, never
    // write. No operand
    // rule (revision/path). Excludes `--output` — **measured to write**: on a
    // scratch checkout, `git diff --output=diffout.txt` created a 93-byte file
    // (the design round had this only as documented). Measured: git 2.55.0.
    "git diff": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-p', '-u', '--patch', '--name-only', '--name-status', '--cached', '--staged', '--raw', '-w',
                '--ignore-all-space', '-b', '--ignore-space-change', '--summary', '--shortstat', '--exit-code',
                '--quiet', '-R', '--no-color', '--first-parent'],
            valueFlags: ['--diff-filter', '-S', '-G', '-O'],
            optionalValueFlags: ['-M', '--find-renames', '-C', '--find-copies', '-U', '--unified', '--color',
                '--word-diff', '--stat'] } },
    // git log: display/format flags, plus optional-value flags kept out of
    // valueFlags (rule 1). No operand rule (revision/path, including anything
    // after `--`). Excludes `--output` — **measured to write**: `git log
    // --output=out.txt HEAD` created a 113-byte file on a scratch checkout
    // (`.git/index` unchanged). `numericShort: true` is required because the
    // corpus needs `git log --oneline -20`: git's own `-<n>` revision-limit
    // shortcut is scanned character by character by real getopt, so no
    // `flags`/`valueFlags` entry can name the word `-20` itself — this is the
    // matcher capability the design round's audit asked for, harmless for `git
    // show` too. Measured: git 2.55.0 (`git log --oneline` called; index
    // unchanged).
    "git log": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['--oneline', '--graph', '--all', '-p', '-u', '--patch', '--name-only', '--name-status',
                '--abbrev-commit', '--relative-date', '--reverse', '--topo-order', '--date-order', '--parents',
                '--merges', '--no-merges'],
            valueFlags: ['-n', '--max-count', '--since', '--until', '--author', '--grep', '--date', '-S', '-G',
                '--skip'],
            optionalValueFlags: ['--pretty', '--format', '--decorate', '--branches', '--tags', '--remotes',
                '--stat', '-L'],
            numericShort: true } },
    // git remote: `-v`/`--verbose` and the two verbose-adjacent no-value flags
    // only display. `first: ['get-url']`, `max: 2` — a bare `git remote`
    // and `git remote -v` are both valid (0 operands). `show` was removed from
    // `first` by the final review: `git remote show <URL>` accepts a URL
    // (measured, git 2.55.0) and runs ssh / `git-remote-<helper>` against the
    // caller-chosen target, so the subcommand is excluded and a viewer loses
    // `git remote show origin` (priced cost). Excludes `add` (writes
    // config — measured, `git remote add` wrote `[remote "origin"]` into
    // `.git/config`), `rename`, `remove`/`rm`, `set-url`, `set-head` (all write),
    // `prune` (deletes remote-tracking refs) and `update` (fetches — changes
    // refs). Measured: git 2.55.0.
    "git remote": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-v', '--verbose', '-n', '--push'],
            operands: { max: 2, first: ['get-url'] } } },
    // git show: display/format flags, plus `--pretty`, `--format`, `--decorate`
    // and `--stat` as optional-value (`optionalValueFlags`: bare or `=value`, a
    // following separate word is never consumed) and `--date` as the one
    // required-value flag. No operand rule (HEAD, commit, tag, …). Excludes
    // `--output` — same write measured for `git log`/`git diff`, same option
    // family. `numericShort: true` for the same `-<n>` shortcut `git log` needs
    // (`git show -3`). Measured: git 2.55.0 (the sibling `--output` write was
    // re-measured this round).
    "git show": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-s', '--no-patch', '--name-only', '--name-status', '--oneline', '--abbrev-commit', '--raw'],
            valueFlags: ['--date'],
            optionalValueFlags: ['--pretty', '--format', '--decorate', '--stat'],
            numericShort: true } },
    "git status": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured git 2.55.0: opportunistically refreshes cached stat data in .git/index when stale; writes no content, ref or config; host can disable via GIT_OPTIONAL_LOCKS=0' } }, // two-word: class only
    "grep": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: searches input for a pattern and prints matches; no option writes a file or runs a program' } },
    "head": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: prints the first lines of a file; no write mode' } },
    "host": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured BIND 9.10.6 (BSD): sends a DNS query and prints the answer; writes nothing locally (DNS egress tracked separately)' } },
    // hostname: display flags only, no value flags. `operands: { max: 0 }` — a
    // bare `hostname NAME` SETS the hostname on every implementation (GNU --help
    // usage line, busybox `[-sidf] [HOSTNAME | -F FILE]`, BSD man), so no operand
    // budget above zero is safe. Excludes `-F`/`--file` (sets from a file),
    // `-b`/`--boot` (sets a default hostname when none is configured — GNU
    // --help) and `-y`/`--yp`/`--nis` (sets the NIS domain via an operand `max:
    // 0` already refuses — left out as unnecessary rather than unsafe). Measured:
    // GNU hostname 3.21/3.25 --help; busybox (`hostname -s`); macOS man (`[-f]
    // [-s | -d]`).
    "hostname": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-a', '--alias', '-A', '--all-fqdns', '-d', '--domain', '-f', '--fqdn', '--long', '-i',
                '--ip-address', '-I', '--all-ip-addresses', '-s', '--short'],
            operands: { max: 0 } } },
    "htop": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "documented (htop(1) + FILES section, 2.x/3.x): no CLI option writes or executes; kill/renice are interactive keys (F7/F8/F9), unreachable by a read-only caller; ~/.config/htop/htoprc is written only after an interactive Setup change on clean exit; not measured — htop is absent from every image and from macOS" } },
    "id": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured GNU/BSD: prints the caller's uid/gid/groups; no write mode" } },
    // ifconfig: display flags/filters only (BSD's `-l -m -d -u -v -L -r -C`
    // format the listing), plus a BSD output-format value flag. `operands: { max:
    // 1 }` — a bare `ifconfig eth0` only SHOWS that interface's status; a second
    // operand (address, `up`/`down`, `netmask`, `hw`, `mtu`, `add`/`del`,
    // `destroy`, …) configures it and is refused. `optionsBeforeOperands:
    // true` (final-review fix): BSD ifconfig reads options only before the
    // interface operand, and macOS accepts the same letters after it as
    // interface settings — `ifconfig en0 -av`/`-dad` change settings from
    // letters this grammar lists — so an option-looking word after the operand
    // is refused rather than read as a listed flag. Measured: busybox --help +
    // `ifconfig -a` (usage line is `[-a] [IFACE] [ADDRESS]` — everything from
    // ADDRESS on is a write); BSD man synopsis; net-tools ifconfig(8) documented
    // only ("Otherwise, it configures the interface").
    "ifconfig": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-a', '-s', '-l', '-m', '-d', '-u', '-v', '-L', '-r', '-C'],
            valueFlags: ['-f'],
            optionsBeforeOperands: true,
            operands: { max: 1 } } },
    "iostat": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (sysstat iostat(1)): reports kernel I/O statistics; no write mode' } },
    // ip addr: no options at all — a global flag like `-4`/`-6`/`-o` sits before
    // the two-word prefix, so `ip -4 addr show` never even reaches the two-word
    // match and is refused visibly (accepted cost). `first: ['show', 'list']`:
    // "add"/"del"/"flush" cannot be the first operand; after `show`/`list`,
    // operands like `dev eth0`, `to PREFIX`, `label`, `scope` are free, and a
    // bare `ip addr` is valid (vacuous `first`). Abbreviations (`ip a`, `ip ad
    // sh`) are documented in GNU but refused here since the grammar requires the
    // full two words — accepted cost. Measured: busybox (`ip addr show`, `ip
    // addr list`, bare `ip addr` all ran); GNU ip(8) documented only (man7: "show
    // (or list)").
    "ip addr": { readOnly: true, operandsAreData: true, grammar: { args: 'exact', operands: { first: ['show', 'list'] } } }, // two-word: class only
    // ip route: `first: ['show', 'list', 'get']` — `get ADDR` is a read-only
    // query (ip-route(8): "no packets are actually sent"). Excludes `add`,
    // `del`, `change`, `append`, `replace`, `flush`, `restore` (all write) and
    // `save` (dumps to stdout, but its sibling `restore` writes, so the verb pair
    // is left out entirely rather than split). Measured: busybox (`ip route
    // list`, `ip route show` ran; `ip route get 10.0.0.1` queried without
    // writing); GNU ip(8) + ip-route(8) documented only.
    "ip route": { readOnly: true, operandsAreData: true, grammar: { args: 'exact', operands: { first: ['show', 'list', 'get'] } } }, // two-word: class only
    // journalctl: display/filter flags, plus `-n`/`--lines`, `-b`/`--boot` and
    // `--facility` as optional-value (`optionalValueFlags`; journalctl(1): the
    // argument may be omitted) — a bare word or an attached form (`-b1`,
    // `--boot=2`) stays read-only, but the matcher never consumes a following
    // SEPARATE word as the value, so `-b -1` still refuses on the unrecognised
    // `-1` (an accepted cost, not a claim that every attached spelling is
    // refused). No operand rule (unit names/match patterns — reads). Excludes
    // the archive-mutating
    // family — `--vacuum-time`/`--vacuum-size` (deletes archived journals;
    // `--vacuum-time=1s` measured destructive elsewhere in this advisory round),
    // `--rotate` (measured elsewhere too), `--flush`/`--sync`/`--relinquish-var`
    // (redirect the daemon's disk writes), `--setup-keys` (generates FSS keys)
    // and `--verify`/`--verify-key`/`--root` (left out as unnecessary). Entirely
    // documented only — journalctl(1) (man7, systemd 262~devel) — journalctl is
    // absent from every measured image and from macOS.
    "journalctl": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-f', '--follow', '-e', '--pager-end', '-r', '--reverse', '-k', '--dmesg', '-q', '--quiet',
                '-x', '--catalog', '-a', '--all', '-l', '--full', '-m', '--merge', '--no-pager', '--no-hostname',
                '--no-tail', '--disk-usage', '--header', '--list-boots', '--system', '--user'],
            valueFlags: ['-u', '--unit', '--since', '--until', '-S', '-U', '-o', '--output', '-p', '--priority',
                '-g', '--grep', '-t', '--identifier', '-D', '--directory'],
            optionalValueFlags: ['-n', '--lines', '-b', '--boot', '--facility'] } },
    "ls": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: lists directory entries; no write mode' } },
    // netstat: ledger correction — moved from the design round's 'any' guess to
    // a grammar; audit.md's main table still records this entry as 'any'
    // ("every option is display"). The corrected reasons (progress.md ledger):
    // FreeBSD netstat(1) documents `-z` as resetting counters (documented, not
    // measured — excluded, not listed below), and `-p` is put in `flags` rather
    // than `valueFlags` because it takes a value on BSD/Windows but takes none
    // on net-tools (Linux) — listing it as a required-value flag would
    // force-consume the next word on the implementation where it takes none.
    // `-f`/`-I` are optional-value (`optionalValueFlags`). No operand rule
    // needed. Measured: busybox + BSD (`netstat -rn`, etc.); net-tools
    // netstat(8) documented only for anything beyond the measured set.
    "netstat": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-a', '-n', '-t', '-u', '-l', '-p', '-r', '-i', '-s', '-e', '-W', '-x', '-w', '-4', '-6',
                '-v', '-b', '-d', '-m'],
            optionalValueFlags: ['-f', '-I'] } },
    "nslookup": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox/BSD: sends a DNS query; interactive mode does nothing beyond querying, and interactive input is unreachable by design (out of scope)' } },
    "ping": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (BSD man): sends ICMP echo requests and prints replies; writes nothing locally (ICMP egress tracked separately)' } },
    "printenv": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints environment variables; no write mode' } },
    "printf": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: writes formatted text to stdout only; a file write needs shell redirection, which the outer gate already refuses' } },
    "ps": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured busybox; documented (procps ps(1): 'works by reading /proc'): lists processes; no write mode" } },
    "pwd": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints the working directory; no write mode' } },
    "readlink": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: resolves a symlink; no write mode' } },
    "realpath": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: resolves a canonical path; no write mode' } },
    "seq": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints a numeric sequence to stdout; no write mode' } },
    // sort: display/comparison flags only, plus `--check` as optional-value
    // (`optionalValueFlags`): a bare `--check`, or an attached
    // `--check=diagnose-first`/`--check=silent`, both stay read-only — a
    // following SEPARATE word is never consumed as the value, which is why the
    // plain `-c` still exists as the no-value form. Value flags read a key
    // spec, a field separator, a buffer size or a parallelism count. No
    // operand-count limit (multiple input files are legitimate). Windows 11
    // build 26200 measurement: `sort.exe /O FILE IN` writes FILE,
    // case-insensitive (`/o`), abbreviations accepted (`/OU`, `/OUTPUT`) — `-O`
    // is not a switch, so nothing here already excludes it. A `/X` switch is an
    // operand under this POSIX grammar and cannot be told apart from a path
    // like `/etc`; `each` refuses any single-segment `/word` operand, with or
    // without a trailing slash — the trailing-slash form re-measured on the VM
    // 2026-09-26 (build 10.0.26200.9550, confined to %TEMP%): `/O/`, `/o/`,
    // `/OU/`, `/OUTPUT/`, `/T/`, `/A/` are all "Invalid switch" and write
    // nothing (control `/O` writes), but the rule is shared with `arp`, whose
    // `/d`/`/s` slash tolerance cannot be measured without running a
    // state-changing form, so it stays fail-closed. The cost is that an
    // operand naming a file directly under `/` (`sort /data`), or such a
    // directory with a trailing slash (`sort /etc/`), is refused too. Excludes `-o`/`--output`
    // (writes — this advisory's own finding), `--compress-program` (executes a
    // program — measured 14,224 times in the same finding), `-T`/`--temporary-directory`
    // (chooses a write location; a viewer has no use for it, decided in the
    // friction table) and `--random-source`/`--files0-from` (read a file but are
    // unnecessary). `DISQUALIFYING_ARGS`'s own sort rule still runs before this
    // grammar and can still raise the class; the grammar only ever draws the
    // read-only/safe line. Measured: GNU d12 + trixie --help; busybox --help
    // (rejects sort's long options itself: `sort: unrecognized option:
    // key=2`); BSD man (same option family; BSD's own `-o` never reaches this
    // grammar since it is not listed).
    "sort": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-b', '-c', '-d', '-f', '-g', '-h', '-i', '-M', '-m', '-n', '-R', '-r', '-s', '-u', '-V', '-z',
                '--ignore-leading-blanks', '--dictionary-order', '--ignore-case', '--general-numeric-sort',
                '--human-numeric-sort', '--ignore-nonprinting', '--month-sort', '--merge', '--numeric-sort',
                '--random-sort', '--reverse', '--stable', '--unique', '--version-sort', '--debug',
                '--zero-terminated'],
            valueFlags: ['-k', '--key', '-t', '--field-separator', '-S', '--buffer-size', '--sort', '--parallel'],
            optionalValueFlags: ['--check'],
            operands: { each: /^(?!\/[^/]*\/?$)/ } } },
    // ss: entirely documented only — ss(8) (man7, iproute2); ss is absent from
    // every measured image and from macOS. Display flags only, plus value flags
    // that name a socket family/query/filter. Excludes `-K`/`--kill` (forcibly
    // closes sockets), `-D`/`--diag` (dumps raw TCP info to a file), `-N`/`--net`
    // (switches network namespace via setns) and `-b`/`--bpf` (admin); a handful
    // of display-only-but-unnecessary flags left out rather than exhaustively
    // listed (`-E`/`-T`/`-Q`/`-S`/`-M`/`-Z`/`-z`/`--tos`/`--cgroup`/…).
    "ss": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-H', '--no-header', '-O', '--oneline', '-n', '--numeric', '-r', '--resolve', '-a', '--all',
                '-l', '--listening', '-o', '--options', '-e', '--extended', '-m', '--memory', '-p', '--processes',
                '-i', '--info', '-s', '--summary', '-t', '--tcp', '-u', '--udp', '-d', '--dccp', '-w', '--raw',
                '-x', '--unix', '-4', '-6', '-0', '--packet'],
            valueFlags: ['-f', '--family', '-A', '--query', '--socket', '-F', '--filter'] } },
    "stat": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: prints file or filesystem status; no write mode' } },
    // systemctl status: ledger correction — moved from the design round's 'any'
    // guess to a grammar; audit.md's main table still records this entry as
    // 'any' ("only reports run state and log; subcommands that mutate state are
    // outside the two-word match"). The corrected reason (progress.md ledger):
    // systemctl(1) documents `-H`/`--host` as running the operation over SSH
    // (executes another program on another host) and `-M`/`--machine` as
    // targeting a container/VM — both excluded, not listed below. `-n`/
    // `--lines` and `-o`/`--output` are optional-value (`optionalValueFlags`).
    // Entirely documented only — systemctl(1) (man7, systemd 262~devel) —
    // absent from every measured image and from macOS.
    "systemctl status": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-l', '--full', '--no-pager', '-a', '--all', '-q', '--quiet', '--user', '--system', '-r',
                '--recursive', '--no-legend'],
            optionalValueFlags: ['-n', '--lines', '-o', '--output'] } }, // two-word: class only
    "tail": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/busybox/BSD: prints the last lines of a file; -f/-F only follow, they do not write' } },
    "test": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: evaluates a conditional expression and sets exit status; no I/O of any kind' } },
    "top": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "measured busybox/BSD; documented (procps top(1)): no non-interactive write mode in any implementation — kill/renice/config-write keys are interactive-only, and batch mode ('top will not accept input') takes none of them" } },
    "tr": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: translates or deletes characters from stdin to stdout; no write mode' } },
    "traceroute": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox; documented (BSD man): sends probe packets and prints the path; writes nothing locally (ICMP/UDP egress tracked separately)' } },
    "true": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU: exits 0 immediately; no I/O of any kind' } },
    "uname": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints system identification; no write mode' } },
    // uniq: display flags only, plus `--all-repeated` kept optional-value out of
    // valueFlags (rule 1). `operands: { max: 1 }` — INPUT only; a second operand
    // is OUTFILE and is OVERWRITTEN (measured elsewhere in this advisory:
    // `uniq /etc/passwd /root/.ssh/authorized_keys`; GNU's own usage line is
    // `[INPUT [OUTPUT]]`, busybox's `[FILE [OUTFILE]]`). `optionsBeforeOperands:
    // true` (final-review fix): macOS's optstring is `+`-prefixed (`+D::cdif:s:u`,
    // POSIX order), so `uniq IN -c` does not read `-c` as the count flag there —
    // it is the OUTFILE, and uniq overwrites it; GNU permutes, so the spelling
    // is only harmless there, and the grammar must hold for every
    // implementation. Excludes `--group` (optional-value, reads, but left out as
    // unnecessary — not a minimal grammar addition). Measured: GNU d12 --help;
    // busybox --help; BSD man (same option family plus `-D --all-repeated
    // [septype]`).
    "uniq": { readOnly: true, operandsAreData: true, grammar: { args: 'getopt',
            flags: ['-c', '--count', '-d', '--repeated', '-u', '--unique', '-i', '--ignore-case', '-z',
                '--zero-terminated', '-D'],
            valueFlags: ['-f', '--skip-fields', '-s', '--skip-chars', '-w', '--check-chars'],
            optionalValueFlags: ['--all-repeated'],
            optionsBeforeOperands: true,
            operands: { max: 1 } } },
    "uptime": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured busybox/BSD: prints load average and boot time; no write mode' } },
    "vmstat": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: "documented (procps vmstat(8): 'requires read access to /proc'): reports virtual-memory statistics; no write mode" } },
    "wc": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: counts lines, words and bytes of input; no write mode' } },
    "whereis": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: searches PATH directories for binaries, sources and manuals; no write mode' } },
    "which": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: locates a binary on PATH; no write mode' } },
    "who": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: lists logged-in sessions from utmp; no write mode' } },
    "whoami": { readOnly: true, operandsAreData: true, grammar: { args: 'any', audit: 'measured GNU/BSD: prints the effective username; no write mode' } },
};
/** The class half of READERS, as the shape its consumers already expect. */
const READ_ONLY_ALLOWLIST = new Set(Object.entries(READERS).filter(([, e]) => e.readOnly).map(([name]) => name));
// Deliberately NOT read-only: `env`, because it is an exec wrapper. `env <cmd>`
// runs <cmd>, so allowlisting the name `env` vouched for a command the
// classifier never looked at — `env sudo rm -f /etc/passwd` classified
// `read-only` and ran on a profile whose whole contract is that it cannot
// write. It carries no shell metacharacter, so the SHELL_CONTROL_CHARS gate
// below did not catch it either. Falls through to `safe`, so run-command can
// still reach it under policy; a bare `env` that only prints the environment
// loses read-only status with it, which is the price of a name-based allowlist.
//
// Deliberately NOT read-only: `curl` and `wget` fetch arbitrary URLs (SSRF to
// cloud metadata / internal services), post local files to a remote host
// (`curl -d @/etc/passwd`), and write remote files (`curl -o`, `wget -O`) —
// none of which need a shell metacharacter to escape the classifier. They fall
// through to the `safe` class, so run-command can still use them under policy.
//
// Residual risk kept on purpose: dig/nslookup/host/ping/traceroute can leak
// small amounts of data through DNS/ICMP queries. They cannot modify the host,
// so they stay read-only; tighten them via profile policy if egress matters.
/**
 * The SFTP read verbs, which the tool layer synthesises rather than a caller typing.
 *
 * A second set rather than two more entries in READ_ONLY_ALLOWLIST, and the
 * reason is that that Set is dual-purpose: `operandsAreData` reads it too, to
 * decide whether a segment's operands are data rather than commands. Putting
 * these verbs there silenced the carrier scan for them — measured,
 * `sftp:list /tmp sh -c 'sudo id'` fell from `privileged` to `read-only`,
 * because `nestedCommands` stopped extracting the `sh -c` payload. That is the
 * one carrier form carrying no character from SHELL_CONTROL_CHARS, i.e. exactly
 * the form the scan is load-bearing for.
 *
 * The suppression buys nothing here anyway. It exists so `grep python3 -c file`
 * is not read as invoking python; these verbs take a path nobody parses, so
 * there is no false positive to suppress.
 *
 * Why they are lowered at all: both carry `readOnlyHint: true`, the README marks
 * both read-only, `sftp-list`'s description ends "Read-only." — and `safe` is
 * refused outright by a `readOnly` profile, so the one profile class the
 * annotation targets was the one that could not run them (#217).
 * (`sftp-download`'s description makes no read-only claim; an earlier version of
 * this paragraph said both did, which is the overstatement this file keeps
 * catching.) The lowering grants that
 * profile nothing new: `cat /etc/shadow` and `ls /root` are already `read-only`,
 * so the authority to read any file the SSH user can read is already held.
 *
 * `sftp:upload`, `sftp:upload-file` and `sftp:download-file` stay out — the
 * first two write on the remote host, the third inside the transfer root.
 */
const READ_ONLY_SYNTHETIC = new Set(['sftp:list', 'sftp:download']);
/**
 * Commands that are never allowed, whatever the role or approval policy.
 *
 * This is the policy engine's denylist — the regex half of it. The word-based
 * rules live below in FORBIDDEN_RULES, and the write-path families in
 * never-allowed-writes.ts, which both the rules and the engine's resource
 * check read. The
 * engine used to keep a parallel copy as regex *strings*, which had already
 * drifted (it was missing the fork bomb and the recursive chown, and its `rm`
 * pattern was narrower). Anything here is also destructive for classification
 * purposes; see DESTRUCTIVE_DENYLIST below.
 */
/*
 * These are the patterns that stayed regexes, and every one of them is linear.
 *
 * The four that were not — `dd\s.*\bof=/dev/`, the two `curl|wget …\|\s*(sh…)`
 * forms, and `chown\s+-R\s.*\s/\s*$` — are now segment checks below. An earlier
 * comment here reasoned that ambiguity *within* a match was the only cost, and
 * that was wrong: the engine also restarts at every offset where the cheap
 * literal head matches, so a command built from `dd curl wget chown -R x `
 * repeated ran at 4x per doubling. Measured on the real chain: 64 KB took
 * 255 ms, 1 MB took 65 seconds of blocked event loop, and the stall lands in
 * classifyCommand — before the approval gate and before the allow/deny
 * decision, so no role, approval mode or readOnly flag protects against it.
 *
 * The old note said sanitizeCommand's maxChars cap kept this cheap, "but a
 * policy check should not depend on a limit set three layers away and
 * configurable to any value". Once a config file could say `commandMaxChars = 0`
 * (#123) that limit went away, and the prediction came true. The rewrite below
 * is what that sentence was asking for: the policy check is now safe on its own
 * terms, whatever maxChars says.
 *
 * The existing cost test did not catch it because its seeds are runs of spaces,
 * which never match the literal heads and so never trigger the restart.
 */
const FORBIDDEN_PATTERNS = [
    // The four operation rules that used to live here — `rm -rf /`, `mkfs…`,
    // `iptables -F`, `chmod -R 777 /` — are segment checks in FORBIDDEN_RULES
    // now (GHSA-5cjr-rc2p-f66f): as text regexes each matched exactly one
    // spelling, and `rm -fr /` or `mkfs -t ext4 /dev/sda1` classified `safe` —
    // the one class the default approval policy never prompts on.
    //
    // The same move deliberately LOOSENS the old rules' mention side: a text
    // regex refused any substring, so `echo 'rm -rf /'` and a grep quoting
    // `iptables -F` were denied as though they were invocations. The
    // head-gated rules refuse the operation and allow the mention, which is
    // the direction this file's invocation-word machinery already chose (#91)
    // — pinned in never-allowed-spellings.test.ts so the loosening is a
    // decision on record rather than a surprise.
    />\s*\/dev\/sd/,
    // Fork bomb, with whitespace allowed at the five positions bash allows it and the old
    // pattern did not: before the parentheses, inside them, either side of the pipe, and
    // before the ampersand. `: () { : | : & } ; :` ran and classified `safe`.
    //
    // What this still does not catch, so that nobody reads it as "fork bombs are handled":
    // the same bomb under another name (`f(){ f|f& };f`), a body that separates the two
    // calls with `&` or `;` rather than `|` (`:(){ :&:& };:`), and a comment between the
    // tokens (`:() # x\n{ :|:& };:`). Matching the first needs a backreference over an
    // unbounded body and this file has already shipped one ReDoS; the others would widen a
    // list no role, tier or approval mode can override. The impact is a denial of service
    // against the target host rather than against this server, which is not worth either
    // trade — but it is a hole, not a closed door.
    /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
];
/**
 * Words that are forbidden when *invoked*, which the patterns above cannot
 * express.
 *
 * These used to be `/\breboot\b/` and friends, matching the word anywhere in
 * the string. `last reboot` reads a log and was refused for containing the
 * word; so were `grep -r reboot /etc/`, `cat /var/run/reboot-required` and
 * `journalctl | grep shutdown`. On a NAS an agent checking boot history trips
 * this on its first command, which is how it was reported (#91).
 *
 * Matching an invocation rather than a mention needs to know where a command
 * word can start, and that is a tokenizer's job, not a regex's — the regex
 * forms that come close all reintroduce the `\S*` backtracking the block above
 * exists to avoid.
 */
const FORBIDDEN_INVOCATIONS = new Set(['shutdown', 'reboot', 'halt', 'poweroff', 'eval']);
/** Binaries that take the dangerous action as an argument: `systemctl reboot`. */
const ACTION_MULTIPLEXERS = new Set(['systemctl', 'init', 'telinit']);
/**
 * Binaries that run the rest of the command as another user.
 *
 * The list is explicit rather than a pattern, because a pattern cannot tell
 * `sudoedit` — which edits a file and is not elevation — from `sudo-rs`, which
 * is sudo. It has to be maintained by hand as new implementations appear; the
 * cost of missing one is that its commands classify `safe`.
 *
 * The last five were added in 2.2.5 (#132). Until 2.2.4 the check was
 * `/^\s*su\b/` and friends, and `\b` matched between `su` and the hyphen, so
 * `su-exec` and `sudo-rs` were caught — by accident of the regex, not by
 * intent. Moving to exact membership dropped them, which narrowed a security
 * control inside a security release. `gosu` and `run0` were never caught by
 * either form.
 */
/**
 * Class ordering, so a command that contains another can take the higher of the two.
 *
 * Only used by the nesting scan below. Everything else in this file decides a single
 * class outright.
 */
const CLASS_RANK = {
    'read-only': 0,
    safe: 1,
    destructive: 2,
    privileged: 3,
};
const INTERPRETERS = Object.assign(Object.create(null), {
    sh: { programBearingWords: ['-c'], readable: true },
    bash: { programBearingWords: ['-c'], readable: true },
    dash: { programBearingWords: ['-c'], readable: true },
    zsh: { programBearingWords: ['-c'], readable: true },
    ksh: { programBearingWords: ['-c'], readable: true },
    ash: { programBearingWords: ['-c'], readable: true },
    python: { programBearingWords: ['-c'], readable: false },
    python2: { programBearingWords: ['-c'], readable: false },
    python3: { programBearingWords: ['-c'], readable: false },
    perl: { programBearingWords: ['-e', '-E'], readable: false },
    ruby: { programBearingWords: ['-e'], readable: false },
    // `-p`/`--print` evaluate exactly as `-e` does and then print the result.
    node: { programBearingWords: ['-e', '--eval', '-p', '--print'], readable: false },
    php: { programBearingWords: ['-r'], readable: false },
    // Measured on 2.11.0: each of these classified `safe` while the identical
    // attack through python3 -c classified `destructive` (GHSA-qmx6-47vm-3vf7).
    // `readable: false` throughout, matching python/perl/node: the program is not
    // shell text, so its presence is what counts rather than its content.
    osascript: { programBearingWords: ['-e'], readable: false },
    lua: { programBearingWords: ['-e'], readable: false },
    Rscript: { programBearingWords: ['-e'], readable: false },
    bun: { programBearingWords: ['-e'], readable: false },
    // No program-bearing flag: real tclsh takes a script FILE as its positional
    // argument or reads one from stdin, unlike sh/bash/python/pwsh, none of
    // which have a `-c` of its own. An empty list still marks tclsh as an
    // unreadable interpreter for `readsProgramFromStdin` (`echo … | tclsh`),
    // which is the genuine carrier; it is simply never handed a program inline
    // on its own command line, so there is no flag to name here.
    tclsh: { programBearingWords: [], readable: false },
    // `eval` is a subcommand, not a flag — the field is named for what it holds.
    deno: { programBearingWords: ['eval'], readable: false },
    pwsh: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
    powershell: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
    // The same gap as the osascript/lua block above, measured on 2.19.1
    // (GHSA-cm4c-4q74-mgmj): `gdb -ex`, `expect -c` and `vi/vim/ex -c` each
    // hand a program to an executor and each classified `safe` — the one class
    // that never reaches the approval gate. `readable: false` throughout: the
    // program is gdb command language / expect / ex, not shell text, so its
    // presence is what counts, exactly like python's `-c`.
    gdb: { programBearingWords: ['-ex', '--eval-command', '-iex', '--init-eval-command'], readable: false },
    expect: { programBearingWords: ['-c'], readable: false },
    vi: { programBearingWords: ['-c', '--cmd'], readable: false },
    vim: { programBearingWords: ['-c', '--cmd'], readable: false },
    ex: { programBearingWords: ['-c', '--cmd'], readable: false },
    view: { programBearingWords: ['-c', '--cmd'], readable: false },
    gvim: { programBearingWords: ['-c', '--cmd'], readable: false },
    vimdiff: { programBearingWords: ['-c', '--cmd'], readable: false },
});
/**
 * Every `INTERPRETERS` entry, keyed by its name lower-cased.
 *
 * A second index rather than lower-casing the lookup key against `INTERPRETERS`
 * directly, because that table's own keys are not uniformly lower-case —
 * `Rscript` is not `rscript` — so folding only the *input* would still miss it.
 * Built once at module load: the table is fixed, so there is nothing to keep in
 * sync.
 */
const INTERPRETERS_BY_LOWERCASE_NAME = Object.assign(Object.create(null), Object.fromEntries(Object.entries(INTERPRETERS).map(([name, spec]) => [name.toLowerCase(), spec])));
/** A Windows executable suffix this table's keys never carry. */
const WINDOWS_EXE_SUFFIX = /\.(exe|cmd|bat)$/i;
/**
 * Resolve an interpreter table entry for a command word already stripped of
 * its path (`stripPath(unquote(word))`, as every call site already computes
 * it for the exact-match case below).
 *
 * The table's keys are exact, case-sensitive, extension-free spellings, so a
 * direct lookup is tried first and is the whole cost for the common case —
 * `sh`, `python3`, the bare lowercase `pwsh`. The fallback strips a trailing
 * `.exe`/`.cmd`/`.bat` and folds case, which is what a Windows target's own
 * shell hands back for the *same* binary: `powershell.exe`, `PWSH.EXE` and
 * `PowerShell` all name the interpreter this table already lists under
 * `powershell`/`pwsh`.
 *
 * Applied to every entry, not only pwsh/powershell. The measured bug is
 * about those two, but the gap is not specific to them: a target running
 * `python.exe` or `Node.EXE` carries the identical mismatch, and scoping the
 * fix to two names would leave the rest of the table exactly as blind as it
 * was. This is the binary-*name* question, answered once — it does not touch
 * flag matching, which stays case-sensitive per interpreter (`perl -E` and
 * `perl -e` are still two different flags) via the existing, separate
 * `caseInsensitive` parameter threaded through `programAfterFlag` and
 * friends.
 */
function resolveInterpreter(word) {
    const exact = INTERPRETERS[word];
    if (exact !== undefined)
        return exact;
    return INTERPRETERS_BY_LOWERCASE_NAME[word.replace(WINDOWS_EXE_SUFFIX, '').toLowerCase()];
}
/** `find … -exec <cmd> +` runs cmd. */
const FIND_EXEC_FLAGS = new Set(['-exec', '-execdir', '-ok', '-okdir']);
/**
 * GNU sort's own long-option table, spelled in full — every entry `sort
 * --help` lists (coreutils 9.11, `docker exec ssh-mcp-ssh-admin-1 sort
 * --help`). Used only to compute which prefixes of `--output` and
 * `--compress-program` `getopt_long` treats as unambiguous.
 *
 * `getopt_long` resolves a `--` word to the option whose name it is an
 * unambiguous prefix of: a prefix shared with another option name is
 * refused outright ("option '--c' is ambiguous; possibilities: '--check'
 * '--compress-program'") rather than run, so it must not be treated as a
 * write. Measured against the binary: `sort --c=x k` exits 2 with no file
 * created; `sort --co=x k` — the second letter is where `--check` and
 * `--compress-program` diverge — runs.
 */
const SORT_LONG_OPTIONS = [
    'ignore-leading-blanks', 'dictionary-order', 'ignore-case',
    'general-numeric-sort', 'ignore-nonprinting', 'month-sort',
    'human-numeric-sort', 'numeric-sort', 'random-sort', 'random-source',
    'reverse', 'sort', 'version-sort', 'batch-size', 'check',
    'compress-program', 'debug', 'files0-from', 'key', 'merge', 'output',
    'stable', 'buffer-size', 'field-separator', 'temporary-directory',
    'parallel', 'unique', 'zero-terminated', 'help', 'version',
];
/**
 * The regex-alternation source matching any prefix of `full` that names
 * exactly one entry of `SORT_LONG_OPTIONS` — every prefix `getopt_long`
 * would accept for it, from the shortest unambiguous one up to `full`
 * itself — each optionally followed by `=value`.
 */
function unambiguousLongOptionSource(full) {
    const prefixes = [];
    for (let len = 1; len <= full.length; len++) {
        const prefix = full.slice(0, len);
        if (SORT_LONG_OPTIONS.filter((opt) => opt.startsWith(prefix)).length === 1) {
            prefixes.push(prefix);
        }
    }
    return `--(?:${prefixes.join('|')})(?:=|$)`;
}
/**
 * How deep a substitution may nest before we stop reading and refuse to guess.
 *
 * Reached only by input no operator writes — the tests use two hundred levels. The
 * fallback is `privileged` rather than a lower class because the entire point of
 * this scan is that a command we cannot read must not be treated as one we can.
 */
const MAX_NESTING_DEPTH = 8;
/**
 * Split a command into segments of words, resolving quoting as a shell would.
 *
 * The classifier's regexes were written against the command as sent, but the transport
 * removes quoting before the command runs, so `rm -rf "/etc"` matched no destructive
 * pattern and `s"u"do id` named no privilege prefix. Every consumer that used to split on
 * `/[;&|\n]/` and `/\s+/` reads this instead, so quote removal happens once, in one
 * place, rather than being re-derived per rule.
 *
 * Not a shell parser. Variable expansion, arithmetic and here-documents are out of scope —
 * `hasUnnameableCommand` is what refuses a command word this cannot resolve.
 */
function tokenizeSegments(command, dialect = 'posix') {
    return tokenizeSegmentsDetailed(command, true, dialect).map((segment) => segment.words);
}
/** Inside double quotes, the characters POSIX lets a backslash escape. */
const DOUBLE_QUOTE_ESCAPABLE = new Set(['$', '`', '"', '\\', '\n']);
/**
 * The same split, keeping the separator that introduced each segment.
 *
 * Only the pipe rules need it: `|` feeds one command's output into the next, while `;`
 * and `&` merely sequence, and a rule about pipes must not fire on a rule about sequences.
 * Deriving both views from one tokeniser is what stops the two from drifting apart.
 */
function tokenizeSegmentsDetailed(command, honorQuotes = true, dialect = 'posix') {
    const segments = [];
    let pending = '';
    let words = [];
    let current = '';
    let quote = null;
    let escaped = false;
    /**
     * Whether the word being built was quoted, so an *empty* one survives.
     *
     * `if (current)` alone dropped it, and a dropped word is not cosmetic for
     * anything that reads arguments by position: `awk -F '' 'BEGIN{system("sudo
     * id")}'` arrived as three words instead of four, so the awk reader consumed
     * the program as `-F`'s value and reported that the invocation ran no program
     * — `safe`, for a command real awk runs. Measured on BWK awk 20200816: it
     * warns "field separator FS is empty" on stderr and then executes both the
     * `system()` call and a file redirection.
     *
     * Only a *quoted* empty survives. Pushing every empty `current` would emit a
     * word per run of whitespace, which is not what a shell does.
     */
    let quotedWord = false;
    const endWord = () => {
        if (current || quotedWord)
            words.push(current);
        current = '';
        quotedWord = false;
    };
    const endSegment = (sep) => {
        endWord();
        if (words.length > 0)
            segments.push({ words, sep: pending });
        words = [];
        pending = sep;
    };
    for (let i = 0; i < command.length; i++) {
        const ch = command[i];
        if (escaped) {
            // A backslash quotes the next character, so `\reboot` runs reboot. Keeping the
            // character and dropping the backslash is what the shell does.
            current += ch;
            escaped = false;
            continue;
        }
        if (quote) {
            // Backslash is literal inside single quotes; inside double quotes it escapes.
            if (dialect === 'posix' && ch === '\\' && quote === '"') {
                const next = command[i + 1];
                // POSIX keeps `\x` before an ordinary character: only $ ` " \ and a
                // newline are escapable, so the backslash survives into the word
                // (GHSA-972x-g47g-3922's second finding — dropping it misread both
                // dialects at once). At end of string there is no next character to
                // protect, and the open quote sends the whole scan to the fallback.
                if (next === undefined || DOUBLE_QUOTE_ESCAPABLE.has(next)) {
                    escaped = true;
                    continue;
                }
                current += ch;
                continue;
            }
            if (ch === quote)
                quote = null;
            else
                current += ch;
            continue;
        }
        if (dialect === 'posix' && ch === '\\') {
            escaped = true;
            continue;
        }
        if (honorQuotes && (ch === '"' || ch === "'")) {
            quote = ch;
            quotedWord = true;
            continue;
        }
        if (ch === ';' || ch === '&' || ch === '|' || ch === '\n') {
            endSegment(ch);
            continue;
        }
        if (/\s/.test(ch)) {
            endWord();
            continue;
        }
        current += ch;
    }
    endSegment('');
    // A quote left open at the end is not a command a shell would run — it is a syntax
    // error. Reading it as one long quoted argument is the dangerous reading: `echo "hi;
    // sudo id` then never splits on the `;` and the elevation disappears, which measured as
    // `privileged` before this tokeniser and `safe` after. So fall back to the scan that
    // treats the quote character as ordinary text, which splits and still sees `sudo id`.
    if (quote !== null)
        return tokenizeSegmentsDetailed(command, false, dialect);
    return segments;
}
/**
 * The command rebuilt from its tokens, for the regex rules to match against.
 *
 * Segments are rejoined with `; ` so a pattern cannot match across two commands that the
 * shell would run separately.
 */
const normalizedCache = new Map();
function normalizeCommand(command, dialect) {
    // One evaluate asks for this about nineteen times, once per regex rule, and each ask
    // re-ran the tokeniser over the whole command. The asks arrive in a row on the same
    // input, so a small cache, evicting the oldest inserted entry, removes almost
    // all of it. The key carries the dialect because both readings of one command
    // are asked about in the same row.
    const key = `${dialect}\u0000${command}`;
    const hit = normalizedCache.get(key);
    if (hit !== undefined)
        return hit;
    const value = normalizeUncached(command, dialect);
    normalizedCache.set(key, value);
    if (normalizedCache.size > 8) {
        normalizedCache.delete(normalizedCache.keys().next().value);
    }
    return value;
}
function normalizeUncached(command, dialect) {
    return tokenizeSegments(command, dialect)
        .map((words) => words.map((w) => (QUOTED_CONTENT.test(w) ? PLACEHOLDER : w)).join(' '))
        .join('; ');
}
/**
 * A character the tokeniser splits on or at, which a token can only hold if it was quoted.
 *
 * The tokeniser splits on unquoted separators and at unquoted whitespace, so a token
 * holding either came from inside quotes — the shell will not split there, and its contents are data. Rejoining it
 * into the pattern text is what makes an argument read as a command: `echo "hello; rm -rf
 * /"` prints a string, and normalising it produced `echo hello; rm -rf /`, which matched
 * the never-allowed list. Dropping those tokens keeps quote removal doing the job it was
 * added for — `rm -rf "/etc"`, whose tokens hold no separator — without letting a quoted
 * argument impersonate a command. A carrier that really does hand over a quoted command
 * (`sh -c "ls; rm -rf /etc"`) is read by `nestedCommands`, not by this.
 */
const QUOTED_CONTENT = /[\s;&|\n]/;
/**
 * What a quoted token becomes in the pattern text.
 *
 * Deleting it instead spliced its neighbours together and created an adjacency that appears
 * nowhere in the command: `echo rm 'a|b' -rf /` normalised to `echo rm -rf /` and landed on
 * the never-allowed list. A character no pattern contains and `\s` does not match stands in
 * its place, so the two sides can no longer be read as one phrase.
 */
const PLACEHOLDER = '\u0000';
/**
 * Try a regex against the command as written and against the tokenised form.
 *
 * Normalising alone is not enough. It rebuilds the command from tokens, so the shell
 * metacharacters between them are gone, and a pattern that matches across a separator no
 * longer fires — the fork bomb, whose `:|:&` needs the literal `|` and `&`, is the case
 * that shows this. Normalising is still what defeats `rm -rf "/etc"`. Neither form is a
 * superset of the other, so both are tried: for a pattern whose whole job is to notice
 * something, the union is the only direction that cannot lose a match.
 *
 * Deliberately scoped to regexes. The word-based rules in `FORBIDDEN_RULES` already
 * tokenise, and handing them the normalised string turns a separator that was safely
 * inside a quoted argument into a real one — `grep -E "warn|reboot" syslog` became an
 * unconditional refusal, which is the mention-vs-invocation bug of #91 all over again.
 */
function matchesEitherForm(command, test, dialect) {
    return test(command) || test(normalizeCommand(command, dialect));
}
/**
 * The commands hiding inside a command.
 *
 * The elevation scan reads tokens produced by splitting on `;&|` and whitespace, so
 * it only ever saw the outer command: `echo $(sudo id)` tokenised to
 * `["echo", "$(sudo", "id)"]`, `echo` was taken to be the real command, and no
 * elevation was found (GHSA-v8jh-gv7v-3gvq). The destructive scan never had this
 * problem because it reads the raw text — which is why `echo $(rm -rf /)` was
 * classified correctly the whole time. This closes that asymmetry by pulling the
 * inner commands out so they can be classified in their own right.
 *
 * Four carriers, all of which a remote shell expands and runs:
 *   `$(...)`, backticks, process substitution `<(...)` / `>(...)`, and a shell
 *   given `-c`.
 *
 * @param speculativeOperands Whether the catch-all below — any multi-word,
 *   non-flag operand of a segment no more specific reader claimed — should be
 *   pushed. That catch-all is a guess about a binary this file does not
 *   recognise; the four carriers above are not guesses, the shell really does
 *   run what they hold, and are pushed regardless of this flag. Defaults to
 *   `true` for `classifyCommand`'s own recursion, where a guess may raise a
 *   command's *class* and leave role, tier and approval to weigh in.
 *   `findForbiddenMatch` passes `false`: its recursion feeds
 *   `FORBIDDEN_RULES`, the one unconditional denylist, and a guess must not
 *   be able to produce a refusal nobody can override (the maintainer's
 *   ruling — see the block comment above `findForbiddenMatch`). `$()`,
 *   backticks and `sh -c` are certain carriers and keep reaching the
 *   denylist either way.
 */
function nestedCommands(command, speculativeOperands = true, dialect = 'posix') {
    const found = [];
    // `$(...)`, `<(...)`, `>(...)` — scanned rather than matched, because a regex
    // cannot balance parentheses and `echo $(echo $(sudo id))` is the case that
    // matters most.
    for (let i = 0; i < command.length; i++) {
        const opensSubstitution = command[i] === '$' && command[i + 1] === '(';
        const opensProcess = (command[i] === '<' || command[i] === '>') && command[i + 1] === '(';
        if (!opensSubstitution && !opensProcess)
            continue;
        // `$((1 + 1))` is arithmetic, not a command. Skipping it keeps the approval
        // prompt off `echo $((1 + 1))`.
        if (opensSubstitution && command[i + 2] === '(')
            continue;
        let depth = 0;
        for (let j = i + 1; j < command.length; j++) {
            if (command[j] === '(')
                depth++;
            else if (command[j] === ')') {
                depth--;
                if (depth === 0) {
                    found.push(command.slice(i + 2, j));
                    i = j;
                    break;
                }
            }
        }
    }
    // Backticks. No nesting to balance — the shell requires escaping to nest them.
    const backticks = command.match(/`([^`]*)`/g);
    if (backticks) {
        for (const raw of backticks)
            found.push(raw.slice(1, -1));
    }
    // A carrier hands a program to something that runs it. Carries no substitution, so the
    // scan above does not see it. Read each segment's command word rather than scanning
    // every word: matching a mention rather than an invocation is #91, and
    // `cat /usr/bin/python3` names an interpreter without running one.
    const segments = tokenizeSegmentsDetailed(command, true, dialect);
    for (const { words } of segments) {
        // Every word, not just the command word. Stopping at the head lost the carrier behind
        // any wrapper this file does not list: `xargs -I {} sh -c 'sudo id'` stops on `{}`, and
        // `flock`, `chroot`, `nsenter` and `systemd-run` are not wrappers it knows — all six
        // went from `privileged` to `safe`. What keeps this from matching a *mention* is not
        // where it looks but what it requires: `programAfterFlag` returns null unless a
        // program-bearing flag actually follows, so `cat /usr/bin/python3` carries nothing.
        //
        // awk is handled below rather than in this loop, and the difference is the
        // point: this loop reads *every* word so a carrier behind an unlisted
        // wrapper is not lost, and doing that to awk is what made `man awk`
        // destructive. awk's program is a positional operand, so the only evidence
        // it was invoked is that it is the segment's command word (#184).
        const awk = awkFindings(words);
        for (const inner of awk?.commands ?? [])
            found.push(inner);
        // A pipe target is classified too, so `print … | "sudo tee /etc/passwd"`
        // still names `tee`. Whether the *direction* makes it worse is decided in
        // hasDangerousAwk, which is where this file already keeps that rule.
        for (const inner of awk?.pipedInto ?? [])
            found.push(inner);
        if (!operandsAreData(words)) {
            // Which operand *indices* an interpreter actually consumed as a program —
            // not whether the segment's head happens to be a name in the table, and not
            // a single segment-wide flag either. A set of indices rather than a boolean:
            // `unknownbin sh -c true 'sudo id'` has `sh -c` consume `true` (harmless,
            // pushed below) and leave `'sudo id'` untouched, and a boolean here defused
            // the catch-all for that second operand too — measured, it classified
            // `safe`. Only the specific word an interpreter actually read should be
            // excluded from the catch-all; every other operand in the segment is still
            // this binary's own, unclaimed by anything more specific.
            //
            // A binary being recognised is also not the same as this segment's
            // invocation of it being one the loop could parse:
            // `pwsh -ExecutionPolicy Bypass -Command 'sudo id'` has a recognised head
            // and a program on the line, but `-ExecutionPolicy` takes a value
            // (`Bypass`) that isn't itself a flag, and `programAfterFlag` gives up
            // rather than guess past it. Gating the catch-all below on "head is in the
            // table" excluded exactly the binaries this file just learned, and for
            // precisely the invocations its own flag-walk cannot follow — a net
            // regression, not a wash.
            const consumedOperands = new Set();
            for (let i = 0; i < words.length; i++) {
                const spec = resolveInterpreter(stripPath(unquote(words[i])));
                // pwsh/powershell's own parameter binder resolves `-ENC`/`-Enc`/`-enc` to the
                // same parameter; every other interpreter's flags are exact letters (`-E` and
                // `-e` are different flags to perl). `-EncodedCommand` only ever appears on
                // the two entries whose own parameter binder works this way, so its presence
                // is the signal for which interpreter this is, not a hardcoded name check.
                const caseInsensitive = spec?.programBearingWords.includes('-EncodedCommand') ?? false;
                if (spec === undefined || isFlagValue(words, i, spec.programBearingWords, caseInsensitive))
                    continue;
                // Same signal, second job: pwsh/powershell's argument parser also does not stop
                // at an unrecognised option's bare value (`-ExecutionPolicy Bypass`) the way a
                // POSIX interpreter stops at its first positional argument. See
                // `programAfterFlag`'s `tolerateUnknownWordsAtHead` for why this is scoped to
                // `i === 0` there rather than here.
                const result = programAfterFlag(words, i, spec.programBearingWords, caseInsensitive, caseInsensitive);
                if (result !== null) {
                    consumedOperands.add(result.index);
                    found.push(result.program);
                    // An encoded program is opaque to every text scan until it is decoded. Gated on
                    // the word `programAfterFlag` actually matched — the table's own canonical
                    // spelling, so every case-folded or clustered form of `-EncodedCommand`/`-e`
                    // reaches this the same way a literal `-EncodedCommand` does — not a scan of
                    // the whole segment for one long spelling.
                    if (caseInsensitive && (result.flag === '-EncodedCommand' || result.flag === '-e')) {
                        const decoded = decodedPowerShellCommand(result.program);
                        if (decoded !== null)
                            found.push(decoded);
                    }
                }
            }
            // An operand of a binary nothing more specific has read is classified as a
            // command in its own right, rather than scanned as text.
            //
            // The gate is the awk reader's own result, and now which specific operands
            // an interpreter actually consumed, rather than a list of names: a name
            // list here would be the defect this change exists to fix
            // (GHSA-qmx6-47vm-3vf7), and "the head is a name in the table" turned out
            // to be one too — it answers a different question than "did this
            // invocation's program-bearing word actually resolve". `awk` is already
            // null for every non-awk segment.
            //
            // Whitespace is what separates an operand worth classifying from one that is
            // not: a single token is a path, a flag value or a subcommand, while a
            // multi-word operand has the shape of a command. Flags are skipped.
            //
            // Deliberately NOT a text scan for `sudo`. That version asserted elevations
            // the awk reader and the variable-command-word logic refuse to assert — both
            // cap at `destructive` on purpose — and it out-ranked the nested
            // classification that names the elevated binary, reporting `awk` where `id`
            // was correct.
            if (speculativeOperands && awk === null) {
                // A command-bearing environment assignment at the head is the one
                // head-position word this loop may read. Every other head word IS the
                // command, and an assignment under any other name is data: FOO="sudo id"
                // cmd runs cmd, not sudo. GIT_SSH_COMMAND="sudo id" git fetch runs sudo,
                // because git execs what that variable names — and so does every other
                // variable in the set below, each through a documented consumer
                // (GHSA-5m7x-xwpc-pp79).
                const headAssignment = ENV_COMMAND_ASSIGNMENT.exec(words[0] ?? '');
                if (headAssignment !== null && /\s/.test(headAssignment[2])) {
                    found.push(headAssignment[2]);
                }
                for (let i = 1; i < words.length; i++) {
                    if (consumedOperands.has(i))
                        continue;
                    const word = words[i];
                    if (word.startsWith('-')) {
                        // A value attached with `=` is still a value: the separated spelling
                        // `--rsync-path "sudo rsync"` reached the push below as an ordinary
                        // operand, but the attached `--rsync-path="sudo rsync"` starts with
                        // `-` and was skipped whole, so the attached spelling of a
                        // value-taking option carried nothing while its separated spelling
                        // classified `privileged` (GHSA-5m7x-xwpc-pp79).
                        const eq = word.lastIndexOf('=');
                        if (eq !== -1 && /\s/.test(word.slice(eq + 1)))
                            found.push(word.slice(eq + 1));
                        continue;
                    }
                    // A carrier's value arrives with the key still glued to the command
                    // it runs — `core.pager=sudo id` (git -c), `+!sudo id` (less),
                    // `system("sudo id")` (cpan) — and the nested classification read
                    // `core.pager=sudo` as a binary that does not exist, settling at
                    // `safe`. Push the command the carrier would run, not the glue
                    // (GHSA-5m7x-xwpc-pp79). Ordinary operands carry none of this glue
                    // and push exactly as they always have.
                    const inner = stripGluedCommandPrefix(word);
                    if (/\s/.test(inner))
                        found.push(inner);
                }
            }
        }
        // `-exec` is a flag rather than a command word, so this one is still a scan.
        for (let i = 0; i < words.length; i++) {
            if (!FIND_EXEC_FLAGS.has(words[i]) || words[i + 1] === undefined)
                continue;
            const rest = words.slice(i + 1);
            const stop = rest.findIndex((w) => w === '+' || w === ';');
            found.push((stop === -1 ? rest : rest.slice(0, stop)).join(' '));
            // Step past what was consumed. Leaving `i` where it was emitted one child per
            // `-exec` token, each an overlapping suffix of the last and each still holding the
            // rest of them, so the recursion re-expanded the same tail once per token: twenty
            // `-ok` tokens in 81 bytes cost 17 seconds of a single-threaded event loop.
            i = stop === -1 ? words.length : i + 1 + stop;
        }
        // Two carriers whose program is embedded inside a single word, as shell
        // text this file can read, so the carried command is classified as itself
        // (GHSA-cm4c-4q74-mgmj). The speculative-operand catch-all above cannot
        // see either one: a `--checkpoint-action=exec=…` word starts with `-`, and
        // the sqlite3 dot-command is only ever one word to begin with. Both
        // helpers are head-gated, so an operand that merely mentions the spelling
        // carries nothing.
        found.push(...tarCheckpointExecPrograms(words));
        found.push(...sqliteShellPrograms(words));
    }
    // A pipe stage whose command word is an interpreter with no program of its own runs
    // whatever the previous stage printed. Starts at 1: a leading `|` records its separator
    // on the first segment, and reading `segments[-1]` threw.
    for (let i = 1; i < segments.length; i++) {
        if (segments[i].sep !== '|')
            continue;
        if (!readsProgramFromStdin(segments[i].words))
            continue;
        found.push(segments[i - 1].words.join(' '));
    }
    return found.filter((c) => c.trim().length > 0);
}
const PRIVILEGE_PREFIXES = new Set([
    'sudo', 'su', 'doas', 'pkexec',
    // BusyBox/Alpine, Docker entrypoints, the Rust sudo now default on some
    // distributions, systemd's replacement, and the Solaris/illumos spelling.
    'su-exec', 'gosu', 'sudo-rs', 'run0', 'pfexec',
    // Both reach root with the command otherwise classified `safe`.
    'runuser', 'setpriv',
]);
/**
 * Binaries whose job is to run another command.
 *
 * The allowlist and the privilege check both name a binary, so a wrapper hides
 * whatever it wraps: `env sudo id` was classified by the name `env`. These are
 * stepped over when deciding whether a segment elevates, so the check sees the
 * command that will actually run.
 *
 * `env` is the one that was also allowlisted, and it has been removed from
 * READ_ONLY_ALLOWLIST above. The rest were never read-only, so before this they
 * hid elevation rather than granting it — `nohup sudo systemctl stop nginx`
 * classified `safe`, which the default bindings grant to admin and operator on
 * every tier.
 */
const EXEC_WRAPPERS = new Set([
    'env', 'nohup', 'nice', 'ionice', 'command', 'exec', 'setsid', 'stdbuf',
    'timeout', 'chrt', 'taskset', 'xargs', 'watch',
    // `busybox <applet>` runs the applet, so it wraps rather than interprets.
    'busybox',
    // Review round (GHSA-cm4c-4q74-mgmj): each of these runs the command it
    // wraps, and being absent here hid every head-keyed gate behind it —
    // `strace docker run --privileged …` and `flock make …` classified `safe`.
    // Also closes the pre-existing `strace sudo id` hole the same way.
    'strace', 'ltrace', 'valgrind', 'flock', 'chroot', 'perf', 'time',
]);
/**
 * Arguments that turn an allowlisted binary into one that writes or executes.
 *
 * The allowlist vouches for a name; these are the flags that make the name a
 * lie. `find /var/www -delete` removes a directory tree and `find / -exec sudo
 * id +` runs a command as root, and both classified `read-only` — the `-exec …
 * \;` form only escaped because `;` happens to be a shell metacharacter, while
 * the `+` terminator carries none.
 */
// Null-prototype for the same reason as INTERPRETERS: indexed by the command word.
const DISQUALIFYING_ARGS = Object.assign(Object.create(null), {
    find: /^-(exec|execdir|ok|okdir|delete|fprintf?|fls)$/,
    // GNU sort execs this for every temporary file it spills, so a reader
    // becomes a launcher. Measured against coreutils 9.11: an attacker-named
    // script ran 14,224 times for one 200k-line input, and the whole command
    // classified `read-only` — which a `readOnly` viewer is allowed to run,
    // while running that same program directly is denied.
    //
    // `-o FILE` / `--output=FILE` is the same shape of bug with a plainer
    // payoff: it creates and truncates FILE, which is a write a `readOnly`
    // profile must never reach through a command classified `read-only`.
    // Measured on HEAD before this rule: `sort -o /root/.ssh/authorized_keys
    // /tmp/key.pub` classified `read-only`.
    //
    // Targeted round (2026-09-24, R2+R3): the version above closed the exact
    // spellings `-o`, `--output` and `--compress-program` and left the CLASS
    // open — GNU sort's own option grammar has two escapes past a fixed
    // spelling, both measured against the real binary:
    //
    //  - A short-option cluster is scanned left to right, and any of sort's
    //    own *argument-less* short flags may sit ahead of `-o` without
    //    consuming it: `sort -mo out in` writes `out` exactly as `sort -o out
    //    in` does. `-m` (merge) is itself argument-less, and its absence from
    //    the char class below is exactly what let `sort -mo …` through as
    //    `read-only`.
    //  - `getopt_long` resolves a `--` word by unambiguous-prefix matching:
    //    `--o`, `--ou`, `--out`, `--outp`, `--outpu` all mean `--output`
    //    (nothing else starts with `o`), and `--co` through
    //    `--compress-progra` all mean `--compress-program` (`--c` alone is
    //    ambiguous with `--check` and sort refuses to run at all —
    //    `unambiguousLongOptionSource` excludes it for exactly that reason,
    //    computed from sort's own option table rather than hand-picked).
    //
    // The cluster branch is still deliberately narrower than "any `o` in a
    // dash word": `-[bcCdfghiMmnRrsuVz]*o` only allows GNU sort's own
    // argument-less short flags ahead of the `o`, so it stops at the first
    // flag that takes a value of its own. Without that, `-tofile` — `-t`
    // (field separator) with its value attached, not `-o` — would be
    // misread as a write. `-t`, `-k`, `-S` and `-T` are exactly the short
    // flags this excludes, because each consumes the rest of a clustered
    // word as its own argument, so a following `o` is that argument's text,
    // not `-o` invoked.
    //
    // `find`'s entry above does not get the same prefix-abbreviation
    // treatment: `find` parses its predicates itself rather than through
    // `getopt_long`, and accepts no abbreviated spelling of `-exec` — `find .
    // -exe` is "unknown predicate `-exe`", measured. There is no class to
    // close there.
    sort: new RegExp(`^(?:${unambiguousLongOptionSource('compress-program')}`
        + `|${unambiguousLongOptionSource('output')}`
        + '|-[bcCdfghiMmnRrsuVz]*o)'),
});
/** A leading `NAME=value`, which a shell treats as an assignment, not a command. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
/**
 * An assignment at the head whose value a documented consumer execs: the git
 * variables git hands to the shell, the editor and pager names every
 * terminal tool spawns, the browser an HTML page can ask to open, and the
 * askpass programs ssh and sudo run to obtain a password. `NAME=` anchored
 * and captured separately so the value cannot reach back into the name
 * (`GIT_SSH_COMMAND-X=…` is not that variable).
 */
const ENV_COMMAND_ASSIGNMENT = /^(GIT_SSH_COMMAND|GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_PAGER|GIT_EXTERNAL_DIFF|SSH_ASKPASS|SUDO_ASKPASS|EDITOR|VISUAL|PAGER|BROWSER)=(.*)$/;
/**
 * The command inside an operand whose key or call syntax is still glued to
 * its first word: everything through the last `=` (git -c `core.pager=`, apt
 * -o `Dpkg::Pre-Invoke::=`, an attached `--flag=`) or `(` (cpan
 * `system(…)`), then the prompt escapes less puts in front of `+!cmd`
 * (GHSA-5m7x-xwpc-pp79). A word carrying none of
 * that glue is returned unchanged, so the speculative-operand push keeps its
 * exact pre-existing behaviour for ordinary multi-word operands. A quote can
 * follow the cut — cpan's system("…") leaves `"sudo id")` — and would keep
 * the whole payload one token to the nested classification, so quotes strip
 * with the escapes.
 */
function stripGluedCommandPrefix(word) {
    // `$(…)`, `<(…)`, `>(…)`: the substitution scan already reads the inside
    // from the raw command, and cutting here would push the substituted command
    // behind a head the operand scan may recognise (`printf $(sudo id)`), whose
    // data-operand rule would hide the elevation the whole-word push used to
    // find. Walk back past substitution opens to the `system(` style of paren.
    const eq = word.lastIndexOf('=');
    let paren = word.lastIndexOf('(');
    while (paren > 0 && '$<>'.includes(word[paren - 1])) {
        paren = word.lastIndexOf('(', paren - 1);
    }
    const cut = Math.max(eq, paren);
    return (cut <= 0 ? word : word.slice(cut + 1)).replace(/^[+!"']+/, '');
}
/** `timeout 5s`, `nice 10` — a bare argument some wrappers take before the command. */
const BARE_NUMERIC = /^\d+(\.\d+)?[smhd]?$/;
/**
 * Remove the quoting a shell would remove before looking up a command.
 *
 * `\sudo`, `'sudo'` and `"sudo"` all execute sudo — the backslash only
 * suppresses alias expansion — but a verbatim string comparison sees three
 * different words. Without this, a one-character edit walks around the check.
 *
 * One surrounding quote pair, and nothing else: the scanner has already
 * resolved escapes by the time a word reaches this, in both the
 * quote-honouring scan and the `honorQuotes = false` fallback, so a second
 * pass here could only remove backslashes the dialect meant to keep — the
 * literal ones inside single quotes, and the POSIX-retained ones inside
 * double quotes (GHSA-972x-g47g-3922).
 */
function unquote(word) {
    return word.replace(/^(['"])(.*)\1$/, '$2');
}
/**
 * Privilege-prefix flags that consume the next argument, so `sudo -u root
 * reboot` is not read as invoking `root`. Enumerable because it is one tool's
 * option set, unlike "every flag of every binary".
 */
const PREFIX_VALUE_FLAGS = new Set([
    '-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-c',
    '--user', '--group', '--prompt', '--close-from', '--host', '--role', '--type',
    '--other-user', '--command',
]);
/** `/sbin/reboot`, `C:\Windows\reboot.exe` and `reboot` are the same invocation. */
function stripPath(word) {
    const cut = Math.max(word.lastIndexOf('/'), word.lastIndexOf('\\'));
    return cut === -1 ? word : word.slice(cut + 1);
}
function parseSegments(command, dialect = 'posix') {
    const segments = [];
    for (const words of tokenizeSegments(command, dialect)) {
        segments.push(...parseWords(words));
    }
    return segments;
}
/**
 * The same, for callers that already hold the tokenised words: one segment per
 * reading of where the command word is (`commandHeads`).
 *
 * The head is read past a wrapper — and the words a wrapper takes before the
 * command it runs — so a wrapper no longer hides what the segment executes:
 * `env shutdown -h now` used to name `env`, and the forbidden-invocation rule
 * never heard `shutdown`. The head is also folded (`commandWord`), so
 * `systemctl.exe reboot` names the multiplexer.
 */
function parseWords(words) {
    return commandHeads(words).map(({ index, head }) => ({ head, args: words.slice(index + 1) }));
}
/**
 * Whether a segment asks for elevation, reading past anything that is not yet
 * the command.
 *
 * A shell resolves the command word after assignments, and a wrapper runs what
 * follows it, so all of these execute sudo while naming something else first:
 *
 *   env sudo id            nohup sudo id         timeout 5 sudo id
 *   FOO=1 sudo id          nice -n 10 sudo id    command sudo id
 *
 * The scan walks left to right and stops at the first word that is a real
 * command. Reaching a privilege prefix before that is elevation; reaching
 * anything else is not, which is what keeps `grep sudo /var/log/auth.log` a
 * mention rather than an invocation.
 *
 * "Not yet the command" includes the words a wrapper takes before the command
 * it runs: the wrapper's operand (`flock /tmp/lk sudo id`, `chroot /mnt sudo
 * id`), the value a wrapper's flag carries as its own word (`strace -o FILE`,
 * `xargs -I {}`), and the subcommand `perf` runs. Until this scan learned them,
 * the wrapper's operand was the first "real command" it saw — so `flock /tmp/lk
 * sudo id` stopped at the lockfile and classified `safe` while `flock /tmp/lk
 * rm -rf /` was already refused. It now walks the same readings as every rule
 * (`commandReadings`), so the two can no longer disagree about where the
 * command is; a segment elevates if any reading of it does.
 */
function elevatedBinary(words) {
    for (const { index, prefix } of commandReadings(words)) {
        if (prefix === null)
            continue;
        // `sudo`, or `sudo -u root`, with nothing after it: the prefix is all there
        // is to name. Otherwise the binary as spelled, which is what the audit
        // record and OPA's input have always carried.
        return index === -1 ? prefix : stripPath(unquote(words[index]));
    }
    // A real command reached before any prefix, under every reading — which is
    // what keeps `grep sudo /var/log/auth.log` a mention.
    return null;
}
/**
 * The binary this command runs under elevation, or null if it runs none.
 *
 * Returning the name rather than a boolean is what lets `ParsedCommand.binary`
 * describe the same command the class does. Until 2.2.4 a `privileged` class
 * implied a leading prefix, so the anchored `extractBinary` always named the
 * elevated binary; once elevation could be found in any segment that stopped
 * holding, and `echo hi; sudo id` recorded `binary: "echo"` against a
 * privileged decision — in the audit log, the OTel span and OPA's input (#134).
 */
function elevatedBinaryOf(command, dialect = 'posix') {
    for (const words of tokenizeSegments(command, dialect)) {
        const found = elevatedBinary(words);
        if (found !== null)
            return found;
    }
    return null;
}
/**
 * sqlite3 dot-commands that hand the rest of their line to `/bin/sh`, and the
 * shell text they hand over. `.shell id` only executes as ONE argv word — as
 * two words sqlite reads `.shell` with no argument and errors — so matching
 * the embedded form is not a shortcut, it is the whole surface
 * (GHSA-cm4c-4q74-mgmj).
 */
const SQLITE_SHELL_DOT_COMMAND = /^\.(?:shell|system)\s+(\S.*)$/;
/**
 * Fold a command word for the head-keyed carrier and broker tables below:
 * strip a Windows executable suffix and fold case, the same normalization
 * `resolveInterpreter` applies for the interpreter table. This server
 * advertises Windows hosts, where the same binary arrives as `ssh.exe` or
 * `Docker`, and a head-keyed table that does not fold is keyed on a spelling
 * the target may never use — measured in the review round: every gate below
 * was bypassable with an `.exe` spelling.
 */
function foldCommandWord(word) {
    return word.replace(WINDOWS_EXE_SUFFIX, '').toLowerCase();
}
/**
 * The name a command word names, however it was spelled: directory part
 * removed, a Windows executable suffix removed, case folded. `/sbin/reboot`,
 * `C:\Windows\reboot.exe`, `REBOOT` and `reboot` are the same invocation, and
 * every table that keys on a command word — prefixes, wrappers,
 * multiplexers, forbidden invocations, the segment rules — answers through
 * this rather than through the exact spelling, for the same reason the
 * interpreter table already did (see `resolveInterpreter`): a spelling the
 * table does not know is a name the check never hears of.
 */
function commandWord(word) {
    return foldCommandWord(stripPath(word));
}
function sqliteShellPrograms(words) {
    const programs = [];
    for (const { index, head } of commandHeads(words)) {
        if (head !== 'sqlite3')
            continue;
        for (let i = index + 1; i < words.length; i++) {
            const match = SQLITE_SHELL_DOT_COMMAND.exec(words[i]);
            if (match)
                programs.push(match[1]);
        }
    }
    return programs;
}
/**
 * GNU tar's `--checkpoint-action=exec=…` hands its value to `sh -c` at every
 * checkpoint. All three spellings fire (GHSA-cm4c-4q74-mgmj, review round):
 * attached with any unambiguous `getopt_long` prefix of the option —
 * `--checkpoint-a` is where it diverges from `--checkpoint`, and the loose
 * `[a-z-]*` tail over-accepts abbreviations real tar would refuse, which only
 * classifies a command that cannot run — and detached, the value as the next
 * argv word, which tar 1.34 measured executing. Head-gated like
 * `sqliteShellPrograms`, so an `echo` of the flag text is a mention
 * (the `grep -e`/`echo` false positives of the review round).
 */
const TAR_CHECKPOINT_FLAG = /^--checkpoint-a[a-z-]*$/;
const TAR_CHECKPOINT_EXEC_ATTACHED = /^--checkpoint-a[a-z-]*=exec=(.+)$/;
const TAR_CHECKPOINT_ACTION_EXEC = /^exec=(.+)$/;
function tarCheckpointExecPrograms(words) {
    const programs = [];
    for (const { index, head } of commandHeads(words)) {
        if (head !== 'tar')
            continue;
        for (let i = index + 1; i < words.length; i++) {
            const attached = TAR_CHECKPOINT_EXEC_ATTACHED.exec(words[i]);
            if (attached) {
                programs.push(attached[1]);
                continue;
            }
            if (TAR_CHECKPOINT_FLAG.test(words[i])) {
                const detached = TAR_CHECKPOINT_ACTION_EXEC.exec(words[i + 1] ?? '');
                if (detached)
                    programs.push(detached[1]);
            }
        }
    }
    return programs;
}
/**
 * Builders whose every invocation runs recipes — shell commands read from a
 * file this classifier never sees. `make deploy` is as arbitrary as
 * `sh -c '…'`; the Makefile is simply elsewhere (GHSA-cm4c-4q74-mgmj).
 */
const RECIPE_RUNNERS = new Set(['make', 'gmake']);
/** Root user spellings, with or without docker's `user[:group]` suffix. */
const ROOT_USERS = new Set(['0', 'root']);
/** `0`, `root`, `0:0`, `root:root` — uid 0 however the CLI spells it. */
function isRootUserValue(value) {
    return ROOT_USERS.has(value.split(':')[0]);
}
/** Docker's own global flags that consume the next word, before the subcommand. */
const DOCKER_GLOBAL_VALUE_FLAGS = new Set(['-H', '--host', '--context', '--config', '--log-level', '-l']);
/** `--privileged`, `--privileged=true`, `--privileged=1` — and not `=false`/`=0`. */
function isPrivilegedFlag(word) {
    if (word === '--privileged')
        return true;
    const value = word.slice('--privileged='.length);
    return word.startsWith('--privileged=') && (value === 'true' || value === '1');
}
/**
 * The privilege brokers: binaries that reach root by their own design, at
 * their own flag, rather than by carrying another command the way `sudo`
 * does. `docker run --privileged` and `docker exec -u 0` are uid 0 in the
 * container, `systemd-run --uid=0` runs the unit as root (and `-p User=root`
 * is the property spelling of the same choice), and `nsenter -t` runs inside
 * another process's namespaces — pid 1's are the host's, and text cannot
 * tell which target an operand names. The `runuser`/`setpriv` answer:
 * `privileged` (GHSA-cm4c-4q74-mgmj).
 *
 * Scoped to the root spellings. Plain `docker run img cmd` and
 * `docker exec ctr cmd` still run as the image's default user — gating every
 * container command is a policy decision this fix does not make for the
 * operator's everyday `docker run -e FOO=bar img`.
 */
function brokeredElevation(words) {
    for (const { index, head } of commandHeads(words)) {
        const found = brokeredElevationAt(head, words.slice(index + 1));
        if (found !== null)
            return found;
    }
    return null;
}
function brokeredElevationAt(head, args) {
    if (head === 'docker') {
        // Global flags first — an operator aiming at a remote daemon writes
        // `-H tcp://…` or `--context prod` before the subcommand.
        let i = 0;
        while (i < args.length && args[i].startsWith('-')) {
            i += DOCKER_GLOBAL_VALUE_FLAGS.has(args[i]) ? 2 : 1;
        }
        let sub = args[i];
        let rest = args.slice(i + 1);
        // `docker container run|exec` is the same subcommand spelled in two words.
        if (sub === 'container') {
            sub = rest[0];
            rest = rest.slice(1);
        }
        if (sub !== 'run' && sub !== 'exec')
            return null;
        // Deliberately not stopped at the image/container operand: docker's own
        // value-taking flags (`-e VAR=x`) make that boundary unparseable without
        // docker's full option table, and a `--user=root` in the container's argv
        // still names root-seeking behaviour inside it. Over-classifying reaches
        // an approval prompt; under-classifying reaches none.
        for (let j = 0; j < rest.length; j++) {
            const word = rest[j];
            if (isPrivilegedFlag(word))
                return 'docker';
            if ((word === '-u' || word === '--user') && isRootUserValue(rest[j + 1] ?? ''))
                return 'docker';
            if (word.startsWith('--user=') && isRootUserValue(word.slice('--user='.length)))
                return 'docker';
            // `-u0`, `-u=0`: the value glued to the shorthand, as pflag allows.
            if (/^-u=?.+/.test(word) && word !== '-u' && isRootUserValue(word.replace(/^-u=?/, '')))
                return 'docker';
        }
        return null;
    }
    if (head === 'systemd-run') {
        for (let j = 0; j < args.length; j++) {
            const word = args[j];
            if (word === '--uid' && isRootUserValue(args[j + 1] ?? ''))
                return 'systemd-run';
            if (word.startsWith('--uid=') && isRootUserValue(word.slice('--uid='.length)))
                return 'systemd-run';
            const property = word === '-p' || word === '--property'
                ? args[j + 1] ?? ''
                : word.startsWith('--property=') ? word.slice('--property='.length) : null;
            if (property !== null) {
                const user = /^User=(.+)$/i.exec(property);
                if (user && isRootUserValue(user[1]))
                    return 'systemd-run';
            }
        }
        return null;
    }
    if (head === 'nsenter') {
        for (let j = 0; j < args.length; j++) {
            const word = args[j];
            if ((word === '-t' || word === '--target') && args[j + 1] !== undefined)
                return 'nsenter';
            // getopt allows the pid attached to the short flag: `-t1`.
            if (/^-t\d/.test(word) || (word.startsWith('--target=') && word.length > '--target='.length))
                return 'nsenter';
        }
        return null;
    }
    return null;
}
function brokeredElevationOf(command, dialect = 'posix') {
    for (const words of tokenizeSegments(command, dialect)) {
        const found = brokeredElevation(words);
        if (found !== null)
            return found;
    }
    return null;
}
/**
 * Does this command elevate anywhere a shell would act on it?
 *
 * Replaces four `^`-anchored regexes that only saw a *leading* prefix. Elevation
 * behind a wrapper, behind an assignment, or after a separator all reached root
 * with the command classified `safe` or `read-only`.
 */
/**
 * An allowlisted binary carrying a flag that makes it write or execute.
 *
 * Read past a wrapper (`commandHeads`), so `env sort --compress-program=X`
 * names `sort` rather than `env` — which is not in `DISQUALIFYING_ARGS`, and
 * the flag went unnoticed.
 */
function hasDisqualifyingArgs(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => {
        const rule = DISQUALIFYING_ARGS[head];
        return rule !== undefined && args.some((arg) => rule.test(arg));
    });
}
function invokedWords(command, dialect = 'posix') {
    const invoked = [];
    for (const { head, args } of parseSegments(command, dialect)) {
        invoked.push(head);
        // `systemctl reboot` restarts the host. Reading a unit that happens to be
        // named after a power action is rare enough that erring towards refusal
        // here costs little.
        if (ACTION_MULTIPLEXERS.has(head)) {
            invoked.push(...args.filter((w) => !w.startsWith('-')).map(commandWord));
        }
    }
    return invoked;
}
const SHELLS = new Set(['sh', 'bash', 'zsh']);
const DOWNLOADERS = new Set(['curl', 'wget']);
/**
 * A download piped into a shell.
 *
 * Split on `|` rather than reading the whole string, so cost is linear in the
 * command's length no matter how the two halves are spaced. `||` produces an
 * empty part between them, and this deliberately still matches: `curl x || sh`
 * runs a shell when the download fails, which is not meaningfully safer than
 * running one when it succeeds.
 */
function pipesDownloadIntoShell(command, dialect = 'posix') {
    // One head per pipe stage. Splitting on every separator would make `curl -O x;
    // bash build.sh` — download, then run a local script — match a rule whose label says
    // "piping a download into a shell", on a list that cannot be switched off.
    const segments = tokenizeSegmentsDetailed(command, true, dialect);
    const stages = segments
        .filter((segment, i) => i === 0 || segment.sep === '|')
        .map((segment) => parseWords(segment.words).map((s) => s.head));
    const firstDownload = stages.findIndex((heads) => heads.some((h) => DOWNLOADERS.has(h)));
    if (firstDownload === -1)
        return false;
    return stages.slice(firstDownload + 1).some((heads) => heads.some((h) => SHELLS.has(h)));
}
/**
 * Whether some segment, under some reading of where its command word is
 * (`commandHeads`), runs a command `test` matches. The one way the segment rules
 * below read a head, so a reading or a spelling one of them learns, they all do.
 */
function anySegmentRuns(command, dialect, test) {
    return tokenizeSegments(command, dialect).some((words) => commandHeads(words).some(({ index, head }) => test(head, words.slice(index + 1))));
}
/**
 * `dd … of=/dev/sda` — writing an image straight onto a block device.
 *
 * Head via `commandHeads`, not the privilege-prefix-only walk an earlier
 * `parseSegments` used: that missed a wrapped `env dd of=/dev/sda` (measured in
 * review) while the never-allowed write scan next door caught `env cp` — two dd
 * readers two rules apart must not answer through different head-extraction
 * machines.
 */
function writesToDevice(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => head === 'dd' && args.some((a) => a.startsWith('of=/dev/')));
}
/**
 * A recursive flag in any spelling a getopt-parsed binary accepts (GHSA-5cjr-
 * rc2p-f66f): `-r`/`-R` alone or inside a short cluster (`-rf`, `-fr`, `-Rh`),
 * separated (`-r -f`), or the long form down to its unambiguous `--rec`
 * prefix. Which letters count is per-binary and the caller names them: rm
 * takes both `-r` and `-R`, while chmod and chown take only `-R` — lowercase
 * `-r` is a mode operation there, not recursion. A cluster carrying a letter
 * the binary rejects errors on the host, so reading it as recursive only
 * refuses a command that cannot run.
 */
function hasRecursiveFlag(args, recursiveLetters) {
    return args.some((arg) => /^--rec/.test(arg)
        || (/^-[A-Za-z]+$/.test(arg) && recursiveLetters.test(arg)));
}
/**
 * Whether an operand names the filesystem root once the shell resolves it:
 * `/`, `//`, `///`, `/.`, `/..`, `/./`, `/etc/..` and `/tmp/../` all name
 * `/`. Purely lexical — no filesystem is consulted, so a symlink to `/` is
 * out of reach (documented residual). Measured in review: `chmod -R 777
 * /etc/..` escaped the exact-equality target set the first cut used.
 */
function isRootTarget(target) {
    if (!target.startsWith('/'))
        return false;
    let depth = 0;
    for (const part of target.split('/').slice(1)) {
        if (part === '' || part === '.')
            continue;
        if (part === '..') {
            depth = Math.max(0, depth - 1);
            continue;
        }
        depth++;
    }
    return depth === 0;
}
/**
 * Whether a chmod mode operand grants the world write access: the numeric
 * spellings with the world-write bit set (`777`, `0777`, `7777`, `666`) and
 * the symbolic ones whose class set includes other (or defaults/a = all)
 * with `+`/`=` and a `w` (`a+rwx`, `+w`, `ugo+rwx`; `u+w` grants only the
 * user and stays outside). Comma lists are read clause by clause.
 */
function isWorldWritableMode(arg) {
    for (const clause of arg.split(',')) {
        if (/^0*[0-7]{3,4}$/.test(clause)) {
            if ((parseInt(clause, 8) & 2) === 2)
                return true;
            continue;
        }
        const symbolic = /^([augo]*)([+=])([rwx]*)$/.exec(clause);
        if (symbolic !== null) {
            const classes = symbolic[1];
            const world = classes === '' || classes === 'a' || classes.includes('o');
            if (world && symbolic[3].includes('w'))
                return true;
        }
    }
    return false;
}
/** rm, recursive in any spelling, targeting the filesystem root itself. */
function deletesRoot(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => head === 'rm' && hasRecursiveFlag(args, /[rR]/) && args.some(isRootTarget));
}
/**
 * Device formatters and wipers: any `mkfs` spelling — `mkfs.ext4 /dev/sda1`
 * and the subcommand form `mkfs -t ext4 /dev/sda1` are the same operation
 * (the report's measured gap: the dot form matched a text regex, the `-t`
 * form classified `safe`) — plus the sibling names that destroy a device's
 * contents just as thoroughly: `mke2fs` is what `mkfs.ext4` symlinks to,
 * `mkswap` rewrites a device as swap, `wipefs` erases its signatures.
 */
const DEVICE_FORMATTERS = /^(?:mkfs|mkswap|wipefs)/;
const DEVICE_FORMATTER_NAMES = new Set(['mke2fs']);
function formatsDevice(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head) => DEVICE_FORMATTERS.test(head) || DEVICE_FORMATTER_NAMES.has(head));
}
/**
 * Flushing the firewall: `iptables -F` / `--flush` (and ip6tables), the
 * policy spelling `iptables -P <chain> ACCEPT` that opens the filter table
 * just as thoroughly, and `nft flush …`, which deletes the whole ruleset.
 */
function flushesFirewall(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => {
        if (head === 'iptables' || head === 'ip6tables') {
            if (args.includes('-F') || args.includes('--flush'))
                return true;
            const policy = args.indexOf('-P');
            return policy !== -1 && args.slice(policy + 1).includes('ACCEPT');
        }
        if (head === 'nft')
            return args[0] === 'flush';
        return false;
    });
}
/**
 * A recursive chmod making a path world-writable — `chmod -R 777 /` in any
 * argument order. The target may be any absolute path, not only the root:
 * the old text regex was unanchored and refused `chmod -R 777 /etc` too, and
 * a recursive world-writable `/etc` is not meaningfully safer than a
 * world-writable root. The mode is read as an operation, not a literal:
 * every numeric spelling with the world-write bit (`777`, `0777`, `7777`,
 * `666`) and the symbolic ones granting others write (`a+rwx`, `+w`) — see
 * `isWorldWritableMode`. `chmod -R 755 /` and `chmod -R u+w /` stay outside.
 */
function worldWritableRoot(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => head === 'chmod' && hasRecursiveFlag(args, /R/) && args.some((a) => a.startsWith('/'))
        && args.some(isWorldWritableMode));
}
/**
 * `chown -R … /` — a recursive chown whose target is the filesystem root.
 *
 * Recursive in any spelling (was `-R` as an exact word only, so `--recursive`
 * and the `-Rh` cluster escaped it — the same fragility as GHSA-5cjr-rc2p-f66f,
 * measured in its verification), and the target may sit anywhere in the argv:
 * chown chowns every operand it is given, so a root anywhere in the list is a
 * root chown. `chown -R app:app /srv/app` is ordinary and stays allowed.
 */
function chownsRoot(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => head === 'chown' && hasRecursiveFlag(args, /R/) && args.some(isRootTarget));
}
/**
 * The destructive floor under the refusal: rm, recursive in any spelling,
 * against any absolute path. The regex this replaces (`/rm\s+-rf?\s+\//`)
 * read one spelling, so `rm -fr /tmp/build` classified `safe` while
 * `rm -r /tmp/build` classified `destructive` — the flag order decided the
 * class (GHSA-5cjr-rc2p-f66f).
 */
function deletesAbsolutePath(command, dialect = 'posix') {
    return anySegmentRuns(command, dialect, (head, args) => head === 'rm' && hasRecursiveFlag(args, /[rR]/) && args.some((a) => a.startsWith('/')));
}
/**
 * One dequoted word starting at `start`, as the redirect-target reader needs it.
 *
 * Stops at whitespace, at a character that begins another shell construct (`; | & < >
 * ( )`), or at the end. Quotes are dropped and a closing quote does not end the
 * word — the shell concatenates what follows it, so `> "/etc/cron.d"/x`,
 * `> ""~/x` and `> a"b"c` all read as one target (the review round measured the
 * `break`-on-close reading as a bypass: `> ""~/.ssh/authorized_keys` fell through).
 * The quote/escape state machine is the same one `tokenizeSegmentsDetailed` runs
 * (both keyed on DOUBLE_QUOTE_ESCAPABLE); a dialect fix must land in both loops.
 */
function readDequotedWord(command, start, dialect) {
    const n = command.length;
    if (start >= n || /[\s;&|<>()]/.test(command[start]))
        return '';
    let word = '';
    let quote = command[start] === '"' || command[start] === "'" ? command[start] : null;
    let escaped = false;
    for (let i = quote === null ? start : start + 1; i < n; i++) {
        const ch = command[i];
        if (escaped) {
            word += ch;
            escaped = false;
            continue;
        }
        if (dialect === 'posix' && ch === '\\') {
            if (quote === "'") {
                word += ch;
                continue;
            }
            if (quote === '"') {
                const next = command[i + 1];
                if (next === undefined || DOUBLE_QUOTE_ESCAPABLE.has(next)) {
                    escaped = true;
                    continue;
                }
                word += ch;
                continue;
            }
            escaped = true;
            continue;
        }
        if (quote) {
            if (ch === quote) {
                quote = null;
                continue;
            }
            word += ch;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            continue;
        }
        if (/[\s;&|<>()]/.test(ch))
            break;
        word += ch;
    }
    return word;
}
/**
 * Every shell-redirect target in `command`, dequoted the way the shell will pass it.
 *
 * A redirect is an unquoted `>` — alone (`> f`), attached to the word it ends
 * (`echo x>f`, which bash also reads as a redirect), doubled (`>>`), with an fd
 * prefix (`2>`, `2>>`), with the both-streams spellings (`&>`, `&>>`, `>&`) or
 * with the noclobber-override marker (`>|`). A `>` inside quotes is data
 * (`echo "> f"` prints a string) and yields nothing, which is what separates this
 * scan from the raw regexes it replaces: those fired on the quoted text too, so a
 * commit message quoting a redirect was a refusal nobody could switch off
 * (measured on main).
 *
 * The target is the next word after the operator, quoted or attached. An operator
 * with nothing readable after it is a syntax error the remote shell would report,
 * and yields nothing. `>(...)` process substitution yields nothing here too — its
 * inner command is a carrier `nestedCommands` already reads.
 */
function redirectTargets(command, dialect) {
    const targets = [];
    const n = command.length;
    let quote = null;
    let escaped = false;
    for (let i = 0; i < n; i++) {
        const ch = command[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (dialect === 'posix' && ch === '\\' && quote !== "'") {
            escaped = true;
            continue;
        }
        if (quote) {
            if (ch === quote)
                quote = null;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            continue;
        }
        if (ch !== '>' && !(ch === '&' && command[i + 1] === '>'))
            continue;
        let j = ch === '&' ? i + 2 : i + 1;
        if (command[j] === '>')
            j++; // >>
        if (command[j] === '&')
            j++; // >& fd duplication
        if (command[j] === '|')
            j++; // >| noclobber override
        while (j < n && /\s/.test(command[j]))
            j++;
        const word = readDequotedWord(command, j, dialect);
        if (word !== '')
            targets.push(word);
        i = j - 1;
    }
    return targets;
}
/**
 * xargs's own value-taking short flags (GNU and BSD), part of its entry in
 * `WRAPPER_OPTIONS`. Read with sudo's table instead, `xargs -I {}` left `{}`
 * looking like the command and the verb xargs really runs hid behind it
 * (measured in review: `xargs -I {} cp {} /root/.ssh/authorized_keys` passed).
 */
const XARGS_VALUE_FLAGS = ['-I', '-J', '-d', '-E', '-n', '-s', '-P', '-R', '-L', '-S'];
/**
 * The positional operands of the copy family, with every option spelling that
 * carries a value stepped over.
 *
 * GNU getopt permutes options anywhere in the argv — `install k
 * /root/.ssh/authorized_keys -m 600` is ordinary usage — so a value-taking flag
 * trailing the destination must not have its value read as the last positional
 * (measured in review: it displaced the destination and the write was missed).
 * `-t`/`--target-directory` in all three spellings (`-t DIR`, `-tDIR`,
 * `--target-directory=DIR`, `--target-directory DIR`) is stepped here too; the
 * caller reads its value as the destination itself.
 */
function copyPositionals(args) {
    const positional = [];
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '-t' || arg === '--target-directory') {
            i++;
            continue;
        }
        if (/^-t.+/.test(arg) || /^--target-directory=/.test(arg))
            continue;
        // An attached short value (`-m600`) needs no line of its own: the generic
        // `-` skip below already keeps it out of the positionals.
        if (arg === '-m' || arg === '-o' || arg === '-g' || arg === '-S' || arg === '-Z') {
            i++;
            continue;
        }
        if (/^--(mode|owner|group|suffix|context|sparse)=/.test(arg))
            continue;
        if (arg === '--mode' || arg === '--owner' || arg === '--group' || arg === '--suffix'
            || arg === '--context' || arg === '--sparse') {
            i++;
            continue;
        }
        if (arg.startsWith('-'))
            continue;
        positional.push(arg);
    }
    return positional;
}
/**
 * The destination operands of the verbs whose argv names the file they write.
 *
 * A closed list, on purpose. `tee` writes every non-flag operand; `cp`, `mv` and
 * `install` write their destination operand — the value of `-t`/
 * `--target-directory` in any of its spellings when present, else the last
 * positional — and, because that operand may name a directory the sources are
 * copied *into*, the same joined with each source's basename, so `cp
 * authorized_keys ~/.ssh/` is caught rather than only `cp k
 * ~/.ssh/authorized_keys`. `install -d` creates every operand. `dd of=` writes
 * the value. Every other verb is a documented residual: a guess about an
 * unrecognised binary's operands must not reach this list (the
 * `speculativeOperands: false` ruling), and #230's decision 1 already ruled that
 * extracting paths from shell text can never be complete — so the README lists
 * these forms and names the rest as governed by class and approval instead.
 *
 * `env cp …`, `sudo cp …`, `timeout 5 cp …` and `xargs -I {} cp …` reach the
 * verb through `commandHeads`, every reading of it.
 */
function writeVerbTargets(command, dialect) {
    const targets = [];
    for (const words of tokenizeSegments(command, dialect)) {
        for (const { index, head } of commandHeads(words)) {
            const args = words.slice(index + 1);
            if (head === 'tee') {
                targets.push(...args.filter((a) => !a.startsWith('-')));
                continue;
            }
            if (head === 'dd') {
                for (const arg of args) {
                    if (arg.startsWith('of='))
                        targets.push(arg.slice(3));
                }
                continue;
            }
            if (head === 'cp' || head === 'mv' || head === 'install') {
                const positional = copyPositionals(args);
                if (head === 'install' && args.some((a) => a === '-d' || a === '--directory')) {
                    targets.push(...positional);
                    continue;
                }
                const tIndex = args.findIndex((a) => a === '-t' || a === '--target-directory'
                    || /^-t.+/.test(a) || a.startsWith('--target-directory='));
                let dest = null;
                let sources = positional;
                if (tIndex !== -1) {
                    const flag = args[tIndex];
                    if (flag === '-t' || flag === '--target-directory') {
                        dest = args[tIndex + 1] || null;
                    }
                    else {
                        const eq = flag.indexOf('=');
                        dest = eq === -1 ? flag.slice(2) : flag.slice(eq + 1);
                    }
                }
                else if (positional.length >= 2) {
                    dest = positional[positional.length - 1];
                    sources = positional.slice(0, -1);
                }
                if (dest === null || dest === '')
                    continue;
                targets.push(dest);
                for (const src of sources) {
                    const base = stripPath(src);
                    if (base !== '')
                        targets.push(`${dest}/${base}`);
                }
            }
        }
    }
    return targets;
}
/**
 * The never-allowed family cache — same shape and reason as `normalizedCache`:
 * three ForbiddenRule entries ask the same (command, dialect) question in a row,
 * and each ask re-ran both scans over the whole command. Keyed with the dialect
 * because both readings of one command are asked in the same row.
 */
const neverAllowedWriteCache = new Map();
/**
 * Which never-allowed family this command's certain write forms name, or null.
 * Both dialects are tried by the caller (findForbiddenMatchInDialect), and nested
 * commands reach this through the same recursion every other rule uses.
 */
function findNeverAllowedWriteFamily(command, dialect) {
    const key = `${dialect}\u0000${command}`;
    if (neverAllowedWriteCache.has(key))
        return neverAllowedWriteCache.get(key);
    let family = null;
    for (const candidate of [...redirectTargets(command, dialect), ...writeVerbTargets(command, dialect)]) {
        family = findNeverAllowedWriteTarget(candidate);
        if (family !== null)
            break;
    }
    neverAllowedWriteCache.set(key, family);
    if (neverAllowedWriteCache.size > 8) {
        neverAllowedWriteCache.delete(neverAllowedWriteCache.keys().next().value);
    }
    return family;
}
const FORBIDDEN_RULES = [
    ...FORBIDDEN_PATTERNS.map((re) => ({
        label: String(re),
        test: (c, dialect) => matchesEitherForm(c, (form) => re.test(form), dialect),
    })),
    {
        label: 'invoking a power-state command (shutdown, reboot, halt, poweroff) or eval',
        test: (command, dialect) => invokedWords(command, dialect).some((w) => FORBIDDEN_INVOCATIONS.has(w)),
    },
    {
        label: 'piping a download into a shell (curl or wget into sh, bash or zsh)',
        test: (c, dialect) => pipesDownloadIntoShell(c, dialect),
    },
    { label: 'dd writing to a block device (of=/dev/…)', test: (c, dialect) => writesToDevice(c, dialect) },
    { label: 'a recursive chown of the filesystem root', test: (c, dialect) => chownsRoot(c, dialect) },
    {
        label: 'rm deleting the filesystem root, recursive in any flag spelling (rm -rf /)',
        test: (c, dialect) => deletesRoot(c, dialect),
    },
    { label: 'formatting a device with any mkfs spelling', test: (c, dialect) => formatsDevice(c, dialect) },
    { label: 'flushing the firewall rules (iptables/ip6tables -F or --flush)', test: (c, dialect) => flushesFirewall(c, dialect) },
    {
        label: 'chmod making the filesystem root world-writable (recursive 777 /)',
        test: (c, dialect) => worldWritableRoot(c, dialect),
    },
    ...['/etc/cron', '/etc/systemd', 'authorized_keys'].map((family) => ({
        label: neverAllowedWriteLabel(family),
        test: (command, dialect) => findNeverAllowedWriteFamily(command, dialect) === family,
    })),
];
/**
 * Which never-allowed rule this command trips, or null. The single entry point:
 * FORBIDDEN_PATTERNS is deliberately not exported, because half of the list
 * lives in FORBIDDEN_RULES and a caller checking only the regexes would quietly
 * permit `sudo reboot`.
 */
function findForbiddenMatch(command, depth = 0) {
    // The engine calls this directly, so it is a decision point of its own and
    // reads both dialects like `classifyCommand` does: a refusal under either
    // reading is a refusal. The destructive-class consultation *inside* a
    // dialect pass (`isDestructive`) stays in-dialect — that pass is already one
    // reading of the whole string.
    if (command.includes('\\')) {
        const windows = findForbiddenMatchInDialect(command, depth, 'windows');
        if (windows !== null)
            return windows;
    }
    return findForbiddenMatchInDialect(command, depth, 'posix');
}
function findForbiddenMatchInDialect(command, depth, dialect) {
    for (const rule of FORBIDDEN_RULES) {
        if (rule.test(command, dialect))
            return rule.label;
    }
    // The same carriers the class scan reads, for the same reason. This list is the
    // one unconditional rule in the policy — forbidden regardless of role, tier or
    // approval — and it was decided from the outer command alone, so
    // `sh -c "shutdown -h now"` and `echo $(shutdown -h now)` were not forbidden.
    // They still classified `destructive`, which on the `prod` tier degrades an
    // absolute `deny` into `require-approval`: a rule that answers "never" became
    // one a human can click through.
    //
    // `speculativeOperands: false` — the maintainer's ruling. `nestedCommands`'
    // catch-all is a guess about an unrecognised binary's operands, and this loop
    // feeds the one unconditional rule in the policy: a guess may raise a
    // command's class, which role, tier and approval still get to weigh in on,
    // but it must not manufacture a refusal nobody can override. Measured before
    // this parameter existed: `git commit -m 'reboot the worker pool'` was a hard
    // deny on an admin profile with `approvalPolicy: 'auto'`, because the catch-all
    // read the quoted commit message as an operand starting with a forbidden word.
    // `$()`, backticks and `sh -c` are certain carriers, not guesses — the shell
    // really does run what they hold — and are unaffected: they are pushed by
    // `nestedCommands` regardless of this flag.
    if (depth >= MAX_NESTING_DEPTH)
        return null;
    for (const inner of nestedCommands(command, false, dialect)) {
        const match = findForbiddenMatchInDialect(inner, depth + 1, dialect);
        if (match !== null)
            return match;
    }
    return null;
}
function isForbidden(command, dialect = 'posix') {
    return findForbiddenMatchInDialect(command, 0, dialect) !== null;
}
/**
 * Commands that are destructive but legitimate under approval — e.g.
 * `rm -rf /tmp/build`, which must NOT be confused with `rm -rf /`.
 */
/**
 * Everything that classifies as destructive: forbidden commands included.
 *
 * Goes through isForbidden() rather than the regex list, so a command caught by
 * an invocation rule is classified destructive too — and, just as importantly,
 * reading a log that mentions `reboot` is no longer classified destructive
 * either. The recursive-rm floor is a segment check for the same reason the
 * refusal above it became one (GHSA-5cjr-rc2p-f66f): flag order must not
 * decide the class. A future text-regex floor re-enters through
 * matchesEitherForm, as FORBIDDEN_RULES still does for its two regex
 * survivors, when one needs no tokenisation to read.
 */
function isDestructive(command, dialect = 'posix') {
    return isForbidden(command, dialect) || deletesAbsolutePath(command, dialect);
}
const LEADING_PRIVILEGE_PREFIXES = [
    /^\s*sudo\b/,
    /^\s*su\b/,
    /^\s*doas\b/,
    /^\s*pkexec\b/,
];
function extractBinary(command, dialect = 'posix') {
    // The first segment's words, so quoting is resolved — `s"u"do id` used to report
    // `s"u"do` in the audit record and the refusal message. Reading the normalised whole
    // command instead would be wrong in the other direction: it rejoins segments with
    // `; `, so `ls | grep x` would report `ls;`, and this name reaches the audit record,
    // the OTel span and OPA's input (#134). A separator is not a binary.
    let cmd = (tokenizeSegments(command, dialect)[0] ?? []).join(' ').trim();
    for (const prefix of LEADING_PRIVILEGE_PREFIXES) {
        cmd = cmd.replace(prefix, '').trim();
    }
    if (cmd.startsWith('-c ')) {
        cmd = cmd.slice(3).trim();
    }
    const parts = cmd.split(/\s+/);
    return parts[0] || '';
}
/**
 * Wrappers that take positional words of their own before the command they
 * run, and how many: flock's lockfile, chroot's directory, taskset's cpu
 * mask (0x1, 0-3, a list), perf's subcommand, timeout's duration. Without
 * this the scan stops at the wrapper's operand and names it as the command —
 * measured in review: `flock /tmp/lk rm -rf /` and `chroot /mnt rm -rf /` read
 * `lk`/`mnt` as the head and the never-allowed rule never fired, where the old
 * text regexes had caught the phrase. The skipped word is gone as a head on
 * purpose: `flock rm -rf /` treats `rm` as the lockfile it creates, which is
 * what real flock does with a lone operand.
 */
const WRAPPER_OPERAND_COUNTS = Object.assign(Object.create(null), { flock: 1, chroot: 1, taskset: 1, perf: 1, timeout: 1 });
function options(takesValue, takesNone) {
    return { takesValue: new Set(takesValue), takesNone: new Set(takesNone) };
}
/**
 * Each wrapper's own options, from its own manual: coreutils 9.5 (env, nice,
 * stdbuf, timeout, chroot, nohup), util-linux 2.40 (flock, taskset, ionice,
 * chrt, setsid), findutils 4.9 (xargs), procps-ng 4 (watch), GNU time 1.9, strace
 * 6 and ltrace 0.7, plus the BSD spellings where they differ (`env -P`,
 * `chroot -u/-g/-G`, `xargs -J/-R/-S`) and bash's `command`/`exec` builtins.
 * A wrapper's flags are its own: `-p` is sudo's prompt and takes a value, while
 * xargs's and time's `-p` take none, and reading one as the other swallowed the
 * command word (`xargs -p rm -rf /`).
 *
 * Long options attached with `=` never take the next word and need no entry.
 * Optional-argument options (`xargs -i`, `watch -d`) only ever attach theirs,
 * so they are listed as taking none.
 */
const WRAPPER_OPTIONS = Object.assign(Object.create(null), {
    env: options(['-u', '--unset', '-C', '--chdir', '-S', '--split-string', '-P'], ['-i', '--ignore-environment', '-0', '--null', '-v', '--debug', '-']),
    nice: options(['-n', '--adjustment'], []),
    ionice: options(['-c', '--class', '-n', '--classdata', '-p', '--pid', '-P', '--pgid', '-u', '--uid'], ['-t', '--ignore']),
    command: options([], ['-p']),
    exec: options(['-a'], ['-c', '-l']),
    setsid: options([], ['-c', '--ctty', '-f', '--fork', '-w', '--wait']),
    stdbuf: options(['-i', '--input', '-o', '--output', '-e', '--error'], []),
    timeout: options(['-s', '--signal', '-k', '--kill-after'], ['-v', '--verbose', '-f', '--foreground', '-p', '--preserve-status']),
    chrt: options(['-T', '--sched-runtime', '-P', '--sched-period', '-D', '--sched-deadline'], ['-a', '--all-tasks', '-b', '--batch', '-d', '--deadline', '-e', '--ext', '-f', '--fifo',
        '-i', '--idle', '-o', '--other', '-r', '--rr', '-R', '--reset-on-fork', '-m', '--max',
        '-p', '--pid', '-v', '--verbose']),
    // `-c`/`--cpu-list` only changes how the mask operand is read; it takes
    // none of its own, and the mask still fills taskset's one operand slot.
    taskset: options([], ['-a', '--all-tasks', '-p', '--pid', '-c', '--cpu-list']),
    xargs: options([...XARGS_VALUE_FLAGS, '-a', '--arg-file', '--delimiter', '--max-args', '--max-procs',
        '--max-chars', '--process-slot-var'], ['-0', '--null', '-p', '--interactive', '-r', '--no-run-if-empty', '-t', '--verbose',
        '-x', '--exit', '-o', '--open-tty', '--show-limits', '-e', '-i', '-l']),
    watch: options(['-n', '--interval', '-q', '--equexit'], ['-b', '--beep', '-c', '--color', '-C', '--no-color', '-d', '--differences', '-e',
        '--errexit', '-g', '--chgexit', '-p', '--precise', '-t', '--no-title', '-w',
        '--no-wrap', '-x', '--exec', '-r', '--no-rerun']),
    strace: options(['-o', '-e', '-p', '-s', '-S', '-u', '-U', '-a', '-b', '-I', '-X', '-P', '-E', '-O'], ['-c', '-C', '-d', '-D', '-f', '-F', '-h', '-i', '-k', '-n', '-q', '-r', '-t', '-T',
        '-v', '-V', '-w', '-x', '-y', '-z', '-Z', '-ff', '-tt', '-ttt', '-qq', '-xx', '-yy']),
    ltrace: options(['-a', '-A', '-D', '-e', '-F', '-l', '-n', '-o', '-p', '-s', '-u', '-w', '-x'], ['-b', '-c', '-C', '-d', '-f', '-h', '-i', '-L', '-r', '-S', '-t', '-tt', '-ttt', '-T', '-V']),
    valgrind: options([], ['-h', '-v', '-q', '-d', '--help', '--version']),
    flock: options(['-w', '--wait', '--timeout', '-E', '--conflict-exit-code'], ['-s', '--shared', '-x', '-e', '--exclusive', '-u', '--unlock', '-n', '--nb',
        '--nonblock', '-o', '--close', '-F', '--no-fork', '--verbose', '-h', '--help',
        '-V', '--version']),
    chroot: options(['--userspec', '--groups', '-u', '-g', '-G'], ['--skip-chdir']),
    time: options(['-o', '--output', '-f', '--format'], ['-p', '--portability', '-a', '--append', '-v', '--verbose', '-q', '--quiet']),
});
/** `command -v NAME`, `command -V NAME`, `command -pv NAME`: a lookup that runs nothing. */
const COMMAND_LOOKUP = /^-[pvV]*[vV][pvV]*$/;
/** Whether an option word takes the next word as its value: yes, no, or not known here. */
function optionTakesValue(owner, word) {
    // `--name=value` carries its own value; `--` ends the options.
    if (word === '--' || (word.startsWith('--') && word.includes('=')))
        return false;
    // The prefixes keep the one shared table they have always been read with.
    // Reading their other flags both ways would have `sudo -E grep reboot x`
    // refused outright, as though `-E` took `grep` and `reboot` ran.
    if (PRIVILEGE_PREFIXES.has(owner))
        return PREFIX_VALUE_FLAGS.has(word);
    const grammar = WRAPPER_OPTIONS[owner];
    if (grammar === undefined)
        return undefined;
    if (grammar.takesValue.has(word))
        return true;
    if (grammar.takesNone.has(word))
        return false;
    if (word.startsWith('--'))
        return undefined;
    // `nice -5`, `head -5`: a number as the option itself.
    if (/^-\d+$/.test(word))
        return false;
    // A short-option cluster, read the way getopt reads it: switches until the
    // first flag that takes a value, which takes the rest of the word if there is
    // any (`stdbuf -oL`, `timeout -s9`) and the next word if not (`flock -nw 5`).
    for (let k = 1; k < word.length; k++) {
        const flag = `-${word[k]}`;
        if (grammar.takesValue.has(flag))
            return k === word.length - 1;
        if (!grammar.takesNone.has(flag))
            return undefined;
    }
    return false;
}
/**
 * Every reading of where a segment's command word is. The likelier branch at
 * each fork is walked first, so a reading that guessed "likelier" throughout
 * comes out before the others that end at a later word.
 *
 * Two questions about the words between a wrapper and what it runs have no
 * answer in the words themselves, and each wrong answer used to lose a command
 * the never-allowed rules refuse:
 *
 *  - whether a wrapper option this file does not know takes the next word as
 *    its value (`flock --wai 5 /tmp/lk …`, `perf stat -e cycles …`);
 *  - whether a word sitting in a wrapper's operand slot is the operand or what
 *    runs (`flock sudo rm -rf /` runs `rm` with `sudo` as the lockfile, where
 *    earlier releases read `sudo` as the prefix; `timeout rm -rf /` has no
 *    duration, and earlier releases read `rm` as the command).
 *
 * Every answer is followed, and callers ask whether *any* reading runs something
 * a rule refuses or elevates — so a guess can only add a refusal, never hide
 * one. The walk is breadth-bounded: a state is a word position plus a little
 * context, each is visited once, and positions only move forward.
 *
 * A bare number fills a pending operand slot (`timeout 5`, `taskset 3`), and is
 * otherwise skipped as the numeric argument `nice`/`chrt` take before theirs.
 */
function commandReadings(words) {
    const readings = [];
    const seen = new Set();
    const stack = [];
    // Pushed last is walked first: each fork pushes its likelier branch last, so
    // the first reading out is the one that guessed "likelier" at every fork.
    const push = (state) => {
        const key = `${state.i}\u0000${state.operandsLeft}\u0000${state.owner}\u0000${state.prefix}`;
        if (seen.has(key))
            return;
        seen.add(key);
        stack.push(state);
    };
    const finish = (index, prefix) => {
        if (!readings.some((r) => r.index === index && r.prefix === prefix))
            readings.push({ index, prefix });
    };
    push({ i: 0, operandsLeft: 0, owner: null, prefix: null });
    while (stack.length > 0) {
        const s = stack.pop();
        if (s.i >= words.length) {
            finish(-1, s.prefix);
            continue;
        }
        const raw = words[s.i];
        const spelled = stripPath(unquote(raw));
        const word = foldCommandWord(spelled);
        const next = { ...s, i: s.i + 1 };
        if (raw.startsWith('-')) {
            if (s.owner === 'command' && COMMAND_LOOKUP.test(raw)) {
                finish(-1, s.prefix);
                continue;
            }
            const takesValue = s.owner === null ? false : optionTakesValue(s.owner, raw);
            const consumed = { ...s, i: s.i + 2 };
            if (takesValue === undefined) {
                push(consumed);
                push(next);
            }
            else {
                push(takesValue ? consumed : next);
            }
            continue;
        }
        if (s.operandsLeft > 0) {
            const asOperand = { ...next, operandsLeft: s.operandsLeft - 1 };
            // A bare number is the operand (`timeout 5`, `taskset 3`). Any other word
            // may be the operand or what runs: `flock rm -rf /` has real flock open
            // `rm` and try to run `-rf`, which only refuses a command that cannot run.
            if (!BARE_NUMERIC.test(raw))
                readWord({ ...s, operandsLeft: 0 }, raw, spelled, word);
            push(asOperand);
            continue;
        }
        readWord(s, raw, spelled, word);
    }
    return readings;
    /** A word that is no wrapper's option or operand: a prefix, a wrapper, a skipped word, or the command. */
    function readWord(s, raw, spelled, word) {
        if (PRIVILEGE_PREFIXES.has(word)) {
            push({ i: s.i + 1, operandsLeft: 0, owner: word, prefix: s.prefix ?? spelled });
        }
        else if (EXEC_WRAPPERS.has(word)) {
            push({ i: s.i + 1, operandsLeft: WRAPPER_OPERAND_COUNTS[word] ?? 0, owner: word, prefix: s.prefix });
        }
        else if (ASSIGNMENT.test(raw) || BARE_NUMERIC.test(raw)) {
            push({ ...s, i: s.i + 1 });
        }
        else {
            finish(s.i, s.prefix);
        }
    }
}
function commandHeads(words) {
    const heads = [];
    for (const { index } of commandReadings(words)) {
        if (index === -1 || heads.some((h) => h.index === index))
            continue;
        heads.push({ index, head: commandWord(unquote(words[index])) });
    }
    return heads;
}
/**
 * Whether this segment's command word is one whose operands are data.
 *
 * The carrier scan reads every word, because a wrapper this file does not list would
 * otherwise hide `sh -c`. The cost is that an outer tool's own flag can be mistaken for an
 * interpreter's: `grep python3 -c /var/log/x` counts lines, and `-c` is also python's
 * program flag. An allowlisted command is one this file already vouches for as reading
 * rather than running, so its arguments are subjects, not commands — the positive form of
 * the mention-vs-invocation rule at #91. `find` keeps its `-exec` scan, which is separate.
 *
 * This answer relaxes a scan rather than adding a refusal, so it needs every reading
 * of the segment to agree: one that lands on something other than a reader keeps
 * the carrier scan on.
 */
function operandsAreData(words) {
    const heads = commandHeads(words);
    return heads.length > 0 && heads.every(({ head }) => READERS[head]?.operandsAreData === true);
}
/**
 * Whether an interpreter name is the value of the flag before it rather than a command.
 *
 * The scan looks at every word so that a carrier behind an unlisted wrapper is not lost,
 * and requires a program-bearing flag to follow before it believes one. That is not quite
 * enough: `grep -e perl -e python` puts `perl` after a flag and a second `-e` after it,
 * which reads as perl being handed a program. A search term is not a command.
 *
 * The test is deliberately narrow — the preceding flag must be one of *this interpreter's*
 * program flags. Any flag at all was too much: `nsenter -t 1 -m sh -c 'sudo id'` puts the
 * shell after `-m`, which takes no value, and dropping it lost a real elevation. Nothing
 * here can know an arbitrary tool's grammar, so `sed -n perl -e p` — a shape no one
 * writes — is still read as a carrier.
 */
/**
 * Words that may sit between an interpreter and its program flag.
 *
 * A quoted empty word survives tokenization now, because a positional reader
 * cannot work with an argument list that silently drops operands. That made an
 * empty word break this chain: `sh '' -c 'sudo id'` stopped finding the program
 * and fell from `privileged` to `safe`. Real `sh` does not run it either — it
 * reports "No such file or directory" and exits, measured — but over-reporting a
 * command that fails costs nothing and under-reporting one is the whole hazard,
 * so the chain keeps the answer it had.
 */
function skippableBetweenFlags(word) {
    return word === '' || word.startsWith('-');
}
/**
 * Whether `word` is a spelling of `flag`, honouring case-insensitivity when asked.
 *
 * Scoped per call, never globally: pwsh/powershell's own parameter binder resolves
 * `-ENC`, `-Enc` and `-enc` to the same parameter, but `-E` and `-e` are two different
 * flags to perl. Every caller here is told explicitly, per invocation, whether the
 * interpreter it is matching against is one of the case-insensitive ones — folding case
 * is never the default.
 */
function sameFlag(word, flag, caseInsensitive) {
    return caseInsensitive ? word.toLowerCase() === flag.toLowerCase() : word === flag;
}
function isFlagValue(words, i, flags, caseInsensitive = false) {
    if (i === 0)
        return false;
    const previous = words[i - 1];
    if (!(previous.length > 1 && previous.startsWith('-')))
        return false;
    if (!flags.some((f) => sameFlag(previous, f, caseInsensitive)))
        return false;
    // The flag in front may be a wrapper's own, spelled like the interpreter's:
    // `xargs -p node -e …` and `time -p node -p …` run `node`, and reading it as
    // the value of node's `-p` lost the program that follows. A word that is the
    // command under some reading is invoked there, not handed over as a value.
    return !commandHeads(words).some(({ index }) => index === i);
}
/**
 * The program an interpreter was handed on its command line, or null.
 *
 * Only flags may sit between the interpreter and its flag; anything else means this was
 * not that kind of invocation, which is what keeps `python3 script.py` — a program this
 * cannot read either, but one every deployment runs — out of the gate. That rule holds
 * for every interpreter here except pwsh/powershell (see `tolerateUnknownWordsAtHead`):
 * real POSIX interpreters stop parsing their own options at the first positional
 * argument — `python3 script.py -c 'evil'` hands `-c evil` to the script as `argv`, not
 * to python — so treating a bare word as "not this kind of invocation" is correct for
 * them, not merely convenient.
 *
 * Returns which of `flags` matched alongside the program, not just the program text, so
 * a caller can tell `-EncodedCommand` from its `-e` abbreviation apart from every other
 * program-bearing word — decoding is specific to that one flag, and both spellings reach
 * here as an ordinary match.
 *
 * @param tolerateUnknownWordsAtHead pwsh/powershell's own argument parser walks the
 *   whole command line looking for named parameters it recognises and does not stop at
 *   an unrecognised one's value (`-ExecutionPolicy Bypass`) the way a POSIX interpreter
 *   stops at its first positional argument. Only takes effect when `from` is the
 *   segment's *effective* command word under some reading — `commandHeads(words)`, which
 *   reads past a privilege prefix or an exec wrapper (`env`, `nohup`, `timeout`, …), not merely
 *   position 0. `from === 0` missed exactly the shape those wrappers exist to describe:
 *   `env pwsh -ExecutionPolicy Bypass -EncodedCommand …` put `pwsh` at index 1, the
 *   tolerance never engaged, and the interpreter loop's own flag-walk gave up at
 *   `Bypass` before ever reaching `-EncodedCommand` — classified `safe`. Still unambiguous
 *   about *which* word is being invoked, not a value or a search term this file has no
 *   business reinterpreting (`grep -e perl -e python` never reaches here with this set,
 *   because `perl` is not the segment's effective command word and isn't pwsh-family
 *   regardless; nor is `customtool --search pwsh …`, where `customtool` is). Structural,
 *   not a list of pwsh's value-taking flags: this file does not need to know
 *   `-ExecutionPolicy` exists to stop being confused by it.
 */
function programAfterFlag(words, from, flags, caseInsensitive = false, tolerateUnknownWordsAtHead = false) {
    const tolerateUnknownWords = tolerateUnknownWordsAtHead
        && commandHeads(words).some(({ index }) => index === from);
    for (let j = from + 1; j < words.length; j++) {
        const word = words[j];
        const exact = flags.find((f) => sameFlag(word, f, caseInsensitive));
        if (exact !== undefined) {
            // A subcommand — a program-bearing word that is not itself a `-` flag, such as
            // `deno`'s `eval` — may still have its own options before the code: `deno eval
            // --unstable <code>` is one invocation, not two. A real flag like `-c` or
            // `-Command` never has anything of its own between it and the program, so this
            // only widens the subcommand case.
            let k = j + 1;
            if (!exact.startsWith('-')) {
                while (k < words.length && skippableBetweenFlags(words[k]))
                    k++;
            }
            const program = words[k];
            return program === undefined ? null : { program, flag: exact, index: k };
        }
        // Deliberately case-SENSITIVE even for pwsh/powershell: this branch exists for a
        // value glued directly onto a short flag with no separating space (`-csudo id`).
        // Folding case here as well made `-ExecutionPolicy` — a real pwsh option this file
        // does not otherwise track — case-insensitively start with `-e` and get read as
        // `-e` plus an attached `xecutionPolicy`, which swallowed `-ExecutionPolicy Bypass
        // -Command 'sudo id'` into `destructive` and, worse, made `foundProgram` true so
        // the catch-all below never ran. Every case-insensitive spelling the table needs
        // to accept (`-enc`, `-ec`, `-EC`, `-ENC`, `-E`, `-EncodedCOMMAND`, `-COMMAND`,
        // `-C`, …) is already reached through the exact match above or the cluster match
        // below, so this branch does not need to fold case to cover them.
        const attached = flags.find((f) => word.startsWith(f) && word.length > f.length);
        if (attached !== undefined) {
            const rest = word.slice(attached.length);
            // `sh -c'sudo id'` tokenises to `-csudo id`, so the program is attached. `bash -cx`
            // is a flag cluster and the program is the next word. A space, or the `=` of
            // `--eval=…`, is what tells them apart: a cluster is letters only.
            if (/\s/.test(rest) || rest.startsWith('=')) {
                return { program: rest.replace(/^=/, ''), flag: attached, index: j };
            }
            const program = words[j + 1];
            return program === undefined ? null : { program, flag: attached, index: j + 1 };
        }
        // The program flag need not lead the cluster: `bash -xc 'sudo id'` runs exactly what
        // `bash -cx 'sudo id'` runs, and a prefix test saw the second and missed the first.
        const clusterFlag = clusterCarriesFlag(word, flags, caseInsensitive);
        if (clusterFlag !== null) {
            const program = words[j + 1];
            return program === undefined ? null : { program, flag: clusterFlag, index: j + 1 };
        }
        if (!skippableBetweenFlags(word) && !tolerateUnknownWords)
            return null;
    }
    return null;
}
/** How much base64 is worth decoding before the answer stops changing. */
const MAX_ENCODED_CHARS = 64 * 1024;
/**
 * The command inside `-EncodedCommand`, or null.
 *
 * PowerShell encodes UTF-16LE, so decoding as utf8 yields text with a NUL between
 * every character and no pattern matches it. `Buffer.from(x, 'base64')` never
 * throws — it drops characters outside the alphabet — so malformed input produces
 * a wrong answer rather than an exception, and the caller must treat null and
 * nonsense alike: the flag alone has already made the command `destructive`.
 *
 * Reads a bounded, 4-aligned PREFIX rather than refusing outright past the limit. A
 * refusal is a downgrade path: it turns "pad the payload past 64 KiB" into a way to
 * trade `privileged` for `destructive`, which is strictly better for whoever is padding
 * it. 4-aligned because base64 decodes in groups of four characters to three bytes;
 * truncating mid-group corrupts the last partial character instead of just dropping
 * trailing content the decode was never going to reach anyway.
 */
function decodedPowerShellCommand(operand) {
    const prefix = operand.length > MAX_ENCODED_CHARS
        ? operand.slice(0, MAX_ENCODED_CHARS - (MAX_ENCODED_CHARS % 4))
        : operand;
    const decoded = Buffer.from(prefix, 'base64').toString('utf16le');
    return decoded.includes('�') || decoded.trim() === '' ? null : decoded;
}
/**
 * What follows a short flag inside a single-dash cluster, or the `flags` entry it
 * carries, or null if it carries none.
 *
 * Clusters only — a run of single letters after one dash. Long flags and attached values
 * are handled before this is reached. Returns the canonical flag rather than a boolean
 * for the same reason `programAfterFlag` does: a caller deciding whether to decode
 * compares against the table's own spellings, not against whatever letters happened to
 * be clustered together.
 */
function clusterCarriesFlag(word, flags, caseInsensitive = false) {
    // Three letters at most. `/^-[A-Za-z]+$/` alone also matches every single-dash long
    // option, and `find`'s predicates are full of them: `-type` contains perl's `-e`, so
    // `find . -name perl -type f` read as a carrier and asked for approval.
    if (!/^-[A-Za-z]{2,3}$/.test(word))
        return null;
    const body = caseInsensitive ? word.slice(1).toLowerCase() : word.slice(1);
    const shortFlags = flags.filter((flag) => flag.length === 2);
    // A cluster is letters only, so whatever follows the program flag is more flags — the
    // program itself is always the next word.
    //
    // Scanned by the BODY's own character order, not the table's order: `-ec` must
    // resolve to `-e` (so a caller deciding whether to decode sees `-e`), not to `-c`
    // just because `-c` happens to sit first in pwsh's `programBearingWords`. The first
    // letter in the cluster is the one the invocation leads with.
    for (const letter of body) {
        const match = shortFlags.find((flag) => (caseInsensitive ? flag[1].toLowerCase() : flag[1]) === letter);
        if (match !== undefined)
            return match;
    }
    return null;
}
/** Spellings of "the program is on standard input" that look like a file operand. */
const STDIN_PATHS = new Set(['-', '/dev/stdin', '/dev/fd/0', '/proc/self/fd/0']);
/**
 * Whether a segment's command word is an interpreter with no program of its own.
 *
 * `echo "sudo id" | bash` hands the program over on stdin, where there is nothing to
 * read. This holds for the shells too — `readable` is about a `-c` argument, and there is
 * no `-c` here. Requiring that no operand follow is what keeps `cat data | python3
 * app.py` out of it: there the pipe carries data, not a program.
 */
function readsProgramFromStdin(words) {
    return commandHeads(words).some(({ index }) => readsProgramFromStdinAt(words, index));
}
function readsProgramFromStdinAt(words, idx) {
    const bin = stripPath(words[idx]);
    // Interpreters only. awk's one program-from-stdin form is `awk -f -`, already gated as a
    // file flag; every other piped awk reads data, not a program.
    const spec = resolveInterpreter(bin);
    if (spec === undefined)
        return false;
    const flags = spec.programBearingWords;
    let sawStdinFlag = false;
    for (let j = idx + 1; j < words.length; j++) {
        const word = words[j];
        if (flags.some((f) => word === f || word.startsWith(f)))
            return false;
        // `--` ends the interpreter's own arguments; what follows is `$1..$n`, so a program
        // still has to come from somewhere and `bash -s -- arg` reads stdin.
        // `-s` says outright that the script comes from stdin, so everything after it is
        // `$1..$n` whatever it looks like.
        if (word === '-s') {
            sawStdinFlag = true;
            continue;
        }
        // `--` ends the interpreter's own arguments. Without `-s` the next word is the script
        // itself, so `bash -- process.sh` reads a file while `bash -s -- arg` reads stdin.
        if (word === '--') {
            const next = words[j + 1];
            return sawStdinFlag || next === undefined || STDIN_PATHS.has(next);
        }
        if (STDIN_PATHS.has(word))
            return true;
        if (!word.startsWith('-'))
            return false;
    }
    return true;
}
/**
 * Whether any segment hands a program to something this file cannot read.
 *
 * Keyed on the segment's command word, never on any word that happens to name an
 * interpreter: matching a mention rather than an invocation is the defect this file
 * records fixing as #91, and `cat /usr/bin/python3` names an interpreter without running
 * one. A program-bearing flag must actually be present, so naming one is not enough.
 */
/**
 * What this segment's awk program does, or null when it runs no awk program.
 *
 * Keyed on `commandHeads` — the word that actually runs — never on any word
 * that happens to say "awk". `readlink -f /usr/bin/awk` and `man awk` name an
 * interpreter without invoking one, and an earlier attempt that scanned every
 * word classified both destructive. When more than one reading lands on awk,
 * their findings are merged, so the strictest reading's program counts.
 */
function awkFindings(words) {
    let merged = null;
    for (const { index, head } of commandHeads(words)) {
        if (!AWK_NAMES.has(head))
            continue;
        // No second `unquote`. `tokenizeSegmentsDetailed` has already resolved shell
        // quoting, and inside single quotes a backslash is literal — so the program
        // word arrives exactly as awk will see it. Unquoting again ran
        // `.replace(/\\(.)/g, '$1')` over the *awk program*, which deleted the
        // backslash of every escape it contains. Measured, all three ways that broke:
        // `system("\163udo id")` became `system("163udo id")` and classified `safe`;
        // `s="\""` collapsed and re-paired the string delimiters so the code between
        // them was read as string content; and `print "\\"` became an unterminated
        // string, gating ordinary awk as unreadable.
        const findings = readAwkInvocation(words.slice(index + 1));
        if (findings === null)
            continue;
        merged = merged === null ? findings : {
            commands: [...merged.commands, ...findings.commands],
            pipedInto: [...merged.pipedInto, ...findings.pipedInto],
            writesFile: merged.writesFile || findings.writesFile,
            unreadable: merged.unreadable || findings.unreadable,
        };
    }
    return merged;
}
/**
 * Whether any segment's awk program writes a file, or could not be read.
 *
 * The commands an awk program hands to a shell are not here: `nestedCommands`
 * emits those so they are classified as themselves, which is how
 * `awk 'BEGIN{system("sudo id")}'` comes out `privileged` rather than flattened
 * to the `destructive` this function reports.
 */
function hasDangerousAwk(command, dialect = 'posix') {
    for (const { words } of tokenizeSegmentsDetailed(command, true, dialect)) {
        const findings = awkFindings(words);
        if (findings === null)
            continue;
        if (findings.writesFile || findings.unreadable)
            return true;
        // `print … | "sh"` is the awk spelling of `echo "sudo id" | sh`, which this
        // file already gates through `readsProgramFromStdin`. Classifying the target
        // alone says `sh`, which is not dangerous; what is dangerous is what awk
        // prints into it, and that is assembled at run time. So it is the same
        // "we cannot tell" this module reports for `-f progfile`.
        for (const target of findings.pipedInto) {
            const stage = tokenizeSegmentsDetailed(target, true, dialect)[0];
            if (stage !== undefined && readsProgramFromStdin(stage.words))
                return true;
        }
    }
    return false;
}
function hasUnreadableProgram(command, dialect = 'posix') {
    const segments = tokenizeSegmentsDetailed(command, true, dialect);
    for (let i = 0; i < segments.length; i++) {
        const { words, sep } = segments[i];
        if (sep === '|' && readsProgramFromStdin(words))
            return true;
        // Carriers whose program is not on this command line at all, or is
        // written for a shell on another host (GHSA-cm4c-4q74-mgmj). All three
        // are "we cannot tell", the `awk -f progfile` answer, so `destructive`:
        //  - `make`/`gmake` run recipes from a file this classifier never sees;
        //  - `ssh` hands its operands to a login shell elsewhere — any non-flag
        //    word means execution this text cannot read. A separated flag value
        //    (`ssh -p 2222` with no destination) counts too, which only moves an
        //    unrunnable fragment to `destructive`: every runnable ssh carries a
        //    destination that counts anyway;
        //  - `sqlite3` with a `.shell`/`.system` dot-command and `tar` with a
        //    checkpoint `exec=` action spawn a shell for text the helpers emit
        //    into `nestedCommands`, which is what puts an inner elevation above
        //    `destructive`.
        for (const { index, head } of commandHeads(words)) {
            const operands = words.slice(index + 1);
            if (RECIPE_RUNNERS.has(head))
                return true;
            if (head === 'ssh' && operands.some((w) => !w.startsWith('-')))
                return true;
        }
        if (sqliteShellPrograms(words).length > 0 || tarCheckpointExecPrograms(words).length > 0)
            return true;
        if (!operandsAreData(words)) {
            for (let j = 0; j < words.length; j++) {
                const spec = resolveInterpreter(stripPath(unquote(words[j])));
                if (spec === undefined || spec.readable)
                    continue;
                // Same case-insensitivity as `nestedCommands`'s interpreter loop, and for the
                // same reason: pwsh/powershell's own parameter binder does not distinguish
                // `-EC` from `-ec`, so neither should this.
                const caseInsensitive = spec.programBearingWords.includes('-EncodedCommand');
                if (isFlagValue(words, j, spec.programBearingWords, caseInsensitive))
                    continue;
                if (programAfterFlag(words, j, spec.programBearingWords, caseInsensitive, caseInsensitive) !== null)
                    return true;
            }
        }
    }
    return false;
}
/**
 * Whether any segment runs a command this process cannot name.
 *
 * The class — and with it the approval gate — is decided from the literal text of
 * the command word. A word carrying `$` or a backtick is a name the shell resolves
 * at run time, so `$S id` was classified as though `$S` were a binary, and came
 * out `safe` (GHSA-fj9r-f47j-c73x).
 *
 * Resolving the variable is not the answer and cannot be: a session run keeps the
 * caller's shell state, so `S=sudo` and `$S id` can arrive as two separate calls,
 * and a variable exported in the target's own profile is never visible here at
 * all. What is answerable is whether we know the name — and when we do not, saying
 * so is the only honest class.
 *
 * Only the command word, never the arguments. `echo $HOME` names a command we know;
 * promoting that would put a prompt on most ordinary shell usage.
 */
function hasUnnameableCommand(command, dialect = 'posix') {
    for (const words of tokenizeSegments(command, dialect)) {
        if (commandHeads(words).some(({ index }) => /[$`]/.test(words[index])))
            return true;
    }
    return false;
}
/**
 * Commands this server synthesises rather than a user typing them.
 *
 * These reach the classifier as text like `sftp:upload /etc/passwd`, and no rule named
 * them, so every one fell through to the default `safe` — a class the default rules grant
 * to `operator` on `prod`. Writing an arbitrary file to the target is not `safe`: it is
 * the same authority as `rm`, spelled through a different tool, and it reaches
 * `~/.ssh/authorized_keys` without touching a shell. Opening a session is the same
 * argument, since it hands over an interactive shell.
 *
 * `session:close` is deliberately absent: it is a release rather than an acquisition, and
 * no tool advertises it as a read.
 *
 * `sftp:download` and `sftp:list` are absent for a different reason now. They *are*
 * lowered to `read-only` — by `READ_ONLY_SYNTHETIC` near the top of this file — because
 * both tools advertise `readOnlyHint: true` and `safe` is refused outright by a `readOnly`
 * profile, so the one profile class the annotation targeted was the one that could not run
 * them (#217). They cannot be lowered *here*, because this table is a floor and a floor
 * can only raise; an entry would be inert. That inertness is the trap worth keeping
 * written down — it produced two wrong attempts during #212.
 *
 * What this paragraph used to say, and what was wrong with it: that the effect anyone
 * wants from lowering `sftp:list` — letting a `viewer` list a remote directory — is "a
 * binding change, not a classification one". It is a classification one, because the tool
 * ships an annotation and a description that both claim read-only, and a policy that
 * disagreed with them was the defect rather than the binding.
 *
 * `sftp:upload-file` and `sftp:download-file` are `destructive` because each writes a
 * file: the first on the remote host, the second inside the operator's transfer root.
 * Without a floor both classify `safe` from the verb alone, which would let an `operator`
 * write to disk through a tool nobody had approved for it.
 */
const SYNTHETIC_CLASSES = Object.assign(Object.create(null), {
    'sftp:upload': 'destructive',
    'sftp:upload-file': 'destructive',
    'sftp:download-file': 'destructive',
    'session:open': 'destructive',
});
/** The first word, tokenised — the synthetic verb when there is one. */
function syntheticVerb(command, dialect = 'posix') {
    return tokenizeSegments(command, dialect)[0]?.[0] ?? '';
}
/**
 * The class of a command, and of everything it carries.
 *
 * A command that carries another decides nothing on its own: the remote shell expands
 * `$(...)`, backticks, `<(...)` and `sh -c` and runs what is inside, so the class is the
 * higher of the two. The scan for carriers already existed, but it *replaced* the outer
 * class instead of raising it, and only when the inner class was above `safe` — so
 * `sudo sh -c 'rm -rf /etc'` reported the inner `destructive` and lost the outer
 * `privileged`, which on `prod` is the difference between a prompt and a refusal.
 * Taking the maximum is what makes the scan unable to lower anything.
 */
function classifyCommand(command, depth = 0) {
    // One string, two dialects, and the class is the worse of the two readings:
    // the classifier cannot know whether the host shell reads a backslash as an
    // escape or as a path separator, so policy must hold on whichever host
    // receives the command (GHSA-972x-g47g-3922). A command without a backslash
    // is byte-identical under both dialects, so it keeps the single pass.
    if (!command.includes('\\'))
        return classifyCommandInDialect(command, depth, 'posix');
    const posix = classifyCommandInDialect(command, depth, 'posix');
    const windows = classifyCommandInDialect(command, depth, 'windows');
    return CLASS_RANK[windows.class] > CLASS_RANK[posix.class] ? windows : posix;
}
function classifyCommandInDialect(command, depth, dialect) {
    const trimmed = command.trim();
    const outer = classifyOuter(trimmed, dialect);
    if (depth >= MAX_NESTING_DEPTH) {
        // Nesting this deep is not something an operator writes, and we have stopped
        // reading. Refusing to guess is the only answer consistent with the rest of this
        // file.
        return { binary: outer.binary, fullCommand: trimmed, class: 'privileged' };
    }
    let highest = outer;
    // A floor, not a verdict. Returning the synthetic class outright would put it above
    // the elevation and never-allowed checks, so `sftp:upload /tmp/x; sudo id` would
    // record `destructive` where the command is `privileged`.
    const verb = syntheticVerb(trimmed, dialect);
    const floor = SYNTHETIC_CLASSES[verb];
    if (floor !== undefined && CLASS_RANK[floor] > CLASS_RANK[highest.class]) {
        highest = { binary: verb, fullCommand: trimmed, class: floor };
    }
    for (const inner of nestedCommands(trimmed, true, dialect)) {
        const parsed = classifyCommandInDialect(inner, depth + 1, dialect);
        // `binary` follows the winning side deliberately: it is what the audit record and
        // the refusal message name, and naming the outer `echo` would describe the wrong
        // process as the one that ran as root.
        if (CLASS_RANK[parsed.class] > CLASS_RANK[highest.class])
            highest = parsed;
    }
    // `readOnlyRejection` only ever describes why the outer command's reader was
    // refused read-only — a grammar rejection or a shell metacharacter, see
    // `ReadOnlyRejection` — and only means anything when that is also what decided
    // the final class. `highest === outer` (reference equality) is exactly that
    // condition: the synthetic floor and the nested-command loop above only
    // ever replace `highest` with something of strictly higher rank than
    // `outer`'s, so if either one fired, `highest` is no longer `outer` and the
    // rejection — which was never a fact about the synthetic verb or the nested
    // command anyway — is correctly left off.
    const result = { binary: highest.binary, fullCommand: trimmed, class: highest.class };
    if (highest === outer && outer.readOnlyRejection) {
        result.readOnlyRejection = outer.readOnlyRejection;
    }
    return result;
}
/** The class of the command itself, reading none of what it carries. */
function classifyOuter(trimmed, dialect) {
    const binary = extractBinary(trimmed, dialect);
    const fullCommand = trimmed;
    // `binary` names the subject of the class. For everything below it is the
    // leading command; here it is the one that runs as root, which are the same
    // thing only when the prefix leads.
    const elevated = elevatedBinaryOf(trimmed, dialect);
    if (elevated !== null) {
        return { binary: elevated, fullCommand, class: 'privileged' };
    }
    // Checked beside the elevation it matches in authority but not in shape:
    // a broker needs no `sudo` in front of it, so `elevatedBinaryOf` never
    // fires, and the brokers each classified `safe` — the class no approval
    // gate ever sees (GHSA-cm4c-4q74-mgmj).
    const broker = brokeredElevationOf(trimmed, dialect);
    if (broker !== null) {
        return { binary: broker, fullCommand, class: 'privileged' };
    }
    if (hasUnreadableProgram(trimmed, dialect) || hasDangerousAwk(trimmed, dialect)
        || isDestructive(trimmed, dialect) || hasDisqualifyingArgs(trimmed, dialect)) {
        return { binary, fullCommand, class: 'destructive' };
    }
    // Below this point every branch assumes the command word names something we
    // recognised. When it is a variable expansion it names nothing we can check, so
    // the allowlist must not be consulted — `$S` is not on it, and falling through to
    // the default made an unknown command `safe`.
    //
    // `destructive` rather than `privileged`: this is "we cannot tell", not "this is
    // root". It gates on approval instead of refusing outright, which keeps
    // `$PREFIX/bin/tool` usable for a role that holds `destructive` on the tier.
    if (hasUnnameableCommand(trimmed, dialect)) {
        return { binary, fullCommand, class: 'destructive' };
    }
    const words = tokenizeSegments(fullCommand, dialect)[0] ?? [];
    const twoWordPrefix = words.slice(0, 2).join(' ');
    if (READ_ONLY_ALLOWLIST.has(binary) || READ_ONLY_ALLOWLIST.has(twoWordPrefix)
        || READ_ONLY_SYNTHETIC.has(binary)) {
        // Whichever key matched decides both which entry answers and how many
        // leading words are the command name rather than an argument: a two-word
        // entry's grammar reads words[2..], a one-word entry's reads words[1..]. An
        // SFTP verb's two-word prefix is never a key, so it is named by itself.
        const matchedTwoWord = READ_ONLY_ALLOWLIST.has(twoWordPrefix);
        const readerName = matchedTwoWord ? twoWordPrefix : binary;
        const metacharacter = SHELL_CONTROL_CHARS.exec(trimmed);
        if (metacharacter) {
            return {
                binary,
                fullCommand,
                class: 'safe',
                readOnlyRejection: { binary: readerName, word: metacharacter[0], cause: 'shell-metacharacter' },
            };
        }
        // The SFTP verbs are synthesised by the tool layer, never typed by a caller,
        // so there is no argv for a grammar to read — READ_ONLY_SYNTHETIC stays
        // exactly as it was.
        if (READ_ONLY_SYNTHETIC.has(binary)) {
            return { binary, fullCommand, class: 'read-only' };
        }
        const entry = READERS[readerName];
        const argWords = words.slice(matchedTwoWord ? 2 : 1);
        // An unquoted glob word is not a word this grammar can vouch for: the
        // shell replaces it with however many filenames it matches, and the
        // grammar's operand count — the thing it was about to prove — is false
        // before the binary runs. `'any'` entries are exempt: their claim is that
        // no option or operand of the binary writes or executes, so extra
        // operands from an expansion are still data.
        if (entry.grammar.args !== 'any') {
            const globWord = firstUnquotedGlobWord(fullCommand, true, dialect);
            if (globWord !== null) {
                return {
                    binary,
                    fullCommand,
                    class: 'safe',
                    readOnlyRejection: { binary: readerName, word: globWord, cause: 'grammar' },
                };
            }
        }
        const match = matchesGrammar(argWords, entry.grammar);
        if (!match.ok) {
            return {
                binary,
                fullCommand,
                class: 'safe',
                readOnlyRejection: { binary: readerName, word: match.word, cause: 'grammar' },
            };
        }
        return { binary, fullCommand, class: 'read-only' };
    }
    return { binary, fullCommand, class: 'safe' };
}
/**
 * The sentence a refusal appends when it carries a `readOnlyRejection`, in one of
 * two shapes chosen by its `cause`. Both name the reader that would have qualified
 * and what cost it the class.
 *
 * - `grammar`: names the argv word, as "is not accepted there" rather than "is not
 *   one of them", because most rejections are operand rules (`hostname NAME`,
 *   `sort /data`) or a listed value flag missing its value, where "is not one of
 *   them" would be false — it may be a perfectly good flag name, just not one bare
 *   or in this position.
 * - `shell-metacharacter`: names the character, and for the SFTP verbs says it is
 *   in the remote path (#224).
 *
 * One function so the engine's role-binding denial and `read-command`'s
 * `enforceClass` refusal never drift into two spellings of the same sentence.
 */
function formatReadOnlyRejection(rejection) {
    if (rejection.cause === 'shell-metacharacter') {
        // `\n` and `\r` are in SHELL_CONTROL_CHARS, and quoted raw they would break the
        // sentence across lines or render as nothing. A backtick is in it too, and inside
        // single backticks it would print as three in a row; double backticks with
        // padding is Markdown's own way to quote one.
        const char = rejection.word.replace(/\n/g, '\\n').replace(/\r/g, '\\r');
        const quoted = char === '`' ? '`` ` ``' : `\`${char}\``;
        // The SFTP verbs' operand is a path the tool layer built the command from, so the
        // path is what the caller can change — not "the command", which they never typed.
        // The verb is named as the audit record spells it (`sftp:list`), not as the tool
        // (`sftp-list`), so the refusal and the record it is filed under read the same.
        if (READ_ONLY_SYNTHETIC.has(rejection.binary)) {
            return `The remote path contains ${quoted}, which counts as a shell metacharacter here, ` +
                `so \`${rejection.binary}\` is read-only only for a path without one.`;
        }
        return `\`${rejection.binary}\` is read-only only when the command contains no shell metacharacter; ` +
            `${quoted} is one.`;
    }
    // The rejected word can be the empty string — a quoted empty operand
    // (`hostname ""`) — and two bare backticks would render as a blank where
    // the word that cost the class should be. `""` is the shell's own spelling
    // of that operand.
    const word = rejection.word === '' ? '""' : rejection.word;
    return `\`${rejection.binary}\` is read-only only with the options and operands its grammar lists; ` +
        `\`${word}\` is not accepted there.`;
}
return {classifyCommand, findForbiddenMatch};
})();

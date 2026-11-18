//! Native Rust port of upstream remote-path and never-allowed-writes rules.
//!
//! Paths are lexical: they do not resolve symlinks or Windows 8.3 names.
//! Conservative Windows readings intentionally widen refusals on POSIX.

fn normalize_remote_path(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let mut parts = slashed.split('/');
    let first = parts.next().unwrap_or("");
    let (root, mut remaining): (Option<&str>, Vec<&str>) = if first.is_empty() {
        (Some(""), parts.collect())
    } else if first.len() == 2
        && first.as_bytes()[0].is_ascii_alphabetic()
        && first.as_bytes()[1] == b':'
    {
        (Some(first), parts.collect())
    } else {
        (None, std::iter::once(first).chain(parts).collect())
    };
    let mut kept = Vec::new();
    for part in remaining.drain(..) {
        push_segment(&mut kept, part, root.is_some());
    }
    render_path(root, &kept)
}

fn normalize_remote_path_for_windows(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let slashed = slashed
        .strip_prefix("//?/")
        .or_else(|| slashed.strip_prefix("//./"))
        .unwrap_or(&slashed);
    let parts: Vec<&str> = slashed.split('/').collect();
    let (root, remaining): (Option<String>, Vec<&str>) =
        if parts.first() == Some(&"") && parts.get(1) == Some(&"") {
            (
                Some(format!(
                    "//{}/{}",
                    parts.get(2).copied().unwrap_or(""),
                    parts.get(3).copied().unwrap_or("")
                )),
                parts.iter().skip(4).copied().collect(),
            )
        } else if parts.first() == Some(&"") {
            (
                Some("/".to_owned()),
                parts.iter().skip(1).copied().collect(),
            )
        } else if let Some(head) = parts.first().copied().filter(|head| {
            head.len() >= 2
                && head.as_bytes()[0].is_ascii_alphabetic()
                && head.as_bytes()[1] == b':'
        }) {
            let mut rest: Vec<&str> = Vec::new();
            if !head[2..].is_empty() {
                rest.push(&head[2..]);
            }
            rest.extend(parts.iter().skip(1).copied());
            (Some(head[..2].to_owned()), rest)
        } else {
            (None, parts)
        };
    let mut kept = Vec::new();
    for part in remaining {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            push_segment(&mut kept, part, root.is_some());
            continue;
        }
        let plain = part
            .split("::")
            .next()
            .unwrap_or("")
            .trim_end_matches([' ', '.']);
        if !plain.is_empty() {
            kept.push(plain);
        }
    }
    render_path(root.as_deref(), &kept)
}

fn push_segment<'a>(kept: &mut Vec<&'a str>, part: &'a str, rooted: bool) {
    match part {
        "" | "." => {}
        ".." if kept.last().is_some_and(|last| *last != "..") => {
            kept.pop();
        }
        ".." if !rooted => kept.push(".."),
        ".." => {}
        _ => kept.push(part),
    }
}

fn render_path(root: Option<&str>, kept: &[&str]) -> String {
    match root {
        None => {
            if kept.is_empty() {
                ".".to_owned()
            } else {
                kept.join("/")
            }
        }
        Some("") | Some("/") => format!("/{}", kept.join("/")),
        Some(prefix) => format!("{prefix}/{}", kept.join("/")),
    }
}

fn family_of(path: &str) -> Option<&'static str> {
    for directory in ["/etc/cron", "/etc/systemd"] {
        if path.starts_with(directory) {
            return Some(directory);
        }
    }
    if path.ends_with("/.ssh/authorized_keys") || path == ".ssh/authorized_keys" {
        return Some("authorized_keys");
    }
    None
}

/// Identify hard-denied write targets across all upstream path readings.
pub(crate) fn find_never_allowed_write_target(path: &str) -> Option<&'static str> {
    family_of(path)
        .or_else(|| family_of(&normalize_remote_path(path)))
        .or_else(|| family_of(&normalize_remote_path_for_windows(path).to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_paths_cannot_escape_the_root() {
        for (input, expected) in [
            ("/etc//cron/./jobs/../", "/etc/cron"),
            ("/../../etc/cron", "/etc/cron"),
            ("C:\\Users\\a\\..\\file", "C:/Users/file"),
            ("C:/../../systemd", "C:/systemd"),
            ("a/../../b", "../b"),
            ("a/..", "."),
            ("./.", "."),
            ("", "/"),
            ("//", "/"),
        ] {
            assert_eq!(normalize_remote_path(input), expected, "{input:?}");
        }
    }

    #[test]
    fn windows_aliases_are_normalized_conservatively() {
        for (input, expected) in [
            (
                r"\\server\share\a\..\authorized_keys",
                "//server/share/authorized_keys",
            ),
            (
                r"\\?\C:\Users\a\.ssh\authorized_keys. ",
                "C:/Users/a/.ssh/authorized_keys",
            ),
            ("C:folder/file", "C:/folder/file"),
            ("a.../b", "a/b"),
            ("authorized_keys::$DATA", "authorized_keys"),
            ("/foo/../../bar", "/bar"),
            (".", "."),
        ] {
            assert_eq!(
                normalize_remote_path_for_windows(input),
                expected,
                "{input:?}"
            );
        }
    }

    #[test]
    fn protected_paths_cover_aliases_and_refuse_prefixes() {
        for (path, family) in [
            ("/etc/cron.d/job", "/etc/cron"),
            ("/etc/cronography", "/etc/cron"),
            ("/tmp/../etc/systemd/system/x", "/etc/systemd"),
            (r"\ETC\SYSTEMD\system\x", "/etc/systemd"),
            ("/home/user/.ssh/authorized_keys", "authorized_keys"),
            (r"C:\Users\a\.ssh\Authorized_Keys. ", "authorized_keys"),
            (".ssh/authorized_keys::$DATA", "authorized_keys"),
        ] {
            assert_eq!(
                find_never_allowed_write_target(path),
                Some(family),
                "{path:?}"
            );
        }
        for path in [
            "/etc/other",
            "/home/user/.ssh/config",
            "a/b",
            "authorized_keys",
        ] {
            assert_eq!(find_never_allowed_write_target(path), None, "{path:?}");
        }
    }
}

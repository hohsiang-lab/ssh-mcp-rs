//! Native privilege-prefix and brokered elevation discovery.

use crate::{
    upstream_heads::{command_heads, command_readings},
    upstream_shell::tokenize_detailed,
};

pub(crate) fn elevated_binary(command: &str, windows: bool) -> Option<String> {
    for segment in tokenize_detailed(command, true, windows) {
        for reading in command_readings(&segment.words) {
            if let Some(prefix) = reading.prefix {
                if reading.index < 0 {
                    return Some(prefix);
                }
                let word = &segment.words[reading.index as usize];
                return Some(word.rsplit(['/', '\\']).next().unwrap_or(word).to_owned());
            }
        }
    }
    None
}

fn root_user(value: &str) -> bool {
    matches!(value.split(':').next(), Some("0" | "root"))
}

fn privileged_flag(value: &str) -> bool {
    value == "--privileged" || matches!(value.strip_prefix("--privileged="), Some("true" | "1"))
}

fn docker_root(args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        let word = args[i].as_str();
        i += if matches!(
            word,
            "-H" | "--host" | "--context" | "--config" | "--log-level" | "-l"
        ) {
            2
        } else {
            1
        };
    }
    let Some(mut sub) = args.get(i).map(String::as_str) else {
        return false;
    };
    let mut rest = &args[(i + 1)..];
    if sub == "container" {
        sub = rest.first().map_or("", String::as_str);
        rest = &rest[rest.len().min(1)..];
    }
    if !matches!(sub, "run" | "exec") {
        return false;
    }
    for (j, word) in rest.iter().enumerate() {
        if privileged_flag(word) {
            return true;
        }
        if matches!(word.as_str(), "-u" | "--user")
            && rest.get(j + 1).is_some_and(|value| root_user(value))
        {
            return true;
        }
        if word.strip_prefix("--user=").is_some_and(root_user) {
            return true;
        }
        if let Some(value) = word.strip_prefix("-u")
            && !value.is_empty()
            && root_user(value.trim_start_matches('='))
        {
            return true;
        }
    }
    false
}

fn systemd_root(args: &[String]) -> bool {
    for (index, word) in args.iter().enumerate() {
        if word == "--uid" && args.get(index + 1).is_some_and(|arg| root_user(arg)) {
            return true;
        }
        if word.strip_prefix("--uid=").is_some_and(root_user) {
            return true;
        }
        let property = if matches!(word.as_str(), "-p" | "--property") {
            args.get(index + 1).map(String::as_str)
        } else {
            word.strip_prefix("--property=")
        };
        if let Some((user_key, user)) = property.and_then(|value| value.split_once('='))
            && user_key.eq_ignore_ascii_case("User")
            && root_user(user)
        {
            return true;
        }
    }
    false
}

fn nsenter(args: &[String]) -> bool {
    for (index, word) in args.iter().enumerate() {
        if matches!(word.as_str(), "-t" | "--target") && args.get(index + 1).is_some() {
            return true;
        }
        if word.starts_with("-t")
            && word
                .get(2..)
                .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
        {
            return true;
        }
        if word
            .strip_prefix("--target=")
            .is_some_and(|suffix| !suffix.is_empty())
        {
            return true;
        }
    }
    false
}

pub(crate) fn brokered_elevation(command: &str, windows: bool) -> Option<String> {
    for segment in tokenize_detailed(command, true, windows) {
        for (index, head) in command_heads(&segment.words) {
            let rest = &segment.words[(index + 1)..];
            let needs_root = match head.as_str() {
                "docker" => docker_root(rest),
                "systemd-run" => systemd_root(rest),
                "nsenter" => nsenter(rest),
                _ => false,
            };
            if needs_root {
                return Some(head);
            }
        }
    }
    None
}

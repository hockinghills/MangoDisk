//! Hides credentials in command lines, scripts and URLs before they leave Core.
//!
//! Process command lines regularly carry tokens (`--api-key=…`, `https://user:pass@host`,
//! bearer tokens). The page shows command lines so the user can identify a process, which is
//! useful only without those values.

const SECRET_KEY_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passwrd",
    "apikey",
    "api-key",
    "api_key",
    "auth",
    "credential",
    "cookie",
    "sessionid",
    "session-id",
    "session_id",
    "privatekey",
    "private-key",
    "private_key",
];
/// Runs of token characters this long are almost always keys, hashes or signed URLs.
const LONG_TOKEN_CHARS: usize = 40;
const MASK: &str = "***";

fn looks_like_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_WORDS.iter().any(|word| lower.contains(word))
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '_' | '-')
}

/// Masks `scheme://user:password@` and replaces long token-like runs.
pub(crate) fn redact_text(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    mask_long_tokens(&mask_url_credentials(&cleaned))
}

fn mask_url_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let (head, tail) = rest.split_at(index + 3);
        out.push_str(head);
        let authority_end = tail
            .find(|ch: char| ch == '/' || ch.is_whitespace())
            .unwrap_or(tail.len());
        match tail[..authority_end].rfind('@') {
            Some(at) if at > 0 => {
                out.push_str(MASK);
                rest = &tail[at..];
            }
            _ => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

fn mask_long_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.chars().count() >= LONG_TOKEN_CHARS {
            out.push_str(MASK);
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in text.chars() {
        if is_token_char(ch) {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Hides the values of arguments whose names look like credentials.
pub(crate) fn redact_command_line(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut hide_next = false;
    for arg in argv {
        if hide_next {
            out.push(MASK.to_owned());
            hide_next = false;
            continue;
        }
        let key = arg.split_once('=').map_or(arg.as_str(), |(key, _)| key);
        if looks_like_secret_key(key) && !arg.starts_with('/') {
            if arg.contains('=') {
                out.push(format!("{key}={MASK}"));
            } else {
                out.push(arg.clone());
                hide_next = arg.starts_with('-');
            }
            continue;
        }
        out.push(redact_text(arg));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn credential_arguments_are_masked() {
        assert_eq!(
            redact_command_line(&argv(&[
                "tool",
                "--api-key",
                "abc",
                "--TOKEN=xyz",
                "--port",
                "80"
            ])),
            argv(&["tool", "--api-key", "***", "--TOKEN=***", "--port", "80"])
        );
    }

    #[test]
    fn paths_that_mention_auth_are_kept() {
        assert_eq!(
            redact_command_line(&argv(&["/usr/lib/auth-helper", "run"])),
            argv(&["/usr/lib/auth-helper", "run"])
        );
    }

    #[test]
    fn url_credentials_and_long_tokens_are_masked() {
        assert_eq!(
            redact_text("git fetch https://user:hunter2@example.test/repo.git"),
            "git fetch https://***@example.test/repo.git"
        );
        let token = "a".repeat(45);
        assert_eq!(
            redact_text(&format!("Bearer {token} done")),
            "Bearer *** done"
        );
        assert_eq!(redact_text("line\nbreak"), "line break");
    }
}

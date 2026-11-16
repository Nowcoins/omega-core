//! The list of warning codes (`signing/warning.rs`), the file the apps read (`warning-codes.json`), and the
//! engine's use of the list.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::super::warning::{ALL, Shown, assert_listed};

/// The file each app's parity test reads.
const FILE: &str = include_str!("../../../warning-codes.json");

fn codes_shown(wanted: &[Shown]) -> Vec<&'static str> {
    let mut codes: Vec<&str> =
        ALL.iter().filter(|l| wanted.contains(&l.shown)).map(|l| l.code.as_str()).collect();
    codes.sort_unstable();
    codes
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().expect("a code is a string").to_owned())
        .collect()
}

#[test]
fn the_file_the_apps_read_is_the_engines_list() {
    let file: Value = serde_json::from_str(FILE).unwrap();
    let object = file.as_object().unwrap();
    assert_eq!(object.keys().map(String::as_str).collect::<Vec<_>>(), ["send", "signing"]);
    // What a send's review shows, and what a site's request shows; the fee warning is in both.
    for (key, shown) in
        [("send", [Shown::Send, Shown::Both]), ("signing", [Shown::Signing, Shown::Both])]
    {
        let in_file = strings(&file[key]);
        assert_eq!(
            in_file,
            codes_shown(&shown),
            "{key}: warning-codes.json differs from warning.rs"
        );
        // Sorted, so that a change reads as one line in a diff.
        let mut sorted = in_file.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(in_file, sorted, "{key} is sorted, with no code twice");
    }
}

#[test]
fn a_code_is_written_once_in_lower_case_words() {
    let mut seen = BTreeSet::new();
    let mut names = BTreeSet::new();
    for listed in ALL {
        let code = listed.code.as_str();
        assert!(seen.insert(code), "{code} is listed twice");
        assert!(names.insert(listed.name), "{} is declared twice", listed.name);
        assert!(!code.is_empty() && !code.starts_with('_') && !code.ends_with('_'), "{code}");
        assert!(
            code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') && !code.contains("__"),
            "{code} is words in lower case joined by single underscores"
        );
        // The constant is the code, in capitals.
        assert_eq!(listed.name, code.to_ascii_uppercase(), "{code}");
    }
}

/// The engine's own source: each file of `src/signing` but the list itself and the tests, up to an inline
/// `mod tests {` (always the last item of a file).
fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/signing");
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.extension().is_none_or(|ext| ext != "rs")
            || name == "warning.rs"
            || name == "tests.rs"
        {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let production = text.split("\nmod tests {").next().unwrap().to_owned();
        files.push((name, production));
    }
    files.sort();
    assert!(files.len() >= 8, "the engine's sources were found: {files:?}");
    files
}

/// Whether `text` names the constant `warning::NAME` (not a longer name that starts the same).
fn names_constant(text: &str, name: &str) -> bool {
    let needle = format!("warning::{name}");
    text.match_indices(&needle).any(|(at, _)| {
        !text[at + needle.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Whether `text` writes `"code"` as a value. A field of a summary that is named like a warning is a key and not a
/// warning: `"durable_nonce": …` where it is made, `details["hidden_characters"]` where it is read.
fn writes_code(text: &str, code: &str) -> bool {
    let quoted = format!("\"{code}\"");
    text.match_indices(&quoted)
        .any(|(at, _)| !text[at + quoted.len()..].trim_start().starts_with([':', ']']))
}

#[test]
fn the_engine_never_writes_a_code_as_a_string() {
    // A code that is a string in the engine's source can be one the list has not heard of, or one the list
    // later drops. Every warning is raised by naming its constant.
    for (file, text) in sources() {
        for listed in ALL {
            let code = listed.code.as_str();
            assert!(
                !writes_code(&text, code),
                "{file} writes \"{code}\": use warning::{}",
                listed.name
            );
        }
        assert!(
            !text.contains("push(Value::from(\""),
            "{file} pushes a string into a summary's warnings: use a constant of warning.rs"
        );
        assert!(
            !text.contains("warnings.push(\""),
            "{file} pushes a string as a warning: use a constant of warning.rs"
        );
    }
}

#[test]
fn every_listed_code_is_raised_for_the_screens_the_list_says() {
    let sources = sources();
    let raised_in = |name: &str, files: &[&str]| {
        sources
            .iter()
            .any(|(file, text)| files.contains(&file.as_str()) && names_constant(text, name))
    };
    for listed in ALL {
        let name = listed.name;
        // Where a request is read for its warnings: the site's kinds are in these files, a send's in `send.rs`,
        // and `mod.rs` adds the fee warning to any kind.
        let signing = ["evm.rs", "solana.rs", "tron.rs", "text.rs"];
        match listed.shown {
            Shown::Send => {
                assert!(
                    raised_in(name, &["send.rs"]),
                    "{name} is listed for a send; send.rs never raises it"
                );
                assert!(
                    !raised_in(name, &signing),
                    "{name} is listed for a send only; a site's request raises it"
                );
            }
            Shown::Signing => {
                assert!(
                    raised_in(name, &signing),
                    "{name} is listed for a site's request; none raises it"
                );
                assert!(
                    !raised_in(name, &["send.rs"]),
                    "{name} is listed for a site's request only; send.rs raises it"
                );
            }
            Shown::Both => {
                assert!(
                    raised_in(name, &["mod.rs"]),
                    "{name} is listed for both; mod.rs never raises it"
                );
            }
        }
    }
}

#[test]
fn a_summary_with_a_code_that_is_not_listed_is_caught() {
    let every: Vec<&str> = ALL.iter().map(|l| l.code.as_str()).collect();
    assert_listed(&json!({ "warnings": every }));
    assert_listed(&json!({ "warnings": [] }));
}

#[test]
#[should_panic(expected = "made_up_warning")]
fn a_code_that_is_not_listed_fails_the_test_that_raised_it() {
    assert_listed(&json!({ "warnings": ["unlimited_approval", "made_up_warning"] }));
}

#[test]
#[should_panic(expected = "a list of warnings")]
fn a_summary_without_its_list_fails_too() {
    assert_listed(&json!({ "request": "send" }));
}

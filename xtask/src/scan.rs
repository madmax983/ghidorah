//! Source gates over the Rust files of the workspace.
//!
//! Each check takes one file (its relative path and its text) and gives its findings.
//! The checks search stripped text (see [`crate::rustsrc`]), so comments and strings do not count.
//! Each pattern comes from parts, so this file does not match its own patterns.

use std::path::Path;

use crate::rustsrc::{find_word, line_of, strip};
use crate::{Error, Finding};

/// The maximum line count of a non-table, non-test source file (AC-014).
pub const MAX_FILE_LINES: usize = 600;

/// The maximum depth of the directory walk.
const MAX_WALK_DEPTH: usize = 32;

/// Gives every `.rs` file under `crates/` and `xtask/`, relative to `root` and sorted.
///
/// The walk skips `target` directories and hidden directories.
///
/// # Errors
///
/// Returns [`Error::Io`] when a directory read fails.
pub fn rust_files(root: &Path) -> Result<Vec<String>, Error> {
    let mut files = Vec::new();
    for top in ["crates", "xtask"] {
        let dir = root.join(top);
        if dir.is_dir() {
            walk(root, &dir, 0, &mut files)?;
        }
    }
    files.sort();
    Ok(files)
}

fn walk(root: &Path, dir: &Path, depth: usize, files: &mut Vec<String>) -> Result<(), Error> {
    if depth > MAX_WALK_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry.file_type().map_err(|e| Error::io(&path, e))?;
        if kind.is_dir() {
            if name != "target" && !name.starts_with('.') {
                walk(root, &path, depth + 1, files)?;
            }
        } else if kind.is_file() && path.extension().is_some_and(|x| x == "rs") {
            files.push(crate::workspace::rel(root, &path));
        }
    }
    Ok(())
}

/// Tells if a file holds test code: a `tests.rs` file or a file under a `tests/` directory.
#[must_use]
pub fn is_test_file(rel: &str) -> bool {
    rel.ends_with("/tests.rs") || rel == "tests.rs" || rel.split('/').any(|part| part == "tests")
}

/// Tells if a file is a const table file under a `tables/` directory.
#[must_use]
pub fn is_table_file(rel: &str) -> bool {
    rel.split('/').any(|part| part == "tables")
}

/// Gives the crate directory name of a path: `crates/json/src/lib.rs` gives `json`.
///
/// A path under `xtask/` gives `xtask`.
#[must_use]
pub fn crate_dir(rel: &str) -> Option<&str> {
    let mut parts = rel.split('/');
    match parts.next() {
        Some("crates") => parts.next().filter(|_| parts.next().is_some()),
        Some("xtask") => Some("xtask"),
        _ => None,
    }
}

fn find_all(
    rule: &str,
    rel: &str,
    text: &str,
    hay: &str,
    needle: &str,
    what: &str,
) -> Vec<Finding> {
    hay.match_indices(needle)
        .map(|(i, _)| Finding::new(rule, rel, line_of(text, i), what))
        .collect()
}

fn find_words(rule: &str, rel: &str, hay: &str, word: &str, what: &str) -> Vec<Finding> {
    find_word(hay, word)
        .into_iter()
        .map(|i| Finding::new(rule, rel, line_of(hay, i), what))
        .collect()
}

/// AC-012: finds stub markers and panicking calls in non-test code.
#[must_use]
pub fn no_stubs(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = Vec::new();
    let calls = [
        (concat!("to", "do!"), "stub macro"),
        (concat!("unimple", "mented!"), "stub macro"),
        (concat!("db", "g!"), "debug macro"),
        (concat!(".un", "wrap()"), "panicking call"),
        (concat!(".ex", "pect("), "panicking call"),
    ];
    for (needle, what) in calls {
        found.extend(find_all("AC-012", rel, &code, &code, needle, what));
    }
    for word in [
        concat!("TO", "DO"),
        concat!("FIX", "ME"),
        concat!("X", "XX"),
    ] {
        found.extend(find_words("AC-012", rel, text, word, "stub marker"));
    }
    found.sort();
    found
}

/// AC-014: finds a file with more than [`MAX_FILE_LINES`] lines.
#[must_use]
pub fn file_size(rel: &str, text: &str) -> Vec<Finding> {
    let lines = text.lines().count();
    if lines > MAX_FILE_LINES {
        vec![Finding::new(
            "AC-014",
            rel,
            0,
            format!("the file has {lines} lines; the cap is {MAX_FILE_LINES}"),
        )]
    } else {
        Vec::new()
    }
}

fn attribute_end(code: &str, start: usize) -> usize {
    code.get(start..)
        .and_then(|rest| rest.find(']'))
        .map_or(code.len(), |i| start + i)
}

/// AC-016: finds an `allow` of `disallowed_types`, or an `expect` without a reason.
#[must_use]
pub fn disallowed_exceptions(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = Vec::new();
    let needle = concat!("clippy::disallowed", "_types");
    for (i, _) in code.match_indices(needle) {
        let before = code.get(..i).unwrap_or_default();
        let open = before.rfind('[').unwrap_or(0);
        let attr = code.get(open..attribute_end(&code, i)).unwrap_or_default();
        let line = line_of(&code, i);
        if attr.contains("allow(") {
            found.push(Finding::new(
                "AC-016",
                rel,
                line,
                "use `expect` with a reason, not `allow`",
            ));
        } else if attr.contains("expect(") && !attr.contains("reason") {
            found.push(Finding::new(
                "AC-016",
                rel,
                line,
                "the `expect` has no reason",
            ));
        }
    }
    found
}

/// Gives the text from the start of `text` to the brace that closes its first `{`.
///
/// Nested groups count, so `std::{a::{b}, c}` gives the full group.
fn brace_group(text: &str) -> &str {
    let mut depth = 0usize;
    for (i, c) in text.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth <= 1 => return text.get(..i).unwrap_or(text),
            '}' => depth -= 1,
            _ => {}
        }
    }
    text
}

/// AC-017: finds use of file, network, process, environment or wall-clock APIs.
#[must_use]
pub fn layering(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = Vec::new();
    for module in ["fs", "net", "process", "env"] {
        let path = format!("std::{module}");
        for i in find_word(&code, &path) {
            found.push(Finding::new(
                "AC-017",
                rel,
                line_of(&code, i),
                format!("pure core crates do not use `{path}`"),
            ));
        }
    }
    found.extend(find_words(
        "AC-017",
        rel,
        &code,
        "SystemTime",
        "pure core crates do not use `SystemTime`",
    ));
    for (i, _) in code.match_indices("std::{") {
        let names = code.get(i..).map_or("", brace_group);
        for module in ["fs", "net", "process", "env"] {
            if !find_word(names, module).is_empty() {
                found.push(Finding::new(
                    "AC-017",
                    rel,
                    line_of(&code, i),
                    format!("pure core crates do not use `std::{module}`"),
                ));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// AC-223: finds calls that change the process environment.
#[must_use]
pub fn no_set_var(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = Vec::new();
    for name in [concat!("set", "_var"), concat!("remove", "_var")] {
        found.extend(find_words(
            "AC-223",
            rel,
            &code,
            name,
            "no crate changes the process environment",
        ));
    }
    found.sort();
    found
}

/// AC-004: finds `unsafe` code or an `unsafe_code` lint exception.
#[must_use]
pub fn no_unsafe(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = find_words(
        "AC-004",
        rel,
        &code,
        "unsafe",
        "shipped crates contain no unsafe code",
    );
    let lint = concat!("unsafe", "_code");
    for i in find_word(&code, lint) {
        let before = code.get(..i).unwrap_or_default();
        let open = before.rfind('[').unwrap_or(0);
        let attr = code.get(open..i).unwrap_or_default();
        if attr.contains("expect(") || attr.contains("allow(") {
            found.push(Finding::new(
                "AC-004",
                rel,
                line_of(&code, i),
                "shipped crates have no `unsafe_code` exception",
            ));
        }
    }
    found.sort();
    found
}

/// AC-008: finds network or process use in a build script.
#[must_use]
pub fn build_script(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = Vec::new();
    for word in [
        "std::net",
        "std::process",
        "TcpStream",
        "UdpSocket",
        "Command",
    ] {
        found.extend(find_words(
            "AC-008",
            rel,
            &code,
            word,
            "build scripts do not use the network or child processes",
        ));
    }
    found.sort();
    found.dedup_by(|a, b| a.line == b.line);
    found
}

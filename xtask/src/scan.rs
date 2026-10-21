//! Source gates over the Rust files of the workspace.
//!
//! Each check takes one file (its relative path and its text) and gives its findings.
//! The checks search stripped text (see [`crate::rustsrc`]), so comments and strings do not count.
//! Each pattern comes from parts, so this file does not match its own patterns.

use std::path::Path;

use crate::rustsrc::{find_word, line_of, strip};
use crate::{Error, Finding, manifest};

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

fn find_text(rule: &str, rel: &str, hay: &str, needle: &str, what: &str) -> Vec<Finding> {
    hay.match_indices(needle)
        .map(|(i, _)| Finding::new(rule, rel, line_of(hay, i), what))
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
        found.extend(find_text("AC-012", rel, &code, needle, what));
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

/// Gives the attribute text around byte `at`: from the last `[` before it to the next `]`.
fn enclosing_attribute(code: &str, at: usize) -> &str {
    let open = code.get(..at).and_then(|b| b.rfind('[')).unwrap_or(0);
    let close = code
        .get(at..)
        .and_then(|rest| rest.find(']'))
        .map_or(code.len(), |i| at + i);
    code.get(open..close).unwrap_or_default()
}

/// AC-016: finds an `allow` of `disallowed_types`, or an `expect` without a reason.
#[must_use]
pub fn disallowed_exceptions(rel: &str, text: &str) -> Vec<Finding> {
    let code = strip(text);
    let mut found = Vec::new();
    let needle = concat!("clippy::disallowed", "_types");
    for (i, _) in code.match_indices(needle) {
        let attr = enclosing_attribute(&code, i);
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

/// The levels of a lint attribute.
const LEVELS: [&str; 4] = ["allow", "expect", "deny", "forbid"];

/// One lint that a lint attribute names, for example `clippy::panic` of `#[allow(clippy::panic)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintAttr {
    /// The 1-based line of the attribute.
    pub line: usize,
    /// The level: `allow`, `expect`, `deny` or `forbid`.
    pub level: &'static str,
    /// The lint path without white space, for example `clippy::panic` or `missing_docs`.
    pub lint: String,
    /// True when the attribute gives a `reason`.
    pub reason: bool,
}

/// Gives the text inside the group that `text` opens with `open`.
///
/// Nested groups of the same kind count. A group without its `close` gives the rest of the text.
fn inside(text: &str, open: char, close: char) -> &str {
    let mut depth = 0usize;
    for (i, c) in text.char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return text.get(open.len_utf8()..i).unwrap_or_default();
            }
        }
    }
    text.get(open.len_utf8()..).unwrap_or_default()
}

/// Splits a list at each comma outside a nested group. Empty items do not count.
fn split_list(list: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in list.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(list.get(start..i).unwrap_or_default().trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(list.get(start..).unwrap_or_default().trim());
    items.retain(|item| !item.is_empty());
    items
}

/// Gives each lint that an `allow`, `expect`, `deny` or `forbid` attribute of `text` names.
///
/// The scan reads stripped text, so a comment or a string does not count. A level inside a
/// `cfg_attr` attribute counts too.
#[must_use]
pub fn lint_attributes(text: &str) -> Vec<LintAttr> {
    let code = strip(text);
    let mut found = Vec::new();
    for (at, _) in code.match_indices('#') {
        let rest = code.get(at + 1..).unwrap_or_default();
        let rest = rest.strip_prefix('!').unwrap_or(rest).trim_start();
        if !rest.starts_with('[') {
            continue;
        }
        let body = inside(rest, '[', ']');
        let line = line_of(&code, at);
        for level in LEVELS {
            for i in find_word(body, level) {
                let after = body.get(i + level.len()..).unwrap_or_default().trim_start();
                if !after.starts_with('(') {
                    continue;
                }
                let items = split_list(inside(after, '(', ')'));
                let reason = items.iter().any(|item| item.starts_with("reason"));
                for item in items.iter().filter(|item| !item.contains('=')) {
                    let path: String = item.chars().filter(|c| !c.is_whitespace()).collect();
                    found.push(LintAttr {
                        line,
                        level,
                        lint: path,
                        reason,
                    });
                }
            }
        }
    }
    found
}

/// Tells if a file is non-test source code of a package: a file under `crates/<name>/src/`
/// or `xtask/src/` that [`is_test_file`] does not select.
#[must_use]
pub fn is_source_file(rel: &str) -> bool {
    let mut parts = rel.split('/');
    let in_src = match parts.next() {
        Some("crates") => parts.nth(1) == Some("src"),
        Some("xtask") => parts.next() == Some("src"),
        _ => false,
    };
    in_src && !is_test_file(rel)
}

/// Gives the clippy lints that a `deny` or `forbid` attribute of `text` names, without the
/// `clippy::` prefix.
#[must_use]
pub fn denied_clippy_lints(text: &str) -> Vec<String> {
    lint_attributes(text)
        .into_iter()
        .filter(|a| matches!(a.level, "deny" | "forbid"))
        .filter_map(|a| a.lint.strip_prefix("clippy::").map(str::to_owned))
        .collect()
}

/// AC-010: finds an `allow` or `expect` of a clippy group lint that ADR-0019 does not review.
///
/// A `restriction` lint is out of scope, because the workspace or a crate denies it by name.
/// A `tables/` file can take a group lint exception. `disallowed_types` with a reason is the
/// exception of CLAUDE.md (AC-016). Each other exception needs an entry of
/// [`manifest::REVIEWED_EXCEPTIONS`].
#[must_use]
pub fn clippy_exceptions(rel: &str, text: &str, restriction: &[String]) -> Vec<Finding> {
    if is_table_file(rel) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for attr in lint_attributes(text) {
        let Some(name) = attr.lint.strip_prefix("clippy::") else {
            continue;
        };
        let accepted = !matches!(attr.level, "allow" | "expect")
            || restriction.iter().any(|r| r == name)
            || (name == concat!("disallowed", "_types") && attr.reason)
            || manifest::REVIEWED_EXCEPTIONS.contains(&(rel, name));
        if !accepted {
            found.push(Finding::new(
                "AC-010",
                rel,
                attr.line,
                format!("`clippy::{name}` is not a reviewed exception of ADR-0019"),
            ));
        }
    }
    found
}

/// AC-011: finds an `allow` or `expect` of `missing_docs` or of a `rustdoc` lint.
#[must_use]
pub fn docs_exceptions(rel: &str, text: &str) -> Vec<Finding> {
    lint_attributes(text)
        .into_iter()
        .filter(|a| matches!(a.level, "allow" | "expect"))
        .filter(|a| a.lint == concat!("missing", "_docs") || a.lint.starts_with("rustdoc::"))
        .map(|a| {
            Finding::new(
                "AC-011",
                rel,
                a.line,
                format!("`{}` takes no exception", a.lint),
            )
        })
        .collect()
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
        let attr = enclosing_attribute(&code, i);
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

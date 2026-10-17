//! Gates over `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `clippy.toml` and `rust-toolchain.toml`.
//!
//! The reader knows the small TOML subset that these files use: table headers, `key = value`
//! lines, inline tables and arrays that can span lines.

use crate::Finding;

/// The pinned Rust toolchain (AC-007a).
pub const TOOLCHAIN: &str = "1.97.0";

/// The toolchain components that `rust-toolchain.toml` must name (AC-007a).
pub const COMPONENTS: &[&str] = &["clippy", "rustfmt", "llvm-tools"];

/// The clippy lint groups that the workspace denies at priority -1 (AC-010).
pub const DENIED_GROUPS: &[&str] = &["all", "pedantic", "nursery", "cargo"];

/// The single clippy lints that the workspace denies (AC-010).
pub const DENIED_LINTS: &[&str] = &[
    "unwrap_used",
    "expect_used",
    "panic",
    "todo",
    "unimplemented",
    "dbg_macro",
    "allow_attributes_without_reason",
    "print_stdout",
    "print_stderr",
];

/// The reviewed allowlist of ADR-0019. No other clippy lint can be `allow`.
pub const ALLOWED_LINTS: &[&str] = &[
    "option_if_let_else",
    "redundant_pub_crate",
    "significant_drop_tightening",
    "missing_const_for_fn",
    "cognitive_complexity",
    "future_not_send",
    "cargo_common_metadata",
];

/// The types that `clippy.toml` must disallow (AC-016).
pub const DISALLOWED_TYPES: &[&str] = &[
    "std::collections::HashMap",
    "std::collections::HashSet",
    "std::hash::RandomState",
];

/// One `key = value` entry of a TOML text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The 1-based line of the key.
    pub line: usize,
    /// The table name, or the empty string for the top level.
    pub table: String,
    /// The key, without quotes.
    pub key: String,
    /// The raw value without a trailing comment. A multi-line array becomes one line.
    pub value: String,
}

fn without_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_string = !in_string,
            '#' if !in_string => return line.get(..i).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn bracket_balance(text: &str) -> i64 {
    let mut in_string = false;
    let mut balance = 0i64;
    for c in text.chars() {
        match c {
            '"' => in_string = !in_string,
            '[' | '{' if !in_string => balance += 1,
            ']' | '}' if !in_string => balance -= 1,
            _ => {}
        }
    }
    balance
}

fn header_name(line: &str) -> Option<String> {
    let inner = line
        .strip_prefix("[[")
        .and_then(|l| l.strip_suffix("]]"))
        .or_else(|| line.strip_prefix('[').and_then(|l| l.strip_suffix(']')))?;
    Some(inner.trim().replace(['"', '\''], ""))
}

/// Gives every entry of a TOML text, in file order.
#[must_use]
pub fn entries(text: &str) -> Vec<Entry> {
    let mut found = Vec::new();
    let mut table = String::new();
    let mut open: Option<Entry> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = without_comment(raw).trim();
        if let Some(mut entry) = open.take() {
            entry.value.push(' ');
            entry.value.push_str(line);
            if bracket_balance(&entry.value) > 0 {
                open = Some(entry);
            } else {
                found.push(entry);
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(name) = header_name(line) {
            table = name;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let entry = Entry {
            line: index + 1,
            table: table.clone(),
            key: key.trim().replace(['"', '\''], ""),
            value: value.trim().to_owned(),
        };
        if bracket_balance(&entry.value) > 0 {
            open = Some(entry);
        } else {
            found.push(entry);
        }
    }
    found.extend(open);
    found
}

/// Gives the table headers of a TOML text with their 1-based lines.
///
/// `[a.b]` gives `a.b`, and `[[bin]]` gives `bin`.
#[must_use]
pub fn headers(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut depth = 0i64;
    for (index, raw) in text.lines().enumerate() {
        let line = without_comment(raw).trim();
        if depth == 0
            && let Some(name) = header_name(line)
        {
            found.push((index + 1, name));
            continue;
        }
        if let Some((_, value)) = line.split_once('=').filter(|_| depth == 0) {
            depth = bracket_balance(value).max(0);
        } else if depth > 0 {
            depth = (depth + bracket_balance(line)).max(0);
        }
    }
    found
}

/// Gives the raw value of `key` in table `table`, without a trailing comment.
///
/// The empty table name means the top level.
#[must_use]
pub fn value(text: &str, table: &str, key: &str) -> Option<String> {
    entries(text)
        .into_iter()
        .find(|e| e.table == table && e.key == key)
        .map(|e| e.value)
}

fn unquote(raw: &str) -> &str {
    raw.trim().trim_matches('"')
}

fn squash(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_whitespace()).collect()
}

/// AC-001b: finds a `[[package]]` entry with a `source` key in `Cargo.lock`.
#[must_use]
pub fn no_lock_sources(text: &str) -> Vec<Finding> {
    entries(text)
        .into_iter()
        .filter(|e| e.table == "package" && e.key == "source")
        .map(|e| {
            Finding::new(
                "AC-001b",
                "Cargo.lock",
                e.line,
                format!("package source {}", e.value),
            )
        })
        .collect()
}

fn is_named(name: &str, word: &str) -> bool {
    name == word || name.starts_with(&format!("{word}."))
}

/// AC-001d: finds a `[patch]` or `[replace]` table in a `Cargo.toml`.
#[must_use]
pub fn no_patch_tables(rel: &str, text: &str) -> Vec<Finding> {
    let mut found: Vec<Finding> = headers(text)
        .into_iter()
        .filter(|(_, name)| is_named(name, "patch") || is_named(name, "replace"))
        .map(|(line, name)| {
            Finding::new(
                "AC-001d",
                rel,
                line,
                format!("table `[{name}]` is not allowed"),
            )
        })
        .collect();
    found.extend(
        entries(text)
            .into_iter()
            .filter(|e| {
                e.table.is_empty() && (is_named(&e.key, "patch") || is_named(&e.key, "replace"))
            })
            .map(|e| {
                Finding::new(
                    "AC-001d",
                    rel,
                    e.line,
                    format!("key `{}` is not allowed", e.key),
                )
            }),
    );
    found
}

/// AC-001d: finds a `[source]` or `[patch]` table in `.cargo/config.toml`.
#[must_use]
pub fn no_source_tables(rel: &str, text: &str) -> Vec<Finding> {
    headers(text)
        .into_iter()
        .filter(|(_, name)| is_named(name, "source") || is_named(name, "patch"))
        .map(|(line, name)| {
            Finding::new(
                "AC-001d",
                rel,
                line,
                format!("table `[{name}]` is not allowed"),
            )
        })
        .collect()
}

/// AC-002: finds a `.cargo/config.toml` that does not set `net.offline = true`.
#[must_use]
pub fn offline(text: &str) -> Vec<Finding> {
    if value(text, "net", "offline").as_deref() == Some("true") {
        Vec::new()
    } else {
        vec![Finding::new(
            "AC-002",
            ".cargo/config.toml",
            0,
            "set `[net] offline = true`",
        )]
    }
}

fn is_verus_name(name: &str) -> bool {
    name == "vstd" || name.starts_with("verus") || name == "builtin" || name == "builtin_macros"
}

/// AC-005: finds a `Cargo.toml` that names `vstd` or a Verus crate.
#[must_use]
pub fn no_vstd(rel: &str, text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    for entry in entries(text) {
        let in_deps = entry
            .table
            .split('.')
            .any(|part| part.ends_with("dependencies"));
        let header_dep = entry
            .table
            .rsplit('.')
            .next()
            .filter(|_| entry.table.contains("dependencies."));
        let package = entry.value.contains("vstd") || entry.value.contains("\"verus");
        let named = (in_deps && is_verus_name(&entry.key)) || header_dep.is_some_and(is_verus_name);
        if named || (in_deps && package) {
            found.push(Finding::new(
                "AC-005",
                rel,
                entry.line,
                "no manifest names `vstd` or a Verus crate",
            ));
        }
    }
    found
}

/// AC-007a: finds a `rust-toolchain.toml` that does not pin [`TOOLCHAIN`] with [`COMPONENTS`].
#[must_use]
pub fn toolchain_pin(text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    let rel = "rust-toolchain.toml";
    if value(text, "toolchain", "channel").as_deref().map(unquote) != Some(TOOLCHAIN) {
        found.push(Finding::new(
            "AC-007a",
            rel,
            0,
            format!("pin `channel = \"{TOOLCHAIN}\"`"),
        ));
    }
    let components = value(text, "toolchain", "components").unwrap_or_default();
    for name in COMPONENTS {
        if !components.contains(&format!("\"{name}\"")) {
            found.push(Finding::new(
                "AC-007a",
                rel,
                0,
                format!("add the component `{name}`"),
            ));
        }
    }
    found
}

/// AC-007c: finds a root `Cargo.toml` without `resolver = "3"`.
#[must_use]
pub fn resolver_3(text: &str) -> Vec<Finding> {
    if value(text, "workspace", "resolver").as_deref().map(unquote) == Some("3") {
        Vec::new()
    } else {
        vec![Finding::new(
            "AC-007c",
            "Cargo.toml",
            0,
            "set `resolver = \"3\"` in `[workspace]`",
        )]
    }
}

fn level(raw: &str) -> String {
    let flat = squash(raw);
    flat.split_once("level=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map_or_else(|| unquote(&flat).to_owned(), |(lvl, _)| lvl.to_owned())
}

/// AC-010: finds gaps in the clippy policy of the root `Cargo.toml`.
#[must_use]
pub fn lint_policy(text: &str) -> Vec<Finding> {
    let table = "workspace.lints.clippy";
    let clippy: Vec<Entry> = entries(text)
        .into_iter()
        .filter(|e| e.table == table)
        .collect();
    let get = |name: &str| clippy.iter().find(|e| e.key == name);
    let mut found = Vec::new();
    for group in DENIED_GROUPS {
        let ok = get(group).is_some_and(|e| {
            let flat = squash(&e.value);
            level(&e.value) == "deny" && flat.contains("priority=-1")
        });
        if !ok {
            let detail = format!("set `{group} = {{ level = \"deny\", priority = -1 }}`");
            found.push(Finding::new("AC-010", "Cargo.toml", 0, detail));
        }
    }
    for lint in DENIED_LINTS {
        if get(lint).is_none_or(|e| level(&e.value) != "deny") {
            found.push(Finding::new(
                "AC-010",
                "Cargo.toml",
                0,
                format!("set `{lint} = \"deny\"`"),
            ));
        }
    }
    for entry in &clippy {
        if level(&entry.value) == "allow" && !ALLOWED_LINTS.contains(&entry.key.as_str()) {
            let detail = format!(
                "`{}` is not in the reviewed allowlist of ADR-0019",
                entry.key
            );
            found.push(Finding::new("AC-010", "Cargo.toml", entry.line, detail));
        }
    }
    found
}

/// AC-011: finds a root `Cargo.toml` without `missing_docs` and `unsafe_code` at `deny`.
#[must_use]
pub fn docs_policy(text: &str) -> Vec<Finding> {
    ["missing_docs", "unsafe_code"]
        .into_iter()
        .filter(|lint| {
            value(text, "workspace.lints.rust", lint).is_none_or(|v| level(&v) != "deny")
        })
        .map(|lint| {
            Finding::new(
                "AC-011",
                "Cargo.toml",
                0,
                format!("set `{lint} = \"deny\"`"),
            )
        })
        .collect()
}

/// AC-010 and AC-011: finds a package `Cargo.toml` without `[lints] workspace = true`.
#[must_use]
pub fn lints_inherited(rel: &str, text: &str) -> Vec<Finding> {
    if value(text, "lints", "workspace").as_deref() == Some("true") {
        Vec::new()
    } else {
        vec![Finding::new(
            "AC-010",
            rel,
            0,
            "set `[lints] workspace = true`",
        )]
    }
}

/// AC-016: finds a `clippy.toml` that does not disallow [`DISALLOWED_TYPES`].
#[must_use]
pub fn clippy_config(text: &str) -> Vec<Finding> {
    let list = value(text, "", "disallowed-types").unwrap_or_default();
    DISALLOWED_TYPES
        .iter()
        .filter(|path| !list.contains(&format!("\"{path}\"")))
        .map(|path| Finding::new("AC-016", "clippy.toml", 0, format!("disallow `{path}`")))
        .collect()
}

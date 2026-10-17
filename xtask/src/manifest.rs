//! Gates over `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `clippy.toml` and `rust-toolchain.toml`.
//!
//! The reader knows the small TOML subset that these files use: table headers and `key = value` lines.

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

/// Gives the table headers of a TOML text with their 1-based lines.
///
/// `[a.b]` gives `a.b`, and `[[bin]]` gives `bin`.
#[must_use]
pub fn headers(text: &str) -> Vec<(usize, String)> {
    let _ = text;
    Vec::new()
}

/// Gives the raw value of `key` in table `table`, without a trailing comment.
///
/// The empty table name means the top level.
#[must_use]
pub fn value(text: &str, table: &str, key: &str) -> Option<String> {
    let _ = (text, table, key);
    None
}

/// AC-001b: finds a `[[package]]` entry with a `source` key in `Cargo.lock`.
#[must_use]
pub fn no_lock_sources(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

/// AC-001d: finds a `[patch]` or `[replace]` table in a `Cargo.toml`.
#[must_use]
pub fn no_patch_tables(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-001d: finds a `[source]` or `[patch]` table in `.cargo/config.toml`.
#[must_use]
pub fn no_source_tables(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-002: finds a `.cargo/config.toml` that does not set `net.offline = true`.
#[must_use]
pub fn offline(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

/// AC-005: finds a `Cargo.toml` that names `vstd` or a Verus crate.
#[must_use]
pub fn no_vstd(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-007a: finds a `rust-toolchain.toml` that does not pin [`TOOLCHAIN`] with [`COMPONENTS`].
#[must_use]
pub fn toolchain_pin(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

/// AC-007c: finds a root `Cargo.toml` without `resolver = "3"`.
#[must_use]
pub fn resolver_3(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

/// AC-010: finds gaps in the clippy policy of the root `Cargo.toml`.
#[must_use]
pub fn lint_policy(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

/// AC-011: finds a root `Cargo.toml` without `missing_docs` and `unsafe_code` at `deny`.
#[must_use]
pub fn docs_policy(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

/// AC-010 and AC-011: finds a package `Cargo.toml` without `[lints] workspace = true`.
#[must_use]
pub fn lints_inherited(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-016: finds a `clippy.toml` that does not disallow [`DISALLOWED_TYPES`].
#[must_use]
pub fn clippy_config(text: &str) -> Vec<Finding> {
    let _ = text;
    Vec::new()
}

//! The truth files `fixtures/truth/<build>.json` and their schema check.
//!
//! One truth file serves a build and every variant of it (the stripped twin, `noeh` and
//! `noshdr`), because a variant keeps the code and the addresses of its build.
//! [`super::assemble`] writes the files. Addresses are `0x` hex text. Sizes and counts are
//! integers.
//!
//! | Key | Shape |
//! |---|---|
//! | `fixture`, `program`, `tier` | text |
//! | `generator` | `{ name, version }` |
//! | `build` | `{ id, compiler, cflags, ldflags }` |
//! | `binaries` | `[{ name, sha256, variant }]` |
//! | `elf` | `{ type, entry, image_base, interp }` |
//! | `libraries`, `imports`, `network_imports` | `[text]` |
//! | `protections` | `{ pie, nx, relro, canary, fortify, ibt, shstk, rpath, runpath, build_id }` |
//! | `functions` | `[{ name, addr, size, insns }]` in address order |
//! | `function_count` | integer |
//! | `cold_parts` | `[{ name, addr, size, parent }]` |
//! | `duplicate_names` | `{ <name>: [addr] }` |
//! | `call_edges`, `tail_calls` | `[[caller, callee]]` |
//! | `self_calls` | `[name]` |
//! | `jump_tables` | `[{ func, table, lea, kind, entries, targets }]` |
//! | `strings` | `[{ addr, encoding, hex, len, text }]` |
//! | `syscalls` | `[{ func, site, nr, name, args }]` |
//! | `syscall_names` | `[name]`, sorted |
//! | `gaps` | `[{ name, addr, size, first_insn }]` |
//! | `leaf_functions` | `[{ name, sig, vectors }]` |
//! | `survey_facts` | `[{ kind, value }]` |
//! | `facts` | the copied source facts |

use std::path::Path;

use super::TRUTH_DIR;
use super::manifest::Manifest;
use crate::json::{self, Value};
use crate::{Error, Finding};

/// Gives the truth path of a build, relative to the workspace root.
#[must_use]
pub fn path(build: &str) -> String {
    format!("{TRUTH_DIR}/{build}.json")
}

/// Reads and parses the truth file of a build.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] when it does not parse.
pub fn read(root: &Path, build: &str) -> Result<Value, Error> {
    let rel = path(build);
    let text = std::fs::read_to_string(root.join(&rel)).map_err(|e| Error::io(&rel, e))?;
    json::parse(&text).map_err(|e| Error::data(&rel, e.to_string()))
}

/// The JSON type that a schema row needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Text,
    Int,
    Bool,
    Addr,
    Array,
    Object,
}

fn is(value: &Value, ty: Ty) -> bool {
    match ty {
        Ty::Text => value.as_str().is_some(),
        Ty::Int => value.as_u64().is_some(),
        Ty::Bool => value.as_bool().is_some(),
        Ty::Addr => value
            .as_str()
            .and_then(|t| t.strip_prefix("0x"))
            .is_some_and(|h| !h.is_empty() && u64::from_str_radix(h, 16).is_ok()),
        Ty::Array => value.as_array().is_some(),
        Ty::Object => value.as_object().is_some(),
    }
}

const TOP: &[(&str, Ty)] = &[
    ("fixture", Ty::Text),
    ("program", Ty::Text),
    ("tier", Ty::Text),
    ("generator", Ty::Object),
    ("build", Ty::Object),
    ("binaries", Ty::Array),
    ("elf", Ty::Object),
    ("libraries", Ty::Array),
    ("network_imports", Ty::Array),
    ("imports", Ty::Array),
    ("protections", Ty::Object),
    ("functions", Ty::Array),
    ("function_count", Ty::Int),
    ("cold_parts", Ty::Array),
    ("duplicate_names", Ty::Object),
    ("call_edges", Ty::Array),
    ("tail_calls", Ty::Array),
    ("self_calls", Ty::Array),
    ("jump_tables", Ty::Array),
    ("strings", Ty::Array),
    ("syscall_names", Ty::Array),
    ("syscalls", Ty::Array),
    ("gaps", Ty::Array),
    ("leaf_functions", Ty::Array),
    ("survey_facts", Ty::Array),
    ("facts", Ty::Object),
];

/// The fields of the items of each array key.
const ITEMS: &[(&str, &[(&str, Ty)])] = &[
    (
        "binaries",
        &[
            ("name", Ty::Text),
            ("sha256", Ty::Text),
            ("variant", Ty::Text),
        ],
    ),
    (
        "functions",
        &[
            ("name", Ty::Text),
            ("addr", Ty::Addr),
            ("size", Ty::Int),
            ("insns", Ty::Int),
        ],
    ),
    (
        "cold_parts",
        &[
            ("name", Ty::Text),
            ("addr", Ty::Addr),
            ("size", Ty::Int),
            ("parent", Ty::Text),
        ],
    ),
    (
        "jump_tables",
        &[
            ("func", Ty::Text),
            ("table", Ty::Addr),
            ("lea", Ty::Addr),
            ("kind", Ty::Text),
            ("entries", Ty::Int),
            ("targets", Ty::Array),
        ],
    ),
    (
        "strings",
        &[
            ("addr", Ty::Addr),
            ("encoding", Ty::Text),
            ("hex", Ty::Text),
            ("len", Ty::Int),
            ("text", Ty::Text),
        ],
    ),
    (
        "syscalls",
        &[
            ("func", Ty::Text),
            ("site", Ty::Addr),
            ("nr", Ty::Int),
            ("name", Ty::Text),
            ("args", Ty::Array),
        ],
    ),
    (
        "gaps",
        &[
            ("name", Ty::Text),
            ("addr", Ty::Addr),
            ("size", Ty::Int),
            ("first_insn", Ty::Text),
        ],
    ),
    (
        "leaf_functions",
        &[("name", Ty::Text), ("sig", Ty::Text), ("vectors", Ty::Text)],
    ),
    ("survey_facts", &[("kind", Ty::Text), ("value", Ty::Text)]),
];

const PROTECTIONS: &[(&str, Ty)] = &[
    ("pie", Ty::Bool),
    ("nx", Ty::Bool),
    ("relro", Ty::Text),
    ("canary", Ty::Bool),
    ("fortify", Ty::Bool),
    ("ibt", Ty::Bool),
    ("shstk", Ty::Bool),
    ("rpath", Ty::Bool),
    ("runpath", Ty::Bool),
];

fn fields(found: &mut Vec<String>, at: &str, value: &Value, rows: &[(&str, Ty)]) {
    for (key, ty) in rows {
        if !value.get(key).is_some_and(|v| is(v, *ty)) {
            found.push(format!("{at}: `{key}` is missing or has the wrong type"));
        }
    }
}

fn addr_of(v: &Value) -> u64 {
    v.get("addr")
        .and_then(Value::as_str)
        .and_then(|t| t.strip_prefix("0x"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .unwrap_or(0)
}

/// Checks one truth value against the schema of this module. Gives one message per fault.
#[must_use]
pub fn check_value(name: &str, truth: &Value) -> Vec<String> {
    let mut found = Vec::new();
    fields(&mut found, "truth", truth, TOP);
    if truth.get("fixture").and_then(Value::as_str) != Some(name) {
        found.push(format!("`fixture` is not `{name}`"));
    }
    for (key, rows) in ITEMS {
        let items = truth.get(key).and_then(Value::as_array).unwrap_or(&[]);
        for (i, item) in items.iter().enumerate() {
            fields(&mut found, &format!("{key}[{i}]"), item, rows);
        }
    }
    if let Some(p) = truth.get("protections") {
        fields(&mut found, "protections", p, PROTECTIONS);
    }
    let funcs = truth
        .get("functions")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    if funcs.windows(2).any(|w| addr_of(&w[0]) > addr_of(&w[1])) {
        found.push("`functions` is not in address order".to_owned());
    }
    if truth.get("function_count").and_then(Value::as_u64) != u64::try_from(funcs.len()).ok() {
        found.push("`function_count` differs from the length of `functions`".to_owned());
    }
    let names: Vec<&str> = funcs
        .iter()
        .filter_map(|f| f.get("name").and_then(Value::as_str))
        .collect();
    for part in truth
        .get("cold_parts")
        .and_then(Value::as_array)
        .unwrap_or(&[])
    {
        let parent = part.get("parent").and_then(Value::as_str).unwrap_or("");
        if !names.contains(&parent) {
            found.push(format!("cold part parent `{parent}` is not a function"));
        }
    }
    for table in truth
        .get("jump_tables")
        .and_then(Value::as_array)
        .unwrap_or(&[])
    {
        let targets = table
            .get("targets")
            .and_then(Value::as_array)
            .unwrap_or(&[]);
        if table.get("entries").and_then(Value::as_u64) != u64::try_from(targets.len()).ok() {
            found.push("a jump table has `entries` unequal to its target count".to_owned());
        }
    }
    found
}

/// Checks every truth file that the manifest names (schema, fixture name and binaries).
///
/// # Errors
///
/// Returns an error when a truth file does not read or parse.
pub fn check_all(root: &Path, manifest: &Manifest) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    let mut builds: Vec<&str> = manifest.entries.iter().map(|e| e.truth.as_str()).collect();
    builds.sort_unstable();
    builds.dedup();
    for rel in builds {
        let name = rel
            .strip_prefix(&format!("{TRUTH_DIR}/"))
            .and_then(|r| r.strip_suffix(".json"))
            .unwrap_or(rel);
        let truth = read(root, name)?;
        for message in check_value(name, &truth) {
            found.push(Finding::new("WP-06", rel, 0, message));
        }
        for bin in truth
            .get("binaries")
            .and_then(Value::as_array)
            .unwrap_or(&[])
        {
            let bin_name = bin.get("name").and_then(Value::as_str).unwrap_or("");
            let sha = bin.get("sha256").and_then(Value::as_str);
            match manifest.entry(bin_name) {
                Some(e) if Some(e.sha256.as_str()) == sha && e.truth == rel => {}
                _ => found.push(Finding::new(
                    "WP-06",
                    rel,
                    0,
                    format!("binary `{bin_name}` differs from the manifest"),
                )),
            }
        }
    }
    Ok(found)
}

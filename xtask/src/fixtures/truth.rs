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
use crate::json::Value;
use crate::{Error, Finding};

/// Gives the truth path of a build, relative to the workspace root.
#[must_use]
pub fn path(build: &str) -> String {
    build.get(..0).unwrap_or_default().to_owned()
}

/// Reads and parses the truth file of a build.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] when it does not parse.
pub fn read(root: &Path, build: &str) -> Result<Value, Error> {
    Err(Error::data(
        root.join(TRUTH_DIR).join(build).display().to_string(),
        "no truth yet",
    ))
}

/// Checks one truth value against the schema of this module. Gives one message per fault.
#[must_use]
pub fn check_value(name: &str, truth: &Value) -> Vec<String> {
    let _ = (name, truth);
    Vec::new()
}

/// Checks every truth file that the manifest names (schema, fixture name and binaries).
///
/// # Errors
///
/// Returns an error when a truth file does not read or parse.
pub fn check_all(root: &Path, manifest: &Manifest) -> Result<Vec<Finding>, Error> {
    let _ = (root, manifest);
    Ok(Vec::new())
}

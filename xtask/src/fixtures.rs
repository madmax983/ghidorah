//! The `xtask fixtures` command: the fixture corpus, its truth and its goldens (WP-06).
//!
//! Subcommands:
//!
//! | Command | Effect |
//! |---|---|
//! | `xtask fixtures build` | Builds every fixture of [`spec::fixtures`] with gcc and clang. Writes the binaries, the truth files, the manifest and the goldens. |
//! | `xtask fixtures build --check` | Builds into `target/fixtures-check` and compares each output file with the checked-in file. |
//! | `xtask fixtures build-pe [--check]` | Builds only the PE32+ fixtures of [`crate::fixtures_pe`]. `build` runs it too. |
//! | `xtask fixtures gen-large` | Writes `fixtures/src/large.c` from the generator of [`large`]. |
//! | `xtask fixtures check` | Runs the tier-1 checks: manifest hashes, golden headers, truth schema, leaf vectors, frozen answers and hash locks. |
//!
//! Outputs, relative to the workspace root:
//!
//! - `fixtures/bin/<fixture>`: the fixture binaries (T1 and T2).
//! - `fixtures/truth/<build>.json`: the truth of each build ([`truth`]).
//! - `fixtures/manifest.json`: the sha256, the size, the compiler and the flags of each fixture ([`manifest`]).
//! - `tests/golden/loader/<fixture>.readelf.txt`: `readelf -W -h -l -S -s -d -r -n` output.
//! - `tests/golden/loader/<fixture>.dynrel.txt`: `readelf -W -D -r` output of each `noshdr` fixture.
//! - `tests/golden/objdump/<fixture>.txt`: `objdump -d -w -z -M intel` output of each fixture with a symbol table.
//! - `tests/golden/ehframe/<fixture>.txt`: `readelf --debug-dump=frames` output of the same fixtures.
//! - `tests/golden/semantics/leaf/<build>.jsonl`: leaf-driver vectors ([`leaf`]).
//!
//! Each golden starts with a header line that names [`GENERATOR`], [`VERSION`], the fixture and
//! its sha256 (`testkit::golden`). `cargo test` reads only these checked-in files.

pub mod assemble;
pub mod build;
pub mod checks;
pub mod elfinfo;
pub mod facts;
pub mod jumptab;
pub mod large;
pub mod leaf;
pub mod manifest;
pub mod objdump;
pub mod pretty;
pub mod questions;
pub mod spec;
pub mod toolchain;
pub mod truth;

use std::path::Path;

use crate::json::Value;
use crate::{Error, Finding};

/// The generator name in golden headers, the manifest and the truth files.
pub const GENERATOR: &str = "xtask-fixtures";

/// The generator version. A change of the output format raises it.
pub const VERSION: &str = "1";

/// The fixture source directory, relative to the workspace root.
pub const SRC_DIR: &str = "fixtures/src";

/// The fixture binary directory, relative to the workspace root.
pub const BIN_DIR: &str = "fixtures/bin";

/// The truth directory, relative to the workspace root.
pub const TRUTH_DIR: &str = "fixtures/truth";

/// The golden areas that `xtask fixtures build` writes, under `tests/golden`.
pub const GOLDEN_AREAS: &[&str] = &["loader", "ehframe", "objdump", "semantics/leaf"];

/// The largest total size of the checked-in fixture binaries (design Section 12.3).
pub const MAX_TOTAL_BYTES: u64 = 3 * 1024 * 1024;

const USAGE: &str = "cargo xtask fixtures <build [--check]|build-pe [--check]|gen-large|check>";

/// Runs every tier-1 check over the checked-in corpus and gives the findings.
///
/// The checks are the manifest hashes and size, the golden headers (AC-022), the truth schema,
/// the leaf vectors, the frozen answers and the hash locks.
///
/// # Errors
///
/// Returns an error when the manifest or another input file does not read or parse.
pub fn check_all(root: &Path) -> Result<Vec<Finding>, Error> {
    let manifest = manifest::read(root)?;
    let mut found = manifest::check_files(root, &manifest)?;
    found.extend(manifest::check_goldens(root, &manifest)?);
    found.extend(truth::check_all(root, &manifest)?);
    found.extend(leaf::check_vectors(root, &manifest)?);
    found.extend(questions::check_answers(root)?);
    found.extend(questions::check_locks(root)?);
    found.extend(crate::fixtures_pe::check(root, &manifest)?);
    Ok(found)
}

/// Runs the PE build of WP-30 after the ELF build and puts its report in `pe`.
///
/// # Errors
///
/// Returns the error of the PE build.
fn with_pe(root: &Path, elf: Value, check: bool) -> Result<Value, Error> {
    let pe = crate::fixtures_pe::run(root, check)?;
    let ok = elf.get("ok").and_then(Value::as_bool) == Some(true)
        && pe.get("ok").and_then(Value::as_bool) == Some(true);
    let Value::Object(mut out) = elf else {
        return Ok(elf);
    };
    out.insert("ok".to_owned(), Value::from(ok));
    out.insert("pe".to_owned(), pe);
    Ok(Value::Object(out))
}

/// Runs `xtask fixtures <command>`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown command, or the error of the command.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["build"] => with_pe(root, build::run(root, false)?, false),
        ["build", "--check"] => with_pe(root, build::run(root, true)?, true),
        ["build-pe"] => crate::fixtures_pe::run(root, false),
        ["build-pe", "--check"] => crate::fixtures_pe::run(root, true),
        ["gen-large"] => {
            let path = root.join(large::SOURCE_PATH);
            std::fs::write(&path, large::generate()).map_err(|e| Error::io(path, e))?;
            Ok(Value::object([
                ("ok", Value::from(true)),
                ("path", Value::from(large::SOURCE_PATH)),
                ("functions", Value::from(large::FUNCTIONS)),
            ]))
        }
        ["check"] => {
            let found = check_all(root)?;
            Ok(Value::object([
                ("ok", Value::from(found.is_empty())),
                (
                    "findings",
                    Value::from(found.iter().map(Finding::to_json).collect::<Vec<_>>()),
                ),
            ]))
        }
        _ => Err(Error::Usage(USAGE.to_owned())),
    }
}

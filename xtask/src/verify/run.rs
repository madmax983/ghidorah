//! The Verus runs of `xtask verify`: one run per kernel, then one run per negative patch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{ARGV, FAILED_PATH, KERNELS, Kernel, Negative, RESULTS_PATH, Tools, patch, tree};
use crate::json::{self, Value};
use crate::{Error, proc};

/// The directory of the negative copies, relative to the workspace root.
const COPY_DIR: &str = "target/xtask-verify";

/// The maximum depth of a directory copy.
const MAX_DEPTH: usize = 16;

/// Runs Verus on the kernel under `dir` for one module.
fn verus_run(
    verus: &Path,
    z3: Option<&Path>,
    dir: &Path,
    module: &str,
) -> Result<proc::Output, Error> {
    let mut cmd = Command::new(verus);
    cmd.args(ARGV.get(1..).unwrap_or_default())
        .args(["--verify-module", module])
        .current_dir(dir);
    if let Some(z3) = z3 {
        cmd.env("VERUS_Z3_PATH", z3);
    }
    proc::run(&mut cmd)
}

/// Gives the `z3 --version` output, or an empty text without z3.
fn z3_version(z3: Option<&Path>) -> String {
    z3.and_then(|path| proc::run(Command::new(path).arg("--version")).ok())
        .map(|out| out.stdout)
        .unwrap_or_default()
}

/// Gives the texts of the kernel files: the module file and the files of its submodule directory.
fn kernel_texts(root: &Path, kernel: &Kernel) -> Result<Vec<String>, Error> {
    let mut files = vec![root.join(kernel.file())];
    let dir = root.join(kernel.dir());
    if dir.is_dir() {
        let mut found = Vec::new();
        list_files(&dir, 0, &mut found)?;
        files.extend(
            found
                .into_iter()
                .filter(|p| p.extension().is_some_and(|x| x == "rs")),
        );
    }
    files
        .iter()
        .map(|path| std::fs::read_to_string(path).map_err(|e| Error::io(path, e)))
        .collect()
}

/// Adds each file under `dir` to `out`.
fn list_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;
    for entry in entries {
        let path = entry.map_err(|e| Error::io(dir, e))?.path();
        if path.is_dir() {
            list_files(&path, depth + 1, out)?;
        } else {
            out.push(path);
        }
    }
    out.sort();
    Ok(())
}

/// Copies the files under `from` to `to`.
fn copy_tree(from: &Path, to: &Path) -> Result<(), Error> {
    let mut files = Vec::new();
    list_files(from, 0, &mut files)?;
    for file in files {
        let rel = file.strip_prefix(from).unwrap_or(&file);
        let target = to.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        std::fs::copy(&file, &target).map_err(|e| Error::io(&target, e))?;
    }
    Ok(())
}

/// Proves one kernel and gives its record row and its tool versions.
fn prove(
    root: &Path,
    verus: &Path,
    z3: Option<&Path>,
    kernel: &Kernel,
    z3_text: &str,
) -> Result<(Value, Tools), Error> {
    let out = verus_run(verus, z3, root, kernel.module)?;
    let counts = super::parse_counts(&out.stdout).unwrap_or_default();
    let texts = kernel_texts(root, kernel)?;
    let spec_items = texts
        .iter()
        .fold(0u64, |n, text| n.saturating_add(super::spec_items(text)));
    let spec: Vec<String> = texts
        .iter()
        .flat_map(|t| super::spec_functions(t))
        .collect();
    // Each spec function needs its own entry. So an `external` function cannot hide in the count.
    let proved = super::parse_functions(&out.stdout).unwrap_or_default();
    let unproved = super::unproved(kernel.module, &spec, &proved);
    let verified = counts.success
        && counts.errors == 0
        && spec_items > 0
        && counts.verified >= spec_items
        && unproved.is_empty();
    let mut row = vec![
        ("name", Value::from(kernel.name)),
        ("file", Value::from(kernel.file())),
        ("module", Value::from(kernel.module)),
        ("verified", Value::from(counts.verified)),
        ("errors", Value::from(counts.errors)),
        ("spec_items", Value::from(spec_items)),
        (
            "status",
            Value::from(if verified { "verified" } else { "failed" }),
        ),
    ];
    if !verified {
        row.push(("error", Value::from(proc::tail(&out.stderr, 20))));
        row.push((
            "unproved",
            Value::Array(unproved.into_iter().map(Value::from).collect()),
        ));
    }
    Ok((Value::object(row), super::parse_tools(&out.stdout, z3_text)))
}

/// The result of a negative copy.
enum Prepared {
    /// The root of the patched copy.
    Patched(PathBuf),
    /// The reason that the patch does not apply.
    Refused(String),
}

/// Applies the negative patch `negative` of `kernel` to a copy of the kernel sources.
fn negative_copy(root: &Path, kernel: &Kernel, negative: &Negative) -> Result<Prepared, Error> {
    let Ok(text) = std::fs::read_to_string(root.join(negative.path())) else {
        return Ok(Prepared::Refused(format!("{} is missing", negative.path())));
    };
    let parsed = match patch::parse(&text) {
        Ok(parsed) => parsed,
        Err(e) => return Ok(Prepared::Refused(e.to_string())),
    };
    let inside =
        parsed.path == kernel.file() || parsed.path.starts_with(&format!("{}/", kernel.dir()));
    if !inside || parsed.path.split('/').any(|part| part == "..") {
        return Ok(Prepared::Refused(format!(
            "the patch changes {}, not a file of {}",
            parsed.path, kernel.name
        )));
    }
    let copy = root.join(COPY_DIR).join(negative.name);
    if copy.exists() {
        std::fs::remove_dir_all(&copy).map_err(|e| Error::io(&copy, e))?;
    }
    copy_tree(
        &root.join("crates/kernel/src"),
        &copy.join("crates/kernel/src"),
    )?;
    let target = copy.join(&parsed.path);
    let source = std::fs::read_to_string(&target).map_err(|e| Error::io(&target, e))?;
    match patch::apply(&source, &parsed) {
        Ok(changed) => {
            std::fs::write(&target, changed).map_err(|e| Error::io(&target, e))?;
            Ok(Prepared::Patched(copy))
        }
        Err(e) => Ok(Prepared::Refused(e.to_string())),
    }
}

/// Runs one negative patch of one kernel and gives its record row.
///
/// The row has `ok: true` only when Verus fails with the expected error of the patch.
fn negative(
    root: &Path,
    verus: &Path,
    z3: Option<&Path>,
    kernel: &Kernel,
    negative: &Negative,
) -> Result<Value, Error> {
    let mut row = vec![
        ("kernel", Value::from(kernel.name)),
        ("patch", Value::from(negative.path())),
    ];
    match negative_copy(root, kernel, negative)? {
        Prepared::Refused(message) => {
            row.extend([
                ("error_kind", Value::Null),
                ("verified", Value::from(0u64)),
                ("errors", Value::from(0u64)),
                ("ok", Value::from(false)),
                ("error", Value::from(message)),
            ]);
        }
        Prepared::Patched(copy) => {
            let out = verus_run(verus, z3, &copy, kernel.module)?;
            let counts = super::parse_counts(&out.stdout).unwrap_or_default();
            let kind = super::error_kind(&out.stderr);
            let ok = kind == Some(negative.kind) && counts.verified >= 1 && !counts.success;
            row.extend([
                ("error_kind", kind.map_or(Value::Null, Value::from)),
                ("verified", Value::from(counts.verified)),
                ("errors", Value::from(counts.errors)),
                ("ok", Value::from(ok)),
            ]);
            if !ok {
                row.push(("expected_kind", Value::from(negative.kind)));
                row.push(("error", Value::from(proc::tail(&out.stderr, 20))));
            }
        }
    }
    Ok(Value::object(row))
}

/// Runs every kernel and every negative patch, writes the record and gives the report.
pub(super) fn proofs(root: &Path, verus: &Path, z3: Option<&Path>) -> Result<Value, Error> {
    let tree_sha256 =
        tree::tree_sha256(root).map_err(|e| Error::io(root.join("crates/kernel/src"), e))?;
    let z3_text = z3_version(z3);
    let mut tools: Option<Tools> = None;
    let mut kernels = BTreeMap::new();
    let mut all_ok = true;
    for kernel in KERNELS {
        let (row, found) = prove(root, verus, z3, kernel, &z3_text)?;
        all_ok &= row.get("status").and_then(Value::as_str) == Some("verified");
        if tools.as_ref().is_none_or(|t| t.verus_commit == "unknown") {
            tools = Some(found);
        }
        kernels.insert(kernel.name.to_owned(), row);
    }
    let mut negatives = Vec::new();
    for kernel in KERNELS {
        for item in kernel.negatives {
            let row = negative(root, verus, z3, kernel, item)?;
            all_ok &= row.get("ok").and_then(Value::as_bool) == Some(true);
            negatives.push(row);
        }
    }
    let copies = root.join(COPY_DIR);
    if copies.exists() {
        std::fs::remove_dir_all(&copies).map_err(|e| Error::io(&copies, e))?;
    }
    let tools = tools.unwrap_or_default();
    let mut record = BTreeMap::new();
    record.insert("verus_commit".to_owned(), Value::from(tools.verus_commit));
    record.insert("toolchain".to_owned(), Value::from(tools.toolchain));
    record.insert("z3".to_owned(), Value::from(tools.z3));
    record.insert(
        "argv".to_owned(),
        Value::Array(ARGV.iter().map(|a| Value::from(*a)).collect()),
    );
    record.insert("tree_sha256".to_owned(), Value::from(tree_sha256));
    record.insert("kernels".to_owned(), Value::Object(kernels));
    record.insert("negatives".to_owned(), Value::Array(negatives));
    let record = Value::Object(record);
    // Only a good run replaces the record. A failed run keeps the record of the last good run.
    let written = if all_ok { RESULTS_PATH } else { FAILED_PATH };
    let path = root.join(written);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    std::fs::write(&path, format!("{}\n", json::write(&record)))
        .map_err(|e| Error::io(&path, e))?;
    let failed = root.join(FAILED_PATH);
    if all_ok && failed.exists() {
        std::fs::remove_file(&failed).map_err(|e| Error::io(&failed, e))?;
    }
    let Value::Object(mut report) = record else {
        return Err(Error::data("verify", "the record is not an object"));
    };
    report.insert("ok".to_owned(), Value::from(all_ok));
    report.insert(
        "status".to_owned(),
        Value::from(if all_ok { "verified" } else { "failed" }),
    );
    report.insert("results".to_owned(), Value::from(written));
    Ok(Value::Object(report))
}

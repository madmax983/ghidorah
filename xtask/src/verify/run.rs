//! The Verus runs of `xtask verify`: one run per kernel, then one run per negative patch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{ARGV, KERNELS, Kernel, RESULTS_PATH, Tools, patch, tree};
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

/// Counts the spec items of the kernel files: the module file and its submodule directory.
fn kernel_spec_items(root: &Path, kernel: &Kernel) -> Result<u64, Error> {
    let file = root.join(kernel.file());
    let text = std::fs::read_to_string(&file).map_err(|e| Error::io(&file, e))?;
    let mut count = super::spec_items(&text);
    let dir = root.join(kernel.dir());
    if dir.is_dir() {
        let mut files = Vec::new();
        list_files(&dir, 0, &mut files)?;
        for path in files
            .iter()
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        {
            let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
            count = count.saturating_add(super::spec_items(&text));
        }
    }
    Ok(count)
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
    let spec_items = kernel_spec_items(root, kernel)?;
    let verified =
        counts.success && counts.errors == 0 && spec_items > 0 && counts.verified >= spec_items;
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
    }
    Ok((Value::object(row), super::parse_tools(&out.stdout, z3_text)))
}

/// Applies the negative patch of `kernel` to a copy of the kernel. Gives the copy root.
fn negative_copy(root: &Path, kernel: &Kernel) -> Result<Result<PathBuf, String>, Error> {
    let patch_path = root.join(kernel.patch());
    let Ok(text) = std::fs::read_to_string(&patch_path) else {
        return Ok(Err(format!("{} is missing", kernel.patch())));
    };
    let parsed = match patch::parse(&text) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e.to_string())),
    };
    let inside =
        parsed.path == kernel.file() || parsed.path.starts_with(&format!("{}/", kernel.dir()));
    if !inside || parsed.path.split('/').any(|part| part == "..") {
        return Ok(Err(format!(
            "the patch changes {}, not a file of {}",
            parsed.path, kernel.name
        )));
    }
    let copy = root.join(COPY_DIR).join(kernel.name);
    if copy.exists() {
        std::fs::remove_dir_all(&copy).map_err(|e| Error::io(&copy, e))?;
    }
    copy_tree(
        &root.join("crates/kernel/src"),
        &copy.join("crates/kernel/src"),
    )?;
    let target = copy.join(&parsed.path);
    let source = std::fs::read_to_string(&target).map_err(|e| Error::io(&target, e))?;
    let changed = match patch::apply(&source, &parsed) {
        Ok(changed) => changed,
        Err(e) => return Ok(Err(e.to_string())),
    };
    std::fs::write(&target, changed).map_err(|e| Error::io(&target, e))?;
    Ok(Ok(copy))
}

/// Runs the negative patch of one kernel and gives its record row.
fn negative(root: &Path, verus: &Path, z3: Option<&Path>, kernel: &Kernel) -> Result<Value, Error> {
    let mut row = vec![
        ("kernel", Value::from(kernel.name)),
        ("patch", Value::from(kernel.patch())),
    ];
    match negative_copy(root, kernel)? {
        Err(message) => {
            row.extend([
                ("error_kind", Value::Null),
                ("verified", Value::from(0u64)),
                ("errors", Value::from(0u64)),
                ("ok", Value::from(false)),
                ("error", Value::from(message)),
            ]);
        }
        Ok(copy) => {
            let out = verus_run(verus, z3, &copy, kernel.module)?;
            let counts = super::parse_counts(&out.stdout).unwrap_or_default();
            let kind = super::error_kind(&out.stderr);
            let ok = kind.is_some() && counts.verified >= 1 && !counts.success;
            row.extend([
                ("error_kind", kind.map_or(Value::Null, Value::from)),
                ("verified", Value::from(counts.verified)),
                ("errors", Value::from(counts.errors)),
                ("ok", Value::from(ok)),
            ]);
            if !ok {
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
        let row = negative(root, verus, z3, kernel)?;
        all_ok &= row.get("ok").and_then(Value::as_bool) == Some(true);
        negatives.push(row);
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
    let path = root.join(RESULTS_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    std::fs::write(&path, format!("{}\n", json::write(&record)))
        .map_err(|e| Error::io(&path, e))?;
    let Value::Object(mut report) = record else {
        return Err(Error::data("verify", "the record is not an object"));
    };
    report.insert("ok".to_owned(), Value::from(all_ok));
    report.insert(
        "status".to_owned(),
        Value::from(if all_ok { "verified" } else { "failed" }),
    );
    report.insert("results".to_owned(), Value::from(RESULTS_PATH));
    Ok(Value::Object(report))
}

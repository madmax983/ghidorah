//! The `xtask oracle` command: host oracles for the x86 crate (design Section 13.8).
//!
//! | Command | Effect |
//! |---|---|
//! | `xtask oracle semantics` | Runs each form of `ghidorah-oracle` in a child process and writes `tests/golden/semantics/x86/<file>.jsonl`. |
//! | `xtask oracle semantics --check` | Runs the forms and compares the result with the checked-in files. Writes no file. Skips a file whose header names another CPU. |
//! | `xtask oracle bash` | Runs the tier-2 host boundary test of `ghidorah-x86` on host bash and libc and writes `verify/oracle-results.json` (AC-066). |
//!
//! The vector files hold host evidence. Their header names the CPU model, so a run on
//! another CPU can differ in the flags that the hardware leaves undefined.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use ghidorah_testkit::golden::{Format, Header};

use crate::json::{self, Value};
use crate::{Error, proc};

/// The vector directory, relative to the workspace root.
pub const SEMANTICS_DIR: &str = "tests/golden/semantics/x86";

/// The record of the host boundary oracle, relative to the workspace root.
pub const RECORD: &str = "verify/oracle-results.json";

/// The generator name in the headers.
pub const GENERATOR: &str = "xtask-oracle";

/// The generator version in the headers.
pub const VERSION: &str = "1";

/// The prefix of the result line that the host boundary test prints.
pub const RESULT_PREFIX: &str = "oracle-result ";

/// The cargo arguments of the host boundary test.
pub const BASH_TEST: &[&str] = &[
    "test",
    "-p",
    "ghidorah-x86",
    "--test",
    "x86",
    "--",
    "--ignored",
    "--exact",
    "host::tier2_host_boundaries",
    "--nocapture",
];

/// The cargo arguments that build the oracle binary.
const BUILD: &[&str] = &[
    "build",
    "--quiet",
    "-p",
    "ghidorah-oracle",
    "--bin",
    "ghidorah-oracle",
    "--message-format=json",
];

const USAGE: &str = "cargo xtask oracle <semantics [--check]|bash>";

/// Gives the CPU model of `/proc/cpuinfo` text, or `unknown`.
#[must_use]
pub fn cpu_model(cpuinfo: &str) -> String {
    cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':'))
        .map_or_else(|| "unknown".to_owned(), |(_, v)| v.trim().to_owned())
}

/// Tells if a vector file name is a plain name: lowercase letters, digits and `_`.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parses the output of `ghidorah-oracle list` into `(file, form name)` pairs.
///
/// # Errors
///
/// Returns [`Error::Data`] for a line without a tab or a file name that is not a plain name.
pub fn parse_list(text: &str) -> Result<Vec<(String, String)>, Error> {
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| match l.split_once('\t') {
            Some((file, name)) if plain_name(file) && !name.is_empty() => {
                Ok((file.to_owned(), name.to_owned()))
            }
            _ => Err(Error::data(
                "ghidorah-oracle list",
                format!("bad line `{l}`"),
            )),
        })
        .collect()
}

/// Gives the text of each vector file: the header line, then the output of each form in
/// list order.
///
/// `outputs` holds the output of `ghidorah-oracle form <name>` for each item of `list`.
#[must_use]
pub fn render_files(
    cpu: &str,
    list: &[(String, String)],
    outputs: &[String],
) -> BTreeMap<String, String> {
    let mut bodies: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for ((file, _), out) in list.iter().zip(outputs) {
        let entry = bodies.entry(file.clone()).or_default();
        entry.0 += 1;
        entry.1.push_str(out);
        if !out.ends_with('\n') {
            entry.1.push('\n');
        }
    }
    bodies
        .into_iter()
        .map(|(file, (forms, body))| {
            let header = Header::new(GENERATOR, VERSION)
                .with("cpu", cpu)
                .with("forms", &forms.to_string())
                .render(Format::Json);
            (file, format!("{header}\n{body}"))
        })
        .collect()
}

/// Gives the CPU field of the header line of a vector file, or `None`.
#[must_use]
pub fn header_cpu(text: &str) -> Option<String> {
    let line = text.lines().next()?;
    let header = Header::parse(line, Format::Json).ok()?;
    header.field("cpu").map(str::to_owned)
}

/// Makes the record of the host boundary oracle from the output of its test.
///
/// # Errors
///
/// Returns [`Error::Data`] when the output has no result line or the line is not a JSON
/// object.
pub fn bash_record(test_stdout: &str) -> Result<Value, Error> {
    let origin = "oracle bash";
    let line = test_stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT_PREFIX))
        .ok_or_else(|| Error::data(origin, "no result line"))?;
    let value = json::parse(line).map_err(|e| Error::data(origin, e.to_string()))?;
    let Value::Object(mut members) = value else {
        return Err(Error::data(origin, "the result is not an object"));
    };
    members.insert("generator".to_owned(), Value::from(GENERATOR));
    members.insert("version".to_owned(), Value::from(VERSION));
    Ok(Value::Object(members))
}

/// Builds the oracle binary and gives its path.
fn oracle_binary(root: &Path) -> Result<PathBuf, Error> {
    let mut cmd = proc::cargo_cmd(BUILD);
    let out = proc::run_ok(cmd.current_dir(root))?;
    out.stdout
        .lines()
        .filter_map(|l| json::parse(l).ok())
        .filter(|v| v.pointer("/target/name").and_then(Value::as_str) == Some("ghidorah-oracle"))
        .find_map(|v| {
            v.get("executable")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .ok_or_else(|| Error::data("cargo build", "no ghidorah-oracle executable"))
}

/// Runs every form in its own child process.
fn run_forms(bin: &Path, list: &[(String, String)]) -> Result<Vec<String>, Error> {
    list.iter()
        .map(|(_, name)| {
            let out = proc::run_ok(Command::new(bin).args(["form", name]))?;
            if out.stdout.starts_with("{\"form\":") {
                Ok(out.stdout)
            } else {
                Err(Error::data(name.clone(), "no form header line"))
            }
        })
        .collect()
}

fn semantics(root: &Path, check: bool) -> Result<Value, Error> {
    let bin = oracle_binary(root)?;
    let list = parse_list(&proc::run_ok(Command::new(&bin).arg("list"))?.stdout)?;
    let outputs = run_forms(&bin, &list)?;
    let cpu = cpu_model(&std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default());
    let files = render_files(&cpu, &list, &outputs);
    let dir = root.join(SEMANTICS_DIR);
    let (mut changed, mut skipped) = (Vec::new(), Vec::new());
    for (name, text) in &files {
        let path = dir.join(format!("{name}.jsonl"));
        let old = std::fs::read_to_string(&path).ok();
        if old.as_deref() == Some(text.as_str()) {
            continue;
        }
        // A check on another CPU skips the file: undefined flags can differ.
        if check
            && old
                .as_deref()
                .is_some_and(|o| header_cpu(o) != header_cpu(text))
        {
            skipped.push(Value::from(name.as_str()));
        } else {
            changed.push(Value::from(name.as_str()));
            if !check {
                std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
                std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
            }
        }
    }
    let vectors: usize = outputs
        .iter()
        .map(|o| o.lines().count().saturating_sub(1))
        .sum();
    Ok(Value::object([
        ("ok", Value::from(!check || changed.is_empty())),
        ("check", Value::from(check)),
        ("cpu", Value::from(cpu)),
        ("files", Value::from(files.len())),
        ("forms", Value::from(list.len())),
        ("vectors", Value::from(vectors)),
        ("changed", Value::from(changed)),
        ("skipped", Value::from(skipped)),
    ]))
}

fn bash(root: &Path) -> Result<Value, Error> {
    let mut cmd = proc::cargo_cmd(BASH_TEST);
    let out = proc::run(cmd.current_dir(root))?;
    let record = bash_record(&out.stdout)?;
    let path = root.join(RECORD);
    let text = format!("{}\n", json::write(&record));
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
    let mismatches = |key: &str| {
        record
            .pointer(&format!("/{key}/mismatches"))
            .and_then(Value::as_u64)
    };
    let ok = out.ok() && mismatches("bash") == Some(0) && mismatches("libc") == Some(0);
    Ok(Value::object([
        ("ok", Value::from(ok)),
        ("record", Value::from(RECORD)),
        ("bash", record.get("bash").cloned().unwrap_or(Value::Null)),
        ("libc", record.get("libc").cloned().unwrap_or(Value::Null)),
    ]))
}

/// Runs `xtask oracle <semantics [--check]|bash>`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for bad arguments, [`Error::Command`] when a child process
/// fails, [`Error::Data`] for a bad child output and [`Error::Io`] when a file does not
/// write.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["semantics"] => semantics(root, false),
        ["semantics", "--check"] => semantics(root, true),
        ["bash"] => bash(root),
        _ => Err(Error::Usage(USAGE.to_owned())),
    }
}

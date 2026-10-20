//! `xtask eval`: the offline agent-quality harness (design Section 12, WP-26).
//!
//! | Command | Effect |
//! |---|---|
//! | `cargo xtask eval [--json]` | Runs `ghidorah-eval` and prints `{ ok, scorecard }`. `ok` is `true` when every gate passes. |
//! | `cargo xtask eval --explain` | Prints the failures of one run. |
//! | `cargo xtask eval --bless --reason TEXT` | Writes the new baselines. The bless log gets the commit of `HEAD`. |
//! | `cargo xtask eval replay FILE` | Sends the requests of a call record to `ghidorah mcp` and compares the replies (AC-201). |
//!
//! The replay ignores the `ms` member of each record line, because only the reply counts. The
//! server runs with `GHIDORAH_FIXED_TIME=0` and a new projects root in the temp directory.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Error;
use crate::json::{self, Value};
use crate::proc;

/// The usage text.
pub const USAGE: &str =
    "cargo xtask eval [--json | --explain | --bless --reason TEXT | replay FILE]";

/// Runs `xtask eval` with `args` in the workspace `root`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for bad arguments, and [`Error::Command`] or [`Error::Data`] when
/// the eval binary or the replay fails to run.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    match args.first().map(String::as_str) {
        Some("replay") => {
            let file = args.get(1).ok_or_else(|| Error::Usage(USAGE.to_owned()))?;
            replay(root, Path::new(file))
        }
        _ => harness(root, args),
    }
}

fn harness(root: &Path, args: &[String]) -> Result<Value, Error> {
    let mut pass: Vec<String> = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" => {}
            "--explain" | "--bless" => pass.push(arg.clone()),
            "--reason" => {
                let reason = rest.next().ok_or_else(|| Error::Usage(USAGE.to_owned()))?;
                pass.extend(["--reason".to_owned(), reason.clone()]);
            }
            _ => return Err(Error::Usage(USAGE.to_owned())),
        }
    }
    let bless = pass.iter().any(|a| a == "--bless");
    if bless != pass.iter().any(|a| a == "--reason") {
        return Err(Error::Usage(USAGE.to_owned()));
    }
    if bless {
        let head = proc::run_ok(
            std::process::Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .current_dir(root),
        )?;
        pass.extend(["--commit".to_owned(), head.stdout.trim().to_owned()]);
    }
    let mut cmd = proc::cargo_cmd(&["run", "-q", "-p", "ghidorah-eval", "--"]);
    cmd.args(&pass).current_dir(root);
    let out = proc::run(&mut cmd)?;
    let last = out.stdout.lines().last().unwrap_or_default();
    let value = json::parse(last).map_err(|e| {
        Error::data(
            "ghidorah-eval",
            format!("{e}: {}", proc::tail(&out.stderr, 5)),
        )
    })?;
    if pass.iter().any(|a| a == "--explain" || a == "--bless") {
        return Ok(Value::object([
            ("ok", Value::from(out.ok())),
            ("result", value),
        ]));
    }
    Ok(Value::object([
        ("ok", Value::from(out.ok())),
        ("scorecard", value),
    ]))
}

/// One record line: its sequence number, the request and the recorded reply.
fn records(text: &str) -> Result<Vec<(u64, Value, Value)>, Error> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v =
            json::parse(line).map_err(|e| Error::data("record", format!("line {}: {e}", n + 1)))?;
        let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let request = v
            .get("request")
            .cloned()
            .ok_or_else(|| Error::data("record", format!("line {} has no request", n + 1)))?;
        let response = v.get("response").cloned().unwrap_or(Value::Null);
        out.push((seq, request, response));
    }
    Ok(out)
}

/// Gives the sequence numbers of the records whose reply differs from the reply with the same
/// request `id` in `replies`. A record with no reply differs.
#[must_use]
pub fn diffs(records: &[(u64, Value, Value)], replies: &[Value]) -> Vec<u64> {
    records
        .iter()
        .filter(|(_, request, expected)| {
            let id = request.get("id");
            replies.iter().find(|r| r.get("id") == id) != Some(expected)
        })
        .map(|(seq, _, _)| *seq)
        .collect()
}

/// Gives the `ghidorah mcp` command of a replay in the workspace `root`.
///
/// The server keeps its projects in `projects`, so a replay writes nothing to the default
/// projects root under `HOME`.
#[must_use]
pub fn replay_command(root: &Path, projects: &Path) -> Command {
    let mut cmd = proc::cargo_cmd(&["run", "-q", "-p", "ghidorah", "--", "mcp", "--root", "."]);
    cmd.arg("--project-root")
        .arg(projects)
        .current_dir(root)
        .env("GHIDORAH_FIXED_TIME", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

/// Makes a new empty projects root for one replay under the system temp directory.
///
/// # Errors
///
/// Returns [`Error::Io`] when the function cannot remove or make the directory.
fn replay_projects() -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("ghidorah-replay-{}", std::process::id()));
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(dir, e)),
    }
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    Ok(dir)
}

/// Replays the call record `file` on a new `ghidorah mcp` and compares the replies.
///
/// The server keeps its projects in a new temp directory, and the replay removes it at the end.
///
/// # Errors
///
/// Returns [`Error::Io`] when the record does not read, or when the function cannot make the
/// projects root. Returns [`Error::Data`] for a bad line and [`Error::Command`] when the server
/// does not start.
pub fn replay(root: &Path, file: &Path) -> Result<Value, Error> {
    let text =
        std::fs::read_to_string(root.join(file)).map_err(|e| Error::io(root.join(file), e))?;
    let entries = records(&text)?;
    let projects = replay_projects()?;
    let report = replay_in(root, &entries, &projects);
    let removed = std::fs::remove_dir_all(&projects).map_err(|e| Error::io(&projects, e));
    let report = report?;
    removed?;
    Ok(report)
}

/// Replays `entries` on a new `ghidorah mcp` with the projects root `projects`.
fn replay_in(
    root: &Path,
    entries: &[(u64, Value, Value)],
    projects: &Path,
) -> Result<Value, Error> {
    let mut cmd = replay_command(root, projects);
    let argv = proc::describe(&cmd);
    let mut child = cmd.spawn().map_err(|e| proc::start_error(&argv, &e))?;
    if let Some(mut stdin) = child.stdin.take() {
        for (_, request, _) in entries {
            writeln!(stdin, "{}", json::write(request))
                .map_err(|e| proc::start_error(&argv, &e))?;
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| proc::start_error(&argv, &e))?;
    let replies: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| json::parse(l).ok())
        .filter(|v| v.get("id").is_some())
        .collect();
    let differ = diffs(entries, &replies);
    Ok(Value::object([
        ("ok", Value::from(differ.is_empty())),
        ("entries", Value::from(entries.len())),
        (
            "diffs",
            Value::Array(differ.into_iter().map(Value::from).collect()),
        ),
    ]))
}

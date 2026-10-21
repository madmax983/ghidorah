//! The `ghidorah-eval` binary. `xtask eval` runs it from the workspace root.
//!
//! | Command | Output |
//! |---|---|
//! | `ghidorah-eval [--json]` | The scorecard of one run, as one JSON object. |
//! | `ghidorah-eval --explain` | The failures of one run: scenarios, mistakes, walks, recall and survey misses. |
//! | `ghidorah-eval --bless --commit C --reason R` | One run, then the new baselines and the bless-log lines. |
//!
//! The exit code is 0 when every gate passes, 1 when a gate fails and 2 for an error.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the binary prints the scorecard and its errors"
)]

use std::path::Path;
use std::process::ExitCode;

use ghidorah_eval::{gate, report};
use ghidorah_json::Value;

/// The usage text.
const USAGE: &str = "ghidorah-eval [--json] | --explain | --bless --commit COMMIT --reason TEXT";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn run(root: &Path, args: &[String]) -> Result<(Value, bool), String> {
    let bless = args.iter().any(|a| a == "--bless");
    if args.iter().any(|a| {
        a.starts_with("--")
            && !["--json", "--explain", "--bless", "--commit", "--reason"].contains(&a.as_str())
    }) {
        return Err(USAGE.to_owned());
    }
    let report = report::evaluate(root).map_err(|e| e.to_string())?;
    let card = report.scorecard();
    if args.iter().any(|a| a == "--explain") {
        return Ok((report.explain(), true));
    }
    if !bless {
        let costs = gate::read_costs(root).unwrap_or_default();
        let ok = report.gates().iter().all(|g| g.3) && report.cost_findings(&costs).is_empty();
        return Ok((card, ok));
    }
    let commit = flag(args, "--commit").ok_or(USAGE)?;
    let reason = flag(args, "--reason").ok_or(USAGE)?;
    let lines = gate::bless(
        root,
        &report.thresholds,
        &report.blessing(),
        &commit,
        &reason,
    )
    .map_err(|e| e.to_string())?;
    let out = Value::object([
        ("ok", Value::from(true)),
        (
            "blessed",
            Value::from(u64::try_from(lines.len()).unwrap_or(u64::MAX)),
        ),
        ("scorecard", card),
    ]);
    Ok((out, true))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(Path::new("."), &args) {
        Ok((value, ok)) => {
            println!("{}", ghidorah_json::write(&value));
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("ghidorah-eval: {e}");
            ExitCode::from(2)
        }
    }
}

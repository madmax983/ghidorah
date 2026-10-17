//! The `xtask` binary. Run it with `cargo xtask <command> [args]`.
//!
//! Each run prints one JSON object on stdout. The exit code is 0 when the object has `ok: true`,
//! 1 when it has `ok: false` and 2 for an error.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the binary writes its JSON report and its errors"
)]

use std::process::ExitCode;

use xtask::json::{self, Value};
use xtask::{Error, ac, ci, cov, dag, fixtures, gates, golden, oracle, ste, verify, workspace};

const USAGE: &str = "cargo xtask <gates|deps|ci|cov|ac|ste|verify|fixtures|golden|oracle> [args]";

fn dispatch(command: &str, rest: &[String]) -> Result<Value, Error> {
    let root = workspace::root();
    match command {
        "gates" => gates::run(&root, rest),
        "deps" => dag::run(&root, rest),
        "ci" => ci::run(&root, rest),
        "cov" => cov::run(&root, rest),
        "ac" => ac::run(&root, rest),
        "ste" => ste::run(&root, rest),
        "verify" => verify::run(&root, rest),
        "fixtures" => fixtures::run(&root, rest),
        "golden" => golden::run(&root, rest),
        "oracle" => oracle::run(&root, rest),
        _ => Err(Error::Usage(USAGE.to_owned())),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = args
        .split_first()
        .map_or(("", &[][..]), |(c, r)| (c.as_str(), r));
    match dispatch(command, rest) {
        Ok(report) => {
            println!("{}", json::write(&report));
            if report.get("ok").and_then(Value::as_bool) == Some(true) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            let report = Value::object([
                ("ok", Value::from(false)),
                ("error", Value::from(err.to_string())),
            ]);
            println!("{}", json::write(&report));
            eprintln!("xtask: {err}");
            ExitCode::from(2)
        }
    }
}

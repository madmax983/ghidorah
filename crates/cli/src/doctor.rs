//! `ghidorah doctor`: the self-test of the build (design Section 10.14).
//!
//! The command prints one JSON object
//! `{ ok, version, run_config, checks: [{ name, ok, .. }] }`:
//!
//! | Check | Test |
//! |---|---|
//! | `registry_lint` | The registry lint finds nothing. |
//! | `examples` | Each registry example runs with no `INTERNAL_ERROR`, and each result fits 60,000 characters in each content mode. The check gives the sizes. |
//! | `project_dir` | A probe file in the projects root writes and syncs. |
//! | `era` | The era rules answer both handshakes and `server/discover`. |
//!
//! The exit code is 0 when all checks pass, else 1. Output holds no absolute path.

use std::fs;
use std::io::Write;
use std::path::Path;

use ghidorah_base::FixedClock;
use ghidorah_json::{Limits, Object, Value};
use ghidorah_tools::budget::HARD_MAX_CHARS;
use ghidorah_tools::content::result_chars;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ContentMode, Request, dispatch};

use crate::Streams;
use crate::argv::DoctorArgs;
use crate::backend::{Backend, OpenError, Options};
use crate::call::SESSION;
use crate::config::Env;
use crate::exit::Exit;
use crate::mcp::era;
use crate::mcp::server::Server;
use crate::out;

/// The name of the probe file in the projects root.
pub const PROBE: &str = ".ghidorah-doctor-probe";

/// The error code of a handler panic.
const INTERNAL: &str = "INTERNAL_ERROR";

fn check(name: &str, ok: bool, extra: Vec<(&str, Value)>) -> Value {
    let mut out = Object::new();
    out.push("name", Value::from(name));
    out.push("ok", Value::Bool(ok));
    for (key, value) in extra {
        out.push(key, value);
    }
    Value::Object(out)
}

fn registry_lint<B: Backend>() -> Value {
    let findings: Vec<Value> = lint(&B::registry())
        .iter()
        .map(|f| Value::from(f.to_string()))
        .collect();
    check(
        "registry_lint",
        findings.is_empty(),
        vec![("findings", Value::Array(findings))],
    )
}

/// Gives the modern `tools/call` request of one example.
fn modern_call(tool: &str, args: &Value) -> String {
    let meta = Value::object([
        (era::VERSION_KEY, Value::from(era::MODERN)),
        (era::CAPABILITIES_KEY, Value::Object(Object::new())),
    ]);
    let request = Value::object([
        ("jsonrpc", Value::from("2.0")),
        ("id", Value::from(1u64)),
        ("method", Value::from("tools/call")),
        (
            "params",
            Value::object([
                ("name", Value::from(tool)),
                ("arguments", args.clone()),
                ("_meta", meta),
            ]),
        ),
    ]);
    ghidorah_json::write(&request)
}

/// Gives the result size and the error code of one example in `mode`.
fn example_in_mode<B: Backend>(
    options: &Options,
    tool: &str,
    args: &Value,
    mode: ContentMode,
) -> Result<(u64, Option<String>), OpenError> {
    let mut backend = B::for_examples(options)?;
    if mode == ContentMode::Plain {
        let envelope = dispatch(&mut backend, &Request::new(tool, args.clone())).to_json();
        let code = envelope
            .pointer("/error/code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return Ok((result_chars(&envelope, false, mode), code));
    }
    let mut server = Server::new(backend, mode, Box::new(FixedClock::new(0)));
    let lines = server.handle_line(modern_call(tool, args).as_bytes());
    let reply = lines
        .last()
        .and_then(|line| ghidorah_json::parse(line, &Limits::DEFAULT).ok())
        .unwrap_or_default();
    let result = reply.get("result").cloned().unwrap_or_default();
    let chars = u64::try_from(ghidorah_json::write(&result).chars().count()).unwrap_or(u64::MAX);
    let code = reply
        .pointer("/error/data/code")
        .or_else(|| result.pointer("/structuredContent/error/code"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((chars, code))
}

const MODES: [(&str, ContentMode); 4] = [
    ("plain", ContentMode::Plain),
    ("structured", ContentMode::Structured),
    ("text", ContentMode::Text),
    ("both", ContentMode::Both),
];

fn examples<B: Backend>(options: &Options) -> Value {
    let mut all_ok = true;
    let mut results = Vec::new();
    for tool in B::registry().tools() {
        for (index, example) in tool.examples.iter().enumerate() {
            let args = ghidorah_json::parse(example.args, &Limits::DEFAULT).unwrap_or_default();
            let mut ok = args.as_object().is_some();
            let mut chars = Object::new();
            for (name, mode) in MODES {
                match example_in_mode::<B>(options, tool.name, &args, mode) {
                    Ok((size, code)) => {
                        ok &=
                            size <= u64::from(HARD_MAX_CHARS) && code.as_deref() != Some(INTERNAL);
                        chars.push(name, Value::from(size));
                    }
                    Err(_) => ok = false,
                }
            }
            all_ok &= ok;
            results.push(Value::object([
                ("tool", Value::from(tool.name)),
                ("example", Value::from(index.saturating_add(1))),
                ("ok", Value::Bool(ok)),
                ("chars", Value::Object(chars)),
            ]));
        }
    }
    check("examples", all_ok, vec![("results", Value::Array(results))])
}

/// Writes, syncs and removes the probe file in `root`.
fn probe(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    let path = root.join(PROBE);
    let mut file = fs::File::create(&path)?;
    file.write_all(b"ghidorah doctor probe\n")?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(&path)?;
    fs::File::open(root)?.sync_all()
}

fn project_dir(options: &Options) -> Value {
    let Some(root) = &options.project_root else {
        return check(
            "project_dir",
            false,
            vec![(
                "reason",
                Value::from(
                    "No projects root is known. Set HOME or XDG_DATA_HOME, or send --project-root.",
                ),
            )],
        );
    };
    match probe(root) {
        Ok(()) => check("project_dir", true, Vec::new()),
        Err(error) => check(
            "project_dir",
            false,
            vec![(
                "reason",
                Value::from(format!("The probe file does not write: {error}.")),
            )],
        ),
    }
}

/// Gives the result of one handshake line on a new server, or `None`.
fn handshake<B: Backend>(options: &Options, line: &str) -> Option<Value> {
    let backend = B::open(options).ok()?;
    let mut server = Server::new(backend, ContentMode::Both, Box::new(FixedClock::new(0)));
    let lines = server.handle_line(line.as_bytes());
    let reply = ghidorah_json::parse(lines.last()?, &Limits::DEFAULT).ok()?;
    reply.get("result").cloned()
}

fn era_check<B: Backend>(options: &Options) -> Value {
    let mut ok = true;
    for version in era::LEGACY {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{version}","capabilities":{{}},"clientInfo":{{"name":"doctor","version":"1"}}}}}}"#
        );
        let answer = handshake::<B>(options, &line);
        ok &= answer
            .as_ref()
            .and_then(|r| r.get("protocolVersion"))
            .and_then(Value::as_str)
            == Some(version);
    }
    let discover = handshake::<B>(
        options,
        r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#,
    );
    let versions: Vec<Value> = era::SUPPORTED.iter().map(|v| Value::from(*v)).collect();
    ok &= discover.as_ref().and_then(|r| r.get("supportedVersions"))
        == Some(&Value::Array(versions.clone()));
    check("era", ok, vec![("versions", Value::Array(versions))])
}

/// Gives the doctor report of the backend `B` with `options`.
#[must_use]
pub fn report<B: Backend>(options: &Options) -> Value {
    let checks = vec![
        registry_lint::<B>(),
        examples::<B>(options),
        project_dir(options),
        era_check::<B>(options),
    ];
    let ok = checks
        .iter()
        .all(|c| c.get("ok") == Some(&Value::Bool(true)));
    Value::object([
        ("ok", Value::Bool(ok)),
        ("version", Value::from(crate::VERSION)),
        ("run_config", options.run.to_json()),
        ("checks", Value::Array(checks)),
    ])
}

/// Runs `ghidorah doctor` with the backend `B`.
pub fn doctor<B: Backend>(args: &DoctorArgs, env: &Env, streams: &mut Streams) -> Exit {
    let mut options = Options::new(env, SESSION);
    if let Some(root) = &args.project_root {
        options.project_root = Some(env.cwd.join(root));
    }
    let report = report::<B>(&options);
    let ok = report.get("ok") == Some(&Value::Bool(true));
    match out::line(&mut streams.stdout, &ghidorah_json::write(&report)) {
        Ok(()) => Exit::of_ok(ok),
        Err(stop) => stop.exit(),
    }
}

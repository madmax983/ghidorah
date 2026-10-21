//! The `xtask bench` command: the benchmarks of design Section 13.10 (ADR-0026).
//!
//! The command builds the release `ghidorah` binary and drives it as a child process. Each
//! benchmark uses the harness of `testkit::bench`: 3 warm-up runs, 31 samples, and up to 3
//! runs while the spread is above 10%. The gate is the median against `perf/budget.json`.
//!
//! | Key | Sample |
//! |---|---|
//! | `cold_start_ms` | the time from the start of `ghidorah mcp` to its `server/discover` reply (AC-171) |
//! | `call_overhead_us` | one `calc` call through a running `ghidorah jsonl` |
//! | `decode_us` | one `mem_read` sweep of 500 instructions of a T2 fixture |
//! | `load_ms` | `ghidorah call binary_load` of a T2 fixture with no analysis |
//! | `analysis_t2_ms` | `ghidorah call binary_load` of a T2 fixture with the full analysis |
//!
//! Each sample checks its reply ([`check_reply`], [`check_load`]). A reply that is not `ok`
//! stops the benchmark with an error, so an error path never counts as a fast sample. A
//! `decode_us` reply needs 500 rows. An `analysis_t2_ms` reply needs the state `complete`.
//!
//! Output: `{ ok, cpu, profile, <key>: { median, mad, runs, budget, ok } }` with values in the
//! unit of the key. AC-171 reads `/cold_start_ms/median`. AC-202 reads `/ok`.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use ghidorah_testkit::bench::{Stats, cpu_model, measure};

use crate::json::{self, Value};
use crate::{Error, proc};

/// The budget file, relative to the workspace root.
pub const BUDGET_PATH: &str = "perf/budget.json";

/// The T2 fixture of the load, decode and analysis benchmarks.
pub const T2_FIXTURE: &str = "fixtures/bin/large.gcc-O2";

/// The number of instructions of one `decode_us` sample.
pub const DECODE_COUNT: u64 = 500;

/// The output budget of one `decode_us` sample: the hard cap of `max_chars`.
///
/// The default budget of `mem_read` is too small for 500 rows, and then the reply is
/// `OUTPUT_BUDGET_EXCEEDED`.
pub const DECODE_MAX_CHARS: u64 = 60_000;

/// The unit of a benchmark value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unit {
    /// Milliseconds.
    Ms,
    /// Microseconds.
    Us,
}

/// One benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bench {
    /// The key in the output and in `perf/budget.json`.
    pub key: &'static str,
    /// The unit of the values.
    pub unit: Unit,
}

/// The benchmarks in run order.
pub const BENCHES: &[Bench] = &[
    Bench {
        key: "cold_start_ms",
        unit: Unit::Ms,
    },
    Bench {
        key: "call_overhead_us",
        unit: Unit::Us,
    },
    Bench {
        key: "decode_us",
        unit: Unit::Us,
    },
    Bench {
        key: "load_ms",
        unit: Unit::Ms,
    },
    Bench {
        key: "analysis_t2_ms",
        unit: Unit::Ms,
    },
];

/// Reads the budgets of `perf/budget.json`: a JSON object of integer values.
///
/// # Errors
///
/// Returns [`Error::Data`] when the text is not such an object.
pub fn parse_budget(text: &str) -> Result<BTreeMap<String, u64>, Error> {
    let bad = |message: String| Error::data(BUDGET_PATH, message);
    let value = json::parse(text).map_err(|e| bad(e.to_string()))?;
    let members = value
        .as_object()
        .ok_or_else(|| bad("the budget is not an object".to_owned()))?;
    members
        .iter()
        .map(|(key, v)| {
            v.as_u64()
                .map(|n| (key.clone(), n))
                .ok_or_else(|| bad(format!("{key} is not a whole number")))
        })
        .collect()
}

/// Gives `ns` nanoseconds in `unit`, rounded up.
#[must_use]
pub const fn to_unit(ns: u64, unit: Unit) -> u64 {
    match unit {
        Unit::Ms => ns.div_ceil(1_000_000),
        Unit::Us => ns.div_ceil(1_000),
    }
}

/// Gives the report of one benchmark: `{ median, mad, runs, budget, ok }`.
///
/// A benchmark with no budget is not `ok`.
#[must_use]
pub fn verdict(bench: &Bench, stats: &Stats, budget: Option<u64>) -> Value {
    let median = to_unit(stats.median_ns, bench.unit);
    Value::object([
        ("median", Value::from(median)),
        ("mad", Value::from(to_unit(stats.mad_ns, bench.unit))),
        ("runs", Value::from(u64::from(stats.runs))),
        ("budget", budget.map_or(Value::Null, Value::from)),
        ("ok", Value::from(budget.is_some_and(|b| median <= b))),
    ])
}

/// Gives the JSON-RPC line of a `server/discover` request with `id`.
#[must_use]
pub fn discover_line(id: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"server/discover"}}"#)
}

/// Checks one reply of a benchmark call: the reply is JSON with `ok: true`.
///
/// With `rows`, the reply also holds that many rows at `/data/rows`, or a page with that
/// many returned items at `/page/returned`.
///
/// # Errors
///
/// Returns [`Error::Data`] for a reply that is not JSON, that is not `ok`, or that holds
/// another number of rows.
pub fn check_reply(tool: &str, reply: &str, rows: Option<u64>) -> Result<Value, Error> {
    let value = json::parse(reply.trim()).map_err(|e| Error::data(tool, e.to_string()))?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = value
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("no error code");
        return Err(Error::data(tool, format!("the reply is not ok: {code}")));
    }
    if let Some(want) = rows {
        let listed = value
            .pointer("/data/rows")
            .and_then(Value::as_array)
            .map(|r| u64::try_from(r.len()).unwrap_or(u64::MAX));
        let got = listed.or_else(|| value.pointer("/page/returned").and_then(Value::as_u64));
        if got != Some(want) {
            let detail = format!("the reply holds {got:?} rows, not {want}");
            return Err(Error::data(tool, detail));
        }
    }
    Ok(value)
}

/// Checks the output of `ghidorah call binary_load`: the reply is `ok`. With `analysis`, the
/// state at `/data/analysis/state` is also `complete`.
///
/// # Errors
///
/// Returns [`Error::Data`] when the output fails a check.
pub fn check_load(stdout: &str, analysis: bool) -> Result<(), Error> {
    let value = check_reply("binary_load", stdout, None)?;
    let state = value
        .pointer("/data/analysis/state")
        .and_then(Value::as_str);
    if analysis && state != Some("complete") {
        let detail = format!("the analysis state is {state:?}, not complete");
        return Err(Error::data("binary_load", detail));
    }
    Ok(())
}

/// Gives the `mem_read` arguments of one `decode_us` sample at `entry` of `binary_id`.
#[must_use]
pub fn decode_args(binary_id: &str, entry: &str) -> String {
    format!(
        r#"{{"binary_id":"{binary_id}","target":"{entry}","as":"insn","count":{DECODE_COUNT},"max_chars":{DECODE_MAX_CHARS}}}"#
    )
}

/// Gives the benchmarks that `args` names, or every benchmark.
fn select(args: &[String]) -> Result<Vec<&'static Bench>, Error> {
    let mut out = Vec::new();
    for arg in args {
        let bench = BENCHES
            .iter()
            .find(|b| b.key == arg)
            .ok_or_else(|| Error::Usage("cargo xtask bench [<key>..]".to_owned()))?;
        out.push(bench);
    }
    if out.is_empty() {
        out.extend(BENCHES.iter());
    }
    Ok(out)
}

/// Builds the release `ghidorah` binary and gives its path.
fn build_release(root: &Path) -> Result<PathBuf, Error> {
    let mut cmd = proc::cargo_cmd(&[
        "build",
        "--release",
        "-p",
        "ghidorah",
        "--bin",
        "ghidorah",
        "--message-format=json",
    ]);
    let out = proc::run_ok(cmd.current_dir(root))?;
    out.stdout
        .lines()
        .filter_map(|line| json::parse(line).ok())
        .filter(|m| m.pointer("/target/name").and_then(Value::as_str) == Some("ghidorah"))
        .find_map(|m| {
            m.get("executable")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .ok_or_else(|| Error::data("cargo build --release", "no ghidorah binary"))
}

/// A running `ghidorah` with piped stdin and stdout.
struct Server {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Server {
    /// Starts `exe` with `args` in `root`.
    fn start(exe: &Path, args: &[&str], root: &Path) -> Result<Self, Error> {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let line = proc::describe(&cmd);
        let mut child = cmd.spawn().map_err(|e| proc::start_error(&line, &e))?;
        let pipes = child.stdin.take().zip(child.stdout.take());
        let Some((input, output)) = pipes else {
            let _ = child.kill();
            return Err(Error::data(line, "no pipes"));
        };
        Ok(Self {
            child,
            input,
            output: BufReader::new(output),
        })
    }

    /// Sends one line and reads one reply line.
    fn ask(&mut self, line: &str) -> Result<String, Error> {
        let fail = |e: &std::io::Error| Error::data("ghidorah", e.to_string());
        self.input
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| fail(&e))?;
        self.input.flush().map_err(|e| fail(&e))?;
        let mut reply = String::new();
        let read = self.output.read_line(&mut reply).map_err(|e| fail(&e))?;
        if read == 0 {
            return Err(Error::data("ghidorah", "the process closed its output"));
        }
        Ok(reply)
    }

    /// Stops the process.
    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Measures `sample`. The first error of a sample stops the benchmark.
fn timed(mut sample: impl FnMut() -> Result<(), Error>) -> Result<Stats, Error> {
    let mut first: Option<Error> = None;
    let stats = measure(|| {
        if first.is_none()
            && let Err(e) = sample()
        {
            first = Some(e);
        }
    });
    first.map_or(Ok(stats), Err)
}

/// The paths of one benchmark run.
struct Paths<'a> {
    exe: &'a Path,
    root: &'a Path,
    work: &'a Path,
}

impl Paths<'_> {
    /// Gives a new projects root under the work directory.
    fn projects(&self, name: &str) -> String {
        self.work.join(name).to_string_lossy().into_owned()
    }

    /// Gives the workspace root as text.
    fn root_text(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }
}

/// `cold_start_ms`: start `ghidorah mcp` and read the `server/discover` reply.
fn cold_start(p: &Paths<'_>) -> Result<Stats, Error> {
    let projects = p.projects("cold");
    let root = p.root_text();
    let line = discover_line(1);
    timed(|| {
        let mut server = Server::start(
            p.exe,
            &["mcp", "--project-root", &projects, "--root", &root],
            p.root,
        )?;
        let reply = server.ask(&line);
        server.stop();
        reply.map(|_| ())
    })
}

/// Gives a `jsonl` request line.
fn request(tool: &str, args: &str) -> String {
    format!(r#"{{"id":1,"tool":"{tool}","args":{args}}}"#)
}

/// `call_overhead_us` or `decode_us`: one call through a running `ghidorah jsonl`.
fn call_overhead(p: &Paths<'_>, decode: bool) -> Result<Stats, Error> {
    let projects = p.projects(if decode { "decode" } else { "calls" });
    let root = p.root_text();
    let mut server = Server::start(
        p.exe,
        &["jsonl", "--project-root", &projects, "--root", &root],
        p.root,
    )?;
    let (tool, line, rows) = if decode {
        let load = request(
            "binary_load",
            &format!(r#"{{"path":"{T2_FIXTURE}","analysis":"none"}}"#),
        );
        let reply = match server.ask(&load) {
            Ok(text) => check_reply("binary_load", &text, None),
            Err(e) => Err(e),
        };
        let reply = match reply {
            Ok(value) => value,
            Err(e) => {
                server.stop();
                return Err(e);
            }
        };
        let field = |ptr: &str| {
            reply
                .pointer(ptr)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let (Some(id), Some(entry)) = (field("/data/binary_id"), field("/data/entry")) else {
            server.stop();
            return Err(Error::data("binary_load", "no binary_id or entry"));
        };
        let line = request("mem_read", &decode_args(&id, &entry));
        ("mem_read", line, Some(DECODE_COUNT))
    } else {
        let line = request("calc", r#"{"expr":"0x10 + 0x20 * 0x3"}"#);
        ("calc", line, None)
    };
    // Each sample checks its reply, so an error reply does not count as a fast call.
    let stats = timed(|| check_reply(tool, &server.ask(&line)?, rows).map(|_| ()));
    server.stop();
    stats
}

/// `load_ms` or `analysis_t2_ms`: `ghidorah call binary_load` of the T2 fixture.
fn load(p: &Paths<'_>, analysis: bool) -> Result<Stats, Error> {
    let root = p.root_text();
    let args = format!(
        r#"{{"path":"{T2_FIXTURE}","analysis":"{}"}}"#,
        if analysis { "full" } else { "none" }
    );
    let mut n = 0u64;
    timed(|| {
        n = n.saturating_add(1);
        let projects = p.projects(&format!("load_{analysis}_{n}"));
        let mut cmd = Command::new(p.exe);
        cmd.args([
            "call",
            "binary_load",
            &args,
            "--project-root",
            &projects,
            "--root",
            &root,
        ])
        .current_dir(p.root);
        let out = proc::run_ok(&mut cmd)?;
        check_load(&out.stdout, analysis)
    })
}

/// Runs `xtask bench [<key>..]`.
///
/// # Errors
///
/// Returns an error for an unknown key, a bad budget file, a build that fails or a child
/// process that does not answer.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let benches = select(args)?;
    let path = root.join(BUDGET_PATH);
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let budgets = parse_budget(&text)?;
    let exe = build_release(root)?;
    let work = root.join("target").join("xtask-bench");
    if work.exists() {
        std::fs::remove_dir_all(&work).map_err(|e| Error::io(&work, e))?;
    }
    std::fs::create_dir_all(&work).map_err(|e| Error::io(&work, e))?;
    let paths = Paths {
        exe: &exe,
        root,
        work: &work,
    };
    let mut ok = true;
    let mut out = BTreeMap::new();
    for bench in benches {
        let stats = match bench.key {
            "cold_start_ms" => cold_start(&paths)?,
            "call_overhead_us" => call_overhead(&paths, false)?,
            "decode_us" => call_overhead(&paths, true)?,
            "load_ms" => load(&paths, false)?,
            _ => load(&paths, true)?,
        };
        let report = verdict(bench, &stats, budgets.get(bench.key).copied());
        ok &= report.get("ok").and_then(Value::as_bool) == Some(true);
        out.insert(bench.key.to_owned(), report);
    }
    std::fs::remove_dir_all(&work).map_err(|e| Error::io(&work, e))?;
    out.insert("ok".to_owned(), Value::from(ok));
    out.insert("cpu".to_owned(), Value::from(cpu_model()));
    out.insert("profile".to_owned(), Value::from("release"));
    Ok(Value::Object(out))
}

//! `binary_load`, the path roots and the binding rules (AC-147, AC-213).

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

use ghidorah_base::{BinaryId, Clock, ErrorCode, Fuel};
use ghidorah_json::{Object, Value};
use ghidorah_tools::handlers::analysis_run::SLICE_STEPS;
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::session::{AnalysisEngine, OpenBinary, ProjectsConfig, RunReport, Until};
use ghidorah_tools::{
    AnalysisState, Args, BinaryArg, Ctx, Payload, Registry, Request, Roots, Session, ToolError,
    ToolSpec, dispatch_with, handlers,
};

use crate::support::{
    DEMO_ID, WP13B, call, call_value, code, config, data, demo, json, load, registry, session,
    session_with, text_at,
};

/// A temporary directory that the test removes at the end.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("ghidorah-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("the parent dir");
    }
    std::fs::write(path, bytes).expect("the file writes");
}

fn path_call(session: &mut Session, path: &str) -> Value {
    call_value(
        session,
        "binary_load",
        Value::object([
            ("path", Value::from(path)),
            ("analysis", Value::from("none")),
        ]),
    )
}

#[test]
fn binary_load_demo() {
    let mut s = session();
    let envelope = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    let got = data(&envelope);
    assert_eq!(text_at(got, "/binary_id"), DEMO_ID);
    assert_eq!(
        text_at(got, "/sha256"),
        ghidorah_base::hex::encode(&ghidorah_base::sha256(ghidorah_tools::demo::BYTES))
    );
    assert_eq!(text_at(got, "/file_name"), "demo.elf");
    assert_eq!(text_at(got, "/format"), "elf64-le");
    assert_eq!(text_at(got, "/arch"), "x86_64");
    assert_eq!(text_at(got, "/kind"), "dyn");
    assert_eq!(text_at(got, "/entry"), "0x10e0");
    assert_eq!(got.get("size"), Some(&Value::from(16_112_u64)));
    assert_eq!(got.get("already_loaded"), Some(&Value::Bool(false)));
    assert_eq!(got.get("read_only"), Some(&Value::Bool(false)));
    assert_eq!(text_at(got, "/analysis/state"), "none");
    assert!(got.pointer("/diagnostics/total").is_some(), "{got}");
    handlers::load::SPEC
        .output
        .check(got, Fit::Exact)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        text_at(&envelope, "/binary_id"),
        DEMO_ID,
        "the envelope echoes the binary"
    );
    assert_eq!(s.binaries().count(), 1);

    let again = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(data(&again).get("already_loaded"), Some(&Value::Bool(true)));
    let by_id = call(
        &mut s,
        "binary_load",
        &format!(r#"{{"binary_id":"{DEMO_ID}"}}"#),
    );
    assert_eq!(data(&by_id).get("already_loaded"), Some(&Value::Bool(true)));
    let by_path = path_call(&mut s, "crates/tools/data/demo.elf");
    assert_eq!(
        data(&by_path).get("already_loaded"),
        Some(&Value::Bool(true))
    );
    assert_eq!(s.binaries().count(), 1);
    assert_eq!(
        s.recent().map(|id| id.to_string()),
        Some(DEMO_ID.to_owned())
    );

    let dry = call(
        &mut s,
        "binary_load",
        r#"{"path":"fixtures/bin/loops.gcc-O2","dry_run":true}"#,
    );
    assert_eq!(data(&dry).get("already_loaded"), Some(&Value::Bool(false)));
    assert_eq!(dry.get("noop"), Some(&Value::Bool(true)), "{dry}");
    assert_eq!(dry.get("diff"), Some(&Value::Array(Vec::new())), "{dry}");
    assert_eq!(s.binaries().count(), 1, "a dry run opens nothing");

    let raw = call(
        &mut s,
        "binary_load",
        r#"{"path":"fixtures/bin/hello.gcc-O2","file_format":"raw","base":"0x400000","entry":"0x401040","analysis":"none"}"#,
    );
    let got = data(&raw);
    assert_eq!(text_at(got, "/format"), "raw");
    assert_eq!(text_at(got, "/kind"), "raw");
    assert_eq!(text_at(got, "/entry"), "0x401040");
    assert_eq!(s.binaries().count(), 2);

    let mut ro = config();
    ro.read_only = true;
    let mut s = session_with(ro);
    let envelope = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(data(&envelope).get("read_only"), Some(&Value::Bool(true)));
}

/// A test engine: the first run uses its steps and reports a fixed state. A later run finds
/// no work, so a load in fuel slices stops after the first slice.
struct TestEngine(AnalysisState, bool);

impl AnalysisEngine for TestEngine {
    fn run(
        &mut self,
        binary: &mut OpenBinary,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        let steps = match (self.1, until) {
            (true, _) => 0,
            (false, Until::Full) => 42,
            (false, Until::Triage) => 7,
        };
        fuel.take(steps)
            .map_err(|_| ToolError::new(ErrorCode::BudgetExceeded))?;
        assert!(!binary.file_name.is_empty());
        self.1 = true;
        Ok(RunReport {
            state: self.0,
            steps_used: steps,
        })
    }
}

#[test]
fn binary_load_runs_the_engine() {
    let mut s = session();
    s.set_engine(Box::new(TestEngine(AnalysisState::Complete, false)));
    let envelope = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    let got = data(&envelope);
    assert_eq!(text_at(got, "/analysis/state"), "complete");
    assert_eq!(
        got.pointer("/analysis/steps_used"),
        Some(&Value::from(42_u64))
    );
    assert_eq!(text_at(&envelope, "/analysis/state"), "complete");
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(false)));

    let mut s = session();
    s.set_engine(Box::new(TestEngine(AnalysisState::BudgetStopped, false)));
    let envelope = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"triage"}"#,
    );
    assert_eq!(
        text_at(data(&envelope), "/analysis/state"),
        "budget_stopped"
    );
    assert_eq!(
        data(&envelope).pointer("/analysis/steps_used"),
        Some(&Value::from(7_u64))
    );
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(true)));
    let later = call(&mut s, "calc", r#"{"expr":"main"}"#);
    assert_eq!(later.get("partial"), Some(&Value::Bool(true)), "{later}");

    let mut s = session();
    s.set_engine(Box::new(TestEngine(AnalysisState::Complete, false)));
    let envelope = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    assert_eq!(text_at(data(&envelope), "/analysis/state"), "none");
    let envelope = call(
        &mut s,
        "binary_load",
        r#"{"path":"fixtures/bin/loops.gcc-O2","max_steps":3}"#,
    );
    assert_eq!(code(&envelope), "BUDGET_EXCEEDED", "{envelope}");
}

/// The fixture of the slice tests: its analysis needs many fuel slices.
const LARGE: &str = "fixtures/bin/large.gcc-O2";

/// Makes a session of the test registry with the shipped engine and the clock `clock`.
fn engine_session(eval_mode: bool, clock: Box<dyn Clock + Send>) -> Session {
    let mut c = config();
    c.run.eval_mode = eval_mode;
    let mut s = Session::with_registry(registry(), c, clock);
    handlers::analysis_run::install(&mut s);
    s
}

/// Runs `binary_load` with `args` in a request that `edit` changes.
fn load_with(s: &mut Session, args: &str, edit: impl FnOnce(&mut Request)) -> Value {
    let registry = s.active_registry();
    let mut request = Request::new("binary_load", json(args));
    edit(&mut request);
    dispatch_with(&registry, s, &request).to_json()
}

/// Gives the work units of the analysis of a `binary_load` result.
fn steps_of(envelope: &Value) -> u64 {
    data(envelope)
        .pointer("/analysis/steps_used")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

#[test]
fn regress_binary_load_stops_on_cancel() {
    let mut s = engine_session(false, Box::new(ghidorah_base::FixedClock::new(0)));
    let args = format!(r#"{{"path":"{LARGE}"}}"#);
    let envelope = load_with(&mut s, &args, |r| {
        r.cancel = Some(Arc::new(AtomicBool::new(true)));
    });
    assert_eq!(
        text_at(data(&envelope), "/analysis/state"),
        "budget_stopped",
        "the cancel stops the analysis at the first fuel checkpoint: {envelope}"
    );
    let used = steps_of(&envelope);
    assert!(used > 0 && used < 2 * SLICE_STEPS, "one slice: {used}");
    assert_eq!(
        envelope.get("noop"),
        Some(&Value::Bool(false)),
        "the load stays"
    );
}

#[test]
fn regress_binary_load_sends_progress() {
    for (path, many) in [("crates/tools/data/demo.elf", false), (LARGE, true)] {
        let mut s = engine_session(false, Box::new(ghidorah_base::FixedClock::new(0)));
        let (sender, reports) = mpsc::channel();
        let args = format!(r#"{{"path":"{path}"}}"#);
        let envelope = load_with(&mut s, &args, |r| r.progress = Some(sender));
        assert_eq!(text_at(data(&envelope), "/analysis/state"), "complete");
        let used = steps_of(&envelope);
        let values: Vec<u64> = reports.try_iter().map(|p| p.progress).collect();
        assert_eq!(values.last(), Some(&used), "{path}: {values:?}");
        assert!(values.windows(2).all(|w| w[0] < w[1]), "{values:?}");
        let mut before = 0;
        for (i, v) in values.iter().enumerate() {
            if i + 1 < values.len() {
                assert!(
                    v - before >= SLICE_STEPS,
                    "a slice uses its fuel: {values:?}"
                );
            }
            before = *v;
        }
        if many {
            assert!(values.len() >= 3, "one report per slice: {values:?}");
        } else {
            assert_eq!(values.len(), 1, "one slice: {values:?}");
        }
    }
}

/// A clock whose monotonic time moves 1,000 ms at each read.
#[derive(Debug, Default)]
struct StepClock {
    now: Cell<u64>,
}

impl Clock for StepClock {
    fn unix_ms(&self) -> u64 {
        0
    }

    fn monotonic_ms(&self) -> u64 {
        let now = self.now.get();
        self.now.set(now.saturating_add(1_000));
        now
    }
}

#[test]
fn regress_max_ms_time_stop() {
    let args = format!(r#"{{"path":"{LARGE}","max_ms":1,"max_steps":20000}}"#);
    let warned = |envelope: &Value| {
        envelope
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(|w| w.iter().any(|w| text_at(w, "/code") == "W_TIME_STOP"))
    };
    // The guard fires at the first fuel checkpoint.
    let mut s = engine_session(false, Box::<StepClock>::default());
    let stopped = call(&mut s, "binary_load", &args);
    assert_eq!(
        text_at(data(&stopped), "/analysis/state"),
        "budget_stopped",
        "{stopped}"
    );
    assert!(warned(&stopped), "a time stop gives W_TIME_STOP: {stopped}");
    assert!(steps_of(&stopped) < 2 * SLICE_STEPS, "one slice: {stopped}");
    // Eval mode turns the guard off: the run uses its fuel.
    let mut s = engine_session(true, Box::<StepClock>::default());
    let full = call(&mut s, "binary_load", &args);
    assert!(!warned(&full), "{full}");
    assert!(steps_of(&full) >= 20_000, "{full}");
    // The guard of analysis_run is the same.
    let mut s = engine_session(false, Box::<StepClock>::default());
    let id = load(&mut s, LARGE);
    let run = call(
        &mut s,
        "analysis_run",
        &format!(r#"{{"binary_id":"{id}","max_ms":1}}"#),
    );
    assert!(warned(&run), "{run}");
    assert_eq!(text_at(data(&run), "/state"), "budget_stopped", "{run}");
}

#[test]
fn regress_stale_lock_repair_call() {
    let dir = TempDir::new("stale_lock");
    let mut c = config();
    c.projects = Some(ProjectsConfig {
        root: dir.0.clone(),
        named: true,
        break_lock: false,
    });
    {
        let mut first = session_with(c.clone());
        data(&call(
            &mut first,
            "binary_load",
            r#"{"builtin":"demo","analysis":"none"}"#,
        ));
    }
    // The owner of the lock is a process that does not exist: a stale lock.
    let lock = dir.0.join(DEMO_ID).join("project.lock");
    std::fs::write(
        &lock,
        r#"{"boot_id":"gone","pid":999999999,"start_time":1}"#,
    )
    .expect("a stale lock");
    let mut s = session_with(c.clone());
    let args = format!(r#"{{"binary_id":"{DEMO_ID}"}}"#);
    let locked = call(&mut s, "binary_load", &args);
    assert_eq!(code(&locked), "PROJECT_LOCKED", "{locked}");
    assert_eq!(
        locked.pointer("/error/details/stale"),
        Some(&Value::Bool(true)),
        "{locked}"
    );
    assert_eq!(text_at(&locked, "/next/0/tool"), "binary_load", "{locked}");
    let repair = locked
        .pointer("/next/0/args")
        .cloned()
        .expect("a repair call");
    assert_eq!(text_at(&repair, "/binary_id"), DEMO_ID, "{locked}");
    assert_eq!(
        repair.get("break_lock"),
        Some(&Value::Bool(true)),
        "{locked}"
    );
    let opened = call_value(&mut s, "binary_load", repair);
    assert_eq!(text_at(data(&opened), "/binary_id"), DEMO_ID);
    // The flag holds for one call only, and a live owner keeps its lock.
    let mut other = session_with(c);
    let held = call(
        &mut other,
        "binary_load",
        &format!(r#"{{"binary_id":"{DEMO_ID}","break_lock":true}}"#),
    );
    assert_eq!(code(&held), "PROJECT_LOCKED", "{held}");
    assert_eq!(
        held.pointer("/error/details/stale"),
        Some(&Value::Bool(false)),
        "{held}"
    );
    assert!(held.pointer("/next/0/args/break_lock").is_none(), "{held}");
}

#[test]
fn binary_load_errors() {
    let mut s = demo();
    let cases = [
        ("{}", "MISSING_ARGUMENT"),
        (r#"{"builtin":"demo","path":"a"}"#, "INVALID_ARGUMENT"),
        (r#"{"builtin":"nope"}"#, "INVALID_ARGUMENT"),
        (r#"{"path":"Cargo.toml"}"#, "FORMAT_MALFORMED"),
        (
            r#"{"path":"Cargo.toml","file_format":"elf"}"#,
            "FORMAT_MALFORMED",
        ),
        (
            r#"{"path":"crates/tools/data/demo.elf","file_format":"raw"}"#,
            "MISSING_ARGUMENT",
        ),
        (r#"{"builtin":"demo","base":"0x1000"}"#, "INVALID_ARGUMENT"),
        (r#"{"builtin":"demo","entry":"0x1000"}"#, "INVALID_ARGUMENT"),
        (r#"{"binary_id":"0000000000000000"}"#, "UNKNOWN_BINARY"),
        (r#"{"binary_id":"zz"}"#, "UNKNOWN_BINARY"),
        (r#"{"path":"no/such/file"}"#, "FILE_UNREADABLE"),
        (r#"{"path":"crates"}"#, "FILE_UNREADABLE"),
    ];
    for (args, want) in cases {
        let envelope = call(&mut s, "binary_load", args);
        assert_eq!(code(&envelope), want, "{args}: {envelope}");
    }
    let envelope = call(&mut s, "binary_load", r#"{"path":"Cargo.toml"}"#);
    assert!(
        envelope.pointer("/error/details/diagnostic/code").is_some(),
        "{envelope}"
    );
    let envelope = call(&mut s, "binary_load", r#"{"binary_id":"0000000000000000"}"#);
    assert_eq!(
        text_at(&envelope, "/error/candidates/0/value"),
        DEMO_ID,
        "{envelope}"
    );
    let envelope = call(
        &mut s,
        "binary_load",
        r#"{"path":"crates/tools/data/demo.elf","file_format":"raw"}"#,
    );
    assert_eq!(
        text_at(&envelope, "/error/field_path"),
        "/base",
        "{envelope}"
    );

    let dir = TempDir::new("formats");
    let mut elf32 = vec![0x7f, b'E', b'L', b'F', 1, 1, 1, 0];
    elf32.resize(64, 0);
    write(&dir.0.join("elf32.bin"), &elf32);
    let mut c = config();
    c.roots = Roots::new(&dir.0, &[PathBuf::from(".")]).expect("the temp root");
    let mut s = session_with(c);
    let envelope = path_call(&mut s, "elf32.bin");
    assert_eq!(code(&envelope), "UNSUPPORTED_FORMAT", "{envelope}");
    assert!(
        !text_at(&envelope, "/error/details/detected").is_empty(),
        "{envelope}"
    );
    let supported = envelope
        .pointer("/error/details/supported")
        .and_then(Value::as_array)
        .map(<[Value]>::len);
    assert_eq!(supported, Some(ghidorah_loader::SUPPORTED_FORMATS.len()));
}

#[test]
#[cfg(unix)]
fn ac_147_path_roots() {
    let dir = TempDir::new("roots");
    let root = dir.0.join("root");
    write(&root.join("inside/demo.elf"), ghidorah_tools::demo::BYTES);
    write(
        &dir.0.join("outside/secret.elf"),
        ghidorah_tools::demo::BYTES,
    );
    std::os::unix::fs::symlink(dir.0.join("outside"), root.join("dir_link")).expect("a symlink");
    std::os::unix::fs::symlink(dir.0.join("outside/secret.elf"), root.join("file_link"))
        .expect("a symlink");
    std::os::unix::fs::symlink(root.join("inside/demo.elf"), root.join("good_link"))
        .expect("a symlink");
    let mut c = config();
    c.roots = Roots::new(&dir.0, &[PathBuf::from("root")]).expect("the temp root");
    let mut s = session_with(c);
    let absolute_inside = root.join("inside/demo.elf");
    let absolute_outside = dir.0.join("outside/secret.elf");
    let cases: [(String, &str); 11] = [
        ("inside/demo.elf".to_owned(), ""),
        ("./inside/../inside/demo.elf".to_owned(), ""),
        ("good_link".to_owned(), ""),
        (absolute_inside.display().to_string(), ""),
        (absolute_outside.display().to_string(), "PATH_OUTSIDE_ROOT"),
        ("../outside/secret.elf".to_owned(), "PATH_OUTSIDE_ROOT"),
        (
            "inside/../../outside/secret.elf".to_owned(),
            "PATH_OUTSIDE_ROOT",
        ),
        ("dir_link/secret.elf".to_owned(), "PATH_OUTSIDE_ROOT"),
        ("file_link".to_owned(), "PATH_OUTSIDE_ROOT"),
        ("/etc/passwd".to_owned(), "PATH_OUTSIDE_ROOT"),
        ("inside/missing.elf".to_owned(), "FILE_UNREADABLE"),
    ];
    let temp = dir.0.display().to_string();
    for (path, want) in &cases {
        let envelope = path_call(&mut s, path);
        assert_eq!(code(&envelope), *want, "{path}: {envelope}");
        if *want == "PATH_OUTSIDE_ROOT" {
            assert_eq!(
                envelope.pointer("/error/details/roots"),
                Some(&json(r#"["root"]"#)),
                "{envelope}"
            );
            let text = ghidorah_json::write(&envelope);
            assert!(
                !text.contains(&temp),
                "no absolute path in the error: {text}"
            );
        }
    }
    let id = load(&mut s, "inside/demo.elf");
    assert_eq!(id, DEMO_ID);
    assert_eq!(
        s.config().roots.check("inside/../inside/demo.elf").ok(),
        std::fs::canonicalize(&absolute_inside).ok()
    );
    assert!(Roots::new(&dir.0, &[]).is_err());
    assert!(Roots::new(&dir.0, &[PathBuf::from("no_such_dir")]).is_err());
    assert!(Roots::new(&dir.0, &[PathBuf::from("outside/secret.elf")]).is_err());
}

const COUNT_ARGS: &[ghidorah_tools::ArgSpec] = &[];

fn count_items(s: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let binary = s.bound(&ctx.frame)?;
    let count = binary.program.binary().symbols.len();
    Ok(Payload::Object(Object::from_iter([(
        "count",
        Value::from(count),
    )])))
}

fn brief(_s: &mut Session, _args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(Object::new()))
}

/// A test tool that needs a binary.
const COUNT: ToolSpec<Session> = ToolSpec {
    title: "Count symbols",
    summary: "Count the symbols of the binary.",
    description: "Count the symbols of the binary.",
    args: COUNT_ARGS,
    ..ToolSpec::base("symbol_count", count_items)
};

/// A stand-in for `session_brief`, so the helper call of `NO_BINARY_OPEN` passes its check.
const BRIEF: ToolSpec<Session> = ToolSpec {
    title: "Brief",
    summary: "Brief the session.",
    description: "Brief the session.",
    binary: BinaryArg::Optional,
    ..ToolSpec::base("session_brief", brief)
};

fn binding_registry() -> Registry<Session> {
    let mut tools: Vec<&'static ToolSpec<Session>> = WP13B.to_vec();
    tools.push(&COUNT);
    tools.push(&BRIEF);
    Registry::new(Box::leak(tools.into_boxed_slice()))
}

#[test]
fn ac_213_no_binary_open() {
    let mut s = Session::with_registry(
        binding_registry(),
        config(),
        Box::new(ghidorah_base::FixedClock::new(0)),
    );
    for (tool, args) in [("symbol_count", "{}"), ("calc", r#"{"expr":"main"}"#)] {
        let envelope = call(&mut s, tool, args);
        assert_eq!(code(&envelope), "NO_BINARY_OPEN", "{tool}: {envelope}");
        assert_eq!(
            text_at(&envelope, "/next/0/tool"),
            "session_brief",
            "{envelope}"
        );
        assert_eq!(
            envelope.pointer("/next/0/args"),
            Some(&json("{}")),
            "{envelope}"
        );
    }
    let envelope = call(&mut s, "calc", r#"{"expr":"0x1"}"#);
    assert!(data(&envelope).get("address").is_none(), "{envelope}");
    let envelope = call(&mut s, "session_brief", "{}");
    assert!(envelope.get("binary_id").is_none(), "{envelope}");
}

#[test]
fn binary_required_and_unknown_binary() {
    let mut s = Session::with_registry(
        binding_registry(),
        config(),
        Box::new(ghidorah_base::FixedClock::new(0)),
    );
    let demo_id = load(&mut s, "crates/tools/data/demo.elf");
    let helpers = load(&mut s, "fixtures/bin/two_helpers.gcc-O2");
    assert_eq!(demo_id, DEMO_ID);
    assert_eq!(s.recent().map(|id| id.to_string()), Some(helpers.clone()));

    let envelope = call(&mut s, "symbol_count", "{}");
    assert_eq!(code(&envelope), "BINARY_REQUIRED", "{envelope}");
    assert_eq!(text_at(&envelope, "/error/details/binary_id"), helpers);
    let values: Vec<String> = envelope
        .pointer("/error/candidates")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|c| text_at(c, "/value"))
        .collect();
    assert_eq!(values, [helpers.clone(), DEMO_ID.to_owned()], "{envelope}");

    let envelope = call(&mut s, "calc", r#"{"expr":"main"}"#);
    assert_eq!(code(&envelope), "BINARY_REQUIRED", "{envelope}");
    assert_eq!(text_at(&envelope, "/next/0/tool"), "calc", "{envelope}");
    assert_eq!(
        text_at(&envelope, "/next/0/args/binary_id"),
        helpers,
        "{envelope}"
    );
    assert_eq!(
        text_at(&envelope, "/next/0/args/expr"),
        "main",
        "{envelope}"
    );
    let envelope = call(&mut s, "calc", r#"{"expr":"0x1 + 0x1"}"#);
    assert_eq!(text_at(data(&envelope), "/value"), "0x2");

    let envelope = call(
        &mut s,
        "symbol_count",
        &format!(r#"{{"binary_id":"{DEMO_ID}"}}"#),
    );
    assert_eq!(text_at(&envelope, "/binary_id"), DEMO_ID, "{envelope}");
    assert_eq!(
        s.recent().map(|id| id.to_string()),
        Some(DEMO_ID.to_owned())
    );
    let full = format!(
        r#"{{"binary_id":"{}"}}"#,
        ghidorah_base::hex::encode(&ghidorah_base::sha256(ghidorah_tools::demo::BYTES))
    );
    let envelope = call(&mut s, "symbol_count", &full);
    assert_eq!(
        text_at(&envelope, "/binary_id"),
        DEMO_ID,
        "64 digits work: {envelope}"
    );
    for bad in ["0000000000000000", "nope"] {
        let envelope = call(
            &mut s,
            "symbol_count",
            &format!(r#"{{"binary_id":"{bad}"}}"#),
        );
        assert_eq!(code(&envelope), "UNKNOWN_BINARY", "{envelope}");
    }
    let id = BinaryId::parse(DEMO_ID).expect("an ID");
    assert!(s.binary(id).is_some());
    let frame = ghidorah_tools::Frame::default();
    assert_eq!(
        s.bound(&frame).err().map(|e| e.code),
        Some(ErrorCode::BinaryRequired)
    );
}

#[test]
fn binary_required_gives_a_repair_call() {
    let mut s = Session::with_registry(
        binding_registry(),
        config(),
        Box::new(ghidorah_base::FixedClock::new(0)),
    );
    let demo_id = load(&mut s, "crates/tools/data/demo.elf");
    let helpers = load(&mut s, "fixtures/bin/two_helpers.gcc-O2");
    let envelope = call(&mut s, "symbol_count", r#"{"format":"detailed"}"#);
    assert_eq!(code(&envelope), "BINARY_REQUIRED", "{envelope}");
    assert_eq!(text_at(&envelope, "/next/0/tool"), "symbol_count");
    assert_eq!(text_at(&envelope, "/next/0/args/binary_id"), helpers);
    assert_eq!(
        text_at(&envelope, "/next/0/args/format"),
        "detailed",
        "the repair call keeps the arguments: {envelope}"
    );
    assert_eq!(
        text_at(&envelope, "/next/0/why"),
        ghidorah_tools::hints::WHY_BINARY
    );
    let next = envelope
        .pointer("/next/0/args")
        .cloned()
        .expect("a repair call");
    let envelope = call_value(&mut s, "symbol_count", next);
    assert_eq!(text_at(&envelope, "/binary_id"), helpers, "{envelope}");
    assert_ne!(demo_id, helpers);
}

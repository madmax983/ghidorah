//! `binary_load`, the path roots and the binding rules (AC-147, AC-213).

use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, ErrorCode, Fuel};
use ghidorah_json::{Object, Value};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::session::{AnalysisEngine, OpenBinary, RunReport, Until};
use ghidorah_tools::{
    AnalysisState, Args, BinaryArg, Ctx, Payload, Registry, Roots, Session, ToolError, ToolSpec,
    handlers,
};

use crate::support::{
    DEMO_ID, WP13B, call, call_value, code, config, data, demo, json, load, session, session_with,
    text_at,
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
        r#"{"path":"fixtures/bin/hello.gcc-O2","format":"raw","base":"0x400000","entry":"0x401040","analysis":"none"}"#,
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

/// A test engine: it reports a fixed state and the steps it used.
struct TestEngine(AnalysisState);

impl AnalysisEngine for TestEngine {
    fn run(
        &mut self,
        binary: &mut OpenBinary,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        let steps = if until == Until::Full { 42 } else { 7 };
        fuel.take(steps)
            .map_err(|_| ToolError::new(ErrorCode::BudgetExceeded))?;
        assert!(!binary.file_name.is_empty());
        Ok(RunReport {
            state: self.0,
            steps_used: steps,
        })
    }
}

#[test]
fn binary_load_runs_the_engine() {
    let mut s = session();
    s.set_engine(Box::new(TestEngine(AnalysisState::Complete)));
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
    s.set_engine(Box::new(TestEngine(AnalysisState::BudgetStopped)));
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
    s.set_engine(Box::new(TestEngine(AnalysisState::Complete)));
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

#[test]
fn binary_load_errors() {
    let mut s = demo();
    let cases = [
        ("{}", "MISSING_ARGUMENT"),
        (r#"{"builtin":"demo","path":"a"}"#, "INVALID_ARGUMENT"),
        (r#"{"builtin":"nope"}"#, "INVALID_ARGUMENT"),
        (r#"{"path":"Cargo.toml"}"#, "FORMAT_MALFORMED"),
        (
            r#"{"path":"Cargo.toml","format":"elf"}"#,
            "FORMAT_MALFORMED",
        ),
        (
            r#"{"path":"crates/tools/data/demo.elf","format":"raw"}"#,
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
        r#"{"path":"crates/tools/data/demo.elf","format":"raw"}"#,
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
    assert_eq!(values.len(), 2, "{envelope}");

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
        Some(ErrorCode::NoBinaryOpen)
    );
}

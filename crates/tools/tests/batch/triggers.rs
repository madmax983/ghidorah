//! The code triggers of `tests/data/code_triggers.jsonl` (AC-141b, AC-220) and the agent text
//! of their envelopes (AC-024, AC-142, AC-143).
//!
//! Each line is `{ code, setup?, before?, tool, args }`. The harness makes the session of
//! `setup`, runs the calls of `before`, then runs `tool` with `args`. The line gives its code
//! when a member `code` of the envelope holds it: the error, a warning, a caveat or a step.
//!
//! | Setup | Session |
//! |---|---|
//! | `demo` (the default) | the analyzed demo binary |
//! | `none` | no open binary |
//! | `raw_demo` | the demo binary with no analysis |
//! | `fixture:NAME` | the analyzed fixture `fixtures/bin/NAME` |
//! | `two` | the demo binary and the fixture `hello.gcc-O2` |
//! | `profile:mini`, `profile:readonly` | the demo binary in that profile |
//! | `read_only` | the demo binary in read-only mode |
//! | `slow` | the demo binary with a clock that moves 1,000 ms at each read |
//! | `panic` | the demo binary and a test tool `panic_tool` that panics |
//! | `locked` | a second session on a project that a first session holds |
//! | `torn`, `corrupt` | a project whose journal has a torn last line, or a bad middle line |
//! | `elf:aarch64`, `elf:mangled`, `elf:sp`, `elf:wide`, `file:elf32` | a temp root with a built input file |

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use ghidorah_base::catalog::RepairClass;
use ghidorah_base::{Clock, ErrorCode, FixedClock, WarningCode};
use ghidorah_json::Value;
use ghidorah_testkit::elf::{ElfBuilder, Fde, ImportKind, Loc, Section, Symbol};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::hints::{MAX_NEXT, check};
use ghidorah_tools::session::{LabelRule, ProjectsConfig};
use ghidorah_tools::{
    Args, Ctx, Example, Host, OpenBinary, OutputShape, Payload, Registry, Request, Roots, Session,
    SessionConfig, ToolError, ToolSpec, dispatch_with, handlers,
};

use crate::support::{
    DEMO_ID, analyzed, call, call_value, config, demo_id, json, registry, root, session_with,
    text_at,
};

/// One line of the trigger file.
struct Line {
    number: usize,
    code: String,
    setup: String,
    before: Vec<(String, Value)>,
    tool: String,
    args: Value,
}

/// Gives the lines of `tests/data/code_triggers.jsonl`.
fn lines() -> Vec<Line> {
    let path = root().join("tests/data/code_triggers.jsonl");
    let text = std::fs::read_to_string(&path).expect("the trigger file reads");
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            let value = json(l);
            let before = value
                .get("before")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .map(|c| {
                    (
                        text_at(c, "/tool"),
                        c.get("args").cloned().unwrap_or_default(),
                    )
                })
                .collect();
            Line {
                number: i + 1,
                code: text_at(&value, "/code"),
                setup: value
                    .get("setup")
                    .and_then(Value::as_str)
                    .unwrap_or("demo")
                    .to_owned(),
                before,
                tool: text_at(&value, "/tool"),
                args: value.get("args").cloned().unwrap_or_default(),
            }
        })
        .collect()
}

fn panics(_: &mut Session, _: &Args, _: &mut Ctx) -> Result<Payload, ToolError> {
    panic!("the test tool panics on purpose")
}

/// A test tool that panics.
const PANIC_TOOL: ToolSpec<Session> = ToolSpec {
    title: "Panic in a test",
    summary: "Panic in a test so that the panic guard runs.",
    description: "Panic in a test so that the panic guard runs.",
    output: OutputShape::Any,
    examples: &[Example {
        args: "{}",
        golden: "tests/golden/batch/panic_tool.json",
    }],
    ..ToolSpec::base("panic_tool", panics)
};

/// Gives the registry of the sessions with the panic tool at the end.
fn panic_registry() -> Registry<Session> {
    static CELL: OnceLock<Registry<Session>> = OnceLock::new();
    *CELL.get_or_init(|| {
        let mut tools = registry().tools().to_vec();
        tools.push(&PANIC_TOOL);
        Registry::new(Box::leak(tools.into_boxed_slice()))
    })
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
        self.now.set(now + 1_000);
        now
    }
}

/// Gives a new empty directory for one setup.
fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("batch_triggers")
        .join(format!("{}-{n}", name.replace(':', "_")));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Gives the settings of a session with the projects root `dir`.
fn projects_config(dir: &std::path::Path) -> SessionConfig {
    let mut config = config();
    config.labels = LabelRule::Mcp;
    config.projects = Some(ProjectsConfig {
        root: dir.to_path_buf(),
        named: true,
        break_lock: false,
    });
    config
}

/// Opens the analyzed demo binary in `session`.
fn open_demo(session: &mut Session, read_only: bool) {
    let found = analyzed();
    let label = session.new_label();
    session.open(OpenBinary {
        id: demo_id(),
        program: found.program.clone(),
        file_name: found.file_name.clone(),
        read_only,
        label,
        analysis: found.analysis,
    });
}

/// Gives the session of `bytes` written to `file` under a new temp root.
fn session_of_file(name: &str, file: &str, bytes: &[u8]) -> Session {
    let dir = tmp(name);
    std::fs::write(dir.join(file), bytes).expect("the input writes");
    let mut config = config();
    config.roots = Roots::new(&dir, &[PathBuf::from(".")]).expect("the temp root");
    session_with(config)
}

/// The count of `cmp edi, N; je end` pairs of `elf:wide`: more blocks than the structurer
/// budget of 500 nodes.
const WIDE_PAIRS: u32 = 600;

/// Gives the bytes of the built input file of `elf:ARG`.
fn elf_bytes(arg: &str) -> Vec<u8> {
    let at = |off| Loc::section(".text", off);
    match arg {
        "aarch64" => {
            let code = [0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
            ElfBuilder::exec()
                .machine(183)
                .section(Section::code(".text", &code))
                .symbol(Symbol::func("main", at(0), 8))
                .entry(Loc::symbol("main"))
                .build()
        }
        "sp" => {
            // push rbp; call leaf; pop rbp; ret, then leaf: ret. The FDE has no CFA rows, so
            // its CFA at the call does not agree with the stack pointer after the push.
            let code = [0x55, 0xe8, 0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0xc3];
            ElfBuilder::exec()
                .section(Section::code(".text", &code))
                .symbol(Symbol::func("main", at(0), 8))
                .symbol(Symbol::func("leaf", at(8), 1))
                .fde(Fde {
                    at: at(0),
                    len: 8,
                    program: Vec::new(),
                })
                .entry(Loc::symbol("main"))
                .build()
        }
        "wide" => {
            let end = WIDE_PAIRS * 9;
            let mut code = Vec::new();
            for i in 0..WIDE_PAIRS {
                code.extend([0x83, 0xff, i.to_le_bytes()[0], 0x0f, 0x84]);
                code.extend((end - (i + 1) * 9).to_le_bytes());
            }
            code.push(0xc3);
            let size = u64::from(end) + 1;
            ElfBuilder::exec()
                .section(Section::code(".text", &code))
                .symbol(Symbol::func("main", at(0), size))
                .entry(Loc::symbol("main"))
                .build()
        }
        _ => ElfBuilder::exec()
            .section(Section::code(".text", &[0xc3; 4]))
            .symbol(Symbol::func("_ZN3foo3barEv", at(0), 1))
            .symbol(Symbol::func("main", at(2), 1))
            .import("__cxa_atexit", ImportKind::Plt)
            .entry(Loc::symbol("main"))
            .build(),
    }
}

/// Writes a project of the demo binary with two renames to `dir`.
fn write_project(dir: &std::path::Path) {
    let mut s = session_with(projects_config(dir));
    let envelope = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(text_at(&envelope, "/data/binary_id"), DEMO_ID, "{envelope}");
    for (target, name) in [("0x1090", "first"), ("0x1094", "second")] {
        let args = format!(r#"{{"target":"{target}","name":"{name}"}}"#);
        let renamed = call(&mut s, "symbol_rename", &args);
        assert_eq!(renamed.get("ok"), Some(&Value::Bool(true)), "{renamed}");
    }
}

/// The sessions that a setup keeps alive, for example the first writer of `locked`.
type Keep = Vec<Session>;

/// Makes the session of `setup`.
fn setup(setup: &str, keep: &mut Keep) -> Session {
    let (kind, arg) = setup.split_once(':').unwrap_or((setup, ""));
    match kind {
        "none" => crate::support::session(),
        "raw_demo" => {
            let mut s = crate::support::session();
            let _ = call(
                &mut s,
                "binary_load",
                r#"{"builtin":"demo","analysis":"none"}"#,
            );
            s
        }
        "fixture" => {
            let mut s = crate::support::session();
            let args = Value::object([("path", Value::from(format!("fixtures/bin/{arg}")))]);
            let envelope = call_value(&mut s, "binary_load", args);
            assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
            s
        }
        "two" => {
            let mut s = crate::support::demo();
            let args = r#"{"path":"fixtures/bin/hello.gcc-O2","analysis":"none"}"#;
            let envelope = call(&mut s, "binary_load", args);
            assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
            s
        }
        "profile" => {
            let profile = ghidorah_tools::profiles::parse_profile(arg).expect("a profile");
            crate::support::demo_in(profile)
        }
        "read_only" => {
            let mut s = crate::support::session();
            open_demo(&mut s, true);
            s
        }
        "slow" => {
            let mut s = Session::with_registry(registry(), config(), Box::<StepClock>::default());
            handlers::analysis_run::install(&mut s);
            open_demo(&mut s, false);
            s
        }
        "panic" => {
            let mut s =
                Session::with_registry(panic_registry(), config(), Box::new(FixedClock::new(0)));
            handlers::analysis_run::install(&mut s);
            open_demo(&mut s, false);
            s
        }
        "locked" => {
            let dir = tmp("locked");
            let mut first = session_with(projects_config(&dir));
            let _ = call(&mut first, "binary_load", r#"{"builtin":"demo"}"#);
            keep.push(first);
            session_with(projects_config(&dir))
        }
        "torn" | "corrupt" => {
            let dir = tmp(kind);
            write_project(&dir);
            let project = dir.join(DEMO_ID);
            std::fs::remove_file(project.join("snapshot.json")).expect("the snapshot exists");
            let journal = project.join("journal.jsonl");
            let text = std::fs::read_to_string(&journal).expect("the journal");
            let out = if kind == "torn" {
                text.get(..text.len() - 7).unwrap_or_default().to_owned()
            } else {
                let mut rows: Vec<String> = text.lines().map(str::to_owned).collect();
                let middle = rows.len() / 2;
                rows[middle] = rows[middle].replace("first", "fXrst");
                rows.join("\n") + "\n"
            };
            std::fs::write(&journal, out).expect("the journal writes");
            session_with(projects_config(&dir))
        }
        "elf" => session_of_file(setup, "input.elf", &elf_bytes(arg)),
        "file" => {
            let mut elf32 = vec![0x7f, b'E', b'L', b'F', 1, 1, 1, 0];
            elf32.resize(64, 0);
            session_of_file(setup, "elf32.bin", &elf32)
        }
        _ => crate::support::demo(),
    }
}

/// Tells if a member `code` of `value` holds `code`.
fn holds_code(value: &Value, code: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, member)| {
            (key == "code" && member.as_str() == Some(code)) || holds_code(member, code)
        }),
        Value::Array(items) => items.iter().any(|i| holds_code(i, code)),
        _ => false,
    }
}

/// Runs one line. Gives the session and the envelope of the trigger call.
fn run(line: &Line) -> (Session, Value, Keep) {
    let mut keep = Keep::new();
    let mut s = setup(&line.setup, &mut keep);
    for (tool, args) in &line.before {
        let _ = call_value(&mut s, tool, args.clone());
    }
    let registry = s.active_registry();
    let request = Request::new(&line.tool, line.args.clone());
    let envelope = dispatch_with(&registry, &mut s, &request).to_json();
    (s, envelope, keep)
}

/// The codes that no call can give yet. AC-141b stays open while the list holds a code.
///
/// | Code | Why no call gives it |
/// |---|---|
/// | `W_STALE_OP_ID`, `W_NORETURN_SUSPECT` | no shipped code path gives the warning |
/// | `BODY_OVERLAP` | `func_edit` gives a no-op for an existing function, and redo stops at a later edit |
/// | `W_STRUCTURE_SELFCHECK` | a guard of the structurer; no input of the fixtures fails the self-check |
const NO_PRODUCER: &[&str] = &[
    "W_STALE_OP_ID",
    "W_NORETURN_SUSPECT",
    "BODY_OVERLAP",
    "W_STRUCTURE_SELFCHECK",
];

#[test]
fn code_triggers_give_their_codes() {
    let all = lines();
    assert!(all.len() >= 40, "{} lines", all.len());
    let mut bad = Vec::new();
    for line in &all {
        let (_s, envelope, _keep) = run(line);
        if !holds_code(&envelope, &line.code) {
            bad.push(format!("line {} ({}): {envelope}", line.number, line.code));
        }
    }
    assert!(
        bad.is_empty(),
        "lines without their code:\n{}",
        bad.join("\n")
    );
}

/// Gives the codes of both enums that the lines must cover.
fn wanted() -> BTreeSet<String> {
    let mut out: BTreeSet<String> = ErrorCode::ALL
        .iter()
        .map(|c| c.info().name.to_owned())
        .collect();
    out.extend(WarningCode::ALL.iter().map(|c| c.info().name.to_owned()));
    out
}

#[test]
fn code_triggers_cover_the_enums_with_a_producer() {
    let covered: BTreeSet<String> = lines().into_iter().map(|l| l.code).collect();
    let missing: Vec<String> = wanted()
        .into_iter()
        .filter(|c| !covered.contains(c) && !NO_PRODUCER.contains(&c.as_str()))
        .collect();
    assert!(missing.is_empty(), "codes with no line: {missing:?}");
}

#[test]
#[ignore = "the codes of NO_PRODUCER have no producer that a call reaches"]
fn ac_141b_code_triggers() {
    let covered: BTreeSet<String> = lines().into_iter().map(|l| l.code).collect();
    let missing: Vec<String> = wanted().difference(&covered).cloned().collect();
    assert!(missing.is_empty(), "codes with no line: {missing:?}");
}

/// Tells if `code` names an error code of class R, or of class R* with a repair call.
fn repair_code(code: &str) -> Option<RepairClass> {
    ErrorCode::ALL
        .iter()
        .find(|c| c.info().name == code)
        .map(|c| c.info().class)
        .filter(|class| matches!(class, RepairClass::Repair | RepairClass::RepairWhen))
}

#[test]
fn ac_220_repair_calls() {
    let mut checked = 0;
    for line in lines() {
        let Some(class) = repair_code(&line.code) else {
            continue;
        };
        let (mut s, envelope, _keep) = run(&line);
        let next = envelope.pointer("/next/0").cloned();
        let Some(next) = next else {
            assert_eq!(
                class,
                RepairClass::RepairWhen,
                "line {} ({}) has no next[0]: {envelope}",
                line.number,
                line.code
            );
            continue;
        };
        let tool = text_at(&next, "/tool");
        let args = next.get("args").cloned().unwrap_or_default();
        let registry = s.active_registry();
        let call = ghidorah_tools::Call::new(&tool, args.clone(), "");
        let in_profile = |name: &str| s.in_profile(name);
        check(&registry, &in_profile, &call)
            .unwrap_or_else(|e| panic!("line {}: {e}: {next}", line.number));
        let repaired = call_value(&mut s, &tool, args);
        assert!(
            !holds_code(&repaired, &line.code),
            "line {} ({}): next[0] does not repair: {repaired}",
            line.number,
            line.code
        );
        checked += 1;
    }
    assert!(checked >= 8, "{checked} repairs");
}

/// Gives every text member of the error, the warnings and the steps of an envelope.
fn agent_texts(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, member) in object.iter() {
                if matches!(key, "message" | "hint" | "why")
                    && let Some(text) = member.as_str()
                {
                    out.push(text.to_owned());
                }
                agent_texts(member, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| agent_texts(i, out)),
        _ => {}
    }
}

#[test]
fn trigger_envelopes_have_clean_text_and_hints() {
    for line in lines() {
        let (s, envelope, _keep) = run(&line);
        let mut texts = Vec::new();
        agent_texts(&envelope, &mut texts);
        for text in texts {
            for bad in ["Some(", "Os {", "Error {", "panicked at"] {
                assert!(!text.contains(bad), "line {}: {text}", line.number);
            }
            let found = check_agent_text(&text);
            assert!(found.is_empty(), "line {}: {text}: {found:?}", line.number);
        }
        let next = envelope
            .get("next")
            .and_then(Value::as_array)
            .unwrap_or_default();
        assert!(next.len() <= MAX_NEXT);
        let registry = s.active_registry();
        let in_profile = |name: &str| s.in_profile(name);
        for c in next {
            let call = ghidorah_tools::Call::new(
                &text_at(c, "/tool"),
                c.get("args").cloned().unwrap_or_default(),
                "",
            );
            check(&registry, &in_profile, &call)
                .unwrap_or_else(|e| panic!("line {}: {e}: {c}", line.number));
        }
    }
}

//! The code triggers of `tests/data/code_triggers.jsonl`: the line reader, the setups and the
//! runner. The test binaries `batch` and `tools` use them (AC-141b, AC-142, AC-220).
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
//! | `selfcheck` | the demo binary and a test tool `selfcheck_tool` that runs the real self-check |
//! | `project:NAME` | a projects root with the golden project `tests/golden/projects/NAME` |
//! | `locked` | a second session on a project that a first session holds |
//! | `torn`, `corrupt` | a project whose journal has a torn last line, or a bad middle line |
//! | `elf:aarch64`, `elf:mangled`, `elf:sp`, `elf:suspect`, `elf:wide`, `file:elf32` | a temp root with a built input file |
//!
//! The module needs the helpers of `tests/batch/support.rs` as `crate::support`.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use ghidorah_base::{Address, Clock, ErrorCode, FixedClock, FuncId};
use ghidorah_decomp::{Opts, ProgramEnv, Tree};
use ghidorah_json::{Object, Value};
use ghidorah_testkit::elf::{ElfBuilder, Fde, ImportKind, Loc, Section, Symbol};
use ghidorah_tools::session::{LabelRule, ProjectsConfig};
use ghidorah_tools::{
    ArgKind, ArgSpec, Args, Ctx, Example, OpenBinary, OutputShape, Payload, Registry, Request,
    Role, Roots, Session, SessionConfig, ToolError, ToolSpec, Warning, dispatch_with, handlers,
};

use crate::support::{
    DEMO_ID, analyzed, call, call_value, config, demo_id, json, registry, root, session_with,
    text_at,
};

/// One line of the trigger file.
pub struct Line {
    /// The line number in the file, from 1.
    pub number: usize,
    /// The code that the line gives.
    pub code: String,
    /// The setup of the session, `demo` when the line has none.
    pub setup: String,
    /// The calls that run before the trigger call: `(tool, args)`.
    pub before: Vec<(String, Value)>,
    /// The tool of the trigger call.
    pub tool: String,
    /// The arguments of the trigger call.
    pub args: Value,
}

/// Gives the lines of `tests/data/code_triggers.jsonl`.
pub fn lines() -> Vec<Line> {
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

/// The entry of `main` in the demo binary.
const DEMO_MAIN: u64 = 0x1080;

/// Runs the real self-check of the decompiler on the tree of `main` in the demo binary. With
/// `wrong: true`, the tree is empty, so its block traces differ from the traces of the CFG.
fn selfcheck(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    let id = FuncId(Address::ram(DEMO_MAIN));
    let mut decomp = ghidorah_decomp::decompile(p, id, &Opts::default(), &mut ctx.fuel)
        .map_err(|_| ToolError::new(ErrorCode::InternalError))?;
    if args.bool("wrong").unwrap_or(false) {
        decomp.tree = Tree::Seq(Vec::new());
    }
    let body = ghidorah_decomp::print::body_units(p, id);
    let names = ghidorah_x86::lift::Names;
    let out = ghidorah_decomp::finish(decomp, &ProgramEnv(p), &names, "main", &body);
    for row in &out.warnings {
        let mut warning = Warning::new(row.code);
        warning.at = Some(format!("{:#x}", row.at));
        ctx.warnings.push(warning);
    }
    let mut result = Object::new();
    result.push("validation", Value::from(out.metrics.validation.name()));
    Ok(Payload::Object(result))
}

/// The arguments of the self-check tool.
const SELFCHECK_ARGS: &[ArgSpec] = &[ArgSpec::new(
    "wrong",
    Role::Param,
    ArgKind::Bool,
    "The value true replaces the tree with an empty tree.",
)];

/// A test tool that runs the real self-check on a tree.
const SELFCHECK_TOOL: ToolSpec<Session> = ToolSpec {
    title: "Run the self-check in a test",
    summary: "Run the self-check of the decompiler on the tree of main.",
    description: "Run the self-check of the decompiler on the tree of main.",
    args: SELFCHECK_ARGS,
    output: OutputShape::Any,
    ..ToolSpec::base("selfcheck_tool", selfcheck)
};

/// Gives the registry of the sessions with `tool` at the end.
fn registry_with(tool: &'static ToolSpec<Session>) -> Registry<Session> {
    let mut tools = registry().tools().to_vec();
    tools.push(tool);
    Registry::new(Box::leak(tools.into_boxed_slice()))
}

/// Gives the registry of the sessions with the panic tool at the end.
fn panic_registry() -> Registry<Session> {
    static CELL: OnceLock<Registry<Session>> = OnceLock::new();
    *CELL.get_or_init(|| registry_with(&PANIC_TOOL))
}

/// Gives the registry of the sessions with the self-check tool at the end.
fn selfcheck_registry() -> Registry<Session> {
    static CELL: OnceLock<Registry<Session>> = OnceLock::new();
    *CELL.get_or_init(|| registry_with(&SELFCHECK_TOOL))
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
        .join(concat!("triggers_", env!("CARGO_CRATE_NAME")))
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
        "suspect" => {
            // main: call helper, then int3 padding. helper: xor eax, eax; ret. The call falls
            // through into padding, but helper returns.
            let code = [0xe8, 0x03, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0x31, 0xc0, 0xc3];
            ElfBuilder::exec()
                .section(Section::code(".text", &code))
                .symbol(Symbol::func("main", at(0), 8))
                .symbol(Symbol::func("helper", at(8), 3))
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

/// Copies the golden project `name` of the demo binary into `dir`. The input copy comes
/// from the bytes of the built-in demo binary.
fn copy_project(name: &str, dir: &std::path::Path) {
    let from = root()
        .join("tests/golden/projects")
        .join(name)
        .join(DEMO_ID);
    let to = dir.join(DEMO_ID);
    std::fs::create_dir_all(to.join("bin")).expect("the project directory exists");
    for entry in std::fs::read_dir(&from).expect("the golden project reads") {
        let path = entry.expect("an entry").path();
        if let Some(file) = path.file_name() {
            std::fs::copy(&path, to.join(file)).expect("the copy works");
        }
    }
    let meta = std::fs::read_to_string(to.join("project.json")).expect("the project file");
    let sha = text_at(&json(&meta), "/sha256");
    std::fs::write(to.join("bin").join(sha), ghidorah_tools::demo::BYTES)
        .expect("the input copy writes");
}

/// The sessions that a setup keeps alive, for example the first writer of `locked`.
pub type Keep = Vec<Session>;

/// Makes a session whose engine stops at 64 code units (`W_ANALYSIS_LIMIT`).
fn capped_session() -> Session {
    let mut s = crate::support::session();
    s.set_engine(Box::new(handlers::analysis_run::Engine::with_unit_cap(64)));
    s
}

/// Makes the session of `setup`.
pub fn setup(setup: &str, keep: &mut Keep) -> Session {
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
        "capped" => capped_session(),
        "panic" => {
            let mut s =
                Session::with_registry(panic_registry(), config(), Box::new(FixedClock::new(0)));
            handlers::analysis_run::install(&mut s);
            open_demo(&mut s, false);
            s
        }
        "selfcheck" => {
            let mut s = Session::with_registry(
                selfcheck_registry(),
                config(),
                Box::new(FixedClock::new(0)),
            );
            handlers::analysis_run::install(&mut s);
            open_demo(&mut s, false);
            s
        }
        "project" => {
            let dir = tmp(setup);
            copy_project(arg, &dir);
            session_with(projects_config(&dir))
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
pub fn holds_code(value: &Value, code: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, member)| {
            (key == "code" && member.as_str() == Some(code)) || holds_code(member, code)
        }),
        Value::Array(items) => items.iter().any(|i| holds_code(i, code)),
        _ => false,
    }
}

/// Runs one line. Gives the session and the envelope of the trigger call.
pub fn run(line: &Line) -> (Session, Value, Keep) {
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

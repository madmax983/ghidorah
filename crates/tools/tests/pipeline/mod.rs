//! The pipeline steps of the fuzz targets `pipeline_raw` and `pipeline_elf` (design Section
//! 13.5).
//!
//! One case writes the input to a file and loads it with `binary_load`. Then it runs
//! `analysis_run` with a fuel cap, lists the functions and calls `func_get` with every section
//! for every function. A result with `INTERNAL_ERROR`, or a result with no valid shape, is a
//! violation.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::path::{Path, PathBuf};

use ghidorah_base::{FixedClock, Limits};
use ghidorah_json::Value;
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::elf::{
    ElfBuilder, Fde, HashStyle, ImportKind, Loc, Section, Symbol, malformed_variants,
};
use ghidorah_tools::handlers::{self, func_get};
use ghidorah_tools::{Request, Roots, Session, SessionConfig, dispatch_with};

/// The fuel cap of the `analysis_run` call of one case.
pub const FUEL_CAP: u64 = 20_000;

/// The largest number of functions of one case that get `func_get` calls.
pub const MAX_FUNCS: usize = 64;

/// The largest number of targets of one `func_get` call.
pub const CHUNK: usize = 16;

/// The stages of the ELF target, from the first stage to the deepest stage (AC-190d).
pub const ELF_STAGES: [&str; 7] = [
    "input", "header", "phdr", "dynamic", "symbols", "relocs", "eh_frame",
];

/// The stages of the raw target.
pub const RAW_STAGES: [&str; 4] = ["input", "loaded", "functions", "func_get"];

/// The load address of a raw case.
pub const RAW_BASE: u64 = 0x40_0000;

/// The seed fixtures of the ELF target: small T1 files with every ELF stage.
pub const SEED_FIXTURES: [&str; 3] = [
    "hello.gcc-O2",
    "syscall_only.gcc-O2",
    "two_helpers.gcc-O2.stripped",
];

/// The load mode of one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Load {
    /// The probe picks the format.
    Auto,
    /// A raw x86-64 blob at `base` with the entry `entry`.
    Raw {
        /// The load address.
        base: u64,
        /// The entry address.
        entry: u64,
    },
}

/// The result of one pipeline run with no violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    /// `true` when `binary_load` gives a binary.
    pub loaded: bool,
    /// The number of listed functions.
    pub functions: usize,
    /// The number of `func_get` calls.
    pub func_gets: usize,
}

impl Summary {
    /// Gives the deepest raw stage of the run: an index of [`RAW_STAGES`].
    #[must_use]
    pub const fn raw_stage(&self) -> usize {
        if self.func_gets > 0 {
            3
        } else if self.functions > 0 {
            2
        } else if self.loaded {
            1
        } else {
            0
        }
    }
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives a new empty work directory for the case files of `target`.
pub fn work_dir(target: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("pipeline")
        .join(target);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    dir
}

/// Gives the bytes of the fixture `name` of `fixtures/bin`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = root().join("fixtures/bin").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Gives the seed corpus of the ELF target: T1 fixtures, `ElfBuilder` files and the malformed
/// variants.
pub fn elf_seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = SEED_FIXTURES.iter().map(|n| fixture(n)).collect();
    let code = [0x55, 0x48, 0x89, 0xe5, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3];
    let built = ElfBuilder::dyn_object()
        .section(Section::code(".text", &code))
        .section(Section::data(".data", &[0u8; 32]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 11))
        .export(Symbol::func("f", Loc::section(".text", 0), 11))
        .import("puts", ImportKind::Plt)
        .needed("libc.so.6")
        .relr(Loc::section(".data", 8))
        .fde(Fde::frame_pointer(Loc::symbol("f"), 11))
        .hash(HashStyle::Both);
    out.push(built.build());
    out.push(built.strip_section_headers().build());
    out.extend(malformed_variants().into_iter().map(|v| v.bytes));
    out
}

/// Gives the seed corpus of the raw target: code bytes of T1 fixtures and short code forms.
pub fn raw_seeds() -> Vec<Vec<u8>> {
    let code = |name: &str| {
        fixture(name)
            .get(0x1100..0x1200)
            .unwrap_or_default()
            .to_vec()
    };
    vec![
        code("hello.gcc-O2"),
        code("loops.gcc-O2"),
        code("switch.gcc-O2"),
        vec![0x55, 0x48, 0x89, 0xe5, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3],
        vec![0xeb, 0xfe],
        vec![0xcc; 64],
        Vec::new(),
    ]
}

/// Gives the entry of a raw case: an offset in the blob that the first two bytes pick.
pub fn raw_entry(bytes: &[u8]) -> u64 {
    let pick = match bytes {
        [a, b, ..] => u64::from(u16::from_le_bytes([*a, *b])),
        _ => 0,
    };
    let len = u64::try_from(bytes.len()).unwrap_or(1).max(1);
    RAW_BASE + pick % len
}

/// Makes a session of the shipped registry with `dir` as its one root and the analysis engine.
pub fn session(dir: &Path) -> Session {
    let roots = Roots::new(dir, &[PathBuf::from(".")])
        .unwrap_or_else(|e| panic!("the root {}: {e}", dir.display()));
    let mut session = Session::new(SessionConfig::new(roots), Box::new(FixedClock::new(0)));
    handlers::analysis_run::install(&mut session);
    session
}

/// Runs one call and gives the envelope JSON.
pub fn call(session: &mut Session, tool: &str, args: Value) -> Value {
    let registry = session.active_registry();
    dispatch_with(&registry, session, &Request::new(tool, args)).to_json()
}

/// Gives a violation message when `envelope` is not a valid result.
///
/// # Errors
///
/// Returns the message of the first problem.
pub fn check(tool: &str, envelope: &Value) -> Result<(), String> {
    let code = envelope.pointer("/error/code").and_then(Value::as_str);
    if code == Some("INTERNAL_ERROR") {
        return Err(format!("{tool} gives INTERNAL_ERROR: {envelope}"));
    }
    match envelope.get("ok") {
        Some(Value::Bool(true)) if envelope.get("data").is_none() => {
            Err(format!("{tool} gives ok with no data"))
        }
        Some(Value::Bool(false)) if code.is_none() => {
            Err(format!("{tool} fails with no error code"))
        }
        Some(Value::Bool(_)) => Ok(()),
        _ => Err(format!("{tool} gives no ok member")),
    }
}

fn load_args(load: Load) -> Value {
    let mut members = vec![
        ("path", Value::from("case.bin")),
        ("analysis", Value::from("none")),
    ];
    if let Load::Raw { base, entry } = load {
        members.push(("file_format", Value::from("raw")));
        members.push(("base", Value::from(format!("{base:#x}"))));
        members.push(("entry", Value::from(format!("{entry:#x}"))));
    }
    Value::object(members)
}

/// Runs the pipeline on `bytes` in the work directory `dir`.
///
/// # Errors
///
/// Returns the violation message of the first bad result.
pub fn run(dir: &Path, bytes: &[u8], load: Load) -> Result<Summary, String> {
    let file = dir.join("case.bin");
    std::fs::write(&file, bytes).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut session = session(dir);
    let loaded = call(&mut session, "binary_load", load_args(load));
    check("binary_load", &loaded)?;
    let mut summary = Summary::default();
    let Some(id) = loaded.pointer("/data/binary_id").and_then(Value::as_str) else {
        return Ok(summary);
    };
    summary.loaded = true;
    let id = Value::from(id);
    let run = call(
        &mut session,
        "analysis_run",
        Value::object([
            ("binary_id", id.clone()),
            ("max_steps", Value::from(FUEL_CAP)),
        ]),
    );
    check("analysis_run", &run)?;
    let list = call(
        &mut session,
        "func_list",
        Value::object([("binary_id", id.clone()), ("limit", Value::from(1_000_u64))]),
    );
    check("func_list", &list)?;
    let funcs: Vec<Value> = list
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|item| item.get("id").cloned())
        .take(MAX_FUNCS)
        .collect();
    summary.functions = funcs.len();
    let include: Vec<Value> = func_get::SECTIONS.iter().map(|s| Value::from(*s)).collect();
    for chunk in funcs.chunks(CHUNK) {
        let got = call(
            &mut session,
            "func_get",
            Value::object([
                ("binary_id", id.clone()),
                ("targets", Value::Array(chunk.to_vec())),
                ("include", Value::Array(include.clone())),
            ]),
        );
        check("func_get", &got)?;
        summary.func_gets += 1;
    }
    Ok(summary)
}

/// Gives the deepest ELF stage of `bytes`: an index of [`ELF_STAGES`].
///
/// The stages form a chain: a stage counts only when every stage before it counts.
pub fn elf_stage(bytes: &[u8]) -> usize {
    let Ok((binary, map)) = ghidorah_loader::load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT) else {
        return 0;
    };
    let steps = [
        !map.is_empty(),
        !binary.dynamic.is_empty(),
        !binary.symbols.is_empty(),
        !binary.relocs.is_empty(),
        !binary.fdes.is_empty(),
    ];
    1 + steps.iter().take_while(|s| **s).count()
}

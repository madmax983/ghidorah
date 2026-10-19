//! Shared helpers of the WP-19 tests: fixtures, truth files, full runs and function IRs.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ghidorah_analysis::fir::{self, FuncIr, Opts};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, Limits};
use ghidorah_db::Program;
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).expect("the JSON parses")
}

/// One fixture of the manifest.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// The path under the root.
    pub path: String,
    /// The variant: `none`, `stripped`, `noeh` or `noshdr`.
    pub variant: String,
    /// The tier: `T1` or `T2`.
    pub tier: String,
    /// The truth file under the root.
    pub truth: String,
    /// The program name, for example `switch`.
    pub program: String,
}

/// Gives the fixtures of the ELF tiers `T1` and `T2` of the manifest in manifest order.
pub fn fixtures() -> Vec<Fixture> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    let manifest = json(&text);
    let list = manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures list");
    let field = |f: &Value, name: &str| {
        f.get(name)
            .and_then(Value::as_str)
            .expect("a manifest field")
            .to_owned()
    };
    list.iter()
        .filter(|f| matches!(f.get("tier").and_then(Value::as_str), Some("T1" | "T2")))
        .map(|f| Fixture {
            path: field(f, "path"),
            variant: field(f, "variant"),
            tier: field(f, "tier"),
            truth: field(f, "truth"),
            program: field(f, "program"),
        })
        .collect()
}

/// Loads the fixture at `path` under the root.
pub fn program(path: &str) -> Program {
    let bytes = std::fs::read(root().join(path)).expect("the fixture bytes");
    program_of(&bytes, &LoadOpts::AUTO)
}

/// Loads `bytes` with `opts` into a program at revision 0.
pub fn program_of(bytes: &[u8], opts: &LoadOpts) -> Program {
    let (binary, mem) = load(bytes, opts, &Limits::DEFAULT).expect("the bytes load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// Runs the analysis of `program` to completion with no fuel limit.
pub fn analyze(program: &mut Program) -> Scheduler {
    let mut sched = Scheduler::new();
    let out = sched
        .run(program, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "an unlimited run completes");
    sched
}

/// Loads and analyzes the fixture at `path`.
pub fn analyzed(path: &str) -> Program {
    let mut p = program(path);
    let _ = analyze(&mut p);
    p
}

/// Gives the analyzed program of each fixture path. The test binary builds each one once.
pub fn cached(path: &str) -> &'static Program {
    type Cache = std::sync::Mutex<BTreeMap<String, &'static Program>>;
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    let mut map = cache.lock().expect("the cache lock");
    if let Some(p) = map.get(path) {
        return p;
    }
    let p: &'static Program = Box::leak(Box::new(analyzed(path)));
    map.insert(path.to_owned(), p);
    p
}

/// Gives the truth file at `path` under the root.
pub fn truth(path: &str) -> Value {
    let text = std::fs::read_to_string(root().join(path)).expect("the truth file");
    json(&text)
}

/// Gives the hex number of a JSON string.
pub fn hex(v: &Value) -> u64 {
    ghidorah_base::hex::parse_u64(v.as_str().expect("a hex string")).expect("a hex number")
}

/// Gives the truth functions: name and address.
pub fn truth_funcs(t: &Value) -> BTreeMap<String, u64> {
    t.get("functions")
        .and_then(Value::as_array)
        .expect("truth functions")
        .iter()
        .map(|f| {
            let name = f.get("name").and_then(Value::as_str).expect("a name");
            (name.to_owned(), hex(f.get("addr").expect("an address")))
        })
        .collect()
}

/// Gives the array member `name` of a truth file.
pub fn list<'a>(t: &'a Value, name: &str) -> &'a [Value] {
    t.get(name).and_then(Value::as_array).unwrap_or_default()
}

/// Gives the function ID at `addr`.
pub const fn fid(addr: u64) -> FuncId {
    FuncId(Address::ram(addr))
}

/// Builds the IR of the published function at `entry`.
pub fn fir_of(p: &Program, entry: u64) -> FuncIr {
    fir::build(p, fid(entry), &Opts::DEFAULT, &mut Fuel::unlimited())
        .unwrap_or_else(|e| panic!("the IR of {entry:#x} builds: {e}"))
}

/// Gives the address of the first symbol named `name`.
pub fn named(program: &Program, name: &str) -> u64 {
    program
        .addrs_named(name)
        .first()
        .map_or_else(|| panic!("the program names {name}"), |a| a.off)
}

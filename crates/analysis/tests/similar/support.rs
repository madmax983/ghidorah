//! Shared helpers of the similarity tests: fixtures, raw blobs, analysis runs and corpora.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use ghidorah_analysis::similar::{self, Context, Feature, Index, Kind, VectorCache};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, Limits};
use ghidorah_db::Program;
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};

/// The load address of the test blobs.
pub const BASE: u64 = 0x40_0000;

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).expect("the JSON parses")
}

/// Loads `bytes` with `opts` into a program at revision 0.
pub fn program_of(bytes: &[u8], opts: &LoadOpts) -> Program {
    let (binary, mem) = load(bytes, opts, &Limits::DEFAULT).expect("the bytes load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// Runs the analysis of `program` to completion with no fuel limit.
pub fn analyze(program: &mut Program) {
    let mut sched = Scheduler::new();
    let out = sched
        .run(program, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "an unlimited run completes");
}

/// Loads and analyzes a raw blob at [`BASE`] with the entry at the blob offset `entry`.
pub fn blob(bytes: &[u8], entry: u64) -> Program {
    let mut p = program_of(bytes, &LoadOpts::raw(BASE, Some(BASE + entry)));
    analyze(&mut p);
    p
}

/// Gives the analyzed program of the fixture at `path` under the root. The test binary
/// builds each one once.
pub fn fixture(path: &str) -> &'static Program {
    type Cache = Mutex<BTreeMap<String, &'static Program>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut map = cache.lock().expect("the cache lock");
    if let Some(p) = map.get(path) {
        return p;
    }
    let bytes = std::fs::read(root().join(path)).expect("the fixture bytes");
    let mut p = program_of(&bytes, &LoadOpts::AUTO);
    analyze(&mut p);
    let p: &'static Program = Box::leak(Box::new(p));
    map.insert(path.to_owned(), p);
    p
}

/// Gives the function ID at `addr`.
pub const fn fid(addr: u64) -> FuncId {
    FuncId(Address::ram(addr))
}

/// Gives the feature stream of the function at `addr` of `program`.
pub fn stream(program: &Program, addr: u64) -> Vec<Feature> {
    let ctx = Context::new(program);
    similar::features::stream(&ctx, fid(addr), &mut Fuel::unlimited()).expect("the stream")
}

/// Gives the texts of the features of `kind` in stream order.
pub fn texts(features: &[Feature], kind: Kind) -> Vec<String> {
    features
        .iter()
        .filter(|f| f.kind == kind)
        .map(|f| f.text.clone())
        .collect()
}

/// Gives the entry of the function named `name` in `program`.
pub fn entry_of(program: &Program, name: &str) -> u64 {
    program
        .funcs()
        .iter()
        .map(|f| f.id().0)
        .find(|a| program.name(*a).is_some_and(|n| n.text == name))
        .unwrap_or_else(|| panic!("no function {name}"))
        .off
}

/// Gives the corpus index of `programs` with a new cache.
pub fn corpus(programs: &[&Program]) -> Index {
    let mut cache = VectorCache::default();
    similar::corpus(programs, &mut cache, &mut Fuel::unlimited()).expect("the corpus builds")
}

/// The T1 fixtures of the corpus tests: two builds of three programs.
pub const T1: [&str; 6] = [
    "fixtures/bin/loops.gcc-O2",
    "fixtures/bin/loops.clang-O2",
    "fixtures/bin/switch.gcc-O2",
    "fixtures/bin/switch.clang-O2",
    "fixtures/bin/crackme.gcc-O2",
    "fixtures/bin/crackme.gcc-O2.stripped",
];

/// Gives the analyzed programs of [`T1`].
pub fn t1() -> Vec<&'static Program> {
    T1.iter().map(|p| fixture(p)).collect()
}

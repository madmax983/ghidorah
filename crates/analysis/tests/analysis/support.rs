//! Shared helpers of the analysis tests: fixtures, truth files and full runs.

use std::path::PathBuf;

use ghidorah_analysis::analyzers::{refs, strings};
use ghidorah_analysis::{ANALYZERS, AnalyzerSpec, RunOutcome, RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, Limits};
use ghidorah_db::Program;
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::elf::{ElfBuilder, Layout};

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).expect("the JSON parses")
}

/// Gives the paths of the T1 fixtures in manifest order.
pub fn t1_fixtures() -> Vec<String> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    let manifest = json(&text);
    let list = manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures list");
    let paths: Vec<String> = list
        .iter()
        .filter(|f| f.get("tier").and_then(Value::as_str) == Some("T1"))
        .filter_map(|f| f.get("path").and_then(Value::as_str).map(str::to_owned))
        .collect();
    assert!(paths.len() > 100, "the manifest lists the T1 fixtures");
    paths
}

/// Loads `bytes` with `opts` into a program at revision 0.
pub fn program_of(bytes: &[u8], opts: &LoadOpts) -> Program {
    let (binary, mem) = load(bytes, opts, &Limits::DEFAULT).expect("the bytes load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// Loads the fixture at `path` under the root.
pub fn program(path: &str) -> Program {
    let bytes = std::fs::read(root().join(path)).expect("the fixture bytes");
    program_of(&bytes, &LoadOpts::AUTO)
}

/// Runs the analysis of `program` to completion with no fuel limit.
pub fn analyze(program: &mut Program) -> (Scheduler, RunOutcome) {
    let mut sched = Scheduler::new();
    let out = sched
        .run(program, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "an unlimited run completes");
    (sched, out)
}

/// Loads and analyzes the fixture at `path`.
pub fn analyzed(path: &str) -> Program {
    let mut p = program(path);
    let _ = analyze(&mut p);
    p
}

/// Gives every T1 fixture with its full analysis. The test binary builds the list once.
pub fn all_t1() -> &'static [(String, Program)] {
    ghidorah_testkit::fixture::cached("t1-analyzed", || {
        t1_fixtures()
            .into_iter()
            .map(|path| {
                let p = analyzed(&path);
                (path, p)
            })
            .collect::<Vec<_>>()
    })
}

/// Gives the fixture name of a path: the part after `fixtures/bin/`.
pub fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Gives the truth file of a fixture name. A stripped variant uses the truth of its build.
pub fn truth(name: &str) -> Value {
    let build = name.strip_suffix(".stripped").unwrap_or(name);
    let path = root().join(format!("fixtures/truth/{build}.json"));
    let text = std::fs::read_to_string(&path).expect("the truth file");
    json(&text)
}

/// Gives the address of the truth function `name`.
pub fn truth_addr(truth: &Value, name: &str) -> u64 {
    let funcs = truth
        .get("functions")
        .and_then(Value::as_array)
        .expect("truth functions");
    let text = funcs
        .iter()
        .find(|f| f.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|f| f.get("addr"))
        .and_then(Value::as_str)
        .expect("the truth names the function");
    ghidorah_base::hex::parse_u64(text).expect("a hex address")
}

/// Gives the function ID at `addr`.
pub const fn fid(addr: u64) -> FuncId {
    FuncId(Address::ram(addr))
}

/// Gives the address of the first symbol named `name`.
pub fn named(program: &Program, name: &str) -> u64 {
    program
        .addrs_named(name)
        .first()
        .map(|a| a.off)
        .expect("the program names the symbol")
}

/// Gives the shipped analyzers plus the WP-17a analyzers that the list does not hold yet.
pub fn full_list() -> Vec<&'static AnalyzerSpec> {
    let mut list: Vec<&'static AnalyzerSpec> = ANALYZERS.to_vec();
    for spec in [&refs::SPEC, &strings::SPEC] {
        if !list.iter().any(|s| s.id == spec.id) {
            list.push(spec);
        }
    }
    list
}

/// Runs the analysis of `program` over [`full_list`] to completion with no fuel limit.
pub fn analyze_full(program: &mut Program) -> (Scheduler, RunOutcome) {
    let mut sched = Scheduler::with_analyzers(full_list());
    let out = sched
        .run(program, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "an unlimited run completes");
    (sched, out)
}

/// Loads the fixture at `path` and analyzes it over [`full_list`].
pub fn analyzed_full(path: &str) -> Program {
    let mut p = program(path);
    let _ = analyze_full(&mut p);
    p
}

/// Gives every T1 fixture with its analysis over [`full_list`]. The test binary builds the
/// list once.
pub fn all_t1_full() -> &'static [(String, Program)] {
    ghidorah_testkit::fixture::cached("t1-analyzed-full", || {
        t1_fixtures()
            .into_iter()
            .map(|path| {
                let p = analyzed_full(&path);
                (path, p)
            })
            .collect::<Vec<_>>()
    })
}

/// Gives the analyzed program of the T1 fixture `name` from [`all_t1_full`].
pub fn t1_full(name: &str) -> &'static Program {
    all_t1_full()
        .iter()
        .find(|(path, _)| name_of(path) == name)
        .map(|(_, p)| p)
        .expect("the manifest lists the fixture")
}

/// Gives the fixture path and the truth file path of each T1 fixture of the manifest.
pub fn truth_paths() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    let manifest = json(&text);
    manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures list")
        .iter()
        .filter(|f| f.get("tier").and_then(Value::as_str) == Some("T1"))
        .filter_map(|f| {
            let path = f.get("path").and_then(Value::as_str)?;
            let truth = f.get("truth").and_then(Value::as_str)?;
            Some((path.to_owned(), truth.to_owned()))
        })
        .collect()
}

/// Reads the JSON file at `path` under the root.
pub fn json_at(path: &str) -> Value {
    let text = std::fs::read_to_string(root().join(path)).expect("the JSON file");
    json(&text)
}

/// Builds an ELF file with `builder` and loads it.
pub fn built(builder: &ElfBuilder) -> (Program, Layout) {
    let (bytes, layout) = builder.build_with_layout();
    (program_of(&bytes, &LoadOpts::AUTO), layout)
}

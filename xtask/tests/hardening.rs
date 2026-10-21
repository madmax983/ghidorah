//! The hardening gates of WP-27: the hermetic run, the time caps, the `fix:` commit rule, the
//! long fuzz driver and the benchmark report (design Sections 13.5, 13.10 and 13.11).

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]

use std::path::{Path, PathBuf};

use ghidorah_testkit::bench::Stats;
use ghidorah_testkit::fuzz::{self as tkfuzz, Outcome};
use std::sync::{Mutex, MutexGuard, PoisonError};
use xtask::bench::{self, BENCHES, Unit};
use xtask::ci::{self, Step, TestTime};
use xtask::fuzz::{self, TARGETS};
use xtask::json::{self, Value};
use xtask::workspace;

/// Serializes the tests that write a program and start child processes.
///
/// A fork in one test thread copies the open write handle of a script that another
/// thread writes. An exec of that script then fails with "Text file busy" (ETXTBSY).
static PROCESS_LOCK: Mutex<()> = Mutex::new(());

/// Takes [`PROCESS_LOCK`]. A test that panics with the lock does not block the others.
fn process_lock() -> MutexGuard<'static, ()> {
    PROCESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// Gives a new empty directory for one test.
fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("hardening")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

#[test]
fn ac_020_hermetic_env() {
    assert_eq!(Step::parse("test_hermetic"), Some(Step::TestHermetic));
    assert!(Step::DEFAULT.contains(&Step::TestHermetic));
    let env = ci::hermetic_env(
        Path::new("/tc/bin"),
        Path::new("/empty/home"),
        Path::new("/empty/cargo"),
    );
    let get = |key: &str| {
        env.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .expect("the variable has a change")
    };
    assert_eq!(get("PATH"), Some("/tc/bin".into()));
    assert_eq!(get("HOME"), Some("/empty/home".into()));
    assert_eq!(
        get("XDG_DATA_HOME"),
        Some("/empty/home/.local/share".into())
    );
    assert_eq!(get("CARGO_HOME"), Some("/empty/cargo".into()));
    assert!(!ci::REMOVED_VARS.contains(&"CARGO_HOME"));
    for var in [
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "CARGO",
        "RUSTUP_TOOLCHAIN",
    ] {
        assert!(ci::REMOVED_VARS.contains(&var), "{var} is removed");
        assert_eq!(get(var), None, "{var} is removed");
    }
}

#[test]
fn hermetic_test_binaries() {
    let _lock = process_lock();
    let lines = [
        r#"{"reason":"compiler-artifact","package_id":"path+file:///w/crates/json#ghidorah-json@0.1.0","manifest_path":"/w/crates/json/Cargo.toml","target":{"kind":["test"],"name":"parse"},"profile":{"test":true},"executable":"/w/target/debug/deps/parse-1"}"#,
        r#"{"reason":"compiler-artifact","manifest_path":"/w/crates/json/Cargo.toml","target":{"kind":["lib"],"name":"ghidorah_json"},"profile":{"test":false},"executable":null}"#,
        r#"{"reason":"compiler-artifact","manifest_path":"/w/xtask/Cargo.toml","target":{"kind":["bin"],"name":"xtask"},"profile":{"test":true},"executable":"/w/target/debug/deps/xtask-2"}"#,
        r#"{"reason":"compiler-artifact","manifest_path":"/w/xtask/Cargo.toml","target":{"kind":["bin"],"name":"xtask"},"profile":{"test":false},"executable":"/w/target/debug/xtask"}"#,
        r#"{"reason":"build-finished","success":true}"#,
        "not json",
    ];
    let found = ci::test_binaries(&lines.join("\n"));
    let pairs: Vec<(String, String)> = found
        .iter()
        .map(|b| (b.exe.display().to_string(), b.dir.display().to_string()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            (
                "/w/target/debug/deps/parse-1".to_owned(),
                "/w/crates/json".to_owned()
            ),
            (
                "/w/target/debug/deps/xtask-2".to_owned(),
                "/w/xtask".to_owned()
            ),
        ]
    );
}

/// Tells if `path` or one of its parent directories holds `.git`.
fn in_git_tree(path: &Path) -> bool {
    path.ancestors().any(|dir| dir.join(".git").exists())
}

/// Writes the shell script `name` with `body` into `dir` and gives it as a test binary.
fn script(dir: &Path, name: &str, body: &str) -> ci::TestBinary {
    use std::os::unix::fs::PermissionsExt as _;
    let exe = dir.join(name);
    std::fs::write(&exe, format!("#!/bin/sh\n{body}\n")).expect("the script is written");
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755))
        .expect("the script is executable");
    ci::TestBinary {
        exe,
        dir: dir.to_path_buf(),
    }
}

/// The HOME of the hermetic run is outside every git work tree, so the default projects root
/// of a spawned `ghidorah` is valid there. The step fails when a binary writes under HOME.
#[test]
fn regress_hermetic_home_outside_git_tree() {
    let _lock = process_lock();
    let dir = tmp("hermetic_home");
    let seen = dir.join("seen.txt");
    // The reduced PATH has no `mkdir`, so the scripts use shell built-ins only.
    let probe = script(
        &dir,
        "probe.sh",
        &format!(
            "echo \"$HOME $XDG_DATA_HOME $CARGO_HOME\" > '{}'",
            seen.display()
        ),
    );
    let leak = script(&dir, "leak.sh", ": > \"$HOME/leak\"");
    // A write to CARGO_HOME is the cache of `cargo`, so the step accepts it.
    let cargo = script(&dir, "cargo.sh", ": > \"$CARGO_HOME/cache\"");
    let toolchain = Path::new("/no/toolchain/bin");

    let run = ci::run_binaries(&[probe.clone(), cargo], toolchain).expect("the run starts");
    assert_eq!(run.binaries, 2);
    assert!(run.failed.is_empty(), "{:?}", run.failed);
    let text = std::fs::read_to_string(&seen).expect("the probe runs");
    let [home, data, cargo_home]: [&str; 3] = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .try_into()
        .expect("HOME, XDG_DATA_HOME and CARGO_HOME");
    let home = Path::new(home);
    assert!(home.starts_with(std::env::temp_dir()), "{}", home.display());
    assert!(!in_git_tree(home), "{} is in a git tree", home.display());
    assert!(Path::new(data).starts_with(home), "{data}");
    assert!(!Path::new(cargo_home).starts_with(home), "{cargo_home}");
    assert!(!home.exists(), "the step removes its empty HOME");

    let run = ci::run_binaries(&[leak, probe], toolchain).expect("the run starts");
    let names: Vec<&str> = run.failed.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["leak.sh"], "{:?}", run.failed);
    assert!(run.failed[0].1.contains("leak"), "{:?}", run.failed);
}

/// `xtask eval replay` gives the server a project root, so a replay writes nothing under HOME.
#[test]
fn regress_eval_replay_names_project_root() {
    let projects = tmp("eval_replay_projects");
    let cmd = xtask::eval::replay_command(&workspace::root(), &projects);
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let at = args
        .iter()
        .position(|a| a == "--project-root")
        .expect("the replay names a project root");
    assert_eq!(
        args.get(at + 1).map(String::as_str),
        Some(projects.to_string_lossy().as_ref())
    );
    assert!(args.iter().any(|a| a == "mcp"), "{args:?}");
}

#[test]
fn ac_021_tier1_cap() {
    assert_eq!(ci::TIER1_CAP_SECS, 120);
    assert!(ci::tier1_within_cap(0));
    assert!(ci::tier1_within_cap(120_000));
    assert!(!ci::tier1_within_cap(120_001));
    // A run that fails early is fast, but it does not finish tier 1.
    assert!(ci::tier1_ok(true, 120_000));
    assert!(
        !ci::tier1_ok(false, 1_000),
        "a failed run is not within the cap"
    );
    assert!(!ci::tier1_ok(true, 120_001));
    assert!(!ci::tier1_ok(false, 120_001));
}

#[test]
fn ac_224_test_times() {
    let lines: Vec<(u64, String)> = [
        (0, "running 3 tests"),
        (1_000, "test a::fast ... ok"),
        (17_500, "test a::slow ... ok"),
        (17_600, "test a::skip ... ignored, tier2"),
        (17_700, "test result: ok. 2 passed; 0 failed; 1 ignored"),
        (20_000, "running 1 test"),
        (36_000, "test b::slower ... ok"),
    ]
    .iter()
    .map(|(at, line)| (*at, (*line).to_owned()))
    .collect();
    let times = ci::parse_test_times(&lines);
    assert_eq!(times.len(), 4);
    let over: Vec<&str> = ci::over_cap(&times)
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    assert_eq!(over, vec!["a::slow", "b::slower"], "slowest first");
    let at_cap = TestTime {
        binary: 0,
        name: "c::edge".to_owned(),
        ms: ci::TEST_CAP_MS,
        ok: true,
        ignored: false,
    };
    assert!(ci::over_cap(&[at_cap]).is_empty(), "the cap itself passes");
    // The second binary has no summary line, so one timed test has no count.
    assert_eq!(ci::summary_ran(&lines), 2);
    assert!(!ci::each_reported(&times, &lines));
    check_each_reported();
}

fn timed(lines: &[(u64, &str)]) -> Vec<(u64, String)> {
    lines
        .iter()
        .map(|(at, line)| (*at, (*line).to_owned()))
        .collect()
}

/// Checks that `each_reported` needs a time for each test that libtest counts (AC-224).
fn check_each_reported() {
    let complete = timed(&[
        (0, "running 4 tests"),
        (10, "test a::one ... ok"),
        (20, "test a::two ... FAILED"),
        (30, "test a::three ... ignored, tier2"),
        (40, "test a::four ... ok"),
        (
            50,
            "test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out",
        ),
        (60, "running 1 test"),
        (70, "test crates/x/src/lib.rs - f (line 3) ... ok"),
        (
            80,
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        ),
    ]);
    let times = ci::parse_test_times(&complete);
    assert_eq!(times.len(), 5);
    assert_eq!(ci::summary_ran(&complete), 4);
    assert!(ci::each_reported(&times, &complete));
    // One result line has no time entry: the test prints over its own result line.
    let mut garbled = complete;
    garbled[4] = (40, "noise from a child process ok".to_owned());
    let times = ci::parse_test_times(&garbled);
    assert_eq!(times.len(), 4);
    assert!(
        !ci::each_reported(&times, &garbled),
        "a test without a time"
    );
    // A run with no tests reports no time.
    let empty = timed(&[
        (0, "running 0 tests"),
        (1, "test result: ok. 0 passed; 0 failed"),
    ]);
    assert!(!ci::each_reported(&ci::parse_test_times(&empty), &empty));
}

#[test]
fn ac_234_fix_commits_change_tests() {
    assert_eq!(Step::parse("fix_commits"), Some(Step::FixCommits));
    assert!(Step::DEFAULT.contains(&Step::FixCommits));
    for (path, test) in [
        ("crates/json/tests/parse.rs", true),
        ("crates/db/src/edit/tests.rs", true),
        ("crates/db/src/edit/tests/funcs.rs", true),
        ("xtask/tests/gates.rs", true),
        ("tests/golden/tools.json", false),
        ("tests/regress/calc/0a1b2c3d.bin", false),
        ("crates/cli/tests/data/x.json", false),
        ("crates/json/src/parse.rs", false),
        ("docs/design.md", false),
        ("crates/testkit/src/tests_helper.rs", false),
    ] {
        assert_eq!(ci::is_test_file(path), test, "{path}");
    }
    let log = "\
@@aaaa111 fix: the parser keeps the offset
crates/json/src/parse.rs
crates/json/tests/parse.rs

@@bbbb222 fix: a bad commit with code only
crates/json/src/parse.rs

@@cccc333 green(WP-04): code only is fine here
crates/json/src/value.rs

@@dddd444 fix: an empty commit

@@eeee555 refactor: fix: in the middle is no fix commit
crates/json/src/write.rs
";
    assert_eq!(ci::fix_commit_count(log), 3);
    assert_eq!(
        ci::fix_commits_without_tests(log),
        vec![
            "bbbb222 fix: a bad commit with code only".to_owned(),
            "dddd444 fix: an empty commit".to_owned(),
        ]
    );
    assert_eq!(ci::LOG_FORMAT, "@@%h %s");
}

/// A golden or a data file under `tests` is not a test: a fix needs a `.rs` test change.
#[test]
fn regress_fix_commit_needs_rs_test() {
    let log = "\
@@ffff666 fix: the loader reads the flags
crates/loader/src/elf.rs
tests/golden/loader/x.readelf.txt

@@abab777 fix: the loader reads the notes
crates/loader/src/elf.rs
crates/loader/tests/elf.rs
tests/golden/loader/x.readelf.txt
";
    assert_eq!(
        ci::fix_commits_without_tests(log),
        vec!["ffff666 fix: the loader reads the flags".to_owned()]
    );
    assert!(!ci::is_test_file("tests/golden/loader/x.readelf.txt"));
    assert!(!ci::is_test_file("crates/x/tests.rs.orig"));
    assert!(ci::is_test_file("crates/x/src/tests.rs"));
}

/// The fuzz targets of design Section 13.5 in the order of the text.
const SECTION_13_5: [&str; 17] = [
    "elf_load",
    "x86_decode",
    "eh_frame",
    "cparse",
    "json_parse",
    "addr_expr",
    "calc",
    "cursor_decode",
    "mcp_line",
    "batch_parse",
    "pe_load",
    "x86_lift_interp",
    "journal_replay",
    "snapshot_load",
    "project_json",
    "pipeline_raw",
    "pipeline_elf",
];

#[test]
fn ac_190a_parser_targets() {
    let names: Vec<&str> = TARGETS.iter().map(|t| t.name).collect();
    assert_eq!(names, SECTION_13_5);
    for t in TARGETS {
        let min = if t.name == "pe_load" { 10_000 } else { 2_000 };
        assert_eq!(t.cases, min, "{}", t.name);
        assert!(
            workspace::PACKAGES
                .iter()
                .any(|p| (p.dir, p.name) == (t.dir, t.package)),
            "{} names a workspace package",
            t.name
        );
    }
    let findings = fuzz::check_targets(&workspace::root());
    assert!(findings.is_empty(), "{findings:#?}");
    let target = TARGETS
        .iter()
        .find(|t| t.name == "calc")
        .expect("the calc target");
    let good = r#"
        fn regress_dir() -> PathBuf { root.join("tests/regress/calc") }
        #[test]
        fn fuzz_calc() {
            let replay = fuzz::replay_regress(&regress_dir(), run);
            let mut config = Config::new("calc", 2_000);
        }
    "#;
    assert!(fuzz::source_problems(target, good).is_empty());
    let two = format!("{good}\n#[test]\nfn other() {{}}");
    assert_eq!(fuzz::source_problems(target, &two).len(), 1, "two tests");
    let few = good.replace("2_000", "600");
    assert_eq!(
        fuzz::source_problems(target, &few).len(),
        1,
        "too few cases"
    );
    let no_replay = good.replace("replay_regress", "replay");
    assert_eq!(fuzz::source_problems(target, &no_replay).len(), 1);
    let renamed = good.replace("fn fuzz_calc", "fn fuzz_other");
    assert_eq!(fuzz::source_problems(target, &renamed).len(), 1);
}

#[test]
fn ac_190b_long_runs() {
    let default = fuzz::parse_args(&[]).expect("empty args parse");
    assert_eq!(default.iters, fuzz::DEFAULT_ITERS);
    assert_eq!(default.iters, 100_000);
    assert_eq!(default.targets.len(), TARGETS.len());
    let picked = fuzz::parse_args(&strings(&[
        "calc",
        "--iters",
        "4000",
        "--seed",
        "7",
        "--timeout",
        "60",
    ]))
    .expect("args parse");
    assert_eq!(picked.targets.len(), 1);
    assert_eq!(
        (picked.iters, picked.seed, picked.timeout_secs),
        (4_000, 7, 60)
    );
    assert!(fuzz::parse_args(&strings(&["nope"])).is_err());
    assert!(fuzz::parse_args(&strings(&["--iters", "x"])).is_err());
    assert!(fuzz::parse_args(&strings(&["--bad"])).is_err());
    assert_eq!(fuzz::batches(100_000, 2_000), 50);
    assert_eq!(fuzz::batches(100_000, 10_000), 10);
    assert_eq!(fuzz::batches(100_001, 2_000), 51);
    assert_eq!(fuzz::batches(0, 2_000), 0);
    assert_eq!(fuzz::batches(5, 0), 0);
    let seeds: std::collections::BTreeSet<u64> = (0..50).map(|b| fuzz::batch_seed(9, b)).collect();
    assert_eq!(seeds.len(), 50, "each batch has its own seed");
    let name = fuzz::regress_name(b"abc");
    assert_eq!(
        name, "ba7816bf.bin",
        "the SHA-256 of abc starts with ba7816bf"
    );
    check_batch_rules("long_runs");
}

#[test]
fn collect_moves_failing_inputs() {
    let dir = tmp("collect");
    std::fs::write(dir.join("crash-3.input"), b"abc").expect("write");
    std::fs::write(dir.join("pending.bin"), b"xyz").expect("write");
    std::fs::write(dir.join("keep.bin"), b"old").expect("write");
    let saved = fuzz::collect(&dir).expect("collect");
    assert_eq!(saved.len(), 2, "{saved:?}");
    assert!(saved.contains(&"ba7816bf.bin".to_owned()), "{saved:?}");
    assert!(!dir.join("crash-3.input").exists());
    assert!(!dir.join("pending.bin").exists());
    assert_eq!(
        std::fs::read(dir.join("ba7816bf.bin")).expect("read"),
        b"abc"
    );
    assert!(dir.join("keep.bin").exists());
    assert!(
        fuzz::collect(&dir.join("missing"))
            .expect("no dir")
            .is_empty()
    );
}

/// The first full `xtask fuzz` run gave 9 violations with no saved input and no hang. A stage
/// share assertion of the test failed for some batch seeds. No case failed.
#[test]
fn regress_fuzz_stage_miss_is_not_violation() {
    use fuzz::{End, Verdict, classify};
    let all = Some(2_000);
    assert_eq!(classify(End::Pass, false, all, 2_000), Verdict::Pass);
    assert_eq!(
        classify(End::Fail { signal: false }, false, all, 2_000),
        Verdict::StageMiss
    );
    assert_eq!(
        classify(End::Fail { signal: false }, true, all, 2_000),
        Verdict::Violation
    );
    assert_eq!(
        classify(End::Fail { signal: true }, false, all, 2_000),
        Verdict::Violation
    );
    assert_eq!(classify(End::Hang, false, all, 2_000), Verdict::Violation);
    assert_eq!(classify(End::Pass, true, all, 2_000), Verdict::Violation);
}

/// A batch that fails before its cases runs no case. Its exit code alone looked like a stage
/// miss, so a run with no passed case gave no violation (AC-190b).
#[test]
fn regress_fuzz_short_batch_is_violation() {
    check_batch_rules("regress");
}

/// Checks the verdict of each batch, the passed-case sum and the `ok` rule of `xtask fuzz`.
///
/// `tag` names the temp directory of the caller, so two tests do not share it.
fn check_batch_rules(tag: &str) {
    use fuzz::{End, Tally, Verdict, classify};
    let fail = End::Fail { signal: false };
    // A failed replay or a harness error ends the batch before the report.
    assert_eq!(classify(fail, false, None, 2_000), Verdict::Violation);
    assert_eq!(classify(fail, false, Some(0), 2_000), Verdict::Violation);
    assert_eq!(classify(End::Pass, false, None, 2_000), Verdict::Violation);
    assert_eq!(
        classify(End::Pass, false, Some(1_999), 2_000),
        Verdict::Violation
    );
    assert_eq!(
        classify(End::Pass, false, Some(2_500), 2_000),
        Verdict::Pass
    );
    assert!(fuzz::ran_all(Some(2_000), 2_000) && !fuzz::ran_all(None, 0));
    let mut tally = Tally::default();
    tally.add(End::Pass, Vec::new(), Some(2_000), 2_000);
    tally.add(fail, Vec::new(), Some(2_000), 2_000);
    tally.add(fail, Vec::new(), None, 2_000);
    tally.add(End::Pass, Vec::new(), Some(10), 2_000);
    tally.add(End::Hang, Vec::new(), None, 2_000);
    tally.add(fail, vec!["ba7816bf.bin".to_owned()], Some(1_999), 2_000);
    let got = (
        tally.batches,
        tally.passed_cases,
        tally.short,
        tally.failed,
        tally.hangs,
        tally.stage_misses,
    );
    assert_eq!(got, (6, 6_009, 4, 4, 1, 1));
    let row = tally.to_json(2_000);
    assert_eq!(row.get("passed_cases").and_then(Value::as_u64), Some(6_009));
    assert_eq!(row.get("cases").and_then(Value::as_u64), Some(12_000));
    assert_eq!(row.get("short").and_then(Value::as_u64), Some(4));
    // `ok` needs `iters` passed cases for each target.
    assert!(fuzz::enough_cases(&[4_000, 100_000], 4_000));
    assert!(!fuzz::enough_cases(&[4_000, 3_999], 4_000));
    assert!(!fuzz::enough_cases(&[], 4_000));
    // The harness reports the cases with no panic and no violation.
    let report = tkfuzz::Report {
        cases: 10,
        panics: 1,
        violations: 2,
        ..tkfuzz::Report::default()
    };
    assert_eq!(tkfuzz::passed_cases(&report), 7);
    let dir = tmp(&format!("fuzz_report_{tag}"));
    let file = dir.join("calc.passed");
    assert_eq!(fuzz::read_passed(&file), None);
    std::fs::write(&file, "2000\n").expect("write");
    assert_eq!(fuzz::read_passed(&file), Some(2_000));
    std::fs::write(&file, "x").expect("write");
    assert_eq!(fuzz::read_passed(&file), None);
}

#[test]
fn long_run_hooks() {
    assert_eq!(tkfuzz::SEED_ENV, "FUZZ_SEED");
    assert_eq!(tkfuzz::batch_seed(41, None), 41);
    let a = tkfuzz::batch_seed(41, Some(1));
    let b = tkfuzz::batch_seed(41, Some(2));
    assert!(a != 41 && b != 41 && a != b, "a batch changes the seed");
    assert_eq!(tkfuzz::crash_name(12), "crash-12.input");
    // The target fails on any input with a 0x7f byte.
    let target = |input: &[u8]| {
        if input.contains(&0x7f) {
            Outcome::violation(1, "has 0x7f".to_owned())
        } else {
            Outcome::reached(1)
        }
    };
    let input = [1, 2, 3, 0x7f, 5, 6, 7, 8, 9];
    assert_eq!(tkfuzz::shrink_input(&input, &target, 500), vec![0x7f]);
    let fine = [1, 2, 3];
    assert_eq!(tkfuzz::shrink_input(&fine, &target, 500), fine.to_vec());
}

#[test]
fn ac_171_cold_start_request() {
    let keys: Vec<&str> = BENCHES.iter().map(|b| b.key).collect();
    assert_eq!(
        keys,
        [
            "cold_start_ms",
            "call_overhead_us",
            "decode_us",
            "load_ms",
            "analysis_t2_ms"
        ]
    );
    let line = bench::discover_line(1);
    let request = json::parse(&line).expect("the request parses");
    assert_eq!(
        request.get("method").and_then(Value::as_str),
        Some("server/discover")
    );
    assert_eq!(request.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
    assert_eq!(request.get("id").and_then(Value::as_u64), Some(1));
    assert!(!line.contains('\n'));
}

#[test]
fn ac_202_bench_budgets() {
    let _lock = process_lock();
    let text = std::fs::read_to_string(workspace::root().join(bench::BUDGET_PATH))
        .expect("the budget file");
    let budgets = bench::parse_budget(&text).expect("the budget parses");
    for b in BENCHES {
        assert!(budgets.contains_key(b.key), "{} has a budget", b.key);
    }
    assert_eq!(budgets.get("cold_start_ms"), Some(&100), "AC-171");
    assert!(budgets.contains_key("similar_2k_ms"), "the WP-29 key stays");
    assert!(bench::parse_budget("[1]").is_err());
    assert!(bench::parse_budget(r#"{"a":1.5}"#).is_err());
    assert_eq!(bench::to_unit(1_500_000, Unit::Ms), 2);
    assert_eq!(bench::to_unit(1_000_000, Unit::Ms), 1);
    assert_eq!(bench::to_unit(1_001, Unit::Us), 2);
    let cold = BENCHES.first().expect("a bench");
    let stats = Stats {
        median_ns: 40_000_000,
        mad_ns: 1_000_000,
        runs: 1,
    };
    let pass = bench::verdict(cold, &stats, Some(100));
    assert_eq!(pass.get("median").and_then(Value::as_u64), Some(40));
    assert_eq!(pass.get("mad").and_then(Value::as_u64), Some(1));
    assert_eq!(pass.get("budget").and_then(Value::as_u64), Some(100));
    assert_eq!(pass.get("ok").and_then(Value::as_bool), Some(true));
    let fail = bench::verdict(cold, &stats, Some(39));
    assert_eq!(fail.get("ok").and_then(Value::as_bool), Some(false));
    let none = bench::verdict(cold, &stats, None);
    assert_eq!(none.get("ok").and_then(Value::as_bool), Some(false));
    assert!(bench::run(&workspace::root(), &strings(&["no_such_bench"])).is_err());
}

/// The step reads `git log`, so it runs in tier 2 (the hermetic run has no `git`).
#[test]
#[ignore = "tier2"]
fn ac_234_fix_commits_step() {
    let _lock = process_lock();
    let args = strings(&["--steps", "fix_commits"]);
    let report = ci::run(&workspace::root(), &args).expect("xtask ci runs");
    assert_eq!(
        report.pointer("/steps/fix_commits/ok"),
        Some(&Value::Bool(true)),
        "{report}"
    );
}

/// Two batches of the `calc` target in child processes.
#[test]
#[ignore = "tier2"]
fn ac_190b_fuzz_batches() {
    let _lock = process_lock();
    let args = strings(&["calc", "--iters", "4000", "--seed", "11"]);
    check_batch_rules("batches");
    let report = fuzz::run(&workspace::root(), &args).expect("xtask fuzz runs");
    assert_eq!(
        report.pointer("/violations").and_then(Value::as_u64),
        Some(0),
        "{report}"
    );
    assert_eq!(report.pointer("/ok"), Some(&Value::Bool(true)), "{report}");
    let passed = report.pointer("/passed_cases").and_then(Value::as_u64);
    assert!(passed.is_some_and(|p| p >= 4_000), "{report}");
    assert_eq!(
        report
            .pointer("/targets/calc/short")
            .and_then(Value::as_u64),
        Some(0),
        "{report}"
    );
    assert_eq!(
        report
            .pointer("/targets/calc/batches")
            .and_then(Value::as_u64),
        Some(2),
        "{report}"
    );
}

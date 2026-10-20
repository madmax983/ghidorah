//! Unit tests of the xtask helpers: JSON, the Rust lexer, `ci`, `cov` and `ac` parsing.

use std::path::{Path, PathBuf};

use xtask::ac::{self, Evidence, Op, Tier};
use xtask::acrun::{self, Status};
use xtask::ci::{self, Step};
use xtask::cov::{self, Counts, Coverage};
use xtask::json::{self, MAX_DEPTH, Value};
use xtask::rustsrc;

#[test]
fn json_round_trip() {
    let text = r#"{"a":[1,-2.5e3,true,false,null],"b":"x\"y\\z\n\u0001é","c":{}}"#;
    let value = json::parse(text).expect("valid JSON parses");
    let again = json::parse(&json::write(&value)).expect("written JSON parses");
    assert_eq!(value, again);
    assert_eq!(
        json::write(&value),
        r#"{"a":[1,-2.5e3,true,false,null],"b":"x\"y\\z\n\u0001é","c":{}}"#
    );
    let sorted = json::parse(r#"{"z":1,"a":2}"#).expect("object parses");
    assert_eq!(json::write(&sorted), r#"{"a":2,"z":1}"#);
}

#[test]
fn json_rejects_bad_text() {
    let bad = [
        "",
        "[1,]",
        "01",
        "1.",
        "\"a\u{1}\"",
        r#""\ud800""#,
        r#"{"a":1,"a":2}"#,
        "[1] x",
        "{'a':1}",
        "tru",
        "-",
        "[1 2]",
        r#""\x""#,
    ];
    for text in bad {
        assert!(json::parse(text).is_err(), "{text:?}");
    }
    let deep_ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    assert!(json::parse(&deep_ok).is_ok());
    let deep_bad = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
    assert!(json::parse(&deep_bad).is_err());
    assert!(json::parse(r#""😀""#).is_ok());
}

#[test]
fn json_accessors_and_pointer() {
    let value = json::parse(r#"{"a":[{"b":7}],"m~n":1,"x/y":2,"big":18446744073709551615,"neg":-1,"f":1.5,"s":"t","t":true}"#)
        .expect("object parses");
    assert_eq!(value.pointer("/a/0/b").and_then(Value::as_u64), Some(7));
    assert_eq!(value.pointer("/m~0n").and_then(Value::as_u64), Some(1));
    assert_eq!(value.pointer("/x~1y").and_then(Value::as_u64), Some(2));
    assert_eq!(value.pointer(""), Some(&value));
    assert_eq!(value.pointer("/a/1"), None);
    assert_eq!(value.pointer("/nope"), None);
    assert_eq!(value.get("big").and_then(Value::as_u64), Some(u64::MAX));
    assert_eq!(value.get("neg").and_then(Value::as_u64), None);
    assert_eq!(value.get("f").and_then(Value::as_u64), None);
    assert_eq!(value.get("f").and_then(Value::as_f64), Some(1.5));
    assert_eq!(value.get("s").and_then(Value::as_str), Some("t"));
    assert_eq!(value.get("t").and_then(Value::as_bool), Some(true));
    assert_eq!(
        value.get("a").and_then(Value::as_array).map(<[Value]>::len),
        Some(1)
    );
    assert_eq!(
        value.as_object().map(std::collections::BTreeMap::len),
        Some(8)
    );
}

#[test]
fn strip_removes_comments_and_literals() {
    let text = "let a = \"x // y\"; // z\nlet b = r#\"q \"r\" s\"#; /* c /* d */ e */ let c = 'x';\nfn f<'a>(v: &'a u8) {}\n";
    let out = rustsrc::strip(text);
    assert_eq!(out.lines().count(), text.lines().count());
    assert!(!out.contains("// z") && !out.contains("q ") && !out.contains(" d "));
    assert!(out.contains("let b = r#\"       \"#;"), "{out}");
    assert!(out.contains("let c = ' ';"), "{out}");
    assert!(out.contains("fn f<'a>(v: &'a u8) {}"), "{out}");
    assert!(out.contains("let a = \"      \";"), "{out}");
    let escaped = rustsrc::strip("let s = \"a\\\"b\"; let t = '\\''; let u = b\"z\";");
    assert_eq!(escaped, "let s = \"    \"; let t = '  '; let u = b\" \";");
}

#[test]
fn find_word_respects_boundaries() {
    let text = "unsafe_code unsafe fn x_unsafe() unsafe";
    assert_eq!(rustsrc::find_word(text, "unsafe"), vec![12, 33]);
    assert_eq!(rustsrc::line_of("a\nb\nc", 4), 3);
    assert_eq!(rustsrc::line_of("a\nb\nc", 0), 1);
}

#[test]
fn ci_args_and_commands() {
    let strings = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let default = ci::parse_args(&[]).expect("empty args parse");
    assert_eq!(default.steps, Step::DEFAULT);
    assert!(!default.tier2);
    let tier2 = ci::parse_args(&strings(&["--tier2"])).expect("--tier2 parses");
    assert!(tier2.tier2 && tier2.steps.contains(&Step::Tier2));
    let picked = ci::parse_args(&strings(&["--steps", "fmt,tier1"])).expect("--steps parses");
    assert_eq!(picked.steps, [Step::Fmt, Step::Tier1]);
    assert!(ci::parse_args(&strings(&["--steps", "nope"])).is_err());
    assert!(ci::parse_args(&strings(&["--bad"])).is_err());
    for step in [
        Step::Fmt,
        Step::Clippy,
        Step::Doc,
        Step::OfflineBuild,
        Step::Tier1,
        Step::Tier2,
        Step::TestTimes,
    ] {
        assert_eq!(Step::parse(step.name()), Some(step));
    }
    let root = Path::new("/w");
    let args = |step: Step| -> Vec<String> {
        ci::command(root, step)
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(args(Step::Fmt), ["fmt", "--all", "--", "--check"]);
    assert!(args(Step::Clippy).ends_with(&strings(&["-D", "warnings"])));
    assert!(args(Step::Tier2).contains(&"--include-ignored".to_owned()));
    assert!(args(Step::TestTimes).contains(&"--test-threads=1".to_owned()));
    // The 15 s cap applies to tier-1 tests, so the timed run never includes tier-2 tests.
    assert!(!args(Step::TestTimes).contains(&"--include-ignored".to_owned()));
    let env = |step: Step, key: &str| -> Option<String> {
        ci::command(root, step)
            .get_envs()
            .find(|(k, _)| *k == key)
            .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
    };
    assert_eq!(
        env(Step::Doc, "RUSTDOCFLAGS").as_deref(),
        Some("-Dwarnings")
    );
    assert_eq!(
        env(Step::Tier1, "GHIDORAH_REQUIRE_PROOFS").as_deref(),
        Some("1")
    );
}

#[test]
fn ci_test_times() {
    let lines: Vec<(u64, String)> = [
        (0, "running 2 tests"),
        (100, "test a ... ok"),
        (350, "test b ... FAILED"),
        (360, ""),
        (370, "test result: FAILED. 1 passed; 1 failed"),
        (500, "running 1 test"),
        (900, "test c ... ignored"),
    ]
    .into_iter()
    .map(|(t, l)| (t, l.to_owned()))
    .collect();
    let times = ci::parse_test_times(&lines);
    assert_eq!(times.len(), 3);
    assert_eq!(
        (
            times[0].binary,
            times[0].name.as_str(),
            times[0].ms,
            times[0].ok
        ),
        (0, "a", 100, true)
    );
    assert_eq!(
        (times[1].name.as_str(), times[1].ms, times[1].ok),
        ("b", 250, false)
    );
    assert_eq!(
        (
            times[2].binary,
            times[2].name.as_str(),
            times[2].ms,
            times[2].ok
        ),
        (1, "c", 400, true)
    );
}

#[test]
fn cov_scope_and_summary() {
    assert_eq!(cov::crate_of("crates/json/src/lib.rs"), Some("json"));
    assert_eq!(cov::crate_of("crates/json/src/value/tests.rs"), None);
    assert_eq!(cov::crate_of("crates/json/tests/roundtrip.rs"), None);
    assert_eq!(cov::crate_of("crates/testkit/src/lib.rs"), None);
    assert_eq!(cov::crate_of("xtask/src/main.rs"), None);
    let export = json::parse(
        r#"{"data":[{"files":[
        {"filename":"/w/crates/json/src/lib.rs","summary":{"lines":{"count":10,"covered":9},"regions":{"count":4,"covered":3}}},
        {"filename":"/w/crates/json/src/parse.rs","summary":{"lines":{"count":10,"covered":10},"regions":{"count":2,"covered":2}}},
        {"filename":"/w/crates/json/src/tests.rs","summary":{"lines":{"count":50,"covered":0},"regions":{"count":5,"covered":0}}},
        {"filename":"/rustc/abc/library/core/src/x.rs","summary":{"lines":{"count":5,"covered":0},"regions":{"count":1,"covered":0}}}
        ]}]}"#,
    )
    .expect("export parses");
    let coverage = cov::summarize(Path::new("/w"), &export).expect("summary works");
    let json_counts = coverage
        .crates
        .get("json")
        .copied()
        .expect("json is measured");
    assert_eq!((json_counts.lines, json_counts.covered), (20, 19));
    assert_eq!((json_counts.regions, json_counts.regions_covered), (6, 5));
    assert_eq!(coverage.crates.len(), 1);
    let report = cov::gate(&coverage);
    assert_eq!(
        report
            .pointer("/crates/json/percent_x100")
            .and_then(Value::as_u64),
        Some(9500)
    );
    assert_eq!(report.get("ok"), Some(&Value::Bool(true)));
}

#[test]
fn cov_test_objects() {
    let lines = [
        r#"{"reason":"compiler-artifact","executable":"/t/deps/gates-1","profile":{"test":true},"target":{"kind":["test"],"name":"gates"}}"#,
        r#"{"reason":"compiler-artifact","executable":null,"profile":{"test":false},"target":{"kind":["lib"],"name":"x"}}"#,
        r#"{"reason":"compiler-artifact","executable":"/t/ghidorah","profile":{"test":false},"target":{"kind":["bin"],"name":"ghidorah"}}"#,
        r#"{"reason":"build-finished","success":true}"#,
    ]
    .join("\n");
    assert_eq!(
        cov::test_objects(&lines),
        [
            PathBuf::from("/t/deps/gates-1"),
            PathBuf::from("/t/ghidorah")
        ]
    );
}

#[test]
fn ac_evidence_grammar() {
    assert_eq!(
        ac::parse_evidence("test:xtask::ac_001a_workspace_packages@T1"),
        Ok(Evidence::Test {
            krate: "xtask".to_owned(),
            func: "ac_001a_workspace_packages".to_owned(),
            tier: Tier::T1,
        })
    );
    assert_eq!(
        ac::parse_evidence("xtask:ci#/steps/tier1/seconds <= 120"),
        Ok(Evidence::Xtask {
            sub: "ci".to_owned(),
            pointer: "/steps/tier1/seconds".to_owned(),
            op: Op::Le,
            value: "120".to_owned(),
        })
    );
    assert_eq!(
        ac::parse_evidence("record:verify/results.json#/kernels/K1@sha256=tree"),
        Ok(Evidence::Record {
            file: "verify/results.json".to_owned(),
            pointer: "/kernels/K1".to_owned(),
            input: "tree".to_owned(),
        })
    );
    assert_eq!(
        ac::parse_evidence("cmd:cargo fmt --all --check"),
        Ok(Evidence::Cmd {
            argv: "cargo fmt --all --check".to_owned()
        })
    );
    let bad = [
        "test:xtask::f",
        "test:xtask::f@T3",
        "test:f@T1",
        "xtask:ci#/steps/x/ok",
        "xtask:ci /x == 1",
        "cmd:",
        "record:f#/p",
        "foo:bar",
    ];
    for text in bad {
        assert!(ac::parse_evidence(text).is_err(), "{text}");
    }
}

#[test]
fn ac_rows_parse() {
    let text = "\
| AC | Statement | Evidence | Closes | Needs |
|---|---|---|---|---|
| AC-001a | One. | `test:xtask::ac_001a_x@T1` | 01 | - |
| AC-002 | Two. | `test:tools::ac_002_a@T1` (T1), `test:tools::ac_002_b@T2` (all) | 13a/25 | 24 |
| AC-063b | Moved to stretch S10 (`insn_fields`). | - | - | - |
| AC-099 | No evidence. | - | 05 | - |
| AC-100 | Bad. | `test:nope` | 05 | - |
| AC-015a | Removed in revision 3 (line counts are information only, ADR-0018). | - | - | - |
";
    let (rows, findings) = ac::parse_rows(text);
    assert_eq!(rows.len(), 6);
    assert!(rows[5].removed && !rows[5].stretch && !rows[5].is_gate());
    assert!(rows[2].stretch && !rows[2].removed && !rows[2].is_gate());
    assert!(rows[0].is_gate());
    assert_eq!(rows[1].evidence.len(), 2);
    assert_eq!(rows[1].closes, ["13a", "25"]);
    assert_eq!(rows[1].needs, ["24"]);
    assert!(rows[2].stretch);
    assert_eq!(rows[0].line, 3);
    assert_eq!(findings.len(), 1);
    assert_eq!(ac::missing(&rows), ["AC-099", "AC-100"]);
    let design = std::fs::read_to_string(xtask::workspace::root().join(ac::DESIGN_PATH))
        .expect("design reads");
    let (rows, findings) = ac::parse_rows(&design);
    assert!(rows.len() >= 300, "{}", rows.len());
    assert!(findings.is_empty(), "{findings:?}");
}

/// A `test:` item names a test with an AC name, a fuzz name or a regression name (CLAUDE.md).
#[test]
fn regress_evidence_test_names() {
    let text = "\
| AC-001a | One. | `test:xtask::ac_001a_x@T1`, `test:xtask::ac_001_y@T2` | 01 | - |
| AC-002 | Two. | `test:<crate>::fuzz_<target>@T1`, `test:x86::regress_z@T1` | 01 | - |
| AC-003 | Bad. | `test:kernel::k1_reader_boundaries@T1` | 03 | - |
| AC-004 | Bad. | `test:tools::ac_4_short@T1`, `test:tools::acx_001_y@T1` | 13a | - |
";
    let (rows, findings) = ac::parse_rows(text);
    assert_eq!(rows.len(), 4);
    let lines: Vec<usize> = findings.iter().map(|f| f.line).collect();
    assert_eq!(lines, [3, 4, 4], "{findings:?}");
    assert!(findings.iter().all(|f| f.rule == "AC-018a"), "{findings:?}");
    assert!(
        findings
            .first()
            .is_some_and(|f| f.detail.contains("k1_reader_boundaries")),
        "{findings:?}"
    );
    assert_eq!(rows[2].evidence.len(), 1);
}

/// Gives the test items of one AC row of the design as `<crate>::<fn>@<tier>` texts.
fn design_tests(rows: &[ac::AcRow], id: &str) -> Vec<String> {
    rows.iter()
        .filter(|r| r.id == id)
        .flat_map(|r| &r.evidence)
        .filter_map(|item| match item {
            Evidence::Test { krate, func, tier } => Some(format!("{krate}::{func}@{tier:?}")),
            _ => None,
        })
        .collect()
}

/// A registry-wide AC names the tests of the shipped registry, not only the tests of the
/// 5-tool test registry. AC-112a names its gcc and clang oracle, and AC-066 names libc.
#[test]
fn regress_registry_ac_evidence() {
    let design = std::fs::read_to_string(xtask::workspace::root().join(ac::DESIGN_PATH))
        .expect("design reads");
    let (rows, findings) = ac::parse_rows(&design);
    assert!(findings.is_empty(), "{findings:?}");
    let full = "tools::ac_132a_137_143_full_registry_examples@T1";
    for (id, wanted) in [
        ("AC-132a", full),
        ("AC-137", full),
        ("AC-143", full),
        ("AC-132a", "tools::examples_on_demo@T1"),
        ("AC-132a", "tools::read_examples_on_demo@T1"),
        ("AC-132a", "tools::batch_examples_on_demo@T1"),
        ("AC-132b", "tools::ac_132b_full_argument_coverage@T1"),
        ("AC-221", "tools::ac_221_full_selector_rules@T1"),
        ("AC-112a", "types::ac_112a_layout_oracle_gcc_clang@T2"),
    ] {
        let tests = design_tests(&rows, id);
        assert!(tests.iter().any(|t| t == wanted), "{id}: {tests:?}");
    }
    let libc = rows.iter().find(|r| r.id == "AC-066").is_some_and(|r| {
        r.evidence.contains(&Evidence::Record {
            file: "verify/oracle-results.json".to_owned(),
            pointer: "/libc".to_owned(),
            input: "host-libc".to_owned(),
        })
    });
    assert!(libc, "AC-066 names the libc record");
    // Each name exception has a reason, breaks the name rule and names a test item of the design.
    for (krate, func, reason) in ac::TEST_NAME_EXCEPTIONS {
        assert!(!reason.trim().is_empty(), "{func}");
        assert!(
            !ac::is_evidence_test_name(func),
            "{func} needs no exception"
        );
        assert!(ac::is_listed_exception(krate, func));
        let used = rows.iter().flat_map(|r| &r.evidence).any(|item| {
            matches!(item, Evidence::Test { krate: k, func: f, .. } if k == krate && f == func)
        });
        assert!(used, "the exception {krate}::{func} names no evidence item");
    }
    assert!(!ac::is_listed_exception("kernel", "examples_on_demo"));
}

#[test]
fn acrun_compare_and_statuses() {
    let num = |n: &str| Value::Number(n.to_owned());
    assert!(acrun::compare(&Value::Bool(true), Op::Eq, "true"));
    assert!(!acrun::compare(&Value::Bool(false), Op::Eq, "true"));
    assert!(acrun::compare(&num("100"), Op::Le, "120"));
    assert!(!acrun::compare(&num("130"), Op::Le, "120"));
    assert!(acrun::compare(&num("0.5"), Op::Lt, "1"));
    assert!(acrun::compare(&Value::Array(Vec::new()), Op::Eq, "[]"));
    assert!(acrun::compare(&num("3"), Op::Ne, "4"));
    assert!(!acrun::compare(&Value::from("x"), Op::Lt, "1"));
    let out = "test gates::a ... ok\ntest b ... FAILED\ntest c ... ignored, tier2\n";
    assert_eq!(
        acrun::test_statuses(out, &["a", "b", "c", "d"]),
        [Status::Pass, Status::Fail, Status::Skipped, Status::Fail]
    );
}

#[test]
fn regress_nested_std_group() {
    let rel = "crates/json/src/lib.rs";
    let text = "use std::{collections::{BTreeMap, BTreeSet}, env};\n";
    assert_eq!(xtask::scan::layering(rel, text).len(), 1);
    let clean = "use std::{collections::{BTreeMap}, fmt};\n";
    assert!(xtask::scan::layering(rel, clean).is_empty());
}

/// An `xtask:` item runs the xtask command, not the binary of the caller.
///
/// A cargo step in a tier-2 run builds `target/debug/xtask` again, and in a test the caller
/// is the test binary. In both cases the path of the running binary is not the xtask binary.
#[test]
fn regress_xtask_evidence_runs_the_xtask_command() {
    let row = ac::AcRow {
        id: "AC-900".to_owned(),
        line: 1,
        stretch: false,
        removed: false,
        evidence: vec![Evidence::Xtask {
            sub: "ac".to_owned(),
            pointer: "/acs".to_owned(),
            op: Op::Ge,
            value: "300".to_owned(),
        }],
        closes: vec!["01".to_owned()],
        needs: Vec::new(),
    };
    let outcomes = acrun::run_rows(&xtask::workspace::root(), &[row], true).expect("the item runs");
    let statuses: Vec<Status> = outcomes.iter().map(|o| o.status).collect();
    assert_eq!(statuses, [Status::Pass]);
}

#[test]
fn regress_coverage_takes_the_best_copy_of_each_line() {
    // Two test binaries link the same kernel file. Only the second one runs line 3.
    let first = "SF:/w/crates/kernel/src/reader.rs\nDA:1,4\nDA:2,4\nDA:3,0\nend_of_record\n";
    let second = "SF:/w/crates/kernel/src/reader.rs\nDA:1,0\nDA:3,7\nend_of_record\n\
                  SF:/w/crates/json/src/lib.rs\nDA:9,1\nDA:9,0\nend_of_record\n";
    let mut hits = cov::parse_lcov(first);
    cov::combine(&mut hits, cov::parse_lcov(second));
    let kernel = hits
        .get("/w/crates/kernel/src/reader.rs")
        .expect("kernel file");
    assert_eq!(kernel.get(&1), Some(&4));
    assert_eq!(kernel.get(&3), Some(&7));
    assert_eq!(
        hits.get("/w/crates/json/src/lib.rs")
            .and_then(|l| l.get(&9)),
        Some(&1)
    );
    let mut coverage = Coverage::default();
    coverage.crates.insert(
        "kernel".to_owned(),
        Counts {
            lines: 3,
            covered: 2,
            regions: 5,
            regions_covered: 4,
        },
    );
    cov::apply_lines(Path::new("/w"), &mut coverage, &hits);
    let kernel = coverage.crates.get("kernel").copied().expect("kernel");
    assert_eq!((kernel.lines, kernel.covered), (3, 3));
    assert_eq!((kernel.regions, kernel.regions_covered), (5, 4));
    let json = coverage.crates.get("json").copied().expect("json");
    assert_eq!((json.lines, json.covered), (1, 1));
}

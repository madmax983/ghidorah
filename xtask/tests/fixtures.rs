//! Tests of the fixture corpus, its truth, its goldens and the frozen eval inputs (WP-06).
//!
//! Tier 1 reads only checked-in files. The tier-2 test rebuilds the corpus with gcc and clang.

use std::path::PathBuf;

use xtask::Finding;
use xtask::fixtures::{self, large, leaf, manifest, questions, spec, truth};
use xtask::json::Value;

// T2 has at least 600 functions (design Section 12.3).
const _: () = assert!(large::FUNCTIONS >= 600);

fn root() -> PathBuf {
    xtask::workspace::root()
}

fn show(found: &[Finding]) -> String {
    let lines: Vec<String> = found.iter().take(20).map(ToString::to_string).collect();
    format!("{} findings:\n{}", found.len(), lines.join("\n"))
}

#[test]
fn ac_022_fixture_manifest() {
    let root = root();
    let manifest = manifest::read(&root).expect("the manifest reads");
    let table = spec::fixtures();
    assert!(
        table.len() >= 120,
        "the fixture table has {} fixtures",
        table.len()
    );
    assert_eq!(
        manifest
            .entries
            .iter()
            .filter(|e| !e.path.starts_with("fixtures/bin/pe/"))
            .count(),
        table.len()
    );
    let found = manifest::check_files(&root, &manifest).expect("the binaries read");
    assert!(found.is_empty(), "{}", show(&found));
    let found = manifest::check_goldens(&root, &manifest).expect("the goldens read");
    assert!(found.is_empty(), "{}", show(&found));
    assert!(manifest.total_bytes() <= fixtures::MAX_TOTAL_BYTES);
    for tool in ["gcc", "clang", "binutils"] {
        assert!(
            manifest.tools.contains_key(tool),
            "the manifest has no {tool} version"
        );
    }
}

#[test]
fn truth_files_parse() {
    let root = root();
    let manifest = manifest::read(&root).expect("the manifest reads");
    let found = truth::check_all(&root, &manifest).expect("the truth files read");
    assert!(found.is_empty(), "{}", show(&found));
    // Spot checks against the C sources.
    let crackme = truth::read(&root, "crackme.gcc-O2").expect("crackme truth");
    assert_eq!(
        crackme
            .pointer("/facts/secrets/password")
            .and_then(|v| v.as_str()),
        Some("s3cr3t-k3y")
    );
    let cold = truth::read(&root, "cold_split.gcc-O2").expect("cold_split truth");
    let parts = cold
        .get("cold_parts")
        .and_then(|v| v.as_array())
        .expect("cold parts");
    assert!(!parts.is_empty(), "gcc -O2 makes .cold parts of cold_split");
    let large = truth::read(&root, "large.gcc-O2").expect("large truth");
    let count = large
        .get("function_count")
        .and_then(Value::as_u64)
        .expect("count");
    assert!(count >= 600, "T2 has {count} functions");
    let tables = large
        .get("jump_tables")
        .and_then(|v| v.as_array())
        .expect("tables");
    assert!(tables.len() >= 50, "T2 has {} jump tables", tables.len());
    let sys = truth::read(&root, "syscall_only.gcc-O2").expect("syscall_only truth");
    let sites = sys
        .get("syscalls")
        .and_then(|v| v.as_array())
        .expect("syscalls");
    assert_eq!(sites.len(), 4);
}

#[test]
fn leaf_vectors_cover_every_leaf() {
    let root = root();
    let manifest = manifest::read(&root).expect("the manifest reads");
    let found = leaf::check_vectors(&root, &manifest).expect("the vectors read");
    assert!(found.is_empty(), "{}", show(&found));
    // Every leaf-vector build of a program with LEAF lines lists its leaf functions.
    let mut builds = 0;
    for fixture in spec::fixtures() {
        if fixture.variant.is_none() && fixture.build.leaf_vectors {
            let t = truth::read(&root, &fixture.truth_name()).expect("truth");
            let fns = t
                .get("leaf_functions")
                .and_then(|v| v.as_array())
                .expect("leafs");
            if !fns.is_empty() {
                builds += 1;
            }
        }
    }
    assert!(builds >= 9, "only {builds} builds have leaf vectors");
}

#[test]
fn answers_equal_truth_ptr() {
    let found = questions::check_answers(&root()).expect("the questions read");
    assert!(found.is_empty(), "{}", show(&found));
}

#[test]
fn questions_and_intents_hash_locked() {
    let root = root();
    let found = questions::check_locks(&root).expect("the frozen inputs read");
    assert!(found.is_empty(), "{}", show(&found));
    let all = questions::read_questions(&root).expect("questions");
    let minimum: usize = questions::CATEGORY_MINIMUMS.iter().map(|(_, n)| n).sum();
    assert!(
        all.len() >= minimum,
        "{} questions, need {minimum}",
        all.len()
    );
    let pe: Vec<usize> = (all.iter().enumerate())
        .filter(|(_, q)| q.category == "pe")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(pe.len(), 5, "WP-30 appends the pe group of 5 questions");
    assert_eq!(
        pe.first().copied(),
        Some(all.len() - 5),
        "the pe group comes last"
    );
}

#[test]
fn gen_large_matches_source() {
    let text = large::generate();
    let path = root().join(large::SOURCE_PATH);
    let checked_in = std::fs::read_to_string(&path).expect("large.c reads");
    assert!(text == checked_in, "run `cargo xtask fixtures gen-large`");
    let count = text.lines().filter(|l| l.starts_with("NI u64 f")).count();
    assert_eq!(count, large::FUNCTIONS);
    assert_eq!(large::generate(), text, "two runs give equal text");
}

#[test]
fn fixtures_and_golden_commands() {
    let root = root();
    let report = fixtures::run(&root, &["check".to_owned()]).expect("the check runs");
    assert_eq!(
        report.get("ok").and_then(Value::as_bool),
        Some(true),
        "{report}"
    );
    let bad = fixtures::run(&root, &["bogus".to_owned()]);
    assert!(matches!(bad, Err(xtask::Error::Usage(_))), "{bad:?}");
    let headers = xtask::golden::run(&root, &["headers".to_owned()]).expect("headers runs");
    assert_eq!(
        headers.get("ok").and_then(Value::as_bool),
        Some(true),
        "{headers}"
    );
    let bad = xtask::golden::run(&root, &[]);
    assert!(matches!(bad, Err(xtask::Error::Usage(_))), "{bad:?}");
    let snap = xtask::golden::snapshot(&root).expect("the goldens read");
    assert!(snap.keys().any(|k| k.starts_with("tests/golden/loader/")));
}

#[test]
fn fixtures_golden_and_oracle_are_commands_of_the_binary() {
    // Each row: the arguments, the exit code and a part of the error text.
    let cases: [(&[&str], i32, &str); 8] = [
        (&["fixtures", "check"], 0, ""),
        (&["golden", "headers"], 0, ""),
        (&["fixtures", "bogus"], 2, "cargo xtask fixtures <"),
        (&["golden"], 2, "cargo xtask golden <"),
        (&["golden", "x86", "extra"], 2, "|headers|x86>"),
        (&["oracle"], 2, "cargo xtask oracle <"),
        (&["oracle", "bogus"], 2, "[--check]|bash>"),
        (&["no-such-command"], 2, "|golden|oracle>"),
    ];
    for (args, code, error) in cases {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .output()
            .expect("the xtask binary starts");
        let stdout = String::from_utf8(out.stdout).expect("the report is UTF-8");
        let report = xtask::json::parse(stdout.trim()).expect("the binary prints one JSON object");
        assert_eq!(out.status.code(), Some(code), "{args:?}: {report}");
        let ok = report.get("ok").and_then(Value::as_bool);
        assert_eq!(ok, Some(code == 0), "{args:?}: {report}");
        let text = report.get("error").and_then(Value::as_str).unwrap_or("");
        assert!(text.contains(error), "{args:?}: {text}");
    }
}

#[test]
#[ignore = "tier2"]
fn fixtures_build_reproduces_checked_in_files() {
    let root = root();
    let tools = fixtures::toolchain::detect().expect("gcc, clang and binutils are on PATH");
    let manifest = manifest::read(&root).expect("the manifest reads");
    let report = fixtures::build::run(&root, true).expect("the fixture build runs");
    let count = report.get("fixtures").and_then(Value::as_u64);
    assert_eq!(
        count,
        u64::try_from(spec::fixtures().len()).ok(),
        "{report}"
    );
    if tools.map() == manifest.tools {
        assert_eq!(
            report.get("ok").and_then(Value::as_bool),
            Some(true),
            "{report}"
        );
    } else {
        // Other tool versions give other bytes. The facts still hold, so the build passes.
        eprintln!(
            "tool versions {:?} differ from {:?}; bytes not compared",
            tools.map(),
            manifest.tools
        );
    }
}

#[test]
fn regress_clang_uses_the_gcc_installation_of_gcc() {
    let dir = "/usr/lib/gcc/x86_64-linux-gnu/13";
    assert_eq!(
        fixtures::toolchain::driver_flags(spec::Compiler::Clang, dir),
        vec![format!("--gcc-install-dir={dir}")]
    );
    assert!(fixtures::toolchain::driver_flags(spec::Compiler::Gcc, dir).is_empty());
}

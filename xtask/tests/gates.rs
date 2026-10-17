//! Workspace gate tests. Each test proves one AC that WP-01 closes.
//!
//! Each test checks the real repository and a synthetic bad input.
#![allow(
    clippy::expect_used,
    reason = "test helpers stop at the first failure with a message"
)]

use std::sync::OnceLock;

use xtask::ac::{self, AcRow};
use xtask::ci::{self, Step};
use xtask::cov::{self, Counts, Coverage};
use xtask::dag::{self, Edge};
use xtask::gates::{self, Repo};
use xtask::json::{self, Value};
use xtask::workspace::{self, DepKind};
use xtask::{Finding, manifest, scan, workflow};

fn repo() -> &'static Repo {
    static REPO: OnceLock<Repo> = OnceLock::new();
    REPO.get_or_init(|| Repo::load(&workspace::root()).expect("the workspace model loads"))
}

fn render(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_clean(ac: &str) {
    let findings = gates::check(repo(), ac).expect("the gate runs");
    assert!(findings.is_empty(), "{ac} findings:\n{}", render(&findings));
}

fn package(name: &str, dir: &str, extra: &str) -> String {
    format!(
        r#"{{"name":"{name}","manifest_path":"/w/{dir}/Cargo.toml","edition":"2024",
        "license":"Apache-2.0","publish":[],"dependencies":[{extra}],
        "targets":[{{"name":"{name}","kind":["lib"],"src_path":"/w/{dir}/src/lib.rs","edition":"2024"}}]}}"#
    )
}

fn metadata(packages: &[String]) -> workspace::Metadata {
    let text = format!(
        r#"{{"packages":[{}],"workspace_root":"/w","version":1}}"#,
        packages.join(",")
    );
    workspace::parse_metadata(std::path::Path::new("/w"), &text).expect("synthetic metadata parses")
}

fn path_dep(name: &str, dir: &str, kind: &str) -> String {
    format!(r#"{{"name":"{name}","source":null,"kind":{kind},"path":"/w/{dir}"}}"#)
}

#[test]
fn ac_001a_workspace_packages() {
    assert_clean("AC-001a");
    let good = metadata(&[package("ghidorah-json", "crates/json", "")]);
    assert!(workspace::check_packages(&good).is_empty());
    let unknown = metadata(&[package("serde", "crates/serde", "")]);
    assert_eq!(workspace::check_packages(&unknown).len(), 1);
    let moved = metadata(&[package("ghidorah-json", "crates/jsonx", "")]);
    assert_eq!(workspace::check_packages(&moved).len(), 1);
}

#[test]
fn ac_001b_no_source_key() {
    assert_clean("AC-001b");
    let lock = "version = 4\n\n[[package]]\nname = \"xtask\"\nversion = \"0.1.0\"\n";
    assert!(manifest::no_lock_sources(lock).is_empty());
    let bad = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let found = manifest::no_lock_sources(bad);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line, 4);
}

#[test]
fn ac_001c_workspace_deps_only() {
    assert_clean("AC-001c");
    let base = package("ghidorah-base", "crates/base", "");
    let local = package(
        "ghidorah-types",
        "crates/types",
        &path_dep("ghidorah-base", "crates/base", "null"),
    );
    assert!(workspace::check_workspace_deps(&metadata(&[base.clone(), local])).is_empty());
    let registry = package(
        "ghidorah-types",
        "crates/types",
        r#"{"name":"serde","source":"registry+https://github.com/rust-lang/crates.io-index","kind":null}"#,
    );
    assert_eq!(
        workspace::check_workspace_deps(&metadata(&[base, registry])).len(),
        1
    );
    let vendored = package(
        "ghidorah-types",
        "crates/types",
        &path_dep("vendored", "vendor/vendored", "null"),
    );
    assert_eq!(
        workspace::check_workspace_deps(&metadata(&[vendored])).len(),
        1
    );
}

#[test]
fn ac_001d_no_patch_tables() {
    assert_clean("AC-001d");
    assert_eq!(
        manifest::no_patch_tables("Cargo.toml", "[patch.crates-io]\nfoo = { path = \"x\" }\n")
            .len(),
        1
    );
    assert_eq!(
        manifest::no_patch_tables(
            "Cargo.toml",
            "[replace]\n\"foo:1.0.0\" = { path = \"x\" }\n"
        )
        .len(),
        1
    );
    assert!(manifest::no_patch_tables("Cargo.toml", "[workspace]\nmembers = [\"x\"]\n").is_empty());
    assert_eq!(
        manifest::no_source_tables(
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"v\"\n"
        )
        .len(),
        1
    );
    assert_eq!(
        manifest::no_source_tables(".cargo/config.toml", "[patch.crates-io]\n").len(),
        1
    );
    assert!(manifest::no_source_tables(".cargo/config.toml", "[net]\noffline = true\n").is_empty());
}

#[test]
fn ac_001e_publish_and_license() {
    assert_clean("AC-001e");
    let good = metadata(&[package("ghidorah-json", "crates/json", "")]);
    assert!(workspace::check_publish_license(&good).is_empty());
    let text = package("ghidorah-json", "crates/json", "")
        .replace("\"publish\":[]", "\"publish\":null")
        .replace("Apache-2.0", "MIT");
    assert_eq!(
        workspace::check_publish_license(&metadata(&[text])).len(),
        2
    );
}

#[test]
fn ac_002_offline_config() {
    assert_clean("AC-002");
    assert!(manifest::offline("[net]\noffline = true\n").is_empty());
    assert_eq!(manifest::offline("[net]\noffline = false\n").len(), 1);
    assert_eq!(manifest::offline("").len(), 1);
    let root = workspace::root();
    let cmd = ci::command(&root, Step::OfflineBuild);
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(args.iter().any(|a| a == "--offline") && args.iter().any(|a| a == "--locked"));
    let home = cmd
        .get_envs()
        .find(|(k, _)| *k == "CARGO_HOME")
        .and_then(|(_, v)| v)
        .map(std::path::PathBuf::from);
    assert_eq!(home, Some(ci::offline_home(&root)));
}

#[test]
#[ignore = "tier2"]
fn ac_002_offline_build() {
    let args = vec!["--steps".to_owned(), "offline_build".to_owned()];
    let report = ci::run(&workspace::root(), &args).expect("xtask ci runs");
    assert_eq!(
        report.pointer("/steps/offline_build/ok"),
        Some(&Value::Bool(true)),
        "{report}"
    );
}

#[test]
fn ac_003_crate_dag() {
    assert_clean("AC-003");
    assert!(dag::is_allowed(
        "ghidorah-x86",
        "ghidorah-ir",
        DepKind::Normal
    ));
    assert!(!dag::is_allowed(
        "ghidorah-ir",
        "ghidorah-x86",
        DepKind::Normal
    ));
    assert!(dag::is_allowed(
        "ghidorah-json",
        "ghidorah-testkit",
        DepKind::Dev
    ));
    assert!(!dag::is_allowed(
        "ghidorah-json",
        "ghidorah-testkit",
        DepKind::Normal
    ));
    assert!(dag::is_allowed(
        "ghidorah-loader",
        "ghidorah-oracle",
        DepKind::Dev
    ));
    assert!(!dag::is_allowed(
        "ghidorah-tools",
        "ghidorah-oracle",
        DepKind::Dev
    ));
    let bad = Edge {
        from: "ghidorah-ir".to_owned(),
        to: "ghidorah-x86".to_owned(),
        kind: DepKind::Normal,
    };
    let found = dag::check_edges(&[bad]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].rule, "AC-003");
    let graph = dag::render();
    assert!(graph.contains("graph TD"));
    assert!(workspace::PACKAGES.iter().all(|p| graph.contains(p.name)));
    assert_eq!(graph, dag::render());
}

#[test]
fn ac_004_no_unsafe_in_shipped() {
    assert_clean("AC-004");
    let rel = "crates/base/src/lib.rs";
    assert_eq!(scan::no_unsafe(rel, "unsafe fn f() {}\n").len(), 1);
    assert_eq!(
        scan::no_unsafe(rel, "#![expect(unsafe_code, reason = \"x\")]\n").len(),
        1
    );
    assert!(
        scan::no_unsafe(
            rel,
            "// unsafe here\nfn unsafe_free() { let _ = \"unsafe\"; }\n"
        )
        .is_empty()
    );
    let meta = metadata(&[
        package(
            "ghidorah",
            "crates/cli",
            &path_dep("ghidorah-tools", "crates/tools", "null"),
        ),
        package(
            "ghidorah-tools",
            "crates/tools",
            &format!(
                "{},{}",
                path_dep("ghidorah-base", "crates/base", "null"),
                path_dep("ghidorah-testkit", "crates/testkit", "\"dev\"")
            ),
        ),
        package("ghidorah-base", "crates/base", ""),
        package("ghidorah-testkit", "crates/testkit", ""),
    ]);
    let names: Vec<String> = workspace::closure(&meta, "ghidorah").into_iter().collect();
    assert_eq!(names, ["ghidorah", "ghidorah-base", "ghidorah-tools"]);
}

#[test]
fn ac_005_no_vstd() {
    assert_clean("AC-005");
    assert_eq!(
        manifest::no_vstd("Cargo.toml", "[dependencies]\nvstd = { path = \"v\" }\n").len(),
        1
    );
    assert_eq!(
        manifest::no_vstd("Cargo.toml", "[dev-dependencies]\nverus_builtin = \"1\"\n").len(),
        1
    );
    assert!(
        manifest::no_vstd(
            "Cargo.toml",
            "[dependencies]\nghidorah-spec = { path = \"../spec\" }\n"
        )
        .is_empty()
    );
}

#[test]
fn ac_007a_toolchain_pin() {
    assert_clean("AC-007a");
    let good = "[toolchain]\nchannel = \"1.97.0\"\ncomponents = [\"clippy\", \"rustfmt\", \"llvm-tools\"]\n";
    assert!(manifest::toolchain_pin(good).is_empty());
    assert_eq!(
        manifest::toolchain_pin(&good.replace(", \"llvm-tools\"", "")).len(),
        1
    );
    assert_eq!(
        manifest::toolchain_pin(&good.replace("1.97.0", "stable")).len(),
        1
    );
}

#[test]
fn ac_007b_edition_2024() {
    assert_clean("AC-007b");
    let old = package("ghidorah-json", "crates/json", "").replace("2024", "2021");
    assert_eq!(workspace::check_edition(&metadata(&[old])).len(), 2);
}

#[test]
fn ac_007c_resolver_3() {
    assert_clean("AC-007c");
    assert!(manifest::resolver_3("[workspace]\nresolver = \"3\"\n").is_empty());
    assert_eq!(
        manifest::resolver_3("[workspace]\nresolver = \"2\"\n").len(),
        1
    );
    assert_eq!(manifest::resolver_3("[workspace]\nmembers = []\n").len(), 1);
}

#[test]
fn ac_008_no_networked_build_scripts() {
    assert_clean("AC-008");
    let rel = "crates/x86/build.rs";
    assert_eq!(
        scan::build_script(rel, "use std::process::Command;\nfn main() {}\n").len(),
        1
    );
    assert_eq!(
        scan::build_script(
            rel,
            "fn main() { let _ = std::net::TcpStream::connect(\"h:1\"); }\n"
        )
        .len(),
        1
    );
    assert!(
        scan::build_script(
            rel,
            "fn main() { println!(\"cargo::rerun-if-changed=build.rs\"); }\n"
        )
        .is_empty()
    );
}

#[test]
fn ac_009_fmt_check() {
    assert_clean("AC-009");
}

#[test]
fn ac_010_clippy_policy() {
    assert_clean("AC-010");
    let root_toml = repo().read("Cargo.toml").expect("root manifest reads");
    assert!(manifest::lint_policy(&root_toml).is_empty());
    let no_nursery = root_toml.replace("nursery = { level = \"deny\", priority = -1 }", "");
    assert_eq!(manifest::lint_policy(&no_nursery).len(), 1);
    let warn = root_toml.replace(
        "pedantic = { level = \"deny\"",
        "pedantic = { level = \"warn\"",
    );
    assert_eq!(manifest::lint_policy(&warn).len(), 1);
    let extra = root_toml.replace(
        "future_not_send = \"allow\"",
        "future_not_send = \"allow\"\ntoo_many_lines = \"allow\"",
    );
    assert_eq!(manifest::lint_policy(&extra).len(), 1);
    assert_eq!(
        manifest::lints_inherited("crates/x/Cargo.toml", "[package]\nname = \"x\"\n").len(),
        1
    );
    assert!(
        manifest::lints_inherited("crates/x/Cargo.toml", "[lints]\nworkspace = true\n").is_empty()
    );
}

#[test]
fn ac_011_docs_policy() {
    assert_clean("AC-011");
    let root_toml = repo().read("Cargo.toml").expect("root manifest reads");
    assert!(manifest::docs_policy(&root_toml).is_empty());
    let warn = root_toml.replace("missing_docs = \"deny\"", "missing_docs = \"warn\"");
    assert_eq!(manifest::docs_policy(&warn).len(), 1);
}

#[test]
fn ac_012_no_stubs() {
    assert_clean("AC-012");
    let rel = "crates/base/src/lib.rs";
    let bad = [
        "fn f() { todo!() }",
        "fn f() { unimplemented!() }",
        "fn f() { dbg!(1); }",
        "fn f() { x.unwrap(); }",
        "fn f() { x.expect(\"m\"); }",
        "// TODO later",
        "/* FIXME */",
        "// XXX",
    ];
    for text in bad {
        assert_eq!(scan::no_stubs(rel, text).len(), 1, "{text}");
    }
    let good = [
        "fn f() { x.unwrap_or(0); }",
        "#[expect(clippy::too_many_lines, reason = \"table\")]",
        "fn todo_list() {}",
        "let s = \"todo!()\";",
    ];
    for text in good {
        assert!(scan::no_stubs(rel, text).is_empty(), "{text}");
    }
}

#[test]
fn ac_013_coverage_gate() {
    assert_eq!(
        (cov::WORKSPACE_MIN, cov::CORE_MIN, cov::KERNEL_MIN),
        (85, 90, 95)
    );
    assert_eq!(cov::min_percent("kernel"), Some(95));
    assert_eq!(cov::min_percent("json"), Some(90));
    assert_eq!(cov::min_percent("decomp"), Some(90));
    assert_eq!(cov::min_percent("base"), None);
    let one = |dir: &str, lines: u64, covered: u64| {
        let counts = Counts {
            lines,
            covered,
            ..Counts::default()
        };
        Coverage {
            crates: std::iter::once((dir.to_owned(), counts)).collect(),
        }
    };
    let ok = |c: &Coverage| cov::gate(c).get("ok").and_then(Value::as_bool);
    assert_eq!(ok(&Coverage::default()), Some(true));
    assert_eq!(ok(&one("kernel", 100, 95)), Some(true));
    assert_eq!(ok(&one("kernel", 100, 94)), Some(false));
    assert_eq!(ok(&one("json", 100, 90)), Some(true));
    assert_eq!(ok(&one("json", 100, 89)), Some(false));
    assert_eq!(ok(&one("base", 100, 85)), Some(true));
    assert_eq!(ok(&one("base", 100, 84)), Some(false));
}

#[test]
#[ignore = "tier2"]
fn ac_013_coverage_run() {
    let report = cov::run(&workspace::root(), &[]).expect("xtask cov runs");
    assert_eq!(
        report.get("ok"),
        Some(&Value::Bool(true)),
        "{}",
        json::write(&report)
    );
}

#[test]
fn ac_014_file_size() {
    assert_clean("AC-014");
    let rel = "crates/base/src/lib.rs";
    assert!(scan::file_size(rel, &"x\n".repeat(600)).is_empty());
    assert_eq!(scan::file_size(rel, &"x\n".repeat(601)).len(), 1);
    assert!(scan::is_table_file("crates/x86/src/tables/ops.rs"));
    assert!(scan::is_test_file("crates/base/src/addr/tests.rs"));
    assert!(scan::is_test_file("crates/base/tests/ac_026.rs"));
    assert!(!scan::is_test_file("crates/base/src/lib.rs"));
}

#[test]
fn ac_016_disallowed_types() {
    assert_clean("AC-016");
    let config = repo().read("clippy.toml").expect("clippy.toml reads");
    assert!(manifest::clippy_config(&config).is_empty());
    assert_eq!(
        manifest::clippy_config(&config.replace("std::collections::HashSet", "x")).len(),
        1
    );
    let rel = "crates/db/src/lib.rs";
    assert_eq!(
        scan::disallowed_exceptions(rel, "#[allow(clippy::disallowed_types)]\n").len(),
        1
    );
    assert_eq!(
        scan::disallowed_exceptions(rel, "#[expect(clippy::disallowed_types)]\n").len(),
        1
    );
    let reasoned = "#[expect(clippy::disallowed_types, reason = \"lookup only\")]\n";
    assert!(scan::disallowed_exceptions(rel, reasoned).is_empty());
}

#[test]
fn ac_017_layering() {
    assert_clean("AC-017");
    let rel = "crates/json/src/lib.rs";
    let bad = [
        "use std::fs;",
        "use std::{collections::BTreeMap, env};",
        "fn f() { std::process::exit(1) }",
        "fn f() { let _ = std::time::SystemTime::now(); }",
        "use std::net::TcpStream;",
    ];
    for text in bad {
        assert_eq!(scan::layering(rel, text).len(), 1, "{text}");
    }
    assert!(scan::layering(rel, "use std::time::Instant;\n// std::fs in a comment\n").is_empty());
    assert_eq!(scan::crate_dir("crates/json/src/lib.rs"), Some("json"));
    assert_eq!(scan::crate_dir("xtask/src/main.rs"), Some("xtask"));
}

fn row(id: &str, closes: &[&str], needs: &[&str]) -> AcRow {
    AcRow {
        id: id.to_owned(),
        line: 1,
        stretch: false,
        removed: false,
        evidence: Vec::new(),
        closes: closes.iter().map(|s| (*s).to_owned()).collect(),
        needs: needs.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[test]
fn ac_018c_needs_order() {
    assert_clean("AC-018c");
    assert_eq!(ac::position("01"), Some((0, 0)));
    assert_eq!(ac::position("WP-02"), Some((0, 1)));
    assert_eq!(ac::needs_order(&[row("AC-1", &["07"], &["17b"])]).len(), 1);
    assert!(ac::needs_order(&[row("AC-2", &["17b"], &["19"])]).is_empty());
    assert_eq!(ac::needs_order(&[row("AC-3", &["19"], &["17b"])]).len(), 1);
    assert!(ac::needs_order(&[row("AC-4", &["13a", "25"], &["24"])]).is_empty());
    assert_eq!(ac::needs_order(&[row("AC-5", &["13a"], &["24"])]).len(), 1);
    assert_eq!(ac::needs_order(&[row("AC-6", &["99"], &[])]).len(), 1);
    assert!(ac::needs_order(&[row("AC-7", &["30"], &["23"])]).is_empty());
    assert_eq!(ac::needs_order(&[row("AC-8", &["23"], &["30"])]).len(), 1);
    assert!(ac::needs_order(&[row("AC-9", &["29"], &["25", "21"])]).is_empty());
    let removed = AcRow {
        removed: true,
        ..row("AC-10", &["01"], &["28"])
    };
    assert!(ac::needs_order(&[removed]).is_empty());
}

#[test]
fn ac_018c_pairs_follow_revision_3() {
    let pairs: Vec<&str> = ac::PAIRS.iter().map(|(name, _)| *name).collect();
    let expected: Vec<String> = (1..=18).map(|n| format!("P{n}")).collect();
    assert_eq!(pairs, expected);
    let wps: usize = ac::PAIRS.iter().map(|(_, wps)| wps.len()).sum();
    assert_eq!(wps, 34);
    assert_eq!(ac::position("18"), Some((6, 1)));
    assert_eq!(ac::position("16"), Some((7, 1)));
    assert_eq!(ac::position("20"), Some((9, 1)));
    assert_eq!(ac::position("30"), Some((14, 1)));
    assert_eq!(ac::position("29"), Some((15, 0)));
    assert_eq!(ac::position("26"), Some((16, 0)));
    assert_eq!(ac::position("28"), Some((17, 1)));
    let design = repo().read(ac::DESIGN_PATH).expect("design reads");
    let headings: Vec<&str> = design
        .lines()
        .filter_map(|l| l.strip_prefix("#### WP-"))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert_eq!(headings.len(), wps);
    for wp in headings {
        assert!(ac::position(wp).is_some(), "WP-{wp} is in no pair");
    }
}

#[test]
fn ac_019_ci_workflow() {
    assert_clean("AC-019");
    let yaml = repo().read(workflow::PATH).expect("ci.yml reads");
    let jobs = workflow::jobs(&yaml);
    assert!(jobs.iter().any(|j| j == "tier1") && jobs.iter().any(|j| j == "tier2"));
    assert!(jobs.iter().any(|j| j == "verus"));
    let node = yaml.replacen("actions/cache@v4", "actions/setup-node@v4", 1);
    assert!(!workflow::check(&node).is_empty());
    let no_tier2 = yaml.replacen("\n  tier2:", "\n  other:", 1);
    assert!(!workflow::check(&no_tier2).is_empty());
}

#[test]
fn ac_223_no_set_var() {
    assert_clean("AC-223");
    let rel = "crates/cli/tests/x.rs";
    assert_eq!(
        scan::no_set_var(rel, "fn f() { std::env::set_var(\"A\", \"1\"); }").len(),
        1
    );
    assert_eq!(
        scan::no_set_var(rel, "fn f() { env::remove_var(\"A\"); }").len(),
        1
    );
    assert!(
        scan::no_set_var(
            rel,
            "fn f() { cmd.env(\"A\", \"1\"); let _ = \"set_var(\"; }"
        )
        .is_empty()
    );
}

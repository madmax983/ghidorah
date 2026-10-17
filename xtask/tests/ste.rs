//! Tests of `xtask ste`, the wrapper over the STE checker of `testkit` (AC-025).

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers fail through a panic"
)]

use std::path::{Path, PathBuf};

use xtask::json::Value;
use xtask::{Error, ste, workspace};

/// Makes a small repository tree under the test temp directory.
fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&root);
    for (rel, text) in files {
        let path = root.join(rel);
        let dir = path.parent().expect("a file path has a parent");
        std::fs::create_dir_all(dir).expect("the directory is made");
        std::fs::write(&path, text).expect("the file is written");
    }
    root
}

fn run(root: &Path) -> Value {
    ste::run(root, &[]).expect("xtask ste runs")
}

fn strings(report: &Value, key: &str) -> Vec<String> {
    let Some(Value::Array(items)) = report.get(key) else {
        panic!("`{key}` is not an array");
    };
    items
        .iter()
        .map(|v| v.as_str().expect("a string item").to_owned())
        .collect()
}

#[test]
fn ste_reports_a_finding_with_its_allow_line() {
    let root = tree(
        "xtask_ste_finding",
        &[
            ("docs/a.md", "# A\n\nThe value would change.\n"),
            ("docs/research.md", "The value would change.\n"),
            ("docs/planning/b.md", "The value would change.\n"),
            (
                "src/lib.rs",
                "//! The parser reads the header.\nfn f() {}\n",
            ),
        ],
    );
    let report = run(&root);
    assert_eq!(report.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(report.get("files"), Some(&Value::from(2_usize)));
    let Some(Value::Array(findings)) = report.get("findings") else {
        panic!("no findings array");
    };
    assert_eq!(findings.len(), 1);
    let first = &findings[0];
    assert_eq!(first.get("rule").and_then(Value::as_str), Some("STE-6"));
    assert_eq!(first.get("path").and_then(Value::as_str), Some("docs/a.md"));
    assert_eq!(first.get("line"), Some(&Value::from(3_usize)));
    let detail = first.get("detail").and_then(Value::as_str).unwrap_or("");
    assert!(detail.contains("The value would change."), "{detail}");
    assert_eq!(
        strings(&report, "allow"),
        ["docs/a.md STE-6 The value would change."]
    );
}

#[test]
fn ste_applies_the_allowlist_and_lists_unused_entries() {
    let allowlist = "# Reviewed.\n\
                     docs/a.md STE-6 The value would change.\n\
                     docs/a.md STE-4 No such sentence.\n";
    let root = tree(
        "xtask_ste_allowlist",
        &[
            ("docs/a.md", "# A\n\nThe value would change.\n"),
            ("docs/ste-allowlist.txt", allowlist),
        ],
    );
    let report = run(&root);
    assert_eq!(report.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(report.get("allowed"), Some(&Value::from(1_usize)));
    assert!(strings(&report, "allow").is_empty());
    assert_eq!(
        strings(&report, "unused"),
        ["docs/a.md STE-4 No such sentence."]
    );
}

#[test]
fn ste_uses_the_ban_list_file() {
    let root = tree(
        "xtask_ste_banlist",
        &[
            ("docs/a.md", "The loader frobs the header.\n"),
            ("docs/ste-banlist.txt", "# Banned.\nfrob\n"),
        ],
    );
    let report = run(&root);
    assert_eq!(report.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        strings(&report, "allow"),
        ["docs/a.md STE-6 The loader frobs the header."]
    );
}

#[test]
fn ste_rejects_arguments_and_a_bad_allowlist() {
    let root = tree(
        "xtask_ste_bad",
        &[("docs/ste-allowlist.txt", "docs/a.md\n")],
    );
    assert!(matches!(
        ste::run(&root, &["--deny".to_owned()]),
        Err(Error::Usage(_))
    ));
    assert!(matches!(ste::run(&root, &[]), Err(Error::Data { .. })));
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xtask_ste_no_root");
    let _ = std::fs::remove_dir_all(&missing);
    assert!(matches!(ste::run(&missing, &[]), Err(Error::Io { .. })));
}

#[test]
fn ste_repository_is_clean() {
    let report = run(&workspace::root());
    let allow = strings(&report, "allow");
    assert_eq!(
        report.get("ok").and_then(Value::as_bool),
        Some(true),
        "new STE findings. Fix the text or add a reviewed line to docs/ste-allowlist.txt:\n{}",
        allow.join("\n")
    );
    let Some(Value::Number(files)) = report.get("files") else {
        panic!("no file count");
    };
    assert!(files.parse::<usize>().is_ok_and(|n| n >= 10), "{files}");
}

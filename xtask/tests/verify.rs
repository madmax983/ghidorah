//! Tests of `xtask verify`: the tree hash, the negative patches, the Verus output and the run.

use std::path::{Path, PathBuf};

use xtask::json::{self, Value};
use xtask::verify::patch::{self, PatchError};
use xtask::verify::tree::{self, hash_files, hex, sha256};
use xtask::verify::{self, KERNELS, Settings};

fn root() -> PathBuf {
    xtask::workspace::root()
}

/// A Verus JSON report with the given counts, in the form of Verus commit ffc9d20.
fn report(verified: u64, errors: u64) -> String {
    let success = errors == 0;
    format!(
        r#"{{"func-details":{{}},"verification-results":{{"encountered-error":{e},"encountered-vir-error":false,"success":{success},"verified":{verified},"errors":{errors},"is-verifying-entire-crate":false}},"verus":{{"profile":"release","version":"0.2026.10.16.ffc9d20","platform":{{"os":"linux","arch":"x86_64"}},"toolchain":"1.98.1-x86_64-unknown-linux-gnu (overridden by environment variable RUSTUP_TOOLCHAIN)","commit":"ffc9d20fee64da92cb037be195b467dd321ae4e3"}}}}"#,
        e = !success
    )
}

#[test]
fn verify_sha256_kat() {
    let cases: [(&[u8], &str); 3] = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (input, want) in cases {
        assert_eq!(hex(&sha256(input)), want);
    }
    let million = vec![b'a'; 1_000_000];
    assert_eq!(
        hex(&sha256(&million)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
    // The padding boundaries: 55, 56 and 64 bytes.
    let lens = [55usize, 56, 63, 64, 65];
    let hashes: Vec<String> = lens.iter().map(|&n| hex(&sha256(&vec![0u8; n]))).collect();
    assert_eq!(
        hashes[0],
        "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"
    );
    assert_eq!(
        hashes[3],
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
    );
    let unique: std::collections::BTreeSet<&String> = hashes.iter().collect();
    assert_eq!(unique.len(), lens.len());
}

#[test]
fn verify_tree_hash_encoding() {
    let files = vec![("a".to_owned(), b"x".to_vec())];
    assert_eq!(
        hash_files(&files, &["v"]),
        hex(&sha256(b"file a\n1\nxargv v\n"))
    );
    let one = vec![
        ("b/c.rs".to_owned(), b"fn c() {}".to_vec()),
        ("a.rs".to_owned(), Vec::new()),
    ];
    let two = vec![one[1].clone(), one[0].clone()];
    assert_eq!(
        hash_files(&one, tree::ARGV),
        hash_files(&two, tree::ARGV),
        "order has no effect"
    );
    assert_ne!(
        hash_files(&one, tree::ARGV),
        hash_files(&one, &["verus"]),
        "the argv counts"
    );
    let mut edited = one.clone();
    edited[0].1.push(b' ');
    assert_ne!(
        hash_files(&one, tree::ARGV),
        hash_files(&edited, tree::ARGV)
    );
    // A path and its bytes do not run together.
    let split_a = vec![("ab".to_owned(), b"c".to_vec())];
    let split_b = vec![("a".to_owned(), b"bc".to_vec())];
    assert_ne!(hash_files(&split_a, &[]), hash_files(&split_b, &[]));
}

#[test]
fn verify_tree_files_cover_the_sources() {
    let files = tree::tree_files(&root()).expect("the source tree is readable");
    let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    assert!(paths.contains(&"crates/kernel/src/lib.rs"));
    assert!(paths.contains(&"crates/kernel/src/reader.rs"));
    assert!(paths.contains(&"crates/spec/src/lib.rs"));
    assert!(paths.iter().all(|p| p.ends_with(".rs")));
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted, "the files come in path order");
    let hash = tree::tree_sha256(&root()).expect("the source tree is readable");
    assert_eq!(hash, hash_files(&files, tree::ARGV));
}

const SOURCE: &str = "fn a() {\n    let x = 1;\n    x + 1\n}\n\nfn b() {\n    let x = 2;\n}\n";

const GOOD: &str = "\
diff --git a/crates/kernel/src/demo.rs b/crates/kernel/src/demo.rs
--- a/crates/kernel/src/demo.rs
+++ b/crates/kernel/src/demo.rs
@@ -1,4 +1,4 @@
 fn a() {
     let x = 1;
-    x + 1
+    x + 2
 }
";

#[test]
fn verify_patch_applies_one_hunk() {
    let p = patch::parse(GOOD).expect("the patch parses");
    assert_eq!(p.path, "crates/kernel/src/demo.rs");
    assert_eq!(p.old.len(), 4);
    assert_eq!(p.new.len(), 4);
    let out = patch::apply(SOURCE, &p).expect("the patch applies");
    assert_eq!(out, SOURCE.replace("x + 1", "x + 2"));
}

#[test]
fn verify_patch_rejects_bad_patches() {
    let p = patch::parse(GOOD).expect("the patch parses");
    assert_eq!(patch::apply("fn z() {}\n", &p), Err(PatchError::Stale));
    let twice = format!("{SOURCE}{SOURCE}");
    assert_eq!(patch::apply(&twice, &p), Err(PatchError::Ambiguous));
    assert_eq!(patch::parse("no diff here\n"), Err(PatchError::NoFile));
    let two_hunks =
        format!("{GOOD}@@ -6,3 +6,3 @@\n fn b() {{\n-    let x = 2;\n+    let x = 3;\n }}\n");
    assert_eq!(patch::parse(&two_hunks), Err(PatchError::NotOneHunk));
    let two_files = format!("{GOOD}{GOOD}");
    assert_eq!(patch::parse(&two_files), Err(PatchError::NotOneHunk));
    let no_hunk = "--- a/x.rs\n+++ b/x.rs\n";
    assert_eq!(patch::parse(no_hunk), Err(PatchError::NotOneHunk));
    let bad_count = GOOD.replace("@@ -1,4 +1,4 @@", "@@ -1,5 +1,4 @@");
    assert!(matches!(
        patch::parse(&bad_count),
        Err(PatchError::BadHunk(_))
    ));
    let bad_line = GOOD.replace("     let x = 1;", "?    let x = 1;");
    assert!(matches!(
        patch::parse(&bad_line),
        Err(PatchError::BadHunk(_))
    ));
    assert!(!PatchError::Stale.to_string().is_empty());
}

#[test]
fn verify_negative_patches_apply() {
    for kernel in KERNELS {
        let path = root().join(kernel.patch());
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let p = patch::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", kernel.name));
        let dir = format!("crates/kernel/src/{}", kernel.module);
        assert!(
            p.path == kernel.file() || p.path.starts_with(&format!("{dir}/")),
            "{}: the patch changes a file of its kernel, not {}",
            kernel.name,
            p.path
        );
        let source = std::fs::read_to_string(root().join(&p.path)).expect("the file exists");
        let out = patch::apply(&source, &p).unwrap_or_else(|e| panic!("{}: {e}", kernel.name));
        assert_ne!(out, source);
    }
}

#[test]
fn verify_kernel_table() {
    let names: Vec<&str> = KERNELS.iter().map(|k| k.name).collect();
    assert_eq!(names, ["K1", "K2", "K3", "K6", "K7"]);
    for kernel in KERNELS {
        assert_eq!(
            kernel.file(),
            format!("crates/kernel/src/{}.rs", kernel.module)
        );
        assert_eq!(
            kernel.patch(),
            format!("verify/negative/{}.patch", kernel.name)
        );
        assert!(
            root().join(kernel.file()).is_file(),
            "{} exists",
            kernel.file()
        );
    }
}

#[test]
fn verify_parses_verus_output() {
    let counts = verify::parse_counts(&report(12, 0)).expect("the report parses");
    assert_eq!(
        (counts.verified, counts.errors, counts.success),
        (12, 0, true)
    );
    let counts = verify::parse_counts(&report(3, 1)).expect("the report parses");
    assert_eq!(
        (counts.verified, counts.errors, counts.success),
        (3, 1, false)
    );
    assert!(verify::parse_counts("").is_err());
    assert!(verify::parse_counts(r#"{"verus":{}}"#).is_err());

    let tools = verify::parse_tools(&report(1, 0), "Z3 version 4.16.0 - 64 bit\n");
    assert_eq!(tools.verus_commit, "ffc9d20");
    assert_eq!(tools.toolchain, "1.98.1");
    assert_eq!(tools.z3, "4.16.0");
    let unknown = verify::parse_tools("not json", "");
    assert_eq!(
        (
            unknown.verus_commit.as_str(),
            unknown.toolchain.as_str(),
            unknown.z3.as_str()
        ),
        ("unknown", "unknown", "unknown")
    );
}

#[test]
fn verify_classifies_errors() {
    let post = "error: postcondition not satisfied\n --> src/a.rs:4:27\n";
    assert_eq!(
        verify::error_kind(post),
        Some("postcondition not satisfied")
    );
    let assert_err = "note: x\nerror: assertion failed\n";
    assert_eq!(verify::error_kind(assert_err), Some("assertion failed"));
    let pre = "error: precondition not satisfied\n";
    assert_eq!(verify::error_kind(pre), Some("precondition not satisfied"));
    let compile = "error[E0425]: cannot find value `y` in this scope\n";
    assert_eq!(
        verify::error_kind(compile),
        None,
        "a compile error does not count"
    );
    assert_eq!(verify::error_kind(""), None);
}

#[test]
fn verify_counts_spec_items() {
    let text = "\
/// Docs name #[verus_spec(r => ensures true)] in a comment.
#[verus_spec(r => ensures r == 1)]
pub fn one() -> u32 { 1 }
fn two() -> u32 {
    let mut i = 0;
    #[cfg_attr(verus_only, verus_spec(invariant i <= 2))]
    while i < 2 { i += 1; }
    i
}
#[verus_spec(
    ensures true,
)]
fn three() {}
";
    assert_eq!(verify::spec_items(text), 2);
    assert_eq!(verify::spec_items(""), 0);
}

#[test]
fn verify_finds_programs_on_path() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_path");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("the test directory is writable");
    std::fs::write(bin.join("verus"), "").expect("the test file is writable");
    let path = std::env::join_paths([dir.join("none"), bin.clone()]).expect("the paths join");
    assert_eq!(
        verify::find_on_path("verus", Some(&path)),
        Some(bin.join("verus"))
    );
    assert_eq!(verify::find_on_path("z3", Some(&path)), None);
    assert_eq!(verify::find_on_path("verus", None), None);
}

#[test]
fn verify_without_verus_is_skipped_only_when_optional() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_no_verus");
    std::fs::create_dir_all(&dir).expect("the test directory is writable");
    let optional = Settings {
        verus: None,
        z3: None,
        optional: true,
    };
    let out = verify::run_with(&dir, &optional).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(out.get("status").and_then(Value::as_str), Some("skipped"));
    assert!(
        !dir.join(tree::RESULTS_PATH).exists(),
        "a skipped run writes no record"
    );

    let required = Settings {
        optional: false,
        ..optional
    };
    let out = verify::run_with(&dir, &required).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(out.get("status").and_then(Value::as_str), Some("missing"));
    assert!(
        verify::run(&dir, &["--x".to_owned()]).is_err(),
        "the command takes no argument"
    );
}

/// Copies the proof inputs and the negative patches of the workspace to `to`.
fn copy_inputs(to: &Path) {
    let from = root();
    for dir in ["crates/kernel/src", "crates/spec/src", "verify/negative"] {
        copy_dir(&from.join(dir), &to.join(dir));
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the test directory is writable");
    for entry in std::fs::read_dir(from).expect("the source directory is readable") {
        let entry = entry.expect("the directory entry is readable");
        let path = entry.path();
        if path.is_dir() {
            copy_dir(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).expect("the file copies");
        }
    }
}

/// Writes a fake Verus program. A run in a negative copy fails with a postcondition error.
#[cfg(unix)]
fn fake_verus(dir: &Path, good: &str, bad: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("fake-verus");
    let script = format!(
        "#!/bin/sh\ncase \"$PWD\" in\n  *xtask-verify*)\n    echo 'error: postcondition not satisfied' >&2\n    echo '{bad}'\n    exit 1 ;;\nesac\necho \"$@\" >> \"{log}\"\necho '{good}'\n",
        log = dir.join("argv.log").display()
    );
    std::fs::write(&path, script).expect("the script is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the script is executable");
    path
}

#[cfg(unix)]
#[test]
fn verify_run_with_a_fake_verus() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_fake_run");
    let _ = std::fs::remove_dir_all(&dir);
    copy_inputs(&dir);
    let verus = fake_verus(&dir, &report(500, 0), &report(2, 1));
    let settings = Settings {
        verus: Some(verus),
        z3: None,
        optional: false,
    };
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(true), "{out}");
    assert_eq!(out.get("status").and_then(Value::as_str), Some("verified"));
    let text = std::fs::read_to_string(dir.join(tree::RESULTS_PATH)).expect("the record exists");
    let record = json::parse(&text).expect("the record is JSON");
    let want_hash = tree::tree_sha256(&dir).expect("the copy is readable");
    assert_eq!(
        record.get("tree_sha256").and_then(Value::as_str),
        Some(want_hash.as_str())
    );
    assert_eq!(
        record.pointer("/verus_commit").and_then(Value::as_str),
        Some("ffc9d20")
    );
    assert_eq!(
        record.pointer("/z3").and_then(Value::as_str),
        Some("unknown")
    );
    for kernel in KERNELS {
        let row = record
            .pointer(&format!("/kernels/{}", kernel.name))
            .unwrap_or_else(|| panic!("the record has {}", kernel.name));
        assert_eq!(row.get("status").and_then(Value::as_str), Some("verified"));
        assert_eq!(row.get("verified").and_then(Value::as_u64), Some(500));
        assert!(row.get("spec_items").and_then(Value::as_u64).unwrap_or(0) > 0);
    }
    let negatives = record
        .get("negatives")
        .and_then(Value::as_array)
        .expect("negatives");
    assert_eq!(negatives.len(), KERNELS.len());
    for row in negatives {
        assert_eq!(row.get("ok").and_then(Value::as_bool), Some(true), "{row}");
        assert_eq!(
            row.get("error_kind").and_then(Value::as_str),
            Some("postcondition not satisfied")
        );
    }
    let log = std::fs::read_to_string(dir.join("argv.log")).expect("the fake Verus ran");
    assert!(log.contains("--verify-module reader"), "{log}");
    assert!(
        log.lines()
            .all(|l| l.starts_with("--cfg verus_only --no-cheating")),
        "{log}"
    );

    // A stale negative patch makes the run fail.
    let k1 = dir.join("verify/negative/K1.patch");
    let stale = std::fs::read_to_string(&k1)
        .expect("K1.patch exists")
        .replace("\n ", "\n x");
    std::fs::write(&k1, stale).expect("the patch is writable");
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(false), "{out}");
}

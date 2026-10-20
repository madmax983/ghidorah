//! Tests of `xtask verify`: the tree hash, the negative patches, the Verus output and the run.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

use std::path::{Path, PathBuf};

use xtask::json::{self, Value};
use xtask::verify::patch::{self, PatchError};
use xtask::verify::tree::{self, hash_files, hex, sha256};
use xtask::verify::{self, KERNELS, POSTCONDITION, PRECONDITION, Settings, VERIFY_ERRORS};

fn root() -> PathBuf {
    xtask::workspace::root()
}

/// A Verus JSON report with the given counts, in the form of Verus commit ffc9d20.
fn report(verified: u64, errors: u64) -> String {
    report_with(verified, errors, &[])
}

/// A Verus JSON report with the given counts and one `func-details` entry for each name.
fn report_with(verified: u64, errors: u64, functions: &[String]) -> String {
    let success = errors == 0;
    let details = functions
        .iter()
        .map(|name| format!(r#""{name}":{{"obligation_proof_notes":[],"failed_proof_notes":[]}}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"func-details":{{{details}}},"verification-results":{{"encountered-error":{e},"encountered-vir-error":false,"success":{success},"verified":{verified},"errors":{errors},"is-verifying-entire-crate":false}},"verus":{{"profile":"release","version":"0.2026.10.16.ffc9d20","platform":{{"os":"linux","arch":"x86_64"}},"toolchain":"1.98.1-x86_64-unknown-linux-gnu (overridden by environment variable RUSTUP_TOOLCHAIN)","commit":"ffc9d20fee64da92cb037be195b467dd321ae4e3"}}}}"#,
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
    assert!(
        paths
            .iter()
            .all(|p| Path::new(p).extension().is_some_and(|x| x == "rs"))
    );
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
        for negative in kernel.negatives {
            let path = root().join(negative.path());
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let p = patch::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", negative.name));
            let dir = format!("crates/kernel/src/{}", kernel.module);
            assert!(
                p.path == kernel.file() || p.path.starts_with(&format!("{dir}/")),
                "{}: the patch changes a file of its kernel, not {}",
                negative.name,
                p.path
            );
            let source = std::fs::read_to_string(root().join(&p.path)).expect("the file exists");
            let out =
                patch::apply(&source, &p).unwrap_or_else(|e| panic!("{}: {e}", negative.name));
            assert_ne!(out, source);
        }
    }
}

/// Gives the name and the expected error of each negative patch in table order.
fn negative_table() -> Vec<(&'static str, &'static str)> {
    KERNELS
        .iter()
        .flat_map(|k| k.negatives.iter().map(|n| (n.name, n.kind)))
        .collect()
}

#[test]
fn verify_kernel_table() {
    let names: Vec<&str> = KERNELS.iter().map(|k| k.name).collect();
    assert_eq!(names, ["K1", "K2", "K3", "K5", "K6", "K7"]);
    assert_eq!(
        negative_table(),
        [
            ("K1", POSTCONDITION),
            ("K2", POSTCONDITION),
            ("K3", PRECONDITION),
            ("K5", POSTCONDITION),
            ("K6", POSTCONDITION),
            ("K7", POSTCONDITION),
        ]
    );
    for kernel in KERNELS {
        assert_eq!(
            kernel.file(),
            format!("crates/kernel/src/{}.rs", kernel.module)
        );
        assert!(
            root().join(kernel.file()).is_file(),
            "{} exists",
            kernel.file()
        );
        assert!(
            !kernel.negatives.is_empty(),
            "{} has a negative patch",
            kernel.name
        );
        for negative in kernel.negatives {
            assert!(negative.name.starts_with(kernel.name), "{}", negative.name);
            assert_eq!(
                negative.path(),
                format!("verify/negative/{}.patch", negative.name)
            );
            assert!(VERIFY_ERRORS.contains(&negative.kind), "{}", negative.name);
        }
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
    let module_run =
        r#"note: x {"verification-results":{"encountered-error":false,"verified":25,"errors":0}}"#;
    let counts = verify::parse_counts(module_run).expect("the module report parses");
    assert_eq!(
        (counts.verified, counts.errors, counts.success),
        (25, 0, true)
    );
    let failed_run =
        r#"{"verification-results":{"encountered-error":true,"verified":24,"errors":1}}"#;
    let counts = verify::parse_counts(failed_run).expect("the module report parses");
    assert_eq!(
        (counts.verified, counts.errors, counts.success),
        (24, 1, false)
    );
    assert!(verify::parse_counts("").is_err());
    assert!(verify::parse_counts(r#"{"verus":{}}"#).is_err());

    let names = vec!["lib::source::may_overwrite".to_owned()];
    assert_eq!(
        verify::parse_functions(&report_with(1, 0, &names)),
        Some(names)
    );
    let failed = r#"{"func-details":{"lib::a::f":{"failed_proof_notes":["x"]},"lib::a::g":{}}}"#;
    assert_eq!(
        verify::parse_functions(failed),
        Some(vec!["lib::a::g".to_owned()]),
        "a function with a failed proof note does not count"
    );
    assert_eq!(verify::parse_functions(module_run), None);

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
    assert_eq!(verify::spec_functions(text), ["one", "three"]);
    let method = "impl R {\n    #[verus_spec(r => ensures r@[0] == 1)]\n    #[expect(clippy::x, reason = \"fn y\")]\n    pub const fn get(&self) -> u8 { 1 }\n}\n";
    assert_eq!(verify::spec_functions(method), ["get"]);
    assert_eq!(
        verify::spec_functions("#[verus_spec(r => ensures true)]\npub struct S;\n"),
        Vec::<String>::new(),
        "a spec item without a function gives no name"
    );
}

#[test]
fn verify_finds_unproved_functions() {
    let spec = vec!["new".to_owned(), "new".to_owned(), "cstr".to_owned()];
    let proved = vec![
        "lib::reader::Reader::new".to_owned(),
        "lib::reader::Other::new".to_owned(),
        "lib::reader::Reader::cstr".to_owned(),
        "lib::range::Range::new".to_owned(),
    ];
    assert_eq!(
        verify::unproved("reader", &spec, &proved),
        Vec::<String>::new()
    );
    let one_new = &proved[1..];
    assert_eq!(verify::unproved("reader", &spec, one_new), ["new"]);
    assert_eq!(
        verify::unproved("range", &spec, &proved),
        ["new", "cstr"],
        "a name counts only in the module of the kernel"
    );
    assert_eq!(
        verify::unproved("rangeset", &["new".to_owned()], &proved),
        ["new"]
    );
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

/// Runs the `xtask` binary with `args` and no Verus. Gives the exit code and the JSON report.
fn xtask_without_verus(args: &[&str], optional: bool) -> (Option<i32>, Value) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"));
    command.args(args).env("VERUS", "").env("PATH", "");
    if optional {
        command.env("GHIDORAH_VERUS_OPTIONAL", "1");
    } else {
        command.env_remove("GHIDORAH_VERUS_OPTIONAL");
    }
    let out = command.output().expect("the xtask binary starts");
    let stdout = String::from_utf8(out.stdout).expect("the report is UTF-8");
    let report = json::parse(stdout.trim()).expect("the binary prints one JSON object");
    (out.status.code(), report)
}

#[test]
fn verify_is_a_command_of_the_binary() {
    let (code, report) = xtask_without_verus(&["verify"], true);
    assert_eq!(code, Some(0), "{report:?}");
    assert_eq!(
        report.get("status").and_then(Value::as_str),
        Some("skipped")
    );

    let (code, report) = xtask_without_verus(&["verify"], false);
    assert_eq!(code, Some(1), "{report:?}");
    assert_eq!(
        report.get("status").and_then(Value::as_str),
        Some("missing")
    );

    // An argument gives a usage error from `verify`, not the usage text of the binary.
    let (code, report) = xtask_without_verus(&["verify", "--x"], true);
    assert_eq!(code, Some(2), "{report:?}");
    let error = report.get("error").and_then(Value::as_str).unwrap_or("");
    assert!(error.contains("cargo xtask verify (no argument"), "{error}");

    // The usage text of the binary names the command.
    let (code, report) = xtask_without_verus(&["no-such-command"], true);
    assert_eq!(code, Some(2), "{report:?}");
    let error = report.get("error").and_then(Value::as_str).unwrap_or("");
    assert!(error.contains("|verify|"), "{error}");
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
    fake_verus_with(dir, good, bad, &negative_table())
}

/// Writes a fake Verus program. The copy of the negative patch `name` fails with `kind`.
/// The copy of another patch fails with a postcondition error.
#[cfg(unix)]
fn fake_verus_with(dir: &Path, good: &str, bad: &str, kinds: &[(&str, &str)]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("fake-verus");
    let fail = |pattern: &str, kind: &str| {
        format!("  {pattern})\n    echo 'error: {kind}' >&2\n    echo '{bad}'\n    exit 1 ;;\n")
    };
    let mut arms: String = kinds
        .iter()
        .map(|(name, kind)| fail(&format!("*/xtask-verify/{name}"), kind))
        .collect();
    arms.push_str(&fail("*xtask-verify*", POSTCONDITION));
    let script = format!(
        "#!/bin/sh\ncase \"$PWD\" in\n{arms}esac\necho \"$@\" >> \"{log}\"\necho '{good}'\n",
        log = dir.join("argv.log").display()
    );
    std::fs::write(&path, script).expect("the script is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the script is executable");
    path
}

/// Gives the `func-details` name of each spec function of each kernel under `root`.
fn kernel_functions(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for kernel in KERNELS {
        let mut files = vec![root.join(kernel.file())];
        if let Ok(entries) = std::fs::read_dir(root.join(kernel.dir())) {
            files.extend(entries.map(|e| e.expect("the directory entry is readable").path()));
        }
        for file in files {
            let text = std::fs::read_to_string(&file).expect("the kernel file is readable");
            for name in verify::spec_functions(&text) {
                names.push(format!("lib::{}::Item::{name}", kernel.module));
            }
        }
    }
    names
}

#[cfg(unix)]
#[test]
fn regress_verify_requires_each_spec_function() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_fake_external");
    let _ = std::fs::remove_dir_all(&dir);
    copy_inputs(&dir);
    let all = kernel_functions(&dir);
    let hidden = "lib::flags::Item::eval_pred";
    let some: Vec<String> = all.iter().filter(|n| *n != hidden).cloned().collect();
    assert_eq!(some.len() + 1, all.len(), "the kernels have {hidden}");
    // `#[verus_verify(external)]` removes a function from the Verus output, not from the count.
    let verus = fake_verus(&dir, &report_with(500, 0, &some), &report(2, 1));
    let settings = Settings {
        verus: Some(verus),
        z3: None,
        optional: false,
    };
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(false), "{out}");
    assert_eq!(status_of(&out, "K5"), Some("failed"), "{out}");
    assert_eq!(status_of(&out, "K1"), Some("verified"), "{out}");
    assert_eq!(
        out.pointer("/kernels/K5/unproved"),
        Some(&Value::Array(vec![Value::from("eval_pred")])),
        "{out}"
    );
    // A run without `func-details` proves no function.
    let verus = fake_verus(
        &dir,
        &report(500, 0).replace("\"func-details\":{},", ""),
        "",
    );
    let settings = Settings {
        verus: Some(verus),
        ..settings
    };
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(status_of(&out, "K7"), Some("failed"), "{out}");
}

/// Gives the status of the kernel `name` in a report.
fn status_of<'a>(out: &'a Value, name: &str) -> Option<&'a str> {
    out.pointer(&format!("/kernels/{name}/status"))
        .and_then(Value::as_str)
}

#[cfg(unix)]
#[test]
fn verify_run_with_a_fake_verus() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_fake_run");
    let _ = std::fs::remove_dir_all(&dir);
    copy_inputs(&dir);
    let verus = fake_verus(
        &dir,
        &report_with(500, 0, &kernel_functions(&dir)),
        &report(2, 1),
    );
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
    let table = negative_table();
    assert_eq!(negatives.len(), table.len());
    for (row, (name, kind)) in negatives.iter().zip(table) {
        assert_eq!(row.get("ok").and_then(Value::as_bool), Some(true), "{row}");
        assert_eq!(row.get("error_kind").and_then(Value::as_str), Some(kind));
        assert_eq!(
            row.get("patch").and_then(Value::as_str),
            Some(format!("verify/negative/{name}.patch").as_str())
        );
    }
    let log = std::fs::read_to_string(dir.join("argv.log")).expect("the fake Verus ran");
    assert!(log.contains("--verify-module reader"), "{log}");
    assert!(
        log.lines()
            .all(|l| l.starts_with("--cfg verus_only --no-cheating")),
        "{log}"
    );
}

#[cfg(unix)]
#[test]
fn regress_verify_failed_run_keeps_the_record() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_fake_failed");
    let _ = std::fs::remove_dir_all(&dir);
    copy_inputs(&dir);
    let verus = fake_verus(
        &dir,
        &report_with(500, 0, &kernel_functions(&dir)),
        &report(2, 1),
    );
    let settings = Settings {
        verus: Some(verus),
        z3: None,
        optional: false,
    };
    let record = dir.join(tree::RESULTS_PATH);
    let failed = dir.join(verify::FAILED_PATH);
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(true), "{out}");
    let good = std::fs::read_to_string(&record).expect("a good run writes the record");
    assert!(!failed.exists(), "a good run writes no failed record");

    // A stale negative patch makes the run fail. The failed run keeps the good record.
    let k1 = dir.join("verify/negative/K1.patch");
    let stale = std::fs::read_to_string(&k1)
        .expect("K1.patch exists")
        .replace("\n ", "\n x");
    std::fs::write(&k1, stale).expect("the patch is writable");
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(false), "{out}");
    assert_eq!(
        out.get("results").and_then(Value::as_str),
        Some(verify::FAILED_PATH)
    );
    assert_eq!(
        std::fs::read_to_string(&record).expect("the record stays"),
        good
    );
    let text = std::fs::read_to_string(&failed).expect("a failed run writes the failed record");
    let row = json::parse(&text)
        .expect("the failed record is JSON")
        .pointer("/negatives/0/ok")
        .cloned();
    assert_eq!(row, Some(Value::Bool(false)), "{text}");

    // The next good run removes the failed record.
    copy_dir(
        &root().join("verify/negative"),
        &dir.join("verify/negative"),
    );
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(true), "{out}");
    assert!(!failed.exists(), "a good run removes the failed record");
}

#[cfg(unix)]
#[test]
fn regress_negative_needs_its_expected_kind() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify_fake_kind");
    let _ = std::fs::remove_dir_all(&dir);
    copy_inputs(&dir);
    // Every copy fails with a postcondition error. K3 expects a precondition error.
    let verus = fake_verus_with(
        &dir,
        &report_with(500, 0, &kernel_functions(&dir)),
        &report(2, 1),
        &[],
    );
    let settings = Settings {
        verus: Some(verus),
        z3: None,
        optional: false,
    };
    let out = verify::run_with(&dir, &settings).expect("the run gives a report");
    assert_eq!(out.get("ok").and_then(Value::as_bool), Some(false), "{out}");
    let negatives = out
        .get("negatives")
        .and_then(Value::as_array)
        .expect("negatives");
    for row in negatives {
        let name = row.get("kernel").and_then(Value::as_str).unwrap_or("");
        let ok = row.get("ok").and_then(Value::as_bool);
        assert_eq!(ok, Some(name != "K3"), "{row}");
        if name == "K3" {
            assert_eq!(
                row.get("expected_kind").and_then(Value::as_str),
                Some(PRECONDITION),
                "{row}"
            );
        }
    }
}

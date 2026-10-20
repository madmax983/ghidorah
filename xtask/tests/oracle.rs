//! Tests of `xtask oracle`: the list parser, the vector files, the host boundary record and
//! the AC-066 record.

use std::path::PathBuf;

use xtask::Error;
use xtask::json::{self, Value};
use xtask::oracle::{self, RECORD, RESULT_PREFIX};

fn root() -> PathBuf {
    xtask::workspace::root()
}

#[test]
fn oracle_cpu_model() {
    let text = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Processor @ 2.80GHz\nflags\t: x\nmodel name\t: other\n";
    assert_eq!(
        oracle::cpu_model(text),
        "Intel(R) Xeon(R) Processor @ 2.80GHz"
    );
    assert_eq!(oracle::cpu_model("flags : x\n"), "unknown");
}

#[test]
fn oracle_list_lines() {
    let list = oracle::parse_list("alu2\tadd al, cl\nshift\tshl eax, cl\n").expect("a list");
    assert_eq!(
        list,
        vec![
            ("alu2".to_owned(), "add al, cl".to_owned()),
            ("shift".to_owned(), "shl eax, cl".to_owned()),
        ]
    );
    assert!(matches!(
        oracle::parse_list("no tab\n"),
        Err(Error::Data { .. })
    ));
    assert!(matches!(
        oracle::parse_list("../x\tname\n"),
        Err(Error::Data { .. })
    ));
    assert_eq!(oracle::parse_list("").expect("an empty list"), Vec::new());
}

#[test]
fn oracle_files_group_forms() {
    let list = vec![
        ("b".to_owned(), "f1".to_owned()),
        ("a".to_owned(), "f2".to_owned()),
        ("b".to_owned(), "f3".to_owned()),
    ];
    let outputs = vec![
        "H1\nV1\n".to_owned(),
        "H2\n".to_owned(),
        "H3\nV3\n".to_owned(),
    ];
    let files = oracle::render_files("Some CPU", &list, &outputs);
    assert_eq!(files.keys().cloned().collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(
        files["b"],
        "{\"golden\":\"generator=xtask-oracle version=1 cpu=Some_CPU forms=2\"}\nH1\nV1\nH3\nV3\n"
    );
    assert_eq!(
        files["a"],
        "{\"golden\":\"generator=xtask-oracle version=1 cpu=Some_CPU forms=1\"}\nH2\n"
    );
}

#[test]
fn oracle_header_cpu() {
    let files = oracle::render_files(
        "Some CPU",
        &[("a".to_owned(), "f".to_owned())],
        &["H\n".to_owned()],
    );
    assert_eq!(oracle::header_cpu(&files["a"]).as_deref(), Some("Some_CPU"));
    assert_eq!(oracle::header_cpu("no header\n"), None);
    assert_eq!(oracle::header_cpu(""), None);
}

#[test]
fn oracle_bash_record() {
    let stdout = format!(
        "running 1 test\n{RESULT_PREFIX}{{\"objdump\":\"GNU objdump 2.42\",\"bash\":{{\"insns\":3,\"agree\":3}}}}\ntest ok\n"
    );
    let record = oracle::bash_record(&stdout).expect("a record");
    assert_eq!(
        record.pointer("/bash/agree").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        record.get("generator").and_then(Value::as_str),
        Some("xtask-oracle")
    );
    assert_eq!(record.get("version").and_then(Value::as_str), Some("1"));
    assert!(matches!(
        oracle::bash_record("no line\n"),
        Err(Error::Data { .. })
    ));
    let bad = format!("{RESULT_PREFIX}{{bad\n");
    assert!(matches!(oracle::bash_record(&bad), Err(Error::Data { .. })));
}

/// Gives the output of the host boundary test with `(insns, agree, mismatches)` of bash and libc.
fn bash_stdout(bash: (u64, u64, u64), libc: (u64, u64, u64)) -> String {
    let entry = |(insns, agree, mismatches): (u64, u64, u64)| {
        format!(r#"{{"insns":{insns},"agree":{agree},"mismatches":{mismatches},"sha256":"aa"}}"#)
    };
    format!(
        "running 1 test\n{RESULT_PREFIX}{{\"objdump\":\"GNU objdump 2.42\",\"bash\":{},\"libc\":{}}}\n",
        entry(bash),
        entry(libc)
    )
}

#[test]
fn regress_oracle_failed_run_keeps_the_record() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("oracle_failed_run");
    let _ = std::fs::remove_dir_all(&dir);
    let record = dir.join(RECORD);
    let failed = dir.join(oracle::FAILED_RECORD);
    let good = bash_stdout((10, 10, 0), (20, 20, 0));
    let report = oracle::bash_report(&dir, true, &good).expect("a report");
    assert_eq!(
        report.get("ok").and_then(Value::as_bool),
        Some(true),
        "{report}"
    );
    let kept = std::fs::read_to_string(&record).expect("a good run writes the record");
    assert!(!failed.exists());

    let bad_runs = [
        (true, bash_stdout((10, 7, 3), (20, 20, 0))),
        (true, bash_stdout((10, 10, 0), (20, 19, 0))),
        (false, good.clone()),
    ];
    for (test_ok, stdout) in bad_runs {
        let report = oracle::bash_report(&dir, test_ok, &stdout).expect("a report");
        assert_eq!(
            report.get("ok").and_then(Value::as_bool),
            Some(false),
            "{report}"
        );
        assert_eq!(
            report.get("record").and_then(Value::as_str),
            Some(oracle::FAILED_RECORD)
        );
        assert_eq!(
            std::fs::read_to_string(&record).expect("the record stays"),
            kept
        );
        assert!(failed.exists(), "a failed run writes the failed record");
    }
    let report = oracle::bash_report(&dir, true, &good).expect("a report");
    assert_eq!(
        report.get("ok").and_then(Value::as_bool),
        Some(true),
        "{report}"
    );
    assert!(!failed.exists(), "a good run removes the failed record");
}

#[test]
fn oracle_usage() {
    for args in [
        &[][..],
        &["bogus"][..],
        &["semantics", "--bad"][..],
        &["bash", "x"][..],
    ] {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let err = oracle::run(&root(), &args).expect_err("a usage error");
        assert!(matches!(err, Error::Usage(_)), "{args:?}: {err}");
    }
}

#[test]
fn ac_066_host_boundary_record() {
    let text = std::fs::read_to_string(root().join(RECORD)).expect("the oracle record");
    let record = json::parse(&text).expect("JSON");
    for key in ["bash", "libc"] {
        let entry = record.get(key).expect("an entry");
        let sha = entry
            .get("sha256")
            .and_then(Value::as_str)
            .expect("a sha256");
        assert_eq!(sha.len(), 64, "{key}: sha256");
        let insns = entry.get("insns").and_then(Value::as_u64).expect("insns");
        let agree = entry.get("agree").and_then(Value::as_u64).expect("agree");
        assert!(insns > 10_000, "{key}: {insns} instructions");
        assert_eq!(agree, insns, "{key}: 100% agreement");
        assert_eq!(
            entry.get("mismatches").and_then(Value::as_u64),
            Some(0),
            "{key}"
        );
    }
    assert!(
        record
            .get("objdump")
            .and_then(Value::as_str)
            .is_some_and(|v| v.contains("objdump"))
    );
}

#[test]
#[ignore = "tier2"]
fn tier2_oracle_semantics_check() {
    let args = vec!["semantics".to_owned(), "--check".to_owned()];
    let report = oracle::run(&root(), &args).expect("the check runs");
    assert_eq!(
        report.get("ok").and_then(Value::as_bool),
        Some(true),
        "{}",
        json::write(&report)
    );
}

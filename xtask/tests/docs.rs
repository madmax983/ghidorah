//! Doc and evidence tests of WP-28: AC-018a, AC-018b, AC-023a, AC-023b and AC-027.
//!
//! Each test checks the real repository and synthetic bad inputs.
#![allow(
    clippy::expect_used,
    reason = "test helpers stop at the first failure with a message"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use xtask::ac::{self, AcRow, Evidence, Op, Tier};
use xtask::acrun::table::{self, Row};
use xtask::acrun::{self, Outcome, Status, record};
use xtask::gates::docs;
use xtask::gates::ledger::{self, DataFile};
use xtask::json::{self, Value};
use xtask::{Finding, workspace};

fn root() -> PathBuf {
    workspace::root()
}

fn render(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn design_rows() -> Vec<AcRow> {
    let text = std::fs::read_to_string(root().join(ac::DESIGN_PATH)).expect("design reads");
    let (rows, grammar) = ac::parse_rows(&text);
    assert!(grammar.is_empty(), "{}", render(&grammar));
    rows
}

fn gate_ids() -> BTreeSet<String> {
    design_rows()
        .into_iter()
        .filter(AcRow::is_gate)
        .map(|r| r.id)
        .collect()
}

fn adr(number: &str, status: &str, body: &str) -> (String, String) {
    (
        format!("{number}-sample.md"),
        format!("# ADR-{number}: Sample\n\nStatus: {status}\nDate: 2026-10-17\n{body}"),
    )
}

#[test]
fn ac_023a_docs_present() {
    let found = docs::check_present(&root()).expect("the check runs");
    assert!(found.is_empty(), "{}", render(&found));
    assert_eq!(docs::missing_docs(&|_| false).len(), docs::REQUIRED.len());
    assert!(docs::missing_docs(&|_| true).is_empty());
    let only_readme = docs::missing_docs(&|p| p != "README.md");
    assert_eq!(only_readme.len(), 1);
    assert_eq!(only_readme[0].path, "README.md");
    let readme = "See [the design](docs/design.md), [the web](https://example.org), \
                  [a part](#quick-start), [the ADRs](docs/adr/) and [gone](docs/nope.md#a).";
    let exists = |p: &str| p == "docs/design.md" || p == "docs/adr/";
    let found = docs::readme_links(readme, &exists);
    assert_eq!(found.len(), 1, "{}", render(&found));
    assert!(found[0].detail.contains("docs/nope.md"), "{}", found[0]);
}

#[test]
fn adr_index_matches_files() {
    let index = std::fs::read_to_string(root().join(docs::ADR_INDEX)).expect("index reads");
    let files = docs::adr_files(&root()).expect("ADRs read");
    assert!(files.len() >= 29, "{}", files.len());
    let rows = docs::index_rows(&index);
    assert_eq!(rows.len(), files.len());
    assert_eq!(rows[0].number, "0001");
    assert_eq!(rows[0].file, "0001-zero-third-party-dependencies.md");
    let found = docs::adr_index(&index, &files);
    assert!(found.is_empty(), "{}", render(&found));
    assert!(docs::is_adr_file("0001-zero-third-party-dependencies.md"));
    assert!(!docs::is_adr_file("README.md"));
    assert!(!docs::is_adr_file("01-short.md"));

    let header = "| ADR | Title | Status | Decision in one line |\n|---|---|---|---|\n";
    let one = adr("0001", "Accepted", "## Alternatives\n");
    let amended = adr(
        "0002",
        "Accepted (amended 2026-10-17)",
        "## Amendment 2026-10-17\n",
    );
    let good = format!(
        "{header}| [0001](0001-sample.md) | Sample | Accepted | One. |\n\
         | [0002](0002-sample.md) | Sample | Accepted (amended) | Two. |\n"
    );
    let pair = [one.clone(), amended.clone()];
    assert!(docs::adr_index(&good, &pair).is_empty());
    let unlisted = format!("{header}| [0001](0001-sample.md) | Sample | Accepted | One. |\n");
    assert_eq!(docs::adr_index(&unlisted, &pair).len(), 1);
    assert_eq!(docs::adr_index(&good, std::slice::from_ref(&one)).len(), 1);
    let stale = good.replace("Accepted (amended)", "Accepted");
    assert_eq!(docs::adr_index(&stale, &pair).len(), 1);
    let wrong_number = good.replace("[0002](0002", "[0003](0002");
    assert_eq!(docs::adr_index(&wrong_number, &pair).len(), 1);
    let no_status = (one.0.clone(), one.1.replace("Status: Accepted\n", ""));
    let found = docs::adr_index(&good, &[no_status, amended]);
    assert!(
        found.iter().any(|f| f.detail.contains("Status")),
        "{}",
        render(&found)
    );
}

#[test]
fn ac_023b_adr_sections() {
    let found = docs::check_adrs(&root()).expect("the check runs");
    assert!(found.is_empty(), "{}", render(&found));
    let acs: BTreeSet<String> = ["AC-001a", "AC-175a", "AC-175b", "AC-185", "AC-018a"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let text = |verified: &str, alternatives: bool| {
        let alt = if alternatives {
            "## Alternatives\n"
        } else {
            ""
        };
        format!("# ADR-0001: X\n\nStatus: Accepted\n{verified}\n## Context\n{alt}")
    };
    let ok = text("Verified by: AC-001a, AC-175 to AC-185 (all sub-ACs)", true);
    assert!(docs::adr_sections("a.md", &ok, &acs).is_empty());
    assert_eq!(
        docs::adr_sections("a.md", &text("Verified by: AC-001a", false), &acs).len(),
        1
    );
    assert_eq!(
        docs::adr_sections("a.md", &text("Proved by: AC-001a", true), &acs).len(),
        1
    );
    let unknown = docs::adr_sections("a.md", &text("Verified by: AC-999, AC-018a", true), &acs);
    assert_eq!(unknown.len(), 1, "{}", render(&unknown));
    assert!(unknown[0].detail.contains("AC-999"));
    assert_eq!(unknown[0].rule, "AC-023b");
}

#[test]
fn ac_027_license_ledger() {
    let found = ledger::check_ledger(&root()).expect("the check runs");
    assert!(found.is_empty(), "{}", render(&found));
    let files = ledger::data_files(&root()).expect("data files read");
    assert!(
        files
            .iter()
            .any(|f| f.path == "crates/types/data/noreturn_elf.txt")
    );
    assert!(ledger::glob_match(
        "tests/data/jsontestsuite/*.json",
        "tests/data/jsontestsuite/y_true.json"
    ));
    assert!(!ledger::glob_match(
        "tests/data/jsontestsuite/*.json",
        "tests/data/jsontestsuite/LICENSE"
    ));
    assert!(!ledger::glob_match(
        "tests/data/*.json",
        "tests/data/a/b.json"
    ));
    assert!(ledger::glob_match("a/b.txt", "a/b.txt"));

    let ledger = "| File | Source | License | Added by |\n|---|---|---|---|\n\
                  | `crates/x/data/list.txt` (2 names) | Upstream | MIT | WP-10 |\n\
                  | `tests/data/corpus/*.json` | Corpus | MIT | WP-04 |\n";
    let notice = "Vendored data files:\n\n- crates/x/data/list.txt: a list.\n\
                  - tests/data/corpus/*.json: a corpus.\n";
    let text = |path: &str, head: &str| DataFile {
        path: path.to_owned(),
        head: Some(head.to_owned()),
    };
    let header =
        "# Source: Upstream (https://example.org).\n# Copyright 2020 Someone. MIT License.\n";
    let good = vec![
        text("crates/x/data/list.txt", header),
        text(
            "crates/x/data/own.txt",
            "# Source: ghidorah. License: Apache-2.0.\n",
        ),
        text("tests/data/corpus/LICENSE", "MIT License\n"),
        text(
            "tests/data/corpus/README.md",
            "- Source: the corpus.\n- License: MIT.\n",
        ),
        DataFile {
            path: "tests/data/corpus/a.json".to_owned(),
            head: None,
        },
        text("tests/data/own.jsonl", "{\"a\":1}\n"),
    ];
    let found = ledger::license_ledger(notice, ledger, &good);
    assert!(found.is_empty(), "{}", render(&found));
    let rows = ledger::ledger_rows(ledger);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].pattern, "crates/x/data/list.txt");
    assert_eq!(rows[1].license, "MIT");

    let mut unlisted = good.clone();
    unlisted.push(text(
        "tests/data/other.txt",
        "# Copyright 2019 Another. BSD.\n",
    ));
    assert_eq!(ledger::license_ledger(notice, ledger, &unlisted).len(), 1);
    let mut corpus = good.clone();
    corpus.push(text("tests/data/corpus2/LICENSE", "MIT License\n"));
    corpus.push(DataFile {
        path: "tests/data/corpus2/b.json".to_owned(),
        head: None,
    });
    let found = ledger::license_ledger(notice, ledger, &corpus);
    assert!(
        found.iter().any(|f| f.path == "tests/data/corpus2/b.json"),
        "{}",
        render(&found)
    );
    let no_notice = notice.replace("- crates/x/data/list.txt: a list.\n", "");
    assert_eq!(ledger::license_ledger(&no_notice, ledger, &good).len(), 1);
    let extra_notice = format!("{notice}- tests/data/gone.txt: a file.\n");
    assert_eq!(
        ledger::license_ledger(&extra_notice, ledger, &good).len(),
        1
    );
    let no_file: Vec<DataFile> = good
        .iter()
        .filter(|f| f.path != "crates/x/data/list.txt")
        .cloned()
        .collect();
    assert_eq!(ledger::license_ledger(notice, ledger, &no_file).len(), 1);
    let mut no_source = good;
    no_source[1] = text("crates/x/data/own.txt", "# A list of names.\n");
    assert_eq!(ledger::license_ledger(notice, ledger, &no_source).len(), 1);
}

#[test]
fn ac_018a_every_ac_has_evidence() {
    let rows = design_rows();
    assert!(ac::missing(&rows).is_empty(), "{:?}", ac::missing(&rows));
    let report = ac::run(&root(), &[]).expect("xtask ac runs");
    assert_eq!(report.pointer("/missing"), Some(&Value::Array(Vec::new())));
    assert!(
        report
            .pointer("/failed")
            .and_then(Value::as_array)
            .is_some(),
        "{report}"
    );
    let text = "| AC-901 | Gate. | - | 28 | - |\n\
                | AC-902 | Removed in revision 3 (x). | - | - | - |\n\
                | AC-903 | Moved to stretch S1 (x). | - | - | - |\n\
                | AC-904 | Gate. | `test:xtask::a@T1` | 28 | - |\n";
    let (rows, grammar) = ac::parse_rows(text);
    assert!(grammar.is_empty());
    assert_eq!(ac::missing(&rows), ["AC-901"]);
}

fn outcome(id: &str, kind: &'static str, status: Status) -> Outcome {
    Outcome {
        ac: id.to_owned(),
        tier: Tier::T1,
        kind,
        status,
    }
}

fn gate_row(id: &str, evidence: Vec<Evidence>) -> AcRow {
    AcRow {
        id: id.to_owned(),
        line: 1,
        stretch: false,
        removed: false,
        evidence,
        closes: vec!["28".to_owned()],
        needs: Vec::new(),
    }
}

#[test]
fn ac_018b_evidence_passes() {
    // The record check of each named input.
    let record = json::parse(
        r#"{"tree_sha256":"aa","kernels":{"K1":{"status":"verified"}},
            "bash":{"path":"/usr/bin/bash","sha256":"bb"}}"#,
    )
    .expect("record parses");
    assert_eq!(record::expected(&record, "/kernels/K1", "tree"), Some("aa"));
    assert_eq!(record::expected(&record, "/bash", "host-bash"), Some("bb"));
    let check = |pointer: &str, input: &str, current: Option<&str>| {
        record::record_match(&record, pointer, input, current)
    };
    assert_eq!(check("/kernels/K1", "tree", Some("aa")), Status::Recorded);
    assert_eq!(check("/kernels/K1", "tree", Some("ab")), Status::Fail);
    assert_eq!(check("/kernels/K1", "tree", None), Status::Fail);
    assert_eq!(check("/kernels/K9", "tree", Some("aa")), Status::Fail);
    assert_eq!(check("/bash", "host-bash", Some("bb")), Status::Recorded);
    assert_eq!(check("/bash", "host-bash", Some("bc")), Status::Fail);
    assert_eq!(check("/bash", "host-bash", None), Status::Skipped);
    assert_eq!(check("/bash", "other", Some("bb")), Status::Fail);
    // The tree record of the repository matches its proof inputs.
    for kernel in ["K1", "K2", "K3", "K5", "K6", "K7"] {
        let pointer = format!("/kernels/{kernel}");
        let status = record::status(&root(), "verify/results.json", &pointer, "tree");
        assert_eq!(status, Status::Recorded, "{kernel}");
    }
    assert_eq!(
        record::status(&root(), "verify/none.json", "/kernels", "tree"),
        Status::Fail
    );

    // The failed list and the merge of a partial run.
    let design = vec![
        gate_row("AC-001", Vec::new()),
        gate_row("AC-002", Vec::new()),
    ];
    let old = vec![
        Row::new(&outcome("AC-002", "test", Status::Fail), "c1"),
        Row::new(&outcome("AC-001", "test", Status::Pass), "c1"),
        Row::new(&outcome("AC-777", "test", Status::Pass), "c1"),
    ];
    assert_eq!(
        json::write(&table::failed(&old)),
        r#"[{"ac":"AC-002","kind":"test","tier":"T1"}]"#
    );
    let ran: BTreeSet<String> = std::iter::once("AC-002".to_owned()).collect();
    let new = vec![
        Row::new(&outcome("AC-002", "test", Status::Pass), "c2"),
        Row::new(&outcome("AC-002", "record", Status::Recorded), "c2"),
    ];
    let merged = table::merge(&old, &ran, &new, &design);
    let ids: Vec<(&str, &str)> = merged
        .iter()
        .map(|r| (r.ac.as_str(), r.commit.as_str()))
        .collect();
    assert_eq!(ids, [("AC-001", "c1"), ("AC-002", "c2"), ("AC-002", "c2")]);
    assert_eq!(table::failed(&merged), Value::Array(Vec::new()));
    let text = format!(
        "[\n{}\n]\n",
        merged
            .iter()
            .map(|r| json::write(&r.to_json()))
            .collect::<Vec<_>>()
            .join(",\n")
    );
    assert_eq!(table::parse(&text), Ok(merged));
    assert!(table::parse("{}").is_err());
    assert_eq!(Status::parse("recorded"), Some(Status::Recorded));
    assert_eq!(Status::parse("other"), None);

    // An `xtask:ac` item runs after the table of its run exists.
    let own = Evidence::Xtask {
        sub: "ac".to_owned(),
        pointer: "/failed".to_owned(),
        op: Op::Eq,
        value: "[]".to_owned(),
    };
    let plain = Evidence::Test {
        krate: "xtask".to_owned(),
        func: "a".to_owned(),
        tier: Tier::T1,
    };
    assert!(acrun::is_self(&own) && !acrun::is_self(&plain));
    let rows = vec![
        gate_row("AC-018b", vec![own.clone()]),
        gate_row("AC-020", vec![plain.clone(), own]),
        gate_row("AC-021", vec![plain]),
    ];
    let (first, last) = acrun::split_self(&rows);
    let first_ids: Vec<&str> = first.iter().map(|r| r.id.as_str()).collect();
    let last_ids: Vec<&str> = last.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(first_ids, ["AC-020", "AC-021"]);
    assert_eq!(last_ids, ["AC-018b", "AC-020"]);

    // The committed table covers each MVP AC with evidence and names no other AC.
    let gates = gate_ids();
    let committed = table::read(&root()).expect("the evidence table reads");
    let named: BTreeSet<&str> = committed.iter().map(|r| r.ac.as_str()).collect();
    for row in design_rows()
        .iter()
        .filter(|r| r.is_gate() && !r.evidence.is_empty())
    {
        assert!(named.contains(row.id.as_str()), "{} has no row", row.id);
    }
    for id in &named {
        assert!(gates.contains(*id), "{id} is not an MVP AC");
    }
}

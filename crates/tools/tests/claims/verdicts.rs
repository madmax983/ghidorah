//! The verdict table of `tests/data/claims.jsonl` (AC-159a) and the per-item errors.

use std::collections::BTreeMap;

use ghidorah_json::Value;

use crate::support::{call, claim, data, json, open, root, text_at, texts, verdicts};

/// One line of the verdict table.
struct Case {
    line: usize,
    claim: Value,
    verdict: String,
    evidence: Option<Vec<String>>,
    gaps: Option<Vec<String>>,
    gaps_include: Vec<String>,
}

/// Gives the texts of the array `key` of `value`, or `None` when the key is absent.
fn list(value: &Value, key: &str) -> Option<Vec<String>> {
    value.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

/// Reads the verdict table, grouped by fixture in file order.
fn table() -> BTreeMap<String, Vec<Case>> {
    let text = std::fs::read_to_string(root().join("tests/data/claims.jsonl"))
        .expect("the verdict table exists");
    let mut out: BTreeMap<String, Vec<Case>> = BTreeMap::new();
    for (i, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let row = json(line);
        let fixture = text_at(&row, "/fixture");
        out.entry(fixture).or_default().push(Case {
            line: i + 1,
            claim: row.get("claim").cloned().expect("each line has a claim"),
            verdict: text_at(&row, "/verdict"),
            evidence: list(&row, "evidence"),
            gaps: list(&row, "gaps"),
            gaps_include: list(&row, "gaps_include").unwrap_or_default(),
        });
    }
    out
}

#[test]
fn ac_159a_verdict_table() {
    let table = table();
    assert!(table.len() >= 3, "the table covers three fixtures");
    let mut relations = std::collections::BTreeSet::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut bad = Vec::new();
    for (fixture, cases) in &table {
        let (mut s, _) = open(fixture);
        let claims: Vec<Value> = cases.iter().map(|c| c.claim.clone()).collect();
        let got = verdicts(&mut s, &claims);
        for (case, v) in cases.iter().zip(&got) {
            relations.insert(text_at(&case.claim, "/rel"));
            seen.insert(case.verdict.clone());
            let verdict = text_at(v, "/verdict");
            let evidence = texts(v, "/evidence");
            let gaps = texts(v, "/basis/gaps");
            let mut problems = Vec::new();
            if verdict != case.verdict {
                problems.push(format!("verdict {verdict}, want {}", case.verdict));
            }
            if case.evidence.as_ref().is_some_and(|e| *e != evidence) {
                problems.push(format!("evidence {evidence:?}, want {:?}", case.evidence));
            }
            if case.gaps.as_ref().is_some_and(|g| *g != gaps) {
                problems.push(format!("gaps {gaps:?}, want {:?}", case.gaps));
            }
            for g in &case.gaps_include {
                if !gaps.contains(g) {
                    problems.push(format!("gaps {gaps:?} lack {g}"));
                }
            }
            let complete = v.pointer("/basis/complete").and_then(Value::as_bool);
            if complete != Some(gaps.is_empty()) {
                problems.push(format!("basis.complete {complete:?} with gaps {gaps:?}"));
            }
            if verdict == "refuted" && !gaps.is_empty() {
                problems.push("a refuted verdict has gaps".to_owned());
            }
            if !problems.is_empty() {
                bad.push(format!("line {}: {}: {v}", case.line, problems.join("; ")));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "verdict table mismatches:\n{}",
        bad.join("\n")
    );
    assert_eq!(relations.len(), 10, "the table covers each relation");
    assert_eq!(seen.len(), 3, "the table covers each verdict");
}

#[test]
fn claim_errors_are_per_item() {
    let (mut s, _) = open("demo");
    let claims = [
        claim("calls", &[Value::from("main"), Value::from("imp:puts")]),
        claim("calls", &[Value::from("no_such_fn"), Value::from("main")]),
        claim("calls", &[Value::from("main")]),
        claim(
            "reaches",
            &[Value::from("main"), Value::from("imp:puts"), Value::from(9)],
        ),
        claim("refs_string", &[Value::from("main"), Value::from("a\\")]),
        claim(
            "xref",
            &[
                Value::from("0x10a1"),
                Value::from("0x1060"),
                Value::from("nope"),
            ],
        ),
        claim(
            "has_syscall",
            &[Value::from("main"), Value::from("sys:nope")],
        ),
        claim("uses_import", &[Value::from("main"), Value::from("main")]),
        claim(
            "const_arg",
            &[Value::from("imp:puts"), Value::from(6), Value::from(0)],
        ),
    ];
    let envelope = call(
        &mut s,
        "fact_check",
        &Value::object([("claims", Value::Array(claims.to_vec()))]).to_string(),
    );
    let list = data(&envelope)
        .get("verdicts")
        .and_then(Value::as_array)
        .expect("verdicts");
    assert_eq!(list.len(), claims.len(), "{envelope}");
    let first = list.first().expect("the first verdict");
    assert_eq!(text_at(first, "/verdict"), "supported", "{envelope}");
    let codes: Vec<String> = list
        .iter()
        .skip(1)
        .map(|v| text_at(v, "/error/code"))
        .collect();
    assert_eq!(
        codes,
        [
            "NOT_FOUND",
            "INVALID_ARGUMENT",
            "INVALID_ARGUMENT",
            "INVALID_ARGUMENT",
            "INVALID_ARGUMENT",
            "NOT_FOUND",
            "INVALID_ARGUMENT",
            "INVALID_ARGUMENT",
        ],
        "{envelope}"
    );
    for v in list.iter().skip(1) {
        assert!(v.get("verdict").is_none(), "an error has no verdict: {v}");
        assert!(
            text_at(v, "/error/field_path").starts_with("/claims/"),
            "the error names the claim: {v}"
        );
    }
}

#[test]
fn explain_errors_are_per_item() {
    let (mut s, _) = open("demo");
    let envelope = call(
        &mut s,
        "fact_check",
        r#"{"explain":["fn:0x9999","t:int","0x1080"]}"#,
    );
    let list = data(&envelope)
        .get("explanations")
        .and_then(Value::as_array)
        .expect("explanations");
    assert_eq!(list.len(), 3, "{envelope}");
    let codes: Vec<String> = list.iter().map(|e| text_at(e, "/error/code")).collect();
    assert_eq!(codes, ["NOT_FOUND", "INVALID_ARGUMENT", ""], "{envelope}");
    let tree = list.get(2).expect("the third tree");
    assert_eq!(text_at(tree, "/id"), "0x1080", "{tree}");
    assert_eq!(text_at(tree, "/fact"), "code_unit", "{tree}");
    assert_eq!(text_at(tree, "/rule"), "R_DISASM_FLOW", "{tree}");
}

#[test]
fn fact_check_needs_claims_or_explain() {
    let (mut s, _) = open("demo");
    let envelope = call(&mut s, "fact_check", "{}");
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(false)), "{envelope}");
    assert_eq!(text_at(&envelope, "/error/code"), "MISSING_ARGUMENT");
}

#[test]
fn stale_analysis_weakens_refuted() {
    let (mut s, _) = open("demo");
    let claims = r#"{"claims":[{"rel":"calls","args":["check_password","imp:puts"]},{"rel":"calls","args":["main","imp:puts"]}]}"#;
    let before = call(&mut s, "fact_check", claims);
    assert_eq!(text_at(&before, "/data/verdicts/0/verdict"), "refuted");
    let edit = call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x11d0","max_steps":20}"#,
    );
    assert_eq!(text_at(data(&edit), "/analysis/state"), "stale", "{edit}");
    let after = call(&mut s, "fact_check", claims);
    assert_eq!(after.get("partial"), Some(&Value::Bool(true)), "{after}");
    assert_eq!(
        text_at(&after, "/data/verdicts/0/verdict"),
        "unknown",
        "{after}"
    );
    assert_eq!(
        after.pointer("/data/verdicts/0/basis/complete"),
        Some(&Value::Bool(false)),
        "{after}"
    );
    assert_eq!(
        text_at(&after, "/data/verdicts/1/verdict"),
        "supported",
        "{after}"
    );
}

#[test]
fn unknown_verdict_hints_at_the_gap() {
    let (mut s, _) = open("fixtures/bin/func_ptrs.gcc-O0");
    let envelope = call(
        &mut s,
        "fact_check",
        r#"{"claims":[{"rel":"calls","args":["fire","log_event"]}]}"#,
    );
    assert_eq!(text_at(&envelope, "/data/verdicts/0/verdict"), "unknown");
    let next = envelope
        .get("next")
        .and_then(Value::as_array)
        .expect("a hint");
    let hint = next
        .iter()
        .find(|n| text_at(n, "/tool") == "addr_info")
        .expect("an addr_info hint");
    assert_eq!(text_at(hint, "/args/target"), "0x1302", "{envelope}");
}

#[test]
fn claim_inputs_take_each_form() {
    let (mut s, _) = open("demo");
    let cases: [(&str, &str, &str); 14] = [
        ("calls", r#"["main",4224]"#, "refuted"),
        ("const_arg", r#"["imp:puts",0,-1]"#, "refuted"),
        ("const_arg", r#"["imp:puts",0,"-1"]"#, "refuted"),
        ("const_arg", r#"["imp:puts",0,"check_password"]"#, "refuted"),
        ("reaches", r#"["main","sys:write"]"#, "INVALID_ARGUMENT"),
        (
            "xref",
            r#"["0x10a1","0x1060","unconditional_call"]"#,
            "supported",
        ),
        ("has_syscall", r#"["main",1]"#, "refuted"),
        ("has_syscall", r#"["main","1"]"#, "refuted"),
        ("has_syscall", r#"["main",70000]"#, "INVALID_ARGUMENT"),
        ("has_syscall", r#"["main",true]"#, "INVALID_ARGUMENT"),
        ("reaches", r#"["main"]"#, "INVALID_ARGUMENT"),
        (
            "const_arg",
            r#"["imp:puts",0,"ext:0x3"]"#,
            "INVALID_ARGUMENT",
        ),
        ("uses_import", r#"["main","puts"]"#, "supported"),
        ("in_func", r#"["ext:0x3","main"]"#, "unknown"),
    ];
    let claims: Vec<Value> = cases
        .iter()
        .map(|(rel, args, _)| {
            let list = json(args)
                .as_array()
                .map(<[Value]>::to_vec)
                .unwrap_or_default();
            claim(rel, &list)
        })
        .collect();
    let got = verdicts(&mut s, &claims);
    for ((rel, args, want), entry) in cases.iter().zip(&got) {
        let found = if entry.get("error").is_some() {
            text_at(entry, "/error/code")
        } else {
            text_at(entry, "/verdict")
        };
        assert_eq!(&found, want, "{rel} {args}: {entry}");
    }
    let arity = got.get(10).expect("the arity case");
    assert_eq!(
        text_at(arity, "/error/details/expected"),
        "2 to 3 arguments: f, g, d",
        "{arity}"
    );
    let ext = got.get(13).expect("the EXTERNAL case");
    assert_eq!(texts(ext, "/basis/gaps"), ["ext:0x3"], "{ext}");
}

//! Soundness of negative verdicts: an unresolved indirect site blocks `refuted` (AC-159b), and
//! an unresolved caller blocks a negative `const_arg`.

use ghidorah_json::Value;

use crate::support::{
    call, claim, data, open, open_sites, program, text_at, texts, verdict_of, verdicts,
};

/// The fixtures of the soundness check. The demo binary has no unresolved site: the analysis
/// resolves the weak import slots of its C runtime.
const FIXTURES: [&str; 3] = [
    "fixtures/bin/func_ptrs.gcc-O0",
    "fixtures/bin/func_ptrs.gcc-O2",
    "fixtures/bin/func_ptrs.clang-O2",
];

/// Gives the negative claims about `f`: a call, a path, an import use, a string and an address
/// for each function and each import of the program.
fn negative_claims(funcs: &[String], imports: &[String], f: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for g in funcs.iter().chain(imports) {
        out.push(claim("calls", &[Value::from(f), Value::from(g.as_str())]));
        out.push(claim(
            "reaches",
            &[Value::from(f), Value::from(g.as_str()), Value::from(2)],
        ));
    }
    for i in imports {
        out.push(claim(
            "uses_import",
            &[Value::from(f), Value::from(i.as_str())],
        ));
    }
    for g in funcs {
        let entry = g.trim_start_matches("fn:").to_owned();
        out.push(claim("refs_addr", &[Value::from(f), Value::from(entry)]));
    }
    out.push(claim(
        "refs_string",
        &[
            Value::from(f),
            Value::from("*no text of the binary has this*"),
        ],
    ));
    out
}

#[test]
fn ac_159b_soundness_unresolved_indirect() {
    let mut checked = 0usize;
    for fixture in FIXTURES {
        let (mut s, id) = open(fixture);
        let p = program(&s, id);
        let funcs: Vec<String> = p.funcs().iter().map(|v| v.id().to_string()).collect();
        let imports: Vec<String> = p.imports().keys().map(ToString::to_string).collect();
        let open = open_sites(p);
        assert!(!open.is_empty(), "{fixture} has an unresolved site");
        for (f, sites) in &open {
            let claims = negative_claims(&funcs, &imports, f);
            for (c, v) in claims.iter().zip(verdicts(&mut s, &claims)) {
                checked += 1;
                let verdict = text_at(&v, "/verdict");
                assert_ne!(verdict, "refuted", "{fixture}: {c} -> {v}");
                assert!(!verdict.is_empty(), "{fixture}: {c} -> {v}");
                if verdict == "unknown" {
                    let gaps = texts(&v, "/basis/gaps");
                    assert!(
                        sites.iter().any(|site| gaps.contains(site)),
                        "{fixture}: the gaps of {c} name a site of {sites:?}: {v}"
                    );
                    assert_eq!(
                        v.pointer("/basis/complete"),
                        Some(&Value::Bool(false)),
                        "{v}"
                    );
                }
            }
        }
    }
    assert!(checked > 500, "the check covers {checked} claims");
}

/// The indirect sites of `func_ptrs.gcc-O0` and the targets that resolve each one.
const RESOLVE: [(&str, &str); 2] = [
    ("0x1292", r#"["op_add","op_sub","op_mul","op_div"]"#),
    ("0x1302", r#"["log_event"]"#),
];

#[test]
fn const_arg_unknown_with_unresolved_caller() {
    let (mut s, id) = open("fixtures/bin/func_ptrs.gcc-O0");
    let sites: Vec<String> = open_sites(program(&s, id))
        .into_iter()
        .flat_map(|(_, sites)| sites)
        .collect();
    let want: Vec<String> = RESOLVE.iter().map(|(a, _)| (*a).to_owned()).collect();
    assert_eq!(sites, want, "the open sites of the fixture");
    let miss = verdict_of(&mut s, "const_arg", &["op_mod", "0", "99"]);
    assert_eq!(text_at(&miss, "/verdict"), "unknown", "{miss}");
    let gaps = texts(&miss, "/basis/gaps");
    for site in &want {
        assert!(gaps.contains(site), "the gaps name {site}: {miss}");
    }
    let hit = verdict_of(&mut s, "const_arg", &["op_mod", "0", "20"]);
    assert_eq!(text_at(&hit, "/verdict"), "supported", "{hit}");
    assert_eq!(texts(&hit, "/evidence"), ["0x1411"], "{hit}");
    for (at, targets) in RESOLVE {
        let args = format!(r#"{{"action":"set_call_targets","at":"{at}","targets":{targets}}}"#);
        let envelope = call(&mut s, "func_edit", &args);
        assert_eq!(
            text_at(data(&envelope), "/analysis/state"),
            "complete",
            "{envelope}"
        );
    }
    let miss = verdict_of(&mut s, "const_arg", &["op_mod", "0", "99"]);
    assert_eq!(text_at(&miss, "/verdict"), "refuted", "{miss}");
    assert_eq!(texts(&miss, "/basis/gaps"), Vec::<String>::new(), "{miss}");
    let hit = verdict_of(&mut s, "const_arg", &["op_mod", "0", "20"]);
    assert_eq!(text_at(&hit, "/verdict"), "supported", "{hit}");
    let unknown = verdict_of(&mut s, "const_arg", &["op_add", "0", "20"]);
    assert_eq!(
        text_at(&unknown, "/verdict"),
        "unknown",
        "the table call passes values that block-local evaluation does not know: {unknown}"
    );
    let gaps = texts(&unknown, "/basis/gaps");
    assert!(gaps.contains(&"0x1292".to_owned()), "{unknown}");
    assert!(
        gaps.iter().any(|g| g.starts_with("ref:0x3d80>")),
        "the pointer in the ops table takes the address of op_add: {unknown}"
    );
}

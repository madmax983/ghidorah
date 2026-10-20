//! The shape of the `decomp` section, the IR level `l1`, the budget cut and the agent texts.

use std::path::PathBuf;

use ghidorah_base::{FixedClock, Fuel};
use ghidorah_decomp::Opts;
use ghidorah_json::Value;
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{
    ArgKind, ArgSpec, Call, Host, Roots, Session, SessionConfig, handlers, hints,
};

use crate::support::{
    call, call_value, chars, data, decomp, fixture, json, program, registry, root, session,
    text_at, text_of,
};

#[test]
fn decomp_registry_lint_is_clean() {
    let found = lint(&registry());
    assert!(found.is_empty(), "{found:?}");
}

fn docs(spec: &ArgSpec, out: &mut Vec<String>) {
    out.push(spec.doc.to_owned());
    match spec.kind {
        ArgKind::Obj(members) => members.iter().for_each(|m| docs(m, out)),
        ArgKind::List(item, _) => docs(item, out),
        _ => {}
    }
}

#[test]
fn decomp_texts_are_ste() {
    let tool = &handlers::func_get::SPEC;
    let mut texts = vec![tool.summary.to_owned(), tool.description.to_owned()];
    for spec in tool.args {
        docs(spec, &mut texts);
    }
    texts.extend(
        handlers::func_sections::TEXTS
            .iter()
            .map(|t| (*t).to_owned()),
    );
    let bad: Vec<String> = texts
        .iter()
        .flat_map(|t| {
            check_agent_text(t)
                .into_iter()
                .map(move |f| format!("{t}: {f}"))
        })
        .collect();
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn decomp_section_on_the_demo() {
    let mut s = session();
    let _ = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    let section = decomp(&mut s, "main", "{}");
    for member in [
        "text",
        "line_start",
        "line_count",
        "total_lines",
        "line_map",
        "elided",
        "vars",
        "calls",
        "strings",
        "metrics",
        "warnings",
    ] {
        assert!(section.get(member).is_some(), "no {member}: {section}");
    }
    let text = text_of(&section);
    assert!(text.contains("main("), "{text}");
    assert_eq!(section.get("line_start").and_then(Value::as_u64), Some(1));
    let count = section
        .get("line_count")
        .and_then(Value::as_u64)
        .expect("a count");
    assert_eq!(u64::try_from(text.lines().count()).expect("small"), count);
    let metrics = section.get("metrics").expect("metrics");
    for member in ["goto_count", "label_count", "max_nesting", "stmt_count"] {
        assert!(
            metrics.get(member).and_then(Value::as_u64).is_some(),
            "{member}"
        );
    }
    assert_eq!(text_at(metrics, "/fallback_mode"), "none");
    assert_eq!(text_at(metrics, "/validation/structure"), "ok");
    let rows = section
        .get("line_map")
        .and_then(Value::as_array)
        .expect("rows");
    assert!(!rows.is_empty());
    for row in rows {
        assert!(row.get("line").and_then(Value::as_u64).is_some(), "{row}");
        assert!(text_at(row, "/start").starts_with("0x"), "{row}");
        assert!(row.get("ops").and_then(Value::as_array).is_some(), "{row}");
    }
    let envelope = call(&mut s, "func_list", r#"{"filter":{"visited":true}}"#);
    let visited = data(&envelope)
        .get("items")
        .and_then(Value::as_array)
        .expect("items");
    assert!(
        visited.iter().any(|i| text_at(i, "/name") == "main"),
        "a decomp read marks main visited: {envelope}"
    );
}

#[test]
fn decomp_vars_calls_and_strings() {
    let (mut s, _) = fixture("hello.gcc-O0");
    let section = decomp(&mut s, "finish", "{}");
    let calls = section
        .get("calls")
        .and_then(Value::as_array)
        .expect("calls");
    assert!(
        calls.iter().any(|c| text_at(c, "/name") == "puts"),
        "{section}"
    );
    for c in calls {
        assert!(c.get("line").and_then(Value::as_u64).is_some(), "{c}");
        assert!(text_at(c, "/target").starts_with("0x"), "{c}");
    }
    let strings = section
        .get("strings")
        .and_then(Value::as_array)
        .expect("strings");
    assert!(
        strings.iter().any(
            |s| text_at(s, "/id").starts_with("str:") && text_at(s, "/text/text") == "Goodbye."
        ),
        "{section}"
    );
    let vars = section.get("vars").and_then(Value::as_array).expect("vars");
    assert!(!vars.is_empty(), "{section}");
    for v in vars {
        for member in ["/id", "/name", "/type", "/storage", "/source"] {
            assert!(!text_at(v, member).is_empty(), "{member}: {v}");
        }
        assert!(text_at(v, "/id").starts_with("var:"), "{v}");
    }
}

#[test]
fn ir_level_l1_gives_the_ssa_form() {
    let (mut s, _) = fixture("loops.gcc-O2");
    let envelope = call(
        &mut s,
        "func_get",
        r#"{"target":"gcd","include":["ir"],"ir_opts":{"level":"l1"}}"#,
    );
    let ir = data(&envelope).get("ir").expect("an ir section");
    assert_eq!(text_at(ir, "/level"), "l1", "{ir}");
    let rows = ir.get("insns").and_then(Value::as_array).expect("rows");
    let ops: Vec<String> = rows
        .iter()
        .flat_map(|r| {
            r.get("ops")
                .and_then(Value::as_array)
                .map(<[Value]>::to_vec)
                .unwrap_or_default()
        })
        .filter_map(|o| o.as_str().map(str::to_owned))
        .collect();
    assert!(ops.iter().any(|o| o.contains("Phi")), "{ops:?}");
    assert!(
        ops.iter().all(|o| !o.contains(" Put.")),
        "L1 has no Put: {ops:?}"
    );
    let l0 = call(&mut s, "func_get", r#"{"target":"gcd","include":["ir"]}"#);
    assert_eq!(text_at(data(&l0), "/ir/level"), "l0");
    let l0_ops = chars(data(&l0));
    assert!(l0_ops > chars(ir), "the L1 form is smaller than L0");
}

/// The characters that the cut test takes from the budget of the full window.
const CUT: u64 = 400;

#[test]
fn a_small_budget_cuts_the_window() {
    let (mut s, id) = fixture("large.gcc-O2");
    let p = program(&s, id);
    let longest = p
        .funcs()
        .iter()
        .map(ghidorah_db::FuncView::id)
        .max_by_key(|f| {
            ghidorah_decomp::render(
                p,
                *f,
                &Opts::default(),
                &ghidorah_x86::lift::Names,
                &mut Fuel::new(50_000_000),
            )
            .map_or(0, |o| o.lines.len())
        })
        .expect("a function");
    let target = longest.to_string();
    let args = Value::object([
        ("target", Value::from(target.as_str())),
        ("include", json(r#"["decomp"]"#)),
    ]);
    let whole = call_value(&mut s, "func_get", args);
    let full = data(&whole).get("decomp").expect("a decomp section");
    let total = full
        .get("total_lines")
        .and_then(Value::as_u64)
        .expect("total");
    assert!(total > 20, "{target} has {total} lines");
    assert!(full.get("next_cursor").is_none(), "{full}");
    let small = u64::try_from(chars(&whole)).expect("small") - CUT;
    let args = Value::object([
        ("target", Value::from(target.as_str())),
        ("include", json(r#"["decomp"]"#)),
        ("max_chars", Value::from(small)),
    ]);
    let envelope = call_value(&mut s, "func_get", args);
    assert!(
        u64::try_from(chars(&envelope)).expect("small") <= small,
        "{}",
        chars(&envelope)
    );
    let cut = data(&envelope).get("decomp").expect("a decomp section");
    let count = cut
        .get("line_count")
        .and_then(Value::as_u64)
        .expect("a count");
    assert!(count > 0 && count < total, "{count} of {total}");
    let cursor = text_at(cut, "/next_cursor");
    assert!(!cursor.is_empty(), "{cut}");
    let args = Value::object([
        ("target", Value::from(target.as_str())),
        ("include", json(r#"["decomp"]"#)),
        ("max_chars", Value::from(small)),
        (
            "cursors",
            Value::object([("decomp", Value::from(cursor.as_str()))]),
        ),
    ]);
    let next = call_value(&mut s, "func_get", args);
    let second = data(&next).get("decomp").expect("a decomp section");
    assert_eq!(
        second.get("line_start").and_then(Value::as_u64),
        Some(count + 1),
        "{second}"
    );
    let bad = Value::object([
        ("target", Value::from(target.as_str())),
        ("include", json(r#"["decomp"]"#)),
        ("cursors", Value::object([("decomp", Value::from("00"))])),
    ]);
    let envelope = call_value(&mut s, "func_get", bad);
    assert_eq!(
        text_at(&envelope, "/error/code"),
        "CURSOR_INVALID",
        "{envelope}"
    );
}

/// Makes a session of the shipped registry with the analysis engine, so a remedy can name
/// `func_edit`.
fn shipped() -> Session {
    let config =
        SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"));
    let mut s = Session::new(config, Box::new(FixedClock::new(0)));
    handlers::analysis_run::install(&mut s);
    s
}

/// Gives the warning `code` at `at` of a decompile section.
fn warning_at<'a>(section: &'a Value, code: &str, at: &str) -> Option<&'a Value> {
    section
        .get("warnings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|w| text_at(w, "/code") == code && text_at(w, "/at") == at)
}

/// Makes sure that `remedy` is a call object that `hints::check` accepts in `s`.
fn assert_checked_call(s: &Session, remedy: &Value) {
    let tool = text_at(remedy, "/tool");
    let args = remedy.get("args").cloned().expect("a remedy has args");
    assert!(!text_at(remedy, "/why").is_empty(), "{remedy}");
    let found = Call::new(&tool, args, &text_at(remedy, "/why"));
    let registry = s.active_registry();
    hints::check(&registry, &|name| s.in_profile(name), &found)
        .unwrap_or_else(|e| panic!("{remedy}: {e}"));
}

/// A PLT stub jumps through its GOT slot. Its decompile is a tail call to the import with no
/// `W_JUMPTABLE_UNRESOLVED`. A real unresolved jump keeps the warning, and its remedy is a
/// `func_edit` call that `hints::check` accepts (maintainability-docs-03).
#[test]
fn regress_plt_stub_decomp_tail_call() {
    let mut s = shipped();
    let _ = data(&call(&mut s, "binary_load", r#"{"builtin":"demo"}"#));
    let section = decomp(&mut s, "fn:0x1060", "{}");
    let text = text_of(&section);
    assert!(text.contains("return puts("), "{text}");
    assert!(!text.contains("goto *"), "{text}");
    assert!(
        warning_at(&section, "W_JUMPTABLE_UNRESOLVED", "0x1064").is_none(),
        "{section}"
    );
    let calls = section
        .get("calls")
        .and_then(Value::as_array)
        .expect("calls");
    assert!(
        calls.iter().any(|c| text_at(c, "/name") == "puts"),
        "{section}"
    );
    let mut s = shipped();
    let _ = data(&call(
        &mut s,
        "binary_load",
        r#"{"path":"fixtures/bin/func_ptrs.gcc-O2"}"#,
    ));
    let section = decomp(&mut s, "fn:0x1350", "{}");
    let warning = warning_at(&section, "W_JUMPTABLE_UNRESOLVED", "0x1366")
        .unwrap_or_else(|| panic!("no warning at 0x1366: {section}"));
    let remedy = warning.get("remedy").expect("the warning has a remedy");
    assert_eq!(text_at(remedy, "/tool"), "func_edit", "{remedy}");
    assert_eq!(text_at(remedy, "/args/at"), "0x1366", "{remedy}");
    assert_eq!(
        text_at(remedy, "/args/action"),
        "set_call_targets",
        "{remedy}"
    );
    assert_checked_call(&s, remedy);
}

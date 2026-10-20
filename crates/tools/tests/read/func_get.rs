//! `func_get`: omitted sizes, section cursors, the section split, the visited mark and the
//! section shapes (AC-154a to AC-154c).

use ghidorah_json::Value;
use ghidorah_tools::{Call, Host, hints};

use crate::support::{call, call_value, code, data, demo, fixture, items, json, str_of, text_at};

/// Every section of `func_get` in schema order.
const ALL: [&str; 12] = [
    "summary",
    "disasm",
    "ir",
    "xrefs",
    "callers",
    "callees",
    "strings",
    "vars",
    "notes",
    "why",
    "cfg",
    "jumptables",
];

/// Gives the ID of the largest function of an open fixture.
fn largest(session: &mut ghidorah_tools::Session) -> String {
    let list = call(session, "func_list", r#"{"sort":"size","limit":1}"#);
    str_of(&items(&list)[0], "id")
}

/// Calls `func_get` on `target` with `include` and extra arguments.
fn get(
    session: &mut ghidorah_tools::Session,
    target: &str,
    include: &[&str],
    extra: &str,
) -> Value {
    let mut args = json(extra).as_object().cloned().unwrap_or_default();
    args.push("target", Value::from(target));
    args.push(
        "include",
        Value::Array(include.iter().map(|s| Value::from(*s)).collect()),
    );
    call_value(session, "func_get", Value::Object(args))
}

/// Gives the number of characters of the compact JSON of `value`.
fn size(value: &Value) -> u64 {
    u64::try_from(ghidorah_json::write(value).chars().count()).expect("a size")
}

#[test]
fn ac_154a_omitted_sizes() {
    let (mut session, _) = fixture("switch.gcc-O0");
    let target = largest(&mut session);
    let full = get(
        &mut session,
        &target,
        &ALL,
        r#"{"max_chars":60000,"disasm_limit":2000}"#,
    );
    let full = data(&full).clone();
    assert!(
        full.get("omitted")
            .is_none_or(|o| o.as_object().is_some_and(ghidorah_json::Object::is_empty))
    );
    let (mut sized, mut null) = (0, 0);
    for max in [1_000, 1_500, 2_000, 3_000, 5_000, 8_000] {
        let extra = format!(r#"{{"max_chars":{max},"disasm_limit":2000}}"#);
        let cut = get(&mut session, &target, &ALL, &extra);
        let d = data(&cut);
        let Some(omitted) = d.get("omitted").and_then(Value::as_object) else {
            continue;
        };
        for (section, value) in omitted.iter() {
            assert!(d.get(section).is_none(), "{section} is omitted and present");
            match value {
                Value::Null => null += 1,
                other => {
                    let chars = other.get("chars").and_then(Value::as_u64);
                    let want = full.get(section).map(size);
                    assert_eq!(chars, want, "{section} at {max}");
                    sized += 1;
                }
            }
        }
    }
    assert!(sized > 0, "a cut section reports its size");
    assert!(null > 0, "a section with no render reports null");
}

#[test]
fn ac_154b_section_cursors() {
    let (mut session, _) = fixture("switch.gcc-O0");
    let target = largest(&mut session);
    let full = get(
        &mut session,
        &target,
        &["disasm"],
        r#"{"max_chars":60000,"disasm_limit":2000}"#,
    );
    let all_rows = data(&full)
        .pointer("/disasm/rows")
        .and_then(Value::as_array)
        .expect("the rows")
        .to_vec();
    assert!(all_rows.len() > 10, "{} rows", all_rows.len());
    let mut rows = Vec::new();
    let mut extra = r#"{"disasm_limit":5}"#.to_owned();
    for _ in 0..1_000 {
        let page = get(&mut session, &target, &["disasm"], &extra);
        let d = data(&page);
        let got = d
            .pointer("/disasm/rows")
            .and_then(Value::as_array)
            .expect("the rows");
        assert!(got.len() <= 5);
        rows.extend(got.iter().cloned());
        let Some(next) = d.pointer("/disasm/next_cursor").and_then(Value::as_str) else {
            break;
        };
        extra = format!(r#"{{"disasm_limit":5,"cursors":{{"disasm":"{next}"}}}}"#);
    }
    assert_eq!(
        rows, all_rows,
        "the cursors page the disassembly to its end"
    );
    // A cursor of one function does not fit another function.
    let first = get(&mut session, &target, &["disasm"], r#"{"disasm_limit":2}"#);
    let next = text_at(data(&first), "/disasm/next_cursor");
    let other = str_of(
        &items(&call(
            &mut session,
            "func_list",
            r#"{"sort":"size","limit":2}"#,
        ))[1],
        "id",
    );
    let extra = format!(r#"{{"cursors":{{"disasm":"{next}"}}}}"#);
    let bad = get(&mut session, &other, &["disasm"], &extra);
    assert_eq!(code(&bad), "CURSOR_INVALID", "{bad}");
    let repair = bad.pointer("/next/0/args").expect("a repair call");
    assert!(repair.get("cursors").is_none(), "{repair}");
}

#[test]
fn ac_154c_section_split() {
    let (mut session, _) = fixture("switch.gcc-O0");
    let target = largest(&mut session);
    let orders: [&[&str]; 3] = [
        &["disasm", "cfg"],
        &["cfg", "disasm", "strings"],
        &["summary", "xrefs", "disasm", "callees", "cfg", "ir"],
    ];
    for include in orders {
        for max in [2_000, 4_000, 9_000] {
            let extra = format!(r#"{{"max_chars":{max},"format":"detailed"}}"#);
            let envelope = get(&mut session, &target, include, &extra);
            let budgets = data(&envelope).get("budgets").expect("detailed budgets");
            let mut free = u128::from(budgets.get("total").and_then(Value::as_u64).expect("total"));
            let rows = budgets
                .get("sections")
                .and_then(Value::as_array)
                .expect("the rows");
            let names: Vec<String> = rows.iter().map(|r| str_of(r, "section")).collect();
            assert_eq!(names, include, "the budget rows follow the include order");
            let weight = |s: &str| u128::from(ghidorah_tools::budget::section_weight(s));
            let mut left: u128 = include.iter().map(|s| weight(s)).sum();
            for row in rows {
                let section = str_of(row, "section");
                let field = |k: &str| u128::from(row.get(k).and_then(Value::as_u64).unwrap_or(0));
                assert_eq!(field("weight"), weight(&section), "{section}");
                let share = free * weight(&section) / left;
                assert_eq!(field("share"), share, "{section} at {max} in {include:?}");
                assert!(field("used") <= share, "{section} uses its share at most");
                free -= field("used");
                left -= weight(&section);
            }
        }
    }
}

#[test]
fn func_get_marks_visited() {
    let (mut session, _) = fixture("hello.gcc-O2");
    let visited = |s: &mut ghidorah_tools::Session| {
        items(&call(s, "func_list", r#"{"filter":{"visited":true}}"#))
            .iter()
            .map(|i| str_of(i, "name"))
            .collect::<Vec<_>>()
    };
    let _ = get(&mut session, "main", &["summary", "callees"], "{}");
    assert!(visited(&mut session).is_empty());
    let _ = get(&mut session, "main", &["disasm"], "{}");
    let _ = get(&mut session, "greet", &["ir"], "{}");
    assert_eq!(visited(&mut session), ["main", "greet"]);
}

#[test]
fn func_get_sections_render() {
    let mut session = demo();
    let envelope = get(&mut session, "main", &ALL, r#"{"max_chars":60000}"#);
    let d = data(&envelope);
    for key in ["id", "name", "entry", "size", "start_reason", "confidence"] {
        assert!(d.get(key).is_some(), "{key}: {envelope}");
    }
    assert_eq!(text_at(d, "/id"), "fn:0x1080");
    assert_eq!(text_at(d, "/name"), "main");
    for section in ALL {
        assert!(d.get(section).is_some(), "{section}: {envelope}");
    }
    let row = d.pointer("/disasm/rows/0").expect("a row");
    assert_eq!(text_at(row, "/a"), "0x1080");
    assert_eq!(text_at(row, "/m"), "endbr64");
    assert_eq!(text_at(row, "/b"), "f30f1efa");
    assert_eq!(text_at(row, "/f"), "seq");
    assert_eq!(row.get("n").and_then(Value::as_u64), Some(4));
    let rows = d
        .pointer("/disasm/rows")
        .and_then(Value::as_array)
        .expect("rows");
    assert!(
        rows.iter().any(|r| str_of(r, "t").contains("puts@plt")),
        "the symbolizer names the stub"
    );
    let callees: Vec<String> = d
        .get("callees")
        .and_then(Value::as_array)
        .expect("callees")
        .iter()
        .map(|c| str_of(c, "id"))
        .collect();
    assert_eq!(callees, ["fn:0x11e0", "imp:puts"]);
    let strings = d.get("strings").and_then(Value::as_array).expect("strings");
    assert_eq!(strings.len(), 3, "{strings:?}");
    assert!(
        strings
            .iter()
            .all(|s| crate::support::is_bin_text(s.get("text").expect("text")))
    );
    let blocks = d
        .pointer("/cfg/blocks")
        .and_then(Value::as_array)
        .expect("blocks");
    assert!(blocks.len() >= 4, "{blocks:?}");
    let ir = d
        .pointer("/ir/insns")
        .and_then(Value::as_array)
        .expect("IR rows");
    assert_eq!(ir.len(), rows.len());
    assert_eq!(str_of(&ir[0], "a"), "0x1080");
    let summary = d.get("summary").expect("summary");
    assert!(summary.get("blocks").and_then(Value::as_u64).unwrap_or(0) >= 4);
    let missing = get(&mut session, "0x2004", &["summary"], "{}");
    assert_eq!(code(&missing), "NOT_IN_FUNCTION", "{missing}");
}

/// A caveat remedy is a call object `{ tool, args, why }` that `hints::check` accepts. It is
/// never a raw string, and it has no `count` argument (agent-protocol-10).
#[test]
fn regress_caveat_remedy_is_a_call() {
    let (mut session, _) = fixture("func_ptrs.gcc-O2");
    let out = get(&mut session, "fn:0x1350", &["cfg"], "{}");
    let caveats = data(&out)
        .get("caveats")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .expect("caveats");
    let caveat = caveats
        .iter()
        .find(|c| str_of(c, "code") == "W_JUMPTABLE_UNRESOLVED")
        .unwrap_or_else(|| panic!("no W_JUMPTABLE_UNRESOLVED: {out}"));
    assert_eq!(str_of(caveat, "at"), "0x1366", "{caveat}");
    let remedy = caveat.get("remedy").expect("the caveat has a remedy");
    assert!(remedy.as_object().is_some(), "a call object: {remedy}");
    assert_eq!(text_at(remedy, "/tool"), "func_edit", "{remedy}");
    assert_eq!(text_at(remedy, "/args/at"), "0x1366", "{remedy}");
    assert!(!text_at(remedy, "/args/action").is_empty(), "{remedy}");
    assert!(remedy.pointer("/args/count").is_none(), "{remedy}");
    let why = text_at(remedy, "/why");
    assert!(!why.is_empty(), "{remedy}");
    let args = remedy.get("args").cloned().expect("args");
    let found = Call::new(&text_at(remedy, "/tool"), args, &why);
    let registry = session.active_registry();
    hints::check(&registry, &|name| session.in_profile(name), &found)
        .unwrap_or_else(|e| panic!("{remedy}: {e}"));
    for c in &caveats {
        if let Some(r) = c.get("remedy") {
            assert!(r.as_object().is_some(), "{c}");
            assert!(r.pointer("/args/count").is_none(), "{c}");
        }
    }
}

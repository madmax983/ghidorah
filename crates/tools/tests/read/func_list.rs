//! `func_list`: the frozen priority, sorts, filters and pages (AC-157).

use std::collections::BTreeSet;

use ghidorah_analysis::analyzers::metrics;
use ghidorah_base::{Address, BinaryId};
use ghidorah_db::{Edit, SymKind};
use ghidorah_json::Value;
use ghidorah_tools::ToolError;

use crate::support::{
    addr_of, all_items, call, code, data, fixture, items, json, program, str_of, text_at,
};

/// Gives the IDs of the items of a list envelope.
fn ids(envelope: &Value) -> Vec<String> {
    items(envelope).iter().map(|i| str_of(i, "id")).collect()
}

/// Renames the function at `entry` of the open binary `id` with one agent commit.
fn rename(session: &mut ghidorah_tools::Session, id: &str, entry: u64, name: &str) {
    let id = BinaryId::parse(id).expect("a binary ID");
    session
        .transact(id, "symbol_rename", "test", |tx| {
            let fact = tx.fact(name.to_owned());
            tx.apply(Edit::SetName {
                addr: Address::ram(entry),
                key: None,
                kind: SymKind::Function,
                primary: true,
                name: Some(fact),
                evidence: Vec::new(),
            })
            .map(drop)
            .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the rename commits");
}

#[test]
fn ac_157_priority_frozen() {
    let name = "socket_client.gcc-O2.stripped";
    let (mut session, id) = fixture(name);
    let first = call(
        &mut session,
        "func_list",
        r#"{"sort":"priority","limit":1000}"#,
    );
    let order = ids(&first);
    let expected: Vec<String> = metrics::priority(program(&session, &id))
        .iter()
        .map(|r| r.func.to_string())
        .collect();
    assert_eq!(order, expected, "the frozen priority of the analysis layer");
    assert!(order.len() >= 5, "{order:?}");
    for target in order.iter().take(3) {
        let args = Value::object([
            ("target", Value::from(target.as_str())),
            ("include", json(r#"["disasm"]"#)),
        ]);
        let got = crate::support::call_value(&mut session, "func_get", args);
        assert!(got.get("ok") == Some(&Value::Bool(true)), "{got}");
    }
    let last = order.last().expect("a function");
    rename(
        &mut session,
        &id,
        addr_of(last.trim_start_matches("fn:")),
        "zz_renamed",
    );
    let again = call(
        &mut session,
        "func_list",
        r#"{"sort":"priority","limit":1000}"#,
    );
    assert_eq!(ids(&again), order, "visits and renames keep the order");
    let visited = call(&mut session, "func_list", r#"{"filter":{"visited":true}}"#);
    let mut seen = ids(&visited);
    seen.sort();
    let mut top: Vec<String> = order.iter().take(3).cloned().collect();
    top.sort();
    assert_eq!(seen, top, "visited is a live filter");
    let (mut other, _) = fixture(name);
    let fresh = call(
        &mut other,
        "func_list",
        r#"{"sort":"priority","limit":1000}"#,
    );
    assert_eq!(ids(&fresh), order, "two sessions give the same order");
}

#[test]
fn func_list_sorts_and_filters() {
    let (mut session, _) = fixture("hello.gcc-O2");
    let by_addr = items(&call(&mut session, "func_list", "{}"));
    let addrs: Vec<u64> = by_addr
        .iter()
        .map(|i| addr_of(&str_of(i, "addr")))
        .collect();
    let mut sorted = addrs.clone();
    sorted.sort_unstable();
    assert_eq!(addrs, sorted);
    let first = by_addr.first().expect("a function");
    for key in [
        "id",
        "addr",
        "name",
        "size",
        "start_reason",
        "confidence",
        "flags",
        "callers",
        "callees",
        "caveats",
        "visited",
        "named",
    ] {
        assert!(first.get(key).is_some(), "{key} in {first}");
    }
    let by_name = items(&call(&mut session, "func_list", r#"{"sort":"name"}"#));
    let names: Vec<String> = by_name.iter().map(|i| str_of(i, "name")).collect();
    let mut sorted_names = names.clone();
    sorted_names.sort();
    assert_eq!(names, sorted_names);
    let by_size = items(&call(&mut session, "func_list", r#"{"sort":"size"}"#));
    let sizes: Vec<u64> = by_size
        .iter()
        .map(|i| i.get("size").and_then(Value::as_u64).unwrap_or(0))
        .collect();
    assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "{sizes:?}");
    let glob = items(&call(
        &mut session,
        "func_list",
        r#"{"filter":{"name":"*_tm_clones"}}"#,
    ));
    assert_eq!(glob.len(), 2, "{glob:?}");
    let puts = items(&call(
        &mut session,
        "func_list",
        r#"{"filter":{"calls":"puts"}}"#,
    ));
    let callers: Vec<String> = puts.iter().map(|i| str_of(i, "name")).collect();
    assert_eq!(callers, ["finish"]);
    let big = items(&call(
        &mut session,
        "func_list",
        r#"{"filter":{"size_min":30}}"#,
    ));
    assert!(
        big.iter()
            .all(|i| i.get("size").and_then(Value::as_u64).unwrap_or(0) >= 30)
    );
    let count = call(&mut session, "func_list", r#"{"count_only":true}"#);
    assert_eq!(
        data(&count).get("count").and_then(Value::as_u64),
        Some(u64::try_from(by_addr.len()).expect("a count"))
    );
    let reason = str_of(first, "start_reason");
    let args = json(&format!(r#"{{"filter":{{"start_reason":["{reason}"]}}}}"#));
    let reasons = items(&crate::support::call_value(&mut session, "func_list", args));
    let want = by_addr
        .iter()
        .filter(|i| str_of(i, "start_reason") == reason)
        .count();
    assert_eq!(reasons.len(), want, "{reason}");
    assert!(
        reasons
            .iter()
            .all(|i| text_at(i, "/start_reason") == reason)
    );
}

#[test]
fn func_list_pages_with_cursor() {
    let (mut session, _) = fixture("varargs.gcc-O2");
    let full = items(&call(&mut session, "func_list", r#"{"limit":1000}"#));
    assert!(full.len() > 10, "{} functions", full.len());
    for sort in ["addr", "name", "size", "priority", "in_degree"] {
        let args = json(&format!(r#"{{"sort":"{sort}"}}"#));
        let one = items(&crate::support::call_value(&mut session, "func_list", {
            let mut o = args.as_object().cloned().unwrap_or_default();
            o.push("limit", Value::from(1000));
            Value::Object(o)
        }));
        let paged = all_items(&mut session, "func_list", &args, 3);
        assert_eq!(paged, one, "{sort}");
        assert_eq!(paged.len(), full.len(), "{sort}");
    }
}

#[test]
fn func_list_filters_the_code_pointer_reasons() {
    let (mut session, _) = fixture("func_ptrs.clang-O2.noeh");
    let all = all_items(&mut session, "func_list", &json("{}"), 1000);
    let mut seeded = 0;
    // The build has no gap component, but the filter takes its reason.
    for reason in ["data_ptr", "addr_taken", "gap_component"] {
        let args = json(&format!(
            r#"{{"filter":{{"start_reason":["{reason}"]}},"limit":1000}}"#
        ));
        let envelope = crate::support::call_value(&mut session, "func_list", args);
        assert!(
            code(&envelope).is_empty(),
            "the filter accepts {reason}: {envelope}"
        );
        let got = items(&envelope);
        let want = all
            .iter()
            .filter(|i| str_of(i, "start_reason") == reason)
            .count();
        assert_eq!(got.len(), want, "{reason}");
        assert!(got.iter().all(|i| str_of(i, "start_reason") == reason));
        seeded += want;
    }
    assert!(seeded > 0, "the noeh build has code-pointer seeds");
}

/// Gives the distinct caller functions of the call items of `xref_list` on `target`.
fn xref_callers(session: &mut ghidorah_tools::Session, target: &str) -> BTreeSet<String> {
    let args = Value::object([
        ("targets", Value::Array(vec![Value::from(target)])),
        ("kinds", json(r#"["call"]"#)),
    ]);
    all_items(session, "xref_list", &args, 1000)
        .iter()
        .filter_map(|i| i.pointer("/from_func/id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

#[test]
fn regress_plt_stub_callers() {
    let (mut session, _) = fixture("func_ptrs.gcc-O2");
    let qsort = call(
        &mut session,
        "func_get",
        r#"{"target":"fn:0x1080","include":["summary","callers"]}"#,
    );
    let d = data(&qsort);
    assert_eq!(text_at(d, "/name"), "qsort@plt", "{qsort}");
    let callers = d.get("callers").and_then(Value::as_array).expect("callers");
    let main = callers
        .iter()
        .find(|c| str_of(c, "name") == "main")
        .unwrap_or_else(|| panic!("main calls qsort@plt: {qsort}"));
    assert!(
        main.get("sites")
            .and_then(Value::as_array)
            .is_some_and(|s| s.contains(&Value::from("0x110f"))),
        "{qsort}"
    );
    let count = d.pointer("/summary/callers").and_then(Value::as_u64);
    assert!(count.is_some_and(|n| n >= 1), "{qsort}");
    let funcs = all_items(&mut session, "func_list", &json("{}"), 1000);
    let mut stubs = 0;
    for f in funcs.iter().filter(|f| str_of(f, "name").ends_with("@plt")) {
        let want = xref_callers(&mut session, &str_of(f, "id"));
        let got = f.get("callers").and_then(Value::as_u64);
        assert_eq!(got, u64::try_from(want.len()).ok(), "{f}");
        stubs += usize::from(!want.is_empty());
    }
    assert!(stubs >= 2, "{stubs} called stubs");
    let args = json(r#"{"sort":"in_degree"}"#);
    let sorted = all_items(&mut session, "func_list", &args, 1000);
    let shown: Vec<u64> = sorted
        .iter()
        .map(|f| f.get("callers").and_then(Value::as_u64).unwrap_or(0))
        .collect();
    assert!(
        shown.windows(2).all(|w| w[0] >= w[1]),
        "in_degree order agrees with callers: {shown:?}"
    );
}

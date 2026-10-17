//! `mem_read`: the instruction sweep against `func_get`, the byte forms, typed reads and
//! errors (AC-216).

use ghidorah_json::Value;

use crate::support::{
    addr_of, all_items, call, call_value, code, data, demo, fixture, json, program, str_of,
    text_at, truth_fixtures,
};

/// Gives the rows of one sweep from `start` until the sweep passes `end` or stops.
fn sweep(session: &mut ghidorah_tools::Session, start: u64, end: u64) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10_000 {
        let mut args = json(r#"{"as":"insn","count":50}"#)
            .as_object()
            .cloned()
            .unwrap_or_default();
        args.push("target", Value::from(format!("{start:#x}")));
        if let Some(c) = &cursor {
            args.push("cursor", Value::from(c.as_str()));
        }
        let page = call_value(session, "mem_read", Value::Object(args));
        let d = data(&page);
        let got = d
            .get("rows")
            .and_then(Value::as_array)
            .expect("rows")
            .to_vec();
        let done = got.last().is_some_and(|r| addr_of(&str_of(r, "a")) >= end);
        rows.extend(got);
        cursor = d
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if done || cursor.is_none() {
            return rows;
        }
    }
    panic!("the sweep does not end");
}

/// Gives the address after a row.
fn row_end(row: &Value) -> u64 {
    addr_of(&str_of(row, "a")) + row.get("n").and_then(Value::as_u64).unwrap_or(0)
}

#[test]
fn ac_216_insn_sweep() {
    let mut checked = 0;
    for name in truth_fixtures() {
        let (mut session, _) = fixture(name);
        let funcs = all_items(&mut session, "func_list", &json("{}"), 1000);
        for f in &funcs {
            let args = Value::object([
                ("target", Value::from(str_of(f, "id"))),
                ("include", json(r#"["disasm"]"#)),
                ("disasm_limit", Value::from(2000)),
                ("max_chars", Value::from(60_000)),
            ]);
            let got = call_value(&mut session, "func_get", args);
            let rows = data(&got)
                .pointer("/disasm/rows")
                .and_then(Value::as_array)
                .expect("rows")
                .to_vec();
            // Each run of adjacent rows is one sweep.
            let mut runs: Vec<Vec<Value>> = Vec::new();
            for row in rows {
                match runs.last_mut() {
                    Some(run)
                        if run
                            .last()
                            .is_some_and(|r| row_end(r) == addr_of(&str_of(&row, "a"))) =>
                    {
                        run.push(row);
                    }
                    _ => runs.push(vec![row]),
                }
            }
            for run in runs {
                let start = addr_of(&str_of(&run[0], "a"));
                let end = run.last().map(row_end).expect("a row");
                let swept = sweep(&mut session, start, end.saturating_sub(1));
                let prefix: Vec<Value> = swept.into_iter().take(run.len()).collect();
                assert_eq!(prefix, run, "{name} {}", str_of(f, "id"));
            }
        }
        checked += 1;
    }
    assert!(checked >= 60, "{checked} fixtures");
    // The cursor reaches the end of the region.
    let (mut session, id) = fixture("hello.gcc-O2");
    let region = program(&session, &id)
        .mem()
        .region_at(0x1080)
        .expect("the code region")
        .va;
    let rows = sweep(&mut session, region.first, u64::MAX);
    assert_eq!(addr_of(&str_of(&rows[0], "a")), region.first);
    assert!(
        rows.windows(2)
            .all(|w| row_end(&w[0]) == addr_of(&str_of(&w[1], "a")))
    );
    assert_eq!(rows.last().map(row_end), Some(region.last + 1));
}

#[test]
fn mem_read_forms() {
    let mut session = demo();
    let hex = call(&mut session, "mem_read", r#"{"target":"0x2004","len":8}"#);
    let d = data(&hex);
    let want = program(&session, crate::support::DEMO_ID)
        .mem()
        .read(0x2004, 8, &ghidorah_base::Limits::DEFAULT)
        .expect("bytes")
        .to_vec();
    assert_eq!(text_at(d, "/hex"), ghidorah_base::hex::encode(&want));
    assert_eq!(text_at(d, "/addr"), "0x2004");
    assert_eq!(d.get("len").and_then(Value::as_u64), Some(8));
    assert_eq!(text_at(d, "/region/perms"), "r--");
    assert_eq!(text_at(d, "/text/src"), "binary");
    let u8s = call(
        &mut session,
        "mem_read",
        r#"{"target":"0x2004","as":"u8","count":2}"#,
    );
    let values: Vec<String> = data(&u8s)
        .get("values")
        .and_then(Value::as_array)
        .expect("values")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        values,
        [format!("{:#x}", want[0]), format!("{:#x}", want[1])]
    );
    let i8s = call(
        &mut session,
        "mem_read",
        r#"{"target":"0x2004","as":"i64","count":1}"#,
    );
    let v = data(&i8s)
        .pointer("/values/0")
        .and_then(Value::as_str)
        .expect("a value");
    let raw = i64::from_le_bytes(want.as_slice().try_into().expect("8 bytes"));
    assert_eq!(v, raw.to_string());
    let ptr = call(
        &mut session,
        "mem_read",
        r#"{"target":"0x3db0","as":"ptr","count":1}"#,
    );
    let p = data(&ptr).pointer("/values/0").expect("a pointer");
    assert_eq!(text_at(p, "/v"), "0x11c0", "{ptr}");
    assert_eq!(text_at(p, "/name"), "frame_dummy");
    let cstr = call(
        &mut session,
        "mem_read",
        r#"{"target":"0x2004","as":"cstr"}"#,
    );
    let text = text_at(data(&cstr), "/text/text");
    assert!(!text.is_empty() && !text.contains("\\x00"), "{cstr}");
    let typed = call(
        &mut session,
        "mem_read",
        r#"{"target":"0x2004","as":"type","c":"struct timespec"}"#,
    );
    let fields = data(&typed)
        .get("fields")
        .and_then(Value::as_array)
        .expect("fields");
    let paths: Vec<(String, u64)> = fields
        .iter()
        .map(|f| {
            (
                str_of(f, "path"),
                f.get("offset").and_then(Value::as_u64).unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(
        paths,
        [("tv_sec".to_owned(), 0), ("tv_nsec".to_owned(), 8)],
        "{typed}"
    );
    assert_eq!(data(&typed).get("len").and_then(Value::as_u64), Some(16));
    let bad = call(
        &mut session,
        "mem_read",
        r#"{"target":"0x2004","as":"type","c":"struct no_such_type"}"#,
    );
    assert_eq!(code(&bad), "C_PARSE_ERROR", "{bad}");
    let unmapped = call(&mut session, "mem_read", r#"{"target":"0x900000"}"#);
    assert_eq!(code(&unmapped), "ADDRESS_UNMAPPED", "{unmapped}");
    let cursor = call(
        &mut session,
        "mem_read",
        r#"{"target":"main","as":"insn","cursor":"00ff"}"#,
    );
    assert_eq!(code(&cursor), "CURSOR_INVALID", "{cursor}");
    assert!(cursor.pointer("/next/0/args/cursor").is_none(), "{cursor}");
}

#[test]
fn mem_read_stops_at_the_region_end() {
    let (mut session, id) = fixture("hello.gcc-O2");
    let region = program(&session, &id)
        .mem()
        .region_at(0x2004)
        .expect("the data region")
        .va;
    let start = region.last - 3;
    let args = Value::object([
        ("target", Value::from(format!("{start:#x}"))),
        ("len", Value::from(64)),
    ]);
    let got = call_value(&mut session, "mem_read", args);
    assert_eq!(
        data(&got).get("len").and_then(Value::as_u64),
        Some(4),
        "{got}"
    );
}

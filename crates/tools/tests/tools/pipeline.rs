//! The dispatcher pipeline: frames, paging, projection, shapes, edits, panics and fuel.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

use ghidorah_base::Fuel;
use ghidorah_json::Value;
use ghidorah_tools::budget::Budget;
use ghidorah_tools::{
    AnalysisInfo, AnalysisState, ContentMode, Ctx, Frame, Members, Request, dispatch, dispatch_with,
};

use crate::common::{code, json, run, run_on, text};
use crate::test_registry::{BINARY, START_REV, TestHost, registry};

fn ok(envelope: &Value) -> bool {
    envelope.get("ok") == Some(&Value::Bool(true))
}

fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|o| o.iter().map(|(k, _)| k.to_owned()).collect())
        .unwrap_or_default()
}

fn addrs(envelope: &Value) -> Vec<String> {
    envelope
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|i| i.get("addr").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

#[test]
fn envelope_members_in_order() {
    let envelope = run("item_get", r#"{"target":"0x401000"}"#);
    assert_eq!(
        keys(&envelope),
        [
            "ok",
            "binary_id",
            "rev",
            "session",
            "analysis",
            "partial",
            "data"
        ]
    );
    assert_eq!(
        envelope.get("binary_id").and_then(Value::as_str),
        Some(BINARY)
    );
    assert_eq!(envelope.get("rev").and_then(Value::as_u64), Some(START_REV));
    assert_eq!(
        envelope.get("session").and_then(Value::as_str),
        Some("test")
    );
    assert_eq!(
        envelope.pointer("/analysis/state").and_then(Value::as_str),
        Some("complete")
    );
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(false)));
    let envelope = run("item_list", "{}");
    assert_eq!(
        keys(&envelope),
        [
            "ok",
            "binary_id",
            "rev",
            "session",
            "analysis",
            "partial",
            "data",
            "page",
            "next"
        ]
    );
    let failure = run("item_get", r#"{"target":"nosuch"}"#);
    assert_eq!(
        keys(&failure),
        ["ok", "binary_id", "rev", "session", "error", "next"]
    );
    assert_eq!(failure.get("ok"), Some(&Value::Bool(false)));
    let error = failure.get("error").expect("an error");
    assert_eq!(
        keys(error)[..5],
        ["code", "num", "message", "hint", "retryable"]
    );
    let echo = run("echo_value", r#"{"value":1}"#);
    assert_eq!(keys(&echo), ["ok", "rev", "session", "partial", "data"]);
}

#[test]
fn unknown_tool_and_profile() {
    let envelope = run("item_lst", "{}");
    assert_eq!(code(&envelope), "UNKNOWN_TOOL");
    assert_eq!(
        envelope
            .pointer("/error/candidates/0/value")
            .and_then(Value::as_str),
        Some("item_list")
    );
    assert!(
        envelope
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("item_lst"))
    );
    let mut host = TestHost {
        profile: Some(["item_list", "item_get"].into_iter().collect()),
        ..TestHost::default()
    };
    let envelope = run_on(
        &mut host,
        "item_edit",
        r#"{"action":"delete","target":"0x401000"}"#,
    )
    .to_json();
    assert_eq!(code(&envelope), "TOOL_NOT_IN_PROFILE");
    assert_eq!(
        envelope
            .pointer("/error/details/reason")
            .and_then(Value::as_str),
        Some("not_in_profile")
    );
    assert_eq!(host.rev, START_REV);
    assert_eq!(code(&run("echo_value", "[]")), "INVALID_ARGUMENT");
}

#[test]
fn frame_binds_the_binary() {
    let mut host = TestHost::default();
    host.binaries.clear();
    assert_eq!(
        code(&run_on(&mut host, "item_list", "{}").to_json()),
        "NO_BINARY_OPEN"
    );
    assert!(ok(
        &run_on(&mut host, "echo_value", r#"{"value":1}"#).to_json()
    ));
    let fuel = run_on(&mut host, "fuel_run", r#"{"work":1}"#).to_json();
    assert!(ok(&fuel));
    assert!(fuel.get("binary_id").is_none());
    assert_eq!(fuel.get("rev").and_then(Value::as_u64), Some(0));
    host.binaries = vec!["b1".to_owned(), "b2".to_owned()];
    assert_eq!(
        code(&run_on(&mut host, "item_list", "{}").to_json()),
        "BINARY_REQUIRED"
    );
    assert_eq!(
        code(&run_on(&mut host, "item_list", r#"{"binary_id":"b9"}"#).to_json()),
        "UNKNOWN_BINARY"
    );
    let envelope = run_on(
        &mut host,
        "item_list",
        r#"{"binary_id":"b2","session":"s7"}"#,
    )
    .to_json();
    assert_eq!(
        envelope.get("binary_id").and_then(Value::as_str),
        Some("b2")
    );
    assert_eq!(envelope.get("session").and_then(Value::as_str), Some("s7"));
    let mut request = Request::new("item_list", json(r#"{"binary_id":"b1"}"#));
    request.session = Some("mcp-1".to_owned());
    let envelope = dispatch_with(&registry(), &mut host, &request).to_json();
    assert_eq!(
        envelope.get("session").and_then(Value::as_str),
        Some("mcp-1")
    );
    let shipped = dispatch(
        &mut TestHost::default(),
        &Request::new("item_list", json("{}")),
    );
    assert!(shipped.ok());
}

#[test]
fn cursor_pages_cover_the_list() {
    for sort in ["addr", "name", "size"] {
        let mut host = TestHost::default();
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let args = match &cursor {
                Some(c) => format!(r#"{{"count":50,"limit":20,"sort":"{sort}","cursor":"{c}"}}"#),
                None => format!(r#"{{"count":50,"limit":20,"sort":"{sort}"}}"#),
            };
            let envelope = run_on(&mut host, "item_list", &args).to_json();
            assert!(ok(&envelope), "{envelope}");
            assert_eq!(
                envelope.pointer("/page/total").and_then(Value::as_u64),
                Some(50)
            );
            seen.extend(addrs(&envelope));
            cursor = envelope
                .pointer("/page/next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if cursor.is_none() {
                assert_eq!(
                    envelope.pointer("/page/truncated"),
                    Some(&Value::Bool(false))
                );
                break;
            }
            assert_eq!(
                envelope.pointer("/page/truncated"),
                Some(&Value::Bool(true))
            );
            assert!(
                envelope
                    .pointer("/page/hint")
                    .and_then(Value::as_str)
                    .is_some()
            );
        }
        assert_eq!(seen.len(), 50, "{sort}");
        let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
        assert_eq!(unique.len(), 50, "{sort}");
    }
    let envelope = run("item_list", r#"{"cursor":"c:3:0x1"}"#);
    assert_eq!(code(&envelope), "CURSOR_INVALID");
    assert_eq!(envelope.pointer("/next/0/args"), Some(&json("{}")));
    let envelope = run("item_list", r#"{"cursor":"c:0:0x401010","limit":2}"#);
    assert_eq!(addrs(&envelope), ["0x401020", "0x401030"]);
}

#[test]
fn set_filter_count_table_and_fields() {
    let envelope = run("item_list", r#"{"in":"set:small"}"#);
    assert_eq!(
        addrs(&envelope),
        ["0x401000", "0x401020", "0x401040", "0x401050"]
    );
    assert_eq!(
        envelope.pointer("/page/total").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(code(&run("item_list", r#"{"in":"set:none"}"#)), "NOT_FOUND");
    let count = run("item_list", r#"{"count_only":true,"count":12}"#);
    assert_eq!(count.get("data"), Some(&json(r#"{"count":12}"#)));
    assert_eq!(
        count.pointer("/page/returned").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        count.pointer("/page/total").and_then(Value::as_u64),
        Some(12)
    );
    let table = run("item_list", r#"{"count":2,"shape":"table"}"#);
    assert_eq!(
        table.pointer("/data/cols"),
        Some(&json(r#"["id","addr","name","size","label"]"#))
    );
    assert_eq!(
        table.pointer("/data/rows/1/1").and_then(Value::as_str),
        Some("0x401010")
    );
    assert_eq!(
        table.pointer("/data/sorted_by").and_then(Value::as_str),
        Some("addr")
    );
    let projected = run(
        "item_list",
        r#"{"count":2,"fields":["/items/*/addr","/sorted_by"]}"#,
    );
    assert_eq!(
        projected.get("data"),
        Some(&json(
            r#"{"items":[{"addr":"0x401000"},{"addr":"0x401010"}],"sorted_by":"addr"}"#
        ))
    );
    let echo = run(
        "echo_value",
        r#"{"value":{"a":1,"b":[1,2]},"fields":["/value/b/1","/nope"]}"#,
    );
    assert_eq!(echo.get("data"), Some(&json(r#"{"value":{"b":[2]}}"#)));
    let bad = run("echo_value", r#"{"value":1,"fields":["/ok","no-slash"]}"#);
    assert_eq!(code(&bad), "INVALID_ARGUMENT");
    assert_eq!(
        bad.pointer("/error/field_path").and_then(Value::as_str),
        Some("/fields/1")
    );
}

#[test]
fn edits_conflicts_and_dry_runs() {
    let mut host = TestHost::default();
    let envelope = run_on(
        &mut host,
        "item_edit",
        r#"{"action":"rename","target":"0x401000","name":"init"}"#,
    )
    .to_json();
    assert!(ok(&envelope), "{envelope}");
    assert_eq!(
        envelope.get("rev").and_then(Value::as_u64),
        Some(START_REV + 1)
    );
    assert_eq!(envelope.get("tx").and_then(Value::as_str), Some("tx:8"));
    assert_eq!(envelope.get("noop"), Some(&Value::Bool(false)));
    let again = run_on(
        &mut host,
        "item_edit",
        r#"{"action":"rename","target":"0x401000","name":"init"}"#,
    )
    .to_json();
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)));
    assert!(again.get("tx").is_none());
    let conflict = run_on(
        &mut host,
        "item_edit",
        r#"{"action":"delete","target":"0x401000","expected_rev":3}"#,
    )
    .to_json();
    assert_eq!(code(&conflict), "CONFLICT");
    assert_eq!(
        conflict
            .pointer("/error/details/current_rev")
            .and_then(Value::as_u64),
        Some(8)
    );
    assert_eq!(
        conflict
            .pointer("/next/0/args/expected_rev")
            .and_then(Value::as_u64),
        Some(8)
    );
    assert_eq!(
        conflict.pointer("/error/retryable"),
        Some(&Value::Bool(true))
    );
    let dry = run_on(
        &mut host,
        "item_edit",
        r#"{"action":"rename","target":"0x401010","name":"x","dry_run":true,"expected_rev":8}"#,
    )
    .to_json();
    assert!(ok(&dry));
    assert!(dry.get("diff").and_then(Value::as_array).is_some());
    assert_eq!(dry.get("rev").and_then(Value::as_u64), Some(8));
    assert_eq!(host.rev, 8);
    assert_eq!(
        code(&run("item_list", r#"{"expected_rev":7}"#)),
        "UNKNOWN_ARGUMENT"
    );
}

#[test]
fn partial_coercion_and_aliases() {
    let mut host = TestHost {
        analysis: Some(AnalysisInfo {
            state: AnalysisState::Stale,
            rev: 6,
        }),
        ..TestHost::default()
    };
    let envelope = run_on(&mut host, "item_get", r#"{"target":"0x401000"}"#).to_json();
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(true)));
    assert_eq!(
        envelope.get("analysis"),
        Some(&json(r#"{"state":"stale","rev":6}"#))
    );
    assert_eq!(
        code(&run("item_list", r#"{"count":"5"}"#)),
        "INVALID_ARGUMENT"
    );
    let mut host = TestHost {
        lenient: true,
        ..TestHost::default()
    };
    let envelope = run_on(&mut host, "item_list", r#"{"count":"5"}"#).to_json();
    assert!(ok(&envelope), "{envelope}");
    assert_eq!(
        envelope.pointer("/page/total").and_then(Value::as_u64),
        Some(5)
    );
    assert_eq!(
        envelope.pointer("/warnings/0/code").and_then(Value::as_str),
        Some("W_COERCED")
    );
    assert_eq!(
        envelope
            .pointer("/warnings/0/field")
            .and_then(Value::as_str),
        Some("/count")
    );
    assert!(envelope.pointer("/warnings/0/details").is_none());
    let detailed = run_on(
        &mut host,
        "item_list",
        r#"{"count":"5","format":"detailed"}"#,
    )
    .to_json();
    assert_eq!(
        detailed.pointer("/warnings/0/details"),
        Some(&json(r#"{"from_type":"string","to_type":"integer"}"#))
    );
    let alias = run("item_get", r#"{"addr":"0x401000","format":"detailed"}"#);
    assert!(ok(&alias));
    assert_eq!(
        alias.pointer("/warnings/0/field").and_then(Value::as_str),
        Some("/addr")
    );
    assert_eq!(
        alias.pointer("/warnings/0/details"),
        Some(&json(r#"{"from_name":"addr","to_name":"target"}"#))
    );
    assert_eq!(
        alias.pointer("/warnings/0/num").and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn panic_gives_internal_error() {
    let mut host = TestHost::default();
    let registry = ghidorah_tools::Registry::new(PANICS);
    let request = Request::new("panic_tool", json(r#"{"value":1}"#));
    let first = dispatch_with(&registry, &mut host, &request).to_json();
    assert_eq!(code(&first), "INTERNAL_ERROR");
    let id = first
        .pointer("/error/crash_id")
        .and_then(Value::as_str)
        .expect("a crash ID");
    assert_eq!(id.len(), 16);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    let second = dispatch_with(&registry, &mut host, &request).to_json();
    assert_eq!(
        second.pointer("/error/crash_id").and_then(Value::as_str),
        Some(id)
    );
    assert_eq!(host.panics.len(), 2);
    assert_eq!(host.panics[0].tool, "panic_tool");
    assert_eq!(host.panics[0].args, r#"{"value":1}"#);
    assert!(host.panics[0].panic.contains("boom"));
    assert!(ok(&run_on(
        &mut host,
        "item_get",
        r#"{"target":"0x401000"}"#
    )
    .to_json()));
}

fn panic_tool(
    _: &mut TestHost,
    _: &ghidorah_tools::Args,
    _: &mut Ctx,
) -> Result<ghidorah_tools::Payload, ghidorah_tools::ToolError> {
    panic!("boom");
}

const PANIC: ghidorah_tools::ToolSpec<TestHost> = ghidorah_tools::ToolSpec {
    title: "Panic",
    summary: "Panic on each call.",
    description: "Panic on each call.",
    args: &[ghidorah_tools::ArgSpec::new(
        "value",
        ghidorah_tools::Role::Param,
        ghidorah_tools::ArgKind::Json,
        "Any value.",
    )],
    binary: ghidorah_tools::BinaryArg::None,
    ..ghidorah_tools::ToolSpec::base("panic_tool", panic_tool)
};

static PANICS: &[&ghidorah_tools::ToolSpec<TestHost>] = &[&PANIC];

#[test]
fn fuel_cancel_and_progress() {
    assert_eq!(
        code(&run("fuel_run", r#"{"work":2000}"#)),
        "BUDGET_EXCEEDED"
    );
    let envelope = run("fuel_run", r#"{"work":2000,"max_steps":5000}"#);
    assert_eq!(
        envelope.pointer("/data/used").and_then(Value::as_u64),
        Some(2000)
    );
    let over = run("fuel_run", r#"{"work":1,"max_steps":200000}"#);
    assert_eq!(code(&over), "LIMIT_EXCEEDED");
    assert_eq!(
        over.pointer("/next/0/args/max_steps")
            .and_then(Value::as_u64),
        Some(100_000)
    );
    let (tx, rx) = mpsc::channel();
    let mut request = Request::new("fuel_run", json(r#"{"work":300}"#));
    request.progress = Some(tx);
    let envelope = dispatch_with(&registry(), &mut TestHost::default(), &request);
    assert!(envelope.ok());
    let reports: Vec<u64> = rx.try_iter().map(|p| p.progress).collect();
    assert_eq!(reports, [100, 200, 300]);
    let mut request = Request::new("fuel_run", json(r#"{"work":300}"#));
    request.cancel = Some(Arc::new(AtomicBool::new(true)));
    let envelope = dispatch_with(&registry(), &mut TestHost::default(), &request).to_json();
    assert_eq!(
        envelope.pointer("/data/cancelled"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        envelope.pointer("/data/used").and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn object_results_fit_or_fail() {
    let long = format!(r#"{{"value":"{}","max_chars":1000}}"#, "x".repeat(5_000));
    let envelope = run("echo_value", &long);
    assert_eq!(code(&envelope), "OUTPUT_BUDGET_EXCEEDED");
    assert!(text(&envelope).chars().count() <= 1_000);
    let over = run("echo_value", r#"{"value":1,"max_chars":70000}"#);
    assert_eq!(code(&over), "LIMIT_EXCEEDED");
    assert_eq!(
        over.pointer("/next/0/args/max_chars")
            .and_then(Value::as_u64),
        Some(60_000)
    );
    let low = run("echo_value", r#"{"value":1,"max_chars":10}"#);
    assert_eq!(code(&low), "INVALID_ARGUMENT");
    let mut request = Request::new("echo_value", json(r#"{"value":"\"\"\"\""}"#));
    request.content = ContentMode::Both;
    assert!(dispatch_with(&registry(), &mut TestHost::default(), &request).ok());
}

#[test]
fn members_and_ctx() {
    let members = Members {
        ids: std::iter::once("fn:0x1".to_owned()).collect(),
        ranges: vec![(0x10, 0x20)],
    };
    assert!(members.holds(&json(r#"{"id":"fn:0x1","addr":"0x99"}"#)));
    assert!(members.holds(&json(r#"{"id":"fn:0x2","addr":"0x1f"}"#)));
    assert!(!members.holds(&json(r#"{"id":"fn:0x2","addr":"0x20"}"#)));
    assert!(!members.holds(&json(r#"{"addr":"zz"}"#)));
    assert!(!members.holds(&json("[]")));
    let mut ctx = Ctx::new(
        Frame::default(),
        Fuel::new(5),
        Budget::new(8_000, ContentMode::Plain),
    );
    assert!(!ctx.cancelled());
    ctx.progress(ghidorah_tools::Progress {
        progress: 1,
        total: None,
        message: "The work runs.".to_owned(),
    });
    ctx.warn(ghidorah_tools::Warning::new(
        ghidorah_base::WarningCode::TimeStop,
    ));
    ctx.hint(ghidorah_tools::Call::new(
        "item_list",
        json("{}"),
        "List the items.",
    ));
    assert_eq!((ctx.warnings.len(), ctx.next.len()), (1, 1));
    let frame = Frame {
        analysis: Some(AnalysisInfo {
            state: AnalysisState::BudgetStopped,
            rev: 1,
        }),
        ..Frame::default()
    };
    assert!(frame.partial());
    assert!(!Frame::default().partial());
    assert_eq!(AnalysisState::BudgetStopped.as_str(), "budget_stopped");
}

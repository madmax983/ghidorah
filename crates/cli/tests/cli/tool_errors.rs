//! Tool errors on MCP (AC-169f).

use ghidorah_cli::mcp::rpc;
use ghidorah_json::Value;

use crate::common::{json, root, run_binary, tmp};
use crate::era::{check, replies};

#[test]
fn regress_call_reopens_binary_id() {
    let dir = tmp("call_reopen");
    let projects = dir.join("projects").to_string_lossy().into_owned();
    let workspace = root().to_string_lossy().into_owned();
    let run = |tool: &str, args: &str| {
        run_binary(
            &[
                "call",
                "--project-root",
                &projects,
                "--root",
                &workspace,
                tool,
                args,
            ],
            "",
        )
    };
    let load = run("binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(load.code, 0, "{}{}", load.stdout, load.stderr);
    // A second process: the call opens the project of its binary_id.
    let list = run("func_list", r#"{"binary_id":"467a43b75d95c826"}"#);
    assert_eq!(list.code, 0, "{}{}", list.stdout, list.stderr);
    let envelope = json(&list.stdout);
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
    assert!(
        envelope
            .pointer("/data/items")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty()),
        "{envelope}"
    );
    // A binary_id with no project still gives UNKNOWN_BINARY.
    let none = run("func_list", r#"{"binary_id":"0123456789abcdef"}"#);
    assert_eq!(none.code, 1, "{}{}", none.stdout, none.stderr);
    assert_eq!(
        json(&none.stdout)
            .pointer("/error/code")
            .and_then(Value::as_str),
        Some("UNKNOWN_BINARY")
    );
}

fn code(reply: &Value) -> Option<i64> {
    reply.pointer("/error/code").and_then(Value::as_i64)
}

#[test]
fn ac_169f_tool_errors() {
    let steps = check("tool_errors");
    let typo = &replies(&steps, 1)[0];
    assert_eq!(code(typo), Some(rpc::INVALID_PARAMS));
    assert_eq!(
        typo.pointer("/error/data/code"),
        Some(&json(r#""UNKNOWN_TOOL""#))
    );
    assert_eq!(
        typo.pointer("/error/data/candidates/0/value"),
        Some(&json(r#""echo_text""#))
    );
    assert!(typo.pointer("/error/data/next").is_some(), "a repair call");
    let unknown = &replies(&steps, 2)[0];
    assert_eq!(code(unknown), Some(rpc::INVALID_PARAMS));
    assert_eq!(
        unknown.pointer("/error/data/code"),
        Some(&json(r#""UNKNOWN_TOOL""#))
    );
    for (index, error) in [(3, "INVALID_ARGUMENT"), (4, "UNKNOWN_ARGUMENT")] {
        let reply = &replies(&steps, index)[0];
        assert_eq!(
            reply.pointer("/result/isError"),
            Some(&Value::Bool(true)),
            "{index}"
        );
        assert_eq!(
            reply
                .pointer("/result/structuredContent/error/code")
                .and_then(Value::as_str),
            Some(error),
            "{index}"
        );
    }
    let repair = &replies(&steps, 4)[0];
    assert_eq!(
        repair.pointer("/result/structuredContent/next/0/args"),
        Some(&json(r#"{"text":"hi"}"#)),
        "next[0] removes the unknown argument"
    );
    for index in [5, 6] {
        assert_eq!(
            code(&replies(&steps, index)[0]),
            Some(rpc::INVALID_PARAMS),
            "{index}"
        );
    }
}

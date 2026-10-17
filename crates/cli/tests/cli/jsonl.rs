//! `ghidorah jsonl` (design Section 10.14).

use ghidorah_json::Value;

use crate::common::registry::TestHost;
use crate::common::{json, run};

#[test]
fn jsonl_echoes_ids() {
    let input = concat!(
        r#"{"id":1,"tool":"echo_text","args":{"text":"one"}}"#,
        "\n\n",
        r#"{"id":"two","tool":"item_list","args":{"count":1}}"#,
        "\n",
        r#"{"id":3,"tool":"echo_text","args":{"text":7}}"#,
        "\n",
    );
    let output = run::<TestHost>(&["jsonl", "--session", "batch-a"], input);
    assert_eq!(output.code, 1, "a tool error gives 1: {}", output.stderr);
    let lines: Vec<Value> = output.lines().iter().map(|l| json(l)).collect();
    assert_eq!(lines.len(), 3, "one line per request");
    assert_eq!(lines[0].get("id"), Some(&json("1")));
    assert_eq!(lines[0].pointer("/data/text"), Some(&json(r#""one""#)));
    assert_eq!(lines[0].get("session"), Some(&json(r#""batch-a""#)));
    assert_eq!(lines[1].get("id"), Some(&json(r#""two""#)));
    assert_eq!(
        lines[1].pointer("/data/items/0/id"),
        Some(&json(r#""fn:0x401000""#))
    );
    assert_eq!(lines[2].get("ok"), Some(&Value::Bool(false)));
    let first = lines[0]
        .as_object()
        .and_then(|o| o.members().first())
        .map(|(k, _)| k.as_str());
    assert_eq!(first, Some("id"), "the id is the first member");
}

#[test]
fn jsonl_bad_lines_give_two() {
    let input = concat!(
        "{not json\n",
        r#"{"id":1,"args":{}}"#,
        "\n",
        r#"{"id":2,"tool":"echo_text","args":[1]}"#,
        "\n",
        r#"{"id":3,"tool":"echo_text","args":{"text":"ok"}}"#,
        "\n",
    );
    let output = run::<TestHost>(&["jsonl"], input);
    assert_eq!(output.code, 2, "{}", output.stdout);
    let lines: Vec<Value> = output.lines().iter().map(|l| json(l)).collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0].get("id"), Some(&Value::Null));
    for line in &lines[..3] {
        assert_eq!(
            line.pointer("/error/code"),
            Some(&json(r#""INVALID_ARGUMENT""#)),
            "{line}"
        );
    }
    assert_eq!(lines[1].get("id"), Some(&json("1")));
    assert_eq!(lines[3].get("ok"), Some(&Value::Bool(true)));
    let clean = run::<TestHost>(
        &["jsonl"],
        "{\"id\":1,\"tool\":\"echo_text\",\"args\":{\"text\":\"a\"}}",
    );
    assert_eq!(clean.code, 0, "{}", clean.stdout);
}

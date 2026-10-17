//! Content modes and exact result sizes.

use ghidorah_json::Value;
use ghidorah_tools::ContentMode;
use ghidorah_tools::content::{chars, cost, escaped_chars, result_chars, tool_result};

use crate::common::{json, text};

#[test]
fn modes_and_copies() {
    assert_eq!(ContentMode::parse("both"), Some(ContentMode::Both));
    assert_eq!(
        ContentMode::parse("structured"),
        Some(ContentMode::Structured)
    );
    assert_eq!(ContentMode::parse("text"), Some(ContentMode::Text));
    assert_eq!(ContentMode::parse("plain"), None);
    assert_eq!(ContentMode::Both.copies(), 2);
    assert_eq!(ContentMode::Text.copies(), 1);
    assert_eq!(ContentMode::default(), ContentMode::Plain);
}

#[test]
fn escaped_sizes_are_exact() {
    for sample in [
        r#"{"a":"b\"c","d":"\\n","e":"ä\u2028"}"#,
        "[]",
        r#""x\ty""#,
        "{\"k\":\"\\u0001\"}",
    ] {
        let value = json(sample);
        let compact = text(&value);
        let as_string = text(&Value::from(compact.clone()));
        assert_eq!(escaped_chars(&compact), chars(&as_string) - 2, "{sample}");
        assert_eq!(cost(&compact, ContentMode::Plain), chars(&compact));
        assert_eq!(cost(&compact, ContentMode::Structured), chars(&compact));
        assert_eq!(cost(&compact, ContentMode::Text), escaped_chars(&compact));
        assert_eq!(
            cost(&compact, ContentMode::Both),
            chars(&compact) + escaped_chars(&compact)
        );
    }
    assert_eq!(chars("äb"), 2);
}

#[test]
fn results_per_mode() {
    let envelope = json(r#"{"ok":true,"data":{"s":"a\"b"}}"#);
    assert_eq!(tool_result(&envelope, false, ContentMode::Plain), envelope);
    let structured = tool_result(&envelope, false, ContentMode::Structured);
    assert_eq!(structured.get("content"), Some(&json("[]")));
    assert_eq!(structured.get("structuredContent"), Some(&envelope));
    assert_eq!(structured.get("isError"), Some(&Value::Bool(false)));
    let text_mode = tool_result(&envelope, true, ContentMode::Text);
    assert!(text_mode.get("structuredContent").is_none());
    assert_eq!(
        text_mode.pointer("/content/0/type").and_then(Value::as_str),
        Some("text")
    );
    assert_eq!(
        text_mode.pointer("/content/0/text").and_then(Value::as_str),
        Some(text(&envelope).as_str())
    );
    assert_eq!(text_mode.get("isError"), Some(&Value::Bool(true)));
    let both = tool_result(&envelope, false, ContentMode::Both);
    assert!(both.get("structuredContent").is_some() && both.pointer("/content/0/text").is_some());
    for mode in ContentMode::ALL {
        let result = tool_result(&envelope, false, mode);
        assert_eq!(
            result_chars(&envelope, false, mode),
            chars(&text(&result)),
            "{mode:?}"
        );
    }
}

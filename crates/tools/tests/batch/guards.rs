//! The guards of a step: `expect` and `claim` (AC-183).

use ghidorah_json::Value;
use ghidorah_tools::batch::{Guard, OPS};

use crate::support::{TRUE_CALL, batch, demo, json, step_code, steps, text_at};

/// Gives the guard of the JSON text `text`.
fn guard(text: &str) -> Guard {
    Guard::parse(&json(text)).unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn guard_ops() {
    let envelope = json(
        r#"{"ok":true,"rev":7,"data":{"items":[{"id":"fn:0x10","name":"main","size":12},{"id":"fn:0x20","name":"helper","size":40}],"addr":"0x401000","text":"check the password"}}"#,
    );
    let pass = [
        r#"{"ptr":"/ok","op":"eq","value":true}"#,
        r#"{"ptr":"/rev","op":"ne","value":8}"#,
        r#"{"ptr":"/rev","op":"gt","value":6}"#,
        r#"{"ptr":"/rev","op":"ge","value":7}"#,
        r#"{"ptr":"/rev","op":"lt","value":8}"#,
        r#"{"ptr":"/rev","op":"le","value":7}"#,
        r#"{"ptr":"/data/addr","op":"gt","value":"0x400fff"}"#,
        r#"{"ptr":"/data/text","op":"contains","value":"pass"}"#,
        r#"{"ptr":"/data/items/*/name","op":"contains","value":"helper"}"#,
        r#"{"ptr":"/data","op":"contains","value":"items"}"#,
        r#"{"ptr":"/data/items/0/name","op":"glob","value":"ma*"}"#,
        r#"{"ptr":"/data/items","op":"len_eq","value":2}"#,
        r#"{"ptr":"/data/text","op":"len_gt","value":3}"#,
        r#"{"ptr":"/data/items/1","op":"exists"}"#,
        r#"{"ptr":"/data/items/5","op":"exists","value":false}"#,
        r#"{"ptr":"/data/items/*/size","op":"eq","value":[12,40]}"#,
    ];
    for text in pass {
        assert_eq!(guard(text).check(&envelope), Ok(()), "{text}");
    }
    let fail = [
        (r#"{"ptr":"/ok","op":"eq","value":false}"#, "true"),
        (r#"{"ptr":"/rev","op":"gt","value":7}"#, "7"),
        (r#"{"ptr":"/data/items","op":"len_eq","value":3}"#, "2"),
        (r#"{"ptr":"/data/items/9","op":"exists"}"#, "null"),
        (
            r#"{"ptr":"/data/text","op":"glob","value":"x*"}"#,
            r#""check the password""#,
        ),
        (r#"{"ptr":"/data/missing","op":"eq","value":1}"#, "null"),
        (
            r#"{"ptr":"/data/text","op":"gt","value":2}"#,
            r#""check the password""#,
        ),
    ];
    for (text, actual) in fail {
        assert_eq!(guard(text).check(&envelope), Err(json(actual)), "{text}");
    }
    let bad = [
        r#"{"ptr":"data","op":"eq","value":1}"#,
        r#"{"ptr":"/data","op":"near","value":1}"#,
        r#"{"ptr":"/data","op":"eq"}"#,
        r#"{"op":"exists"}"#,
        r#"{"ptr":"/data","op":"len_eq","value":"x"}"#,
        "[]",
    ];
    for text in bad {
        assert!(Guard::parse(&json(text)).is_err(), "{text}");
    }
    assert_eq!(OPS.len(), 11);
}

#[test]
fn ac_183_guards() {
    let mut s = demo();
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"list","tool":"func_list","args":{},"expect":[{"ptr":"/data/items","op":"len_eq","value":0}]},
            {"id":"after","tool":"calc","args":{"expr":"0x1"}}
        ],"return":["after"]}"#,
    );
    assert_eq!(step_code(&envelope, 0), "EXPECT_FAILED", "{envelope}");
    let entries = steps(&envelope);
    let actual = entries[0].pointer("/error/details/actual");
    assert!(
        actual.and_then(Value::as_u64).is_some_and(|n| n > 0),
        "the actual length: {envelope}"
    );
    assert_eq!(
        text_at(&entries[0], "/error/field_path"),
        "/steps/0/expect/0"
    );
    assert_eq!(entries[1].get("ok"), Some(&Value::Bool(true)), "{envelope}");

    // A claim guard needs the verdict supported.
    let claim = |a: &str, b: &str| {
        format!(
            r#"{{"steps":[{{"id":"look","tool":"func_list","args":{{"limit":1}},"claim":[{{"rel":"calls","args":["{a}","{b}"]}}]}}]}}"#
        )
    };
    let envelope = batch(&mut s, &claim(TRUE_CALL[0], TRUE_CALL[1]));
    assert_eq!(
        envelope.pointer("/data/steps/0/ok"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    let envelope = batch(&mut s, &claim(TRUE_CALL[1], TRUE_CALL[0]));
    assert_eq!(step_code(&envelope, 0), "EXPECT_FAILED", "{envelope}");
    let actual = text_at(&envelope, "/data/steps/0/error/details/actual");
    assert!(!actual.is_empty() && actual != "supported", "{envelope}");
    assert_eq!(
        text_at(&envelope, "/data/steps/0/error/field_path"),
        "/steps/0/claim/0"
    );
}

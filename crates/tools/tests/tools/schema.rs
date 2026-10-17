//! The JSON Schema subset and the `tools/list` entries.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_tools::schema::{arg_schema, input_schema, tool_entry};
use ghidorah_tools::{ArgKind, ArgSpec, Role};

use crate::common::{json, root};
use crate::test_registry::{ECHO_VALUE, ITEM_EDIT, ITEM_GET, ITEM_LIST, registry};

const FROM: &[ArgSpec] =
    &[ArgSpec::new("from", Role::Param, ArgKind::Addr, "The source.").required()];
const NESTED: ArgSpec = ArgSpec::new("ref", Role::Param, ArgKind::Obj(FROM), "A reference.");

#[test]
fn schema_of_each_kind() {
    let addr = ArgSpec::new("at", Role::At, ArgKind::Addr, "The point.");
    assert_eq!(
        arg_schema(&addr),
        json(r#"{"type":["integer","string"],"description":"The point."}"#)
    );
    let schema = input_schema(&ITEM_GET);
    assert_eq!(
        schema.pointer("/properties/targets"),
        Some(&json(
            r#"{"type":"array","items":{"type":["integer","string"]},"maxItems":50,"description":"The addresses of up to 50 items."}"#
        ))
    );
    assert_eq!(
        schema.pointer("/properties/include"),
        Some(&json(
            r#"{"type":"array","items":{"type":"string","enum":["summary","body"],"description":"One section."},"maxItems":2,"description":"The sections of each item.","default":["summary"]}"#
        ))
    );
    assert!(
        schema.pointer("/properties/id").is_none(),
        "aliases stay out of the schema"
    );
    assert!(schema.get("required").is_none());
    let list = input_schema(&ITEM_LIST);
    assert_eq!(
        list.pointer("/properties/count"),
        Some(&json(
            r#"{"type":"integer","minimum":0,"maximum":20000,"description":"The number of test items in the binary.","default":40}"#
        ))
    );
    assert_eq!(
        list.pointer("/properties/filter/additionalProperties"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        list.pointer("/properties/filter/properties/name"),
        Some(&json(
            r#"{"type":"string","maxLength":64,"description":"Keep the items whose name holds this text."}"#
        ))
    );
    assert_eq!(
        list.pointer("/properties/in/pattern")
            .and_then(Value::as_str),
        Some("^(set):")
    );
    let names: Vec<&str> = list
        .get("properties")
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, _)| k).collect())
        .unwrap_or_default();
    assert_eq!(
        names,
        [
            "count",
            "filter",
            "sort",
            "binary_id",
            "format",
            "fields",
            "max_chars",
            "limit",
            "cursor",
            "count_only",
            "shape",
            "in",
            "session"
        ]
    );
    let echo = input_schema(&ECHO_VALUE);
    assert_eq!(echo.get("required"), Some(&json(r#"["value"]"#)));
    assert_eq!(
        echo.pointer("/properties/value"),
        Some(&json(r#"{"description":"Any JSON value."}"#))
    );
    assert_eq!(
        echo.pointer("/properties/flag/type")
            .and_then(Value::as_str),
        Some("boolean")
    );
    assert_eq!(
        echo.pointer("/properties/tag/pattern")
            .and_then(Value::as_str),
        Some("^(note|set):")
    );
    let edit = input_schema(&ITEM_EDIT);
    assert_eq!(edit.get("required"), Some(&json(r#"["action"]"#)));
    assert_eq!(
        arg_schema(&NESTED).pointer("/required"),
        Some(&json(r#"["from"]"#))
    );
}

#[test]
fn tools_list_entries() {
    let entry = tool_entry(&ITEM_EDIT);
    assert_eq!(
        entry.get("annotations"),
        Some(&json(
            r#"{"title":"Edit test items","readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}"#
        ))
    );
    let keys: Vec<&str> = entry
        .as_object()
        .map(|o| o.iter().map(|(k, _)| k).collect())
        .unwrap_or_default();
    assert_eq!(
        keys,
        ["name", "title", "description", "inputSchema", "annotations"]
    );
    let list: Vec<Value> = registry().tools().iter().map(|t| tool_entry(t)).collect();
    let header = Header::new("tools_list", "1");
    golden::assert_json(
        &root().join("tests/golden/tools/test/tools_list.json"),
        &header,
        &write_pretty(&Value::Array(list)),
    );
}

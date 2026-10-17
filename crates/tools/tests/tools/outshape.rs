//! The fit check of `OutputShape`.

use ghidorah_base::IdKind;
use ghidorah_tools::outshape::{is_addr_text, is_id_text};
use ghidorah_tools::{Field, Fit, OutputShape};

use crate::common::json;

const ITEM: &[Field] = &[
    Field::req("addr", OutputShape::Addr),
    Field::opt("name", OutputShape::Nullable(&OutputShape::Str)),
];
const ITEM_SHAPE: OutputShape = OutputShape::Obj(ITEM);
const LIST: &[Field] = &[Field::req("items", OutputShape::List(&ITEM_SHAPE))];

fn fits(shape: OutputShape, text: &str) -> bool {
    shape.check(&json(text), Fit::Exact).is_ok()
}

#[test]
fn scalar_shapes() {
    assert!(fits(OutputShape::Any, r#"{"x":[1]}"#));
    assert!(fits(OutputShape::Str, r#""a""#));
    assert!(!fits(OutputShape::Str, "1"));
    assert!(fits(OutputShape::Int, "42"));
    assert!(fits(OutputShape::Int, "-3"));
    assert!(!fits(OutputShape::Int, "1.5"));
    assert!(!fits(OutputShape::Int, "9007199254740992"));
    assert!(!fits(OutputShape::Int, r#""1""#));
    assert!(fits(OutputShape::Bool, "false"));
    assert!(!fits(OutputShape::Bool, "0"));
    assert!(fits(OutputShape::Addr, r#""0x401000""#));
    assert!(!fits(OutputShape::Addr, r#""0x40ABC""#));
    assert!(!fits(OutputShape::Addr, r#""401000""#));
    assert!(!fits(OutputShape::Addr, "4198400"));
    assert!(fits(OutputShape::Id(IdKind::Func), r#""fn:0x401000""#));
    assert!(!fits(OutputShape::Id(IdKind::Func), r#""imp:puts""#));
    assert!(!fits(OutputShape::Id(IdKind::Func), "1"));
    assert!(fits(
        OutputShape::Text,
        r#"{"text":"a","hex":"61","len":1,"src":"binary"}"#
    ));
    assert!(fits(
        OutputShape::Text,
        r#"{"text":"a","hex":"61","len":1,"truncated":true,"src":"binary"}"#
    ));
    assert!(!fits(
        OutputShape::Text,
        r#"{"text":"a","hex":"61","len":1}"#
    ));
    assert!(!fits(
        OutputShape::Text,
        r#"{"text":"a","hex":"61","len":1,"src":"agent"}"#
    ));
    assert!(!fits(OutputShape::Text, r#""a""#));
    assert!(fits(OutputShape::Nullable(&OutputShape::Int), "null"));
    assert!(!fits(OutputShape::Nullable(&OutputShape::Int), r#""x""#));
    assert!(is_addr_text("0x0"));
    assert!(!is_addr_text("0x"));
    assert!(is_id_text("note:3", IdKind::Note));
    assert!(!is_id_text("note:3", IdKind::Set));
}

#[test]
fn object_and_list_shapes() {
    let shape = OutputShape::Obj(LIST);
    assert!(fits(
        shape,
        r#"{"items":[{"addr":"0x1"},{"addr":"0x2","name":null},{"addr":"0x3","name":"a"}]}"#
    ));
    let error = shape
        .check(
            &json(r#"{"items":[{"addr":"0x1"},{"addr":"0xG"}]}"#),
            Fit::Exact,
        )
        .expect_err("a bad addr");
    assert_eq!(error.path, "/items/1/addr");
    assert!(error.to_string().contains("/items/1/addr"));
    let error = shape
        .check(&json(r#"{"items":[{"addr":"0x1","extra":1}]}"#), Fit::Exact)
        .expect_err("an extra member");
    assert_eq!(error.path, "/items/0/extra");
    assert!(!fits(shape, r#"{"items":[{"name":"a"}]}"#));
    assert!(
        shape
            .check(&json(r#"{"items":[{"name":"a"}]}"#), Fit::Partial)
            .is_ok()
    );
    assert!(shape.check(&json("{}"), Fit::Partial).is_ok());
    assert!(!fits(shape, "{}"));
    assert!(!fits(shape, r#"{"items":{}}"#));
    assert!(!fits(shape, "[]"));
}

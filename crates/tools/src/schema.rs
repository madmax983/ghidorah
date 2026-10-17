//! The JSON Schema subset of a tool and its `tools/list` entry (design Section 10.1).
//!
//! The root of each input schema is `{ type: "object", properties, required?,
//! additionalProperties: false }`. The root has no combinator. Groups and action rules
//! appear in the description text, not in the schema. Aliases never appear.
//!
//! | Kind | Schema |
//! |---|---|
//! | `Addr` | `{ type: ["integer", "string"] }` |
//! | `AddrList(n)` | `{ type: "array", items: { type: ["integer", "string"] }, maxItems: n }` |
//! | `Id(kinds)` | `{ type: "string", pattern: "^(fn\|imp):" }` |
//! | `Int { min, max }` | `{ type: "integer", minimum, maximum }` |
//! | `Str(n)` | `{ type: "string", maxLength: n }` |
//! | `Enum(values)` | `{ type: "string", enum: values }` |
//! | `Bool` | `{ type: "boolean" }` |
//! | `Obj(specs)` | a nested object with `additionalProperties: false` |
//! | `List(item, n)` | `{ type: "array", items, maxItems: n }` |
//! | `Json` | `{}` |

use ghidorah_json::{Limits, Number, Object, Value};

use crate::args::globals_of;
use crate::errors::count;
use crate::spec::{ArgKind, ArgSpec, ToolSpec};

/// The root keys that a schema must not have (AC-129b).
pub const ROOT_COMBINATORS: [&str; 7] = ["oneOf", "anyOf", "allOf", "not", "if", "then", "else"];

fn address_type() -> Value {
    Value::Array(vec![Value::from("integer"), Value::from("string")])
}

fn integer(value: i64) -> Value {
    Number::parse(&value.to_string()).map_or(Value::Null, Value::Number)
}

/// Gives an object schema of `specs` with no extra members.
fn object_schema(specs: &[ArgSpec]) -> Object {
    let mut out = Object::new();
    out.push("type", Value::from("object"));
    out.push(
        "properties",
        Value::Object(specs.iter().map(|s| (s.name, arg_schema(s))).collect()),
    );
    let required: Vec<Value> = specs
        .iter()
        .filter(|s| s.required)
        .map(|s| Value::from(s.name))
        .collect();
    if !required.is_empty() {
        out.push("required", Value::Array(required));
    }
    out.push("additionalProperties", Value::Bool(false));
    out
}

fn kind_schema(kind: &ArgKind) -> Object {
    let mut out = Object::new();
    match kind {
        ArgKind::Addr => out.push("type", address_type()),
        ArgKind::AddrList(max) => {
            out.push("type", Value::from("array"));
            out.push("items", Value::object([("type", address_type())]));
            out.push("maxItems", count(*max));
        }
        ArgKind::Id(kinds) => {
            let names: Vec<&str> = kinds
                .iter()
                .map(|k| k.prefix().trim_end_matches(':'))
                .collect();
            out.push("type", Value::from("string"));
            out.push("pattern", Value::from(format!("^({}):", names.join("|"))));
        }
        ArgKind::Int { min, max } => {
            out.push("type", Value::from("integer"));
            out.push("minimum", integer(*min));
            out.push("maximum", integer(*max));
        }
        ArgKind::Str(max) => {
            out.push("type", Value::from("string"));
            out.push("maxLength", count(*max));
        }
        ArgKind::Enum(values) => {
            out.push("type", Value::from("string"));
            out.push(
                "enum",
                Value::Array(values.iter().map(|v| Value::from(*v)).collect()),
            );
        }
        ArgKind::Bool => out.push("type", Value::from("boolean")),
        ArgKind::Obj(members) => out = object_schema(members),
        ArgKind::List(item, max) => {
            out.push("type", Value::from("array"));
            out.push("items", arg_schema(item));
            out.push("maxItems", count(*max));
        }
        ArgKind::Json => {}
    }
    out
}

/// Gives the schema of one argument.
#[must_use]
pub fn arg_schema(spec: &ArgSpec) -> Value {
    let mut out = kind_schema(&spec.kind);
    if !spec.doc.is_empty() {
        out.push("description", Value::from(spec.doc));
    }
    let default = spec
        .default
        .and_then(|text| ghidorah_json::parse(text, &Limits::DEFAULT).ok());
    if let Some(value) = default {
        out.push("default", value);
    }
    Value::Object(out)
}

/// Gives the input schema of `tool`: its arguments, then the global arguments that apply.
#[must_use]
pub fn input_schema<S: 'static>(tool: &ToolSpec<S>) -> Value {
    let mut specs = tool.args.to_vec();
    specs.extend(globals_of(tool));
    Value::Object(object_schema(&specs))
}

/// Gives the `tools/list` entry of `tool`:
/// `{ name, title, description, inputSchema, annotations }`.
///
/// The annotations hold `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint` and
/// `openWorldHint`.
#[must_use]
pub fn tool_entry<S: 'static>(tool: &ToolSpec<S>) -> Value {
    let a = tool.annotations;
    Value::object([
        ("name", Value::from(tool.name)),
        ("title", Value::from(tool.title)),
        ("description", Value::from(tool.description)),
        ("inputSchema", input_schema(tool)),
        (
            "annotations",
            Value::object([
                ("title", Value::from(tool.title)),
                ("readOnlyHint", Value::Bool(a.read_only)),
                ("destructiveHint", Value::Bool(a.destructive)),
                ("idempotentHint", Value::Bool(a.idempotent)),
                ("openWorldHint", Value::Bool(a.open_world)),
            ]),
        ),
    ])
}

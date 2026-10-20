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
//!
//! Three detail levels exist ([`Detail`]). The catalog of `tools/list` uses the short levels,
//! so the catalog stays small (AC-131a, AC-131b). `tool_search` with level `full` gives the
//! full schema with every doc, default and bound. A global argument takes the default of the
//! tool, for example the page size of `limit`.
//!
//! | Level | Own arguments | Nested objects | Global arguments |
//! |---|---|---|---|
//! | [`Detail::Full`] | every keyword, the doc and the default | every keyword | all, with docs |
//! | [`Detail::Catalog`] | the type, the enum and `maxItems` | the member types | the kept globals, type only |
//! | [`Detail::Compact`] | the type and the enum | `{ type: "object" }` | the kept globals, type only |
//!
//! A published schema holds each key that the tool tells the agent to send. So the catalog
//! levels keep a global argument when one of these rules holds ([`kept_global`]):
//!
//! - The name is in [`CATALOG_GLOBALS`].
//! - The name is `force`. A tool with `force` gives it in the repair call of a blocked write.
//! - The global is the fuel `max_steps`. A fuel stop gives a repair call with more fuel.
//! - The text of the tool names the global ([`text_names`]). The catalog level reads the
//!   description and the summary. The compact level reads only the summary, its published text.
//! - An example of the tool sends the global.

use ghidorah_json::{Limits, Number, Object, Value};

use crate::args::{global_default, globals_of};
use crate::errors::count;
use crate::spec::{ArgKind, ArgSpec, Role, ToolSpec};

/// The root keys that a schema must not have (AC-129b).
pub const ROOT_COMBINATORS: [&str; 7] = ["oneOf", "anyOf", "allOf", "not", "if", "then", "else"];

/// The global arguments that the catalog levels always keep. [`kept_global`] adds the globals
/// that a tool names. The server instructions name the others.
pub const CATALOG_GLOBALS: [&str; 3] = ["binary_id", "limit", "cursor"];

/// The detail level of a schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Detail {
    /// Every keyword and every doc: `tool_search` with level `full`.
    Full,
    /// The catalog of the `full` and `readonly` profiles.
    Catalog,
    /// The catalog of the `mini` profile.
    Compact,
}

fn address_type() -> Value {
    Value::Array(vec![Value::from("integer"), Value::from("string")])
}

fn integer(value: i64) -> Value {
    Number::parse(&value.to_string()).map_or(Value::Null, Value::Number)
}

/// Gives an object schema of `specs` at `detail`, then the optional members `extra`, with no
/// other members.
fn object_schema<'a>(
    specs: impl Iterator<Item = &'a ArgSpec>,
    detail: Detail,
    extra: Vec<(&str, Value)>,
) -> Object {
    let mut properties = Object::new();
    let mut required = Vec::new();
    for spec in specs {
        properties.push(spec.name, schema_at(spec, detail));
        if spec.required {
            required.push(Value::from(spec.name));
        }
    }
    for (name, schema) in extra {
        properties.push(name, schema);
    }
    let mut out = Object::new();
    out.push("type", Value::from("object"));
    out.push("properties", Value::Object(properties));
    if !required.is_empty() {
        out.push("required", Value::Array(required));
    }
    out.push("additionalProperties", Value::Bool(false));
    out
}

fn kind_schema(kind: &ArgKind, detail: Detail) -> Object {
    let full = detail == Detail::Full;
    let mut out = Object::new();
    match kind {
        ArgKind::Addr => out.push("type", address_type()),
        ArgKind::AddrList(max) => {
            out.push("type", Value::from("array"));
            if detail != Detail::Compact {
                out.push("items", Value::object([("type", address_type())]));
                out.push("maxItems", count(*max));
            }
        }
        ArgKind::Id(kinds) => {
            out.push("type", Value::from("string"));
            if full {
                let names: Vec<&str> = kinds
                    .iter()
                    .map(|k| k.prefix().trim_end_matches(':'))
                    .collect();
                out.push("pattern", Value::from(format!("^({}):", names.join("|"))));
            }
        }
        ArgKind::Int { min, max } => {
            out.push("type", Value::from("integer"));
            if full {
                out.push("minimum", integer(*min));
                out.push("maximum", integer(*max));
            }
        }
        ArgKind::Str(max) => {
            out.push("type", Value::from("string"));
            if full {
                out.push("maxLength", count(*max));
            }
        }
        ArgKind::Enum(values) => {
            if full {
                out.push("type", Value::from("string"));
            }
            out.push(
                "enum",
                Value::Array(values.iter().map(|v| Value::from(*v)).collect()),
            );
        }
        ArgKind::Bool => out.push("type", Value::from("boolean")),
        ArgKind::Obj(members) => match detail {
            Detail::Full => out = object_schema(members.iter(), detail, Vec::new()),
            Detail::Catalog => {
                let properties = members.iter().map(|m| (m.name, schema_at(m, detail)));
                out.push("type", Value::from("object"));
                out.push("properties", Value::Object(properties.collect()));
            }
            Detail::Compact => out.push("type", Value::from("object")),
        },
        ArgKind::List(item, max) => {
            out.push("type", Value::from("array"));
            if detail != Detail::Compact {
                out.push("items", schema_at(item, detail));
                out.push("maxItems", count(*max));
            }
        }
        ArgKind::Json => {}
    }
    out
}

/// Gives the schema of one argument at `detail`. Only the full level adds the doc and the
/// default.
fn schema_at(spec: &ArgSpec, detail: Detail) -> Value {
    let mut out = kind_schema(&spec.kind, detail);
    if detail != Detail::Full {
        return Value::Object(out);
    }
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

/// Gives the full schema of one argument.
#[must_use]
pub fn arg_schema(spec: &ArgSpec) -> Value {
    schema_at(spec, Detail::Full)
}

/// Gives the full input schema of `tool`: its arguments, then the global arguments that
/// apply.
#[must_use]
pub fn input_schema<S: 'static>(tool: &ToolSpec<S>) -> Value {
    catalog_schema(tool, Detail::Full)
}

/// Gives the input schema of `tool` at `detail`: its arguments, then the global arguments
/// that apply.
///
/// The full level adds the defaults of the tool ([`global_default`]). The catalog levels keep
/// the globals of [`kept_global`] with their type only. See the module doc.
#[must_use]
pub fn catalog_schema<S: 'static>(tool: &ToolSpec<S>, detail: Detail) -> Value {
    let globals = globals_of(tool);
    if detail == Detail::Full {
        let full = globals
            .iter()
            .map(|g| {
                let mut schema = schema_at(g, detail);
                let default = global_default(tool, g.name).map(Value::from);
                if let (Value::Object(o), Some(value)) = (&mut schema, default) {
                    o.push("default", value);
                }
                (g.name, schema)
            })
            .collect();
        return Value::Object(object_schema(tool.args.iter(), detail, full));
    }
    let kept = globals
        .iter()
        .filter(|g| kept_global(tool, g, detail))
        .map(|g| (g.name, type_only(&g.kind)))
        .collect();
    Value::Object(object_schema(tool.args.iter(), detail, kept))
}

/// Tells if the schema of `tool` at `detail` keeps the global argument `global`. The full
/// level keeps every global. See the module doc for the rules of the catalog levels.
#[must_use]
pub fn kept_global<S: 'static>(tool: &ToolSpec<S>, global: &ArgSpec, detail: Detail) -> bool {
    let described = detail != Detail::Compact && text_names(tool.description, global.name);
    let example = |args: &str| {
        ghidorah_json::parse(args, &Limits::DEFAULT)
            .ok()
            .is_some_and(|v| v.get(global.name).is_some())
    };
    detail == Detail::Full
        || CATALOG_GLOBALS.contains(&global.name)
        || global.name == "force"
        || global.role == Role::Fuel
        || described
        || text_names(tool.summary, global.name)
        || tool.examples.iter().any(|e| example(e.args))
}

/// Tells if `text` tells the agent to send the argument `name`. The name is a word of the text.
/// It holds `_`, or a value comes after it, for example `force true` or `session *`.
#[must_use]
pub fn text_names(text: &str, name: &str) -> bool {
    let words: Vec<&str> = text
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | '.' | ':' | ';'))
        .filter(|w| !w.is_empty())
        .collect();
    let value = |w: Option<&&str>| {
        w.is_some_and(|w| {
            matches!(*w, "true" | "false" | "*") || w.starts_with(|c: char| c.is_ascii_digit())
        })
    };
    words
        .iter()
        .enumerate()
        .any(|(i, w)| *w == name && (name.contains('_') || value(words.get(i + 1))))
}

/// Gives the schema of a kind with its JSON type only.
fn type_only(kind: &ArgKind) -> Value {
    let name = match kind {
        ArgKind::Addr => return Value::object([("type", address_type())]),
        ArgKind::Json => return Value::Object(Object::new()),
        ArgKind::AddrList(_) | ArgKind::List(..) => "array",
        ArgKind::Id(_) | ArgKind::Str(_) | ArgKind::Enum(_) => "string",
        ArgKind::Int { .. } => "integer",
        ArgKind::Bool => "boolean",
        ArgKind::Obj(_) => "object",
    };
    Value::object([("type", Value::from(name))])
}

/// Gives the full `tools/list` entry of `tool`:
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

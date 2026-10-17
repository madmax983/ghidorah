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
//! | `Id(kinds)` | `{ type: "string" }`; the description names the prefixes |
//! | `Int { min, max }` | `{ type: "integer", minimum, maximum }` |
//! | `Str(n)` | `{ type: "string", maxLength: n }` |
//! | `Enum(values)` | `{ type: "string", enum: values }` |
//! | `Bool` | `{ type: "boolean" }` |
//! | `Obj(specs)` | a nested object with `additionalProperties: false` |
//! | `List(item, n)` | `{ type: "array", items, maxItems: n }` |
//! | `Json` | `{}` |

use ghidorah_json::Value;

use crate::spec::{ArgSpec, ToolSpec};

/// The root keys that a schema must not have (AC-129b).
pub const ROOT_COMBINATORS: [&str; 7] = ["oneOf", "anyOf", "allOf", "not", "if", "then", "else"];

/// Gives the schema of one argument.
#[must_use]
pub fn arg_schema(spec: &ArgSpec) -> Value {
    let _ = spec;
    Value::Null
}

/// Gives the input schema of `tool`: its arguments, then the global arguments that apply.
#[must_use]
pub fn input_schema<S: 'static>(tool: &ToolSpec<S>) -> Value {
    let _ = tool;
    Value::Null
}

/// Gives the `tools/list` entry of `tool`:
/// `{ name, title, description, inputSchema, annotations }`.
///
/// The annotations hold `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint` and
/// `openWorldHint`.
#[must_use]
pub fn tool_entry<S: 'static>(tool: &ToolSpec<S>) -> Value {
    let _ = tool;
    Value::Null
}

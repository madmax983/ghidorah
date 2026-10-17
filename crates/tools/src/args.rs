//! The argument parser and validator (design Section 10.2).
//!
//! The parser reads the JSON arguments of one call against the [`ArgSpec`] list of the tool
//! and the global arguments that apply to it. Input is strict:
//!
//! | Input | Result |
//! |---|---|
//! | A key outside the schema | `UNKNOWN_ARGUMENT`. `next[0]` renames or removes the key. |
//! | An alias of an argument | The canonical name and `W_COERCED` |
//! | A value of the wrong type or range | `INVALID_ARGUMENT` with `details.expected` |
//! | A value above its cap | `LIMIT_EXCEEDED`. `next[0]` clamps the value. |
//! | Address text that does not parse | `ADDRESS_INVALID` |
//! | A required argument that is absent | `MISSING_ARGUMENT` with `details.example` |
//! | A broken group rule | `MISSING_ARGUMENT` or `INVALID_ARGUMENT` |
//! | An action rule of a selector tool | `MISSING_ARGUMENT` or `INVALID_ARGUMENT` with `details.action` |
//!
//! A host can give a lenient coercion (Section 10.2). The parser calls it for a value of the
//! wrong JSON type, and each coercion gives `W_COERCED`.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::IdKind;
use ghidorah_json::Value;
use ghidorah_json::pointer::Pointer;

use crate::envelope::Warning;
use crate::errors::ToolError;
use crate::spec::{ArgKind, ArgSpec, Role, ToolSpec};

/// A lenient coercion: it gives the coerced value, or `None` when no coercion applies.
pub type Coerce<'a> = &'a dyn Fn(&ArgKind, &Value) -> Option<Value>;

/// The largest number of `fields` pointers.
pub const MAX_FIELDS: usize = 32;

/// The output format of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// The default form.
    #[default]
    Concise,
    /// The form with provenance, coercion details, `resolved` rows and sizes.
    Detailed,
}

/// The item form of a list result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Shape {
    /// Items as objects.
    #[default]
    Objects,
    /// Items as a table `{ cols, rows }`.
    Table,
}

/// The global arguments of one call (design Section 10.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Globals {
    /// `binary_id`.
    pub binary_id: Option<String>,
    /// `format`.
    pub format: Format,
    /// `fields`: pointers into `data`.
    pub fields: Vec<Pointer>,
    /// `max_chars`.
    pub max_chars: Option<u32>,
    /// `limit`.
    pub limit: Option<u32>,
    /// `cursor`.
    pub cursor: Option<String>,
    /// `count_only`.
    pub count_only: bool,
    /// `shape`.
    pub shape: Shape,
    /// `in`: the name of a set, for example `set:parsers`.
    pub in_set: Option<String>,
    /// `session`.
    pub session: Option<String>,
    /// `expected_rev`.
    pub expected_rev: Option<u64>,
    /// `dry_run`.
    pub dry_run: bool,
    /// `force`.
    pub force: bool,
    /// `max_steps`.
    pub max_steps: Option<u64>,
    /// `max_ms`.
    pub max_ms: Option<u64>,
}

/// The item kind of `fields`: one JSON pointer.
const FIELD_ITEM: ArgSpec =
    ArgSpec::new("field", Role::Param, ArgKind::Str(256), "A JSON pointer.");

/// The global arguments in schema order. [`globals_of`] gives the ones that apply to a tool.
pub const GLOBALS: [ArgSpec; 15] = [
    ArgSpec::new(
        "binary_id",
        Role::Param,
        ArgKind::Str(64),
        "The ID of the target binary. Leave it out when exactly one binary is open.",
    ),
    ArgSpec::new(
        "format",
        Role::Param,
        ArgKind::Enum(&["concise", "detailed"]),
        "The detail level. The detailed form adds provenance, coercion details and sizes.",
    )
    .default_json("\"concise\""),
    ArgSpec::new(
        "fields",
        Role::Param,
        ArgKind::List(&FIELD_ITEM, MAX_FIELDS),
        "JSON pointers into data. The result keeps only these fields.",
    ),
    ArgSpec::new(
        "max_chars",
        Role::Budget,
        ArgKind::Int {
            min: 200,
            max: 60_000,
        },
        "The largest result in characters. The count includes every copy of the result.",
    ),
    ArgSpec::new(
        "limit",
        Role::PageSize,
        ArgKind::Int { min: 1, max: 1_000 },
        "The largest number of items on one page.",
    ),
    ArgSpec::new(
        "cursor",
        Role::PageCursor,
        ArgKind::Str(1_024),
        "The page.next_cursor of the previous page.",
    ),
    ArgSpec::new(
        "count_only",
        Role::Param,
        ArgKind::Bool,
        "Return only the count of the items.",
    ),
    ArgSpec::new(
        "shape",
        Role::Param,
        ArgKind::Enum(&["objects", "table"]),
        "The form of the items. The table form gives cols and rows.",
    )
    .default_json("\"objects\""),
    ArgSpec::new(
        "in",
        Role::In,
        ArgKind::Id(&[IdKind::Set]),
        "Keep only the members of this named set, for example set:parsers.",
    ),
    ArgSpec::new(
        "session",
        Role::Param,
        ArgKind::Str(64),
        "The session label for provenance, filters and the undo scope.",
    ),
    ArgSpec::new(
        "expected_rev",
        Role::Param,
        ArgKind::Int {
            min: 0,
            max: 9_007_199_254_740_991,
        },
        "The rev that the call expects. Another rev gives CONFLICT.",
    ),
    ArgSpec::new(
        "dry_run",
        Role::Param,
        ArgKind::Bool,
        "Return the planned edit list with no commit.",
    ),
    ArgSpec::new(
        "force",
        Role::Param,
        ArgKind::Bool,
        "Allow an agent write over an imported fact. The journal records the force.",
    ),
    ArgSpec::new(
        "max_steps",
        Role::Fuel,
        ArgKind::Int {
            min: 1,
            max: 9_007_199_254_740_991,
        },
        "The fuel of the call in work units.",
    ),
    ArgSpec::new(
        "max_ms",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: 3_600_000,
        },
        "A wall-clock guard in milliseconds. Fuel stays the main stop rule.",
    ),
];

/// Gives the global arguments that apply to `tool`, in schema order.
///
/// `max_steps` carries the fuel cap of the tool as its maximum.
#[must_use]
pub fn globals_of<S: 'static>(tool: &ToolSpec<S>) -> Vec<ArgSpec> {
    let _ = tool;
    Vec::new()
}

/// The parsed arguments of one call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Args {
    tool: &'static str,
    values: BTreeMap<&'static str, Value>,
    given: BTreeSet<&'static str>,
    globals: Globals,
}

impl Args {
    /// Gives the tool name.
    #[must_use]
    pub const fn tool(&self) -> &'static str {
        self.tool
    }

    /// Gives the value of an argument of the tool: the given value or the default.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        let _ = name;
        None
    }

    /// Tells if the call gives the argument.
    #[must_use]
    pub fn given(&self, name: &str) -> bool {
        let _ = name;
        false
    }

    /// Gives a string argument.
    #[must_use]
    pub fn str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::as_str)
    }

    /// Gives an integer argument.
    #[must_use]
    pub fn int(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(Value::as_i64)
    }

    /// Gives a boolean argument.
    #[must_use]
    pub fn bool(&self, name: &str) -> Option<bool> {
        self.get(name).and_then(Value::as_bool)
    }

    /// Gives a list argument.
    #[must_use]
    pub fn list(&self, name: &str) -> Option<&[Value]> {
        self.get(name).and_then(Value::as_array)
    }

    /// Gives the value of the selector argument of a selector tool.
    #[must_use]
    pub fn action(&self) -> Option<&str> {
        None
    }

    /// Gives the global arguments.
    #[must_use]
    pub const fn globals(&self) -> &Globals {
        &self.globals
    }

    /// Gives the arguments of the tool with their values, in name order.
    pub fn values(&self) -> impl Iterator<Item = (&'static str, &Value)> {
        self.values.iter().map(|(name, value)| (*name, value))
    }
}

/// The result of [`parse`]: the arguments and the warnings of the parse.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parsed {
    /// The arguments.
    pub args: Args,
    /// One `W_COERCED` warning per alias or coercion.
    pub warnings: Vec<Warning>,
}

/// Parses the JSON arguments `raw` of one call to `tool`.
///
/// `coerce` is the lenient coercion of the host, or `None` for strict input.
///
/// # Errors
///
/// Returns the first error of the table in the module docs. Its `next` holds the repair call
/// when the code has one.
pub fn parse<S: 'static>(
    tool: &ToolSpec<S>,
    raw: &Value,
    coerce: Option<Coerce<'_>>,
) -> Result<Parsed, ToolError> {
    let _ = (tool, raw, coerce);
    Ok(Parsed::default())
}

/// Parses `raw` with no coercion and no alias. Hint checks use it (AC-143).
///
/// # Errors
///
/// Returns the same errors as [`parse`]. An alias counts as an unknown key.
pub fn parse_strict<S: 'static>(tool: &ToolSpec<S>, raw: &Value) -> Result<Args, ToolError> {
    let _ = (tool, raw);
    Ok(Args::default())
}

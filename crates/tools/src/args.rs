//! The argument parser and validator (design Section 10.2).
//!
//! The parser reads the JSON arguments of one call against the [`ArgSpec`] list of the tool
//! and the global arguments that apply to it. Input is strict:
//!
//! | Input | Result |
//! |---|---|
//! | A key outside the schema | `UNKNOWN_ARGUMENT`. `next[0]` renames or removes the key. A rename to a list argument puts a single value in an array. |
//! | An alias of an argument | The canonical name and `W_COERCED` |
//! | A value of the wrong type or range | `INVALID_ARGUMENT` with `details.expected` |
//! | A value above its cap | `LIMIT_EXCEEDED`. `next[0]` clamps the value. |
//! | Address text that does not parse | `ADDRESS_INVALID` |
//! | An ID prefix with a body that does not parse | `INVALID_ARGUMENT` that names the ID kind |
//! | An address in a list item | A type check only. The handler gives an error for that item. |
//! | A required argument that is absent | `MISSING_ARGUMENT` with `details.example` |
//! | A broken group rule | `MISSING_ARGUMENT` or `INVALID_ARGUMENT` |
//! | An action rule of a selector tool | `MISSING_ARGUMENT` or `INVALID_ARGUMENT` with `details.action` |
//!
//! A host can give a lenient coercion (Section 10.2). The parser calls it for a value of the
//! wrong JSON type, and each coercion gives `W_COERCED`.

mod walk;

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{ErrorCode, IdKind};
use ghidorah_json::Value;
use ghidorah_json::pointer::{self, Pointer};

use crate::envelope::Warning;
use crate::errors::ToolError;
use crate::spec::{ArgKind, ArgSpec, BinaryArg, GroupRule, Role, ToolSpec};
use walk::Walk;

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
            min: 1_000,
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
/// `max_steps` carries the fuel cap of the tool as its maximum. A tool with no binary has no
/// `binary_id` and no `in`, because a set belongs to a binary. [`global_default`] gives the
/// defaults of the tool.
#[must_use]
pub fn globals_of<S: 'static>(tool: &ToolSpec<S>) -> Vec<ArgSpec> {
    let list = tool.list.is_some();
    let bound = tool.binary != BinaryArg::None;
    GLOBALS
        .iter()
        .filter(|g| match g.name {
            "binary_id" => bound,
            "in" => list && bound,
            "limit" | "cursor" | "count_only" | "shape" => list,
            "expected_rev" | "dry_run" => tool.mutating,
            "force" => tool.force,
            "max_steps" | "max_ms" => tool.fuel.is_some(),
            _ => true,
        })
        .map(|g| match (g.name, tool.fuel) {
            ("max_steps", Some(fuel)) => ArgSpec {
                kind: ArgKind::Int {
                    min: 1,
                    max: i64::try_from(fuel.cap).unwrap_or(i64::MAX),
                },
                ..*g
            },
            _ => *g,
        })
        .collect()
}

/// Gives the default of the global argument `name` for `tool`, when the tool sets one. The
/// defaults are the budget of `max_chars`, the page size of `limit` and the fuel of `max_steps`.
#[must_use]
pub fn global_default<S: 'static>(tool: &ToolSpec<S>, name: &str) -> Option<u64> {
    match name {
        "max_chars" => Some(u64::from(tool.max_chars)),
        "limit" => tool.list.map(|l| u64::from(l.default_limit)),
        "max_steps" => tool.fuel.map(|f| f.default),
        _ => None,
    }
}

/// The parsed arguments of one call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Args {
    tool: &'static str,
    values: BTreeMap<&'static str, Value>,
    given: BTreeSet<&'static str>,
    selector: Option<&'static str>,
    globals: Globals,
    canonical: Value,
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
        self.values.get(name)
    }

    /// Tells if the call gives the argument.
    #[must_use]
    pub fn given(&self, name: &str) -> bool {
        self.given.contains(name)
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
        self.selector.and_then(|name| self.str(name))
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

    /// Gives the arguments of the call with canonical names, in input order.
    ///
    /// Aliases have their canonical names, and defaults are absent. Repair calls start here.
    #[must_use]
    pub const fn canonical(&self) -> &Value {
        &self.canonical
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
    parse_with(tool, raw, coerce, true)
}

/// Parses `raw` with no coercion and no alias. Hint checks use it (AC-143).
///
/// # Errors
///
/// Returns the same errors as [`parse`]. An alias counts as an unknown key.
pub fn parse_strict<S: 'static>(tool: &ToolSpec<S>, raw: &Value) -> Result<Args, ToolError> {
    parse_with(tool, raw, None, false).map(|parsed| parsed.args)
}

/// Checks one value against one argument spec, with no coercion.
///
/// # Errors
///
/// Returns the error of the value, as [`parse`] gives it.
pub fn check_value(spec: &ArgSpec, value: &Value) -> Result<(), ToolError> {
    let mut walk = Walk {
        tool: "",
        base: Value::Null,
        coerce: None,
        aliases: false,
        format: Format::Concise,
        warnings: Vec::new(),
    };
    walk.value(spec, value, &mut Vec::new()).map(|_| ())
}

fn parse_with<S: 'static>(
    tool: &ToolSpec<S>,
    raw: &Value,
    coerce: Option<Coerce<'_>>,
    aliases: bool,
) -> Result<Parsed, ToolError> {
    let Value::Object(object) = raw else {
        return Err(ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "arguments")
            .path("")
            .detail("expected", Value::from("a JSON object")));
    };
    let globals = globals_of(tool);
    let detailed = raw.get("format").and_then(Value::as_str) == Some("detailed");
    let mut walk = Walk {
        tool: tool.name,
        base: Value::Object(walk::fix_object(tool.args, &globals, object, aliases)),
        coerce,
        aliases,
        format: if detailed {
            Format::Detailed
        } else {
            Format::Concise
        },
        warnings: Vec::new(),
    };
    let level = walk
        .level(tool.args, &globals, object, &mut Vec::new())
        .map_err(|e| with_example(tool, e))?;
    let mut args = Args {
        tool: tool.name,
        selector: tool.selector().map(|s| s.name),
        canonical: std::mem::take(&mut walk.base),
        ..Args::default()
    };
    let mut global_values = BTreeMap::new();
    for (spec, value, given) in level {
        if tool.arg(spec.name).is_some() {
            if given {
                args.given.insert(spec.name);
            }
            args.values.insert(spec.name, value);
        } else {
            global_values.insert(spec.name, value);
        }
    }
    groups(tool, &args)?;
    actions(tool, &args)?;
    args.globals = read_globals(&global_values)?;
    Ok(Parsed {
        args,
        warnings: walk.warnings,
    })
}

/// Gives the JSON value of the first example of `tool`, or `null`.
fn first_example<S: 'static>(tool: &ToolSpec<S>) -> Value {
    tool.examples
        .first()
        .and_then(|e| ghidorah_json::parse(e.args, &ghidorah_json::Limits::DEFAULT).ok())
        .unwrap_or_default()
}

/// Adds the first example of the tool to a `MISSING_ARGUMENT` error with no example.
fn with_example<S: 'static>(tool: &ToolSpec<S>, error: ToolError) -> ToolError {
    let has = error
        .details
        .as_ref()
        .is_some_and(|d| d.contains_key("example"));
    if error.code == ErrorCode::MissingArgument && !has {
        error.detail("example", first_example(tool))
    } else {
        error
    }
}

fn groups<S: 'static>(tool: &ToolSpec<S>, args: &Args) -> Result<(), ToolError> {
    for group in tool.groups {
        let present: Vec<&str> = group
            .members
            .iter()
            .copied()
            .filter(|m| args.given(m))
            .collect();
        let members = Value::Array(group.members.iter().map(|m| Value::from(*m)).collect());
        let first = group.members.first().copied().unwrap_or_default();
        match (group.rule, present.as_slice()) {
            (_, []) => {
                return Err(ToolError::new(ErrorCode::MissingArgument)
                    .var("field", first)
                    .path(&format!("/{first}"))
                    .detail("group", members)
                    .detail("example", first_example(tool)));
            }
            (GroupRule::ExactlyOne, [_, second, ..]) => {
                let names: Vec<&str> = group.members.to_vec();
                return Err(ToolError::new(ErrorCode::InvalidArgument)
                    .var("field", second)
                    .path(&format!("/{second}"))
                    .detail("group", members)
                    .detail(
                        "expected",
                        Value::from(format!("exactly one of {}", names.join(", "))),
                    ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn actions<S: 'static>(tool: &ToolSpec<S>, args: &Args) -> Result<(), ToolError> {
    let Some((selector, action)) = tool
        .selector()
        .and_then(|s| args.str(s.name).map(|v| (s.name, v)))
    else {
        return Ok(());
    };
    let names = |rules: &[(&str, &str)]| rules.iter().any(|(s, v)| *s == selector && *v == action);
    let example = tool
        .action(action)
        .and_then(|a| ghidorah_json::parse(a.example, &ghidorah_json::Limits::DEFAULT).ok())
        .unwrap_or_default();
    if let Some(spec) = tool
        .args
        .iter()
        .find(|s| names(s.required_when) && !args.given(s.name))
    {
        return Err(ToolError::new(ErrorCode::MissingArgument)
            .var("field", spec.name)
            .path(&format!("/{}", spec.name))
            .detail("action", Value::from(action))
            .detail("example", example));
    }
    if let Some(spec) = tool
        .args
        .iter()
        .find(|s| names(s.forbidden_when) && args.given(s.name))
    {
        return Err(ToolError::new(ErrorCode::InvalidArgument)
            .var("field", spec.name)
            .path(&format!("/{}", spec.name))
            .detail("action", Value::from(action))
            .detail("forbidden", Value::from(spec.name))
            .detail(
                "expected",
                Value::from(format!("no {} for the action {action}", spec.name)),
            ));
    }
    Ok(())
}

/// Reads the global values into [`Globals`].
fn read_globals(values: &BTreeMap<&'static str, Value>) -> Result<Globals, ToolError> {
    let text = |name: &str| values.get(name).and_then(Value::as_str).map(str::to_owned);
    let flag = |name: &str| values.get(name).and_then(Value::as_bool).unwrap_or(false);
    let number = |name: &str| values.get(name).and_then(Value::as_u64);
    let small = |name: &str| number(name).and_then(|v| u32::try_from(v).ok());
    let mut fields = Vec::new();
    let list = values
        .get("fields")
        .and_then(Value::as_array)
        .unwrap_or_default();
    for (i, item) in list.iter().enumerate() {
        let parsed = item.as_str().map(pointer::parse);
        match parsed {
            Some(Ok(p)) => fields.push(p),
            _ => {
                return Err(ToolError::new(ErrorCode::InvalidArgument)
                    .var("field", &format!("fields/{i}"))
                    .path(&format!("/fields/{i}"))
                    .detail(
                        "expected",
                        Value::from("a JSON pointer such as /items/*/id"),
                    ));
            }
        }
    }
    Ok(Globals {
        binary_id: text("binary_id"),
        format: if text("format").as_deref() == Some("detailed") {
            Format::Detailed
        } else {
            Format::Concise
        },
        fields,
        max_chars: small("max_chars"),
        limit: small("limit"),
        cursor: text("cursor"),
        count_only: flag("count_only"),
        shape: if text("shape").as_deref() == Some("table") {
            Shape::Table
        } else {
            Shape::Objects
        },
        in_set: text("in"),
        session: text("session"),
        expected_rev: number("expected_rev"),
        dry_run: flag("dry_run"),
        force: flag("force"),
        max_steps: number("max_steps"),
        max_ms: number("max_ms"),
    })
}

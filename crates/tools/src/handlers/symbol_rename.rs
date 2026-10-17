//! `symbol_rename`: rename functions, labels, data and variables (design Section 10.4, tool 16).
//!
//! | Call | Result |
//! |---|---|
//! | `{ target, name }` | one rename. An error fails the call. |
//! | `{ items: [{ target, name, evidence? }] }` | one rename per item in one transaction. Each item gives `{ input, ok, data \| error }` (AC-144). |
//!
//! | Target | Fact |
//! |---|---|
//! | `fn:`, an address, a name or another address input | the primary symbol at the address. A function entry gets a function symbol, another address gets a label. |
//! | `var:` | the name fact of the variable |
//!
//! A rename item is `{ target, id, old, new, source, noop }`. `id` is the `fn:` ID of a
//! function entry, the `var:` ID of a variable, or else the address. `evidence` holds IDs or
//! `func_similar` feature texts. An item `evidence` replaces the call `evidence`. A call
//! `confidence` adds the evidence text `confidence:<level>`. The journal keeps the evidence of
//! each `SetName` edit, and `history_list` shows it.
//!
//! An agent rename over an imported name gives `BLOCKED_BY_HIGHER_PRIORITY_SOURCE`. Then
//! `next[0]` repeats the call with `force: true`.

pub(crate) mod edits;

use ghidorah_base::{Address, ErrorCode, FuncId, Id, VarId};
use ghidorah_db::{Edit, SymKind, Tx, VarField};
use ghidorah_json::{Object, Value};

use super::func_sections::{self as fs, Namer};
use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::hints::Call;
use crate::outshape::{Field, OutputShape};
use crate::resolve;
use crate::session::Session;
use crate::spec::{
    Annotations, ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec,
};

/// The largest number of items in one call.
pub const MAX_ITEMS: usize = 100;

/// The largest number of evidence entries of one rename.
pub const MAX_EVIDENCE: usize = 16;

/// The longest evidence entry in characters.
pub const MAX_EVIDENCE_CHARS: usize = 200;

/// The longest name in characters.
pub const MAX_NAME_CHARS: usize = 256;

/// The values of `confidence`.
pub const CONFIDENCES: [&str; 3] = ["low", "medium", "high"];

/// The `why` of the repair call that adds `force: true`.
pub const WHY_FORCE: &str = "Send the call again with force true when the change is correct.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_FORCE];

const EVIDENCE_ITEM: ArgSpec = ArgSpec::new(
    "entry",
    Role::Param,
    ArgKind::Str(MAX_EVIDENCE_CHARS),
    "An ID or a func_similar feature text.",
);

const TARGET_DOC: &str = "The function, address or variable to rename, for example fn:0x401130 or var:0x401130/stack:-0x14.";

const ITEM_ARGS: &[ArgSpec] = &[
    ArgSpec::new("target", Role::Target, ArgKind::Addr, TARGET_DOC).required(),
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(MAX_NAME_CHARS),
        "The new name.",
    )
    .required(),
    ArgSpec::new(
        "evidence",
        Role::Param,
        ArgKind::List(&EVIDENCE_ITEM, MAX_EVIDENCE),
        "The evidence of this item. It replaces the evidence of the call.",
    ),
];

const ITEM: ArgSpec = ArgSpec::new(
    "item",
    Role::Param,
    ArgKind::Obj(ITEM_ARGS),
    "One rename: a target, a name and its evidence.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new("target", Role::Target, ArgKind::Addr, TARGET_DOC),
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(MAX_NAME_CHARS),
        "The new name of target.",
    ),
    ArgSpec::new(
        "items",
        Role::Param,
        ArgKind::List(&ITEM, MAX_ITEMS),
        "More renames in one transaction. One bad item does not stop the other items.",
    ),
    ArgSpec::new(
        "evidence",
        Role::Param,
        ArgKind::List(&EVIDENCE_ITEM, MAX_EVIDENCE),
        "IDs or func_similar feature texts that support the new names. The journal keeps them.",
    ),
    ArgSpec::new(
        "confidence",
        Role::Param,
        ArgKind::Enum(&CONFIDENCES),
        "How sure you are of the new names. The journal keeps it with the evidence.",
    ),
];

const RESULT: &[Field] = &[
    Field::req("target", OutputShape::Any),
    Field::req("id", OutputShape::Str),
    Field::req("old", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("new", OutputShape::Str),
    Field::req("source", OutputShape::Str),
    Field::req("noop", OutputShape::Bool),
];
const RESULT_SHAPE: OutputShape = OutputShape::Obj(RESULT);
const ITEM_OUT: &[Field] = &[
    Field::opt("target", OutputShape::Any),
    Field::opt("id", OutputShape::Str),
    Field::opt("old", OutputShape::Nullable(&OutputShape::Str)),
    Field::opt("new", OutputShape::Str),
    Field::opt("source", OutputShape::Str),
    Field::opt("noop", OutputShape::Bool),
    Field::opt("input", OutputShape::Any),
    Field::opt("ok", OutputShape::Bool),
    Field::opt("data", RESULT_SHAPE),
    Field::opt("error", OutputShape::Any),
];
const ITEM_OUT_SHAPE: OutputShape = OutputShape::Obj(ITEM_OUT);
const FIELDS: &[Field] = &[
    Field::req("items", OutputShape::List(&ITEM_OUT_SHAPE)),
    Field::opt("ok_count", OutputShape::Int),
    Field::opt("error_count", OutputShape::Int),
    Field::req("rev", OutputShape::Int),
    Field::req("tx", OutputShape::Nullable(&OutputShape::Str)),
];

/// `symbol_rename`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Rename symbols",
    summary: "Rename the symbols of functions, labels, data and variables.",
    description: "Rename the symbols of functions, labels, data and variables. \
                  Send target and name for one rename, or items for up to 100 renames in one transaction. \
                  Add evidence with IDs or func_similar feature texts, so that the journal keeps the reason. \
                  IDs such as fn:0x401130 stay the same after a rename. \
                  A name from the symbol table of the binary has a higher rank than your name, so its rename needs force true.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "items"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations::EDIT,
    mutating: true,
    profiles: &[Profile::Full, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"target":"0x1090","name":"read_input"}"#,
            golden: "tests/golden/tools/symbol_rename.1.json",
        },
        Example {
            args: r#"{"items":[{"target":"0x1094","name":"check_len","evidence":["fn:0x11e0"]}],"confidence":"high"}"#,
            golden: "tests/golden/tools/symbol_rename.2.json",
        },
    ],
    force: true,
    ..ToolSpec::base("symbol_rename", run)
};

/// One rename of a call: the target, the new name, the evidence and the argument path.
struct Rename<'a> {
    target: &'a Value,
    name: &'a str,
    evidence: Vec<String>,
    /// The JSON pointer of the rename in the arguments: empty, or `/items/<i>`.
    at: String,
    /// The repair call with `force: true`, for a call with one rename.
    retry: Option<Call>,
}

/// Gives the strings of a list argument.
fn texts(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Gives the evidence of a rename: `own` or else `call`, and then the confidence entry.
fn evidence(own: Option<&Value>, call: &[String], confidence: Option<&str>) -> Vec<String> {
    let mut out = if own.is_some() {
        texts(own)
    } else {
        call.to_vec()
    };
    out.extend(confidence.map(|c| format!("confidence:{c}")));
    out
}

/// Checks a new name: 1 to [`MAX_NAME_CHARS`] characters and no control character.
fn check_name(name: &str, path: &str) -> Result<(), ToolError> {
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(ToolError::new(ErrorCode::InvalidArgument)
            .var("field", path.trim_start_matches('/'))
            .path(path)
            .detail(
                "expected",
                Value::from("a name of 1 to 256 characters with no control character"),
            ));
    }
    Ok(())
}

/// Gives the `MISSING_ARGUMENT` error of the argument `field`.
pub(crate) fn missing(field: &str) -> ToolError {
    ToolError::new(ErrorCode::MissingArgument)
        .var("field", field)
        .path(&format!("/{field}"))
}

/// Gives the `INVALID_ARGUMENT` error of an argument that the call with `items` does not take.
pub(crate) fn not_with_items(field: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field)
        .path(&format!("/{field}"))
        .detail(
            "expected",
            Value::from("no value: each item of items holds its own value"),
        )
}

/// Gives the address of an address input on the program of a transaction.
///
/// # Errors
///
/// Returns the errors of [`resolve::address`] with the field path `path`.
pub(crate) fn address_at(tx: &Tx<'_>, input: &Value, path: &str) -> Result<Address, ToolError> {
    resolve::address(tx.program(), input, &fs::site(path)).map(|(a, _)| a)
}

/// Gives the ID, the old name and the edit of a variable rename.
fn var_rename(
    tx: &Tx<'_>,
    var: VarId,
    name: &str,
    path: &str,
) -> Result<(String, Option<String>, Edit), ToolError> {
    let p = tx.program();
    if p.func(var.func).is_none() {
        return Err(ToolError::new(ErrorCode::NotFound)
            .var("kind", "function")
            .path(path)
            .detail("kind", Value::from("function")));
    }
    let old = p.var(&var).name.map(|f| f.value.clone());
    let id = var.to_string();
    let edit = Edit::SetVarFact {
        var,
        field: VarField::Name(Some(tx.fact(name.to_owned()))),
    };
    Ok((id, old, edit))
}

/// Gives the ID, the old name and the edit of a symbol rename at an address.
fn symbol_rename(
    tx: &Tx<'_>,
    r: &mut Rename<'_>,
    namer: &Namer,
    path: &str,
) -> Result<(String, Option<String>, Edit), ToolError> {
    let addr = address_at(tx, r.target, path)?;
    let p = tx.program();
    let entry = p.func(FuncId(addr)).is_some();
    let old = p.name(addr).map(|n| namer.text(&n.text));
    let edit = Edit::SetName {
        addr,
        key: None,
        kind: if entry {
            SymKind::Function
        } else {
            SymKind::Label
        },
        primary: true,
        name: Some(tx.fact(r.name.to_owned())),
        evidence: std::mem::take(&mut r.evidence),
    };
    let id = if entry {
        FuncId(addr).to_string()
    } else {
        addr.to_string()
    };
    Ok((id, old, edit))
}

/// Applies one rename. Gives its result item `{ target, id, old, new, source, noop }`.
fn rename_one(tx: &mut Tx<'_>, mut r: Rename<'_>, namer: &Namer) -> Result<Value, ToolError> {
    let name_path = format!("{}/name", r.at);
    let target_path = format!("{}/target", r.at);
    check_name(r.name, &name_path)?;
    let var = r.target.as_str().and_then(|t| match Id::parse(t) {
        Ok(Id::Var(var)) => Some(var),
        _ => None,
    });
    let (id, old, edit) = match var {
        Some(var) => var_rename(tx, var, r.name, &target_path)?,
        None => symbol_rename(tx, &mut r, namer, &target_path)?,
    };
    let source = tx.origin().source;
    let applied = tx
        .apply(edit)
        .map_err(|e| edits::edit_error(&e, &name_path, r.retry.take()))?;
    let mut out = Object::new();
    out.push("target", r.target.clone());
    out.push("id", Value::from(id));
    out.push("old", old.map_or(Value::Null, Value::from));
    out.push("new", Value::from(fs::safe(r.name)));
    out.push("source", Value::from(source.name()));
    out.push("noop", Value::Bool(applied.is_none()));
    Ok(Value::Object(out))
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let single = args.given("target");
    if single && !args.given("name") {
        return Err(missing("name"));
    }
    if !single && args.given("name") {
        return Err(not_with_items("name"));
    }
    let call_evidence = texts(args.get("evidence"));
    let confidence = args.str("confidence");
    let namer = Namer::new();
    let none = Value::Null;
    let (mut out, committed) = edits::commit(session, args, ctx, |tx| {
        if single {
            let r = Rename {
                target: args.get("target").unwrap_or(&none),
                name: args.str("name").unwrap_or_default(),
                evidence: evidence(None, &call_evidence, confidence),
                at: String::new(),
                retry: Some(edits::with_force(args)),
            };
            let item = rename_one(tx, r, &namer)?;
            let mut out = Object::new();
            out.push("items", Value::Array(vec![item]));
            return Ok(out);
        }
        let inputs = args.list("items").unwrap_or_default();
        Ok(fs::per_item("items", inputs, |i, input| {
            let r = Rename {
                target: input.get("target").unwrap_or(&none),
                name: input
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                evidence: evidence(input.get("evidence"), &call_evidence, confidence),
                at: fs::item_path("items", i),
                retry: None,
            };
            rename_one(tx, r, &namer)
        }))
    })?;
    namer.finish(ctx);
    out.push("rev", Value::from(committed.rev));
    out.push("tx", committed.tx_value());
    Ok(Payload::Object(out))
}

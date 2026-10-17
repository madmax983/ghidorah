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

use ghidorah_json::Object;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
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

fn run(_session: &mut Session, _args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(Object::new()))
}

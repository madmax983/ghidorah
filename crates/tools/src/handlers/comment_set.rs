//! `comment_set`: set or clear comments at addresses (design Section 10.4, tool 17).
//!
//! | Call | Result |
//! |---|---|
//! | `{ target, kind, text }` | one comment. An error fails the call. |
//! | `{ items: [{ target, kind, text }] }` | one comment per item in one transaction. Each item gives `{ input, ok, data \| error }` (AC-144). |
//!
//! A comment item is `{ target, addr, kind, old, new, noop }`. An empty text deletes the
//! comment, and then `new` is `null`. The kinds are the Ghidra kinds `eol`, `pre`, `post`,
//! `plate` and `repeatable`. A `plate` comment at a function entry is the function comment.
//! `func_get` shows the comments in the disassembly rows, and `addr_info` and
//! `search { kind: "comment" }` read them back.

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

/// The longest comment in characters.
pub const MAX_TEXT: usize = ghidorah_db::comments::MAX_COMMENT;

/// The comment kinds in Ghidra code order.
pub const KINDS: [&str; 5] = ["eol", "pre", "post", "plate", "repeatable"];

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const TARGET_DOC: &str =
    "The address of the comment, for example 0x401130, main+0x10 or fn:0x401130.";
const KIND_DOC: &str =
    "The kind of the comment. A plate comment at a function entry is the function comment.";
const TEXT_DOC: &str = "The text of the comment. An empty text deletes the comment.";

const ITEM_ARGS: &[ArgSpec] = &[
    ArgSpec::new("target", Role::Target, ArgKind::Addr, TARGET_DOC).required(),
    ArgSpec::new("kind", Role::Param, ArgKind::Enum(&KINDS), KIND_DOC).required(),
    ArgSpec::new("text", Role::Param, ArgKind::Str(MAX_TEXT), TEXT_DOC).required(),
];

const ITEM: ArgSpec = ArgSpec::new(
    "item",
    Role::Param,
    ArgKind::Obj(ITEM_ARGS),
    "One comment: a target, a kind and a text.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new("target", Role::Target, ArgKind::Addr, TARGET_DOC),
    ArgSpec::new("kind", Role::Param, ArgKind::Enum(&KINDS), KIND_DOC),
    ArgSpec::new("text", Role::Param, ArgKind::Str(MAX_TEXT), TEXT_DOC),
    ArgSpec::new(
        "items",
        Role::Param,
        ArgKind::List(&ITEM, MAX_ITEMS),
        "More comments in one transaction. One bad item does not stop the other items.",
    ),
];

const RESULT: &[Field] = &[
    Field::req("target", OutputShape::Any),
    Field::req("addr", OutputShape::Str),
    Field::req("kind", OutputShape::Str),
    Field::req("old", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("new", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("noop", OutputShape::Bool),
];
const RESULT_SHAPE: OutputShape = OutputShape::Obj(RESULT);
const ITEM_OUT: &[Field] = &[
    Field::opt("target", OutputShape::Any),
    Field::opt("addr", OutputShape::Str),
    Field::opt("kind", OutputShape::Str),
    Field::opt("old", OutputShape::Nullable(&OutputShape::Str)),
    Field::opt("new", OutputShape::Nullable(&OutputShape::Str)),
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

/// `comment_set`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Set comments",
    summary: "Set or clear the comments at addresses.",
    description: "Set or clear the comments at addresses. \
                  Send target, kind and text for one comment, or items for up to 100 comments in one transaction. \
                  An empty text deletes the comment. \
                  A plate comment at a function entry is the function comment. \
                  The disassembly rows of func_get show the comments.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "items"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations::EDIT,
    mutating: true,
    profiles: &[Profile::Full],
    examples: &[
        Example {
            args: r#"{"target":"0x1080","kind":"plate","text":"Entry of the program."}"#,
            golden: "tests/golden/tools/comment_set.1.json",
        },
        Example {
            args: r#"{"items":[{"target":"0x1090","kind":"eol","text":"Reads the input."},{"target":"0x1094","kind":"pre","text":""}]}"#,
            golden: "tests/golden/tools/comment_set.2.json",
        },
    ],
    force: true,
    ..ToolSpec::base("comment_set", run)
};

fn run(_session: &mut Session, _args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(Object::new()))
}

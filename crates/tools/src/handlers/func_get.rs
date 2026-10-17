//! `func_get`: get one or more functions with selected sections (design Section 10.4, tool 5).
//!
//! The result of one function is `{ id, name, entry, size, parts, signature, start_reason,
//! confidence, flags, caveats, <sections>, omitted? }`. [`super::func_sections`] renders the
//! sections. With `targets`, the result is `{ items: [{ input, ok, data | error }],
//! ok_count, error_count }` in input order, and one bad item never fails the call (AC-144).
//!
//! Budget (design Section 10.9): with `targets`, the budget first splits evenly per target.
//! The sections of one function split their part by weight in include order: `disasm` 3,
//! `ir` 3, every other section 1. A section that needs less gives the rest to the later
//! sections. A row section that does not fit keeps the rows that fit and gets a
//! `next_cursor`. Send it in `cursors` for the next rows (AC-154b). Another section that
//! does not fit goes to `omitted` with its exact size (AC-154a).
//!
//! A call with `disasm` or `ir` marks the function `visited`. The mark changes no fact and no
//! `rev`.

use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec};

/// The sections of `func_get` in schema order.
pub const SECTIONS: [&str; 12] = [
    "summary",
    "disasm",
    "ir",
    "xrefs",
    "callers",
    "callees",
    "strings",
    "vars",
    "notes",
    "why",
    "cfg",
    "jumptables",
];

/// The largest number of targets of one call.
pub const MAX_TARGETS: usize = 50;

/// The default number of disassembly rows.
pub const DEFAULT_DISASM_LIMIT: i64 = 200;

/// The largest number of disassembly rows.
pub const MAX_DISASM_LIMIT: i64 = 2_000;

const SECTION_ITEM: ArgSpec = ArgSpec::new(
    "section",
    Role::Param,
    ArgKind::Enum(&SECTIONS),
    "One section of the function.",
);

const CURSORS: &[ArgSpec] = &[
    ArgSpec::new(
        "disasm",
        Role::Param,
        ArgKind::Str(1_024),
        "The disasm.next_cursor of the previous call.",
    ),
    ArgSpec::new(
        "ir",
        Role::Param,
        ArgKind::Str(1_024),
        "The ir.next_cursor of the previous call.",
    ),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The function: an address in its body, a name or a fn: ID.",
    )
    .aliases(&["id", "addr", "address", "function"]),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "Up to 50 functions. Each item gets its own result.",
    ),
    ArgSpec::new(
        "include",
        Role::Param,
        ArgKind::List(&SECTION_ITEM, 12),
        "The sections to return in this order.",
    )
    .default_json("[\"summary\"]"),
    ArgSpec::new(
        "disasm_limit",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: MAX_DISASM_LIMIT,
        },
        "The largest number of disassembly rows.",
    )
    .default_json("200"),
    ArgSpec::new(
        "cursors",
        Role::Param,
        ArgKind::Obj(CURSORS),
        "The section cursors of the previous call, to get the next rows of a section.",
    ),
];

const FIELDS: &[Field] = &[
    Field::opt("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::opt("name", OutputShape::Str),
    Field::opt("entry", OutputShape::Addr),
    Field::opt("size", OutputShape::Int),
    Field::opt("parts", OutputShape::Any),
    Field::opt("signature", OutputShape::Any),
    Field::opt("start_reason", OutputShape::Str),
    Field::opt("confidence", OutputShape::Int),
    Field::opt("flags", OutputShape::List(&OutputShape::Str)),
    Field::opt("caveats", OutputShape::Any),
    Field::opt("summary", OutputShape::Any),
    Field::opt("disasm", OutputShape::Any),
    Field::opt("ir", OutputShape::Any),
    Field::opt("xrefs", OutputShape::Any),
    Field::opt("callers", OutputShape::Any),
    Field::opt("callees", OutputShape::Any),
    Field::opt("strings", OutputShape::Any),
    Field::opt("vars", OutputShape::Any),
    Field::opt("notes", OutputShape::Any),
    Field::opt("why", OutputShape::Any),
    Field::opt("cfg", OutputShape::Any),
    Field::opt("jumptables", OutputShape::Any),
    Field::opt("omitted", OutputShape::Any),
    Field::opt("budgets", OutputShape::Any),
    Field::opt("items", OutputShape::Any),
    Field::opt("ok_count", OutputShape::Int),
    Field::opt("error_count", OutputShape::Int),
];

/// `func_get`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Get functions",
    summary: "Get one or more functions with selected sections: summary, disassembly, IR, xrefs, callers, callees, strings, variables, notes, why, CFG and jump tables.",
    description: "Get one or more functions with selected sections: summary, disassembly, IR, xrefs, callers, callees, strings, variables, notes, why, CFG and jump tables. \
                  Send target, or targets for up to 50 functions. \
                  The sections share max_chars by weight, so a large section can come back cut. \
                  A cut disassembly gives next_cursor: send it in cursors to read on. \
                  The member omitted names each section that did not fit, with its size. \
                  A call with disasm or ir marks the function as visited, and this mark changes no fact.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "targets"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"target":"main"}"#,
            golden: "tests/golden/tools/func_get.1.json",
        },
        Example {
            args: r#"{"target":"fn:0x1080","include":["disasm","callees"],"disasm_limit":8}"#,
            golden: "tests/golden/tools/func_get.2.json",
        },
        Example {
            args: r#"{"targets":["main","0x11e0"],"include":["summary","strings"]}"#,
            golden: "tests/golden/tools/func_get.3.json",
        },
    ],
    max_chars: crate::budget::LARGE_MAX_CHARS,
    ..ToolSpec::base("func_get", run)
};

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = session.bound(&ctx.frame)?;
    let mut out = Object::new();
    out.push("omitted", Value::Object(Object::new()));
    Ok(Payload::Object(out))
}

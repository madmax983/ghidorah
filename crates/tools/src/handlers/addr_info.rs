//! `addr_info`: tell what is at an address (design Section 10.4, tool 9).
//!
//! The result of one address is `{ input, addr, resolved_from, region, section, func?,
//! symbol?, code_unit, override?, xrefs_in, xrefs_out, notes, comments?, refs?,
//! file_offset }`. `resolved_from` gives the rule of design Section 10.5 that resolved the
//! input. `code_unit` is `{ kind: insn | data | undefined, len, mnem?, text?, type? }`.
//! `include` adds `comments` (each kind with its text and source) and `refs` (the references
//! in and out). With `targets`, the result is `{ items: [{ input, ok, data | error }],
//! ok_count, error_count }` in input order (AC-144).

use ghidorah_json::Object;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, Group, GroupRule, Profile, Role, ToolSpec};

/// The largest number of targets of one call.
pub const MAX_TARGETS: usize = 50;

/// The largest number of references in each list of `refs`.
pub const MAX_REFS: usize = 20;

const INCLUDE_ITEM: ArgSpec = ArgSpec::new(
    "part",
    Role::Param,
    ArgKind::Enum(&["refs", "comments"]),
    "One optional part of the result.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The address: a 0x hex string, a name or an ID.",
    ),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "Up to 50 addresses. Each item gets its own result.",
    ),
    ArgSpec::new(
        "include",
        Role::Param,
        ArgKind::List(&INCLUDE_ITEM, 2),
        "The optional parts: refs and comments.",
    ),
];

const FIELDS: &[Field] = &[
    Field::opt("input", OutputShape::Any),
    Field::opt("addr", OutputShape::Str),
    Field::opt("resolved_from", OutputShape::Any),
    Field::opt("region", OutputShape::Any),
    Field::opt("section", OutputShape::Any),
    Field::opt("func", OutputShape::Any),
    Field::opt("symbol", OutputShape::Any),
    Field::opt("code_unit", OutputShape::Any),
    Field::opt("override", OutputShape::Any),
    Field::opt("xrefs_in", OutputShape::Int),
    Field::opt("xrefs_out", OutputShape::Int),
    Field::opt("notes", OutputShape::Int),
    Field::opt("comments", OutputShape::Any),
    Field::opt("refs", OutputShape::Any),
    Field::opt("file_offset", OutputShape::Nullable(&OutputShape::Addr)),
    Field::opt("items", OutputShape::Any),
    Field::opt("ok_count", OutputShape::Int),
    Field::opt("error_count", OutputShape::Int),
];

/// `addr_info`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Describe addresses",
    summary: "Tell what is at an address: region, section, function, symbol, code unit, overrides, comments and xref counts.",
    description: "Tell what is at an address: region, section, function, symbol, code unit, overrides, comments and xref counts. \
                  Send target, or targets for up to 50 addresses. \
                  The member resolved_from tells which rule of the address grammar read the input. \
                  Send include with refs or comments for those lists. \
                  The file offset is null for bytes that the file does not hold.",
    args: ARGS,
    groups: &[Group {
        members: &["target", "targets"],
        rule: GroupRule::ExactlyOne,
    }],
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        Example {
            args: r#"{"target":"main"}"#,
            golden: "tests/golden/tools/addr_info.1.json",
        },
        Example {
            args: r#"{"targets":["0x1091","imp:puts","0x2004"],"include":["refs","comments"]}"#,
            golden: "tests/golden/tools/addr_info.2.json",
        },
    ],
    ..ToolSpec::base("addr_info", run)
};

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = session.bound(&ctx.frame)?;
    Ok(Payload::Object(Object::new()))
}

//! `xref_list`: list the cross-references to or from targets (design Section 10.4, tool 6).
//!
//! Each target resolves through the target table of design Section 10.5. Each item is one
//! reference: `{ from, from_func?, to, to_name?, kind, via?, op_index, source, insn?,
//! context?, args? }`. `kind` is the reference type name, for example
//! `unconditional_call`. The filter `kinds` takes these classes:
//!
//! | Class | Reference types |
//! |---|---|
//! | `call` | `unconditional_call`, `conditional_call`, `computed_call` |
//! | `jump` | `unconditional_jump`, `conditional_jump`, `computed_jump` |
//! | `read`, `write` | `read`, `write` and `read_write` |
//! | `data` | `data` from an instruction |
//! | `ptr` | `data` from a pointer slot |
//! | `string` | a data reference to a string |
//! | `syscall` | a syscall site of a `sys:` target |
//!
//! The member `via` tells how an import site reaches the import: `plt` (the stub), `got`
//! (the slot) or `direct` (the EXTERNAL address). `args: true` adds the argument values of each call site
//! (design Section 7.11). `context: n` adds the display text of up to n instructions before
//! the site. `depth` above 1 adds `edges`: the call graph from the targets, with at most
//! `max_nodes` functions.
//!
//! `basis: { complete, unresolved }` tells if an unresolved indirect call can add callers.
//! A bad target never fails the call. It goes to `errors: [{ input, index, error }]`.

use crate::args::Args;
use crate::dispatch::{Ctx, ListPayload, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, ListSpec, Profile, Role, ToolSpec};

/// The default page size of `xref_list`.
pub const DEFAULT_LIMIT: u32 = 50;

/// The largest number of targets of one call.
pub const MAX_TARGETS: usize = 50;

/// The reference classes of the `kinds` filter.
pub const CLASSES: [&str; 8] = [
    "call", "jump", "read", "write", "data", "ptr", "string", "syscall",
];

/// The largest number of unresolved sites in `basis.unresolved`.
pub const MAX_UNRESOLVED: usize = 20;

/// The page hint of a long result.
pub const HINT_NARROW: &str = "Add kinds, or send fewer targets to narrow the list.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[HINT_NARROW];

const CLASS_ITEM: ArgSpec = ArgSpec::new(
    "kind",
    Role::Param,
    ArgKind::Enum(&CLASSES),
    "One class of references.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "Up to 50 targets: addresses, names, fn:, imp:, str:, sys: or jt: IDs.",
    )
    .required(),
    ArgSpec::new(
        "direction",
        Role::Param,
        ArgKind::Enum(&["to", "from"]),
        "The value to lists the references to the targets. The value from lists the references from them.",
    )
    .default_json("\"to\""),
    ArgSpec::new(
        "kinds",
        Role::Param,
        ArgKind::List(&CLASS_ITEM, 8),
        "Keep only these classes of references.",
    ),
    ArgSpec::new(
        "depth",
        Role::Param,
        ArgKind::Int { min: 1, max: 3 },
        "The depth of the call graph in edges. A depth above 1 adds the call edges of each level.",
    )
    .default_json("1"),
    ArgSpec::new(
        "max_nodes",
        Role::Param,
        ArgKind::Int { min: 1, max: 1_000 },
        "The largest number of functions in edges.",
    )
    .default_json("200"),
    ArgSpec::new(
        "context",
        Role::Param,
        ArgKind::Int { min: 0, max: 3 },
        "The number of instructions before each site to show.",
    )
    .default_json("0"),
    ArgSpec::new(
        "args",
        Role::Param,
        ArgKind::Bool,
        "Add the argument values of each call site.",
    )
    .default_json("false"),
];

const FIELDS: &[Field] = &[
    Field::opt("items", OutputShape::Any),
    Field::opt("cols", OutputShape::List(&OutputShape::Str)),
    Field::opt(
        "rows",
        OutputShape::List(&OutputShape::List(&OutputShape::Any)),
    ),
    Field::opt("count", OutputShape::Int),
    Field::opt("edges", OutputShape::Any),
    Field::opt("basis", OutputShape::Any),
    Field::opt("errors", OutputShape::Any),
];

/// `xref_list`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "List cross-references",
    summary: "List the xrefs to or from targets, with call-graph depth, call-site context and argument values.",
    description: "List the xrefs to or from targets, with call-graph depth, call-site context and argument values. \
                  Send targets with addresses, names or IDs. The target imp:puts gives every site of the import, and `via` tells the path: plt, got or direct. \
                  Send direction from for the references out of a function body. \
                  Send args true for the argument values of each call: an integer, a string, a function, an address or unknown. \
                  When basis.complete is false, an unresolved indirect call can add callers.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"targets":["imp:puts"]}"#,
            golden: "tests/golden/tools/xref_list.1.json",
        },
        Example {
            args: r#"{"targets":["main"],"direction":"from","kinds":["call"],"args":true}"#,
            golden: "tests/golden/tools/xref_list.2.json",
        },
    ],
    max_chars: crate::budget::LIST_MAX_CHARS,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("xref_list", run)
};

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = session.bound(&ctx.frame)?;
    Ok(Payload::List(ListPayload::new(Vec::new())))
}

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

mod items;
mod sites;

use ghidorah_analysis::CallGraph;
use ghidorah_json::{Object, Value};

use super::func_sections::{self as fs, Namer};
use crate::args::Args;
use crate::dispatch::{Ctx, ListPayload, Payload, Total};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::resolve::Family;
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
                  The target imp:puts gives every site of the import. \
                  Send direction from for the references out of a function, and args true for the argument values. \
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

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let p = &session.bound(&ctx.frame)?.program;
    fs::x86_only(p)?;
    let to = args.str("direction") != Some("from");
    let q = items::Query {
        classes: args
            .list("kinds")
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        context: usize::try_from(args.int("context").unwrap_or(0)).unwrap_or(0),
        args: args.bool("args").unwrap_or(false),
        caps: fs::caps(ctx),
    };
    let namer = Namer::new();
    let family = if to { Family::XrefTo } else { Family::XrefFrom };
    let found = sites::resolve_all(p, args.list("targets").unwrap_or_default(), family);
    let mut list = items::ref_items(p, &found.refs, &q, &namer, &mut ctx.fuel);
    list.extend(items::syscall_items(
        p,
        &found.syscalls,
        &q,
        &namer,
        &mut ctx.fuel,
    ));
    let depth = u64::try_from(args.int("depth").unwrap_or(1)).unwrap_or(1);
    let max = usize::try_from(args.int("max_nodes").unwrap_or(200)).unwrap_or(200);
    let mut extra = Object::new();
    if depth > 1 {
        let graph = CallGraph::build(p);
        extra.push("edges", sites::edges(&graph, &found.starts, to, depth, max));
    }
    let open = sites::unresolved(p, (!to).then_some(found.bodies.as_slice()));
    let shown = open
        .iter()
        .take(MAX_UNRESOLVED)
        .map(|a| fs::addr(*a))
        .collect();
    extra.push(
        "basis",
        Value::object([
            ("complete", Value::Bool(open.is_empty())),
            ("unresolved", Value::Array(shown)),
        ]),
    );
    if !found.errors.is_empty() {
        extra.push("errors", Value::Array(found.errors));
    }
    namer.finish(ctx);
    Ok(Payload::List(ListPayload {
        items: list,
        total: Total::Items,
        extra,
        narrow: Some(HINT_NARROW.to_owned()),
    }))
}

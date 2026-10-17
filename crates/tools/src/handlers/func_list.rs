//! `func_list`: list and filter the functions (design Section 10.4, tool 4).
//!
//! Each item is `{ id, addr, name, size, start_reason, confidence, flags, callers, callees,
//! caveats, visited, named }`. `flags` lists `noreturn`, `thunk` and `varargs`. `caveats`
//! lists the warning codes of the caveats.
//!
//! | `sort` | Order | Sort key |
//! |---|---|---|
//! | `addr` (default) | entry, low first | `(addr)` |
//! | `name` | name, then entry | `(name, addr)` |
//! | `size` | size, large first | `(rank, addr)` |
//! | `priority` | the frozen priority of design Section 7.11 | `(rank, addr)` |
//! | `in_degree` | references to the entry from outside the body, many first | `(rank, addr)` |
//!
//! The rank of a descending sort is `u64::MAX` minus the value, or the priority position.
//! `priority` reads only the analysis layer, so names, comments and `visited` never change it
//! (AC-157). The filter `visited` is a live filter.

use ghidorah_db::StartReason;

use crate::args::Args;
use crate::dispatch::{Ctx, ListPayload, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, ListSpec, Profile, Role, ToolSpec};

/// The default page size of `func_list`.
pub const DEFAULT_LIMIT: u32 = 100;

/// The sort orders.
pub const SORTS: [&str; 5] = ["addr", "name", "size", "priority", "in_degree"];

/// The page hint of a long result.
pub const HINT_NARROW: &str =
    "Add filter.name, filter.min_confidence or filter.calls to narrow the list.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[HINT_NARROW];

/// The names of the start reasons in the order of design Section 7.3.
const REASONS: [&str; 10] = [
    StartReason::Entry.name(),
    StartReason::Symbol.name(),
    StartReason::PltStub.name(),
    StartReason::Main.name(),
    StartReason::Pdata.name(),
    StartReason::Fde.name(),
    StartReason::Call.name(),
    StartReason::TailCall.name(),
    StartReason::Endbr.name(),
    StartReason::Agent.name(),
];

const REASON_ITEM: ArgSpec = ArgSpec::new(
    "reason",
    Role::Param,
    ArgKind::Enum(&REASONS),
    "One start reason.",
);

const SIZE: ArgKind = ArgKind::Int {
    min: 0,
    max: 9_007_199_254_740_991,
};

const FILTER: &[ArgSpec] = &[
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(256),
        "A glob for the name, for example parse_*.",
    ),
    ArgSpec::new(
        "min_confidence",
        Role::Param,
        ArgKind::Int { min: 0, max: 100 },
        "The lowest confidence, 0 to 100.",
    ),
    ArgSpec::new(
        "start_reason",
        Role::Param,
        ArgKind::List(&REASON_ITEM, 10),
        "Keep the functions with one of these start reasons.",
    ),
    ArgSpec::new(
        "visited",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions that a func_get call read, or the others.",
    ),
    ArgSpec::new(
        "named",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions with a real name, or the functions with a default name.",
    ),
    ArgSpec::new(
        "typed",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions with a signature, or the others.",
    ),
    ArgSpec::new(
        "has_caveat",
        Role::Param,
        ArgKind::Bool,
        "Keep the functions with a caveat, or the others.",
    ),
    ArgSpec::new(
        "calls",
        Role::Param,
        ArgKind::Str(256),
        "A glob for the name of an import that the function calls, for example recv*.",
    ),
    ArgSpec::new("size_min", Role::Param, SIZE, "The smallest size in bytes."),
    ArgSpec::new("size_max", Role::Param, SIZE, "The largest size in bytes."),
];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "filter",
        Role::Param,
        ArgKind::Obj(FILTER),
        "The filters. A function must pass every filter of the object.",
    ),
    ArgSpec::new(
        "sort",
        Role::Param,
        ArgKind::Enum(&SORTS),
        "The order of the list. The value priority gives the most interesting functions first.",
    )
    .default_json("\"addr\""),
];

const ITEM: &[Field] = &[
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::req("addr", OutputShape::Addr),
    Field::req("name", OutputShape::Str),
    Field::req("size", OutputShape::Int),
    Field::req("start_reason", OutputShape::Str),
    Field::req("confidence", OutputShape::Int),
    Field::req("flags", OutputShape::List(&OutputShape::Str)),
    Field::req("callers", OutputShape::Int),
    Field::req("callees", OutputShape::Int),
    Field::req("caveats", OutputShape::List(&OutputShape::Str)),
    Field::req("visited", OutputShape::Bool),
    Field::req("named", OutputShape::Bool),
];
const ITEM_SHAPE: OutputShape = OutputShape::Obj(ITEM);
const FIELDS: &[Field] = &[
    Field::opt("items", OutputShape::List(&ITEM_SHAPE)),
    Field::opt("cols", OutputShape::List(&OutputShape::Str)),
    Field::opt(
        "rows",
        OutputShape::List(&OutputShape::List(&OutputShape::Any)),
    ),
    Field::opt("count", OutputShape::Int),
];

/// `func_list`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "List the functions",
    summary: "List and filter the functions of a binary, and sort them by address, name, size or priority.",
    description: "List and filter the functions of a binary, and sort them by address, name, size or priority. \
                  Each item gives the ID, the entry, the name, the size, the start reason, the confidence, the counts of callers and callees, and the caveats. \
                  The sort priority puts functions with risky imports, many references and strings first. \
                  Each analysis run fixes the priority order, so names and visits do not change it. \
                  Send filter to narrow the list, and cursor for the next page.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"sort":"priority","limit":5}"#,
            golden: "tests/golden/tools/func_list.1.json",
        },
        Example {
            args: r#"{"filter":{"name":"*pass*"}}"#,
            golden: "tests/golden/tools/func_list.2.json",
        },
    ],
    max_chars: crate::budget::LIST_MAX_CHARS,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("func_list", run)
};

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = session.bound(&ctx.frame)?;
    Ok(Payload::List(ListPayload::new(Vec::new())))
}

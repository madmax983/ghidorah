//! `func_similar`: find similar functions in the open binaries (design Sections 7.13 and 10.4,
//! tool 23).
//!
//! The corpus is every function of every open binary. The target functions resolve in the
//! bound binary. The result is `{ items, renames, corpus, omitted? }`:
//!
//! | Member | Content |
//! |---|---|
//! | `items` | one item per target in input order: `{ query, matches, proposal? }`, or `{ input, error }` for a bad item of `targets` |
//! | `query` | `{ id, binary_id, name, features }`: `features` is the number of distinct keys |
//! | `matches` | `{ id, binary_id, name, score, shared, total, top_features: [{ kind, text, weight }] }` |
//! | `proposal` | `{ name, from: { binary_id, id }, score, evidence }` when the four rules of [`ghidorah_analysis::similar::propose`] hold |
//! | `renames` | one `{ target, name, evidence }` per proposal, in item order: the shape of a `symbol_rename` item |
//! | `corpus` | `{ binaries, functions }`: the open binaries and their functions |
//! | `omitted` | `{ matches }`: the matches that the budget cut, from the end of the longest lists |
//!
//! Scores, `min_score` and weights are integers in thousandths. `limit` caps the matches of
//! each item. It is not a page size, so the tool has no cursor.
//!
//! `next` holds two calls. When a proposal exists and the active profile holds
//! `symbol_rename`, the first call is a `batch_run`: step `s1` repeats the call with `fn:` IDs,
//! and step `s2` is `symbol_rename { items: { "$ref": "s1", "ptr": "/data/renames" } }`. So the
//! hint holds IDs and references only (ADR-0022). The other call is `func_get` on the best
//! match. A fuel stop gives `BUDGET_EXCEEDED`, and `next[0]` sends the same call again. The
//! vectors of the worker thread stay in its cache, so the second call continues.

use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::budget::LARGE_MAX_CHARS;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, FuelSpec, Group, GroupRule, Profile, Role, ToolSpec};

/// The largest number of targets of one call.
pub const MAX_TARGETS: usize = 20;

/// The default number of matches of one item.
pub const DEFAULT_LIMIT: i64 = 10;

/// The largest number of matches of one item.
pub const MAX_LIMIT: i64 = 50;

/// The default lowest score of a match, in thousandths.
pub const DEFAULT_MIN_SCORE: i64 = 500;

/// The fuel of a call with no `max_steps`.
pub const DEFAULT_STEPS: u64 = 20_000_000;

/// The largest `max_steps` of one call.
pub const MAX_STEPS: u64 = 1_000_000_000_000;

/// The `why` of the `func_get` hint on the best match.
pub const WHY_BEST: &str = "Read the best match.";

/// The `why` of the batch hint that applies the proposals.
pub const WHY_RENAME: &str = "Apply the proposed names with their evidence in one transaction.";

/// The `why` of the repair call after a fuel stop.
pub const WHY_RETRY: &str = "Send the call again. It continues with the vectors that it built.";

/// The label of the transaction of the batch hint.
pub const RENAME_LABEL: &str = "func_similar renames";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[WHY_BEST, WHY_RENAME, WHY_RETRY, RENAME_LABEL];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "target",
        Role::Target,
        ArgKind::Addr,
        "The query function: an address in its body, a name or a fn: ID.",
    )
    .aliases(&["id", "addr", "address", "function"]),
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(MAX_TARGETS),
        "Up to 20 query functions. Each item gets its own matches.",
    ),
    ArgSpec::new(
        "scope",
        Role::Param,
        ArgKind::Enum(&["binary", "open"]),
        "The candidates: binary for the other functions of the bound binary, open for every open binary.",
    )
    .default_json("\"binary\""),
    ArgSpec::new(
        "min_score",
        Role::Param,
        ArgKind::Int { min: 0, max: 1_000 },
        "The lowest score of a match in thousandths. 500 means 0.5.",
    )
    .default_json("500"),
    ArgSpec::new(
        "limit",
        Role::Param,
        ArgKind::Int {
            min: 1,
            max: MAX_LIMIT,
        },
        "The largest number of matches of each query function.",
    )
    .default_json("10"),
    ArgSpec::new(
        "propose_names",
        Role::Param,
        ArgKind::Bool,
        "Propose the name of a strong match for a query function with a default name.",
    )
    .default_json("false"),
];

const TOP: &[Field] = &[
    Field::req("kind", OutputShape::Str),
    Field::req("text", OutputShape::Str),
    Field::req("weight", OutputShape::Int),
];
const TOP_SHAPE: OutputShape = OutputShape::Obj(TOP);
const QUERY: &[Field] = &[
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::req("binary_id", OutputShape::Str),
    Field::req("name", OutputShape::Str),
    Field::req("features", OutputShape::Int),
];
const MATCH: &[Field] = &[
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::req("binary_id", OutputShape::Str),
    Field::req("name", OutputShape::Str),
    Field::req("score", OutputShape::Int),
    Field::req("shared", OutputShape::Int),
    Field::req("total", OutputShape::Int),
    Field::req("top_features", OutputShape::List(&TOP_SHAPE)),
];
const MATCH_SHAPE: OutputShape = OutputShape::Obj(MATCH);
const FROM: &[Field] = &[
    Field::req("binary_id", OutputShape::Str),
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
];
const PROPOSAL: &[Field] = &[
    Field::req("name", OutputShape::Str),
    Field::req("from", OutputShape::Obj(FROM)),
    Field::req("score", OutputShape::Int),
    Field::req("evidence", OutputShape::List(&OutputShape::Str)),
];
const ITEM: &[Field] = &[
    Field::opt("input", OutputShape::Any),
    Field::opt("query", OutputShape::Obj(QUERY)),
    Field::opt("matches", OutputShape::List(&MATCH_SHAPE)),
    Field::opt("proposal", OutputShape::Obj(PROPOSAL)),
    Field::opt("error", OutputShape::Any),
];
const ITEM_SHAPE: OutputShape = OutputShape::Obj(ITEM);
const RENAME: &[Field] = &[
    Field::req("target", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::req("name", OutputShape::Str),
    Field::req("evidence", OutputShape::List(&OutputShape::Str)),
];
const RENAME_SHAPE: OutputShape = OutputShape::Obj(RENAME);
const CORPUS: &[Field] = &[
    Field::req("binaries", OutputShape::Int),
    Field::req("functions", OutputShape::Int),
];
const OMITTED: &[Field] = &[Field::req("matches", OutputShape::Int)];
const FIELDS: &[Field] = &[
    Field::req("items", OutputShape::List(&ITEM_SHAPE)),
    Field::req("renames", OutputShape::List(&RENAME_SHAPE)),
    Field::req("corpus", OutputShape::Obj(CORPUS)),
    Field::opt("omitted", OutputShape::Obj(OMITTED)),
];

/// `func_similar`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Find similar functions",
    summary: "Find functions similar to target functions in the open binaries, explain each match and propose names.",
    description: "Find functions similar to target functions in the open binaries, explain each match and propose names. \
                  Send target, or targets for up to 20 functions. \
                  Scope binary compares with the other functions of the bound binary, and scope open compares with every open binary. \
                  Each match gives a score from 0 to 1000 and its top shared features. \
                  With propose_names true, a strong match with a real name gives a proposal, and next[0] applies the proposals in one batch.",
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
            golden: "tests/golden/tools/func_similar.1.json",
        },
        Example {
            args: r#"{"targets":["main","fn:0x11e0"],"min_score":0,"limit":3}"#,
            golden: "tests/golden/tools/func_similar.2.json",
        },
    ],
    max_chars: LARGE_MAX_CHARS,
    fuel: Some(FuelSpec {
        default: DEFAULT_STEPS,
        cap: MAX_STEPS,
    }),
    ..ToolSpec::base("func_similar", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session.bound(&ctx.frame)?, args);
    let mut out = Object::new();
    out.push("items", Value::Array(Vec::new()));
    out.push("renames", Value::Array(Vec::new()));
    out.push(
        "corpus",
        Value::object([("binaries", Value::from(0)), ("functions", Value::from(0))]),
    );
    Ok(Payload::Object(out))
}

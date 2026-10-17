//! `tool_search`: search tools and topics (design Section 10.4, tool 15).
//!
//! | Argument | Result |
//! |---|---|
//! | `query` | the active tools in rank order, see [`crate::tool_search`] |
//! | `name` | the one active tool with this name |
//! | `topic` | one item `{ topic, text }` |
//! | none | every active tool in registry order |
//!
//! Send at most one of `query`, `name` and `topic`. `level` sets the detail of a tool item:
//! `names`, `summaries` (the default) or `full`. The ranking is the same at each level.

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, BinaryArg, Example, ListSpec, Profile, Role, ToolSpec};
use crate::tool_search::TOPIC_NAMES;

/// The default page size of `tool_search`.
pub const DEFAULT_LIMIT: u32 = 50;

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "query",
        Role::Param,
        ArgKind::Str(200),
        "Words that tell what the tool does, for example disassemble a function.",
    ),
    ArgSpec::new(
        "name",
        Role::Param,
        ArgKind::Str(64),
        "The exact name of one tool.",
    ),
    ArgSpec::new(
        "topic",
        Role::Param,
        ArgKind::Enum(&TOPIC_NAMES),
        "A concept topic. The result gives its text.",
    ),
    ArgSpec::new(
        "level",
        Role::Param,
        ArgKind::Enum(&["names", "summaries", "full"]),
        "The detail of each tool item. The full level adds the schema and examples.",
    )
    .default_json("\"summaries\""),
];

const ANNOTATIONS: &[Field] = &[
    Field::req("readOnlyHint", OutputShape::Bool),
    Field::req("destructiveHint", OutputShape::Bool),
    Field::req("idempotentHint", OutputShape::Bool),
    Field::req("openWorldHint", OutputShape::Bool),
];
const EXAMPLE: &[Field] = &[
    Field::opt("action", OutputShape::Str),
    Field::req("args", OutputShape::Any),
];
const EXAMPLE_SHAPE: OutputShape = OutputShape::Obj(EXAMPLE);
const ITEM: &[Field] = &[
    Field::opt("name", OutputShape::Str),
    Field::opt("summary", OutputShape::Str),
    Field::opt("schema", OutputShape::Any),
    Field::opt("examples", OutputShape::List(&EXAMPLE_SHAPE)),
    Field::opt("annotations", OutputShape::Obj(ANNOTATIONS)),
    Field::opt("topic", OutputShape::Str),
    Field::opt("text", OutputShape::Str),
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

/// `tool_search`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Search tools",
    summary: "Search the tools and the topics: give names, summaries or full schemas.",
    description: "Search the tools and the topics: give names, summaries or full schemas. \
                  Send query with words that tell the task, name for one tool, or topic for a concept text. \
                  With no argument, the result lists every tool. \
                  The level names gives only the names, summaries adds the first sentence, and full adds the input schema and one example per action. \
                  The rank is the same at each level. \
                  Topics: addresses, ids, budgets, batch, errors, rules, relations, profiles, resume.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly, Profile::Mini],
    examples: &[
        Example {
            args: r#"{"query":"disassemble a function"}"#,
            golden: "tests/golden/tools/tool_search.1.json",
        },
        Example {
            args: r#"{"name":"calc","level":"full"}"#,
            golden: "tests/golden/tools/tool_search.2.json",
        },
        Example {
            args: r#"{"topic":"addresses"}"#,
            golden: "tests/golden/tools/tool_search.3.json",
        },
        Example {
            args: r#"{"query":"load a file","level":"names","limit":2}"#,
            golden: "tests/golden/tools/tool_search.4.json",
        },
    ],
    binary: BinaryArg::None,
    max_chars: 16_000,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("tool_search", run)
};

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let _ = (session, args, ctx);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}

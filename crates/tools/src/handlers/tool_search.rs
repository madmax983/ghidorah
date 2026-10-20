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

use ghidorah_base::{ErrorCode, Fuel, did_you_mean};
use ghidorah_json::Value;

use crate::args::Args;
use crate::dispatch::{Ctx, Item, KeyPart, ListPayload, Payload, SortKey};
use crate::errors::{Candidate, ToolError};
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, BinaryArg, Example, ListSpec, Profile, Role, ToolSpec};
use crate::tool_search::{Level, TOPIC_NAMES, item, rank, topic};

/// The default page size of `tool_search`.
pub const DEFAULT_LIMIT: u32 = 50;

/// The fuel of the did-you-mean scan of a tool name.
const DYM_FUEL: u64 = 100_000;

/// The page hint of a long result.
pub const HINT_NARROW: &str = "Add words to query, or send level names for shorter items.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[HINT_NARROW];

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
                  The level full adds the schema with every argument doc and one example per action. \
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
    max_chars: crate::budget::LIST_MAX_CHARS,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("tool_search", run)
};

/// Gives the list item at rank position `pos`.
fn ranked(pos: usize, value: Value) -> Item {
    let pos = u64::try_from(pos).unwrap_or(u64::MAX);
    Item {
        key: SortKey(vec![KeyPart::Int(pos)]),
        value,
    }
}

/// Gives the `NOT_FOUND` error of an unknown tool name with the nearest active names.
fn unknown_tool(name: &str, tools: &[&'static ToolSpec<Session>]) -> ToolError {
    let mut fuel = Fuel::new(DYM_FUEL);
    let names = tools.iter().map(|t| t.name);
    let candidates = did_you_mean(name, names, &mut fuel)
        .into_iter()
        .map(|s| Candidate::text(&s.name, "tool"))
        .collect();
    ToolError::new(ErrorCode::NotFound)
        .var("kind", "tool")
        .path("/name")
        .detail("kind", Value::from("tool"))
        .candidates(candidates)
}

fn run(session: &mut Session, args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let given: Vec<&str> = ["query", "name", "topic"]
        .into_iter()
        .filter(|n| args.given(n))
        .collect();
    if let [_, second, ..] = given.as_slice() {
        return Err(ToolError::new(ErrorCode::InvalidArgument)
            .var("field", second)
            .path(&format!("/{second}"))
            .detail(
                "expected",
                Value::from("at most one of query, name and topic"),
            ));
    }
    if let Some(name) = args.str("topic") {
        let text = topic(name).map_or("", |t| t.text);
        let value = Value::object([("topic", Value::from(name)), ("text", Value::from(text))]);
        return Ok(Payload::List(ListPayload::new(vec![ranked(0, value)])));
    }
    let level = args
        .str("level")
        .and_then(Level::parse)
        .unwrap_or(Level::Summaries);
    let tools = session.active_tools();
    let order: Vec<usize> = match args.str("name") {
        Some(name) => vec![
            tools
                .iter()
                .position(|t| t.name == name)
                .ok_or_else(|| unknown_tool(name, &tools))?,
        ],
        None => rank(&tools, args.str("query").unwrap_or_default())
            .into_iter()
            .map(|(i, _)| i)
            .collect(),
    };
    let profile = &session.config().profile;
    let items = order
        .iter()
        .filter_map(|i| tools.get(*i))
        .enumerate()
        .map(|(pos, tool)| ranked(pos, item(tool, level, profile)))
        .collect();
    let mut list = ListPayload::new(items);
    list.narrow = Some(HINT_NARROW.to_owned());
    Ok(Payload::List(list))
}

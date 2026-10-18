//! `history_list`: list the edits since a revision and the analysis runs (design Section 10.4,
//! tool 13).
//!
//! The rows come from the journal, so they never expire (AC-232).
//!
//! | `coalesce` | Rows |
//! |---|---|
//! | `true` (default) | one row per changed fact: `{ kind, id, addr?, fields, last_rev, session }` |
//! | `false` | one row per edit: `{ rev, tx, label, source, session, kind, id, addr?, fields, undone_by? }` |
//!
//! Both forms add one row of kind `analysis` per analysis run. `fields` holds the new state of
//! the fact, for example `{ name, old, evidence }` for a name. The global `session` argument
//! keeps only the commits of that session, and `exclude_session` leaves one session out.

use ghidorah_base::{ErrorCode, Rev};
use ghidorah_db::{ChangeKind, Row, RowQuery};
use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::dispatch::{Ctx, Item, KeyPart, ListPayload, Payload, SortKey};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{ArgKind, ArgSpec, Example, ListSpec, Profile, Role, ToolSpec};

/// The default page size of `history_list`.
pub const DEFAULT_LIMIT: u32 = 50;

/// The page hint of a long result.
pub const HINT_NARROW: &str = "Send a higher since_rev, or add kinds to narrow the list.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[HINT_NARROW];

/// The names of the fact kinds in schema order.
const KIND_NAMES: [&str; 12] = [
    "name",
    "comment",
    "var",
    "ref",
    "function",
    "signature",
    "noreturn",
    "jumptable",
    "flow",
    "data",
    "note",
    "analysis",
];

const KIND_ITEM: ArgSpec = ArgSpec::new(
    "kind",
    Role::Param,
    ArgKind::Enum(&KIND_NAMES),
    "One kind of fact.",
);

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "since_rev",
        Role::Param,
        ArgKind::Int {
            min: 0,
            max: 9_007_199_254_740_991,
        },
        "List the changes after this rev. The value 0 lists all changes.",
    )
    .default_json("0"),
    ArgSpec::new(
        "kinds",
        Role::Param,
        ArgKind::List(&KIND_ITEM, 12),
        "Keep only these kinds of facts, for example name and note.",
    ),
    ArgSpec::new(
        "exclude_session",
        Role::Param,
        ArgKind::Str(64),
        "Leave out the commits of this session label.",
    ),
    ArgSpec::new(
        "coalesce",
        Role::Param,
        ArgKind::Bool,
        "Give one row per changed fact with its last change. Send false for one row per edit.",
    )
    .default_json("true"),
];

const ITEM: &[Field] = &[
    Field::opt("rev", OutputShape::Int),
    Field::opt("tx", OutputShape::Str),
    Field::opt("label", OutputShape::Str),
    Field::opt("source", OutputShape::Str),
    Field::req("session", OutputShape::Str),
    Field::req("kind", OutputShape::Str),
    Field::req("id", OutputShape::Str),
    Field::opt("addr", OutputShape::Addr),
    Field::req("fields", OutputShape::Any),
    Field::opt("last_rev", OutputShape::Int),
    Field::opt("undone_by", OutputShape::Str),
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

/// `history_list`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "List the history",
    summary: "List the history of edits since a revision, and the analysis runs.",
    description: "List the history of edits since a revision, and the analysis runs. \
                  By default each changed fact gives one row with its last rev and session. \
                  Send coalesce false for one row per edit. \
                  Call it after a context reset to see what changed since your last rev.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[
        Example {
            args: r#"{"since_rev":0}"#,
            golden: "tests/golden/tools/history_list.1.json",
        },
        Example {
            args: r#"{"since_rev":0,"coalesce":false,"kinds":["name","note"]}"#,
            golden: "tests/golden/tools/history_list.2.json",
        },
    ],
    max_chars: 16_000,
    list: Some(ListSpec {
        default_limit: DEFAULT_LIMIT,
    }),
    ..ToolSpec::base("history_list", run)
};

/// Gives the row filter of the call.
fn query(args: &Args) -> RowQuery {
    let kinds = args
        .get("kinds")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(ChangeKind::parse)
                .collect()
        })
        .unwrap_or_default();
    RowQuery {
        since_rev: Rev(args.get("since_rev").and_then(Value::as_u64).unwrap_or(0)),
        kinds,
        session: args.globals().session.clone(),
        exclude_session: args.str("exclude_session").map(str::to_owned),
        coalesce: args
            .get("coalesce")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    }
}

/// Gives the list item of one row.
fn item(row: &Row, coalesce: bool) -> Item {
    let mut out = Object::new();
    if coalesce {
        out.push("kind", Value::from(row.kind.name()));
        out.push("id", Value::from(row.id.as_str()));
        if let Some(addr) = row.addr {
            out.push("addr", Value::from(addr.to_string()));
        }
        out.push("fields", row.fields.clone());
        out.push("last_rev", Value::from(row.rev.0));
        out.push("session", Value::from(row.session.as_str()));
        return Item {
            key: SortKey(vec![
                KeyPart::Int(row.rev.0),
                KeyPart::Text(row.key.clone()),
            ]),
            value: Value::Object(out),
        };
    }
    out.push("rev", Value::from(row.rev.0));
    out.push("tx", Value::from(row.tx.to_string()));
    out.push("label", Value::from(row.label.as_str()));
    out.push("source", Value::from(row.source.name()));
    out.push("session", Value::from(row.session.as_str()));
    out.push("kind", Value::from(row.kind.name()));
    out.push("id", Value::from(row.id.as_str()));
    if let Some(addr) = row.addr {
        out.push("addr", Value::from(addr.to_string()));
    }
    out.push("fields", row.fields.clone());
    if let Some(tx) = row.undone_by {
        out.push("undone_by", Value::from(tx.to_string()));
    }
    Item {
        key: SortKey(vec![
            KeyPart::Int(row.rev.0),
            KeyPart::Int(u64::from(row.seq)),
        ]),
        value: Value::Object(out),
    }
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let binary = session.bound(&ctx.frame)?;
    let id = binary.id;
    let history = session
        .history(id)
        .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
    let query = query(args);
    let rows = history.rows(&binary.program, &query);
    let items = rows.iter().map(|row| item(row, query.coalesce)).collect();
    let mut list = ListPayload::new(items);
    list.narrow = Some(HINT_NARROW.to_owned());
    Ok(Payload::List(list))
}

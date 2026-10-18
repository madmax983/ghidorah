//! `session_brief`: brief a new context (design Section 10.4, tool 14).
//!
//! | Open binaries | Result |
//! |---|---|
//! | none | `{ projects: [{ binary_id, file_name, rev, last_session, last_rev, open }] }`: at most 20 projects of the projects root, newest rev first. `next[0]` is `binary_load { binary_id }` for the first project (AC-212). |
//! | one or more | the brief of the bound binary, else of the most recent binary |
//!
//! The brief of a binary:
//!
//! | Member | Content |
//! |---|---|
//! | `binary_id`, `binaries` | the briefed binary and every open binary |
//! | `progress` | `{ functions, visited, named, typed, commented, pct }` |
//! | `open_notes` | `{ todo, hypothesis, total, top }`: the counts of the open notes and the newest open notes |
//! | `recent_findings` | the newest findings |
//! | `recent_edits` | the newest changed facts of the history |
//! | `changed_since_last_brief` | `{ since_rev, count, by_kind }`: the facts that changed after the last brief of the session |
//! | `weak_names` | the functions of the highest priority that still have a default name |
//! | `orphans` | the agent facts that lost their anchor after a complete analysis: `{ kind, at, id }` |
//! | `truncated` | `true` when the budget cut a list |
//!
//! Each list holds at most [`MAX_ROWS`] rows. The handler cuts all lists to one row cap until
//! the result fits `max_chars` (default 8,000, AC-155). Note texts show at most
//! [`TEXT_CHARS`] characters. The call writes the last-brief mark of the session. The mark
//! changes no fact and no rev.

mod parts;

use ghidorah_base::{BinaryId, ErrorCode, Rev};
use ghidorah_db::MetaLine;
use ghidorah_json::{Object, Value};

use super::func_sections::{self as fs, safe};
use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::hints::Call;
use crate::outshape::{Field, OutputShape};
use crate::session::{Session, session_label};
use crate::spec::{BinaryArg, Example, Profile, ToolSpec};
use parts::Facts;

/// The largest number of rows of one list of the brief.
pub const MAX_ROWS: usize = 10;

/// The largest number of projects in the list of projects.
pub const MAX_PROJECTS: usize = 20;

/// The largest number of characters of a note text in the brief.
pub const TEXT_CHARS: usize = 160;

/// The `why` of the `binary_load` call that reopens a project.
pub const WHY_REOPEN: &str = "Open the project with the newest change.";

/// The `why` of the `tool_search` call when no project exists.
pub const WHY_LOAD: &str = "Get the schema of binary_load to open a binary.";

/// The `why` of the `history_list` call after other changes.
pub const WHY_CHANGES: &str = "List the changes after your last brief.";

/// The `why` of the `func_get` call on a weak name.
pub const WHY_WEAK: &str = "Read the function of the highest priority that has a default name.";

/// The `why` of the `search` call for the open notes.
pub const WHY_NOTES: &str = "List the open notes.";

/// The `why` of the `func_edit` call on an orphan.
pub const WHY_ORPHAN: &str = "Make a function again for the orphaned fact.";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[
    WHY_REOPEN,
    WHY_LOAD,
    WHY_CHANGES,
    WHY_WEAK,
    WHY_NOTES,
    WHY_ORPHAN,
];

const BINARY: &[Field] = &[
    Field::req("binary_id", OutputShape::Str),
    Field::req("file_name", OutputShape::Str),
    Field::req("rev", OutputShape::Int),
    Field::req("read_only", OutputShape::Bool),
    Field::req("analysis", OutputShape::Nullable(&OutputShape::Str)),
];
const BINARY_SHAPE: OutputShape = OutputShape::Obj(BINARY);
const PROGRESS: &[Field] = &[
    Field::req("functions", OutputShape::Int),
    Field::req("visited", OutputShape::Int),
    Field::req("named", OutputShape::Int),
    Field::req("typed", OutputShape::Int),
    Field::req("commented", OutputShape::Int),
    Field::req("pct", OutputShape::Int),
];
const NOTE: &[Field] = &[
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Note)),
    Field::req("kind", OutputShape::Str),
    Field::req("text", OutputShape::Str),
    Field::opt("truncated", OutputShape::Bool),
    Field::opt("at", OutputShape::Addr),
    Field::req("status", OutputShape::Str),
    Field::opt("evidence", OutputShape::Int),
    Field::req("rev", OutputShape::Int),
];
const NOTE_SHAPE: OutputShape = OutputShape::Obj(NOTE);
const OPEN_NOTES: &[Field] = &[
    Field::req("todo", OutputShape::Int),
    Field::req("hypothesis", OutputShape::Int),
    Field::req("total", OutputShape::Int),
    Field::req("top", OutputShape::List(&NOTE_SHAPE)),
];
const EDIT: &[Field] = &[
    Field::req("kind", OutputShape::Str),
    Field::req("id", OutputShape::Str),
    Field::opt("addr", OutputShape::Addr),
    Field::opt("value", OutputShape::Str),
    Field::req("rev", OutputShape::Int),
    Field::req("session", OutputShape::Str),
];
const EDIT_SHAPE: OutputShape = OutputShape::Obj(EDIT);
const KIND_COUNT: &[Field] = &[
    Field::req("kind", OutputShape::Str),
    Field::req("count", OutputShape::Int),
];
const KIND_COUNT_SHAPE: OutputShape = OutputShape::Obj(KIND_COUNT);
const CHANGED: &[Field] = &[
    Field::req("since_rev", OutputShape::Int),
    Field::req("count", OutputShape::Int),
    Field::req("by_kind", OutputShape::List(&KIND_COUNT_SHAPE)),
];
const WEAK: &[Field] = &[
    Field::req("id", OutputShape::Id(ghidorah_base::IdKind::Func)),
    Field::req("name", OutputShape::Str),
];
const WEAK_SHAPE: OutputShape = OutputShape::Obj(WEAK);
const ORPHAN: &[Field] = &[
    Field::req("kind", OutputShape::Str),
    Field::req("at", OutputShape::Addr),
    Field::req("id", OutputShape::Str),
];
const ORPHAN_SHAPE: OutputShape = OutputShape::Obj(ORPHAN);
const PROJECT: &[Field] = &[
    Field::req("binary_id", OutputShape::Str),
    Field::req("file_name", OutputShape::Str),
    Field::req("rev", OutputShape::Int),
    Field::req("last_session", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("last_rev", OutputShape::Int),
    Field::req("open", OutputShape::Bool),
];
const PROJECT_SHAPE: OutputShape = OutputShape::Obj(PROJECT);
const FIELDS: &[Field] = &[
    Field::opt("projects", OutputShape::List(&PROJECT_SHAPE)),
    Field::opt("binary_id", OutputShape::Str),
    Field::opt("binaries", OutputShape::List(&BINARY_SHAPE)),
    Field::opt("progress", OutputShape::Obj(PROGRESS)),
    Field::opt("open_notes", OutputShape::Obj(OPEN_NOTES)),
    Field::opt("recent_findings", OutputShape::List(&NOTE_SHAPE)),
    Field::opt("recent_edits", OutputShape::List(&EDIT_SHAPE)),
    Field::opt("changed_since_last_brief", OutputShape::Obj(CHANGED)),
    Field::opt("weak_names", OutputShape::List(&WEAK_SHAPE)),
    Field::opt("orphans", OutputShape::List(&ORPHAN_SHAPE)),
    Field::req("truncated", OutputShape::Bool),
];

/// `session_brief`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Brief the session",
    summary: "Brief a new session: projects on disk, progress, open notes, recent findings and edits, and orphans.",
    description: "Brief a new session: projects on disk, progress, open notes, recent findings and edits, and orphans. \
                  Call it first after a context reset or a server restart. \
                  With no open binary, next opens the newest project. \
                  The call writes the last-brief mark of your session, and this mark changes no fact and no rev.",
    output: OutputShape::Obj(FIELDS),
    profiles: &[Profile::Full, Profile::Readonly],
    examples: &[Example {
        args: r"{}",
        golden: "tests/golden/tools/session_brief.1.json",
    }],
    binary: BinaryArg::Optional,
    ..ToolSpec::base("session_brief", run)
};

/// Gives the largest row cap from [`MAX_ROWS`] down to 0 whose data fits the budget, and the
/// data with that cap.
fn fit(
    ctx: &Ctx,
    full: usize,
    render: impl Fn(usize, bool) -> Object,
    cuts: impl Fn(usize) -> bool,
) -> Object {
    let room = fs::room(ctx);
    let mut cap = full;
    loop {
        let data = render(cap, cap < full && cuts(cap));
        if cap == 0 || fs::chars(ctx, &Value::Object(data.clone())) <= room {
            return data;
        }
        cap -= 1;
    }
}

/// Gives the brief with zero open binaries: the projects on disk, newest rev first.
fn projects(session: &mut Session, ctx: &mut Ctx) -> Object {
    let all = session.projects();
    let rows: Vec<Value> = all
        .iter()
        .take(MAX_PROJECTS)
        .map(|p| {
            Value::object([
                ("binary_id", Value::from(p.binary_id.to_string())),
                ("file_name", Value::from(safe(&p.file_name))),
                ("rev", Value::from(p.rev.0)),
                (
                    "last_session",
                    p.last_session.as_deref().map_or(Value::Null, Value::from),
                ),
                ("last_rev", Value::from(p.rev.0)),
                ("open", Value::Bool(false)),
            ])
        })
        .collect();
    match all.first() {
        Some(first) => ctx.hint(Call::new(
            "binary_load",
            Value::object([("binary_id", Value::from(first.binary_id.to_string()))]),
            WHY_REOPEN,
        )),
        None => ctx.hint(Call::new(
            "tool_search",
            Value::object([
                ("name", Value::from("binary_load")),
                ("level", Value::from("full")),
            ]),
            WHY_LOAD,
        )),
    }
    let longer = all.len() > MAX_PROJECTS;
    fit(
        ctx,
        rows.len(),
        |cap, cut| {
            let mut out = Object::new();
            out.push(
                "projects",
                Value::Array(rows.iter().take(cap).cloned().collect()),
            );
            out.push("truncated", Value::Bool(longer || cut));
            out
        },
        |cap| cap < rows.len(),
    )
}

/// Adds the `next` calls of a brief. A frame with no bound binary adds `binary_id`.
fn hints(ctx: &mut Ctx, facts: &Facts, bound: bool) {
    let with_binary = |pairs: Vec<(&str, Value)>| {
        let mut object = Object::new();
        if !bound {
            object.push("binary_id", Value::from(facts.binary_id.as_str()));
        }
        for (k, v) in pairs {
            object.push(k, v);
        }
        Value::Object(object)
    };
    let mut calls = Vec::new();
    if facts.changed_count() > 0 {
        let args = with_binary(vec![("since_rev", Value::from(facts.changed.0))]);
        calls.push(Call::new("history_list", args, WHY_CHANGES));
    }
    if let Some(id) = facts.weak.first().and_then(|w| w.get("id")) {
        let include = Value::Array(vec![Value::from("decomp")]);
        let args = with_binary(vec![("target", id.clone()), ("include", include)]);
        calls.push(Call::new("func_get", args, WHY_WEAK));
    }
    if facts.open_counts.2 > 0 {
        let filter = Value::object([("status", Value::from("open"))]);
        let args = with_binary(vec![("kind", Value::from("note")), ("note_filter", filter)]);
        calls.push(Call::new("search", args, WHY_NOTES));
    }
    if let Some(o) = facts.orphans.iter().find(|o| o.lost_function) {
        let args = with_binary(vec![
            ("action", Value::from("create")),
            ("target", fs::addr(o.at)),
        ]);
        calls.push(Call::new("func_edit", args, WHY_ORPHAN));
    }
    for call in calls {
        ctx.hint(call);
    }
}

fn run(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let bound = ctx
        .frame
        .binary_id
        .as_deref()
        .and_then(|t| BinaryId::parse(t).ok());
    let Some(id) = bound
        .or_else(|| session.recent())
        .filter(|id| session.binary(*id).is_some())
    else {
        return Ok(Payload::Object(projects(session, ctx)));
    };
    let label = session_label(&ctx.frame.session)?;
    let rows: Vec<Value> = session.binaries().map(parts::binary_row).collect();
    let (facts, rev) = {
        let binary = session
            .binary(id)
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
        let history = session
            .history(id)
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
        let since = binary
            .program
            .progress()
            .mark(&label)
            .map_or(Rev(0), |m| m.last_brief_rev);
        (
            Facts::gather(binary, rows, history, since),
            binary.program.rev(),
        )
    };
    hints(ctx, &facts, bound.is_some());
    let data = fit(
        ctx,
        MAX_ROWS,
        |cap, cut| facts.render(cap, cut),
        |cap| facts.cuts(cap),
    );
    // A failed journal write keeps the mark in memory, so the brief still succeeds.
    let _ = session.write_meta(
        id,
        &MetaLine::Brief {
            session: label,
            rev,
        },
    );
    Ok(Payload::Object(data))
}

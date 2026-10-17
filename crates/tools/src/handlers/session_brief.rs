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
//! | `orphans` | the agent facts whose function no longer exists |
//! | `truncated` | `true` when the budget cut a list |
//!
//! Each list holds at most [`MAX_ROWS`] rows. The handler cuts all lists to one row cap until
//! the result fits `max_chars` (default 8,000, AC-155). Note texts show at most
//! [`TEXT_CHARS`] characters. The call writes the last-brief mark of the session. The mark
//! changes no fact and no rev.

use ghidorah_json::Object;

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::Session;
use crate::spec::{BinaryArg, Example, Profile, ToolSpec};

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
                  With no open binary, the result lists the projects on disk, and next opens the newest one. \
                  With an open binary, the result tells what changed after your last brief and which functions still have default names. \
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

fn run(_session: &mut Session, _args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(Object::new()))
}

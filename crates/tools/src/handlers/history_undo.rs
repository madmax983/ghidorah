//! `history_undo`: undo or redo committed edits as new commits (design Section 10.4, tool 21).
//!
//! The rules are in design Section 3.7 and in [`ghidorah_db::undo`]:
//!
//! | Call | Effect |
//! |---|---|
//! | `{}` | reverts the most recent applied transaction of the caller's session |
//! | `{ session: "*" }` | the scope is every session |
//! | `{ count: n }` | reverts `n` transactions in one commit |
//! | `{ tx: "tx:N" }` | reverts that transaction when no later applied one changed its facts |
//! | `{ redo: true }` | applies the most recently undone transactions again |
//!
//! The result is `{ undone | redone: [{ tx, label, session }], new_tx, rev, analysis? }`. An
//! undo of an analysis-affecting edit starts the re-analysis within `max_steps`.

use ghidorah_base::{BinaryId, ErrorCode, TxId};
use ghidorah_db::codec::{edit_to_json, key_to_json};
use ghidorah_db::{Scope, UndoRequest};
use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::dispatch::{Ctx, Payload};
use crate::envelope::Mutation;
use crate::errors::ToolError;
use crate::outshape::{Field, OutputShape};
use crate::session::{Session, session_label};
use crate::spec::{Annotations, ArgKind, ArgSpec, Example, FuelSpec, Profile, Role, ToolSpec};

/// The default fuel of the re-analysis after an undo.
pub const DEFAULT_STEPS: u64 = 2_000_000;

/// The largest `max_steps` of one undo.
pub const MAX_STEPS: u64 = 1_000_000_000_000;

/// The `session` value of the scope of every session.
pub const ALL_SESSIONS: &str = "*";

/// Every fixed text of the handler that an agent reads.
pub const TEXTS: &[&str] = &[];

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "tx",
        Role::Param,
        ArgKind::Id(&[ghidorah_base::IdKind::Tx]),
        "The transaction of a selective undo, for example tx:12.",
    ),
    ArgSpec::new(
        "count",
        Role::Param,
        ArgKind::Int { min: 1, max: 1_000 },
        "The number of transactions to undo or redo. The result is one commit.",
    )
    .default_json("1"),
    ArgSpec::new(
        "redo",
        Role::Param,
        ArgKind::Bool,
        "Apply the most recently undone transactions again.",
    )
    .default_json("false"),
];

const ENTRY: &[Field] = &[
    Field::req("tx", OutputShape::Str),
    Field::req("label", OutputShape::Str),
    Field::req("session", OutputShape::Str),
];
const ENTRY_SHAPE: OutputShape = OutputShape::Obj(ENTRY);
const ANALYSIS: &[Field] = &[
    Field::req("state", OutputShape::Str),
    Field::req("steps_used", OutputShape::Int),
];
const FIELDS: &[Field] = &[
    Field::opt("undone", OutputShape::List(&ENTRY_SHAPE)),
    Field::opt("redone", OutputShape::List(&ENTRY_SHAPE)),
    Field::req("new_tx", OutputShape::Nullable(&OutputShape::Str)),
    Field::req("rev", OutputShape::Int),
    Field::opt("analysis", OutputShape::Obj(ANALYSIS)),
];

/// `history_undo`.
pub const SPEC: ToolSpec<Session> = ToolSpec {
    title: "Undo or redo edits",
    summary: "Undo or redo your committed edits in the history as new commits.",
    description: "Undo or redo your committed edits in the history as new commits. \
                  With no argument, the call reverts the most recent transaction of your session. \
                  Send session * for every session, count for more transactions, or tx for one older transaction. \
                  A selective undo gives CONFLICT when a later transaction changed the same facts. \
                  Send redo true to apply undone transactions again, until a new edit ends the redo chain. \
                  Send dry_run true to see the planned edits first.",
    args: ARGS,
    output: OutputShape::Obj(FIELDS),
    annotations: Annotations {
        read_only: false,
        destructive: true,
        idempotent: false,
        open_world: false,
    },
    mutating: true,
    analysis_affecting: true,
    profiles: &[Profile::Full],
    examples: &[
        Example {
            args: r"{}",
            golden: "tests/golden/tools/history_undo.1.json",
        },
        Example {
            args: r#"{"session":"*","count":1,"dry_run":true}"#,
            golden: "tests/golden/tools/history_undo.2.json",
        },
    ],
    force: true,
    fuel: Some(FuelSpec {
        default: DEFAULT_STEPS,
        cap: MAX_STEPS,
    }),
    ..ToolSpec::base("history_undo", run)
};

/// Gives the scope of the call: every session for `*`, else the session of the frame.
fn scope(args: &Args, frame_session: &str) -> Result<Scope, ToolError> {
    if args.globals().session.as_deref() == Some(ALL_SESSIONS) {
        return Ok(Scope::All);
    }
    session_label(frame_session).map(Scope::Session)
}

/// Gives the planned edit list of a dry run: `[{ op, key, old, new }]`.
fn diff(planned: &[ghidorah_db::Applied]) -> Value {
    let rows = planned
        .iter()
        .map(|a| {
            let key = a
                .edit
                .keys()
                .into_iter()
                .chain(a.inverse.keys())
                .next()
                .map_or(Value::Null, |k| key_to_json(&k));
            Value::object([
                ("op", Value::from(a.edit.kind().name())),
                ("key", key),
                ("old", edit_to_json(&a.inverse)),
                ("new", edit_to_json(&a.edit)),
            ])
        })
        .collect();
    Value::Array(rows)
}

/// Gives the entry rows `[{ tx, label, session }]` of the selected transactions.
fn entries(session: &Session, id: BinaryId, txs: &[TxId]) -> Value {
    let rows = txs
        .iter()
        .filter_map(|tx| session.history(id)?.entry(*tx))
        .map(|e| {
            Value::object([
                ("tx", Value::from(e.tx.to_string())),
                ("label", Value::from(e.label.as_str())),
                ("session", Value::from(e.session.as_str())),
            ])
        })
        .collect();
    Value::Array(rows)
}

fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let id = session.bound(&ctx.frame)?.id;
    let default_label = session.bound(&ctx.frame)?.label.clone();
    let label = if ctx.frame.session == ALL_SESSIONS {
        default_label
    } else {
        ctx.frame.session.clone()
    };
    let tx = match args.str("tx") {
        Some(text) => Some(text.parse::<TxId>().map_err(|_| {
            ToolError::new(ErrorCode::InvalidArgument)
                .var("field", "tx")
                .path("/tx")
                .detail("expected", Value::from("a transaction ID such as tx:12"))
        })?),
        None => None,
    };
    let count = args
        .get("count")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(1);
    let redo = args.get("redo").and_then(Value::as_bool).unwrap_or(false);
    let req = UndoRequest {
        scope: scope(args, &label)?,
        tx,
        count,
        redo,
        force: args.globals().force,
        dry_run: args.globals().dry_run,
        source: session.config().source,
        session: session_label(&label)?,
    };
    let out = session.undo(id, &req)?;
    let mut result = Object::new();
    let selected = entries(session, id, &out.entries);
    result.push(if redo { "redone" } else { "undone" }, selected);
    result.push(
        "new_tx",
        out.line
            .as_ref()
            .map_or(Value::Null, |l| Value::from(l.tx.to_string())),
    );
    result.push("rev", Value::from(out.rev.0));
    if out.line.is_none() {
        ctx.mutation = Some(Mutation {
            tx: None,
            noop: true,
            diff: Some(diff(&out.planned)),
        });
        return Ok(Payload::Object(result));
    }
    ctx.mutation = Some(Mutation {
        tx: out.line.as_ref().map(|l| l.tx.to_string()),
        noop: false,
        diff: None,
    });
    let report = session.after_edit(id, out.start_band, &mut ctx.fuel)?;
    if let Some(binary) = session.binary(id) {
        ctx.frame.rev = binary.program.rev().0;
        ctx.frame.analysis = binary.analysis;
    }
    if let Some(report) = report {
        result.push(
            "analysis",
            Value::object([
                ("state", Value::from(report.state.as_str())),
                ("steps_used", Value::from(report.steps_used)),
            ]),
        );
    }
    Ok(Payload::Object(result))
}

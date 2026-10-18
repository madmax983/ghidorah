//! The commit steps of the edit tools `symbol_rename`, `comment_set` and `note_write`.
//!
//! | Step | Effect |
//! |---|---|
//! | [`commit`] | runs the edits of one call in one transaction and writes its journal line. A dry run rolls back and gives the planned edits. |
//! | [`edit_error`] | gives the tool error of a refused edit. A write that `force` allows gets the repair call with `force: true`. |
//! | [`with_force`] | gives the call again with `force: true` |
//! | [`invalid`], [`missing`], [`not_with_items`] | give the argument errors of the edit tools |
//! | [`address_at`], [`texts`] | read an address input and a list of strings |
//!
//! A commit sets the envelope members `tx` and `noop` and the new rev of the frame. A dry run
//! sets `noop: true` and `diff: [{ op, key, old, new }]`.

use ghidorah_base::{Address, ErrorCode};
use ghidorah_db::codec::{edit_to_json, key_to_json};
use ghidorah_db::{Applied, EditError, Tx};
use ghidorah_json::Value;

use super::WHY_FORCE;
use crate::args::Args;
use crate::dispatch::Ctx;
use crate::envelope::Mutation;
use crate::errors::ToolError;
use crate::handlers::func_sections::{safe, site};
use crate::hints::Call;
use crate::resolve;
use crate::session::{Session, session_label};

/// The commit facts of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Committed {
    /// The rev after the call.
    pub rev: u64,
    /// The transaction ID of the commit, or `None` for a no-op or a dry run.
    pub tx: Option<String>,
}

impl Committed {
    /// Gives the JSON value of `tx`: the ID text or `null`.
    pub(crate) fn tx_value(&self) -> Value {
        self.tx.as_deref().map_or(Value::Null, Value::from)
    }
}

/// Gives the planned edit list of a dry run: `[{ op, key, old, new }]`.
fn diff(planned: &[Applied]) -> Value {
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

/// Runs `edit` in one transaction on the bound binary and commits it.
///
/// The transaction label is the tool name, and the session label is the label of the frame.
/// `force` sets the force flag of the facts. With `dry_run`, the transaction rolls back, and
/// the envelope gets the planned edits.
///
/// # Errors
///
/// Returns the error of `edit`, `READ_ONLY_PROJECT` for a commit on a read-only binary, or
/// the error of a failed journal write. Then the program does not change.
pub(crate) fn commit<T>(
    session: &mut Session,
    args: &Args,
    ctx: &mut Ctx,
    edit: impl FnOnce(&mut Tx<'_>) -> Result<T, ToolError>,
) -> Result<(T, Committed), ToolError> {
    let id = session.bound(&ctx.frame)?.id;
    let force = args.globals().force;
    if args.globals().dry_run {
        let source = session.config().source;
        let who = session_label(&ctx.frame.session)?;
        let binary = session
            .binary_mut(id)
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
        let mut tx = binary
            .program
            .begin(args.tool(), source, who)
            .map_err(|e| ToolError::new(e.code()))?;
        tx.set_force(force);
        let value = edit(&mut tx)?;
        let planned = diff(tx.edits());
        let rev = tx.program().rev().0;
        tx.abort();
        ctx.mutation = Some(Mutation {
            tx: None,
            noop: true,
            diff: Some(planned),
        });
        return Ok((value, Committed { rev, tx: None }));
    }
    let label = ctx.frame.session.clone();
    let (commit, value) = session.transact(id, args.tool(), &label, |tx| {
        tx.set_force(force);
        edit(tx)
    })?;
    let tx = (!commit.noop).then(|| commit.tx.to_string());
    ctx.frame.rev = commit.rev.0;
    ctx.mutation = Some(Mutation {
        tx: tx.clone(),
        noop: commit.noop,
        diff: None,
    });
    Ok((
        value,
        Committed {
            rev: commit.rev.0,
            tx,
        },
    ))
}

/// Gives the strings of a list value.
pub(crate) fn texts(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Gives the `INVALID_ARGUMENT` error of the argument at `path` with `details.expected`.
pub(crate) fn invalid(path: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", path.trim_start_matches('/'))
        .path(path)
        .detail("expected", Value::from(expected))
}

/// Gives the `MISSING_ARGUMENT` error of the argument `field`.
pub(crate) fn missing(field: &str) -> ToolError {
    ToolError::new(ErrorCode::MissingArgument)
        .var("field", field)
        .path(&format!("/{field}"))
}

/// Gives the `INVALID_ARGUMENT` error of an argument that a call with `items` does not take.
pub(crate) fn not_with_items(field: &str) -> ToolError {
    invalid(
        &format!("/{field}"),
        "no value: each item of items holds its own value",
    )
}

/// Gives the address of an address input on the program of a transaction.
///
/// # Errors
///
/// Returns the errors of [`resolve::address`] with the field path `path`.
pub(crate) fn address_at(tx: &Tx<'_>, input: &Value, path: &str) -> Result<Address, ToolError> {
    resolve::address(tx.program(), input, &site(path)).map(|(a, _)| a)
}

/// Gives the call of `args` again with `force: true`.
pub(crate) fn with_force(args: &Args) -> Call {
    let mut object = args.canonical().as_object().cloned().unwrap_or_default();
    let _ = object.remove("force");
    object.push("force", Value::Bool(true));
    Call::new(args.tool(), Value::Object(object), WHY_FORCE)
}

/// Gives the tool error of the refused edit `e`. `path` is the JSON pointer of the argument
/// that the edit writes.
///
/// A `BLOCKED_BY_HIGHER_PRIORITY_SOURCE` error has `details: { current, source }`. When the
/// same write with `force: true` succeeds, `next[0]` is `retry`.
pub(crate) fn edit_error(e: &EditError, path: &str, retry: Option<Call>) -> ToolError {
    let out = ToolError::new(e.code());
    match (e, e.code()) {
        (EditError::Blocked(b), _) => {
            let current = match &b.value {
                Value::String(text) => Value::from(safe(text)),
                other => other.clone(),
            };
            let out = out
                .path(path)
                .detail("current", current)
                .detail("source", Value::from(b.current.source.name()));
            match retry {
                Some(call) if b.force_applies() && !b.force => out.next(call),
                _ => out,
            }
        }
        (_, ErrorCode::InvalidArgument) => out
            .var("field", path.trim_start_matches('/'))
            .path(path)
            .detail("expected", Value::from(e.to_string())),
        (_, ErrorCode::NotFound) => out
            .var("kind", "fact")
            .path(path)
            .detail("kind", Value::from("fact")),
        _ => out.path(path).detail("reason", Value::from(e.to_string())),
    }
}

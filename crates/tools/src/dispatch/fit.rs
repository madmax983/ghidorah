//! The last step of a call: the budget fit of an object result and the failure envelope
//! (design Sections 10.6, 10.8 and 10.9).
//!
//! An object result that does not fit its budget gives `OUTPUT_BUDGET_EXCEEDED`, with one
//! exception. A call that committed an edit never fails after the commit. Its envelope drops
//! data members, largest first, until it fits. It keeps `tx`, `rev`, `noop` and each ID member.
//! It sets `data.truncated` and `data.omitted`. Then `next[0]` reads the history since the rev
//! before the call.
//!
//! A failure envelope holds the error object and the valid repair calls.

use std::any::Any;

use ghidorah_base::{ErrorCode, IdKind};
use ghidorah_json::{Object, Value};

use super::{Ctx, Invocation, StepRun, with_arg};
use crate::api::Host;
use crate::content::result_chars;
use crate::envelope::{Body, Envelope, Frame};
use crate::errors::{ToolError, int};
use crate::hints::{
    Call, MAX_NEXT, WHY_BINARY, WHY_BRIEF, WHY_HISTORY, WHY_SCHEMA, WHY_SEARCH, keep_valid,
};
use crate::registry::Registry;
use crate::session::{Session, WHY_REOPEN};

/// The data members that a trimmed commit always keeps.
const KEEP: [&str; 4] = ["id", "rev", "tx", "noop"];

/// The data members that mark a trimmed commit.
const MARKS: [&str; 2] = ["truncated", "omitted"];

/// The longest text value that counts as an ID member.
const MAX_ID_CHARS: usize = 256;

/// Gives `envelope` when it fits the budget. A committed call drops data members until it
/// fits. Else the result is an `OUTPUT_BUDGET_EXCEEDED` failure. A batch step keeps its whole
/// envelope.
pub(super) fn fit_or_fail<S: Host>(
    call: &Invocation<'_, S>,
    host: &S,
    ctx: &Ctx,
    envelope: Envelope,
) -> StepRun {
    let size = chars(ctx, &envelope);
    if call.whole || size <= ctx.budget.limit() {
        return done(envelope);
    }
    if committed(call, ctx) {
        return done(trim(call, host, ctx, envelope));
    }
    let error = ToolError::new(ErrorCode::OutputBudgetExceeded)
        .detail("chars", int(size))
        .detail("limit", int(ctx.budget.limit()));
    fail(
        call.registry,
        host,
        ctx.frame.clone(),
        call.tool.name,
        error,
    )
}

/// Gives the step result of a success.
const fn done(envelope: Envelope) -> StepRun {
    StepRun {
        envelope,
        fuel_used: 0,
        error: None,
    }
}

/// Gives the size of `envelope` in the result.
fn chars(ctx: &Ctx, envelope: &Envelope) -> u64 {
    result_chars(&envelope.to_json(), false, ctx.budget.mode)
}

/// Tells if the call committed: a mutating tool that made a transaction, changed the rev or
/// bound a new binary.
fn committed<S: Host>(call: &Invocation<'_, S>, ctx: &Ctx) -> bool {
    let tx = ctx.mutation.as_ref().is_some_and(|m| m.tx.is_some());
    let moved = ctx.frame.rev != call.start.rev || ctx.frame.binary_id != call.start.binary_id;
    call.tool.mutating && (tx || moved)
}

/// Tells if the data member `name` with `value` stays in a trimmed commit.
fn keeps(name: &str, value: &Value) -> bool {
    KEEP.contains(&name)
        || name.ends_with("_id")
        || value.as_str().is_some_and(|text| {
            text.chars().count() <= MAX_ID_CHARS && IdKind::of_text(text).is_some()
        })
}

/// Drops the data members of a committed envelope, largest first, until it fits.
///
/// The data gets `truncated: true` and `omitted`: the names of the dropped members. `next[0]`
/// is `history_list { since_rev }` with the rev before the call, when the profile holds it.
/// When the kept members still do not fit, the warnings go, then each `next` call after the
/// first. The call never fails after its commit.
fn trim<S: Host>(
    call: &Invocation<'_, S>,
    host: &S,
    ctx: &Ctx,
    mut envelope: Envelope,
) -> Envelope {
    let since = Value::object([("since_rev", int(call.start.rev))]);
    let history = Call::new("history_list", since, WHY_HISTORY);
    let mut next = keep_valid(call.registry, &|name| host.in_profile(name), vec![history]);
    next.append(&mut envelope.next);
    next.truncate(MAX_NEXT);
    envelope.next = next;
    let Body::Ok { data, .. } = &mut envelope.body else {
        return envelope;
    };
    let mut object = match std::mem::take(data) {
        Value::Object(object) => object,
        other => {
            let mut object = Object::new();
            object.push("data", other);
            object
        }
    };
    let mut order: Vec<(usize, String)> = object
        .iter()
        .filter(|(name, value)| !MARKS.contains(name) && !keeps(name, value))
        .map(|(name, value)| (ghidorah_json::write(value).len(), name.to_owned()))
        .collect();
    order.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut omitted: Vec<Value> = Vec::new();
    let mut drops = order.into_iter();
    loop {
        let mut shown = object.clone();
        let _ = shown.insert("truncated", Value::Bool(true));
        let _ = shown.insert("omitted", Value::Array(omitted.clone()));
        if let Body::Ok { data, .. } = &mut envelope.body {
            *data = Value::Object(shown);
        }
        if chars(ctx, &envelope) <= ctx.budget.limit() {
            return envelope;
        }
        let Some((_, name)) = drops.next() else {
            break;
        };
        let _ = object.remove(&name);
        omitted.push(Value::from(name));
    }
    if let Body::Ok { warnings, .. } = &mut envelope.body {
        warnings.clear();
    }
    envelope.next.truncate(1);
    envelope
}

/// Adds the repair call of a `BINARY_REQUIRED` error that has `details.binary_id`: the same
/// call with that `binary_id`. Other errors and errors with a repair call stay the same.
pub(super) fn binary_repair(tool: &str, args: &Value, error: ToolError) -> ToolError {
    let id = error
        .details
        .as_ref()
        .and_then(|details| details.get("binary_id"))
        .cloned();
    match id {
        Some(id) if error.code == ErrorCode::BinaryRequired && error.next.is_empty() => {
            let call = Call::new(tool, with_arg(args, "binary_id", Some(id)), WHY_BINARY);
            error.next(call)
        }
        _ => error,
    }
}

/// Gives the failure envelope of `error`, with helper calls for the codes of class H.
pub(super) fn failure<S: Host>(
    registry: &Registry<S>,
    host: &S,
    frame: Frame,
    tool: &str,
    error: &ToolError,
) -> Envelope {
    let mut next = error.next.clone();
    if next.is_empty() {
        let helper = match error.code {
            ErrorCode::MissingArgument => Some((
                "tool_search",
                Value::object([("name", Value::from(tool)), ("level", Value::from("full"))]),
                WHY_SCHEMA,
            )),
            ErrorCode::UnknownTool => Some((
                "tool_search",
                Value::object([("query", Value::from(tool))]),
                WHY_SEARCH,
            )),
            ErrorCode::NoBinaryOpen => {
                Some(("session_brief", Value::Object(Object::new()), WHY_BRIEF))
            }
            _ => None,
        };
        next.extend(helper.map(|(name, args, why)| Call::new(name, args, why)));
    }
    let next = keep_valid(registry, &|name| host.in_profile(name), next);
    Envelope {
        frame,
        body: Body::Err(error.to_json_with(!next.is_empty())),
        next,
    }
}

/// Adds the repair call of a `NO_BINARY_OPEN` error in a profile with no `session_brief`:
/// `binary_load { binary_id }` of the newest project of the session. Other errors, errors
/// with a repair call and other hosts stay the same.
pub(super) fn project_repair<S: Host>(host: &mut S, error: ToolError) -> ToolError {
    if error.code != ErrorCode::NoBinaryOpen
        || !error.next.is_empty()
        || host.in_profile("session_brief")
    {
        return error;
    }
    let any: &mut dyn Any = host;
    let newest = any
        .downcast_mut::<Session>()
        .and_then(|session| session.projects().into_iter().next());
    match newest {
        Some(project) => {
            let args = Value::object([("binary_id", Value::from(project.binary_id.to_string()))]);
            error.next(Call::new("binary_load", args, WHY_REOPEN))
        }
        None => error,
    }
}

/// Gives the step result of the failure `error`.
pub(super) fn fail<S: Host>(
    registry: &Registry<S>,
    host: &S,
    frame: Frame,
    tool: &str,
    error: ToolError,
) -> StepRun {
    StepRun {
        envelope: failure(registry, host, frame, tool, &error),
        fuel_used: 0,
        error: Some(error),
    }
}

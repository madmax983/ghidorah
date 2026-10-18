//! The output of a batch: the step entries, the errors of a batch with edits and the data of
//! the batch result.

use ghidorah_base::ErrorCode;
use ghidorah_json::{Object, Value};

use super::{Failure, Run, Slot, Stop, calls_of};
use crate::args::Args;
use crate::batch::validate::{Plan, repair_in_batch};
use crate::batch::{DEFAULT_FUEL, MAX_FUEL, WHY_RESUME, budget};
use crate::dispatch::Ctx;
use crate::envelope::{Body, Envelope};
use crate::errors::{ToolError, int};
use crate::handlers::batch_run::SPEC;
use crate::hints::Call;

/// The characters that the last fit keeps free for a hint that the dispatcher adds.
const HINT_SLACK: u64 = 160;

/// The members of a step envelope that the step entry copies after `error`.
const COPIED: [&str; 3] = ["page", "warnings", "next"];

/// Removes the `analysis_run` calls from the `next` list of a step. A batch with edits runs
/// the analysis once after the commit, so these step hints do not help.
fn without_analysis(next: Value) -> Value {
    match next {
        Value::Array(calls) => Value::Array(
            calls
                .into_iter()
                .filter(|c| c.get("tool").and_then(Value::as_str) != Some("analysis_run"))
                .collect(),
        ),
        other => other,
    }
}

/// The result of one step run, before the entry.
pub(super) struct Ran {
    /// The step envelope as JSON.
    pub json: Value,
    /// The size of the envelope.
    pub chars: u64,
    /// The fuel that the step used.
    pub fuel: u64,
    /// The step error, with its template variables.
    pub error: Option<ToolError>,
}

impl Run<'_> {
    /// Adds the entry of step `i` that ran out of fuel, and stops the batch.
    pub(super) fn out_of_fuel(&mut self, i: usize, ran: &Ran) {
        let mut entry = self.head(i);
        entry.push("ok", Value::Bool(false));
        entry.push("chars", int(ran.chars));
        entry.push("fuel", int(ran.fuel));
        entry.push("error", ToolError::new(ErrorCode::BudgetExceeded).to_json());
        self.entries.push(Value::Object(entry));
        if let Some(slot) = self.slots.get_mut(i) {
            *slot = Slot::Failed;
        }
        self.stop = Some((Stop::Fuel, i));
    }

    /// Adds the entry of step `i` that ran. A returned step that passed keeps its data. A
    /// failed step or guard records the failure of the batch.
    pub(super) fn record(&mut self, i: usize, ran: Ran, guard: Option<ToolError>, ok: bool) {
        let returned = self.plan.returned.get(i).copied().unwrap_or(false);
        let mut entry = self.head(i);
        entry.push("ok", Value::Bool(ok));
        entry.push("chars", int(ran.chars));
        entry.push("fuel", int(ran.fuel));
        if returned
            && ok
            && let Some(data) = ran.json.get("data")
        {
            entry.push("data", data.clone());
            self.returned_chars = self.returned_chars.saturating_add(ran.chars);
        }
        match (&guard, ran.json.get("error")) {
            (Some(g), _) => entry.push("error", g.to_json()),
            (None, Some(e)) => entry.push("error", e.clone()),
            _ => {}
        }
        for key in COPIED {
            let Some(mut value) = ran.json.get(key).cloned() else {
                continue;
            };
            if key == "next" && self.plan.is_mutating() {
                value = without_analysis(value);
            }
            if value.as_array().is_some_and(<[Value]>::is_empty) {
                continue;
            }
            entry.push(key, value);
        }
        self.entries.push(Value::Object(entry));
        let next = calls_of(&ran.json);
        let slot = if ok {
            Slot::Done(ran.json)
        } else {
            Slot::Failed
        };
        if let Some(s) = self.slots.get_mut(i) {
            *s = slot;
        }
        if !ok {
            let error = guard
                .or(ran.error)
                .unwrap_or_else(|| ToolError::new(ErrorCode::InternalError));
            self.failed(i, &error, next);
        }
    }
}

/// Gives the error of a failed batch with edits, after the roll back.
///
/// A repair call of the step tool becomes the batch with the repaired step.
pub(super) fn batch_error(plan: &Plan, failure: Failure) -> ToolError {
    let Some(step) = plan.steps.get(failure.step) else {
        return failure.error;
    };
    let mut error = failure.error;
    let inner = error.field_path.clone().unwrap_or_default();
    if !inner.starts_with("/steps/") {
        error.field_path = Some(format!("/steps/{}/args{inner}", failure.step));
    }
    error.next = failure
        .next
        .iter()
        .map(|c| {
            repair_in_batch(&plan.raw, failure.step, step.tool, &step.refs, c)
                .unwrap_or_else(|| c.clone())
        })
        .collect();
    error.detail("step", Value::from(step.id.as_str()))
}

/// Gives the error of a batch with edits that ran out of fuel or time: `next[0]` sends the
/// batch again with more fuel.
pub(super) fn stop_error(plan: &Plan, stop: Stop, args: &Args) -> ToolError {
    let given = args.globals().max_steps.unwrap_or(DEFAULT_FUEL);
    let more = given.saturating_mul(10).clamp(DEFAULT_FUEL, MAX_FUEL);
    let error = ToolError::new(ErrorCode::BudgetExceeded).detail(
        "stopped_by",
        Value::from(if stop == Stop::Time { "time" } else { "fuel" }),
    );
    if stop == Stop::Fuel && given >= MAX_FUEL {
        return error;
    }
    let mut batch = plan.raw.clone();
    if let Some(object) = batch.as_object_mut() {
        let _ = object.insert("max_steps", Value::from(more));
    }
    error.next(Call::new(SPEC.name, batch, WHY_RESUME))
}

/// Gives the size of the result of `data` in the frame of `ctx`.
fn result_size(ctx: &Ctx, data: &Value, next: &[Call]) -> u64 {
    let envelope = Envelope {
        frame: ctx.frame.clone(),
        body: Body::Ok {
            data: data.clone(),
            page: None,
            warnings: ctx.warnings.clone(),
            mutation: ctx.mutation.clone(),
        },
        next: next.to_vec(),
    };
    budget::result_cost(&ctx.budget, &envelope.to_json()).saturating_add(HINT_SLACK)
}

/// Builds the data of the batch result from the step entries `entries`.
fn build(run: &Run<'_>, entries: &[Value]) -> Value {
    let mut out = Object::new();
    out.push("steps", Value::Array(entries.to_vec()));
    out.push(
        "budget_used",
        Value::object([
            ("chars", int(run.returned_chars)),
            ("fuel", int(run.fuel)),
            ("steps", int(run.ran)),
        ]),
    );
    if let Some((stop, from)) = run.stop {
        let time = stop == Stop::Time;
        out.push(
            "stopped_by",
            Value::from(if time { "time" } else { "fuel" }),
        );
        if time {
            out.push("deterministic", Value::Bool(false));
        }
        if let Some(resume) = run.resume(from) {
            out.push("resume", resume);
        }
    }
    Value::Object(out)
}

/// Builds the data of the batch result and fits it into the budget.
pub(super) fn data_of(run: &Run<'_>, ctx: &Ctx, next: &[Call]) -> Value {
    let mut entries = run.entries.clone();
    let limit = ctx.budget.limit();
    budget::fit(&mut entries, &mut |e| {
        result_size(ctx, &build(run, e), next) <= limit
    });
    build(run, &entries)
}

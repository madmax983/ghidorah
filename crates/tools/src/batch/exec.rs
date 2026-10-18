//! The run of a batch (design Sections 11.4 to 11.6).
//!
//! The steps run in order through the dispatcher of the session. Thus a step envelope equals
//! the envelope of the same direct call at the same rev (AC-175). A step that refers to a
//! failed step gets `SKIPPED_DEPENDENCY`. A batch with edits opens one transaction on the
//! bound binary: it commits once at the end, or rolls back at the first failure.

use ghidorah_base::{BinaryId, ErrorCode, WarningCode};
use ghidorah_json::{Object, Value};

use super::budget::{self, MIN_STEP_CHARS};
use super::refs::{self, Reference};
use super::validate::{Plan, check, repair_in_batch, with_step_args};
use super::{DEFAULT_FUEL, MAX_FUEL, OnError, WHY_LIMIT, WHY_RESUME};
use crate::api::{Host, Request};
use crate::args::Args;
use crate::content::ContentMode;
use crate::dispatch::{Ctx, Payload, StepLimits, StepRun, run_step};
use crate::envelope::{Body, Envelope, Mutation, Warning};
use crate::errors::{ToolError, int};
use crate::handlers::batch_run::SPEC;
use crate::handlers::symbol_rename::edits::diff;
use crate::hints::Call;
use crate::registry::Registry;
use crate::session::Session;

/// The characters that the last fit keeps free for a hint that the dispatcher adds.
const HINT_SLACK: u64 = 160;

/// The largest size of an actual value in `details.actual` of a guard error.
const MAX_ACTUAL_CHARS: u64 = 512;

/// The state of one step during the run.
#[derive(Debug, Clone)]
enum Slot {
    /// The step did not run yet.
    Waiting,
    /// The step ran and passed: its envelope.
    Done(Value),
    /// A replay binds the values of the step.
    Resumed,
    /// The step failed or the batch skipped it.
    Failed,
}

/// Why a batch stopped before its last step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The fuel ran out.
    Fuel,
    /// The `max_ms` guard fired.
    Time,
}

/// The first failed step of a batch.
#[derive(Debug, Clone)]
struct Failure {
    /// The index of the step.
    step: usize,
    /// The error.
    error: ToolError,
    /// The `next` calls of the step.
    next: Vec<Call>,
}

/// The run state of one batch.
struct Run<'p> {
    plan: &'p Plan,
    registry: Registry<Session>,
    slots: Vec<Slot>,
    entries: Vec<Value>,
    failure: Option<Failure>,
    stop: Option<(Stop, usize)>,
    ran: u64,
    fuel: u64,
    returned_chars: u64,
}

/// Gives the error of a step that refers to the failed step `failed`.
fn skipped(failed: &str) -> ToolError {
    ToolError::new(ErrorCode::SkippedDependency).detail("failed_step", Value::from(failed))
}

/// Gives the `next` calls of an envelope.
fn calls_of(envelope: &Value) -> Vec<Call> {
    envelope
        .get("next")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|c| {
            Call::new(
                c.get("tool").and_then(Value::as_str).unwrap_or_default(),
                c.get("args").cloned().unwrap_or_default(),
                c.get("why").and_then(Value::as_str).unwrap_or_default(),
            )
        })
        .collect()
}

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

/// Gives the actual value of a failed guard, cut to a summary when it is long.
fn actual_of(value: Value) -> Value {
    if budget::size(&value) <= MAX_ACTUAL_CHARS {
        return value;
    }
    let kind = match &value {
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        _ => "text",
    };
    let len = match &value {
        Value::Array(items) => items.len(),
        Value::Object(object) => object.len(),
        Value::String(text) => text.chars().count(),
        _ => 0,
    };
    Value::object([("type", Value::from(kind)), ("len", Value::from(len))])
}

/// Gives the batch call `raw` with the `limit` of step `step` set to `cap`.
fn with_limit(raw: &Value, step: usize, cap: usize) -> Value {
    with_step_args(raw, step, |args| {
        let _ = args.insert("limit", Value::from(cap));
    })
}

impl<'p> Run<'p> {
    fn new(plan: &'p Plan, registry: Registry<Session>) -> Self {
        let count = plan.steps.len();
        Self {
            plan,
            registry,
            slots: vec![Slot::Waiting; count],
            entries: Vec::with_capacity(count),
            failure: None,
            stop: None,
            ran: 0,
            fuel: 0,
            returned_chars: 0,
        }
    }

    /// Gives the start of the step entry `i`: `{ id, tool }`.
    fn head(&self, i: usize) -> Object {
        let mut out = Object::new();
        if let Some(step) = self.plan.steps.get(i) {
            out.push("id", Value::from(step.id.as_str()));
            out.push("tool", Value::from(step.tool.name));
        }
        out
    }

    /// Adds the entry of a step that did not run: `ok`, no chars, no fuel and `error`.
    fn not_run(&mut self, i: usize, error: Option<&ToolError>) {
        let mut entry = self.head(i);
        entry.push("ok", Value::Bool(false));
        entry.push("chars", int(0));
        entry.push("fuel", int(0));
        if let Some(e) = error {
            entry.push("error", e.to_json());
        }
        self.entries.push(Value::Object(entry));
        if let Some(slot) = self.slots.get_mut(i) {
            *slot = Slot::Failed;
        }
    }

    /// Records the first failure of the batch.
    fn failed(&mut self, step: usize, error: &ToolError, next: Vec<Call>) {
        if self.failure.is_none() {
            self.failure = Some(Failure {
                step,
                error: error.clone(),
                next,
            });
        }
    }

    /// Gives the value of reference `r` of step `i` from the bindings of the replay.
    fn bound(&self, r: &Reference, i: usize) -> Result<Value, ToolError> {
        let source = self.plan.steps.get(r.source).map_or("", |s| s.id.as_str());
        let bindings = self
            .plan
            .resume
            .as_ref()
            .map(|x| x.bindings.as_slice())
            .unwrap_or_default();
        let found = bindings.iter().find(|b| b.step == source && b.ptr == r.ptr);
        let Some(binding) = found else {
            let options = bindings
                .iter()
                .filter(|b| b.step == source)
                .map(|b| crate::errors::Candidate::text(&b.ptr, "binding"))
                .collect();
            return Err(ToolError::new(ErrorCode::BadReference)
                .path(&r.path(i))
                .detail("expected", Value::from("a binding of the completed step"))
                .candidates(options));
        };
        refs::check(r, &binding.value, i)?;
        Ok(binding.value.clone())
    }

    /// Gives the resolved arguments of step `i`, or the error of a reference.
    fn resolve(&self, i: usize) -> Result<Value, ToolError> {
        let step = &self.plan.steps[i];
        let mut args = step.args.clone();
        for r in &step.refs {
            let value = match self.slots.get(r.source) {
                Some(Slot::Done(envelope)) => refs::resolve(r, envelope, i),
                Some(Slot::Resumed) => self.bound(r, i),
                _ => Err(skipped(
                    self.plan.steps.get(r.source).map_or("", |s| s.id.as_str()),
                )),
            };
            match value {
                Ok(value) => refs::set_at(&mut args, &r.at, value),
                Err(e) if e.code == ErrorCode::PluckTooLong => {
                    let source = self.plan.steps.get(r.source);
                    let cap = r.cap().unwrap_or(0);
                    let error = match source.filter(|s| s.tool.list.is_some()) {
                        Some(_) => {
                            let batch = with_limit(&self.plan.raw, r.source, cap);
                            e.next(Call::new(SPEC.name, batch, WHY_LIMIT))
                        }
                        None => e,
                    };
                    return Err(error);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(args)
    }

    /// Checks the claim guards of step `i`. Gives the guard index and the actual verdict of
    /// the first claim that is not supported.
    fn claims(
        &mut self,
        i: usize,
        session: &mut Session,
        ctx: &mut Ctx,
        binary: Option<&str>,
    ) -> Option<(usize, Value)> {
        let step = &self.plan.steps[i];
        for (j, claim) in step.claims.iter().enumerate() {
            let known =
                self.registry.get("fact_check").is_some() && session.in_profile("fact_check");
            if !known {
                return Some((j, Value::from("unknown")));
            }
            let mut args = Object::new();
            args.push("claims", Value::Array(vec![claim.clone()]));
            if let Some(id) = binary {
                args.push("binary_id", Value::from(id));
            }
            let mut request = Request::new("fact_check", Value::Object(args));
            request.session = Some(ctx.frame.session.clone());
            let limits = StepLimits {
                max_chars: budget::unreturned(),
                fuel: ctx.fuel.remaining(),
            };
            let run = run_step(&self.registry, session, &request, limits);
            let _ = ctx.fuel.take(run.fuel_used.min(ctx.fuel.remaining()));
            self.fuel = self.fuel.saturating_add(run.fuel_used);
            let envelope = run.envelope.to_json();
            let verdict = envelope
                .pointer("/data/verdicts/0/verdict")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    envelope
                        .pointer("/error/code")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "unknown".to_owned());
            if verdict != "supported" {
                return Some((j, Value::from(verdict)));
            }
        }
        None
    }

    /// Gives the size of the entries so far.
    fn used(&self) -> u64 {
        self.entries.iter().map(budget::size).sum()
    }

    /// Runs step `i`.
    fn step(&mut self, i: usize, session: &mut Session, ctx: &mut Ctx, binary: Option<&str>) {
        let step = &self.plan.steps[i];
        let failed_source = step
            .refs
            .iter()
            .find(|r| matches!(self.slots.get(r.source), Some(Slot::Failed)))
            .and_then(|r| self.plan.steps.get(r.source))
            .map(|s| s.id.clone());
        if let Some(source) = failed_source {
            self.not_run(i, Some(&skipped(&source)));
            return;
        }
        let mut args = match self.resolve(i) {
            Ok(args) => args,
            Err(e) => {
                let next = e.next.clone();
                self.not_run(i, Some(&e));
                self.failed(i, &e, next);
                return;
            }
        };
        let tool = step.tool;
        if let (Some(id), Some(object)) = (binary, args.as_object_mut())
            && tool.binary != crate::spec::BinaryArg::None
        {
            object.push("binary_id", Value::from(id));
        }
        let mut request = Request::new(tool.name, args);
        request.session = Some(ctx.frame.session.clone());
        request.content = ContentMode::Plain;
        let returned = self.plan.returned.get(i).copied().unwrap_or(false);
        let later = self.plan.steps.len().saturating_sub(i.saturating_add(1));
        let max_chars = if returned {
            budget::share(&ctx.budget, self.used(), later, tool.max_chars)
        } else {
            budget::unreturned()
        };
        let remaining = ctx.fuel.remaining();
        let limits = StepLimits {
            max_chars: max_chars.max(MIN_STEP_CHARS),
            fuel: remaining,
        };
        let StepRun {
            envelope,
            fuel_used,
            error,
        } = run_step(&self.registry, session, &request, limits);
        let _ = ctx.fuel.take(fuel_used.min(remaining));
        self.fuel = self.fuel.saturating_add(fuel_used);
        self.ran = self.ran.saturating_add(1);
        let json = envelope.to_json();
        let chars = budget::size(&json);
        let out_of_fuel = error
            .as_ref()
            .is_some_and(|e| e.code == ErrorCode::BudgetExceeded)
            || (fuel_used > 0 && fuel_used >= remaining);
        let mut entry = self.head(i);
        if out_of_fuel {
            let e = ToolError::new(ErrorCode::BudgetExceeded);
            entry.push("ok", Value::Bool(false));
            entry.push("chars", int(chars));
            entry.push("fuel", int(fuel_used));
            entry.push("error", e.to_json());
            self.entries.push(Value::Object(entry));
            self.slots[i] = Slot::Failed;
            self.stop = Some((Stop::Fuel, i));
            return;
        }
        let mut guard: Option<ToolError> = None;
        if envelope.ok() {
            for (j, g) in step.expect.iter().enumerate() {
                if let Err(actual) = g.check(&json) {
                    guard = Some(
                        ToolError::new(ErrorCode::ExpectFailed)
                            .path(&format!("/steps/{i}/expect/{j}"))
                            .detail("actual", actual_of(actual))
                            .detail("ptr", Value::from(g.ptr.as_str())),
                    );
                    break;
                }
            }
            if guard.is_none()
                && let Some((j, verdict)) = self.claims(i, session, ctx, binary)
            {
                guard = Some(
                    ToolError::new(ErrorCode::ExpectFailed)
                        .path(&format!("/steps/{i}/claim/{j}"))
                        .detail("actual", verdict),
                );
            }
        }
        let ok = envelope.ok() && guard.is_none();
        entry.push("ok", Value::Bool(ok));
        entry.push("chars", int(chars));
        entry.push("fuel", int(fuel_used));
        if returned
            && ok
            && let Some(data) = json.get("data")
        {
            entry.push("data", data.clone());
            self.returned_chars = self.returned_chars.saturating_add(chars);
        }
        match (&guard, json.get("error")) {
            (Some(g), _) => entry.push("error", g.to_json()),
            (None, Some(e)) => entry.push("error", e.clone()),
            _ => {}
        }
        for key in ["page", "warnings", "next"] {
            let Some(mut value) = json.get(key).cloned() else {
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
        if ok {
            self.slots[i] = Slot::Done(json);
            return;
        }
        self.slots[i] = Slot::Failed;
        let next = calls_of(&json);
        let error = guard
            .or(error)
            .unwrap_or_else(|| ToolError::new(ErrorCode::InternalError));
        self.failed(i, &error, next);
    }

    /// Runs the steps in order until the end, a stop or a failure that ends the batch.
    fn all(
        &mut self,
        session: &mut Session,
        ctx: &mut Ctx,
        binary: Option<&str>,
        max_ms: Option<u64>,
    ) {
        let start = session.clock().monotonic_ms();
        let timed = !session.config().run.eval_mode;
        let from = self.plan.resume.as_ref().map_or(0, |r| r.from);
        for i in 0..self.plan.steps.len() {
            if i < from {
                let mut entry = self.head(i);
                entry.push("ok", Value::Bool(true));
                entry.push("chars", int(0));
                entry.push("fuel", int(0));
                entry.push("resumed", Value::Bool(true));
                self.entries.push(Value::Object(entry));
                self.slots[i] = Slot::Resumed;
                continue;
            }
            let stopped = self.stop.is_some()
                || (self.failure.is_some() && self.plan.on_error == OnError::Stop);
            if stopped {
                let failed = self
                    .failure
                    .as_ref()
                    .map(|f| self.plan.steps[f.step].id.clone());
                let error = failed
                    .filter(|_| self.stop.is_none())
                    .map(|id| skipped(&id));
                self.not_run(i, error.as_ref());
                self.slots[i] = Slot::Waiting;
                continue;
            }
            let late = max_ms.is_some_and(|ms| {
                timed && session.clock().monotonic_ms().saturating_sub(start) > ms
            });
            if late || ctx.fuel.is_empty() {
                self.stop = Some((if late { Stop::Time } else { Stop::Fuel }, i));
                self.not_run(i, None);
                self.slots[i] = Slot::Waiting;
                continue;
            }
            self.step(i, session, ctx, binary);
        }
    }

    /// Gives the resume member of a stop at step `from`: `{ from_step, bindings }`, or `None`
    /// when the bindings are too large.
    fn resume(&self, from: usize) -> Option<Value> {
        let mut list = Vec::new();
        for step in self.plan.steps.iter().skip(from) {
            for r in step.refs.iter().filter(|r| r.source < from) {
                let source = &self.plan.steps[r.source];
                let value = match self.slots.get(r.source) {
                    Some(Slot::Done(envelope)) => refs::resolve(r, envelope, r.source).ok(),
                    Some(Slot::Resumed) => self.bound(r, r.source).ok(),
                    _ => None,
                };
                if let Some(value) = value {
                    list.push((source.id.clone(), r.ptr.clone(), value));
                }
            }
        }
        let bindings = budget::bindings(list)?;
        let id = self.plan.steps.get(from).map_or("", |s| s.id.as_str());
        Some(Value::object([
            ("from_step", Value::from(id)),
            ("bindings", bindings),
        ]))
    }
}

/// Gives the error of a failed batch with edits, after the roll back.
///
/// A repair call of the step tool becomes the batch with the repaired step.
fn batch_error(plan: &Plan, failure: Failure) -> ToolError {
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
fn stop_error(plan: &Plan, stop: Stop, args: &Args) -> ToolError {
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

/// Builds the data of the batch result and fits it into the budget.
fn data_of(run: &Run<'_>, ctx: &Ctx, next: &[Call]) -> Value {
    let mut entries = run.entries.clone();
    let build = |entries: &[Value]| {
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
    };
    let limit = ctx.budget.limit();
    budget::fit(&mut entries, &mut |e| {
        result_size(ctx, &build(e), next) <= limit
    });
    build(&entries)
}

/// Runs the batch of `args`: the handler of `batch_run`.
///
/// # Errors
///
/// Returns the first validation error, with a `/steps/N/..` field path. A batch with edits
/// returns the error of its failed step after the roll back, or `BUDGET_EXCEEDED` when its
/// fuel or its time runs out.
pub fn run(session: &mut Session, args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let registry = session.active_registry();
    let profile = session.config().profile.clone();
    let plan = check(&registry, &profile, args)?;
    let bound = ctx
        .frame
        .binary_id
        .as_deref()
        .and_then(|t| BinaryId::parse(t).ok());
    let binary = args.globals().binary_id.clone();
    let batch = bound.filter(|_| plan.mutating);
    if let Some(id) = batch {
        session.batch_begin(id, &plan.label)?;
    }
    let mut run = Run::new(&plan, registry);
    run.all(session, ctx, binary.as_deref(), args.globals().max_ms);
    let dry = args.globals().dry_run;
    if plan.mutating {
        let stop = run.stop;
        if let Some(failure) = run.failure.clone() {
            if let Some(id) = batch {
                session.batch_rollback(id);
            }
            return Err(batch_error(&plan, failure));
        }
        if let Some((stop, _)) = stop {
            if let Some(id) = batch {
                session.batch_rollback(id);
            }
            return Err(stop_error(&plan, stop, args));
        }
    }
    match (batch, dry) {
        (Some(id), true) => {
            let planned = session.batch_planned(id);
            session.batch_rollback(id);
            ctx.mutation = Some(Mutation {
                tx: None,
                noop: true,
                diff: Some(diff(&planned)),
            });
        }
        (Some(id), false) => {
            let commit = session.batch_commit(id, &mut ctx.fuel)?;
            ctx.mutation = Some(Mutation {
                tx: commit.tx.map(|t| t.to_string()),
                noop: commit.tx.is_none(),
                diff: None,
            });
        }
        (None, true) => {
            ctx.mutation = Some(Mutation {
                tx: None,
                noop: true,
                diff: Some(Value::Array(Vec::new())),
            });
        }
        (None, false) => {}
    }
    if let Some(binary) = bound.and_then(|id| session.binary(id)) {
        ctx.frame.rev = binary.program.rev().0;
        ctx.frame.analysis = binary.analysis;
    }
    if run.stop.is_some_and(|(s, _)| s == Stop::Time) {
        ctx.warn(Warning::new(WarningCode::TimeStop));
    }
    let next = run
        .failure
        .as_ref()
        .map(|f| f.next.clone())
        .unwrap_or_default();
    let data = data_of(&run, ctx, &next);
    for call in next {
        ctx.hint(call);
    }
    match data {
        Value::Object(object) => Ok(Payload::Object(object)),
        _ => Err(ToolError::new(ErrorCode::InternalError)),
    }
}

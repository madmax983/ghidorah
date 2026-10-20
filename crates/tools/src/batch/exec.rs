//! The run of a batch (design Sections 11.4 to 11.6).
//!
//! The steps run in order through the dispatcher of the session. Thus a step envelope equals
//! the envelope of the same direct call at the same rev (AC-175). A step that refers to a
//! failed step gets `SKIPPED_DEPENDENCY`. A batch with edits opens one transaction on the
//! bound binary: it commits once at the end, or rolls back at the first failure.
//!
//! | Module | Part |
//! |---|---|
//! | `inputs` | the resolved references, the bindings of a replay and the guards |
//! | `output` | the step entries, the errors of a batch with edits and the result data |

mod inputs;
mod output;

use ghidorah_base::{BinaryId, ErrorCode, WarningCode};
use ghidorah_json::{Object, Value};

use self::output::{Ran, batch_error, data_of, stop_error};
use super::OnError;
use super::budget::{self, MIN_STEP_CHARS};
use super::refs;
use super::validate::{Plan, check};
use crate::api::Request;
use crate::args::Args;
use crate::content::ContentMode;
use crate::dispatch::{Ctx, Payload, StepLimits, StepRun, run_step};
use crate::envelope::{Mutation, Warning};
use crate::errors::{ToolError, int};
use crate::handlers::symbol_rename::edits::diff;
use crate::hints::Call;
use crate::registry::Registry;
use crate::session::Session;

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

    /// Sets the slot of step `i`.
    fn set(&mut self, i: usize, slot: Slot) {
        if let Some(s) = self.slots.get_mut(i) {
            *s = slot;
        }
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
        self.set(i, Slot::Failed);
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

    /// Gives the size of the entries so far.
    fn used(&self) -> u64 {
        self.entries.iter().map(budget::size).sum()
    }

    /// Gives the arguments of step `i`, or `None` when the step does not run. The batch skips
    /// a step that refers to a failed step. A reference that does not resolve fails the step.
    fn inputs(&mut self, i: usize) -> Option<Value> {
        let step = self.plan.steps.get(i)?;
        let failed_source = step
            .refs
            .iter()
            .find(|r| matches!(self.slots.get(r.source), Some(Slot::Failed)))
            .and_then(|r| self.plan.steps.get(r.source))
            .map(|s| s.id.clone());
        if let Some(source) = failed_source {
            self.not_run(i, Some(&skipped(&source)));
            return None;
        }
        match self.resolve(i) {
            Ok(args) => Some(args),
            Err(e) => {
                let next = e.next.clone();
                self.not_run(i, Some(&e));
                self.failed(i, &e, next);
                None
            }
        }
    }

    /// Gives the limits of step `i`: a returned step shares the budget, and a step outside
    /// `return` gets the hard cap. The step gets the remaining fuel.
    fn limits(&self, i: usize, ctx: &Ctx) -> StepLimits {
        let returned = self.plan.returned.get(i).copied().unwrap_or(false);
        let later = self.plan.steps.len().saturating_sub(i.saturating_add(1));
        let tool_max = self.plan.steps.get(i).map_or(0, |s| s.tool.max_chars);
        let max_chars = if returned {
            budget::share(&ctx.budget, self.used(), later, tool_max)
        } else {
            budget::unreturned()
        };
        StepLimits {
            max_chars: max_chars.max(MIN_STEP_CHARS),
            fuel: ctx.fuel.remaining(),
        }
    }

    /// Runs step `i`.
    fn step(&mut self, i: usize, session: &mut Session, ctx: &mut Ctx, binary: Option<&str>) {
        let Some(tool) = self.plan.steps.get(i).map(|s| s.tool) else {
            return;
        };
        let Some(mut args) = self.inputs(i) else {
            return;
        };
        if let (Some(id), Some(object)) = (binary, args.as_object_mut())
            && tool.binary != crate::spec::BinaryArg::None
        {
            object.push("binary_id", Value::from(id));
        }
        let mut request = Request::new(tool.name, args);
        request.session = Some(ctx.frame.session.clone());
        request.content = ContentMode::Plain;
        let limits = self.limits(i, ctx);
        let remaining = limits.fuel;
        let StepRun {
            envelope,
            fuel_used,
            error,
        } = run_step(&self.registry, session, &request, limits);
        let _ = ctx.fuel.take(fuel_used.min(remaining));
        self.fuel = self.fuel.saturating_add(fuel_used);
        self.ran = self.ran.saturating_add(1);
        let json = envelope.to_json();
        let ran = Ran {
            chars: budget::size(&json),
            json,
            fuel: fuel_used,
            error,
        };
        let budget_error = ran
            .error
            .as_ref()
            .is_some_and(|e| e.code == ErrorCode::BudgetExceeded);
        if budget_error || (fuel_used > 0 && fuel_used >= remaining) {
            self.out_of_fuel(i, &ran);
            return;
        }
        let guard = if envelope.ok() {
            self.guard(i, &ran.json, session, ctx, binary)
        } else {
            None
        };
        let ok = envelope.ok() && guard.is_none();
        self.record(i, ran, guard, ok);
    }

    /// Adds the entry of step `i` that a replay skips: the step passed in an earlier call.
    fn resumed(&mut self, i: usize) {
        let mut entry = self.head(i);
        entry.push("ok", Value::Bool(true));
        entry.push("chars", int(0));
        entry.push("fuel", int(0));
        entry.push("resumed", Value::Bool(true));
        self.entries.push(Value::Object(entry));
        self.set(i, Slot::Resumed);
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
                self.resumed(i);
                continue;
            }
            let stopped = self.stop.is_some()
                || (self.failure.is_some() && self.plan.on_error == OnError::Stop);
            if stopped {
                let failed = self
                    .failure
                    .as_ref()
                    .and_then(|f| self.plan.steps.get(f.step))
                    .map(|s| s.id.clone());
                let error = failed
                    .filter(|_| self.stop.is_none())
                    .map(|id| skipped(&id));
                self.not_run(i, error.as_ref());
                self.set(i, Slot::Waiting);
                continue;
            }
            let late = max_ms.is_some_and(|ms| {
                timed && session.clock().monotonic_ms().saturating_sub(start) > ms
            });
            if late || ctx.fuel.is_empty() {
                self.stop = Some((if late { Stop::Time } else { Stop::Fuel }, i));
                self.not_run(i, None);
                self.set(i, Slot::Waiting);
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
                let Some(source) = self.plan.steps.get(r.source) else {
                    continue;
                };
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

/// Ends the transaction of a batch with edits: the roll back of a dry run, or the commit.
/// Sets the mutation of the result.
fn finish(
    session: &mut Session,
    ctx: &mut Ctx,
    batch: Option<BinaryId>,
    dry: bool,
) -> Result<(), ToolError> {
    ctx.mutation = match (batch, dry) {
        (Some(id), true) => {
            let planned = session.batch_planned(id);
            session.batch_rollback(id);
            Some(Mutation {
                tx: None,
                noop: true,
                diff: Some(diff(&planned)),
            })
        }
        (Some(id), false) => {
            let commit = session.batch_commit(id, ctx)?;
            Some(Mutation {
                tx: commit.tx.map(|t| t.to_string()),
                noop: commit.tx.is_none(),
                diff: None,
            })
        }
        (None, true) => Some(Mutation {
            tx: None,
            noop: true,
            diff: Some(Value::Array(Vec::new())),
        }),
        (None, false) => return Ok(()),
    };
    Ok(())
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
    if plan.mutating {
        let error = match (run.failure.clone(), run.stop) {
            (Some(failure), _) => Some(batch_error(&plan, failure)),
            (None, Some((stop, _))) => Some(stop_error(&plan, stop, args)),
            (None, None) => None,
        };
        if let Some(error) = error {
            if let Some(id) = batch {
                session.batch_rollback(id);
            }
            return Err(error);
        }
    }
    finish(session, ctx, batch, args.globals().dry_run)?;
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

//! The inputs and the guards of one step: the resolved references, the bindings of a replay,
//! the `expect` guards and the claim guards.
//!
//! A claim guard calls [`fact_check::check_claim`], the same function as a direct
//! `fact_check` call. So a guard gives the same verdict, and it needs no `fact_check` in the
//! active profile: the `mini` profile has `batch_run` but not `fact_check`.

use ghidorah_analysis::facts::Checker;
use ghidorah_base::ErrorCode;
use ghidorah_json::Value;

use super::{Run, Slot, skipped};
use crate::api::Host;
use crate::args::Globals;
use crate::batch::WHY_LIMIT;
use crate::batch::budget;
use crate::batch::refs::{self, Reference};
use crate::batch::validate::with_step_args;
use crate::dispatch::Ctx;
use crate::errors::{Candidate, ToolError};
use crate::handlers::batch_run::SPEC;
use crate::handlers::fact_check;
use crate::handlers::func_sections::x86_only;
use crate::hints::Call;
use crate::session::Session;

/// The largest size of an actual value in `details.actual` of a guard error.
const MAX_ACTUAL_CHARS: u64 = 512;

/// The verdict of a claim that the batch cannot check.
const UNKNOWN: &str = "unknown";

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

/// Gives the verdict of a `fact_check` verdict entry, or the error code of a claim that does
/// not resolve.
fn verdict_of(entry: &Value) -> String {
    entry
        .get("verdict")
        .or_else(|| entry.pointer("/error/code"))
        .and_then(Value::as_str)
        .unwrap_or(UNKNOWN)
        .to_owned()
}

impl Run<'_> {
    /// Gives the value of reference `r` of step `i` from the bindings of the replay.
    pub(super) fn bound(&self, r: &Reference, i: usize) -> Result<Value, ToolError> {
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
                .map(|b| Candidate::text(&b.ptr, "binding"))
                .collect();
            return Err(ToolError::new(ErrorCode::BadReference)
                .path(&r.path(i))
                .detail("expected", Value::from("a binding of the completed step"))
                .candidates(options));
        };
        refs::check(r, &binding.value, i)?;
        Ok(binding.value.clone())
    }

    /// Gives the error of a `*` reference of step `i` with too many values. When the source
    /// step is a list tool, `next[0]` sends the batch with a limit on the source step.
    fn too_long(&self, r: &Reference, error: ToolError) -> ToolError {
        let cap = r.cap().unwrap_or(0);
        match self
            .plan
            .steps
            .get(r.source)
            .filter(|s| s.tool.list.is_some())
        {
            Some(_) => {
                let batch = with_limit(&self.plan.raw, r.source, cap);
                error.next(Call::new(SPEC.name, batch, WHY_LIMIT))
            }
            None => error,
        }
    }

    /// Gives the resolved arguments of step `i`, or the error of a reference.
    pub(super) fn resolve(&self, i: usize) -> Result<Value, ToolError> {
        let Some(step) = self.plan.steps.get(i) else {
            return Err(ToolError::new(ErrorCode::InternalError));
        };
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
                Err(e) if e.code == ErrorCode::PluckTooLong => return Err(self.too_long(r, e)),
                Err(e) => return Err(e),
            }
        }
        Ok(args)
    }

    /// Checks the claim guards of step `i` on the binary that a direct `fact_check` call
    /// binds now. The claims of the step share one [`Checker`]. Gives the guard index and the
    /// actual verdict of the first claim that is not supported. When no x86-64 binary binds,
    /// the actual value of the first guard is the error code.
    fn claims(
        &self,
        i: usize,
        session: &mut Session,
        ctx: &Ctx,
        binary: Option<&str>,
    ) -> Option<(usize, Value)> {
        let claims = self.plan.steps.get(i).map(|s| s.claims.as_slice());
        let claims = claims.unwrap_or_default();
        if claims.is_empty() {
            return None;
        }
        let globals = Globals {
            binary_id: binary.map(str::to_owned),
            ..Globals::default()
        };
        let frame = session.frame(&fact_check::SPEC, &globals, Some(&ctx.frame.session));
        let open = frame.and_then(|frame| {
            let open = session.bound(&frame)?;
            x86_only(&open.program)?;
            Ok((open, frame.partial()))
        });
        let (open, partial) = match open {
            Ok(found) => found,
            Err(e) => return Some((0, Value::from(e.code.name()))),
        };
        let mut checker = Checker::new(&open.program);
        for (j, claim) in claims.iter().enumerate() {
            let path = format!("/steps/{i}/claim/{j}");
            let entry = fact_check::check_claim(&mut checker, claim, &path, partial);
            let verdict = verdict_of(&entry);
            if verdict != "supported" {
                return Some((j, Value::from(verdict)));
            }
        }
        None
    }

    /// Checks the `expect` guards, then the claim guards, of step `i` against its envelope
    /// `json`. Gives the `EXPECT_FAILED` error of the first guard that fails.
    pub(super) fn guard(
        &self,
        i: usize,
        json: &Value,
        session: &mut Session,
        ctx: &Ctx,
        binary: Option<&str>,
    ) -> Option<ToolError> {
        let expect = self.plan.steps.get(i).map(|s| s.expect.as_slice());
        for (j, g) in expect.unwrap_or_default().iter().enumerate() {
            if let Err(actual) = g.check(json) {
                return Some(
                    ToolError::new(ErrorCode::ExpectFailed)
                        .path(&format!("/steps/{i}/expect/{j}"))
                        .detail("actual", actual_of(actual))
                        .detail("ptr", Value::from(g.ptr.as_str())),
                );
            }
        }
        let (j, verdict) = self.claims(i, session, ctx, binary)?;
        Some(
            ToolError::new(ErrorCode::ExpectFailed)
                .path(&format!("/steps/{i}/claim/{j}"))
                .detail("actual", verdict),
        )
    }
}

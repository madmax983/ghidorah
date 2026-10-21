//! The inputs and the guards of one step: the resolved references, the bindings of a replay,
//! the `expect` guards and the claim guards.
//!
//! A claim guard calls [`fact_check::check_claim`], the same function as a direct
//! `fact_check` call. So a guard gives the same verdict, and it needs no `fact_check` in the
//! active profile: the `mini` profile has `batch_run` but not `fact_check`.

use std::borrow::Cow;

use ghidorah_analysis::facts::Checker;
use ghidorah_base::ErrorCode;
use ghidorah_json::{Object, Value, pointer};

use super::{Run, Slot, skipped};
use crate::api::Host;
use crate::args::Globals;
use crate::batch::WHY_LIMIT;
use crate::batch::budget;
use crate::batch::refs::{self, Reference};
use crate::batch::validate::{Binding, with_step_args};
use crate::dispatch::Ctx;
use crate::errors::ToolError;
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

/// Sets `partial: true` on the reference object at `at` in the step arguments `args`.
fn mark_partial(args: &mut Object, at: &[refs::Part]) {
    let mut root = Value::Object(std::mem::take(args));
    let mut slot = Some(&mut root);
    for part in at {
        slot = match (part, slot) {
            (refs::Part::Key(key), Some(Value::Object(o))) => o.get_mut(key),
            (refs::Part::Index(i), Some(Value::Array(a))) => a.get_mut(*i),
            _ => None,
        };
    }
    if let Some(Value::Object(reference)) = slot {
        let _ = reference.insert("partial", Value::from(true));
    }
    if let Value::Object(o) = root {
        *args = o;
    }
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

/// Sets `value` at the path `tokens` in `root`. A missing object member becomes an object. A
/// path through a scalar or a missing array item leaves `root` as it is.
fn place(root: &mut Value, tokens: &[String], value: Value) {
    let Some((last, parents)) = tokens.split_last() else {
        *root = value;
        return;
    };
    let mut slot = root;
    for token in parents {
        slot = match slot {
            Value::Object(object) => {
                if !object.contains_key(token) {
                    let _ = object.insert(token.as_str(), Value::Object(Object::new()));
                }
                match object.get_mut(token) {
                    Some(child) => child,
                    None => return,
                }
            }
            Value::Array(items) => match token.parse::<usize>().ok().and_then(|i| items.get_mut(i))
            {
                Some(child) => child,
                None => return,
            },
            _ => return,
        };
    }
    match slot {
        Value::Object(object) => {
            let _ = object.insert(last.as_str(), value);
        }
        Value::Array(items) => {
            if let Some(item) = last.parse::<usize>().ok().and_then(|i| items.get_mut(i)) {
                *item = value;
            }
        }
        _ => {}
    }
}

/// Gives the envelope of the completed step `source` in a replay: the value of each binding
/// of the step at its pointer. A binding with `*` has no place, so only its own reference
/// reads it. The bindings with shorter pointers go first.
fn bound_envelope(bindings: &[Binding], source: &str) -> Value {
    let mut placed: Vec<(Vec<String>, &Value)> = bindings
        .iter()
        .filter(|b| b.step == source)
        .filter_map(|b| {
            let parsed = pointer::parse(&b.ptr).ok().filter(|p| !p.has_star())?;
            let tokens = parsed.segments().iter().map(|s| s.token().to_owned());
            Some((tokens.collect(), &b.value))
        })
        .collect();
    placed.sort_by_key(|(tokens, _)| tokens.len());
    let mut root = Value::Object(Object::new());
    for (tokens, value) in placed {
        place(&mut root, &tokens, value.clone());
    }
    root
}

impl Run<'_> {
    /// Gives the bindings of the replay.
    fn bindings(&self) -> &[Binding] {
        self.plan
            .resume
            .as_ref()
            .map(|x| x.bindings.as_slice())
            .unwrap_or_default()
    }

    /// Gives the envelope of step `k` for its references, or `None`. A step that ran gives its
    /// own envelope. A step of a replay gives the envelope of its bindings.
    pub(super) fn source_envelope(&self, k: usize) -> Option<Cow<'_, Value>> {
        match self.slots.get(k) {
            Some(Slot::Done(envelope)) => Some(Cow::Borrowed(envelope)),
            Some(Slot::Resumed) => {
                let id = self.plan.steps.get(k).map_or("", |s| s.id.as_str());
                Some(Cow::Owned(bound_envelope(self.bindings(), id)))
            }
            _ => None,
        }
    }

    /// Gives the value of reference `r` of step `i` from the bindings of the replay.
    ///
    /// The bindings of the source step act as its envelope. So a reference that does not
    /// resolve gives the error of [`refs::resolve`], with the candidates of the bound data.
    /// A binding with the pointer of `r` gives its value, also for a pointer with `*`.
    pub(super) fn bound(&self, r: &Reference, i: usize) -> Result<Value, ToolError> {
        let source = self.plan.steps.get(r.source).map_or("", |s| s.id.as_str());
        let bindings = self.bindings();
        let Some(binding) = bindings.iter().find(|b| b.step == source && b.ptr == r.ptr) else {
            return refs::resolve(r, &bound_envelope(bindings, source), i);
        };
        if refs::check(r, &binding.value, i).is_err() {
            refs::check_in(r, &binding.value, &bound_envelope(bindings, source), i)?;
        }
        Ok(binding.value.clone())
    }

    /// Gives the error of a `*` reference of step `i` with too many values. When the source
    /// step is a list tool, `next[0]` sends the batch with a limit on the source step.
    fn too_long(&self, r: &Reference, step: usize, error: ToolError) -> ToolError {
        let cap = r.cap().unwrap_or(0);
        match self
            .plan
            .steps
            .get(r.source)
            .filter(|s| s.tool.list.is_some())
        {
            Some(_) => {
                let batch = with_limit(&self.plan.raw, r.source, cap);
                // The limit cuts the source page, so the reference must accept a partial page.
                let batch = with_step_args(&batch, step, |args| mark_partial(args, &r.at));
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
                Err(e) if e.code == ErrorCode::PluckTooLong => return Err(self.too_long(r, i, e)),
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

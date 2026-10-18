//! The checks of a whole batch before any step runs (design Section 11.3).
//!
//! The checks run in this order, and the first error stops them:
//!
//! 1. The step count, the step ID grammar and the unique IDs.
//! 2. Each tool: it exists, it can run in a batch, it is in the active profile, and it is
//!    not destructive.
//! 3. The step arguments: no global key of [`STEP_GLOBALS`], references to earlier steps
//!    with a pointer that fits the output shape of the source tool, and arguments that pass
//!    the parser of the tool. A reference counts as a value of its argument kind.
//! 4. The guards, `return`, `on_error`, `label` and `resume`.

use ghidorah_base::{ErrorCode, Fuel, did_you_mean};
use ghidorah_json::pointer::Segment;
use ghidorah_json::{Object, Value};

use super::guards::Guard;
use super::refs::{self, Reference};
use super::shapes;
use super::{
    DESTRUCTIVE, MAX_STEP_ID, NOT_IN_BATCH, OnError, STEP_GLOBALS, WHY_DIRECT, WHY_LIMIT, WHY_TOP,
};
use crate::args::{Args, parse};
use crate::errors::{Candidate, ToolError};
use crate::handlers::batch_run::SPEC;
use crate::hints::{Call, WHY_SCHEMA, WHY_SEARCH};
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use crate::session::Session;
use crate::spec::{Profile, ToolSpec};

/// The fuel of the did-you-mean scan of a tool name.
const DYM_FUEL: u64 = 100_000;

/// The label of a batch with no edit step and no label.
const DEFAULT_LABEL: &str = "batch_run";

/// One checked step.
#[derive(Clone)]
pub struct Step {
    /// The step ID.
    pub(crate) id: String,
    /// The tool.
    pub(crate) tool: &'static ToolSpec<Session>,
    /// The arguments with their references.
    pub(crate) args: Value,
    /// The references of the arguments.
    pub(crate) refs: Vec<Reference>,
    /// The `expect` guards.
    pub(crate) expect: Vec<Guard>,
    /// The `claim` guards: `{ rel, args }` objects.
    pub(crate) claims: Vec<Value>,
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Step")
            .field("id", &self.id)
            .field("tool", &self.tool.name)
            .field("args", &self.args)
            .field("refs", &self.refs)
            .field("expect", &self.expect)
            .field("claims", &self.claims)
            .finish()
    }
}

/// One value of a completed step for a replay (design Section 11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The ID of the completed step.
    pub(crate) step: String,
    /// The pointer of the reference.
    pub(crate) ptr: String,
    /// The value.
    pub(crate) value: Value,
}

/// The replay of a batch that stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    /// The index of the first step that did not complete.
    pub(crate) from: usize,
    /// The values of the references to the completed steps.
    pub(crate) bindings: Vec<Binding>,
}

/// A checked batch: the steps and the run settings.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The steps in run order.
    pub(crate) steps: Vec<Step>,
    /// For each step, `true` when the result holds its data.
    pub(crate) returned: Vec<bool>,
    /// What a read-only batch does after a failed step.
    pub(crate) on_error: OnError,
    /// The label of the transaction.
    pub(crate) label: String,
    /// `true` when a step writes facts.
    pub(crate) mutating: bool,
    /// The replay settings, or `None`.
    pub(crate) resume: Option<Resume>,
    /// The batch arguments with canonical names, the base of repair calls.
    pub(crate) raw: Value,
}

impl Plan {
    /// Gives the step IDs in run order.
    #[must_use]
    pub fn ids(&self) -> Vec<&str> {
        self.steps.iter().map(|s| s.id.as_str()).collect()
    }

    /// Tells if a step writes facts, so the batch is one transaction.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        self.mutating
    }
}

/// Tells if `id` matches `^[a-z][a-z0-9_]{0,15}$`.
fn is_step_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    id.len() <= MAX_STEP_ID
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Gives the `INVALID_ARGUMENT` error at `path` with `details.expected`.
fn invalid(path: &str, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", path.trim_start_matches('/'))
        .path(path)
        .detail("expected", Value::from(expected))
}

/// Gives the batch arguments `raw` with the arguments of step `step` set by `change`.
pub(super) fn with_step_args(raw: &Value, step: usize, change: impl FnOnce(&mut Object)) -> Value {
    let mut out = raw.clone();
    let entry = out
        .as_object_mut()
        .and_then(|o| o.get_mut("steps"))
        .and_then(Value::as_array_mut)
        .and_then(|s| s.get_mut(step))
        .and_then(|s| s.as_object_mut());
    let Some(entry) = entry else {
        return out;
    };
    if entry.get("args").is_none_or(|a| a.as_object().is_none()) {
        let _ = entry.insert("args", Value::Object(Object::new()));
    }
    if let Some(args) = entry.get_mut("args").and_then(Value::as_object_mut) {
        change(args);
    }
    out
}

/// Gives the batch call that repairs step `step` with the direct repair call `call` of its
/// tool, or `None` when `call` names another tool.
///
/// The repair keeps the references of the step and drops the global keys of the batch.
pub(super) fn repair_in_batch(
    raw: &Value,
    step: usize,
    tool: &ToolSpec<Session>,
    refs: &[Reference],
    call: &Call,
) -> Option<Call> {
    if call.tool != tool.name {
        return None;
    }
    let mut fixed = call.args.clone();
    if let Some(object) = fixed.as_object_mut() {
        for key in STEP_GLOBALS {
            let _ = object.remove(key);
        }
    }
    let given = raw
        .pointer(&format!("/steps/{step}/args"))
        .cloned()
        .unwrap_or_default();
    for r in refs {
        if let Some(value) = refs::get_at(&given, &r.at) {
            refs::set_at(&mut fixed, &r.at, value.clone());
        }
    }
    let batch = with_step_args(raw, step, |args| {
        *args = fixed.as_object().cloned().unwrap_or_default();
    });
    Some(Call::new(SPEC.name, batch, &call.why))
}

/// Gives the batch error of a step argument error: the field path below
/// `/steps/N/args`, and a repair call on the batch.
fn step_error(
    error: ToolError,
    raw: &Value,
    step: usize,
    tool: &ToolSpec<Session>,
    refs: &[Reference],
) -> ToolError {
    let inner = error.field_path.clone().unwrap_or_default();
    let path = format!("/steps/{step}/args{inner}");
    let mut out = error;
    out.field_path = Some(path);
    let repair = out
        .next
        .first()
        .and_then(|c| repair_in_batch(raw, step, tool, refs, c));
    out.next.clear();
    if out.code == ErrorCode::MissingArgument {
        let args = Value::object([
            ("name", Value::from(tool.name)),
            ("level", Value::from("full")),
        ]);
        return out.next(Call::new("tool_search", args, WHY_SCHEMA));
    }
    match repair {
        Some(call) => out.next(call),
        None => out,
    }
}

/// Gives the error of a step that names an unknown tool.
fn unknown_tool<S: 'static>(registry: &Registry<S>, name: &str, step: usize) -> ToolError {
    let mut fuel = Fuel::new(DYM_FUEL);
    let names = registry.names();
    let candidates = did_you_mean(name, names.iter().copied(), &mut fuel)
        .into_iter()
        .map(|s| Candidate::text(&s.name, "tool"))
        .collect();
    let query = Value::object([("query", Value::from(name))]);
    ToolError::new(ErrorCode::UnknownTool)
        .var("tool", name)
        .path(&format!("/steps/{step}/tool"))
        .candidates(candidates)
        .next(Call::new("tool_search", query, WHY_SEARCH))
}

/// Tells if step `args` of `tool` names a destructive action, or if the tool is destructive.
/// A selector that a reference gives counts as destructive when an action is destructive.
fn destructive(tool: &ToolSpec<Session>, args: &Value) -> bool {
    if tool.annotations.destructive && tool.actions.is_empty() {
        return true;
    }
    let Some(selector) = tool.selector() else {
        return tool.annotations.destructive;
    };
    match args.get(selector.name) {
        Some(Value::String(value)) => tool.action(value).is_some_and(|a| a.destructive),
        Some(_) => tool.actions.iter().any(|a| a.destructive),
        None => false,
    }
}

/// Gives the error of a destructive step: `next[0]` is the direct call.
fn destructive_error(
    raw: &Value,
    step: usize,
    tool: &ToolSpec<Session>,
    args: &Value,
) -> ToolError {
    let mut direct = args.as_object().cloned().unwrap_or_default();
    for key in ["binary_id", "session"] {
        if let Some(value) = raw.get(key) {
            direct.push(key, value.clone());
        }
    }
    ToolError::new(ErrorCode::ToolNotInProfile)
        .var("tool", tool.name)
        .path(&format!("/steps/{step}/tool"))
        .detail("reason", Value::from(DESTRUCTIVE))
        .next(Call::new(tool.name, Value::Object(direct), WHY_DIRECT))
}

/// Gives the error of a global key in step args: `next[0]` moves it to the top level.
fn global_error(raw: &Value, step: usize, key: &str, value: &Value) -> ToolError {
    let mut batch = with_step_args(raw, step, |args| {
        let _ = args.remove(key);
    });
    if let Some(top) = batch.as_object_mut()
        && !top.contains_key(key)
    {
        top.push(key, value.clone());
    }
    invalid(
        &format!("/steps/{step}/args/{key}"),
        "no global argument in step args: it goes at the top level of the batch",
    )
    .next(Call::new(SPEC.name, batch, WHY_TOP))
}

/// Checks the source limit of a `*` reference into a list with a cap (design Section 11.3).
///
/// Only a literal `limit` above the cap counts. The run checks the other cases.
fn limit_check(r: &Reference, source: &Step, raw: &Value) -> Result<(), ToolError> {
    let Some(cap) = r.cap() else {
        return Ok(());
    };
    let items = [
        Segment::Key("data".to_owned()),
        Segment::Key("items".to_owned()),
        Segment::Star,
    ];
    let direct = r.pointer.segments().get(..3) == Some(&items[..])
        && r.pointer
            .segments()
            .iter()
            .filter(|s| **s == Segment::Star)
            .count()
            == 1;
    let limit = source.args.get("limit").and_then(Value::as_u64);
    let over = limit.is_some_and(|l| u64::try_from(cap).is_ok_and(|c| l > c));
    if !(direct && over && source.tool.list.is_some()) {
        return Ok(());
    }
    let step = r.source;
    let batch = with_step_args(raw, step, |args| {
        let _ = args.insert("limit", Value::from(cap));
    });
    Err(ToolError::new(ErrorCode::LimitExceeded)
        .var("field", &format!("steps/{step}/args/limit"))
        .path(&format!("/steps/{step}/args/limit"))
        .detail("cap", Value::from(cap))
        .next(Call::new(SPEC.name, batch, WHY_LIMIT)))
}

/// Checks one step. `done` holds the checked steps before it.
fn check_step(
    registry: &Registry<Session>,
    profile: &ProfileSet,
    raw: &Value,
    step: usize,
    object: &Value,
    done: &[Step],
) -> Result<Step, ToolError> {
    let id = object.get("id").and_then(Value::as_str).unwrap_or_default();
    if !is_step_id(id) {
        return Err(invalid(
            &format!("/steps/{step}/id"),
            "a step ID: a lower case letter, then up to 15 lower case letters, digits or _",
        ));
    }
    if done.iter().any(|s| s.id == id) {
        return Err(invalid(
            &format!("/steps/{step}/id"),
            "a step ID that no other step has",
        ));
    }
    let name = object
        .get("tool")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some((_, tool)) = registry.get(name) else {
        return Err(unknown_tool(registry, name, step));
    };
    let tool_path = format!("/steps/{step}/tool");
    if NOT_IN_BATCH.contains(&tool.name) {
        return Err(invalid(
            &tool_path,
            "a tool that runs as a batch step. Call this tool directly",
        ));
    }
    let readonly = profile.profile() == Profile::Readonly && tool.mutating;
    if readonly || !profile.holds(registry, tool.name) {
        return Err(ToolError::new(ErrorCode::ToolNotInProfile)
            .var("tool", tool.name)
            .path(&tool_path)
            .detail("reason", Value::from("not_in_profile")));
    }
    let args = object
        .get("args")
        .cloned()
        .unwrap_or_else(|| Value::Object(Object::new()));
    let Some(members) = args.as_object() else {
        return Err(invalid(&format!("/steps/{step}/args"), "a JSON object"));
    };
    if let Some((key, value)) = members.iter().find(|(k, _)| STEP_GLOBALS.contains(k)) {
        return Err(global_error(raw, step, key, value));
    }
    let earlier: Vec<&str> = done.iter().map(|s| s.id.as_str()).collect();
    let found = refs::find(tool, &args, &earlier, step)?;
    if destructive(tool, &args) {
        return Err(destructive_error(raw, step, tool, &args));
    }
    let mut test = args.clone();
    for r in &found {
        let source = done
            .get(r.source)
            .ok_or_else(|| ToolError::new(ErrorCode::BadReference))?;
        refs::typed(r, source.tool, step)?;
        limit_check(r, source, raw)?;
        let sample = r.spec.map_or(Value::Null, |s| shapes::sample(&s.kind));
        refs::set_at(&mut test, &r.at, sample);
    }
    let coerce = |kind: &crate::spec::ArgKind, value: &Value| crate::coerce::lenient(kind, value);
    parse(tool, &test, Some(&coerce)).map_err(|e| step_error(e, raw, step, tool, &found))?;
    let mut expect = Vec::new();
    let guards = object
        .get("expect")
        .and_then(Value::as_array)
        .unwrap_or_default();
    for (j, guard) in guards.iter().enumerate() {
        let parsed =
            Guard::parse(guard).map_err(|e| invalid(&format!("/steps/{step}/expect/{j}"), &e))?;
        expect.push(parsed);
    }
    let claims = object
        .get("claim")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    Ok(Step {
        id: id.to_owned(),
        tool,
        args,
        refs: found,
        expect,
        claims,
    })
}

/// Gives the transaction label: the `label` argument with each byte outside
/// `[A-Za-z0-9._+-]` as `_`, or the tool names of the edit steps joined with `+`.
fn label_of(args: &Args, steps: &[Step]) -> String {
    let text = args.str("label").map_or_else(
        || {
            let mut names: Vec<&str> = Vec::new();
            for step in steps.iter().filter(|s| s.tool.mutating) {
                if !names.contains(&step.tool.name) {
                    names.push(step.tool.name);
                }
            }
            names.join("+")
        },
        str::to_owned,
    );
    let mut out: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(ghidorah_db::tx::MAX_TX_LABEL)
        .collect();
    if out.is_empty() {
        DEFAULT_LABEL.clone_into(&mut out);
    }
    out
}

/// Reads `resume`.
fn resume_of(args: &Args, steps: &[Step], mutating: bool) -> Result<Option<Resume>, ToolError> {
    let Some(value) = args.get("resume") else {
        return Ok(None);
    };
    if mutating {
        return Err(invalid("/resume", "a batch with no edit step"));
    }
    let from = value
        .get("from_step")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(index) = steps.iter().position(|s| s.id == from) else {
        let ids: Vec<Candidate> = steps
            .iter()
            .map(|s| Candidate::text(&s.id, "step"))
            .collect();
        return Err(invalid("/resume/from_step", "the ID of a step of the batch").candidates(ids));
    };
    let bindings = value
        .get("bindings")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|b| Binding {
            step: b
                .get("step")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            ptr: b
                .get("ptr")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            value: b.get("value").cloned().unwrap_or_default(),
        })
        .collect();
    Ok(Some(Resume {
        from: index,
        bindings,
    }))
}

/// Checks the parsed batch arguments `args` before any step runs. `registry` and `profile`
/// give the tools that a step can call.
///
/// # Errors
///
/// Returns the first error of the module rules. Its field path starts with `/steps/N` for
/// an error of step `N`.
pub fn check(
    registry: &Registry<Session>,
    profile: &ProfileSet,
    args: &Args,
) -> Result<Plan, ToolError> {
    let raw = args.canonical().clone();
    let list = args.list("steps").unwrap_or_default();
    if list.is_empty() {
        return Err(invalid("/steps", "1 to 32 steps"));
    }
    let mut steps: Vec<Step> = Vec::with_capacity(list.len());
    for (i, object) in list.iter().enumerate() {
        let step = check_step(registry, profile, &raw, i, object, &steps)?;
        steps.push(step);
    }
    let mut returned = vec![false; steps.len()];
    match args.list("return") {
        Some(ids) => {
            for (j, id) in ids.iter().enumerate() {
                let found = id
                    .as_str()
                    .and_then(|id| steps.iter().position(|s| s.id == id));
                let Some(index) = found else {
                    let options: Vec<Candidate> = steps
                        .iter()
                        .map(|s| Candidate::text(&s.id, "step"))
                        .collect();
                    return Err(
                        invalid(&format!("/return/{j}"), "the ID of a step of the batch")
                            .candidates(options),
                    );
                };
                if let Some(slot) = returned.get_mut(index) {
                    *slot = true;
                }
            }
        }
        None => {
            if let Some(last) = returned.last_mut() {
                *last = true;
            }
        }
    }
    let mutating = steps.iter().any(|s| s.tool.mutating);
    let on_error = match (mutating, args.str("on_error")) {
        (false, Some("stop")) | (true, _) => OnError::Stop,
        _ => OnError::Continue,
    };
    let resume = resume_of(args, &steps, mutating)?;
    Ok(Plan {
        label: label_of(args, &steps),
        steps,
        returned,
        on_error,
        mutating,
        resume,
        raw,
    })
}

/// Checks the batch arguments `raw` before any step runs. `registry` and `profile` give the
/// tools that a step can call.
///
/// # Errors
///
/// Returns the error of the argument parser of `batch_run`, or the first error of the module
/// rules. Its field path starts with `/steps/N` for an error of step `N`.
pub fn plan(
    registry: &Registry<Session>,
    profile: &ProfileSet,
    raw: &Value,
) -> Result<Plan, ToolError> {
    let coerce = |kind: &crate::spec::ArgKind, value: &Value| crate::coerce::lenient(kind, value);
    let parsed = parse(&SPEC, raw, Some(&coerce))?;
    check(registry, profile, &parsed.args)
}

//! The dispatcher pipeline (design Sections 10.6 and 10.9, ADR-0021).
//!
//! One call runs these steps in order:
//!
//! 1. Find the tool (`UNKNOWN_TOOL`) and check the profile (`TOOL_NOT_IN_PROFILE`).
//! 2. Parse the arguments ([`crate::args::parse`]).
//! 3. Open the frame through the host: binary, rev, session label and analysis state.
//! 4. Check `expected_rev` of a mutating tool (`CONFLICT`).
//! 5. Run the handler under `catch_unwind`. A panic gives `INTERNAL_ERROR` with a `crash_id`.
//! 6. Shape a list: `in` filter, cursor, `count_only`, `limit`, `fields`, `shape`.
//! 7. Trim the items to the budget (kernel K6) and set `page`.
//! 8. Keep the valid hints, at most 3, and wrap the envelope.
//!
//! The handler returns full data. It never trims its own output.

mod list;

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use ghidorah_base::{ErrorCode, Fnv1a64, Fuel, did_you_mean, hex};
use ghidorah_json::{Object, Value};

use crate::api::{Host, Progress, Request};
use crate::args::{self, Args, Format, Globals};
use crate::budget::Budget;
use crate::content::result_chars;
use crate::envelope::{Body, Envelope, Frame, Mutation, Warning};
use crate::errors::{Candidate, ToolError, int};
use crate::hints::{
    Call, WHY_ANALYSIS, WHY_BRIEF, WHY_FIRST_PAGE, WHY_REV, WHY_SCHEMA, WHY_SEARCH, check,
    keep_valid,
};
use crate::registry::Registry;
use crate::spec::{ArgKind, ToolSpec};

/// One part of a sort key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyPart {
    /// A number, for example an address or a size.
    Int(u64),
    /// A text, for example a name or an ID.
    Text(String),
}

/// The keyset sort key of one list item (design Section 10.9).
///
/// Keys compare part by part. Each item of a list has a unique key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SortKey(pub Vec<KeyPart>);

/// One list item with its sort key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The sort key.
    pub key: SortKey,
    /// The item object.
    pub value: Value,
}

/// The total of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Total {
    /// The pipeline counts the items that the handler gives.
    Items,
    /// The exact total.
    Exact(u64),
    /// A lower bound: a full count costs more fuel than the budget.
    AtLeast(u64),
}

/// The list data of a list tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPayload {
    /// All items in sort order. The pipeline pages and trims them.
    pub items: Vec<Item>,
    /// The total.
    pub total: Total,
    /// The other members of `data`, after `items`, for example `basis` or `edges`.
    pub extra: Object,
    /// A hint that names the filter arguments that narrow the list.
    pub narrow: Option<String>,
}

impl ListPayload {
    /// Makes a list of `items` with no extra members and no narrowing hint.
    #[must_use]
    pub const fn new(items: Vec<Item>) -> Self {
        Self {
            items,
            total: Total::Items,
            extra: Object::new(),
            narrow: None,
        }
    }
}

/// The data that a handler returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// An object result. The pipeline projects it with `fields`. It must fit the budget.
    Object(Object),
    /// A list result.
    List(ListPayload),
}

/// The members of a named set (design Section 10.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Members {
    /// The member IDs, for example `fn:0x401000`.
    pub ids: BTreeSet<String>,
    /// The member address ranges `(start, end)` with `end` exclusive.
    pub ranges: Vec<(u64, u64)>,
}

impl Members {
    /// Tells if a list item is a member: its `id` is in the set, or its `addr` is in a range.
    #[must_use]
    pub fn holds(&self, item: &Value) -> bool {
        if item
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| self.ids.contains(id))
        {
            return true;
        }
        item.get("addr")
            .and_then(Value::as_str)
            .and_then(hex::parse_u64)
            .is_some_and(|a| self.ranges.iter().any(|(s, e)| *s <= a && a < *e))
    }
}

/// What the host needs to encode or decode a cursor.
#[derive(Debug, Clone, Copy)]
pub struct CursorCall<'a> {
    /// The index of the tool in the registry.
    pub tool_index: usize,
    /// The tool name.
    pub tool: &'static str,
    /// The parsed arguments.
    pub args: &'a Args,
    /// The frame of the call.
    pub frame: &'a Frame,
}

/// The facts of a handler panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    /// The crash ID: 16 hex digits of FNV-1a over the tool, the arguments and the panic text.
    pub id: String,
    /// The tool name.
    pub tool: String,
    /// The JCS text of the arguments.
    pub args: String,
    /// The panic text.
    pub panic: String,
}

impl Crash {
    /// Makes the crash facts of one panic.
    fn new(tool: &str, args: &Value, panic: String) -> Self {
        let args = ghidorah_json::write_jcs(args).unwrap_or_else(|_| ghidorah_json::write(args));
        let mut hash = Fnv1a64::new();
        for part in [tool, args.as_str(), panic.as_str()] {
            hash.write(part.as_bytes());
            hash.write_u8(0);
        }
        Self {
            id: format!("{:016x}", hash.finish()),
            tool: tool.to_owned(),
            args,
            panic,
        }
    }
}

/// The context of one handler call.
#[derive(Debug)]
pub struct Ctx {
    /// The output format.
    pub format: Format,
    /// The frame. A handler that commits sets the new rev and analysis state here.
    pub frame: Frame,
    /// The fuel of the call: `max_steps` or the default of the tool.
    pub fuel: Fuel,
    /// The `max_ms` guard of the call.
    pub max_ms: Option<u64>,
    /// The output budget of the call.
    pub budget: Budget,
    /// The warnings of the call.
    pub warnings: Vec<Warning>,
    /// The `next` calls of the handler, in order.
    pub next: Vec<Call>,
    /// The edit members of a mutating call.
    pub mutation: Option<Mutation>,
    cancel: Option<Arc<AtomicBool>>,
    progress: Option<Sender<Progress>>,
}

impl Ctx {
    /// Makes a context. The dispatcher calls it. Tests of handlers can call it too.
    #[must_use]
    pub fn new(frame: Frame, fuel: Fuel, budget: Budget) -> Self {
        Self {
            format: Format::Concise,
            frame,
            fuel,
            max_ms: None,
            budget,
            warnings: Vec::new(),
            next: Vec::new(),
            mutation: None,
            cancel: None,
            progress: None,
        }
    }

    /// Tells if the client cancelled the request. Long work checks it at fuel checkpoints.
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    /// Sends a progress report. A closed channel drops the report.
    pub fn progress(&self, report: Progress) {
        if let Some(sender) = &self.progress {
            let _ = sender.send(report);
        }
    }

    /// Adds a warning.
    pub fn warn(&mut self, warning: Warning) {
        self.warnings.push(warning);
    }

    /// Adds a `next` call.
    pub fn hint(&mut self, call: Call) {
        self.next.push(call);
    }
}

/// The parts of one call that the shaping steps share.
struct Call0<'a, S: Host> {
    registry: &'a Registry<S>,
    tool: &'static ToolSpec<S>,
    index: usize,
    args: &'a Args,
    request: &'a Request,
}

/// Gives the request arguments with `key` set to `value`, or removed for `None`.
fn with_arg(args: &Value, key: &str, value: Option<Value>) -> Value {
    let mut object = args.as_object().cloned().unwrap_or_default();
    let _ = object.remove(key);
    if let Some(value) = value {
        object.push(key, value);
    }
    Value::Object(object)
}

/// Gives the failure envelope of `error`, with helper calls for the codes of class H.
fn failure<S: Host>(
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
    Envelope {
        frame,
        body: Body::Err(error.to_json()),
        next: keep_valid(registry, &|name| host.in_profile(name), next),
    }
}

/// Gives the panic text of a panic payload.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "the handler panicked".to_owned())
}

/// Runs one request through `registry` on `host`.
pub(crate) fn run<S: Host>(registry: &Registry<S>, host: &mut S, request: &Request) -> Envelope {
    let bare = Frame {
        session: request.session.clone().unwrap_or_default(),
        ..Frame::default()
    };
    let Some((index, tool)) = registry.get(&request.tool) else {
        let mut fuel = Fuel::new(1_000_000);
        let names = registry.names();
        let candidates = did_you_mean(&request.tool, names.iter().copied(), &mut fuel)
            .into_iter()
            .map(|s| Candidate::text(&s.name, "tool"))
            .collect();
        let error = ToolError::new(ErrorCode::UnknownTool)
            .var("tool", &request.tool)
            .candidates(candidates);
        return failure(registry, host, bare, &request.tool, &error);
    };
    if !host.in_profile(tool.name) {
        let error = ToolError::new(ErrorCode::ToolNotInProfile)
            .var("tool", tool.name)
            .detail("reason", Value::from("not_in_profile"));
        return failure(registry, host, bare, tool.name, &error);
    }
    let coerce = |kind: &ArgKind, value: &Value| host.coerce(kind, value);
    let parsed = match args::parse(tool, &request.args, Some(&coerce)) {
        Ok(parsed) => parsed,
        Err(error) => {
            let session = request.session.as_deref();
            let frame = host
                .frame(tool, &Globals::default(), session)
                .unwrap_or(bare);
            return failure(registry, host, frame, tool.name, &error);
        }
    };
    let globals = parsed.args.globals();
    let frame = match host.frame(tool, globals, request.session.as_deref()) {
        Ok(frame) => frame,
        Err(error) => return failure(registry, host, bare, tool.name, &error),
    };
    if let (true, Some(expected)) = (tool.mutating, globals.expected_rev)
        && expected != frame.rev
    {
        let args = with_arg(&request.args, "expected_rev", Some(int(frame.rev)));
        let error = ToolError::new(ErrorCode::Conflict)
            .detail("current_rev", int(frame.rev))
            .next(Call::new(tool.name, args, WHY_REV));
        return failure(registry, host, frame, tool.name, &error);
    }
    let max_chars = globals.max_chars.unwrap_or(tool.max_chars);
    let fuel = globals
        .max_steps
        .or_else(|| tool.fuel.map(|f| f.default))
        .map_or_else(Fuel::unlimited, Fuel::new);
    let mut ctx = Ctx::new(
        frame,
        fuel,
        Budget::new(u64::from(max_chars), request.content),
    );
    ctx.format = globals.format;
    ctx.max_ms = globals.max_ms;
    ctx.warnings = parsed.warnings;
    ctx.cancel.clone_from(&request.cancel);
    ctx.progress.clone_from(&request.progress);
    let result = catch_unwind(AssertUnwindSafe(|| {
        (tool.handler)(host, &parsed.args, &mut ctx)
    }));
    let call = Call0 {
        registry,
        tool,
        index,
        args: &parsed.args,
        request,
    };
    match result {
        Ok(Ok(payload)) => success(&call, host, ctx, payload),
        Ok(Err(error)) => failure(registry, host, ctx.frame, tool.name, &error),
        Err(payload) => {
            let crash = Crash::new(tool.name, &request.args, panic_text(payload.as_ref()));
            host.on_panic(&crash);
            let mut error = ToolError::new(ErrorCode::InternalError);
            error.crash_id = Some(crash.id);
            failure(registry, host, ctx.frame, tool.name, &error)
        }
    }
}

/// Gives the valid `next` calls and warnings of a success.
fn hints<S: Host>(call: &Call0<'_, S>, host: &S, ctx: &mut Ctx) -> Vec<Call> {
    let in_profile = |name: &str| host.in_profile(name);
    let mut next = std::mem::take(&mut ctx.next);
    if ctx.frame.partial() && call.tool.name != "analysis_run" {
        next.push(Call::new(
            "analysis_run",
            Value::Object(Object::new()),
            WHY_ANALYSIS,
        ));
    }
    for warning in &mut ctx.warnings {
        if warning
            .remedy
            .as_ref()
            .is_some_and(|r| check(call.registry, &in_profile, r).is_err())
        {
            warning.remedy = None;
        }
    }
    keep_valid(call.registry, &in_profile, next)
}

/// Wraps a handler payload into the success envelope.
fn success<S: Host>(call: &Call0<'_, S>, host: &S, mut ctx: Ctx, payload: Payload) -> Envelope {
    let next = hints(call, host, &mut ctx);
    let fields = &call.args.globals().fields;
    match payload {
        Payload::Object(object) => {
            let data = if fields.is_empty() {
                Value::Object(object)
            } else {
                list::project(&Value::Object(object), fields)
            };
            let envelope = Envelope {
                frame: ctx.frame.clone(),
                body: Body::Ok {
                    data,
                    page: None,
                    warnings: ctx.warnings.clone(),
                    mutation: ctx.mutation.clone(),
                },
                next,
            };
            fit_or_fail(call, host, &ctx, envelope)
        }
        Payload::List(list) => match list::shape(call, host, &ctx, list, &next) {
            Ok(envelope) => envelope,
            Err(error) => failure(call.registry, host, ctx.frame, call.tool.name, &error),
        },
    }
}

/// Gives `envelope` when it fits the budget, else an `OUTPUT_BUDGET_EXCEEDED` failure.
fn fit_or_fail<S: Host>(call: &Call0<'_, S>, host: &S, ctx: &Ctx, envelope: Envelope) -> Envelope {
    let size = result_chars(&envelope.to_json(), false, ctx.budget.mode);
    if size <= ctx.budget.limit() {
        envelope
    } else {
        let error = ToolError::new(ErrorCode::OutputBudgetExceeded)
            .detail("chars", int(size))
            .detail("limit", int(ctx.budget.limit()));
        failure(
            call.registry,
            host,
            ctx.frame.clone(),
            call.tool.name,
            &error,
        )
    }
}

/// Gives the repair call of a cursor error: the call without `cursor`.
fn first_page<S: Host>(call: &Call0<'_, S>, error: ToolError) -> ToolError {
    if error.next.is_empty() {
        let args = with_arg(&call.request.args, "cursor", None);
        error.next(Call::new(call.tool.name, args, WHY_FIRST_PAGE))
    } else {
        error
    }
}

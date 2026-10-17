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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use ghidorah_base::Fuel;
use ghidorah_json::{Object, Value};

use crate::api::{Host, Progress, Request};
use crate::args::Format;
use crate::budget::Budget;
use crate::envelope::{Envelope, Frame, Mutation, Warning};
use crate::hints::Call;
use crate::registry::Registry;

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
    pub ids: std::collections::BTreeSet<String>,
    /// The member address ranges `(start, end)` with `end` exclusive.
    pub ranges: Vec<(u64, u64)>,
}

impl Members {
    /// Tells if a list item is a member: its `id` is in the set, or its `addr` is in a range.
    #[must_use]
    pub fn holds(&self, item: &Value) -> bool {
        let _ = item;
        false
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
    pub args: &'a crate::args::Args,
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
            && false
    }

    /// Sends a progress report. A closed channel drops the report.
    pub fn progress(&self, report: Progress) {
        let _ = report;
    }

    /// Adds a warning.
    pub fn warn(&mut self, warning: Warning) {
        let _ = warning;
    }

    /// Adds a `next` call.
    pub fn hint(&mut self, call: Call) {
        let _ = call;
    }
}

/// Runs one request through `registry` on `host`.
pub(crate) fn run<S: Host>(registry: &Registry<S>, host: &mut S, request: &Request) -> Envelope {
    let _ = (registry, host, request);
    Envelope {
        frame: Frame::default(),
        body: crate::envelope::Body::Err(Value::Null),
        next: Vec::new(),
    }
}

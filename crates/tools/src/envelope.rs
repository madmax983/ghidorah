//! The result envelope (design Section 10.6, ADR-0021).
//!
//! A success envelope has the members `ok, binary_id?, rev, session, analysis?, partial, data,
//! page?, warnings?, next?, tx?, noop?, diff?` in this order. A failure envelope has
//! `ok, binary_id?, rev, session, error, next?`. Empty `warnings` and `next` lists are absent.

use ghidorah_base::WarningCode;
use ghidorah_json::{Object, Value};

use crate::hints::Call;

/// The analysis state of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnalysisState {
    /// The analysis is complete.
    Complete,
    /// The analysis stopped on its fuel budget.
    BudgetStopped,
    /// An edit made the analysis stale, and a re-analysis is due.
    Stale,
}

impl AnalysisState {
    /// Gives the state name: `complete`, `budget_stopped` or `stale`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::BudgetStopped => "budget_stopped",
            Self::Stale => "stale",
        }
    }
}

/// The analysis member of an envelope: `{ state, rev }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisInfo {
    /// The state.
    pub state: AnalysisState,
    /// The rev of the last analysis run.
    pub rev: u64,
}

/// The frame of one call: what the envelope tells about the session and the binary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    /// The bound binary, or `None`.
    pub binary_id: Option<String>,
    /// The rev of the bound binary, or 0 with no binary.
    pub rev: u64,
    /// The session label.
    pub session: String,
    /// The analysis state of the bound binary, or `None`.
    pub analysis: Option<AnalysisInfo>,
}

impl Frame {
    /// Tells if the result is partial: the analysis state is not `complete`.
    #[must_use]
    pub fn partial(&self) -> bool {
        false
    }
}

/// One warning: `{ code, num, at?, message, remedy?, details? }`.
///
/// The message is the catalog text of the code. `details` exists only in `detailed` format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// The code.
    pub code: WarningCode,
    /// The place that the warning is about: an address, an ID or an argument pointer.
    pub at: Option<String>,
    /// The complete call that fixes the cause.
    pub remedy: Option<Call>,
    /// More facts for the `detailed` format, for example `{ from, to }` of a coercion.
    pub details: Option<Object>,
}

impl Warning {
    /// Makes a warning with no place, remedy or details.
    #[must_use]
    pub const fn new(code: WarningCode) -> Self {
        Self {
            code,
            at: None,
            remedy: None,
            details: None,
        }
    }

    /// Gives the JSON form of the warning.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

/// The `page` member of a list result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    /// The number of returned items.
    pub returned: u64,
    /// The total number of items, or a lower bound of it.
    pub total: u64,
    /// `true` when `total` is a lower bound. The member is then `total_lower_bound`.
    pub lower_bound: bool,
    /// `true` when more items follow the returned items.
    pub truncated: bool,
    /// The cursor of the next page.
    pub next_cursor: Option<String>,
    /// A hint that names filter arguments to narrow the list.
    pub hint: Option<String>,
}

impl Page {
    /// Gives the JSON form `{ returned, total | total_lower_bound, truncated, next_cursor?, hint? }`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

/// The edit members of a mutating result: `tx`, `noop` and `diff`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mutation {
    /// The transaction ID of the commit, for example `tx:12`.
    pub tx: Option<String>,
    /// `true` when the call changed no fact.
    pub noop: bool,
    /// The planned edit list of a dry run: `[{ op, key, old, new }]`.
    pub diff: Option<Value>,
}

/// One result envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The frame of the call.
    pub frame: Frame,
    /// The success body, or the error object of a failure.
    pub body: Body,
    /// The `next` calls: at most 3, each one valid.
    pub next: Vec<Call>,
}

/// The body of an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// A success.
    Ok {
        /// The `data` member.
        data: Value,
        /// The `page` member of a list result.
        page: Option<Page>,
        /// The warnings.
        warnings: Vec<Warning>,
        /// The edit members of a mutating result.
        mutation: Option<Mutation>,
    },
    /// A failure with its error object.
    Err(Value),
}

impl Envelope {
    /// Tells if the envelope is a success.
    #[must_use]
    pub const fn ok(&self) -> bool {
        false
    }

    /// Gives the JSON form of the envelope.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

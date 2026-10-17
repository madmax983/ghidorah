//! The result envelope (design Section 10.6, ADR-0021).
//!
//! A success envelope has the members `ok, binary_id?, rev, session, analysis?, partial, data,
//! page?, warnings?, next?, tx?, noop?, diff?` in this order. A failure envelope has
//! `ok, binary_id?, rev, session, error, next?`. Empty `warnings` and `next` lists are absent.

use ghidorah_base::WarningCode;
use ghidorah_json::{Object, Value};

use crate::errors::int;
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
        self.analysis
            .is_some_and(|a| a.state != AnalysisState::Complete)
    }

    /// Writes the frame members `binary_id?, rev, session, analysis?` into `out`.
    fn write(&self, out: &mut Object, with_analysis: bool) {
        if let Some(id) = &self.binary_id {
            out.push("binary_id", Value::from(id.as_str()));
        }
        out.push("rev", int(self.rev));
        out.push("session", Value::from(self.session.as_str()));
        if let (Some(a), true) = (self.analysis, with_analysis) {
            out.push(
                "analysis",
                Value::object([
                    ("state", Value::from(a.state.as_str())),
                    ("rev", int(a.rev)),
                ]),
            );
        }
    }
}

/// One warning: `{ code, num, at?, field?, message, remedy?, details? }`.
///
/// The message is the catalog text of the code. `details` exists only in `detailed` format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// The code.
    pub code: WarningCode,
    /// The address or the ID that the warning is about.
    pub at: Option<String>,
    /// The JSON pointer of the argument that the warning is about, for example `/count`.
    pub field: Option<String>,
    /// The complete call that fixes the cause.
    pub remedy: Option<Call>,
    /// More facts for the `detailed` format, for example the types of a coercion.
    pub details: Option<Object>,
}

impl Warning {
    /// Makes a warning with no place, remedy or details.
    #[must_use]
    pub const fn new(code: WarningCode) -> Self {
        Self {
            code,
            at: None,
            field: None,
            remedy: None,
            details: None,
        }
    }

    /// Gives the JSON form of the warning.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let info = self.code.info();
        let mut out = Object::new();
        out.push("code", Value::from(info.name));
        out.push("num", int(u64::from(info.num)));
        if let Some(at) = &self.at {
            out.push("at", Value::from(at.as_str()));
        }
        if let Some(field) = &self.field {
            out.push("field", Value::from(field.as_str()));
        }
        out.push("message", Value::from(info.message));
        if let Some(remedy) = &self.remedy {
            out.push("remedy", remedy.to_json());
        }
        if let Some(details) = &self.details {
            out.push("details", Value::Object(details.clone()));
        }
        Value::Object(out)
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
        let mut out = Object::new();
        out.push("returned", int(self.returned));
        let total = if self.lower_bound {
            "total_lower_bound"
        } else {
            "total"
        };
        out.push(total, int(self.total));
        out.push("truncated", Value::Bool(self.truncated));
        if let Some(cursor) = &self.next_cursor {
            out.push("next_cursor", Value::from(cursor.as_str()));
        }
        if let Some(hint) = &self.hint {
            out.push("hint", Value::from(hint.as_str()));
        }
        Value::Object(out)
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
        matches!(self.body, Body::Ok { .. })
    }

    /// Gives the JSON form of the envelope.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut out = Object::new();
        out.push("ok", Value::Bool(self.ok()));
        match &self.body {
            Body::Ok {
                data,
                page,
                warnings,
                mutation,
            } => {
                self.frame.write(&mut out, true);
                out.push("partial", Value::Bool(self.frame.partial()));
                out.push("data", data.clone());
                if let Some(page) = page {
                    out.push("page", page.to_json());
                }
                if !warnings.is_empty() {
                    out.push(
                        "warnings",
                        Value::Array(warnings.iter().map(Warning::to_json).collect()),
                    );
                }
                self.write_next(&mut out);
                if let Some(m) = mutation {
                    if let Some(tx) = &m.tx {
                        out.push("tx", Value::from(tx.as_str()));
                    }
                    out.push("noop", Value::Bool(m.noop));
                    if let Some(diff) = &m.diff {
                        out.push("diff", diff.clone());
                    }
                }
            }
            Body::Err(error) => {
                self.frame.write(&mut out, false);
                out.push("error", error.clone());
                self.write_next(&mut out);
            }
        }
        Value::Object(out)
    }

    fn write_next(&self, out: &mut Object) {
        if !self.next.is_empty() {
            out.push(
                "next",
                Value::Array(self.next.iter().map(Call::to_json).collect()),
            );
        }
    }
}

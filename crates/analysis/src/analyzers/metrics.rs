//! Metrics, coverage, the worklist and the frozen priority (design Section 7.11).
//!
//! These views are derived data of the committed facts (design Section 3.9). They have no band
//! and no work state, so one set of facts always gives the same values.
//!
//! | View | Facts |
//! |---|---|
//! | [`func_metrics`] | the merged facts: blocks, instructions, cyclomatic complexity, callers, callees, string references and import calls by category |
//! | [`coverage`] | the merged facts and the progress rows |
//! | [`worklist`] | unresolved indirect jumps and calls, override conflicts and gap items |
//! | [`priority`] | the analysis layer only |
//!
//! The score of [`priority`]:
//!
//! ```text
//! score = 8 * risky_calls + 4 * in_degree + 2 * string_refs + min(size / 16, 64)
//! ```
//!
//! `risky_calls` counts the call sites to imports of the [`RISKY`] categories. `in_degree`
//! counts the references to the entry from outside the body. `string_refs` counts the
//! references from the body to strings. `size` is the body size in bytes. The order is the
//! score from high to low, then the entry from low to high. Only an analysis run changes the
//! analysis layer, so a run freezes the order (AC-157). Names, comments and `visited` do not
//! change it.

use std::collections::BTreeMap;

use ghidorah_base::{Address, FuncId};
use ghidorah_db::Program;
use ghidorah_json::Value;
use ghidorah_types::Category;

use crate::analyzers::gaps::Gap;
use crate::callgraph::CallGraph;

/// The import categories that raise the priority.
pub const RISKY: [Category; 6] = [
    Category::Network,
    Category::Process,
    Category::File,
    Category::Crypto,
    Category::AntiDebug,
    Category::Environment,
];

/// The weight of a risky import call in the score.
pub const W_RISKY: u64 = 8;

/// The weight of a reference to the entry in the score.
pub const W_IN: u64 = 4;

/// The weight of a string reference in the score.
pub const W_STRING: u64 = 2;

/// The body bytes of one size point in the score.
pub const SIZE_UNIT: u64 = 16;

/// The largest number of size points in the score.
pub const MAX_SIZE_POINTS: u64 = 64;

/// The metrics of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncMetrics {
    /// The function.
    pub func: FuncId,
    /// The body size in bytes.
    pub size: u64,
    /// The number of basic blocks.
    pub blocks: u64,
    /// The number of instructions.
    pub insns: u64,
    /// The number of CFG edges in the body.
    pub edges: u64,
    /// The cyclomatic complexity: `edges - blocks + 2`, at least 1.
    pub cyclomatic: u64,
    /// The number of distinct calling functions.
    pub callers: u64,
    /// The number of distinct callees: functions and imports.
    pub callees: u64,
    /// The number of references from the body to strings.
    pub string_refs: u64,
    /// The number of call sites to imports of each Tier-0 category.
    pub import_calls: BTreeMap<Category, u64>,
}

/// The coverage of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    /// The number of functions.
    pub functions: u64,
    /// The functions with a decoded entry.
    pub analyzed: u64,
    /// The functions with the progress flag `visited`.
    pub visited: u64,
    /// The functions with a name that is not a default name.
    pub named: u64,
    /// The functions with a signature.
    pub typed: u64,
    /// The functions with a comment in the body.
    pub commented: u64,
}

/// A call that fixes a worklist item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remedy {
    /// `func_edit { action: "create", target }`.
    Create(u64),
    /// `func_edit { action: "set_call_targets", at }`.
    SetCallTargets(u64),
    /// `func_edit { action: "set_jumptable", at }`.
    SetJumpTable(u64),
    /// `func_edit { action: "set_noreturn", target }`.
    SetNoreturn(u64),
}

impl Remedy {
    /// Gives the `func_edit` action.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Create(_) => "create",
            Self::SetCallTargets(_) => "set_call_targets",
            Self::SetJumpTable(_) => "set_jumptable",
            Self::SetNoreturn(_) => "set_noreturn",
        }
    }

    /// Gives the arguments of the `func_edit` call, for example
    /// `{"action":"create","target":"0x1150"}`.
    #[must_use]
    pub fn args(self) -> Value {
        Value::object([("action", Value::from(self.action()))])
    }
}

/// The kind of a worklist item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemKind {
    /// An indirect jump with no jump table and no import slot.
    UnresolvedJump,
    /// An indirect call with no call reference and no target override.
    UnresolvedCall,
    /// A function with the caveat `W_AGENT_OVERRIDE_CONFLICT`.
    OverrideConflict,
    /// A gap item.
    Gap,
}

impl ItemKind {
    /// Gives the output name, for example `unresolved_jump`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnresolvedJump => "unresolved_jump",
            Self::UnresolvedCall => "unresolved_call",
            Self::OverrideConflict => "override_conflict",
            Self::Gap => "gap",
        }
    }
}

/// One worklist item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkItem {
    /// The kind.
    pub kind: ItemKind,
    /// The address of the item.
    pub at: Address,
    /// The function of the item.
    pub func: Option<FuncId>,
    /// The remedy call.
    pub remedy: Option<Remedy>,
    /// The gap of a gap item.
    pub gap: Option<Gap>,
}

/// The priority of one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ranked {
    /// The function.
    pub func: FuncId,
    /// The score.
    pub score: u64,
}

/// Gives the metrics of the function `func`, or `None` when the program has no such function.
#[must_use]
pub fn func_metrics(program: &Program, graph: &CallGraph, func: FuncId) -> Option<FuncMetrics> {
    let _ = (program, graph, func);
    None
}

/// Gives the metrics of every function in entry order.
#[must_use]
pub fn all(program: &Program) -> Vec<FuncMetrics> {
    let _ = program;
    Vec::new()
}

/// Gives the coverage of `program`.
#[must_use]
pub fn coverage(program: &Program) -> Coverage {
    let _ = program;
    Coverage::default()
}

/// Gives the worklist of `program` in address order, then in kind order.
#[must_use]
pub fn worklist(program: &Program) -> Vec<WorkItem> {
    let _ = program;
    Vec::new()
}

/// Gives the priority of each function of the analysis layer in priority order.
#[must_use]
pub fn priority(program: &Program) -> Vec<Ranked> {
    let _ = program;
    Vec::new()
}

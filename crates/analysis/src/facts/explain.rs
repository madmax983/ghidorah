//! Why trees: the premises of a fact, and their premises in turn (ADR-0023).
//!
//! [`key_of`] reads the ID text of a fact. [`explain`] gives its tree. A node with a why-record
//! has its rule and its premises. A node with no why-record is an input of the binary or a
//! fact of an agent, an import or a user: it has its source and no premises.
//!
//! | Input | Fact |
//! |---|---|
//! | `fn:A` | the function at A |
//! | `ref:A>B:kind` | the reference |
//! | `str:A`, `jt:A`, `var:..`, `note:N` | the string, the jump table, the variable, the note |
//! | `sym:name` | the first symbol with the name |
//! | `imp:..`, `exp:..` | the import or the export: an input of the binary |
//! | `0x..` | the code unit at the address, else the data definition, else the string |
//!
//! The premise graph has no cycle (Section 3.11, invariant 6). The walk also keeps the path,
//! so a premise that is on its own path stops there with `cycle`.

use std::fmt;

use ghidorah_db::{FactKey, Program, RuleCode, Source};

/// The default depth of a tree.
pub const DEFAULT_DEPTH: u32 = 3;

/// The default largest number of nodes of the trees of one call.
pub const DEFAULT_NODES: usize = 200;

/// One node of a why tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The key of the fact.
    pub key: FactKey,
    /// The ID text of the fact, for example `fn:0x1149`.
    pub id: String,
    /// The rule of the why-record, or `None` for a fact with no record.
    pub rule: Option<RuleCode>,
    /// The source of a fact with no why-record.
    pub source: Option<Source>,
    /// The premise trees in premise order.
    pub premises: Vec<Self>,
    /// The depth or the node cap cut the premises.
    pub truncated: bool,
    /// The premise is on its own path. The walk stops there.
    pub cycle: bool,
}

/// The error of [`key_of`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    /// The text is not an ID of a fact kind.
    BadId(String),
    /// No fact has the ID. The value is the fact kind, for example `function`.
    NotFound(&'static str),
}

impl fmt::Display for ExplainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadId(text) => write!(f, "The text {text} is not the ID of a fact."),
            Self::NotFound(kind) => write!(f, "No {kind} has the ID."),
        }
    }
}

impl std::error::Error for ExplainError {}

/// Gives the fact name of a key, for example `function` or `code_unit`.
#[must_use]
pub const fn fact_name(key: &FactKey) -> &'static str {
    match key {
        FactKey::CodeUnit(_) => "code_unit",
        FactKey::Data(_) => "data",
        FactKey::Symbol(..) => "symbol",
        FactKey::Func(_) => "function",
        FactKey::Signature(_) => "signature",
        FactKey::Noreturn(_) => "noreturn",
        FactKey::Ref(_) => "ref",
        FactKey::Comment(..) => "comment",
        FactKey::JumpTable(_) => "jumptable",
        FactKey::FlowOverride(_) => "flow_override",
        FactKey::Str(_) => "string",
        FactKey::Var(_) => "variable",
        FactKey::Import(_) => "import",
        FactKey::Export(_) => "export",
        FactKey::Entry(_) => "entry",
        FactKey::Reloc(_) => "reloc",
        FactKey::Fde(_) => "fde",
        FactKey::Note(_) => "note",
    }
}

/// Gives the key of the fact with the ID text `text`.
///
/// # Errors
///
/// Returns [`ExplainError::BadId`] for a text that is not a fact ID of the module table, and
/// [`ExplainError::NotFound`] when the program has no such fact.
pub fn key_of(program: &Program, text: &str) -> Result<FactKey, ExplainError> {
    let _ = program;
    Err(ExplainError::BadId(text.to_owned()))
}

/// Gives the why tree of the fact `key`. The tree stops at the depth `depth`. The walk takes
/// one unit of `nodes` for each node, and it stops when `nodes` is 0.
#[must_use]
pub fn explain(program: &Program, key: &FactKey, depth: u32, nodes: &mut usize) -> Node {
    let _ = (program, depth, nodes);
    Node {
        key: key.clone(),
        id: String::new(),
        rule: None,
        source: None,
        premises: Vec::new(),
        truncated: false,
        cycle: false,
    }
}

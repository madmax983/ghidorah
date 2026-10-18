//! Why trees: the premises of a fact, and their premises in turn (ADR-0023).
//!
//! [`key_of`] reads the ID text of a fact. [`explain`] gives its tree. A node with a why-record
//! has its rule and its premises. A node with no why-record is an input of the binary or a
//! fact of an agent, an import or a user: it has its source and no premises.
//!
//! | Input | Fact |
//! |---|---|
//! | `fn:A` | the function at A |
//! | `bb:A` | the code unit at A |
//! | `ref:A>B:kind` | the reference |
//! | `str:A`, `jt:A`, `var:..`, `note:N` | the string, the jump table, the variable, the note |
//! | `sym:name` | the first symbol with the name |
//! | `imp:..`, `exp:..` | the import or the export: an input of the binary |
//! | `0x..` | the code unit at the address, else the data definition, else the string |
//!
//! The premise graph has no cycle (Section 3.11, invariant 6). The walk also keeps the path,
//! so a premise that is on its own path stops there with `cycle`.

use std::fmt;

use ghidorah_base::{Address, Id, StringId, SymId};
use ghidorah_db::{FactKey, Program, RuleCode, Source};

/// The default depth of a tree.
pub const DEFAULT_DEPTH: u32 = 3;

/// The default largest number of nodes of the trees of one call.
pub const DEFAULT_NODES: usize = 200;

/// The largest depth of a tree. A larger depth counts as this depth.
pub const MAX_DEPTH: u32 = 64;

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

/// Gives the key of the RAM address `off`: the code unit, else the data definition, else the
/// string.
fn addr_key(program: &Program, off: u64) -> Option<FactKey> {
    if program.code_unit(off).is_some() {
        Some(FactKey::CodeUnit(off))
    } else if program.data_def(off).is_some() {
        Some(FactKey::Data(off))
    } else {
        program
            .string(off)
            .map(|_| FactKey::Str(StringId(Address::ram(off))))
    }
}

/// Gives the key of the first symbol with the name `name`.
fn symbol_key(program: &Program, name: &SymId) -> Option<FactKey> {
    let addr = *program.addrs_named(name.as_str()).first()?;
    program
        .symbols_at(addr)
        .into_iter()
        .find(|s| s.name.value == name.as_str())
        .map(|s| FactKey::Symbol(addr, s.key))
}

/// Gives `key` when `exists`, else [`ExplainError::NotFound`] with the fact kind `kind`.
fn found(exists: bool, key: FactKey, kind: &'static str) -> Result<FactKey, ExplainError> {
    if exists {
        Ok(key)
    } else {
        Err(ExplainError::NotFound(kind))
    }
}

/// Gives the key of the fact with the ID text `text`.
///
/// # Errors
///
/// Returns [`ExplainError::BadId`] for a text that is not a fact ID of the module table, and
/// [`ExplainError::NotFound`] when the program has no such fact.
pub fn key_of(program: &Program, text: &str) -> Result<FactKey, ExplainError> {
    let p = program;
    let text = text.trim();
    let bad = || ExplainError::BadId(text.to_owned());
    if text.starts_with("0x") {
        let addr = Address::parse(text).map_err(|_| bad())?;
        return addr_key(p, addr.off).ok_or(ExplainError::NotFound("code_unit"));
    }
    match Id::parse(text).map_err(|_| bad())? {
        Id::Func(f) => found(p.func(f).is_some(), FactKey::Func(f), "function"),
        Id::Block(b) => {
            let at = b.0.off;
            found(
                p.code_unit(at).is_some(),
                FactKey::CodeUnit(at),
                "code_unit",
            )
        }
        Id::Ref(r) => p
            .refs_from(r.from())
            .into_iter()
            .map(|f| f.value.key)
            .find(|k| k.to == r.to() && k.kind.name() == r.kind())
            .map(FactKey::Ref)
            .ok_or(ExplainError::NotFound("ref")),
        Id::Str(s) => {
            let exists = s.0.is_ram() && p.string(s.0.off).is_some();
            found(exists, FactKey::Str(s), "string")
        }
        Id::JumpTable(j) => found(
            p.jump_table(j).is_some(),
            FactKey::JumpTable(j),
            "jumptable",
        ),
        Id::Sym(name) => symbol_key(p, &name).ok_or(ExplainError::NotFound("symbol")),
        Id::Var(v) => {
            let view = p.var(&v);
            let exists = view.name.is_some() || view.ty.is_some();
            found(exists, FactKey::Var(v), "variable")
        }
        Id::Import(i) => found(p.imports().contains_key(&i), FactKey::Import(i), "import"),
        Id::Export(e) => found(p.exports().contains_key(&e), FactKey::Export(e), "export"),
        Id::Note(n) => found(p.notes().get(n).is_some(), FactKey::Note(n), "note"),
        _ => Err(bad()),
    }
}

/// Gives the ID text of the fact `key`, for example `fn:0x1149` or `sym:main`.
#[must_use]
pub fn key_text(program: &Program, key: &FactKey) -> String {
    match key {
        FactKey::CodeUnit(off)
        | FactKey::Data(off)
        | FactKey::Entry(off)
        | FactKey::Reloc(off)
        | FactKey::Fde(off) => Address::ram(*off).to_string(),
        FactKey::Symbol(addr, k) => program
            .base()
            .symbols()
            .get(*addr, *k)
            .or_else(|| program.analysis().symbols().get(*addr, *k))
            .and_then(|s| SymId::new(&s.name.value).ok())
            .map_or_else(|| addr.to_string(), |id| id.to_string()),
        FactKey::Func(f) | FactKey::Signature(f) | FactKey::Noreturn(f) => f.to_string(),
        FactKey::Ref(k) => k
            .id()
            .map_or_else(|_| k.from.to_string(), |id| id.to_string()),
        FactKey::Comment(a, _) | FactKey::FlowOverride(a) => a.to_string(),
        FactKey::JumpTable(j) => j.to_string(),
        FactKey::Str(s) => s.to_string(),
        FactKey::Var(v) => v.to_string(),
        FactKey::Import(i) => i.to_string(),
        FactKey::Export(e) => e.to_string(),
        FactKey::Note(n) => n.to_string(),
    }
}

/// Gives `Analysis` when the analysis layer has the fact, else `Imported` when the base layer
/// has it.
const fn layer_source(analysis: bool, base: bool) -> Option<Source> {
    if analysis {
        Some(Source::Analysis)
    } else if base {
        Some(Source::Imported)
    } else {
        None
    }
}

/// Gives the source of the fact `key`, or `None` when the program has no such fact. An input
/// of the binary has the source `Imported`.
#[must_use]
pub fn source_of(program: &Program, key: &FactKey) -> Option<Source> {
    let p = program;
    match key {
        FactKey::Func(f) => p.func(*f).map(|v| v.source),
        FactKey::Signature(f) => p.func(*f).and_then(|v| v.sig).map(|s| s.source),
        FactKey::Noreturn(f) => p.func(*f).and_then(|v| v.noreturn).map(|n| n.source),
        FactKey::Ref(k) => p
            .base()
            .refs()
            .get(k)
            .or_else(|| p.analysis().refs().get(k))
            .map(|r| r.source),
        FactKey::Comment(a, kind) => p.comment(*a, *kind).map(|c| c.source),
        FactKey::JumpTable(j) => p.jump_table(*j).map(|t| t.source),
        FactKey::FlowOverride(a) => p.flow_override(*a).map(|o| o.source),
        FactKey::Data(off) => p.data_def(*off).map(|d| d.source),
        FactKey::Var(v) => {
            let view = p.var(v);
            view.name
                .map(|n| n.source)
                .or_else(|| view.ty.map(|t| t.source))
        }
        FactKey::Symbol(addr, k) => p
            .base()
            .symbols()
            .get(*addr, *k)
            .or_else(|| p.analysis().symbols().get(*addr, *k))
            .map(|s| s.name.source),
        FactKey::Str(s) => layer_source(
            s.0.is_ram() && p.analysis().strings().get(s.0.off).is_some(),
            s.0.is_ram() && p.base().strings().get(s.0.off).is_some(),
        ),
        FactKey::CodeUnit(off) => layer_source(
            p.analysis().listing().unit(*off).is_some(),
            p.base().listing().unit(*off).is_some(),
        ),
        FactKey::Note(n) => p.notes().get(*n).map(|n| n.src),
        FactKey::Import(_)
        | FactKey::Export(_)
        | FactKey::Entry(_)
        | FactKey::Reloc(_)
        | FactKey::Fde(_) => Some(Source::Imported),
    }
}

/// Gives the why tree of the fact `key`. The tree stops at the depth `depth`, at most
/// [`MAX_DEPTH`]. The walk takes one unit of `nodes` for each node, and it stops when `nodes`
/// is 0. The root is always in the tree.
#[must_use]
pub fn explain(program: &Program, key: &FactKey, depth: u32, nodes: &mut usize) -> Node {
    let mut path = Vec::new();
    walk(program, key, depth.min(MAX_DEPTH), nodes, &mut path)
}

/// Gives the node of `key` with `left` levels of premises below it.
fn walk(
    program: &Program,
    key: &FactKey,
    left: u32,
    nodes: &mut usize,
    path: &mut Vec<FactKey>,
) -> Node {
    *nodes = nodes.saturating_sub(1);
    let why = program.why(key);
    let mut node = Node {
        key: key.clone(),
        id: key_text(program, key),
        rule: why.map(|w| w.rule.clone()),
        source: if why.is_none() {
            source_of(program, key)
        } else {
            None
        },
        premises: Vec::new(),
        truncated: false,
        cycle: false,
    };
    let Some(why) = why.filter(|w| !w.premises.is_empty()) else {
        return node;
    };
    let Some(below) = left.checked_sub(1) else {
        node.truncated = true;
        return node;
    };
    path.push(key.clone());
    for premise in &why.premises {
        if *nodes == 0 {
            node.truncated = true;
            break;
        }
        if path.contains(premise) {
            *nodes = nodes.saturating_sub(1);
            node.premises.push(Node {
                key: premise.clone(),
                id: key_text(program, premise),
                rule: None,
                source: None,
                premises: Vec::new(),
                truncated: false,
                cycle: true,
            });
            continue;
        }
        node.premises
            .push(walk(program, premise, below, nodes, path));
    }
    path.pop();
    node
}

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
//! The cyclomatic complexity is 1 plus the sum over the blocks of the internal out-edges minus 1.
//! The score of [`priority`]:
//!
//! ```text
//! score = 8 * risky_calls + 4 * in_degree + 2 * string_refs + min(size / 16, 64)
//! ```
//!
//! `risky_calls` counts the call sites to imports of the [`RISKY`] categories, except the C
//! runtime imports of [`RUNTIME`]: nearly every file calls them. `in_degree` counts the
//! references to the entry from outside the body. `string_refs` counts the references from the
//! body to strings. `size` is the body size in bytes.
//!
//! The order is the score from high to low, then the entry from low to high. Only an analysis
//! run changes the analysis layer, so a run freezes the order (AC-157). Names, comments and
//! `visited` do not change it.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, WarningCode};
use ghidorah_db::{CodeUnit, FlowKind, FlowOverride, Program};
use ghidorah_json::Value;
use ghidorah_kernel::RangeSet;
use ghidorah_types::Category;

use crate::analyzers::gaps::{self, Gap};
use crate::callgraph::{CallGraph, Callee};
use crate::cfg::{self, EdgeKind};

/// The import categories that raise the priority.
pub const RISKY: [Category; 6] = [
    Category::Network,
    Category::Process,
    Category::File,
    Category::Crypto,
    Category::AntiDebug,
    Category::Environment,
];

/// The C runtime imports that do not raise the priority.
pub const RUNTIME: [&str; 4] = [
    "__libc_start_main",
    "__cxa_finalize",
    "__cxa_atexit",
    "__stack_chk_fail",
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
    /// The cyclomatic complexity, at least 1.
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

/// The kind of call that fixes a worklist item: the `func_edit` action and its address.
///
/// The value is not a complete call. A site action also needs `targets`, and `set_noreturn`
/// needs `noreturn`. The `binary_survey` tool adds these arguments from the facts of the
/// site, or sends a read call in place of the edit.
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

    /// Gives the address of the remedy.
    #[must_use]
    pub const fn addr(self) -> u64 {
        match self {
            Self::Create(a)
            | Self::SetCallTargets(a)
            | Self::SetJumpTable(a)
            | Self::SetNoreturn(a) => a,
        }
    }

    /// Gives the action and the address arguments of the `func_edit` call, for example
    /// `{"action":"create","target":"0x1150"}`. An action on a site names it with `at`. The
    /// other arguments of the action are not in the value.
    #[must_use]
    pub fn args(self) -> Value {
        let key = match self {
            Self::Create(_) | Self::SetNoreturn(_) => "target",
            Self::SetCallTargets(_) | Self::SetJumpTable(_) => "at",
        };
        Value::object([
            ("action", Value::from(self.action())),
            (key, Value::from(Address::ram(self.addr()).to_string())),
        ])
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

/// Gives a count as a `u64`.
fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Gives the size of `body` in bytes.
fn size_of(body: &RangeSet) -> u64 {
    body.ranges()
        .iter()
        .map(|r| u64::try_from(r.len()).unwrap_or(u64::MAX))
        .fold(0, u64::saturating_add)
}

/// Gives the code units of `body` in address order. The analysis layer comes first.
fn units_of(program: &Program, body: &RangeSet) -> Vec<(u64, CodeUnit)> {
    let mut out = BTreeMap::new();
    for layer in [program.base(), program.analysis()] {
        for r in body.ranges() {
            out.extend(layer.listing().units_in(*r).map(|(at, u)| (at, *u)));
        }
    }
    out.into_iter().collect()
}

/// Gives the Tier-0 category of an import name.
fn category(name: &str) -> Option<Category> {
    ghidorah_types::proto::builtin()
        .ok()?
        .get(name)
        .map(|p| p.category)
}

/// Gives the metrics of the function `func`, or `None` when the program has no such function.
#[must_use]
pub fn func_metrics(program: &Program, graph: &CallGraph, func: FuncId) -> Option<FuncMetrics> {
    let view = program.func(func)?;
    let cfg = cfg::build(program, func)?;
    let mut succ: BTreeMap<u64, u64> = BTreeMap::new();
    for e in cfg.edges.iter().filter(|e| e.kind.is_internal()) {
        let n = succ.entry(e.from).or_default();
        *n = n.saturating_add(1);
    }
    let edges = succ.values().fold(0, |a: u64, n| a.saturating_add(*n));
    let decisions = succ
        .values()
        .fold(0, |a: u64, n| a.saturating_add(n.saturating_sub(1)));
    let insns = cfg.blocks.iter().map(|b| b.insns.len()).sum::<usize>();
    let mut string_refs = 0u64;
    for (at, _) in units_of(program, &view.func.body) {
        for r in program.refs_from(Address::ram(at)) {
            let to = r.value.key.to;
            if !r.value.key.kind.is_flow() && to.is_ram() && program.string(to.off).is_some() {
                string_refs = string_refs.saturating_add(1);
            }
        }
    }
    let mut import_calls: BTreeMap<Category, u64> = BTreeMap::new();
    let callees = graph.callees(func);
    for callee in &callees {
        if let Callee::Import(id) = callee
            && let Some(c) = id.name().and_then(category)
        {
            let n = import_calls.entry(c).or_default();
            *n = n.saturating_add(count(graph.sites(func, callee).len()));
        }
    }
    Some(FuncMetrics {
        func,
        size: size_of(&view.func.body),
        blocks: count(cfg.blocks.len()),
        insns: count(insns),
        edges,
        cyclomatic: decisions.saturating_add(1),
        callers: count(graph.callers_of_func(func).len()),
        callees: count(callees.len()),
        string_refs,
        import_calls,
    })
}

/// Gives the metrics of every function in entry order.
#[must_use]
pub fn all(program: &Program) -> Vec<FuncMetrics> {
    let graph = CallGraph::build(program);
    program
        .funcs()
        .iter()
        .filter_map(|f| func_metrics(program, &graph, f.id()))
        .collect()
}

/// Gives the coverage of `program`.
#[must_use]
pub fn coverage(program: &Program) -> Coverage {
    let mut commented = BTreeSet::new();
    for layer in [program.base(), program.analysis()] {
        for (addr, _, _) in layer.comments().iter() {
            commented.extend(program.owner_of(addr));
        }
    }
    let mut c = Coverage::default();
    for f in program.funcs() {
        let id = f.id();
        let flags = [
            true,
            program.code_unit(id.0.off).is_some(),
            program.progress().get(id).visited,
            program.name(id.0).is_some_and(|n| !n.is_default()),
            f.sig.is_some(),
            commented.contains(&id),
        ];
        let fields = [
            &mut c.functions,
            &mut c.analyzed,
            &mut c.visited,
            &mut c.named,
            &mut c.typed,
            &mut c.commented,
        ];
        for (field, on) in fields.into_iter().zip(flags) {
            *field = field.saturating_add(u64::from(on));
        }
    }
    c
}

/// Adds the worklist items of the function `func` to `out`.
fn func_items(program: &Program, func: FuncId, out: &mut Vec<WorkItem>) {
    let Some(view) = program.func(func) else {
        return;
    };
    let mut push = |kind, at: u64, remedy| {
        out.push(WorkItem {
            kind,
            at: Address::ram(at),
            func: Some(func),
            remedy,
            gap: None,
        });
    };
    if let Some(cfg) = cfg::build(program, func) {
        for e in cfg
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::IndirectUnresolved)
        {
            let block = cfg.blocks.iter().find(|b| b.start == e.from);
            if let Some((at, _)) = block.and_then(|b| b.insns.last()) {
                push(
                    ItemKind::UnresolvedJump,
                    *at,
                    Some(Remedy::SetJumpTable(*at)),
                );
            }
        }
    }
    for (at, unit) in units_of(program, &view.func.body) {
        let CodeUnit::Insn { flow, .. } = unit;
        let site = Address::ram(at);
        let called = program
            .refs_from(site)
            .iter()
            .any(|r| r.value.key.kind.is_call());
        let targets = program
            .flow_override(site)
            .is_some_and(|f| matches!(f.value, FlowOverride::IndirectTargets(_)));
        if flow == FlowKind::ICall && !called && !targets {
            push(
                ItemKind::UnresolvedCall,
                at,
                Some(Remedy::SetCallTargets(at)),
            );
        }
    }
    let mut conflicts = BTreeSet::new();
    for layer in [program.base(), program.analysis()] {
        let caveats = layer.funcs().get(func).map(|f| f.caveats.as_slice());
        for caveat in caveats.unwrap_or_default() {
            if caveat.code == WarningCode::AgentOverrideConflict {
                conflicts.insert(caveat.at.filter(Address::is_ram).unwrap_or(func.0).off);
            }
        }
    }
    for at in conflicts {
        push(ItemKind::OverrideConflict, at, None);
    }
}

/// Gives the worklist of `program` in address order, then in kind order.
#[must_use]
pub fn worklist(program: &Program) -> Vec<WorkItem> {
    let mut out = Vec::new();
    for f in program.funcs() {
        func_items(program, f.id(), &mut out);
    }
    for gap in gaps::items(program) {
        out.push(WorkItem {
            kind: ItemKind::Gap,
            at: Address::ram(gap.range.first),
            func: None,
            remedy: Some(gap.remedy()),
            gap: Some(gap),
        });
    }
    out.sort_by_key(|i| (i.at, i.kind));
    out
}

/// The counts of one function of [`priority`].
#[derive(Default)]
struct Stat {
    in_degree: u64,
    strings: u64,
    risky: u64,
    size: u64,
}

impl Stat {
    /// Gives the score.
    fn score(&self) -> u64 {
        let size = (self.size / SIZE_UNIT).min(MAX_SIZE_POINTS);
        W_RISKY
            .saturating_mul(self.risky)
            .saturating_add(W_IN.saturating_mul(self.in_degree))
            .saturating_add(W_STRING.saturating_mul(self.strings))
            .saturating_add(size)
    }
}

/// Gives the priority of each function of the analysis layer in priority order.
#[must_use]
pub fn priority(program: &Program) -> Vec<Ranked> {
    let a = program.analysis();
    let mut risky_at: BTreeSet<Address> = BTreeSet::new();
    for row in program.imports().values() {
        let name = row
            .id
            .name()
            .map(|n| n.split_once('@').map_or(n, |(head, _)| head));
        let runtime = name.is_some_and(|n| RUNTIME.contains(&n));
        if !runtime && name.and_then(category).is_some_and(|c| RISKY.contains(&c)) {
            risky_at.insert(row.ext);
            risky_at.extend(row.stub);
        }
    }
    let mut stats: BTreeMap<FuncId, Stat> = a
        .funcs()
        .iter()
        .map(|f| {
            let stat = Stat {
                size: size_of(&f.body),
                ..Stat::default()
            };
            (f.id(), stat)
        })
        .collect();
    for r in a.refs().iter() {
        let k = r.value.key;
        let owner = k
            .from
            .is_ram()
            .then(|| a.funcs().owner_of(k.from.off))
            .flatten();
        if k.to.is_ram()
            && owner != Some(FuncId(k.to))
            && let Some(s) = stats.get_mut(&FuncId(k.to))
        {
            s.in_degree = s.in_degree.saturating_add(1);
        }
        let Some(s) = owner.and_then(|o| stats.get_mut(&o)) else {
            continue;
        };
        if !k.kind.is_flow() && k.to.is_ram() && a.strings().get(k.to.off).is_some() {
            s.strings = s.strings.saturating_add(1);
        }
        if k.kind.is_call() && risky_at.contains(&k.to) {
            s.risky = s.risky.saturating_add(1);
        }
    }
    let mut out: Vec<Ranked> = stats
        .into_iter()
        .map(|(func, s)| Ranked {
            func,
            score: s.score(),
        })
        .collect();
    out.sort_by_key(|r| (Reverse(r.score), r.func));
    out
}

//! The facts of the IR-based analyzers in the work state, and their rows in the analysis set
//! (design Sections 7.3 and 7.8 to 7.11).
//!
//! | Field | Analyzer | Published as |
//! |---|---|---|
//! | `tables` | `JumpTables` | a `jumptables` row, and `W_JUMPTABLE_UNRESOLVED` on the owner |
//! | `parts` | `TailCallsAndParts` | a `Cold` part of the owner |
//! | `main` | `MainDiscovery` | a `FUNCTION` symbol `main` when the base layer has no symbol there |
//! | `mismatches` | `StackFrames` | `W_SP_MISMATCH` on the function at each site |
//! | `varargs` | `CallingConvention` | the `varargs` flag of the function |
//! | `syscalls` | `Syscalls` | an `EOL` comment `sys:<name>` at the site |
//! | `conflicts` | `JumpTables` | `W_AGENT_OVERRIDE_CONFLICT` with the analysis value |
//!
//! A record whose owner is not in the set does not go into the set. The agent noreturn flag
//! of the base layer also gives `W_AGENT_OVERRIDE_CONFLICT` when the flow disagrees. A call
//! with an unsafe fall-through gives `W_NORETURN_SUSPECT` (see `noreturn::suspects`).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, WarningCode};
use ghidorah_db::codec::edit_to_json;
use ghidorah_db::{
    Caveat, CommentKind, Edit, FactKey, FlowKind, Function, JumpTable, Origin, PartKind, Program,
    SymKey, SymKind,
};
use ghidorah_json::Value;

use crate::ctx::AnalysisCtx;
use crate::fir::{self, FirError, FuncIr, Input, Opts, Unit};
use crate::why::Why;
use crate::work::Work;

/// The remedy of `W_JUMPTABLE_UNRESOLVED`.
pub const JUMPTABLE_REMEDY: &str = "func_edit { action: \"set_jumptable\" }";

/// The name of the symbol of `MainDiscovery`.
pub const MAIN_NAME: &str = "main";

/// One jump table of method A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TableRec {
    /// The entry of the function of the jump.
    pub owner: u64,
    /// The table. An unresolved table has no targets.
    pub table: JumpTable,
    /// The why-record.
    pub why: Why,
}

/// The syscall note of one `syscall` site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SysRec {
    /// The entry of the function of the site.
    pub owner: u64,
    /// The text: `sys:<name>` or `sys:<number>`.
    pub text: String,
    /// The why-record.
    pub why: Why,
}

/// One disagreement of the analysis with an agent fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Conflict {
    /// The place of the agent fact.
    pub at: u64,
    /// The remedy with the analysis value.
    pub remedy: String,
}

/// The facts of the IR-based analyzers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct IrFacts {
    /// The jump tables of method A by the address of the jump.
    pub tables: BTreeMap<u64, TableRec>,
    /// The cold parts: the part start and the entry of its parent.
    pub parts: BTreeMap<u64, u64>,
    /// The entry of `main` and its why-record.
    pub main: Option<(u64, Why)>,
    /// The call sites with `W_SP_MISMATCH` by function entry.
    pub mismatches: BTreeMap<u64, BTreeSet<u64>>,
    /// The entries of the varargs functions.
    pub varargs: BTreeSet<u64>,
    /// The syscall notes by site.
    pub syscalls: BTreeMap<u64, SysRec>,
    /// The disagreements with agent jump tables by function entry.
    pub conflicts: BTreeMap<u64, BTreeSet<Conflict>>,
}

impl AnalysisCtx<'_> {
    /// Gives the facts of the IR-based analyzers.
    pub(crate) fn ir(&self) -> &IrFacts {
        &self.work.ir
    }

    /// Gives the facts of the IR-based analyzers for a change. The call marks the step as a
    /// change, so the publish step runs.
    pub(crate) fn ir_mut(&mut self) -> &mut IrFacts {
        self.touch();
        &mut self.work.ir
    }

    /// Gives the code units of the function `entry` in the work state.
    pub(crate) fn units_of(&self, entry: u64) -> BTreeMap<u64, Unit> {
        let Some(f) = self.work.funcs.get(&entry) else {
            return BTreeMap::new();
        };
        f.units
            .iter()
            .filter_map(|at| {
                let u = self.work.units.get(at)?;
                Some((
                    *at,
                    Unit {
                        len: u.len,
                        flow: u.flow,
                        flags: u.flags,
                    },
                ))
            })
            .collect()
    }
}

/// Builds the L0 IR of the function `entry` from the work state. The build uses its code
/// units, the cases of [`crate::overrides::cases`] and the noreturn flags of the context.
///
/// # Errors
///
/// Returns the [`FirError`] of the build.
pub(crate) fn work_ir(
    ctx: &AnalysisCtx<'_>,
    entry: u64,
    fuel: &mut Fuel,
) -> Result<FuncIr, FirError> {
    work_ir_at(ctx, entry, entry, fuel)
}

/// Builds the L0 IR of the code units of the function `owner` with the entry `root`. The
/// blocks that `root` does not reach stay out of the CFG.
///
/// # Errors
///
/// Returns the [`FirError`] of the build.
pub(crate) fn work_ir_at(
    ctx: &AnalysisCtx<'_>,
    owner: u64,
    root: u64,
    fuel: &mut Fuel,
) -> Result<FuncIr, FirError> {
    let units = ctx.units_of(owner);
    let cases: BTreeMap<u64, Vec<u64>> = units
        .iter()
        .filter(|(_, u)| u.flow == FlowKind::IJmp)
        .filter_map(|(at, _)| Some((*at, crate::overrides::cases(ctx, *at)?)))
        .collect();
    let noreturn = |t: u64| ctx.noreturn(t);
    let input = Input {
        entry: root,
        units,
        cases,
        noreturn: &noreturn,
    };
    fir::build_units(ctx.program(), input, &Opts::DEFAULT, fuel)
}

/// The rows of the IR facts for the analysis set.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Rows {
    jumptables: Vec<Value>,
    symbols: Vec<Value>,
    comments: Vec<Value>,
}

/// Gives the member `name` of the JSON form of `edit`.
fn member(edit: &Edit, name: &str) -> Value {
    edit_to_json(edit).get(name).cloned().unwrap_or_default()
}

/// Gives the rows of the IR facts of `work` whose owner is in `funcs`. Each row adds its
/// why-record to `whys`.
pub(crate) fn rows(
    program: &Program,
    work: &Work,
    funcs: &[Function],
    whys: &mut BTreeMap<FactKey, Why>,
) -> Rows {
    let kept: BTreeSet<u64> = funcs.iter().map(|f| f.entry.off).collect();
    let owns = |owner: u64, at: u64| kept.contains(&owner) && work.owner(at) == Some(owner);
    let o = origin();
    let mut out = Rows::default();
    for (site, rec) in &work.ir.tables {
        if !owns(rec.owner, *site) {
            continue;
        }
        let edit = Edit::SetJumpTable {
            id: JumpTableId(Address::ram(*site)),
            table: Some(o.fact(rec.table.clone())),
        };
        out.jumptables.push(Value::object([
            ("at", member(&edit, "at")),
            ("table", member(&edit, "table")),
        ]));
        whys.insert(table_key(*site), rec.why.clone());
    }
    if let Some((entry, why)) = &work.ir.main {
        let addr = Address::ram(*entry);
        if kept.contains(entry) && program.base().symbols().primary(addr).is_none() {
            let edit = Edit::SetName {
                addr,
                key: Some(SymKey(0)),
                kind: SymKind::Function,
                primary: true,
                name: Some(o.fact(MAIN_NAME.to_owned())),
                evidence: Vec::new(),
            };
            out.symbols.push(Value::object(
                ["addr", "key", "kind", "primary", "name"].map(|m| (m, member(&edit, m))),
            ));
            whys.insert(main_key(*entry), why.clone());
        }
    }
    for (site, rec) in &work.ir.syscalls {
        if !owns(rec.owner, *site) {
            continue;
        }
        let edit = Edit::SetComment {
            addr: Address::ram(*site),
            kind: CommentKind::Eol,
            text: Some(o.fact(rec.text.clone())),
        };
        out.comments.push(Value::object(
            ["addr", "kind", "text"].map(|m| (m, member(&edit, m))),
        ));
        whys.insert(note_key(*site), rec.why.clone());
    }
    out
}

impl Rows {
    /// Adds the rows to the members of the JSON form of an analysis set.
    pub(crate) fn merge(self, mut value: Value) -> Value {
        if let Some(members) = value.as_object_mut() {
            for (name, rows) in [
                ("jumptables", self.jumptables),
                ("symbols", self.symbols),
                ("comments", self.comments),
            ] {
                if let Some(list) = members.get_mut(name).and_then(Value::as_array_mut) {
                    list.extend(rows);
                }
            }
        }
        value
    }
}

/// Gives the analysis value of the noreturn flag of `entry` when it disagrees with the agent
/// fact `agent`. For example, the flow returns while the agent says noreturn.
fn noreturn_conflict(work: &Work, entry: u64, agent: bool) -> Option<bool> {
    let returns = work
        .funcs
        .get(&entry)
        .and_then(|f| f.summary.as_ref())
        .is_some_and(|s| s.ret);
    let flagged = work.noreturn(entry);
    if agent && returns {
        Some(false)
    } else if !agent && flagged {
        Some(true)
    } else {
        None
    }
}

/// Adds the IR facts of the function `entry` to its record: the cold parts, the `varargs`
/// flag and the caveats.
pub(crate) fn decorate(program: &Program, work: &Work, entry: u64, func: &mut Function) {
    let ir = &work.ir;
    for part in &mut func.parts {
        let cold = ir
            .parts
            .range(part.range.first..=part.range.last)
            .any(|(_, owner)| *owner == entry);
        if cold && !part.range.contains(entry) {
            part.kind = PartKind::Cold;
        }
    }
    func.flags.varargs = ir.varargs.contains(&entry);
    let mut caveats = BTreeSet::new();
    for (site, rec) in &ir.tables {
        if rec.owner == entry && !rec.table.resolved && work.owner(*site) == Some(entry) {
            caveats.insert(caveat(
                WarningCode::JumptableUnresolved,
                *site,
                Some(JUMPTABLE_REMEDY),
            ));
        }
    }
    for site in ir.mismatches.get(&entry).into_iter().flatten() {
        caveats.insert(caveat(WarningCode::SpMismatch, *site, None));
    }
    for c in ir.conflicts.get(&entry).into_iter().flatten() {
        caveats.insert(caveat(
            WarningCode::AgentOverrideConflict,
            c.at,
            Some(&c.remedy),
        ));
    }
    let agent = program
        .base()
        .funcs()
        .get(FuncId(Address::ram(entry)))
        .and_then(|f| f.flags.noreturn.as_ref())
        .map(|f| f.value);
    if let Some(value) = agent.and_then(|a| noreturn_conflict(work, entry, a)) {
        let remedy = format!("func_edit {{ action: \"set_noreturn\", noreturn: {value} }}");
        caveats.insert(caveat(
            WarningCode::AgentOverrideConflict,
            entry,
            Some(&remedy),
        ));
    }
    caveats.extend(crate::analyzers::noreturn::suspects(program, work, entry));
    func.caveats.extend(caveats);
}

/// Gives the caveat `code` at `at` with `remedy`.
fn caveat(code: WarningCode, at: u64, remedy: Option<&str>) -> Caveat {
    Caveat {
        code,
        at: Some(Address::ram(at)),
        remedy: remedy.map(str::to_owned),
    }
}

/// Gives the key of a jump table.
const fn table_key(site: u64) -> FactKey {
    FactKey::JumpTable(JumpTableId(Address::ram(site)))
}

/// Gives the key of the function at `entry`.
pub(crate) const fn func_key(entry: u64) -> FactKey {
    FactKey::Func(FuncId(Address::ram(entry)))
}

/// Gives the key of the syscall note at `site`.
const fn note_key(site: u64) -> FactKey {
    FactKey::Comment(Address::ram(site), CommentKind::Eol)
}

/// Gives the key of the `main` symbol.
const fn main_key(entry: u64) -> FactKey {
    FactKey::Symbol(Address::ram(entry), SymKey(0))
}

/// Gives the origin of every analysis fact.
fn origin() -> Origin {
    Origin::analysis()
}

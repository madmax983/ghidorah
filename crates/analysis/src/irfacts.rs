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
//! | `thunks` | `IatThunks` | the `thunk` flag and a `FUNCTION` symbol with the import name |
//! | `slot_sites` | `JumpTables` | no row: `Disasm` gives the site a reference to the import ([`crate::slotsite`]) |
//!
//! A record whose owner is not in the set does not go into the set. The agent noreturn flag
//! of the base layer also gives `W_AGENT_OVERRIDE_CONFLICT` when the flow disagrees. A call
//! with an unsafe fall-through gives `W_NORETURN_SUSPECT` (see `noreturn::suspects`).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, WarningCode};
use ghidorah_db::codec::SetRows;
use ghidorah_db::{
    Caveat, CommentKind, Fact, FactKey, FlowKind, Function, JumpTable, Origin, PartKind, Program,
    SymKey, SymKind, Symbol,
};

use crate::analyzers::iat::ThunkRec;
use crate::ctx::AnalysisCtx;
use crate::fir::{self, FirError, FuncIr, Input, Opts, Unit};
use crate::slotsite::SiteTarget;
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

/// One indirect jump or call through a register that holds an import slot or 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotSite {
    /// The entry of the function of the site.
    pub owner: u64,
    /// The target.
    pub target: SiteTarget,
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
    /// The IAT thunks by function entry.
    pub thunks: BTreeMap<u64, ThunkRec>,
    /// The indirect sites through a register that holds an import slot or 0, by site.
    pub slot_sites: BTreeMap<u64, SlotSite>,
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
        self.work
            .units_of(entry)
            .map(|(at, u)| {
                (
                    at,
                    Unit {
                        len: u.len,
                        flow: u.flow,
                        flags: u.flags,
                    },
                )
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
    jumptables: Vec<(JumpTableId, Fact<JumpTable>)>,
    symbols: Vec<Symbol>,
    comments: Vec<(Address, CommentKind, Fact<String>)>,
}

/// Gives the primary `FUNCTION` symbol `name` at `addr`.
fn function_symbol(addr: Address, name: Fact<String>) -> Symbol {
    Symbol {
        addr,
        key: SymKey(0),
        name,
        kind: SymKind::Function,
        primary: true,
    }
}

/// Gives the rows of the IR facts of `work` whose owner is in `funcs`. Each row adds its
/// why-record to `whys`.
pub(crate) fn rows(
    program: &Program,
    work: &Work,
    funcs: &[Function],
    whys: &mut crate::publish::whys::Whys,
) -> Rows {
    let kept: BTreeSet<u64> = funcs.iter().map(|f| f.entry.off).collect();
    let owns = |owner: u64, at: u64| kept.contains(&owner) && work.owner(at) == Some(owner);
    let o = origin();
    let mut out = Rows::default();
    for (site, rec) in &work.ir.tables {
        if !owns(rec.owner, *site) {
            continue;
        }
        out.jumptables
            .push((JumpTableId(Address::ram(*site)), o.fact(rec.table.clone())));
        whys.insert(table_key(*site), rec.why.clone());
    }
    if let Some((entry, why)) = &work.ir.main {
        let addr = Address::ram(*entry);
        if kept.contains(entry) && program.base().symbols().primary(addr).is_none() {
            out.symbols
                .push(function_symbol(addr, o.fact(MAIN_NAME.to_owned())));
            whys.insert(main_key(*entry), why.clone());
        }
    }
    for (entry, rec) in &work.ir.thunks {
        let addr = Address::ram(*entry);
        if !kept.contains(entry) || program.base().symbols().primary(addr).is_some() {
            continue;
        }
        out.symbols
            .push(function_symbol(addr, o.fact(rec.name.clone())));
        whys.insert(main_key(*entry), rec.why.clone());
    }
    for (site, rec) in &work.ir.syscalls {
        if !owns(rec.owner, *site) {
            continue;
        }
        out.comments.push((
            Address::ram(*site),
            CommentKind::Eol,
            o.fact(rec.text.clone()),
        ));
        whys.insert(note_key(*site), rec.why.clone());
    }
    out
}

impl Rows {
    /// Adds the rows to the rows of an analysis set.
    pub(crate) fn add_to(self, rows: &mut SetRows) {
        rows.jumptables.extend(self.jumptables);
        rows.symbols.extend(self.symbols);
        rows.comments.extend(self.comments);
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

/// Gives the key of the `main` symbol, or of the symbol of an IAT thunk.
const fn main_key(entry: u64) -> FactKey {
    FactKey::Symbol(Address::ram(entry), SymKey(0))
}

/// Gives the origin of every analysis fact.
fn origin() -> Origin {
    Origin::analysis()
}

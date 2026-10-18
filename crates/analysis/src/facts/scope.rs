//! The scope of one function: what the checks read from its body.
//!
//! | Member | Content |
//! |---|---|
//! | `calls` | each callee with its evidence: call references, jumps that leave the body and override targets |
//! | `refs` | the references from the instructions of the body |
//! | `gaps` | the indirect calls and jumps with no target |
//! | `jump_gaps` | the indirect jumps with no target: code of the body can hide behind them |
//! | `rets` | the return instructions |
//! | `tails` | the jumps that leave the body |
//! | `syscalls` | the syscall sites with the number of their analysis note |
//!
//! A jump to the entry of another function or to an import is a tail call, so it is an edge.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, Id, ImportId, Limits};
use ghidorah_db::{CommentKind, FlowKind, FlowOverride, Program, RefKey, RefType};
use ghidorah_kernel::RangeSet;

use super::relations::Evidence;
use crate::callgraph::Callee;

/// The bytes of the `syscall` instruction.
const SYSCALL: [u8; 2] = [0x0f, 0x05];

/// The imports by the addresses that name them: the stub and the EXTERNAL address.
#[derive(Debug, Clone, Default)]
pub(crate) struct Imports {
    by_addr: BTreeMap<Address, ImportId>,
}

impl Imports {
    /// Gives the imports of `program`.
    pub(crate) fn of(program: &Program) -> Self {
        let mut by_addr = BTreeMap::new();
        for row in program.imports().values() {
            by_addr.insert(row.ext, row.id.clone());
            if let Some(stub) = row.stub {
                by_addr.insert(stub, row.id.clone());
            }
        }
        Self { by_addr }
    }

    /// Gives the import whose stub or EXTERNAL address is `addr`.
    pub(crate) fn at(&self, addr: Address) -> Option<&ImportId> {
        self.by_addr.get(&addr)
    }
}

/// The scope of one function.
#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    /// The callees with their evidence.
    pub calls: BTreeMap<Callee, BTreeSet<Evidence>>,
    /// The references from the body in key order.
    pub refs: Vec<RefKey>,
    /// The indirect calls and jumps with no target.
    pub gaps: BTreeSet<Address>,
    /// The indirect jumps with no target.
    pub jump_gaps: BTreeSet<Address>,
    /// The return instructions.
    pub rets: Vec<Address>,
    /// The jumps that leave the body.
    pub tails: Vec<Address>,
    /// The syscall sites with their numbers.
    pub syscalls: Vec<(Address, Option<u16>)>,
    /// The work of the build: one unit per instruction and per reference.
    pub cost: u64,
}

/// Gives the callee at the target `to`: an import, else a function entry.
pub(crate) fn callee(program: &Program, imports: &Imports, to: Address) -> Option<Callee> {
    if let Some(id) = imports.at(to) {
        return Some(Callee::Import(id.clone()));
    }
    program.func(FuncId(to)).map(|_| Callee::Func(FuncId(to)))
}

/// Tells if `body` holds the address `to`.
fn holds(body: &RangeSet, to: Address) -> bool {
    to.is_ram() && body.contains(to.off)
}

/// Tells if the reference type is a jump.
const fn is_jump(kind: RefType) -> bool {
    matches!(
        kind,
        RefType::UnconditionalJump | RefType::ConditionalJump | RefType::ComputedJump
    )
}

/// Gives the targets of the `IndirectTargets` override at `site`.
pub(crate) fn override_targets(program: &Program, site: Address) -> Option<&[Address]> {
    match program.flow_override(site).map(|f| &f.value) {
        Some(FlowOverride::IndirectTargets(t)) => Some(t),
        _ => None,
    }
}

/// Tells if the indirect jump at `site` has a resolved jump table with targets.
fn table_resolved(program: &Program, site: Address) -> bool {
    program
        .jump_table(ghidorah_base::JumpTableId(site))
        .is_some_and(|t| t.value.resolved && !t.value.targets.is_empty())
}

/// Tells if the instruction at `site` with the flow `flow` is an indirect call or jump with
/// no target.
pub(crate) fn is_gap(program: &Program, site: Address, flow: FlowKind) -> bool {
    if override_targets(program, site).is_some() {
        return false;
    }
    let refs = program.refs_from(site);
    match flow {
        FlowKind::ICall => !refs.iter().any(|r| r.value.key.kind.is_call()),
        FlowKind::IJmp => {
            !table_resolved(program, site) && !refs.iter().any(|r| r.value.key.kind.is_flow())
        }
        _ => false,
    }
}

/// Tells if the instruction at `at` with the length `len` is a `syscall`.
fn is_syscall(program: &Program, at: u64, len: u8) -> bool {
    len == 2
        && program
            .mem()
            .read(at, 2, &Limits::DEFAULT)
            .is_ok_and(|b| b.as_ref() == SYSCALL)
}

/// Gives the syscall number of the analysis note at `site`: `sys:<name>` or `sys:<number>`.
fn syscall_number(program: &Program, site: Address) -> Option<u16> {
    let note = program.analysis().comments().get(site, CommentKind::Eol)?;
    let Ok(Id::Syscall(id)) = Id::parse(&note.value) else {
        return None;
    };
    id.number().or_else(|| {
        let table = ghidorah_types::syscalls::x86_64().ok()?;
        table.number(id.name()?)
    })
}

/// Builds the scope of the function `func`. A missing function gives `None`.
pub(crate) fn build(program: &Program, imports: &Imports, func: FuncId) -> Option<Scope> {
    let view = program.func(func)?;
    let body = &view.func.body;
    let units = crate::fir::units_of(program, func)?;
    let mut s = Scope::default();
    for (at, unit) in &units {
        let site = Address::ram(*at);
        let refs = program.refs_from(site);
        s.cost = s
            .cost
            .saturating_add(1)
            .saturating_add(u64::try_from(refs.len()).unwrap_or(u64::MAX));
        for r in &refs {
            let key = r.value.key;
            s.refs.push(key);
            let leaves = is_jump(key.kind) && !holds(body, key.to);
            if leaves {
                s.tails.push(site);
            }
            if key.kind.is_call() || leaves {
                if let Some(c) = callee(program, imports, key.to) {
                    s.calls.entry(c).or_default().insert(Evidence::Ref(key));
                }
            }
        }
        for t in override_targets(program, site).unwrap_or_default() {
            if let Some(c) = callee(program, imports, *t) {
                s.calls
                    .entry(c)
                    .or_default()
                    .insert(Evidence::Override(site));
            }
        }
        if is_gap(program, site, unit.flow) {
            s.gaps.insert(site);
            if unit.flow == FlowKind::IJmp {
                s.jump_gaps.insert(site);
            }
        }
        if unit.flow == FlowKind::Ret {
            s.rets.push(site);
        }
        if is_syscall(program, *at, unit.len) {
            s.syscalls.push((site, syscall_number(program, site)));
        }
    }
    s.refs.sort();
    s.refs.dedup();
    s.tails.sort();
    s.tails.dedup();
    Some(s)
}

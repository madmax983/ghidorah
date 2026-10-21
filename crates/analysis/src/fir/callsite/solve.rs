//! The parameter solve over the callees of a function (design Section 7.10).
//!
//! [`solve`] recovers the parameters of a function with the reads of its calls and tail
//! calls. A call reads each argument register of its callee that holds its entry value at the
//! call:
//!
//! 1. The solve takes the function, then each callee with no parameter fact that a call can
//!    pass an entry value to, depth first. It stops at [`MAX_SOLVE`] functions.
//! 2. It recovers the functions callees first, in that fixed order, until no count changes. A
//!    recursion takes more rounds.
//!
//! One forward pass finds the callees of step 1. Such a callee has a call with a free
//! argument register. A path from the entry to that call does not write the register. Each
//! step of the
//! rounds takes one unit of fuel. Each pass over the blocks of a function takes one unit for
//! each block and each call op. The solve stops with an error when the fuel runs out.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId, OutOfFuel};
use ghidorah_db::{Program, Types};
use ghidorah_ir::{Loc, OpId, Opc, rpo};
use ghidorah_types::CallConv;

use super::{arg_regs, call_targets, fixed, from_sig};
use crate::cc::{self, BlockUse, Params, loc_of};
use crate::fir::{self, FirError, FuncIr, Image, Opts};

/// The largest count of functions of one [`solve`].
pub const MAX_SOLVE: usize = 32;

/// What the facts say about the callee of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Callee {
    /// The callee reads these registers.
    Fixed(Vec<Loc>),
    /// A function with no parameter fact. The solve recovers it.
    Func(u64),
    /// An import with no Tier-0 prototype. It has no count, and the call reads no register.
    Import,
    /// A target with no facts. The call reads no register.
    Unknown,
}

/// Gives the callee at the target `addr`: an import stub or slot, or a function entry.
fn callee_of(program: &Program, conv: &CallConv, addr: u64) -> Callee {
    let at = Address::ram(addr);
    if let Some(row) = program
        .imports()
        .values()
        .find(|r| r.stub == Some(at) || r.slot == Some(at))
    {
        return row
            .id
            .name()
            .and_then(Types::prototype)
            .map_or(Callee::Import, |p| {
                Callee::Fixed(arg_regs(conv, &from_sig(&p.sig), None))
            });
    }
    if program.func(FuncId(at)).is_none() {
        return Callee::Unknown;
    }
    match fixed(program, FuncId(at)) {
        Some((p, _)) => Callee::Fixed(arg_regs(conv, &p, None)),
        None => Callee::Func(addr),
    }
}

/// The fixed part of one function of a solve: its IR, the use summaries of its blocks and
/// the callees of its calls.
#[derive(Debug)]
struct Base {
    /// The L0 IR.
    ir: FuncIr,
    /// The use summary of each block.
    blocks: Vec<BlockUse>,
    /// The callee of each call and tail jump.
    callees: BTreeMap<OpId, Callee>,
    /// The live-in registers with the reads of the fixed callees only.
    live: BTreeSet<Loc>,
    /// The parameters of `live`.
    params: Params,
    /// The callees of step 1 of the module doc, in address order.
    children: Vec<u64>,
    /// The callees of the tail jumps at stack height 0.
    tails: Vec<Callee>,
    /// The fuel of one pass over the blocks: one unit for each block and each call op.
    cost: u64,
}

impl Base {
    /// Makes the base of `ir`. Its first parameters take the reads of the fixed callees.
    fn new(
        program: &Program,
        conv: &CallConv,
        ir: FuncIr,
        fuel: &mut Fuel,
    ) -> Result<Self, OutOfFuel> {
        let blocks = cc::summaries(&ir, conv, false, &Image(program));
        let mut known: BTreeMap<u64, Callee> = BTreeMap::new();
        let mut callees = BTreeMap::new();
        for (id, t) in call_targets(&ir) {
            let c = known
                .entry(t)
                .or_insert_with(|| callee_of(program, conv, t))
                .clone();
            callees.insert(id, c);
        }
        let tails = tail_callees(&ir, &callees);
        let ops = blocks.iter().map(|b| b.free.len()).sum::<usize>();
        let cost = u64::try_from(blocks.len().saturating_add(ops)).unwrap_or(u64::MAX);
        let mut base = Self {
            ir,
            blocks,
            callees,
            live: BTreeSet::new(),
            params: Params::default(),
            children: Vec::new(),
            tails,
            cost,
        };
        base.live = base.live_with(&base.reads(conv, &BTreeMap::new()), fuel)?;
        base.params = cc::from_live(&base.ir, conv, &base.live);
        base.children = base.children(conv, fuel)?;
        Ok(base)
    }

    /// Gives the live-in registers when each call op of `reads` reads its registers. A call
    /// reads only the registers that its block does not write before it.
    fn live_with(
        &self,
        reads: &BTreeMap<OpId, Vec<Loc>>,
        fuel: &mut Fuel,
    ) -> Result<BTreeSet<Loc>, OutOfFuel> {
        fuel.take(self.cost)?;
        let extra: Vec<BTreeSet<Loc>> = self
            .blocks
            .iter()
            .map(|b| {
                let mut set = BTreeSet::new();
                for (id, free) in &b.free {
                    let regs = reads.get(id).into_iter().flatten();
                    set.extend(regs.filter(|r| free.contains(r)));
                }
                set
            })
            .collect();
        Ok(cc::flow(&self.ir, &self.blocks, &extra))
    }

    /// Gives the reads of the calls: the fixed callees, and the callees in `state`.
    fn reads(&self, conv: &CallConv, state: &BTreeMap<u64, Solved>) -> BTreeMap<OpId, Vec<Loc>> {
        let mut out = BTreeMap::new();
        for (id, c) in &self.callees {
            let regs = match c {
                Callee::Fixed(r) => r.clone(),
                Callee::Func(t) => match state.get(t) {
                    Some(n) => arg_regs(conv, &n.params, Some(&n.live)),
                    None => continue,
                },
                Callee::Import | Callee::Unknown => continue,
            };
            out.insert(*id, regs);
        }
        out
    }

    /// Gives the callees with no parameter fact that a call can pass an entry value to. Such a
    /// call has a free argument register that is not in `live`. A path from the entry to the
    /// block of the call does not write that register.
    fn children(&self, conv: &CallConv, fuel: &mut Fuel) -> Result<Vec<u64>, OutOfFuel> {
        fuel.take(self.cost)?;
        let names = conv.int_args.iter().chain(conv.float_args.iter());
        let all: BTreeSet<Loc> = names.filter_map(|n| loc_of(n)).collect();
        let open = unwritten(&self.ir, &self.blocks, &all);
        let mut out = BTreeSet::new();
        for (b, at) in self.blocks.iter().zip(&open) {
            for (id, free) in &b.free {
                let Some(Callee::Func(t)) = self.callees.get(id) else {
                    continue;
                };
                if free
                    .iter()
                    .any(|r| at.contains(r) && !self.live.contains(r))
                {
                    out.insert(*t);
                }
            }
        }
        Ok(out.into_iter().collect())
    }
}

/// Gives the callees of the tail jumps of `ir` at stack height 0, in op order.
fn tail_callees(ir: &FuncIr, callees: &BTreeMap<OpId, Callee>) -> Vec<Callee> {
    let jump = |id: OpId| {
        let op = ir.op_index(id).and_then(|i| ir.arena.op(i));
        op.is_some_and(|o| matches!(o.opc, Opc::Jump | Opc::JumpInd))
    };
    let height = |id: OpId| ir.frame.as_ref().and_then(|f| f.sp_at(id.addr));
    callees
        .iter()
        .filter(|(id, _)| jump(**id) && height(**id) == Some(0))
        .map(|(_, c)| c.clone())
        .collect()
}

/// Tells if the function at `root` has no count. Such a function has a tail jump at stack
/// height 0 to an import with no Tier-0 prototype, or to a function with no count. The jump
/// passes its registers on. A thunk of such an import is such a function. The walk takes at most [`MAX_SOLVE`]
/// functions.
///
/// # Errors
///
/// Returns [`FirError::Fuel`] when the fuel runs out.
fn is_open(
    program: &Program,
    conv: &CallConv,
    root: u64,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Result<bool, FirError> {
    let mut seen = BTreeSet::from([root]);
    let mut stack = vec![root];
    while let Some(at) = stack.pop() {
        let tails = match memo.bases.get(&at) {
            Some(Some(b)) => b.tails.clone(),
            _ => continue,
        };
        for c in tails {
            match c {
                Callee::Import => return Ok(true),
                Callee::Func(t) if seen.len() < MAX_SOLVE && seen.insert(t) => {
                    if let Entry::Vacant(slot) = memo.bases.entry(t) {
                        slot.insert(build(program, conv, t, fuel)?);
                    }
                    stack.push(t);
                }
                _ => {}
            }
        }
    }
    Ok(false)
}

/// Gives, for each block, the registers of `regs` that a path from the entry to the start of
/// the block does not write.
fn unwritten(ir: &FuncIr, blocks: &[BlockUse], regs: &BTreeSet<Loc>) -> Vec<BTreeSet<Loc>> {
    let cfg = &ir.body.cfg;
    let order = rpo(cfg);
    let mut at: Vec<BTreeSet<Loc>> = vec![BTreeSet::new(); blocks.len()];
    if let Some(entry) = at.get_mut(cfg.entry().index()) {
        entry.clone_from(regs);
    }
    let rounds = order.len().saturating_mul(4).saturating_add(8);
    for _ in 0..rounds {
        let mut changed = false;
        for node in &order {
            let (Some(b), Some(set)) = (blocks.get(node.index()), at.get(node.index())) else {
                continue;
            };
            let out: Vec<Loc> = set
                .iter()
                .filter(|l| !b.defs.contains(l))
                .copied()
                .collect();
            for s in cfg.succs(*node) {
                if let Some(next) = at.get_mut(s.index()) {
                    for l in &out {
                        changed |= next.insert(*l);
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    at
}

/// The result of one solve: the parameters and the live-in registers of the function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Solved {
    /// The parameters.
    pub params: Params,
    /// The live-in registers, with the reads of the calls.
    pub live: BTreeSet<Loc>,
    /// The function has no count (see `is_open`). A tail jump passes its registers on to an
    /// import with no Tier-0 prototype.
    pub open: bool,
}

/// The memo of the solves of one caller.
///
/// It holds the base of each function by entry, and the result of each solve. The base of a
/// function depends only on the program, so all the solves of one caller can share it. The fuel of a solve takes no unit for a base in the memo.
#[derive(Debug, Default)]
pub struct Memo {
    /// The base of each function. A function whose IR does not build has `None`.
    bases: BTreeMap<u64, Option<Base>>,
    /// The result of each solve, by the entry of its function.
    solved: BTreeMap<u64, Solved>,
}

/// Builds the base of the function at `addr`. A function whose IR does not build gives
/// `None`.
///
/// # Errors
///
/// Returns [`FirError::Fuel`] when the fuel runs out.
fn build(
    program: &Program,
    conv: &CallConv,
    addr: u64,
    fuel: &mut Fuel,
) -> Result<Option<Base>, FirError> {
    match fir::build(program, FuncId(Address::ram(addr)), &Opts::DEFAULT, fuel) {
        Ok(ir) => Ok(Some(Base::new(program, conv, ir, fuel)?)),
        Err(FirError::Fuel(e)) => Err(FirError::Fuel(e)),
        Err(_) => Ok(None),
    }
}

/// Recovers the parameters of the published function `id` with the reads of its calls and
/// tail calls (see the module doc).
///
/// # Errors
///
/// Returns the errors of [`solve_in`].
pub fn solve(
    program: &Program,
    id: FuncId,
    conv: &CallConv,
    fuel: &mut Fuel,
) -> Result<Params, FirError> {
    solve_in(program, id, conv, &mut Memo::default(), fuel).map(|s| s.params)
}

/// Gives the functions of the solve of `root` in callee-first order (step 1 of the module
/// doc). It builds each base that `memo` does not hold.
///
/// # Errors
///
/// Returns [`FirError::Fuel`] when the fuel runs out.
fn members(
    program: &Program,
    conv: &CallConv,
    root: u64,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Result<Vec<u64>, FirError> {
    let bases = &mut memo.bases;
    let mut members = BTreeSet::from([root]);
    let mut stack = vec![(root, 0usize)];
    let mut order = Vec::new();
    while let Some(top) = stack.last_mut() {
        let (at, k) = *top;
        let next = bases
            .get(&at)
            .and_then(Option::as_ref)
            .and_then(|b| b.children.get(k))
            .copied();
        let Some(t) = next else {
            order.push(at);
            stack.pop();
            continue;
        };
        top.1 = k.saturating_add(1);
        if members.contains(&t) || members.len() >= MAX_SOLVE {
            continue;
        }
        if let Entry::Vacant(slot) = bases.entry(t) {
            slot.insert(build(program, conv, t, fuel)?);
        }
        if bases.get(&t).is_some_and(Option::is_some) {
            members.insert(t);
            stack.push((t, 0));
        }
    }
    Ok(order)
}

/// Recovers the parameters of the published function `id` like [`solve`], with the bases
/// and the results of `memo`. The result goes into `memo`.
///
/// # Errors
///
/// Returns the [`FirError`] of the function IR of `id`, and [`FirError::Fuel`] when the fuel
/// runs out. A callee whose IR does not build reads no register.
pub fn solve_in(
    program: &Program,
    id: FuncId,
    conv: &CallConv,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Result<Solved, FirError> {
    let root = id.0.off;
    if let Some(found) = memo.solved.get(&root) {
        return Ok(found.clone());
    }
    if !memo.bases.get(&root).is_some_and(Option::is_some) {
        let ir = fir::build(program, id, &Opts::DEFAULT, fuel)?;
        let base = Base::new(program, conv, ir, fuel)?;
        memo.bases.insert(root, Some(base));
    }
    let order = members(program, conv, root, memo, fuel)?;
    let bases = &memo.bases;
    let mut state: BTreeMap<u64, Solved> = BTreeMap::new();
    for u in &order {
        if let Some(Some(b)) = bases.get(u) {
            let live = b.live.clone();
            let params = b.params;
            state.insert(
                *u,
                Solved {
                    params,
                    live,
                    open: false,
                },
            );
        }
    }
    let rounds = order.len().saturating_mul(4).saturating_add(4);
    for _ in 0..rounds {
        let mut changed = false;
        for u in &order {
            fuel.tick()?;
            let Some(Some(base)) = bases.get(u) else {
                continue;
            };
            let live = base.live_with(&base.reads(conv, &state), fuel)?;
            if state.get(u).is_some_and(|s| s.live == live) {
                continue;
            }
            let params = cc::from_live(&base.ir, conv, &live);
            state.insert(
                *u,
                Solved {
                    params,
                    live,
                    open: false,
                },
            );
            changed = true;
        }
        if !changed {
            break;
        }
    }
    let mut out = state.remove(&root).unwrap_or_default();
    out.open = is_open(program, conv, root, memo, fuel)?;
    memo.solved.insert(root, out.clone());
    Ok(out)
}

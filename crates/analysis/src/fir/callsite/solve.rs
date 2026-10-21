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

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId, OutOfFuel};
use ghidorah_db::{Program, Types};
use ghidorah_ir::{Loc, OpId, rpo};
use ghidorah_types::CallConv;

use super::{arg_regs, call_targets, fixed, from_sig};
use crate::cc::{self, BlockUse, Params, loc_of};
use crate::fir::{self, FirError, FuncIr, Opts};

/// The largest count of functions of one [`solve`].
pub const MAX_SOLVE: usize = 32;

/// What the facts say about the callee of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Callee {
    /// The callee reads these registers.
    Fixed(Vec<Loc>),
    /// A function with no parameter fact. The solve recovers it.
    Func(u64),
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
            .map_or(Callee::Unknown, |p| {
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
        let blocks = cc::summaries(&ir, conv, false);
        let mut known: BTreeMap<u64, Callee> = BTreeMap::new();
        let mut callees = BTreeMap::new();
        for (id, t) in call_targets(&ir) {
            let c = known
                .entry(t)
                .or_insert_with(|| callee_of(program, conv, t))
                .clone();
            callees.insert(id, c);
        }
        let ops = blocks.iter().map(|b| b.free.len()).sum::<usize>();
        let cost = u64::try_from(blocks.len().saturating_add(ops)).unwrap_or(u64::MAX);
        let mut base = Self {
            ir,
            blocks,
            callees,
            live: BTreeSet::new(),
            params: Params::default(),
            children: Vec::new(),
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
    fn reads(&self, conv: &CallConv, state: &BTreeMap<u64, State>) -> BTreeMap<OpId, Vec<Loc>> {
        let mut out = BTreeMap::new();
        for (id, c) in &self.callees {
            let regs = match c {
                Callee::Fixed(r) => r.clone(),
                Callee::Func(t) => match state.get(t) {
                    Some(n) => arg_regs(conv, &n.params, Some(&n.live)),
                    None => continue,
                },
                Callee::Unknown => continue,
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

/// The state of one function in the rounds of a solve.
struct State {
    /// The live-in registers so far.
    live: BTreeSet<Loc>,
    /// The parameters so far.
    params: Params,
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
/// Returns the [`FirError`] of the function IR of `id`, and [`FirError::Fuel`] when the fuel
/// runs out. A callee whose IR does not build reads no register.
pub fn solve(
    program: &Program,
    id: FuncId,
    conv: &CallConv,
    fuel: &mut Fuel,
) -> Result<Params, FirError> {
    let root = id.0.off;
    let ir = fir::build(program, id, &Opts::DEFAULT, fuel)?;
    let mut bases: BTreeMap<u64, Option<Base>> = BTreeMap::new();
    bases.insert(root, Some(Base::new(program, conv, ir, fuel)?));
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
        if let std::collections::btree_map::Entry::Vacant(slot) = bases.entry(t) {
            slot.insert(build(program, conv, t, fuel)?);
        }
        if bases.get(&t).is_some_and(Option::is_some) {
            members.insert(t);
            stack.push((t, 0));
        }
    }
    let mut state: BTreeMap<u64, State> = BTreeMap::new();
    for u in &members {
        if let Some(Some(b)) = bases.get(u) {
            let live = b.live.clone();
            state.insert(
                *u,
                State {
                    live,
                    params: b.params,
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
            state.insert(*u, State { live, params });
            changed = true;
        }
        if !changed {
            break;
        }
    }
    Ok(state.get(&root).map_or_else(Params::default, |s| s.params))
}

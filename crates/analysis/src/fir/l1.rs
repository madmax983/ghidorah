//! The L1 extension of the function IR builder (design Sections 6.4 and 7.12, WP-21).
//!
//! [`lift`] takes the L0 IR of a function. It makes the L1 form in three steps:
//!
//! 1. Each tail jump becomes a call in place: a `Jump` to an address outside the body, at the
//!    end of a block with no successor. So the argument registers stay live at the jump. A
//!    tail call of an import ([`crate::tailcall::import_jumps`]) becomes a call of its slot
//!    load in the same way.
//! 2. Braun SSA ([`ghidorah_ir::ssa::build`]) with the location sets of [`ssa_opts`].
//! 3. The L1 passes in fixed order ([`ghidorah_ir::passes::run`]) with the given switches.
//!
//! [`ssa_opts`] applies the calling convention:
//!
//! | Op | Locations |
//! |---|---|
//! | `Ret` reads | the first integer return register |
//! | A call reads | the integer and floating argument registers, the varargs register when the callee can take a variable argument list, and its stack arguments ([`callsite`]) |
//! | A call writes | each general register that the callee does not keep, each XMM register and the flags |
//! | A call pops | 8 bytes from `rsp` on return: the return address that the call pushes |
//!
//! The result is derived data: the journal never holds it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Fuel, FuncId};
use ghidorah_db::Program;
use ghidorah_ir::passes::{self, Report, Switches};
use ghidorah_ir::ssa::{self, Ssa, SsaError};
use ghidorah_ir::{Arg, Loc, LocSet, Node, Opc};
use ghidorah_types::CallConv;

use super::{FirError, FuncIr, Opts, callsite};
use crate::cc::{conv_of, loc_of};
use crate::jumptable::{self, GuardInfo};

/// The L1 form of one function, with its L0 IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Ir {
    /// The L0 IR. Its arena has no tail-jump rewrite.
    pub l0: FuncIr,
    /// The L1 form. The instruction ops keep the index of their L0 op.
    pub ssa: Ssa,
    /// The change counts of the passes.
    pub report: Report,
    /// The addresses of the tail jumps that became calls.
    pub tail_calls: BTreeSet<u64>,
    /// The guard of each indirect jump with a jump table, by the address of the jump.
    pub guards: BTreeMap<u64, GuardInfo>,
}

/// The error of [`lift`] and [`build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L1Error {
    /// The L0 IR does not build.
    Fir(FirError),
    /// The SSA build or a pass fails.
    Ssa(SsaError),
}

impl fmt::Display for L1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fir(e) => write!(f, "The L0 IR does not build: {e}"),
            Self::Ssa(e) => write!(f, "The L1 form does not build: {e}"),
        }
    }
}

impl std::error::Error for L1Error {}

impl From<FirError> for L1Error {
    fn from(e: FirError) -> Self {
        Self::Fir(e)
    }
}

impl From<SsaError> for L1Error {
    fn from(e: SsaError) -> Self {
        Self::Ssa(e)
    }
}

/// Gives the set of the register names of a convention table.
fn regs(names: &[&str]) -> LocSet {
    names.iter().filter_map(|n| loc_of(n)).collect()
}

/// Gives the location sets of the flow ops for the convention `conv` (see the module table).
#[must_use]
pub fn ssa_opts(conv: &CallConv) -> ssa::Opts {
    let ret_uses = regs(conv.int_ret.get(..1).unwrap_or_default());
    let call_uses = regs(conv.int_args)
        .union(regs(conv.float_args))
        .union(regs(conv.varargs_reg.as_slice()));
    let kept = regs(conv.callee_saved);
    let mut call_defs: LocSet = (0..16u8)
        .filter_map(Loc::gpr)
        .filter(|l| !kept.contains(*l))
        .collect();
    call_defs = call_defs.union((0..16u8).filter_map(Loc::xmm).collect());
    let _ = call_defs.insert(Loc::Flags);
    ssa::Opts {
        ret_uses,
        call_uses,
        call_defs,
        call_pop: Some((Loc::RSP, 8)),
    }
}

/// Rewrites each tail jump of `l0` into a call. `imports` holds the addresses of the
/// indirect jumps that call an import. Gives the arena and the jump addresses.
fn rewrite_tail_jumps(l0: &FuncIr, imports: &BTreeSet<u64>) -> (ghidorah_ir::Arena, BTreeSet<u64>) {
    let mut arena = l0.arena.clone();
    let mut tails = BTreeSet::new();
    for (i, b) in l0.body.blocks.iter().enumerate() {
        let Ok(n) = u32::try_from(i) else {
            continue;
        };
        if !l0.body.cfg.succs(Node(n)).is_empty() || b.count == 0 {
            continue;
        }
        let last = b.first.saturating_add(b.count.saturating_sub(1));
        let Some(span) = usize::try_from(last)
            .ok()
            .and_then(|k| arena.insns().get(k))
            .copied()
        else {
            continue;
        };
        let Some(k) = span
            .count
            .checked_sub(1)
            .and_then(|c| span.first.checked_add(c))
        else {
            continue;
        };
        let Some(op) = usize::try_from(k)
            .ok()
            .and_then(|k| arena.ops_mut().get_mut(k))
        else {
            continue;
        };
        let outside =
            op.a.first()
                .and_then(|a| a.as_k())
                .is_some_and(|t| l0.arena.insn_index(t).is_none());
        let import = op.opc == Opc::JumpInd && imports.contains(&span.addr);
        if (op.opc == Opc::Jump && outside) || import {
            op.opc = Opc::Call;
            op.a = [op.a[0], Arg::Nil, Arg::Nil];
            tails.insert(span.addr);
        }
    }
    (arena, tails)
}

/// Makes the L1 form of the L0 IR `l0` under the convention `conv`.
///
/// Each op of the SSA build and each step of a pass takes one unit of `fuel`.
///
/// # Errors
///
/// Returns [`L1Error::Ssa`] when the SSA build or a pass fails, for example when the fuel
/// runs out.
pub fn lift(
    l0: FuncIr,
    conv: &CallConv,
    switches: &Switches,
    fuel: &mut Fuel,
) -> Result<L1Ir, L1Error> {
    lift_with(l0, conv, &|_| None, &BTreeSet::new(), switches, fuel)
}

/// Makes the L1 form like [`lift`], with the arity facts of the callees.
///
/// `callee` gives the arity of the direct callee at an address. A call of a callee with an
/// arity reads only its argument registers ([`callsite::uses`]). `imports` holds the
/// addresses of the indirect jumps that are tail calls of an import.
///
/// # Errors
///
/// Returns the errors of [`lift`].
pub fn lift_with(
    l0: FuncIr,
    conv: &CallConv,
    callee: &dyn Fn(u64) -> Option<callsite::Arity>,
    imports: &BTreeSet<u64>,
    switches: &Switches,
    fuel: &mut Fuel,
) -> Result<L1Ir, L1Error> {
    let (arena, tail_calls) = rewrite_tail_jumps(&l0, imports);
    let calls = callsite::uses(&l0, &arena, conv, callee);
    let mut ssa = ssa::build_with(arena, l0.body.clone(), &ssa_opts(conv), &calls, fuel)?;
    for (&index, &from) in &l0.fused_from {
        ssa.note_fused(index, from);
    }
    let report = passes::run(&mut ssa, switches, fuel)?;
    let guards = jumptable::sites(&l0)
        .into_iter()
        .filter_map(|site| Some((site, jumptable::guard_info(&l0, site)?)))
        .collect();
    Ok(L1Ir {
        l0,
        ssa,
        report,
        tail_calls,
        guards,
    })
}

/// Builds the L1 form of the published function `id` with the convention of its format.
///
/// # Errors
///
/// Returns [`L1Error::Fir`] when the L0 IR does not build, and the errors of [`lift`].
pub fn build(
    program: &Program,
    id: FuncId,
    opts: &Opts,
    switches: &Switches,
    fuel: &mut Fuel,
) -> Result<L1Ir, L1Error> {
    let mut memo = callsite::Memo::default();
    build_in(program, id, opts, switches, &mut memo, fuel)
}

/// Builds the L1 form like [`build`], with the solve memo `memo`.
///
/// The parameter recovery of each callee takes its fuel from `fuel`
/// ([`callsite::callee_arity_in`]). The callees share the bases of `memo`, so a function that
/// many callees call builds once.
///
/// # Errors
///
/// Returns the errors of [`build`], and [`FirError::Fuel`] when a callee recovery uses the
/// last unit of `fuel`.
pub fn build_in(
    program: &Program,
    id: FuncId,
    opts: &Opts,
    switches: &Switches,
    memo: &mut callsite::Memo,
    fuel: &mut Fuel,
) -> Result<L1Ir, L1Error> {
    let l0 = super::build(program, id, opts, fuel)?;
    let targets: BTreeSet<u64> = callsite::call_targets(&l0).into_values().collect();
    let conv = conv_of(program);
    let mut arity: BTreeMap<u64, callsite::Arity> = BTreeMap::new();
    for t in targets {
        let found =
            callsite::callee_arity_in(program, t, conv, memo, fuel).map_err(FirError::Fuel)?;
        if let Some(a) = found {
            arity.insert(t, a);
        }
    }
    let imports = crate::tailcall::import_jumps(program, id, &l0);
    lift_with(
        l0,
        conv,
        &|t| arity.get(&t).copied(),
        &imports,
        switches,
        fuel,
    )
}

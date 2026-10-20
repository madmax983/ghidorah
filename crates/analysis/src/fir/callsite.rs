//! The location uses of each call of the L1 form (design Sections 6.4 and 7.10).
//!
//! [`uses`] gives each call op its own use list in place of the uses of the convention:
//!
//! | Uses | Rule |
//! |---|---|
//! | the argument registers | every call |
//! | the varargs register (`al`) | only a call whose callee can take a variable argument list |
//! | the stack arguments | the slots `Stack(k + 8j)` above the stack pointer at the call that the block writes before the call, while no slot is missing |
//!
//! `k` is the stack offset before the call plus the first stack argument offset of the
//! convention, less the 8 bytes of the return address. The block writes the slots of one call
//! after the call before it. So a slot of an earlier call is not an argument again. A push of a callee-saved register in the entry block is not an argument.
//! A slot that escapes stays in memory, so it has no `Stack` location.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId};
use ghidorah_db::{Program, Types};
use ghidorah_ir::{Arg, Loc, Opc};
use ghidorah_types::CallConv;

use super::FuncIr;
use super::l1::ssa_opts;
use crate::cc::{loc_of, params};

/// The largest count of stack arguments of one call.
pub const MAX_STACK_ARGS: i64 = 16;

/// The fuel of the parameter recovery of one callee.
const CALLEE_FUEL: u64 = 1_000_000;

/// Gives the use list of each call op of `l0` (see the module doc). `variadic` tells if the
/// direct callee at an address can take a variable argument list. An indirect call can.
#[must_use]
pub fn uses(
    l0: &FuncIr,
    conv: &CallConv,
    variadic: &dyn Fn(u64) -> bool,
) -> BTreeMap<u32, Vec<Loc>> {
    let base: Vec<Loc> = ssa_opts(conv).call_uses.iter().collect();
    let al: BTreeSet<Loc> = conv.varargs_reg.iter().filter_map(|r| loc_of(r)).collect();
    let first = i64::from(conv.stack_arg_offset).saturating_sub(8);
    let saved: BTreeSet<i64> = l0
        .frame
        .iter()
        .flat_map(|f| f.saved.iter().map(|(_, k)| *k))
        .collect();
    let mut out = BTreeMap::new();
    for block in &l0.body.blocks {
        let first_insn = usize::try_from(block.first).unwrap_or(usize::MAX);
        let count = usize::try_from(block.count).unwrap_or(0);
        let mut written: BTreeSet<i64> = BTreeSet::new();
        for span in l0.arena.insns().iter().skip(first_insn).take(count) {
            for k in 0..span.count {
                let Some(index) = span.first.checked_add(k) else {
                    continue;
                };
                let Some(op) = l0.arena.op(index) else {
                    continue;
                };
                match op.opc {
                    Opc::Put => {
                        if let Some(Loc::Stack(slot)) = op.a[0].as_loc()
                            && !saved.contains(&i64::from(slot))
                        {
                            written.insert(i64::from(slot));
                        }
                    }
                    Opc::Call | Opc::CallInd => {
                        let direct = match (op.opc, op.a[0]) {
                            (Opc::Call, Arg::K(t)) => Some(t.get()),
                            _ => None,
                        };
                        let mut list = base.clone();
                        if direct.is_some_and(|t| !variadic(t)) {
                            list.retain(|l| !al.contains(l));
                        }
                        let sp = l0.frame.as_ref().and_then(|f| f.sp_at(span.addr));
                        if let Some(sp) = sp {
                            let start = sp.saturating_add(first);
                            for j in 0..MAX_STACK_ARGS {
                                let off = start.saturating_add(j.saturating_mul(8));
                                let Ok(slot) = i32::try_from(off) else {
                                    break;
                                };
                                if !written.contains(&off) {
                                    break;
                                }
                                list.push(Loc::Stack(slot));
                            }
                        }
                        out.insert(index, list);
                        written.clear();
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// Tells if the function or import at `addr` can take a variable argument list.
///
/// An import uses its Tier-0 prototype. A function uses its parameters: its signature, its
/// prototype or the recovery. An address with no facts can take a variable argument list.
#[must_use]
pub fn callee_varargs(program: &Program, addr: u64) -> bool {
    let at = Address::ram(addr);
    if let Some(row) = program
        .imports()
        .values()
        .find(|r| r.stub == Some(at) || (r.stub.is_none() && r.slot == Some(at)))
    {
        return row
            .id
            .name()
            .and_then(Types::prototype)
            .is_none_or(|p| p.sig.variadic);
    }
    params(program, FuncId(at), &mut Fuel::new(CALLEE_FUEL)).map_or(true, |(p, _)| p.varargs)
}

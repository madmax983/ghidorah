//! The location uses of each call of the L1 form (design Sections 6.4 and 7.10).
//!
//! [`uses`] gives each call op its own use list in place of the uses of the convention:
//!
//! | Uses | Rule |
//! |---|---|
//! | the integer argument registers | the count of the callee, or all of them for a callee with no count or a variadic callee |
//! | the floating argument registers | every call |
//! | the varargs register (`al`) | only a call whose callee can take a variable argument list |
//! | the stack arguments | the slots `Stack(k + 8j)` above the stack pointer at the call that the block writes before the call, while no slot is missing |
//!
//! So a register that the callee does not read keeps no value alive. A loop with a call then
//! has no phi of an argument register that it never sets.
//!
//! `k` is the stack offset before the call plus the first stack argument offset of the
//! convention, less the 8 bytes of the return address. The block writes the slots of one call
//! after the call before it. So a slot of an earlier call is not an argument again. A push of
//! a callee-saved register in the entry block is not an argument. A slot that escapes stays
//! in memory, so it has no `Stack` location.
//!
//! A callee has a count when its signature, its Tier-0 prototype or the recovery gives one
//! ([`callee_arity_in`]). The call then keeps only that count of integer argument registers.
//! A callee with no count reads all of them. An unknown target has no count. So has an import
//! with no Tier-0 prototype. So has a function whose tail jump at stack height 0 passes its
//! registers on to such an import, as a thunk does.
//!
//! [`solve`] recovers the parameters of a function with the reads of its calls and tail
//! calls (the `solve` module).
//!
//! A callee is a direct call target or the target of a tail jump out of the body. An indirect
//! call can load its target from an import slot. Then the slot is the callee. The same is true
//! for an indirect jump at stack height 0.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Fuel, FuncId, OutOfFuel};
use ghidorah_db::{Program, Types};
use ghidorah_ir::{Arena, Arg, Loc, OpId, Opc};
use ghidorah_types::CallConv;

use super::l1::ssa_opts;
use super::{FirError, FuncIr};
use crate::cc::{ParamSource, Params, conv_of, loc_of};

mod slots;
mod solve;

pub(crate) use slots::{declared, fixed, proto_params};
pub use slots::{fixed_slots, sig_slots};
pub use solve::{MAX_SOLVE, Memo, Solved, solve, solve_in};

/// The largest count of stack arguments of one call.
pub const MAX_STACK_ARGS: i64 = 16;

/// The largest fuel of the parameter recovery of one callee.
pub const CALLEE_FUEL: u64 = 1_000_000;

/// The arguments of a direct callee that the facts know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Arity {
    /// The count of the integer argument registers that the callee reads.
    pub int: u8,
    /// The callee can take a variable argument list.
    pub varargs: bool,
}

/// Gives the use list of each call op of `arena` (see the module doc).
///
/// `arena` is the arena of `l0` with its tail jumps as calls. `callee` gives the arity of the
/// direct callee at an address, or `None` for a callee with no count. The callee of an
/// indirect call through an import slot is the slot. Another indirect call has no facts.
#[must_use]
pub fn uses(
    l0: &FuncIr,
    arena: &Arena,
    conv: &CallConv,
    callee: &dyn Fn(u64) -> Option<Arity>,
) -> BTreeMap<u32, Vec<Loc>> {
    let base: Vec<Loc> = ssa_opts(conv).call_uses.iter().collect();
    let al: BTreeSet<Loc> = conv.varargs_reg.iter().filter_map(|r| loc_of(r)).collect();
    let ints: Vec<Loc> = conv.int_args.iter().filter_map(|r| loc_of(r)).collect();
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
        for span in arena.insns().iter().skip(first_insn).take(count) {
            for k in 0..span.count {
                let Some(index) = span.first.checked_add(k) else {
                    continue;
                };
                let Some(op) = arena.op(index) else {
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
                            (_, a) => slot_load(arena, a, op.id.addr),
                        };
                        let mut list = base.clone();
                        if let Some(a) = direct.and_then(callee).filter(|a| !a.varargs) {
                            let keep = usize::from(a.int);
                            let unread: BTreeSet<Loc> = ints.iter().skip(keep).copied().collect();
                            list.retain(|l| !al.contains(l) && !unread.contains(l));
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

/// Gives the arity of the function or import at `addr`: a stub or a slot of an import, or a
/// function entry.
///
/// An import uses its Tier-0 prototype. A function uses its parameters: its signature, its
/// prototype or the recovery. A function with stack parameters reads every integer argument
/// register. An address with no facts gives `None`.
#[must_use]
pub fn callee_arity(program: &Program, addr: u64, conv: &CallConv) -> Option<Arity> {
    let mut fuel = Fuel::new(CALLEE_FUEL);
    callee_arity_in(program, addr, conv, &mut Memo::default(), &mut fuel)
        .ok()
        .flatten()
}

/// Gives the arity of the function or import at `addr` like [`callee_arity`], with the solve
/// memo `memo` of the caller.
///
/// The recovery takes its fuel from `fuel`, at most [`CALLEE_FUEL`] units. A recovery that
/// needs more units gives `None`. So does a function with no count ([`Solved::open`]), and an
/// import with no Tier-0 prototype.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out.
pub fn callee_arity_in(
    program: &Program,
    addr: u64,
    conv: &CallConv,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Result<Option<Arity>, OutOfFuel> {
    let at = Address::ram(addr);
    if let Some(row) = program
        .imports()
        .values()
        .find(|r| r.stub == Some(at) || r.slot == Some(at))
    {
        return Ok(row.id.name().and_then(Types::prototype).map(|proto| {
            let p = proto_params(program, conv, &proto.sig);
            Arity {
                int: p.int,
                varargs: p.varargs,
            }
        }));
    }
    let mut part = Fuel::new(fuel.remaining().min(CALLEE_FUEL));
    let found = param_facts(program, FuncId(at), memo, &mut part);
    fuel.take(part.used())?;
    let p = match found {
        Ok(f) if f.open => return Ok(None),
        Ok(f) => f.params,
        Err(FirError::Fuel(e)) if fuel.is_empty() => return Err(e),
        Err(_) => return Ok(None),
    };
    let regs = u8::try_from(conv.int_args.len()).unwrap_or(u8::MAX);
    let int = if p.stack > 0 {
        regs
    } else if conv.positional {
        p.int.saturating_add(p.float)
    } else {
        p.int
    };
    Ok(Some(Arity {
        int,
        varargs: p.varargs,
    }))
}

/// The parameter facts of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamFacts {
    /// The parameters.
    pub params: Params,
    /// The source of the parameters.
    pub source: ParamSource,
    /// The live-in registers of a recovered count, with the reads of the calls. A signature
    /// or a prototype gives `None`.
    pub live: Option<BTreeSet<Loc>>,
    /// The function has no count ([`Solved::open`]). A signature or a prototype gives `false`.
    pub open: bool,
}

/// Gives the parameter facts of the published function `id`: its signature, then the Tier-0
/// prototype of its name, then the solve over `memo`.
///
/// # Errors
///
/// Returns [`FirError::NoFunc`] when no function starts at `id`, and the errors of
/// [`solve_in`].
pub fn param_facts(
    program: &Program,
    id: FuncId,
    memo: &mut Memo,
    fuel: &mut Fuel,
) -> Result<ParamFacts, FirError> {
    if program.func(id).is_none() {
        return Err(FirError::NoFunc(id));
    }
    if let Some((params, source)) = fixed(program, id) {
        return Ok(ParamFacts {
            params,
            source,
            live: None,
            open: false,
        });
    }
    let s = solve_in(program, id, conv_of(program), memo, fuel)?;
    Ok(ParamFacts {
        params: s.params,
        source: ParamSource::Recovered,
        live: Some(s.live),
        open: s.open,
    })
}

/// Gives the import slot that the value `a` loads: a 64-bit `Load` of a constant address in
/// the instruction at `addr`.
#[must_use]
pub fn slot_load(arena: &Arena, a: Arg, addr: u64) -> Option<u64> {
    let op = arena.op(arena.def_of(a.as_v()?)?)?;
    let load = op.opc == Opc::Load && op.w == 64 && op.id.addr == addr;
    load.then(|| op.a[0].as_k()).flatten()
}

/// Gives the callee address of each call and tail jump of `fir` by op (see the module doc).
#[must_use]
pub fn call_targets(fir: &FuncIr) -> BTreeMap<OpId, u64> {
    let mut out = BTreeMap::new();
    for op in fir.arena.ops() {
        let at = op.id.addr;
        let height = fir.frame.as_ref().and_then(|f| f.sp_at(at));
        let target = match (op.opc, op.a[0].as_k()) {
            (Opc::Call, Some(t)) => Some(t),
            (Opc::Jump, Some(t)) => fir.arena.insn_index(t).is_none().then_some(t),
            (Opc::Call | Opc::CallInd, None) => slot_load(&fir.arena, op.a[0], at),
            (Opc::JumpInd, None) if height == Some(0) => slot_load(&fir.arena, op.a[0], at),
            _ => None,
        };
        if let Some(t) = target {
            out.insert(op.id, t);
        }
    }
    out
}

/// Gives the argument registers that a call reads, in slot order.
///
/// The callee has the parameters `p`. `live` holds the live-in registers of a recovered
/// callee. In a positional convention, slot n is a floating slot when only its floating
/// register is live-in there.
#[must_use]
pub fn arg_regs(conv: &CallConv, p: &Params, live: Option<&BTreeSet<Loc>>) -> Vec<Loc> {
    let ints: Vec<Loc> = conv.int_args.iter().filter_map(|n| loc_of(n)).collect();
    let floats: Vec<Loc> = conv.float_args.iter().filter_map(|n| loc_of(n)).collect();
    let has = |l: Option<&Loc>| l.is_some_and(|l| live.is_some_and(|s| s.contains(l)));
    if conv.positional {
        let used = usize::from(p.int.saturating_add(p.float));
        let slots = if p.stack > 0 { ints.len() } else { used };
        return (0..slots.min(ints.len()))
            .filter_map(|k| {
                let float = has(floats.get(k)) && !has(ints.get(k));
                if float { floats.get(k) } else { ints.get(k) }.copied()
            })
            .collect();
    }
    let n = if p.stack > 0 {
        ints.len()
    } else {
        usize::from(p.int)
    };
    let mut out: Vec<Loc> = ints.into_iter().take(n).collect();
    out.extend(floats.into_iter().take(usize::from(p.float)));
    out
}

/// Gives the varargs flag that a base fact sets for the function `entry`: its agent
/// signature, then the Tier-0 prototype of its base symbol name.
pub(crate) fn known_varargs(program: &Program, entry: u64) -> Option<bool> {
    let addr = Address::ram(entry);
    if let Some(sig) = program
        .base()
        .funcs()
        .get(FuncId(addr))
        .and_then(|f| f.sig.as_ref())
        .and_then(|s| program.types().sig(s.value))
    {
        return Some(sig.variadic);
    }
    let name = program.base().symbols().primary(addr)?;
    Types::prototype(&name.name.value).map(|p| p.sig.variadic)
}

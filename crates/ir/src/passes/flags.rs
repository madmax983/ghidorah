//! The flag passes `cond_through_phi` and `materialize_flags`.
//!
//! `cond_through_phi` takes `Cond(cc, p)` where `p` is a phi of flags words. Each argument of
//! `p` must be a constant, `p` itself or a `Flags` thunk that [`fuse`] can fuse with `cc`.
//! Then each predecessor gets the compare at its tail, and a new 1-bit phi of the compares
//! takes the place of the `Cond`.
//!
//! `materialize_flags` turns each other `Cond` into bit tests on the flags word:
//!
//! | Conditions | Ops |
//! |---|---|
//! | `o b e be s p` and their negations | `TestNZ` or `TestZ` of the flags word and a mask |
//! | `l ge` | `t = f ^ (f >> 4)`, then a test of bit 7 (SF xor OF) |
//! | `le g` | The test of `l` or `ge`, joined with the ZF test by `Or` or `And` |

use std::collections::BTreeMap;

use ghidorah_base::Fuel;

use crate::fuse::fuse;
use crate::graph::Node;
use crate::op::{Arg, Cc, Opc, Val};
use crate::sem::{CF, OF, PF, SF, ZF, x86_cond};
use crate::ssa::{Anchor, Ssa, SsaError};

/// One argument of a new compare phi.
#[derive(Debug, Clone, Copy)]
enum Slot {
    /// A known condition.
    Known(bool),
    /// The new phi itself.
    Own,
    /// A compare at the end of a predecessor.
    Compare {
        /// The anchor of the compare.
        anchor: Anchor,
        /// The compare opcode.
        opc: Opc,
        /// The width of the compare.
        w: u8,
        /// The operands.
        x: Arg,
        /// The operands.
        y: Arg,
    },
}

/// A planned change of `cond_through_phi`.
struct Plan {
    cond: u32,
    out: Val,
    key: (Val, u8),
    block: Node,
    slots: Vec<Slot>,
}

/// Gives the slot of one phi argument, or `None` when no compare applies.
fn slot_of(ssa: &Ssa, cc: Cc, phi: Val, arg: Arg, anchor: Anchor) -> Option<Slot> {
    match ssa.root(arg) {
        Arg::K(imm) => {
            let word = u16::try_from(imm.get() & 0xffff).ok()?;
            Some(Slot::Known(x86_cond(cc, word)))
        }
        Arg::V(v) if v == phi => Some(Slot::Own),
        Arg::V(v) => {
            let thunk = ssa.live_def(v)?;
            let op = thunk
                .flag_op()
                .filter(|_| matches!(thunk.w, 8 | 16 | 32 | 64))?;
            let (opc, x, y) = fuse(op, cc, ssa.root(thunk.a[0]), ssa.root(thunk.a[1]))?;
            Some(Slot::Compare {
                anchor,
                opc,
                w: thunk.w,
                x,
                y,
            })
        }
        Arg::Nil | Arg::L(_) => None,
    }
}

/// Plans the change of one `Cond` op, or gives `None`.
fn plan_one(ssa: &Ssa, index: u32) -> Option<Plan> {
    let op = ssa.arena().op(index)?;
    let (Opc::Cond, Some(cc), Some(out)) = (op.opc, op.cc(), op.out) else {
        return None;
    };
    let Arg::V(phi) = ssa.root(op.a[0]) else {
        return None;
    };
    let phi_index = ssa.arena().def_of(phi)?;
    let phi_op = ssa.live_def(phi).filter(|p| p.opc == Opc::Phi)?;
    let Some(Anchor::Head(block)) = ssa.place(phi_index) else {
        return None;
    };
    let preds = ssa.preds(block);
    let args = ssa.arena().phi_args(phi_op)?;
    let mut slots = Vec::with_capacity(args.len());
    for (j, &arg) in args.iter().enumerate() {
        let anchor = preds.get(j).map_or(Anchor::Start, |&p| Anchor::Tail(p));
        slots.push(slot_of(ssa, cc, phi, arg, anchor)?);
    }
    Some(Plan {
        cond: index,
        out,
        key: (phi, cc.code()),
        block,
        slots,
    })
}

/// Makes the changes of `cond_through_phi` on `ssa`. Gives the count of changed `Cond` ops.
fn apply_through(ssa: &mut Ssa, plans: &[Plan]) -> Result<u64, SsaError> {
    let mut made: BTreeMap<(Val, u8), Val> = BTreeMap::new();
    let mut compares: BTreeMap<(Anchor, Opc, u8, Arg, Arg), Arg> = BTreeMap::new();
    let mut repl = BTreeMap::new();
    for plan in plans {
        if let Some(&phi) = made.get(&plan.key) {
            repl.insert(plan.out, Arg::V(phi));
            ssa.remove_op(plan.cond);
            continue;
        }
        let (phi_index, phi) = ssa.push_phi(plan.block, 1, Vec::new())?;
        let mut args = Vec::with_capacity(plan.slots.len());
        for slot in &plan.slots {
            let arg = match *slot {
                Slot::Known(b) => Arg::k(u64::from(b)),
                Slot::Own => Arg::V(phi),
                Slot::Compare {
                    anchor,
                    opc,
                    w,
                    x,
                    y,
                } => {
                    if let Some(&v) = compares.get(&(anchor, opc, w, x, y)) {
                        v
                    } else {
                        let (_, out) = ssa.push_at(anchor, opc, w, 0, [x, y, Arg::Nil])?;
                        let v = Arg::V(out.ok_or(SsaError::Full)?);
                        compares.insert((anchor, opc, w, x, y), v);
                        v
                    }
                }
            };
            args.push(arg);
        }
        ssa.set_phi_args(phi_index, args);
        made.insert(plan.key, phi);
        repl.insert(plan.out, Arg::V(phi));
        ssa.remove_op(plan.cond);
    }
    ssa.replace_uses(&repl);
    Ok(u64::try_from(plans.len()).unwrap_or(u64::MAX))
}

/// The pass `cond_through_phi`. Gives the count of changed `Cond` ops.
pub(super) fn cond_through_phi(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let mut plans = Vec::new();
    for index in ssa.order() {
        fuel.tick()?;
        plans.extend(plan_one(ssa, index));
    }
    if plans.is_empty() {
        return Ok(0);
    }
    let mut next = ssa.clone();
    let changes = apply_through(&mut next, &plans)?;
    *ssa = next;
    Ok(changes)
}

/// The tests of `l` and `ge` read bit 7 (the SF bit) of `f ^ (f >> 4)`: SF xor OF.
const SF_XOR_OF: u64 = 0x80;

const _: () = assert!(SF == 0x80 && OF == 0x800, "OF is 4 bits above SF");

/// Rewrites the `Cond` op `index` on the flags word `f` with condition code `code`.
fn materialize_one(ssa: &mut Ssa, index: u32, code: u8, f: Arg) -> Result<(), SsaError> {
    let test = |negate: bool| if negate { Opc::TestZ } else { Opc::TestNZ };
    let odd = code & 1 == 1;
    let mask = match code >> 1 {
        0 => Some(OF),
        1 => Some(CF),
        2 => Some(ZF),
        3 => Some(CF | ZF),
        4 => Some(SF),
        5 => Some(PF),
        _ => None,
    };
    if let Some(mask) = mask {
        let a = [f, Arg::k(u64::from(mask)), Arg::Nil];
        ssa.set_op(index, test(odd), 16, 0, a);
        return Ok(());
    }
    let nil = Arg::Nil;
    let high = ssa.push_before(index, Opc::LShr, 16, [f, Arg::k(4), nil])?;
    let mixed = ssa.push_before(index, Opc::Xor, 16, [f, Arg::V(high), nil])?;
    let sign = [Arg::V(mixed), Arg::k(SF_XOR_OF), nil];
    if code >> 1 == 6 {
        ssa.set_op(index, test(odd), 16, 0, sign);
        return Ok(());
    }
    let less = ssa.push_before(index, test(odd), 16, sign)?;
    let zero = ssa.push_before(index, test(odd), 16, [f, Arg::k(u64::from(ZF)), nil])?;
    let join = if odd { Opc::And } else { Opc::Or };
    ssa.set_op(index, join, 1, 0, [Arg::V(less), Arg::V(zero), nil]);
    Ok(())
}

/// The pass `materialize_flags`. Gives the count of changed `Cond` ops.
pub(super) fn materialize(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let mut plans = Vec::new();
    for index in ssa.order() {
        fuel.tick()?;
        if let Some(op) = ssa.arena().op(index)
            && let (Opc::Cond, Some(cc)) = (op.opc, op.cc())
        {
            plans.push((index, cc.code(), op.a[0]));
        }
    }
    if plans.is_empty() {
        return Ok(0);
    }
    let mut next = ssa.clone();
    for &(index, code, f) in &plans {
        materialize_one(&mut next, index, code, f)?;
    }
    *ssa = next;
    Ok(u64::try_from(plans.len()).unwrap_or(u64::MAX))
}

//! The pass `dce`: dead code removal over L1 with a worklist (design Section 6.4).
//!
//! The roots are the ops that an L1 run cannot drop: stores, flow ops, loads, and each op
//! that can stop a run. Their inputs and their location uses are live. The def of a live
//! value is live, and its inputs are live too. Each other op with a value is dead, and it
//! becomes a `Nop`. An added dead op leaves its anchor.
//!
//! | Op | Pure |
//! |---|---|
//! | `Get` (added), `Phi`, `Copy` | yes |
//! | `Load` | no: the address can be unmapped |
//! | `UDiv`, `SDiv`, `URem`, `SRem` | only with a constant divisor that is not 0 |
//! | `Flags`, `Cond`, `ZExt`, `SExt`, `Insert`, `Bswap` | only with a valid width and aux byte |
//! | Other data ops | yes |

use std::collections::BTreeSet;

use ghidorah_base::Fuel;

use crate::arena::MAX_WIDTH;
use crate::op::{Arg, FlagOp, Op, Opc, Val};
use crate::ssa::{Ssa, SsaError, low_mask};

/// Tells if an L1 run can drop the op: it has a value, and it cannot stop a run.
#[must_use]
pub(crate) fn pure(op: &Op) -> bool {
    if op.out.is_none() || op.w == 0 || op.w > MAX_WIDTH {
        return false;
    }
    match op.opc {
        Opc::Get | Opc::Phi => true,
        Opc::Load => false,
        Opc::UDiv | Opc::SDiv | Opc::URem | Opc::SRem => {
            op.a[1].as_k().is_some_and(|d| d & low_mask(op.w) != 0)
        }
        Opc::Flags => matches!(op.w, 8 | 16 | 32 | 64) && FlagOp::from_code(op.sub).is_some(),
        Opc::Cond => op.sub < 16,
        Opc::ZExt | Opc::SExt => op.sub != 0 && op.sub <= op.w,
        Opc::Insert => op.a[2].as_k().is_some_and(|lo| {
            lo < u64::from(op.w) && op.sub != 0 && u64::from(op.sub) + lo <= u64::from(op.w)
        }),
        Opc::Bswap => op.w.is_multiple_of(8),
        _ => !op.a.iter().any(|a| matches!(a, Arg::L(_))),
    }
}

/// Marks the inputs of the op `index` as live.
fn mark(ssa: &Ssa, index: u32, op: &Op, live: &mut BTreeSet<Val>, work: &mut Vec<Val>) {
    let phi_args = if op.opc == Opc::Phi {
        ssa.arena().phi_args(op).unwrap_or_default()
    } else {
        &[]
    };
    let uses = ssa.uses_at(index).iter().map(|&(_, a)| a);
    for arg in
        op.a.iter()
            .copied()
            .chain(phi_args.iter().copied())
            .chain(uses)
    {
        if let Arg::V(v) = arg
            && live.insert(v)
        {
            work.push(v);
        }
    }
}

/// Runs `dce`. Gives the count of removed ops.
///
/// # Errors
///
/// Returns [`SsaError::OutOfFuel`] when the plan runs out of fuel. Then the pass makes no
/// change.
pub(crate) fn run(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let order = ssa.order();
    let mut live = BTreeSet::new();
    let mut work = Vec::new();
    for &index in &order {
        fuel.tick()?;
        if let Some(op) = ssa.arena().op(index)
            && !pure(op)
        {
            mark(ssa, index, op, &mut live, &mut work);
        }
    }
    while let Some(v) = work.pop() {
        fuel.tick()?;
        let Some(index) = ssa.arena().def_of(v) else {
            continue;
        };
        if let Some(op) = ssa.live_def(v) {
            mark(ssa, index, op, &mut live, &mut work);
        }
    }
    let dead: Vec<u32> = order
        .into_iter()
        .filter(|&i| {
            ssa.arena()
                .op(i)
                .is_some_and(|op| pure(op) && op.out.is_some_and(|v| !live.contains(&v)))
        })
        .collect();
    for &index in &dead {
        ssa.remove_op(index);
    }
    Ok(u64::try_from(dead.len()).unwrap_or(u64::MAX))
}

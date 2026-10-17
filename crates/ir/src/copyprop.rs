//! The pass `copyprop`: copy propagation over L1 (design Section 6.4).
//!
//! A use of the value of `Copy(x)` reads `x` when the copy keeps the value: `x` has at most
//! the width of the copy. A constant input becomes its low bits at the width of the copy.
//! The pass changes only uses, so a `Load` stays at its place before each `Store`. The
//! copies stay for `dce`.

use std::collections::BTreeMap;

use ghidorah_base::Fuel;

use crate::op::{Arg, Opc};
use crate::ssa::{Ssa, SsaError, low_mask};

/// Runs `copyprop`. Gives the count of changed uses.
///
/// # Errors
///
/// Returns [`SsaError::OutOfFuel`] when the plan runs out of fuel. Then the pass makes no
/// change.
pub(crate) fn run(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let mut repl = BTreeMap::new();
    for index in ssa.order() {
        fuel.tick()?;
        let Some(op) = ssa.arena().op(index) else {
            continue;
        };
        let (Opc::Copy, Some(out)) = (op.opc, op.out) else {
            continue;
        };
        match op.a[0] {
            Arg::K(imm) => {
                repl.insert(out, Arg::k(imm.get() & low_mask(op.w)));
            }
            Arg::V(src) if ssa.value_width(src).is_some_and(|w| w <= op.w) => {
                repl.insert(out, Arg::V(src));
            }
            _ => {}
        }
    }
    Ok(ssa.replace_uses(&repl))
}

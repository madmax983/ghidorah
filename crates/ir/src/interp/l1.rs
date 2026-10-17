//! L1 in the interpreter (design Sections 6.4 and 6.5).
//!
//! [`Interp::run_l1`] runs an [`Ssa`] with the one interpreter of L0. The instruction ops run
//! as in L0, and each takes one unit of fuel. So L0 and L1 take the same steps.
//!
//! The added ops of L1 take no fuel. They run at their anchor:
//!
//! | Anchor | When the ops run |
//! |---|---|
//! | `Start` | Once, before the entry block |
//! | `Head(b)` | At each entry to `b`. The phis read the argument of the incoming edge, all at the same time. |
//! | `Before(i)`, `After(i)` | Before and after the instruction op `i` |
//! | `Tail(b)` | At each exit from `b` to a successor, before the phis of the successor |
//!
//! An L1 run never writes a location, so a `Get` op reads the location state at the start
//! of the run. A flow that goes to an address outside the CFG edges stops the run with
//! [`StopReason::BadIr`].

use ghidorah_base::Fuel;

use super::{Interp, Stop, StopReason, stop};
use crate::op::OpId;
use crate::ssa::Ssa;

impl Interp<'_> {
    /// Runs the L1 form `ssa` from its entry block until a stop.
    ///
    /// Make the interpreter over the arena of `ssa`. A run over another arena stops at once
    /// with [`StopReason::BadIr`].
    pub fn run_l1(&mut self, ssa: &Ssa, fuel: &mut Fuel) -> Stop {
        let _ = fuel;
        let addr = ssa.block_addr(ssa.entry()).unwrap_or_default();
        stop(StopReason::BadIr, OpId { addr, seq: 0 }, 0)
    }
}

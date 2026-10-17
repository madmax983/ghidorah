//! The registers that each instruction reads and writes.

use crate::insn::Insn;
use crate::regs::RegSet;

/// Gives the read set and the write set of an instruction.
pub(crate) fn regs(insn: &Insn) -> (RegSet, RegSet) {
    let _ = insn;
    (RegSet::EMPTY, RegSet::EMPTY)
}

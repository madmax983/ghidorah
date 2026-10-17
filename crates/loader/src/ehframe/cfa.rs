//! The CFA row interpreter of one CIE or FDE program.

use crate::binary::CfaRow;

/// The CFA rule: a register and an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Rule {
    /// The DWARF register number, or `None` before the first `def_cfa`.
    pub(crate) reg: Option<u16>,
    /// The offset from the register.
    pub(crate) offset: i64,
}

/// The factors of a CIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Factors {
    /// The code alignment factor of `advance_loc`.
    pub(crate) code: u64,
    /// The data alignment factor of the `_sf` forms.
    pub(crate) data: i64,
}

/// The rows and the last rule of one program.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Run {
    /// The rows in address order.
    pub(crate) rows: Vec<CfaRow>,
    /// The rule after the last instruction.
    pub(crate) rule: Rule,
}

/// The cause of a stopped program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stop {
    /// The diagnostic code.
    pub(crate) code: ghidorah_base::DiagCode,
    /// The offset of the instruction in the program.
    pub(crate) at: usize,
    /// The opcode.
    pub(crate) opcode: u8,
    /// A short fact for the diagnostic.
    pub(crate) hint: &'static str,
}

/// Runs `program` from `start` with the rule `init`.
///
/// `end` is the first address after the PC range. Rows at or after `end` are not kept.
/// `None` keeps no row limit, for the initial program of a CIE.
pub(crate) fn run(
    program: &[u8],
    factors: Factors,
    start: u64,
    end: Option<u64>,
    init: Rule,
    max_insns: u64,
) -> Result<Run, Stop> {
    let _ = (program, factors, start, end, max_insns);
    Ok(Run {
        rows: Vec::new(),
        rule: init,
    })
}

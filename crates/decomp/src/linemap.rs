//! The line map and the coverage of the instructions (design Section 8.3, AC-099).
//!
//! A [`LineRow`] maps one line to its address range and its ops. A line gets a row when it
//! has a range: a line with ops, or a comment line.
//!
//! [`cover`] makes sure that every instruction of the function is in a line range or in an
//! elided range with a reason. An instruction outside both gets one of these reasons:
//!
//! | Instruction | Reason |
//! |---|---|
//! | the jump at the end of a block, which the structure shows | `control flow` |
//! | another instruction of a reachable block, whose effect no line shows | `no effect` |
//! | an instruction of the body outside every block | `padding` |

use std::collections::BTreeSet;

use ghidorah_db::CommentKind;
use ghidorah_ir::OpId;

use crate::Elided;
use crate::print::Line;

/// One row of the line map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LineRow {
    /// The line number, from 1.
    pub line: usize,
    /// The first address of the range.
    pub start: u64,
    /// The size of the range in bytes.
    pub size: u64,
    /// The ops of the line in op order.
    pub ops: Vec<OpId>,
    /// The comment kind of the line.
    pub comment: Option<CommentKind>,
}

/// Gives the row of the line `line` (from 1), or `None` for a line with no range.
#[must_use]
pub fn row(line: usize, l: &Line) -> Option<LineRow> {
    let _ = (line, l);
    None
}

/// Gives the rows of `lines` in line order. The first line has the number `first`.
#[must_use]
pub fn rows(first: usize, lines: &[Line]) -> Vec<LineRow> {
    let _ = (first, lines);
    Vec::new()
}

/// Tells if `addr` is in a line range or in an elided range.
#[must_use]
pub fn covered(lines: &[Line], elided: &[Elided], addr: u64) -> bool {
    let _ = (lines, elided, addr);
    false
}

/// Adds an elided range for each instruction that no line and no elided range holds.
///
/// `insns` holds the instructions of the reachable blocks, `flow` the addresses of the jumps
/// that end a block, and `body` the instructions of the function body. Each list holds the
/// address and the length.
pub fn cover(
    lines: &[Line],
    insns: &[(u64, u8)],
    flow: &BTreeSet<u64>,
    body: &[(u64, u8)],
    elided: &mut Vec<Elided>,
) {
    let _ = (lines, insns, flow, body, elided);
}

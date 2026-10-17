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

use crate::print::Line;
use crate::{ElideReason, Elided};

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
    let (start, size) = l.span?;
    Some(LineRow {
        line,
        start,
        size,
        ops: l.ops.clone(),
        comment: l.comment,
    })
}

/// Gives the rows of `lines` in line order. The first line has the number `first`.
#[must_use]
pub fn rows(first: usize, lines: &[Line]) -> Vec<LineRow> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| row(first.saturating_add(i), l))
        .collect()
}

/// The sorted and merged address ranges `[start, end)` of the lines and the elided ranges.
struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    fn new(lines: &[Line], elided: &[Elided]) -> Self {
        let mut all: Vec<(u64, u64)> = lines
            .iter()
            .filter_map(|l| l.span)
            .map(|(s, n)| (s, s.saturating_add(n)))
            .chain(
                elided
                    .iter()
                    .map(|e| (e.start, e.start.saturating_add(e.size))),
            )
            .filter(|(s, e)| s < e)
            .collect();
        all.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(all.len());
        for (s, e) in all {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        Self(merged)
    }

    fn holds(&self, addr: u64) -> bool {
        let i = self.0.partition_point(|r| r.0 <= addr);
        i > 0 && self.0.get(i - 1).is_some_and(|r| addr < r.1)
    }
}

/// Tells if `addr` is in a line range or in an elided range.
#[must_use]
pub fn covered(lines: &[Line], elided: &[Elided], addr: u64) -> bool {
    Ranges::new(lines, elided).holds(addr)
}

/// Gives the elided ranges in address order. Two ranges with the same reason merge when one
/// ends where the next one starts.
#[must_use]
pub fn merge(mut elided: Vec<Elided>) -> Vec<Elided> {
    elided.sort_unstable();
    elided.dedup();
    let mut out: Vec<Elided> = Vec::with_capacity(elided.len());
    for e in elided {
        match out.last_mut() {
            Some(last)
                if last.reason == e.reason && last.start.saturating_add(last.size) == e.start =>
            {
                last.size = last.size.saturating_add(e.size);
            }
            _ => out.push(e),
        }
    }
    out
}

/// Adds an elided range for each instruction that no line and no elided range holds.
///
/// `insns` holds the instructions of the reachable blocks. `flow` holds the addresses of the
/// jumps at the block ends. `body` holds the instructions of the function body. Each list
/// holds the address and the length.
pub fn cover(
    lines: &[Line],
    insns: &[(u64, u8)],
    flow: &BTreeSet<u64>,
    body: &[(u64, u8)],
    elided: &mut Vec<Elided>,
) {
    let ranges = Ranges::new(lines, elided);
    let mut added = Vec::new();
    for &(start, len) in insns {
        if ranges.holds(start) {
            continue;
        }
        let reason = if flow.contains(&start) {
            ElideReason::Flow
        } else {
            ElideReason::NoEffect
        };
        added.push(Elided {
            start,
            size: u64::from(len.max(1)),
            reason,
        });
    }
    let known: BTreeSet<u64> = insns.iter().map(|i| i.0).collect();
    for &(start, len) in body {
        if known.contains(&start) || ranges.holds(start) {
            continue;
        }
        added.push(Elided {
            start,
            size: u64::from(len.max(1)),
            reason: ElideReason::Padding,
        });
    }
    elided.extend(added);
}

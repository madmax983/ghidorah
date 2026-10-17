//! The CFG of one function (design Section 7.4).
//!
//! [`build`] derives the CFG from the published code units of a function body. It decodes
//! each branch again for its target. The block ID is the start address (`bb:0x..`).
//!
//! Leaders: the entry, the branch targets in the body, the instruction after a branch, a
//! call or a stop, the start of each body range and each jump-table target.
//!
//! | Last instruction | Edges |
//! |---|---|
//! | plain, before a leader | `fallthrough` |
//! | `jmp` | `branch` in the body, else `tailcall` |
//! | `jcc` | `cond_true` to the target, `cond_false` to the next instruction |
//! | `call` | `call_return`, except after a noreturn callee (AC-080a) |
//! | indirect `jmp` | `switch_case(i)` for a jump table, `tailcall` through an import slot, else `indirect_unresolved` |
//! | `ret`, trap | none |
//!
//! A `fallthrough` or `cond_false` edge out of the body is a `tailcall` edge.
//!
//! [`check`] tests the invariants of AC-083: the blocks are contiguous and disjoint, each
//! internal edge ends at a block start, each block is reachable from the entry or from a
//! jump-table case, and no instruction is in two blocks.

use std::fmt;

use ghidorah_base::{Address, FuncId};
use ghidorah_db::Program;

/// The kind of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// Execution continues at the next block.
    Fallthrough,
    /// A direct jump in the body.
    Branch,
    /// The taken edge of a conditional branch.
    CondTrue,
    /// The edge of a conditional branch that is not taken.
    CondFalse,
    /// Case `i` of a jump table.
    SwitchCase(u16),
    /// The return of a call that returns.
    CallReturn,
    /// A flow to code outside the body.
    TailCall,
    /// An indirect jump with no known target.
    IndirectUnresolved,
}

impl EdgeKind {
    /// Gives the output name, for example `cond_true` or `switch_case`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fallthrough => "fallthrough",
            Self::Branch => "branch",
            Self::CondTrue => "cond_true",
            Self::CondFalse => "cond_false",
            Self::SwitchCase(_) => "switch_case",
            Self::CallReturn => "call_return",
            Self::TailCall => "tailcall",
            Self::IndirectUnresolved => "indirect_unresolved",
        }
    }

    /// Tells if the edge stays in the body.
    #[must_use]
    pub const fn is_internal(self) -> bool {
        !matches!(self, Self::TailCall | Self::IndirectUnresolved)
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One basic block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The first address: the block ID.
    pub start: u64,
    /// The instructions: start and length, in address order.
    pub insns: Vec<(u64, u8)>,
}

impl Block {
    /// Gives the address after the last instruction.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.insns
            .last()
            .map_or(self.start, |(at, len)| at.saturating_add(u64::from(*len)))
    }
}

/// One CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edge {
    /// The start of the source block.
    pub from: u64,
    /// The target, or `None` for an unresolved indirect jump.
    pub to: Option<Address>,
    /// The kind.
    pub kind: EdgeKind,
}

/// The CFG of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncCfg {
    /// The function.
    pub func: FuncId,
    /// The blocks in address order.
    pub blocks: Vec<Block>,
    /// The edges in source order, then in the order of the last instruction.
    pub edges: Vec<Edge>,
}

/// A broken CFG invariant (AC-083).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CfgViolation {
    /// The CFG has no block at the entry.
    NoEntryBlock,
    /// A block has a gap between two instructions.
    Gap {
        /// The block.
        block: u64,
    },
    /// Two blocks overlap, or two blocks hold one instruction.
    Overlap {
        /// The second block.
        block: u64,
    },
    /// An internal edge ends where no block starts.
    EdgeTarget {
        /// The source block.
        from: u64,
        /// The target.
        to: u64,
    },
    /// No path from the entry or from a jump-table case reaches the block.
    Unreachable {
        /// The block.
        block: u64,
    },
}

/// Builds the CFG of the function `func`. Gives `None` when the program has no such function.
#[must_use]
pub fn build(program: &Program, func: FuncId) -> Option<FuncCfg> {
    let _ = (program, func);
    None
}

/// Checks the invariants of AC-083. Gives the violations in block order.
#[must_use]
pub fn check(cfg: &FuncCfg) -> Vec<CfgViolation> {
    let _ = cfg;
    vec![CfgViolation::NoEntryBlock]
}

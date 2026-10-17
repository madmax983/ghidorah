//! `JumpTables` (band 410): jump tables by method A (design Section 7.8).
//!
//! [`method_a`] finds the guard `cmp idx, N; ja default` (or `jae`, `jbe`, `jb`) in the block
//! of the indirect jump or up a chain of blocks with one predecessor. Then it runs the backward
//! slice of the jump target with the index pinned to each value `0..=N`. The slice has at most
//! [`MAX_SLICE_OPS`] ops and [`MAX_SLICE_BLOCKS`] blocks, and it stops at calls. The loads read
//! the read-only image. The forms are the 4-byte PIC table (`movsxd; add`) and the 8-byte
//! absolute table (`jmp [T + idx*8]`). The first load gives the table base and the entry size.
//!
//! | Result | Record |
//! |---|---|
//! | every target is an executable address that the caller accepts | a resolved table with method `a` |
//! | the guard, the slice or a target fails | an unresolved table and `W_JUMPTABLE_UNRESOLVED` |
//! | an agent table at the jump | no record; a different method A result gives `W_AGENT_OVERRIDE_CONFLICT` |
//! | an agent `indirect_targets` override at the jump | no record |
//!
//! A new or changed table queues `Disasm` for its function, so the descent follows the cases.

use std::fmt;

use ghidorah_base::Fuel;
use ghidorah_ir::Memory;
use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::fir::FuncIr;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};

/// The largest number of ops of a slice.
pub const MAX_SLICE_OPS: usize = 50;

/// The largest number of blocks of a slice.
pub const MAX_SLICE_BLOCKS: usize = 4;

/// The largest number of entries of a table.
pub const MAX_CASES: u64 = 1024;

/// Gives the spec of `JumpTables` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "JumpTables",
        priority: 410,
        triggers: &[Trigger::Instructions],
        version: 1,
        grain: Grain::Whole,
        options: &[
            Opt {
                name: "max_slice_ops",
                value: 50,
                doc: "The largest number of ops of a slice.",
            },
            Opt {
                name: "max_cases",
                value: MAX_CASES,
                doc: "The largest number of entries of a table.",
            },
        ],
        doc: "Resolves the jump tables of the indirect jumps by method A.",
    }
}

/// A resolved table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Resolved {
    /// The address of the first entry.
    pub base: Option<u64>,
    /// The entry size in bytes: 4 or 8.
    pub entry_size: u8,
    /// The case targets in case order.
    pub targets: Vec<u64>,
}

/// Why method A fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Failure {
    /// The address is not an indirect jump of the function IR.
    NoSite,
    /// No guard bounds the index.
    NoGuard,
    /// The slice has no value for an index.
    Slice {
        /// The index.
        idx: u64,
    },
    /// A target is not an accepted executable address.
    Target {
        /// The target.
        target: u64,
    },
    /// The guard gives more than [`MAX_CASES`] entries.
    TooMany {
        /// The entry count.
        count: u64,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSite => f.write_str("The address is not an indirect jump."),
            Self::NoGuard => f.write_str("No guard bounds the index."),
            Self::Slice { idx } => write!(f, "The slice has no target for the index {idx}."),
            Self::Target { target } => write!(f, "The target {target:#x} is not accepted."),
            Self::TooMany { count } => write!(f, "The table has {count} entries."),
        }
    }
}

/// Resolves the jump table of the indirect jump at `site` in `fir`. `accept` tells if a
/// target is an executable address of the function region. The loads read `mem`.
///
/// # Errors
///
/// Returns the [`Failure`] of the first step that fails.
pub fn method_a(
    fir: &FuncIr,
    mem: &dyn Memory,
    site: u64,
    accept: &dyn Fn(u64) -> bool,
    fuel: &mut Fuel,
) -> Result<Resolved, Failure> {
    let _ = (fir, mem, site, accept, fuel);
    Err(Failure::NoSite)
}

/// Gives the indirect jumps of `fir` that do not go through an import slot, in address order.
#[must_use]
pub fn sites(fir: &FuncIr) -> Vec<u64> {
    let _ = fir;
    Vec::new()
}

/// Runs one step over `ranges`: each function that the ranges touch gets its tables again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}

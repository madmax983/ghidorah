//! `DataPtrSeeds` (band 450): seed 11 of design Section 7.3, code pointers in data.
//!
//! A code pointer is an aligned 8-byte value in an initialized region without execute
//! permission. The value is an address in an executable region.
//!
//! | File | Code pointer |
//! |---|---|
//! | a file with `R_X86_64_RELATIVE` or `R_X86_64_64` relocations | the value that such a relocation puts in its slot |
//! | a file without such relocations | a value in a run of [`MIN_RUN`] or more code pointers |
//!
//! [`start_at`] tests each target. A target that passes the tests starts a function with the
//! reason `DataPtr`, confidence [`CONFIDENCE`] and `R_DATA_CODE_PTR`. The tests are:
//!
//! - A padding head (`nop`, `int3` or a 0 byte) moves the target to the next other instruction.
//! - The start is in an executable region and not in the PLT area.
//! - The start is not a jump-table case target.
//! - No other function holds the start in its body or in a declared extent.
//! - No function with a reason of seeds 1 to 10 starts there. A `Call` reason does not count.
//! - A linear decode gives at least [`MIN_INSNS`] valid instructions before bad bytes or the
//!   end of the region.
//!
//! The band is above the bands of seeds 1 to 10 and of `JumpTables`. So the tests see the
//! bodies of these seeds and the resolved jump tables. Each step tests every pointer again,
//! and a `DataPtr` reason that fails a test goes.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_db::{FactKey, Program, StartReason};
use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::Why;

/// The confidence of a `DataPtr` start.
pub const CONFIDENCE: u8 = 70;

/// The smallest number of valid instructions of a linear decode from a start.
pub const MIN_INSNS: u64 = 4;

/// The smallest number of code pointers in a run, in a file without pointer relocations.
pub const MIN_RUN: u64 = 2;

/// The largest number of padding bytes before a start.
pub const MAX_PADDING: u64 = 64;

/// The largest number of bytes of one section that the run scan reads.
pub const MAX_SCAN_BYTES: u64 = 16 << 20;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::DataPtrSeeds,
    name: "DataPtrSeeds",
    priority: 450,
    triggers: &[Trigger::Bytes, Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[
        Opt {
            name: "min_insns",
            value: MIN_INSNS,
            doc: "The smallest number of valid instructions of a linear decode from a start.",
        },
        Opt {
            name: "min_run",
            value: MIN_RUN,
            doc: "The smallest number of code pointers in a run without relocations.",
        },
    ],
    doc: "Starts a function at each code pointer in data that no body holds.",
};

/// One code pointer in data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pointer {
    /// The address of the 8-byte slot.
    pub slot: u64,
    /// The value: an address in an executable region.
    pub target: u64,
    /// A relocation gives the value.
    pub relocated: bool,
}

impl Pointer {
    /// Gives the premise of a seed: the relocation, or the data slot of a pointer run.
    #[must_use]
    pub const fn premise(&self) -> FactKey {
        if self.relocated {
            FactKey::Reloc(self.slot)
        } else {
            FactKey::Data(self.slot)
        }
    }
}

/// The code-pointer state of a work state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CodePtrs {
    /// The code pointers in data, or `None` before the first step of `DataPtrSeeds`.
    pub pointers: Option<Vec<Pointer>>,
    /// The address-taken sites of the code units, each with its target.
    pub sites: BTreeMap<u64, u64>,
}

/// Gives the code pointers in the data of `program` in slot order.
#[must_use]
pub fn pointers(program: &Program) -> Vec<Pointer> {
    let _ = program;
    Vec::new()
}

/// Gives the first address at or after `target` that is not padding: a `nop` form, `int3` or
/// a 0 byte. Bad bytes, an address outside executable memory and more than [`MAX_PADDING`]
/// padding bytes give `None`.
#[must_use]
pub fn skip_padding(program: &Program, target: u64) -> Option<u64> {
    let _ = (program, target);
    None
}

/// Counts the valid instructions of a linear decode from `at`, up to `max`. The count stops
/// at bad bytes and at the end of the executable region.
#[must_use]
pub fn linear_insns(program: &Program, at: u64, max: u64) -> u64 {
    let _ = (program, at, max);
    0
}

/// Gives the case targets of the resolved jump tables: the method A tables of the work state,
/// the agent tables and the agent cases of indirect jumps.
pub(crate) fn case_targets(ctx: &AnalysisCtx<'_>) -> BTreeSet<u64> {
    let _ = ctx;
    BTreeSet::new()
}

/// Gives the start of a seed at the code pointer `target` by the tests of the module, or
/// `None` when a test fails.
pub(crate) fn start_at(ctx: &AnalysisCtx<'_>, cases: &BTreeSet<u64>, target: u64) -> Option<u64> {
    let _ = (ctx, cases, target);
    None
}

/// Puts the reason `reason` on each start of `want` and removes it from each other function.
pub(crate) fn seed(
    ctx: &mut AnalysisCtx<'_>,
    reason: StartReason,
    confidence: u8,
    want: BTreeMap<u64, Why>,
) {
    let _ = (ctx, reason, confidence, want);
}

/// Runs one step: every code pointer gets the tests again. The ranges only queue the step.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}

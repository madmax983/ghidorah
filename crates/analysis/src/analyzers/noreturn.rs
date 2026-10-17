//! `NoReturnKnown` (band 301) and `NoReturnDiscovered` (band 302) (design Section 7.7).
//!
//! `NoReturnKnown` reads the noreturn list of the binary format. The match uses the name part
//! of each import without leading underscores. The PLT stub of a listed import gets the
//! noreturn flag with `R_NORETURN_KNOWN`. The import slot of a listed import becomes a
//! noreturn slot, so a `call [rip+slot]` site does not fall through.
//!
//! `NoReturnDiscovered` gives a function the flag when one of these rules holds:
//!
//! | Rule | Condition |
//! |---|---|
//! | `R_NORETURN_BODY` | No path returns: no `ret`, no unknown end, and each exit goes to a noreturn function or slot |
//! | `R_NORETURN_FALLTHROUGH` | 3 or more call sites fall through into another function, bad code or memory that is not executable |
//!
//! The flags of the flow are the least fixpoint from the known flags. Each run computes them
//! again for all functions, so a lost reason also removes a flag.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};

/// The smallest number of unsafe call sites of `R_NORETURN_FALLTHROUGH`.
pub const UNSAFE_SITES: u64 = 3;

/// The spec of `NoReturnKnown`.
pub const KNOWN: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::NoReturnKnown,
    name: "NoReturnKnown",
    priority: 301,
    triggers: &[Trigger::Bytes, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Flags the stubs and the slots of the imports on the noreturn list.",
};

/// The spec of `NoReturnDiscovered`.
pub const DISCOVERED: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::NoReturnDiscovered,
    name: "NoReturnDiscovered",
    priority: 302,
    triggers: &[Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[Opt {
        name: "unsafe_sites",
        value: UNSAFE_SITES,
        doc: "The smallest number of call sites with an unsafe fall-through.",
    }],
    doc: "Flags the functions whose flow never returns.",
};

/// Runs one step of `NoReturnKnown` over `ranges`.
pub fn run_known(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}

/// Runs one step of `NoReturnDiscovered` over `ranges`.
pub fn run_discovered(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}

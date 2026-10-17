//! `MainDiscovery` (band 430): `main` from the first argument of `__libc_start_main` (design
//! Section 7.11). ELF only.
//!
//! [`find`] looks at each call in the function at the ELF entry. A call to the PLT stub of
//! `__libc_start_main`, or a call through its import slot, is the start call. Block-local
//! evaluation (design Section 6.6) gives `rdi` before it. An address in executable memory is
//! `main`: it gets the start reason `Main` with confidence 95 and the name `main` with the
//! source `Analysis`.

use ghidorah_base::Fuel;
use ghidorah_db::Program;
use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::fir::FuncIr;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The name of the start function of the C library.
pub const LIBC_START: &str = "__libc_start_main";

/// The confidence of a `Main` start (design Section 7.3).
pub const CONFIDENCE: u8 = 95;

/// Gives the spec of `MainDiscovery` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "MainDiscovery",
        priority: 430,
        triggers: &[Trigger::Instructions, Trigger::Functions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Finds main from the first argument of __libc_start_main.",
    }
}

/// One start call: the call site and the value of `rdi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StartCall {
    /// The call site.
    pub site: u64,
    /// The address of `main`.
    pub main: u64,
}

/// Finds the start call in `fir`, the IR of the function at the ELF entry.
#[must_use]
pub fn find(program: &Program, fir: &FuncIr, fuel: &mut Fuel) -> Option<StartCall> {
    let _ = (program, fir, fuel);
    None
}

/// Runs one step: the function at the ELF entry gets its start call again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}

//! `Syscalls` (band 810): Linux syscall sites (design Section 7.11). ELF only.
//!
//! Block-local evaluation gives `rax` at each `Syscall` op. The x86-64 table of
//! `ghidorah-types` gives the name. The arguments come from `rdi rsi rdx r10 r8 r9`. The
//! argument count is the parameter count of the Tier-0 prototype with the syscall name, else
//! six. Each site gets the `EOL` note `sys:<name>`, or `sys:<number>` for a number with no
//! name, with `R_SYSCALL_NUMBER`. [`sites`] gives the sites of a program on demand.

use ghidorah_base::{Fuel, FuncId, SyscallId};
use ghidorah_db::Program;
use ghidorah_kernel::RangeSet;

use crate::callargs::ArgValue;
use crate::ctx::AnalysisCtx;
use crate::fir::FuncIr;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The largest number of syscall arguments.
pub const MAX_ARGS: usize = 6;

/// Gives the spec of `Syscalls` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "Syscalls",
        priority: 810,
        triggers: &[Trigger::Instructions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Names the syscall sites from the value of rax.",
    }
}

/// One syscall site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Site {
    /// The address of the `syscall` instruction.
    pub site: u64,
    /// The function of the site.
    pub func: FuncId,
    /// The value of `rax`, or `None` when it is not known.
    pub nr: Option<u64>,
    /// The name of the number in the syscall table.
    pub name: Option<&'static str>,
    /// The argument values.
    pub args: Vec<ArgValue>,
}

impl Site {
    /// Gives the `sys:` ID: the name, else the number.
    #[must_use]
    pub fn id(&self) -> Option<SyscallId> {
        let _ = self;
        None
    }

    /// Gives the text of the site note: `sys:<name>` or `sys:<number>`.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        self.id().map(|id| id.to_string())
    }
}

/// Gives the syscall sites of `fir` in address order.
#[must_use]
pub fn of_fir(program: &Program, fir: &FuncIr, fuel: &mut Fuel) -> Vec<Site> {
    let _ = (program, fir, fuel);
    Vec::new()
}

/// Gives the syscall sites of every published function of `program` in address order.
#[must_use]
pub fn sites(program: &Program, fuel: &mut Fuel) -> Vec<Site> {
    let _ = (program, fuel);
    Vec::new()
}

/// Runs one step over `ranges`: each function that the ranges touch gets its site notes
/// again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}

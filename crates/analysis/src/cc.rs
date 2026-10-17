//! `CallingConvention` (band 800): parameter recovery and the varargs flag (design Section
//! 7.10).
//!
//! [`recover`] finds the live-in registers of the L0 body: a register that a path reads before
//! a write. A `xor r, r` or `sub r, r` reads no register. A call writes the registers that the
//! callee does not keep, so a read after a call is not a live-in read.
//!
//! - The parameters are the argument registers among the live-in registers, filled up to the
//!   highest one. The integer and the floating registers count apart.
//! - A store of a callee-saved register to the frame, as a push does, is not a read.
//! - A read of the frame slot `k` at the first stack-parameter offset or above adds the stack
//!   parameters up to `k`.
//! - Varargs: a `test al, al` prologue, or the integer save area: 64-bit stores of the last
//!   argument registers, `r9` included, to slots that go up by 8 in register order. The
//!   registers of the save area are not named parameters.
//!
//! [`params`] gives the parameters of a function: an agent signature first, then the Tier-0
//! prototype of its name, then [`recover`]. ELF binaries use [`SYSV_X86_64`].

use ghidorah_base::{Fuel, FuncId};
use ghidorah_db::Program;
use ghidorah_kernel::RangeSet;
use ghidorah_types::CallConv;
use ghidorah_types::cc::SYSV_X86_64;

use crate::ctx::AnalysisCtx;
use crate::fir::{FirError, FuncIr};
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// Gives the spec of `CallingConvention` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "CallingConvention",
        priority: 800,
        triggers: &[Trigger::Instructions, Trigger::Signatures],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Recovers the parameters and the varargs flag of each function.",
    }
}

/// The parameters of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Params {
    /// The integer and pointer parameters in registers.
    pub int: u8,
    /// The floating parameters in registers.
    pub float: u8,
    /// The parameters on the stack.
    pub stack: u8,
    /// The function takes a variable argument list.
    pub varargs: bool,
}

impl Params {
    /// Gives the count of the named parameters.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.int as u32 + self.float as u32 + self.stack as u32
    }
}

/// Where the parameters of [`params`] come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamSource {
    /// The signature fact of the function.
    Signature,
    /// The Tier-0 prototype of the name of the function.
    Prototype,
    /// The recovery from the body.
    Recovered,
}

/// Gives the calling convention of the binary format of `program`.
#[must_use]
pub const fn conv_of(program: &Program) -> &'static CallConv {
    let _ = program;
    &SYSV_X86_64
}

/// Recovers the parameters of `fir` by the rules of the module doc.
#[must_use]
pub fn recover(fir: &FuncIr, conv: &CallConv) -> Params {
    let _ = (fir, conv);
    Params::default()
}

/// Gives the parameters of the published function `id` and their source.
///
/// # Errors
///
/// Returns the [`FirError`] of the function IR when the recovery needs it.
pub fn params(
    program: &Program,
    id: FuncId,
    fuel: &mut Fuel,
) -> Result<(Params, ParamSource), FirError> {
    let _ = (program, fuel);
    Err(FirError::NoFunc(id))
}

/// Runs one step over `ranges`: each function that the ranges touch gets its varargs flag
/// again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}

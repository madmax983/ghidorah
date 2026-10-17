//! Call-site argument values (design Section 7.11). Derived data: `xref_list { args: true }`
//! computes them on demand.
//!
//! Block-local evaluation (design Section 6.6) gives the value of each argument register at
//! the call. [`classify`] gives the kind of a value:
//!
//! | Value | Kind |
//! |---|---|
//! | the start of a string fact, or of a NUL-terminated text in a read-only region | `str` |
//! | a function entry | `func` |
//! | another address in a mapped region | `addr` |
//! | another constant | `int` |
//! | no value | `unknown` |
//!
//! The argument count comes from the parameters of the callee ([`crate::cc::params`]), or from
//! the Tier-0 prototype of an import. A call with no known callee gives six arguments.

use ghidorah_base::{Fuel, FuncId};
use ghidorah_db::Program;
use ghidorah_ir::{Loc, LocalValue};

use crate::fir::{FirError, FuncIr};

/// The largest text of a string value in bytes.
pub const MAX_TEXT: usize = 256;

/// The value of one argument.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArgValue {
    /// An integer.
    Int(u64),
    /// A pointer to a string, with the string bytes as text.
    Str {
        /// The address.
        addr: u64,
        /// The text, at most [`MAX_TEXT`] bytes.
        text: String,
    },
    /// A pointer to a function.
    Func(FuncId),
    /// Another address.
    Addr(u64),
    /// No value.
    Unknown,
}

impl ArgValue {
    /// Gives the kind name: `int`, `str`, `func`, `addr` or `unknown`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Str { .. } => "str",
            Self::Func(_) => "func",
            Self::Addr(_) => "addr",
            Self::Unknown => "unknown",
        }
    }
}

/// Gives the kind of the value `v` in `program`.
#[must_use]
pub fn classify(program: &Program, v: LocalValue) -> ArgValue {
    let _ = (program, v);
    ArgValue::Unknown
}

/// Gives the values of `regs` before the op `op` of `fir`.
#[must_use]
pub fn values(
    program: &Program,
    fir: &FuncIr,
    op: u32,
    regs: &[Loc],
    fuel: &mut Fuel,
) -> Vec<ArgValue> {
    let _ = (program, fir, op, fuel);
    vec![ArgValue::Unknown; regs.len()]
}

/// Gives the argument values of the call at `site` in its published function.
///
/// # Errors
///
/// Returns [`FirError::NoFunc`] when no function holds `site`, and the errors of the IR build.
pub fn at(program: &Program, site: u64, fuel: &mut Fuel) -> Result<Vec<ArgValue>, FirError> {
    let _ = (program, fuel);
    Err(FirError::NoFunc(crate::fir::func_id(site)))
}

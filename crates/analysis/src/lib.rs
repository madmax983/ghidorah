//! The analysis engine of ghidorah (design Section 7).
//!
//! The crate is a pure core crate. It does no I/O and reads no clock.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`spec`] | [`AnalyzerSpec`], [`Trigger`], [`Grain`], [`Step`] and the start bands | Section 7.2, ADR-0024 |
//! | [`registry`] | [`AnalyzerId`], the plain analyzer list and the one dispatch `match` | Section 7.1 |
//! | [`why`] | The closed rule catalog [`Rule`] and the analysis [`Why`] | ADR-0023 |
//! | [`ctx`] | [`AnalysisCtx`]: each insert function takes a required [`Why`] | Section 7.2 |
//! | [`sched`] | [`Scheduler`]: pending sets, the queue, fuel slices, committed and shadow runs | Sections 3.9, 7.2, ADR-0016 |
//! | [`publish`] | The analysis set of the work state and its `ReplaceAnalysis` commit | Section 3.9 |
//! | [`mod@cfg`] | The CFG of a function and its invariant check | Section 7.4 |
//! | [`callgraph`] | The call graph of the published facts | Section 7.11 |
//! | [`inputs`] | `analysis_inputs_hash` | Section 3.9 |
//! | [`analyzers`] | The analyzers of bands 100 to 650, and the derived views `gaps`, `lang` and `metrics` | Sections 7.3, 7.5 to 7.7, 7.11, 9.6 |
//! | [`fir`] | [`FuncIr`]: the L0 function IR builder | Section 7.12 |
//! | [`stack`] | [`Frame`]: stack tracking, frames and the escape rule | Section 7.9 |
//! | [`overrides`] | `Overrides` (160): the seeds of the agent facts | Sections 3.6, 7.1 |
//! | [`orphans`] | The agent facts that lost their anchor: `W_FACT_ORPHANED` | Section 3.9 |
//! | [`facts`] | The relation catalog, claim verdicts with an absence basis and why trees | Section 11.8, ADR-0023 |
//! | [`jumptable`] | `JumpTables` (410): method A | Section 7.8 |
//! | [`slotsite`] | Indirect sites through a register that holds an import slot | Section 7.8 |
//! | [`tailcall`] | `TailCallsAndParts` (420): FETCH tail calls and cold parts | Section 7.3 |
//! | [`main_discovery`] | `MainDiscovery` (430) | Section 7.11 |
//! | [`cc`] | `CallingConvention` (800): parameters and varargs | Section 7.10 |
//! | [`syscalls`] | `Syscalls` (810) | Section 7.11 |
//! | [`callargs`] | The argument values of a call site | Section 7.11 |
//! | [`similar`] | Function similarity: feature streams, vectors, the corpus index and name proposals | Section 7.13, ADR-0028 |
//!
//! The analyzers write into a work state. A publish step makes the analysis set of the
//! program from the work state. So a read sees one consistent set after each fuel slice.

pub mod analyzers;
pub mod callargs;
pub mod callgraph;
pub mod cc;
pub mod cfg;
pub mod code;
pub mod ctx;
pub mod facts;
pub mod fir;
pub mod inputs;
mod irfacts;
pub mod jumptable;
pub mod main_discovery;
pub mod orphans;
pub mod overrides;
pub mod publish;
pub mod registry;
pub mod sched;
pub mod similar;
pub mod slotsite;
pub mod spec;
pub mod stack;
pub mod syscalls;
pub mod tailcall;
pub mod why;
mod work;

use std::fmt;

use ghidorah_db::{CodecError, EditError, Invalid, TxError};

pub use callgraph::{CallGraph, Callee};
pub use cfg::{Block, CfgViolation, Edge, EdgeKind, FuncCfg};
pub use ctx::{AnalysisCtx, Body, Summary, UnitRec};
pub use fir::{FirError, FuncIr};
pub use inputs::inputs_hash;
pub use publish::Changed;
pub use registry::{ANALYZERS, AnalyzerId};
pub use sched::{AnalyzerRow, Mode, Ran, RunOutcome, RunState, Scheduler, Until};
pub use spec::{AnalyzerSpec, BAND_FULL, BAND_SIGNATURES, BAND_TRIAGE, Grain, Opt, Step, Trigger};
pub use stack::Frame;
pub use why::{Rule, Why};

/// The error of a publish step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    /// The analysis set does not decode. The work state breaks a table rule.
    Codec(CodecError),
    /// The transaction of the publish step does not open or commit.
    Tx(TxError),
    /// The `ReplaceAnalysis` edit fails.
    Edit(EditError),
    /// A rule code or a session label breaks its grammar.
    Invalid(Invalid),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "The analysis set does not decode: {e}"),
            Self::Tx(e) => write!(f, "The publish transaction fails: {e}"),
            Self::Edit(e) => write!(f, "The analysis edit fails: {e}"),
            Self::Invalid(e) => write!(f, "A value of the analysis set is not valid: {e}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl From<CodecError> for AnalysisError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<TxError> for AnalysisError {
    fn from(e: TxError) -> Self {
        Self::Tx(e)
    }
}

impl From<EditError> for AnalysisError {
    fn from(e: EditError) -> Self {
        Self::Edit(e)
    }
}

impl From<Invalid> for AnalysisError {
    fn from(e: Invalid) -> Self {
        Self::Invalid(e)
    }
}

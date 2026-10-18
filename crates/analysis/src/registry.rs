//! The analyzer registry: the closed [`AnalyzerId`] enum, the plain list [`ANALYZERS`] and the
//! one dispatch `match` (design Section 7.2, ADR-0024).
//!
//! A new analyzer adds one variant, one line in [`ANALYZERS`] and one arm in [`run`].
//! The list order is the order of design Section 7.1. An analyzer outside
//! [`crate::analyzers`] exports `spec(id)`, and a constant of this module holds its spec.

use ghidorah_kernel::RangeSet;

use crate::analyzers::{
    addrtaken, calls, dataptr, disasm, endbr, entry, fde, gapcomp, noreturn, refs, strings, stubs,
    symbols,
};
use crate::ctx::AnalysisCtx;
use crate::spec::{AnalyzerSpec, Step};
use crate::{cc, jumptable, main_discovery, overrides, stack, syscalls, tailcall};

/// The ID of an analyzer. The list is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnalyzerId {
    /// `Entry` (100): the entry points of the binary.
    Entry,
    /// `Symbols` (110): the function symbols.
    Symbols,
    /// `ImportStubs` (120): the PLT stubs of an ELF file.
    ImportStubs,
    /// `FdeSeeds` (150): the FDE starts of an ELF file.
    FdeSeeds,
    /// `Overrides` (160): the seeds of the agent facts.
    Overrides,
    /// `Disasm` (300): recursive descent.
    Disasm,
    /// `NoReturnKnown` (301): the noreturn list.
    NoReturnKnown,
    /// `NoReturnDiscovered` (302): the noreturn flags of the flow.
    NoReturnDiscovered,
    /// `CallTargets` (400): direct call targets.
    CallTargets,
    /// `JumpTables` (410): the jump tables of method A.
    JumpTables,
    /// `TailCallsAndParts` (420): FETCH tail calls and cold parts.
    TailCallsAndParts,
    /// `MainDiscovery` (430): `main` from the call to `__libc_start_main`.
    MainDiscovery,
    /// `EndbrSeeds` (440): `endbr64` heads.
    EndbrSeeds,
    /// `DataPtrSeeds` (450): code pointers in data.
    DataPtrSeeds,
    /// `AddrTakenSeeds` (460): address-taken code.
    AddrTakenSeeds,
    /// `GapComponents` (470): connected code components in gaps.
    GapComponents,
    /// `References` (600): data references of operands, relocations and address tables.
    References,
    /// `Strings` (650): ASCII, UTF-8 and UTF-16LE strings.
    Strings,
    /// `StackFrames` (700): stack frames and the check of the stack pointer against the CFA.
    StackFrames,
    /// `CallingConvention` (800): the parameters and the varargs flag.
    CallingConvention,
    /// `Syscalls` (810): the syscall notes.
    Syscalls,
}

/// The spec of `Overrides` (160).
const OVERRIDES: AnalyzerSpec = overrides::spec(AnalyzerId::Overrides);
/// The spec of `JumpTables` (410).
const JUMP_TABLES: AnalyzerSpec = jumptable::spec(AnalyzerId::JumpTables);
/// The spec of `TailCallsAndParts` (420).
const TAIL_CALLS: AnalyzerSpec = tailcall::spec(AnalyzerId::TailCallsAndParts);
/// The spec of `MainDiscovery` (430).
const MAIN_DISCOVERY: AnalyzerSpec = main_discovery::spec(AnalyzerId::MainDiscovery);
/// The spec of `StackFrames` (700).
const STACK_FRAMES: AnalyzerSpec = stack::spec(AnalyzerId::StackFrames);
/// The spec of `CallingConvention` (800).
const CALLING_CONVENTION: AnalyzerSpec = cc::spec(AnalyzerId::CallingConvention);
/// The spec of `Syscalls` (810).
const SYSCALLS: AnalyzerSpec = syscalls::spec(AnalyzerId::Syscalls);

/// The analyzers in the order of design Section 7.1.
pub static ANALYZERS: &[&AnalyzerSpec] = &[
    &entry::SPEC,
    &symbols::SPEC,
    &stubs::SPEC,
    &fde::SPEC,
    &OVERRIDES,
    &disasm::SPEC,
    &noreturn::KNOWN,
    &noreturn::DISCOVERED,
    &calls::SPEC,
    &JUMP_TABLES,
    &TAIL_CALLS,
    &MAIN_DISCOVERY,
    &endbr::SPEC,
    &dataptr::SPEC,
    &addrtaken::SPEC,
    &refs::SPEC,
    &strings::SPEC,
    &STACK_FRAMES,
    &CALLING_CONVENTION,
    &SYSCALLS,
];

/// Runs one step of the analyzer `id` over `ranges`.
pub fn run(id: AnalyzerId, ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    match id {
        AnalyzerId::Entry => entry::run(ctx, ranges),
        AnalyzerId::Symbols => symbols::run(ctx, ranges),
        AnalyzerId::ImportStubs => stubs::run(ctx, ranges),
        AnalyzerId::FdeSeeds => fde::run(ctx, ranges),
        AnalyzerId::Overrides => overrides::run(ctx, ranges),
        AnalyzerId::Disasm => disasm::run(ctx, ranges),
        AnalyzerId::NoReturnKnown => noreturn::run_known(ctx, ranges),
        AnalyzerId::NoReturnDiscovered => noreturn::run_discovered(ctx, ranges),
        AnalyzerId::CallTargets => calls::run(ctx, ranges),
        AnalyzerId::JumpTables => jumptable::run(ctx, ranges),
        AnalyzerId::TailCallsAndParts => tailcall::run(ctx, ranges),
        AnalyzerId::MainDiscovery => main_discovery::run(ctx, ranges),
        AnalyzerId::EndbrSeeds => endbr::run(ctx, ranges),
        AnalyzerId::DataPtrSeeds => dataptr::run(ctx, ranges),
        AnalyzerId::AddrTakenSeeds => addrtaken::run(ctx, ranges),
        AnalyzerId::GapComponents => gapcomp::run(ctx, ranges),
        AnalyzerId::References => refs::run(ctx, ranges),
        AnalyzerId::Strings => strings::run(ctx, ranges),
        AnalyzerId::StackFrames => stack::run(ctx, ranges),
        AnalyzerId::CallingConvention => cc::run(ctx, ranges),
        AnalyzerId::Syscalls => syscalls::run(ctx, ranges),
    }
}

/// Gives the index of the analyzer `id` in [`ANALYZERS`].
#[must_use]
pub fn index(id: AnalyzerId) -> Option<usize> {
    ANALYZERS.iter().position(|s| s.id == id)
}

/// Gives the spec of the analyzer with the name `name`.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static AnalyzerSpec> {
    ANALYZERS.iter().copied().find(|s| s.name == name)
}

//! The analyzer registry: the closed [`AnalyzerId`] enum, the plain list [`ANALYZERS`] and the
//! one dispatch `match` (design Section 7.2, ADR-0024).
//!
//! A new analyzer adds one variant, one line in [`ANALYZERS`] and one arm in [`run`].
//! The list order is the order of design Section 7.1.

use ghidorah_kernel::RangeSet;

use crate::analyzers::{calls, disasm, endbr, entry, fde, noreturn, refs, strings, stubs, symbols};
use crate::ctx::AnalysisCtx;
use crate::spec::{AnalyzerSpec, Step};

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
    /// `Disasm` (300): recursive descent.
    Disasm,
    /// `NoReturnKnown` (301): the noreturn list.
    NoReturnKnown,
    /// `NoReturnDiscovered` (302): the noreturn flags of the flow.
    NoReturnDiscovered,
    /// `CallTargets` (400): direct call targets.
    CallTargets,
    /// `EndbrSeeds` (440): `endbr64` heads.
    EndbrSeeds,
    /// `References` (600): data references of operands, relocations and address tables.
    References,
    /// `Strings` (650): ASCII, UTF-8 and UTF-16LE strings.
    Strings,
}

/// The analyzers in the order of design Section 7.1.
pub static ANALYZERS: &[&AnalyzerSpec] = &[
    &entry::SPEC,
    &symbols::SPEC,
    &stubs::SPEC,
    &fde::SPEC,
    &disasm::SPEC,
    &noreturn::KNOWN,
    &noreturn::DISCOVERED,
    &calls::SPEC,
    &endbr::SPEC,
];

/// Runs one step of the analyzer `id` over `ranges`.
pub fn run(id: AnalyzerId, ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    match id {
        AnalyzerId::Entry => entry::run(ctx, ranges),
        AnalyzerId::Symbols => symbols::run(ctx, ranges),
        AnalyzerId::ImportStubs => stubs::run(ctx, ranges),
        AnalyzerId::FdeSeeds => fde::run(ctx, ranges),
        AnalyzerId::Disasm => disasm::run(ctx, ranges),
        AnalyzerId::NoReturnKnown => noreturn::run_known(ctx, ranges),
        AnalyzerId::NoReturnDiscovered => noreturn::run_discovered(ctx, ranges),
        AnalyzerId::CallTargets => calls::run(ctx, ranges),
        AnalyzerId::EndbrSeeds => endbr::run(ctx, ranges),
        AnalyzerId::References => refs::run(ctx, ranges),
        AnalyzerId::Strings => strings::run(ctx, ranges),
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

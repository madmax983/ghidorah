//! The program: the binary, its memory, the managers and two fact layers (design Sections
//! 3.4 and 3.9).
//!
//! The facts live in two [`Tables`] layers:
//!
//! - The base layer holds `Imported`, `Agent` and `User` facts.
//! - The analysis layer ([`AnalysisSet`]) holds `Analysis` facts. `ReplaceAnalysis` swaps the
//!   whole layer in O(1) and keeps the old layer for a rollback.
//!
//! A read merges the layers by these rules:
//!
//! | Facts | Merge rule |
//! |---|---|
//! | One value per key: names, comments, jump tables, flow overrides, data, variables, signatures, noreturn flags | the fact of the higher rank wins |
//! | Many values per key: references, symbols of an address | both layers. The base layer wins for the same key. |
//! | Functions | the analysis record gives the body and the parts. The base record gives the source, the signature and the noreturn flag of a higher rank. |
//! | Code units, strings, why-records | the analysis layer first |
//!
//! An analyzer writes only the analysis layer. So it never replaces an `Agent`, `Imported`
//! or `User` fact (ADR-0013). A read shows the higher fact instead.

mod load;
mod view;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{Address, BinaryId, ExportId, ImportId, Limits, Rev};
use ghidorah_loader::{Arch, Binary, Format, Kind, MemoryMap};
use ghidorah_types::PreludeError;

pub use view::{FuncView, Name, VarView};

use crate::comments::Comments;
use crate::fact::Invalid;
use crate::funcs::Funcs;
use crate::jumptables::JumpTables;
use crate::listing::Listing;
use crate::notes::Notes;
use crate::overrides::FlowOverrides;
use crate::progress::Progress;
use crate::refs::Refs;
use crate::source::Source;
use crate::strings::Strings;
use crate::symbols::Symbols;
use crate::typesglue::Types;
use crate::vars::Vars;
use crate::why::WhyStore;

/// The fact tables of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tables {
    pub(crate) listing: Listing,
    pub(crate) symbols: Symbols,
    pub(crate) refs: Refs,
    pub(crate) funcs: Funcs,
    pub(crate) comments: Comments,
    pub(crate) vars: Vars,
    pub(crate) jumptables: JumpTables,
    pub(crate) strings: Strings,
    pub(crate) why: WhyStore,
    pub(crate) overrides: FlowOverrides,
}

/// The analysis layer: every `Analysis` fact of a program.
pub type AnalysisSet = Tables;

impl Tables {
    /// Gives the code units and data definitions.
    #[must_use]
    pub const fn listing(&self) -> &Listing {
        &self.listing
    }

    /// Gives the symbols.
    #[must_use]
    pub const fn symbols(&self) -> &Symbols {
        &self.symbols
    }

    /// Gives the references.
    #[must_use]
    pub const fn refs(&self) -> &Refs {
        &self.refs
    }

    /// Gives the functions.
    #[must_use]
    pub const fn funcs(&self) -> &Funcs {
        &self.funcs
    }

    /// Gives the comments.
    #[must_use]
    pub const fn comments(&self) -> &Comments {
        &self.comments
    }

    /// Gives the variable facts.
    #[must_use]
    pub const fn vars(&self) -> &Vars {
        &self.vars
    }

    /// Gives the jump tables.
    #[must_use]
    pub const fn jumptables(&self) -> &JumpTables {
        &self.jumptables
    }

    /// Gives the strings.
    #[must_use]
    pub const fn strings(&self) -> &Strings {
        &self.strings
    }

    /// Gives the why-records.
    #[must_use]
    pub const fn why(&self) -> &WhyStore {
        &self.why
    }

    /// Gives the flow overrides.
    #[must_use]
    pub const fn overrides(&self) -> &FlowOverrides {
        &self.overrides
    }
}

/// The identity and the shape of the binary of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryMeta {
    /// The binary ID: the first 8 bytes of the SHA-256.
    pub binary_id: BinaryId,
    /// The SHA-256 of the file.
    pub sha256: [u8; 32],
    /// The format.
    pub format: Format,
    /// The machine.
    pub arch: Arch,
    /// The address width in bits.
    pub bits: u8,
    /// The kind.
    pub kind: Kind,
    /// The image base.
    pub image_base: u64,
    /// The file size in bytes.
    pub file_size: u64,
}

/// One import of the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRow {
    /// The ID.
    pub id: ImportId,
    /// The index in [`Binary::imports`].
    pub index: usize,
    /// The EXTERNAL address: `ext:` and the index plus 1.
    pub ext: Address,
    /// The import slot: the GOT or IAT entry.
    pub slot: Option<Address>,
    /// The stub that jumps through the slot.
    pub stub: Option<Address>,
    /// The import is a PE delay import.
    pub delay: bool,
}

/// One export of the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRow {
    /// The ID.
    pub id: ExportId,
    /// The index in [`Binary::exports`].
    pub index: usize,
    /// The address, or `None` for a PE forwarder.
    pub addr: Option<Address>,
}

/// The error of [`Program::from_binary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    /// The prelude types do not install.
    Prelude(PreludeError),
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prelude(e) => write!(f, "The program has no types: {e}"),
        }
    }
}

impl std::error::Error for ProgramError {}

/// One program: plain owned data. The Tx guard is the only public write path.
#[derive(Debug, Clone)]
pub struct Program {
    binary: Binary,
    mem: MemoryMap,
    meta: BinaryMeta,
    imports: BTreeMap<ImportId, ImportRow>,
    exports: BTreeMap<ExportId, ExportRow>,
    types: Types,
    base: Tables,
    analysis: Box<AnalysisSet>,
    notes: Notes,
    progress: Progress,
    rev: Rev,
}

impl Program {
    /// Makes a program from a loaded binary and its memory map, at revision 0.
    ///
    /// The base layer gets the `Imported` facts of the binary (Section 3.6):
    ///
    /// - one symbol for each named symbol of the symbol tables at a mapped address,
    /// - `<name>@plt`, `<name>@plt.lazy` and `.plt0` at the PLT stubs,
    /// - `<name>@got` at each ELF import slot,
    /// - the import name at the EXTERNAL address of each import.
    ///
    /// The analysis layer is empty. A name that is not UTF-8 keeps its escaped text.
    ///
    /// # Errors
    ///
    /// Returns [`ProgramError::Prelude`] when the prelude types do not install.
    pub fn from_binary(
        binary: Binary,
        mem: MemoryMap,
        limits: &Limits,
    ) -> Result<Self, ProgramError> {
        load::from_binary(binary, mem, limits)
    }

    /// Gives the binary model.
    #[must_use]
    pub const fn binary(&self) -> &Binary {
        &self.binary
    }

    /// Gives the memory map.
    #[must_use]
    pub const fn mem(&self) -> &MemoryMap {
        &self.mem
    }

    /// Gives the identity and shape of the binary.
    #[must_use]
    pub const fn meta(&self) -> &BinaryMeta {
        &self.meta
    }

    /// Gives the imports in ID order.
    #[must_use]
    pub const fn imports(&self) -> &BTreeMap<ImportId, ImportRow> {
        &self.imports
    }

    /// Gives the exports in ID order.
    #[must_use]
    pub const fn exports(&self) -> &BTreeMap<ExportId, ExportRow> {
        &self.exports
    }

    /// Gives the types.
    #[must_use]
    pub const fn types(&self) -> &Types {
        &self.types
    }

    /// Gives the base layer: the `Imported`, `Agent` and `User` facts.
    #[must_use]
    pub const fn base(&self) -> &Tables {
        &self.base
    }

    /// Gives the analysis layer: the `Analysis` facts.
    #[must_use]
    pub fn analysis(&self) -> &AnalysisSet {
        &self.analysis
    }

    /// Gives the notes and the named sets.
    #[must_use]
    pub const fn notes(&self) -> &Notes {
        &self.notes
    }

    /// Gives the progress rows and the marks.
    #[must_use]
    pub const fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Gives the revision.
    #[must_use]
    pub const fn rev(&self) -> Rev {
        self.rev
    }

    /// Gives the layer that a write of `source` changes.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::DefaultSource`] for `Default`. The DB never stores a default.
    pub(crate) fn layer_mut(&mut self, source: Source) -> Result<&mut Tables, Invalid> {
        let _ = source;
        Err(Invalid::DefaultSource)
    }

    /// Puts `set` in place of the analysis layer and gives the old layer.
    pub(crate) fn swap_analysis(&mut self, set: Box<AnalysisSet>) -> Box<AnalysisSet> {
        let _ = set;
        Box::default()
    }

    /// Gives the notes for a change.
    pub(crate) const fn notes_mut(&mut self) -> &mut Notes {
        &mut self.notes
    }

    /// Gives the progress rows for a change.
    pub(crate) const fn progress_mut(&mut self) -> &mut Progress {
        &mut self.progress
    }

    /// Gives the types for a change.
    pub(crate) const fn types_mut(&mut self) -> &mut Types {
        &mut self.types
    }

    /// Sets the revision.
    pub(crate) const fn set_rev(&mut self, rev: Rev) {
        self.rev = rev;
    }
}

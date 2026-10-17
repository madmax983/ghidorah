#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
//! Format probe, ELF64 little-endian parser, raw loader, `MemoryMap` and the owned
//! `Binary` model of ghidorah (design Section 4).
//!
//! The crate is a pure core crate. It reads no file and no clock. The caller gives the bytes.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | [`probe`](mod@probe) | [`probe()`] and [`Detected`] | Sections 4.1, 4.9 |
//! | [`binary`] | [`Binary`], the owned model | Section 4.2 |
//! | [`memmap`] | [`MemoryMap`], [`Region`], [`Perms`] | Section 3.3 |
//! | [`elf`] | The ELF64 LE loader | Section 4.3 |
//! | [`raw`] | The raw loader | Section 4.1 |
//! | [`limits`] | The caps of a load | Section 4.7 |
//! | [`diag`] | [`Diagnostic`] and [`LoadError`] | Section 4.8 |
//!
//! The crate denies `indexing_slicing` and `arithmetic_side_effects`. Hostile input never
//! causes a panic.

pub mod binary;
pub mod diag;
pub mod elf;
pub mod limits;
pub mod memmap;
pub mod probe;
pub mod raw;

use std::sync::Arc;

use ghidorah_base::{DiagCode, Limits};

pub use binary::{
    Arch, Binary, CfaRow, CodeView, DataDir, DynEntry, ElfProtections, Entry, EntryKind, Export,
    Fde, Format, Identity, Import, Kind, Note, PeHeaders, PeProtections, Protections, Reloc,
    RelocForm, RelocSource, RelocType, Relro, RuntimeFunction, Section, SectionKind, Segment,
    SegmentKind, Sym, SymBind, SymKind, SymTable, SymVersion, SymVis,
};
pub use diag::{Diagnostic, LoadError};
pub use memmap::{Bytes, MemError, MemoryMap, Perms, Region, RegionSource};
pub use probe::{Detected, ElfClass, ElfData, probe};
pub use raw::RawOpts;

/// The formats that load fully. `UNSUPPORTED_FORMAT` details and the server instructions
/// read this list.
pub const SUPPORTED_FORMATS: &[&str] = &["elf64-le", "raw"];

/// The settings of a load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoadOpts {
    /// Loads the file as a raw blob, whatever its magic bytes.
    pub raw: Option<RawOpts>,
}

impl LoadOpts {
    /// The settings that let the probe pick the format.
    pub const AUTO: Self = Self { raw: None };

    /// Makes the settings of a raw load at `base`.
    #[must_use]
    pub const fn raw(base: u64, entry: Option<u64>) -> Self {
        Self {
            raw: Some(RawOpts { base, entry }),
        }
    }
}

/// Loads one file into the owned model and its memory map.
///
/// # Errors
///
/// Returns [`LoadError::TooLarge`] above `limits.file_size`,
/// [`LoadError::UnsupportedFormat`] for a format outside [`SUPPORTED_FORMATS`] and
/// [`LoadError::Malformed`] for a bad magic or a cut main header.
pub fn load(
    bytes: &[u8],
    opts: &LoadOpts,
    limits: &Limits,
) -> Result<(Binary, MemoryMap), LoadError> {
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if size > limits.file_size {
        return Err(LoadError::TooLarge {
            size,
            limit: limits.file_size,
        });
    }
    let sha256 = ghidorah_base::sha256(bytes);
    if let Some(raw) = opts.raw {
        return raw::load(Arc::from(bytes), sha256, raw);
    }
    let detected = probe(bytes);
    match detected {
        Detected::Elf {
            class: ElfClass::Elf64,
            data: ElfData::Le,
            e_type: None | Some(elf::consts::ET_EXEC | elf::consts::ET_DYN),
            ..
        } => elf::load(&Arc::from(bytes), sha256, limits),
        Detected::Elf { .. } if bytes.len() < 6 => Err(LoadError::Malformed(
            Diagnostic::new(DiagCode::Oob, "elf.ident")
                .need(6)
                .have(size),
        )),
        Detected::Elf {
            class: ElfClass::Other(_),
            ..
        }
        | Detected::Elf {
            data: ElfData::Other(_),
            ..
        } => Err(LoadError::Malformed(
            Diagnostic::new(DiagCode::BadMagic, "elf.ident").at(4),
        )),
        Detected::Unknown if bytes.len() < 4 => Err(LoadError::Malformed(
            Diagnostic::new(DiagCode::Oob, "probe").need(4).have(size),
        )),
        Detected::Unknown => Err(LoadError::Malformed(
            Diagnostic::new(DiagCode::BadMagic, "probe").at(0),
        )),
        other => Err(LoadError::UnsupportedFormat {
            detected: other.name(),
            supported: SUPPORTED_FORMATS,
        }),
    }
}

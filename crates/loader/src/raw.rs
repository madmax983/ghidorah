//! The raw loader (design Section 4.1).
//!
//! A raw load maps the whole file as one region `raw` with read, write and execute access
//! at `base`. The entry, when given, is the only entry point. Discovery seeds only from it
//! and from agent `func_edit create` calls.

use std::sync::Arc;

use ghidorah_base::{DiagCode, Range};

use crate::binary::{Arch, Binary, Entry, EntryKind, Format, Kind, Segment, SegmentKind};
use crate::diag::{Diagnostic, LoadError};
use crate::memmap::{MemoryMap, Perms, Region, RegionSource};

/// The settings of a raw load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOpts {
    /// The address of the first file byte.
    pub base: u64,
    /// The entry point.
    pub entry: Option<u64>,
}

/// Loads `file` as a raw x86-64 blob at `opts.base`.
///
/// # Errors
///
/// Returns [`LoadError::Malformed`] with `E_OOB` for an empty file and with `E_OVERFLOW`
/// when the blob goes past `u64::MAX`.
pub fn load(
    file: Arc<[u8]>,
    sha256: [u8; 32],
    opts: RawOpts,
) -> Result<(Binary, MemoryMap), LoadError> {
    let len = u64::try_from(file.len()).unwrap_or(u64::MAX);
    if len == 0 {
        return Err(LoadError::Malformed(
            Diagnostic::new(DiagCode::Oob, "raw").need(1).have(0),
        ));
    }
    let va = Range::with_len(opts.base, len).ok_or_else(|| {
        LoadError::Malformed(
            Diagnostic::new(DiagCode::Overflow, "raw.base")
                .at(opts.base)
                .need(len),
        )
    })?;
    let mut binary = Binary::empty(Format::Raw, Arch::X86_64, Kind::Raw, sha256);
    binary.image_base = opts.base;
    binary.entry_points = opts
        .entry
        .map(|addr| Entry {
            addr,
            kind: EntryKind::Entry,
        })
        .into_iter()
        .collect();
    binary.segments.push(Segment {
        index: 0,
        kind: SegmentKind::Raw,
        va: Some(va),
        vaddr: opts.base,
        paddr: opts.base,
        file_off: 0,
        file_size: len,
        mem_size: len,
        perms: Perms::RWX,
        flags: 0,
        align: 1,
    });
    let mut map = MemoryMap::new(file);
    map.map(Region {
        name: "raw".to_string(),
        va,
        file_off: 0,
        file_size: len,
        perms: Perms::RWX,
        source: RegionSource::Raw,
    });
    Ok((binary, map))
}

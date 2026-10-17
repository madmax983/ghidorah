//! Load caps on top of [`Limits`] (design Sections 4.7 and 13.6).
//!
//! Each count from the file goes through [`clamp_count`] before an allocation.
//! A count above its cap gives `E_LIMIT`. A table that runs past its bytes gives `E_OOB`.
//! The load continues with the clamped count.
//!
//! Two more caps keep the heap of a load below 32 times the file size plus 16 MiB (AC-055):
//!
//! | Cap | Value |
//! |---|---|
//! | Text bytes that the load copies (names, notes, versions) | 4 x file size + 1 MiB |
//! | Relocations of all tables together | file size / 4 + 65,536, and at most `Limits::relocations` |

use ghidorah_base::Limits;

use crate::diag::Diags;

/// The extra text bytes of the text cap.
pub const TEXT_SLACK: u64 = 1 << 20;

/// The extra relocations of the relocation cap.
pub const RELOC_SLACK: u64 = 65_536;

/// The caps and the counters of one load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Budget {
    /// The caps of the load.
    pub(crate) limits: Limits,
    /// The text bytes that the load can still copy.
    text_left: u64,
    /// The relocations that the load can still keep.
    relocs_left: u64,
    /// The text cap gave its diagnostic.
    text_told: bool,
}

impl Budget {
    /// Makes the budget of a file with `file_len` bytes.
    pub(crate) fn new(limits: &Limits, file_len: u64) -> Self {
        Self {
            limits: *limits,
            text_left: 0,
            relocs_left: 0,
            text_told: false,
        }
    }
}

/// Clamps a table count from the file.
///
/// `avail` is the count of bytes that the table can use. The result is at most `limit`
/// and at most `avail / entsize`. The function adds `E_LIMIT` or `E_OOB` for each clamp.
pub(crate) fn clamp_count(
    count: u64,
    entsize: u64,
    avail: u64,
    limit: u64,
    path: &str,
    diags: &mut Diags,
) -> usize {
    0
}

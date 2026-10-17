//! Load caps on top of [`Limits`] (design Sections 4.7 and 13.6).
//!
//! Each count from the file goes through a clamp before an allocation.
//! A count above its cap gives `E_LIMIT`. A table that runs past its bytes gives `E_OOB`.
//! The load continues with the clamped count.
//!
//! Two more caps keep the heap of a load below 32 times the file size plus 16 MiB (AC-055):
//!
//! | Cap | Value |
//! |---|---|
//! | Heap bytes of copied text and notes (names, versions, note data) | 4 x file size + 1 MiB |
//! | Relocations of all tables together | file size / 4 + 65,536, and at most `Limits::relocations` |
//!
//! Each cap gives one `E_LIMIT` diagnostic when the load reaches it.

use ghidorah_base::{DiagCode, Limits};

use crate::diag::{Diagnostic, Diags};

/// The extra bytes of the text cap.
pub const TEXT_SLACK: u64 = 1 << 20;

/// The extra relocations of the relocation cap.
pub const RELOC_SLACK: u64 = 65_536;

/// The caps and the counters of one load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Budget {
    /// The caps of the load.
    pub(crate) limits: Limits,
    /// The heap bytes that the load can still use for copies.
    text_left: u64,
    /// The relocations that the load can still keep.
    relocs_left: u64,
    /// The text cap gave its diagnostic.
    text_told: bool,
    /// The relocation cap gave its diagnostic.
    relocs_told: bool,
}

impl Budget {
    /// Makes the budget of a file with `file_len` bytes.
    pub(crate) fn new(limits: &Limits, file_len: u64) -> Self {
        Self {
            limits: *limits,
            text_left: file_len.saturating_mul(4).saturating_add(TEXT_SLACK),
            relocs_left: (file_len / 4)
                .saturating_add(RELOC_SLACK)
                .min(limits.relocations),
            text_told: false,
            relocs_told: false,
        }
    }

    /// Takes `bytes` from the text cap. On `false`, the caller keeps no copy.
    ///
    /// After the first refusal, the cap refuses every later request.
    pub(crate) fn take_text(&mut self, bytes: u64, path: &str, diags: &mut Diags) -> bool {
        if self.text_told {
            return false;
        }
        if let Some(left) = self.text_left.checked_sub(bytes) {
            self.text_left = left;
            return true;
        }
        self.text_told = true;
        diags.push(
            Diagnostic::new(DiagCode::Limit, path)
                .need(bytes)
                .have(self.text_left)
                .hint("the load keeps no more text"),
        );
        false
    }

    /// Tells if the text cap refuses all requests now.
    pub(crate) const fn text_spent(&self) -> bool {
        self.text_told
    }

    /// Takes room for up to `want` relocations and gives the room that the cap allows.
    pub(crate) fn take_relocs(&mut self, want: u64, path: &str, diags: &mut Diags) -> u64 {
        let got = want.min(self.relocs_left);
        self.relocs_left = self.relocs_left.saturating_sub(got);
        if got < want && !self.relocs_told {
            self.relocs_told = true;
            diags.push(
                Diagnostic::new(DiagCode::Limit, path)
                    .need(want)
                    .have(got)
                    .hint("the load keeps no more relocations"),
            );
        }
        got
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
    let mut n = count;
    if n > limit {
        diags.push(
            Diagnostic::new(DiagCode::Limit, path)
                .need(count)
                .have(limit),
        );
        n = limit;
    }
    if let Some(fit) = avail.checked_div(entsize)
        && n > fit
    {
        diags.push(
            Diagnostic::new(DiagCode::Oob, path)
                .need(count.saturating_mul(entsize))
                .have(avail),
        );
        n = fit;
    }
    usize::try_from(n).unwrap_or(usize::MAX)
}

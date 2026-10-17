//! The budget writer (design Section 10.9, ADR-0021).
//!
//! `max_chars` covers the whole serialized `tools/call` result, every copy of the envelope
//! included. The dispatcher applies the budget, not the handlers. The trimmer keeps the
//! longest prefix of items that fits (kernel K6, [`ghidorah_base::fit_prefix`]). It never
//! cuts inside an item or a string.
//!
//! `func_get` splits its budget by section weight: `decomp` 6, `disasm` 3, `ir` 3 and 1 for
//! every other section. Unused budget flows to later sections.

use crate::content::ContentMode;

/// The hard cap of `max_chars`.
pub const HARD_MAX_CHARS: u32 = 60_000;

/// The default `max_chars` of a list tool.
pub const LIST_MAX_CHARS: u32 = 16_000;

/// The default `max_chars` of `func_get` and `batch_run`.
pub const LARGE_MAX_CHARS: u32 = 24_000;

/// The default `max_chars` of `binary_survey`.
pub const SURVEY_MAX_CHARS: u32 = 12_000;

/// The default `max_chars` of the other tools.
pub const OTHER_MAX_CHARS: u32 = 8_000;

/// The characters kept free for protocol members that the transport adds to a result.
///
/// Examples are MCP `resultType` and the `_meta` size report.
pub const PROTOCOL_RESERVE: u64 = 160;

/// The hard cap of a list page (`limit`).
pub const MAX_LIMIT: u32 = 1_000;

/// The output budget of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The largest result in characters.
    pub max_chars: u64,
    /// The content mode of the result.
    pub mode: ContentMode,
}

impl Budget {
    /// Makes a budget.
    #[must_use]
    pub const fn new(max_chars: u64, mode: ContentMode) -> Self {
        Self { max_chars, mode }
    }

    /// Gives the characters of the result that the envelope can use: `max_chars` minus
    /// [`PROTOCOL_RESERVE`].
    #[must_use]
    pub const fn limit(&self) -> u64 {
        0
    }

    /// Gives an estimate of the envelope size that fits: the limit divided by the copies.
    ///
    /// Handlers use it for sub-budgets, for example the sections of `binary_survey`.
    #[must_use]
    pub const fn envelope_chars(&self) -> u64 {
        0
    }
}

/// Gives the number of items that fit: the largest `k` such that the result with the first
/// `k` of `items` fits in `limit` characters.
///
/// `overhead` is the cost of the result with no items. Each item is compact JSON text.
/// The cost of an item and of its separator comes from [`crate::content::cost`].
#[must_use]
pub fn fit_items(items: &[String], overhead: u64, limit: u64, mode: ContentMode) -> usize {
    let _ = (items, overhead, limit, mode);
    0
}

/// Gives the weight of a `func_get` section: `decomp` 6, `disasm` 3, `ir` 3, else 1.
#[must_use]
pub fn section_weight(section: &str) -> u64 {
    let _ = section;
    0
}

/// Splits `total` over sections in include order.
///
/// Each section gets its weight share of the budget that is still free. A section that needs
/// less than its share gives the rest to the later sections. `needs[i]` is the full size of
/// section `i`. The result holds the budget of each section.
#[must_use]
pub fn split_by_weight(total: u64, weights: &[u64], needs: &[u64]) -> Vec<u64> {
    let _ = (total, weights, needs);
    Vec::new()
}

/// Splits `total` evenly over `parts` parts. The first parts get the remainder.
#[must_use]
pub fn split_even(total: u64, parts: usize) -> Vec<u64> {
    let _ = (total, parts);
    Vec::new()
}

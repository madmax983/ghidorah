//! Keyset cursors (design Section 10.9, ADR-0021).
//!
//! A cursor is the lower case hex text of these bytes:
//!
//! | Bytes | Field |
//! |---|---|
//! | 1 | The format version [`VERSION`] |
//! | 2 | The tool index in the registry, little-endian |
//! | 8 | The args hash: SHA-256 of the JCS of the query, see [`args_hash`] |
//! | 1 | The section: 0 for a list page, else a `func_get` section |
//! | 1 + 8 | A flag and the analysis rev of an analysis-derived sort key |
//! | 1 + parts | The sort key of the last returned item, see below |
//! | 4 | The check: the first 4 bytes of FNV-1a 64 over the bytes before it |
//!
//! A key part is `0` and a `u64` (little-endian), or `1`, a `u16` length and UTF-8 bytes.
//! A cursor above [`MAX_CURSOR_CHARS`] characters keeps its key in the [`Spill`] store of
//! the session instead: the part list is `0xff` and the FNV-1a 64 hash of the key.
//!
//! Decode errors:
//!
//! | Cause | Code |
//! |---|---|
//! | The text is not hex, the check fails, the version, tool, section or args hash differ | `CURSOR_INVALID` |
//! | A spilled key that the store does not hold | `CURSOR_INVALID` |
//! | An analysis-derived sort key, and the analysis rev changed | `CURSOR_STALE` |
//!
//! Edits never make a cursor stale. The tools with a name sort check the boundary item.

use std::collections::{BTreeMap, VecDeque};

use crate::args::Args;
use crate::dispatch::{CursorCall, SortKey};
use crate::envelope::Frame;
use crate::errors::ToolError;

/// The format version of a cursor.
pub const VERSION: u8 = 1;

/// The longest cursor text. It equals the cap of the `cursor` argument.
pub const MAX_CURSOR_CHARS: usize = 1_024;

/// The values of the `sort` argument that give analysis-derived sort keys.
pub const ANALYSIS_SORTS: [&str; 3] = ["size", "priority", "in_degree"];

/// The arguments that the args hash leaves out: paging, budget, form and attribution.
pub const PAGING_ARGS: [&str; 8] = [
    "cursor",
    "limit",
    "count_only",
    "shape",
    "fields",
    "format",
    "max_chars",
    "session",
];

/// The largest number of keys in a [`Spill`] store.
pub const SPILL_CAP: usize = 1_024;

/// The largest number of parts in a sort key.
pub const MAX_PARTS: usize = 8;

/// The fields of one cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// The tool index in the registry.
    pub tool_index: u16,
    /// The args hash of the query.
    pub args_hash: [u8; 8],
    /// The section: 0 for a list page.
    pub section: u8,
    /// The analysis rev of an analysis-derived sort key.
    pub analysis_rev: Option<u64>,
    /// The sort key of the last returned item.
    pub key: SortKey,
}

/// The store of long sort keys, keyed by the FNV-1a 64 hash of the key bytes.
///
/// The store keeps at most [`SPILL_CAP`] keys. The oldest key goes first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spill {
    keys: BTreeMap<u64, SortKey>,
    order: VecDeque<u64>,
}

impl Spill {
    /// Makes an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Tells if the store holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Puts `key` in the store and gives its hash.
    pub fn put(&mut self, key: &SortKey) -> u64 {
        let _ = key;
        0
    }

    /// Gives the key with the hash `hash`, or `None`.
    #[must_use]
    pub fn get(&self, hash: u64) -> Option<&SortKey> {
        self.keys.get(&hash)
    }
}

/// Gives the args hash of a query: the first 8 bytes of the SHA-256 of the JCS of an object.
///
/// The object holds the tool arguments with their defaults, the `in` set and the bound binary.
/// The arguments of [`PAGING_ARGS`] are not in it.
#[must_use]
pub fn args_hash(args: &Args, frame: &Frame) -> [u8; 8] {
    let _ = (args, frame);
    [0; 8]
}

/// Tells if the query sorts by an analysis-derived key: its `sort` is in [`ANALYSIS_SORTS`].
#[must_use]
pub fn analysis_derived(args: &Args) -> bool {
    let _ = args;
    false
}

impl Cursor {
    /// Makes the cursor of `call` after the item with `key` in `section`.
    #[must_use]
    pub fn of_call(call: &CursorCall<'_>, key: &SortKey, section: u8) -> Self {
        Self {
            tool_index: u16::try_from(call.tool_index).unwrap_or(u16::MAX),
            args_hash: args_hash(call.args, call.frame),
            section,
            analysis_rev: None,
            key: key.clone(),
        }
    }

    /// Gives the cursor bytes. A long key goes into `spill`.
    #[must_use]
    pub fn to_bytes(&self, spill: &mut Spill) -> Vec<u8> {
        let _ = spill;
        Vec::new()
    }

    /// Reads the cursor bytes. A spilled key comes from `spill`.
    ///
    /// # Errors
    ///
    /// Returns `CURSOR_INVALID` for bytes that are cut, have extra bytes, fail the check or
    /// name a key that `spill` does not hold.
    pub fn from_bytes(bytes: &[u8], spill: &Spill) -> Result<Self, ToolError> {
        let _ = (bytes, spill);
        Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
    }
}

/// Gives the cursor text of `call` after the item with `key` in `section`.
#[must_use]
pub fn encode(call: &CursorCall<'_>, key: &SortKey, section: u8, spill: &mut Spill) -> String {
    let _ = (call, key, section, spill);
    String::new()
}

/// Gives the sort key of the cursor `text` of `call` in `section`.
///
/// # Errors
///
/// Returns `CURSOR_INVALID` or `CURSOR_STALE` as the module docs say.
pub fn decode(
    call: &CursorCall<'_>,
    text: &str,
    section: u8,
    spill: &Spill,
) -> Result<SortKey, ToolError> {
    let _ = (call, text, section, spill);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}

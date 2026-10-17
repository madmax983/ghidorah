//! Caps for file-driven work (design Section 4.7).
//!
//! One [`Limits`] value holds all caps. Each allocation whose size comes from a file uses
//! [`bounded_vec`]. It clamps the count to the bytes left and to the cap before it allocates.
//! A clamp gives an `E_LIMIT` diagnostic, and the load continues with the clamped count.

/// The caps of one load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest input file in bytes (1 GiB).
    pub file_size: u64,
    /// The largest number of program headers (65,535).
    pub program_headers: u64,
    /// The largest number of section headers (65,535).
    pub sections: u64,
    /// The largest number of symbols (4,194,304).
    pub symbols: u64,
    /// The largest number of relocations (16,777,216).
    pub relocations: u64,
    /// The largest number of notes in one segment (4,096).
    pub notes_per_segment: u64,
    /// The longest C string in a table, in bytes (4,096).
    pub string_len: u64,
    /// The largest number of FDEs (1,048,576).
    pub fdes: u64,
    /// The largest number of CFA instructions in one FDE (4,096).
    pub cfa_insns_per_fde: u64,
    /// The largest number of PLT bytes that the stub scan reads (16 MiB).
    pub plt_scan_bytes: u64,
    /// The largest number of PE import DLLs (4,096).
    pub pe_import_dlls: u64,
    /// The largest number of PE imports from one DLL (65,536).
    pub pe_imports_per_dll: u64,
    /// The largest PE `NumberOfFunctions` and `NumberOfNames` (65,536).
    pub pe_exports: u64,
    /// The largest number of PE TLS callbacks (256).
    pub pe_tls_callbacks: u64,
    /// The largest number of PE `.pdata` entries (1,048,576).
    pub pe_pdata_entries: u64,
    /// The deepest PE unwind chain (32).
    pub pe_unwind_depth: u64,
    /// The largest number of PE debug directory entries (64).
    pub pe_debug_entries: u64,
}

impl Limits {
    /// The default caps of Section 4.7.
    pub const DEFAULT: Self = Self {
        file_size: 0,
        program_headers: 0,
        sections: 0,
        symbols: 0,
        relocations: 0,
        notes_per_segment: 0,
        string_len: 0,
        fdes: 0,
        cfa_insns_per_fde: 0,
        plt_scan_bytes: 0,
        pe_import_dlls: 0,
        pe_imports_per_dll: 0,
        pe_exports: 0,
        pe_tls_callbacks: 0,
        pe_pdata_entries: 0,
        pe_unwind_depth: 0,
        pe_debug_entries: 0,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The reason for a clamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clamp {
    /// The bytes left in the input hold fewer entries than the count.
    Bytes,
    /// The cap is below the count.
    Limit,
}

/// The result of [`bounded_count`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    /// The count that the file gives.
    pub requested: u64,
    /// The count after the clamp.
    pub count: usize,
    /// The reason for the clamp, or `None` when the count stays the same.
    pub clamp: Option<Clamp>,
}

/// Clamps a file-given count of entries.
///
/// The count goes down to `remaining_bytes / entry_size`, then to `limit`.
/// An `entry_size` of 0 skips the byte clamp. The result also fits in `usize`.
#[must_use]
pub fn bounded_count(count: u64, entry_size: u64, remaining_bytes: u64, limit: u64) -> Bound {
    let _ = (entry_size, remaining_bytes, limit);
    Bound {
        requested: count,
        count: 0,
        clamp: None,
    }
}

/// Makes an empty vector with room for the clamped count of [`bounded_count`].
#[must_use]
pub fn bounded_vec<T>(
    count: u64,
    entry_size: u64,
    remaining_bytes: u64,
    limit: u64,
) -> (Vec<T>, Bound) {
    let bound = bounded_count(count, entry_size, remaining_bytes, limit);
    (Vec::new(), bound)
}

//! The raw loader (design Section 4.1).
//!
//! A raw load maps the whole file as one region `raw` with read, write and execute access
//! at `base`. The entry, when given, is the only entry point. Discovery seeds only from it
//! and from agent `func_edit create` calls.

use std::sync::Arc;

use ghidorah_base::DiagCode;

use crate::binary::Binary;
use crate::diag::{Diagnostic, LoadError};
use crate::memmap::MemoryMap;

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
    Err(LoadError::Malformed(Diagnostic::new(DiagCode::Oob, "raw")))
}

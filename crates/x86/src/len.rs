//! Layer 1: the structural length decoder (design Section 5.1).

use crate::Opts;
use crate::error::{DecodeError, InvalidReason};

/// The structure of one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Layout {
    /// The instruction length.
    pub(crate) len: u8,
}

/// Scans the structure of the instruction at the start of `bytes`.
pub(crate) fn scan(bytes: &[u8], opts: &Opts) -> Result<Layout, DecodeError> {
    let _ = (bytes, opts);
    Err(DecodeError::Invalid {
        len_consumed: 0,
        reason: InvalidReason::Undefined,
    })
}

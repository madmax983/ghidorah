//! Layer 2: the semantic decoder (design Section 5.1).

use crate::error::{DecodeError, InvalidReason};
use crate::insn::Insn;
use crate::len::Layout;

/// Builds the instruction of a scanned layout.
pub(crate) fn build(bytes: &[u8], addr: u64, layout: &Layout) -> Result<Insn, DecodeError> {
    let _ = (bytes, addr);
    Err(DecodeError::Invalid {
        len_consumed: layout.len,
        reason: InvalidReason::Undefined,
    })
}

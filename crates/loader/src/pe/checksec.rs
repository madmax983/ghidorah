//! The protections of a PE file from `DllCharacteristics` (design Section 4.13).
//!
//! | Field | Bit |
//! |---|---|
//! | `high_entropy_va` | `HIGH_ENTROPY_VA` (0x20) |
//! | `dynamic_base` | `DYNAMIC_BASE` (0x40) |
//! | `force_integrity` | `FORCE_INTEGRITY` (0x80) |
//! | `nx_compat` | `NX_COMPAT` (0x100) |
//! | `guard_cf` | `GUARD_CF` (0x4000) |

use crate::binary::{PeProtections, Protections};

/// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`.
const HIGH_ENTROPY_VA: u16 = 0x20;
/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`.
const DYNAMIC_BASE: u16 = 0x40;
/// `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`.
const FORCE_INTEGRITY: u16 = 0x80;
/// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.
const NX_COMPAT: u16 = 0x100;
/// `IMAGE_DLLCHARACTERISTICS_GUARD_CF`.
const GUARD_CF: u16 = 0x4000;

/// Gives the protections of `DllCharacteristics`.
pub(crate) const fn protections(flags: u16) -> Protections {
    Protections::Pe(PeProtections {
        dynamic_base: flags & DYNAMIC_BASE != 0,
        high_entropy_va: flags & HIGH_ENTROPY_VA != 0,
        nx_compat: flags & NX_COMPAT != 0,
        guard_cf: flags & GUARD_CF != 0,
        force_integrity: flags & FORCE_INTEGRITY != 0,
    })
}

//! The Microsoft x64 calling convention of PE binaries (design Section 7.10, WP-30).

use crate::cc::{CallConv, SYSV_X86_64};

/// The Microsoft x64 convention of PE binaries.
pub const MS_X64: CallConv = CallConv {
    name: "ms_x64",
    ..SYSV_X86_64
};

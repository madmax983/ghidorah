//! The decoder errors of design Section 5.1.

use std::fmt;

/// Why a decode failed.
///
/// A sweep can step over [`DecodeError::Unsupported`] with its `len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeError {
    /// The bytes end inside the instruction.
    Truncated {
        /// The number of bytes that the decoder had, at most 15.
        have: u8,
        /// The smallest total length that the decoder knows the instruction needs.
        need_at_least: u8,
    },
    /// No instruction starts with these bytes.
    Invalid {
        /// The number of bytes that the decoder read before it stopped.
        len_consumed: u8,
        /// The reason.
        reason: InvalidReason,
    },
    /// The opcode is not valid in the 64-bit mode.
    InvalidInMode {
        /// The length of the prefixes and the opcode.
        len: u8,
    },
    /// The instruction is valid, and its length is known, but the tables do not cover it.
    Unsupported {
        /// The feature of the instruction.
        feature: Feature,
        /// The instruction length.
        len: u8,
    },
}

impl DecodeError {
    /// Gives the number of bytes that a linear sweep can skip after this error.
    ///
    /// The value is at least 1.
    #[must_use]
    pub fn skip(&self) -> u8 {
        let n = match *self {
            Self::Truncated { have, .. } => have,
            Self::Invalid { len_consumed, .. } => len_consumed,
            Self::InvalidInMode { len } | Self::Unsupported { len, .. } => len,
        };
        n.max(1)
    }

    /// Gives the stable name of the error kind, for example `truncated`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "truncated",
            Self::Invalid { .. } => "invalid",
            Self::InvalidInMode { .. } => "invalid_in_mode",
            Self::Unsupported { .. } => "unsupported",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                have,
                need_at_least,
            } => write!(
                f,
                "the instruction needs at least {need_at_least} bytes, but only {have} bytes are available"
            ),
            Self::Invalid {
                len_consumed,
                reason,
            } => write!(
                f,
                "no instruction starts with these bytes ({reason}, {len_consumed} bytes read)"
            ),
            Self::InvalidInMode { len } => {
                write!(
                    f,
                    "the opcode is not valid in the 64-bit mode ({len} bytes)"
                )
            }
            Self::Unsupported { feature, len } => {
                write!(
                    f,
                    "the decoder tables do not cover this {feature} instruction ({len} bytes)"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// The reason of a [`DecodeError::Invalid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidReason {
    /// The instruction is longer than 15 bytes.
    TooLong,
    /// The opcode has no definition.
    Undefined,
    /// The `lock` prefix is on an instruction that cannot take it.
    BadLock,
    /// The operand must be memory, but the ModRM byte selects a register.
    RegisterForm,
    /// The operand must be a register, but the ModRM byte selects memory.
    MemoryForm,
    /// The VEX, EVEX or XOP map field selects no map.
    BadMap,
    /// A reserved bit of an EVEX prefix has the wrong value.
    BadEvex,
    /// A VEX, EVEX or XOP prefix follows a legacy prefix (strict option only).
    VexAfterPrefix,
    /// A REX2 prefix is followed by a prefix or by the `0F` escape.
    BadRex2,
}

impl InvalidReason {
    /// Gives the stable name of the reason, for example `too_long`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TooLong => "too_long",
            Self::Undefined => "undefined",
            Self::BadLock => "bad_lock",
            Self::RegisterForm => "register_form",
            Self::MemoryForm => "memory_form",
            Self::BadMap => "bad_map",
            Self::BadEvex => "bad_evex",
            Self::VexAfterPrefix => "vex_after_prefix",
            Self::BadRex2 => "bad_rex2",
        }
    }
}

impl fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The feature of a [`DecodeError::Unsupported`] instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feature {
    /// A system instruction of the `0F 01` group, for example a VMX or SGX form.
    System,
}

impl Feature {
    /// Gives the stable name of the feature, for example `system`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::System => "system",
        }
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

//! The x86-64 decoder and printer of ghidorah (design Section 5).
//!
//! The crate is a pure core crate. It does no I/O and reads no clock.
//!
//! | Item | Content | Design |
//! |---|---|---|
//! | [`length`] | Layer 1: the structural length of one instruction | Section 5.1 |
//! | [`decode`] | Layer 2: an [`Insn`] with a mnemonic, operands and flow | Sections 5.1, 5.3 |
//! | [`print()`] | The Intel display text of an [`Insn`] | Section 5.4 |
//! | [`Mnem`] | The canonical mnemonics | Section 5.4 |
//! | [`Reg`], [`RegSet`] | The register model, with XMM registers | Section 5.3 |
//! | [`Operand`], [`Mem`] | The operand model | Section 5.3 |
//! | [`Flow`] | The control flow kind of an instruction | Section 5.3 |
//!
//! Layer 1 knows the prefix, `ModRM`, SIB, displacement and immediate sizes of all maps:
//! 1-byte, 0F, 0F38, 0F3A, VEX2, VEX3, EVEX, REX2 and XOP. Layer 2 has semantic tables
//! for the general-purpose set, x87 and the legacy SSE and SSE2 forms. Other vector
//! forms decode as opaque forms with the mnemonic `(vector)` (design Section 5.1).
//!
//! Hostile bytes never cause a panic. Each decode reads at most 15 bytes.

mod decode;
mod error;
mod fields;
mod flags;
mod flow;
mod implicit;
mod insn;
mod len;
mod operand;
mod print;
mod regs;
mod tables;

pub use error::{DecodeError, Feature, InvalidReason};
pub use flags::FlagSet;
pub use flow::Flow;
pub use insn::{Encoding, Insn, Map, OpaqueForm, Ops, PrefixSet, RawFields};
pub use operand::{Access, Mem, Operand};
pub use print::{NoSymbols, Symbolizer, operand_text, print};
pub use regs::{Reg, RegClass, RegSet, Seg};
pub use tables::mnem::Mnem;

/// The largest length of one instruction in bytes.
pub const MAX_LEN: usize = 15;

/// The decoder options of design Section 5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Opts {
    /// Use the AMD rule for a `66` prefix on a near branch: `call`, `jmp` and `jcc`
    /// take a 16-bit displacement. The default `false` uses the LLVM rule: `call` keeps
    /// a 32-bit displacement, and `jmp` and `jcc` take a 16-bit displacement.
    pub amd_branch_osz: bool,
    /// Reject a VEX, EVEX or XOP form after a `66`, `F2`, `F3`, `F0` or REX prefix,
    /// as the hardware does. The default `false` accepts it, as the oracle does.
    pub strict_vex_legacy_prefix: bool,
}

impl Opts {
    /// The default options.
    pub const DEFAULT: Self = Self {
        amd_branch_osz: false,
        strict_vex_legacy_prefix: false,
    };
}

/// Gives the length of the instruction at the start of `bytes`, with the default options.
///
/// The function reads at most [`MAX_LEN`] bytes. A valid length is between 1 and 15.
///
/// # Errors
///
/// Returns [`DecodeError::Truncated`] when `bytes` ends inside the instruction,
/// [`DecodeError::Invalid`] or [`DecodeError::InvalidInMode`] for bytes that no
/// instruction of the 64-bit mode starts with.
pub fn length(bytes: &[u8]) -> Result<u8, DecodeError> {
    length_with(bytes, &Opts::DEFAULT)
}

/// Gives the length of the instruction at the start of `bytes`.
///
/// # Errors
///
/// Returns the errors of [`length`].
pub fn length_with(bytes: &[u8], opts: &Opts) -> Result<u8, DecodeError> {
    len::scan(bytes, *opts).map(|layout| layout.len)
}

/// Decodes the instruction at the start of `bytes`. `addr` is the address of the first byte.
///
/// The result depends only on the first [`Insn::len`] bytes, so
/// `decode(&bytes[..len], ..)` gives the same instruction (AC-062c).
///
/// # Errors
///
/// Returns the errors of [`length`]. It also returns [`DecodeError::Invalid`] for an
/// undefined opcode, a bad `lock` prefix or a register in place of memory.
/// It returns [`DecodeError::Unsupported`] for a valid form outside the tables.
pub fn decode(bytes: &[u8], addr: u64, opts: &Opts) -> Result<Insn, DecodeError> {
    let layout = len::scan(bytes, *opts)?;
    decode::build(bytes, addr, &layout)
}

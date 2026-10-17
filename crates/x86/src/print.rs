//! The Intel syntax printer (design Section 5.4).

use crate::insn::Insn;

/// Gives names and notes for addresses in the display text.
///
/// The implementer gives escaped and capped text, for example through `BinText`.
pub trait Symbolizer {
    /// Gives the name of a branch or call target.
    fn name(&self, addr: u64) -> Option<String> {
        let _ = addr;
        None
    }

    /// Gives the note text for the target of a RIP-relative operand.
    fn note(&self, addr: u64) -> Option<String> {
        let _ = addr;
        None
    }
}

/// A symbolizer that knows no names.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSymbols;

impl Symbolizer for NoSymbols {}

/// Gives the Intel display text of an instruction.
#[must_use]
pub fn print<S: Symbolizer + ?Sized>(insn: &Insn, sym: &S) -> String {
    let _ = (insn, sym);
    String::new()
}

/// Gives the display text of the operand at `index`.
#[must_use]
pub fn operand_text<S: Symbolizer + ?Sized>(insn: &Insn, index: usize, sym: &S) -> Option<String> {
    let _ = (insn, index, sym);
    None
}

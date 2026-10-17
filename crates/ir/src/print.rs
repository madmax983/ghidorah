//! The IR text and JSON printers (design Sections 6.1 and 10.4, `func_get include ir`).
//!
//! Both printers show the instructions of an [`Arena`] in address order, then the ops
//! outside each instruction (L1 phis and pass ops). The output is deterministic: equal
//! arenas give equal bytes.
//!
//! Text form, one line for each instruction and each op:
//!
//! ```text
//! 0x401000 len=3
//!   op:0x401000:0 v0 = Get.64 rax
//!   op:0x401000:1 v1 = Add.64 v0 0x8
//!   op:0x401000:2 Put.64 rax v1
//! ```
//!
//! An op shows its output value, its opcode with its width, the aux byte (a flag operation,
//! a condition, or `#n` for an input width) and its arguments. A `Syscall` or `Intrinsic`
//! op shows its effect: `name=.. defs=[..] uses=[..] mem=..`. A `Phi` op shows its
//! arguments in brackets.
//!
//! JSON form: `{"insns":[{"addr","len","ops":[op]}],"extra":[op]}`. Each op is
//! `{"id","opc","w","out"?,"args":[..],"sub"?,"effect"?,"phi"?}`. An argument is `v<n>`
//! for a value, `0x..` for a constant and the location name for a location. `sub` is the
//! flag operation name, the condition name or the input width.

use crate::arena::Arena;
use crate::op::{IntrinsicId, Op};

/// Gives the names of intrinsic instructions. The ISA crate gives the meaning of an
/// [`IntrinsicId`], so it implements this trait.
pub trait IntrinsicNames {
    /// Gives the name of an intrinsic instruction, or `None` for an unknown number.
    fn name(&self, id: IntrinsicId) -> Option<&'static str>;
}

/// The names of no intrinsic instruction. The printers then show `#<number>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoNames;

impl IntrinsicNames for NoNames {
    fn name(&self, _id: IntrinsicId) -> Option<&'static str> {
        None
    }
}

/// Gives the text of one op, without the op ID.
#[must_use]
pub fn op_text(arena: &Arena, op: &Op, names: &dyn IntrinsicNames) -> String {
    let _ = (arena, op, names);
    String::new()
}

/// Gives the text form of an arena.
#[must_use]
pub fn text(arena: &Arena, names: &dyn IntrinsicNames) -> String {
    let _ = (arena, names);
    String::new()
}

/// Gives the JSON form of an arena on one line.
#[must_use]
pub fn json(arena: &Arena, names: &dyn IntrinsicNames) -> String {
    let _ = (arena, names);
    String::new()
}

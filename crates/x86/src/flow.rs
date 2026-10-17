//! The control flow kind of an instruction (design Section 5.3).

use std::fmt;

/// The control flow kind of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Flow {
    /// Execution continues at the next instruction.
    #[default]
    Seq,
    /// A direct jump.
    Jmp,
    /// A conditional branch: `jcc`, `loop`, `jrcxz` or `xbegin`.
    Jcc,
    /// A direct call.
    Call,
    /// An indirect call through a register or memory.
    ICall,
    /// An indirect jump through a register or memory.
    IJmp,
    /// A return: `ret`, `retf`, `iret` or `sysret`.
    Ret,
    /// An instruction that does not continue: `int3`, `ud2` or `hlt`.
    Trap,
    /// No valid instruction. A decoded [`crate::Insn`] never has this kind.
    Invalid,
}

impl Flow {
    /// Gives the stable name, for example `seq` or `icall`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Seq => "seq",
            Self::Jmp => "jmp",
            Self::Jcc => "jcc",
            Self::Call => "call",
            Self::ICall => "icall",
            Self::IJmp => "ijmp",
            Self::Ret => "ret",
            Self::Trap => "trap",
            Self::Invalid => "invalid",
        }
    }

    /// Tells if execution can continue at the next instruction.
    ///
    /// A call continues, because the callee can return.
    #[must_use]
    pub const fn falls_through(self) -> bool {
        matches!(self, Self::Seq | Self::Jcc | Self::Call | Self::ICall)
    }

    /// Tells if the kind changes the control flow.
    #[must_use]
    pub const fn is_branch(self) -> bool {
        !matches!(self, Self::Seq | Self::Invalid)
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

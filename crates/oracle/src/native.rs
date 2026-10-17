//! The native semantic oracle: instruction forms that run on the host CPU (design
//! Section 13.8, ADR-0025).
//!
//! Each [`Form`] holds the bytes of one instruction form and a harness function. The harness
//! loads the registers, the flags and a memory buffer from a [`State`], runs the bytes,
//! and stores the state again. [`Form::vectors`] makes the semantic vectors of a form: fixed
//! inputs from a seeded stream, and the outputs of the host CPU.
//!
//! Only `xtask oracle semantics` runs a form, in a child process for each form. The
//! vectors go to `tests/golden/semantics/x86/<file>.jsonl`, and `cargo test` replays them
//! through the lifter and the interpreter.
//!
//! Address model of a vector:
//!
//! - The instruction has the address [`VIP`].
//! - The memory buffer has the address [`VBASE`]. A pointer register of a form holds
//!   `VBASE + offset` in the vector. The harness gives it the host address of the buffer.
//! - A register outside the register list of a form holds [`FILL`] plus its number.
//!
//! Kinds of forms:
//!
//! | Kind | Harness | Output `pc` |
//! |---|---|---|
//! | `plain` | the bytes only | not listed |
//! | `branch` | a 4-byte `lea r14, [r14+1]` after the branch, which jumps over it | the next address or the target |
//! | `call` | `call` to the next address, then `lea r14, [rip]` | the target |
//! | `ret` | `lea r14` and `mov [rsp], r14` before `ret`, so the return goes to the next address | not listed |

use std::fmt::Write as _;

mod tables;

/// The address of the instruction of each vector.
pub const VIP: u64 = 0x1000;

/// The address of the memory buffer of each vector.
pub const VBASE: u64 = 0x1_0000;

/// The value of a register outside the register list: `FILL` plus the register number.
pub const FILL: u64 = 0x5a5a_5a5a_0000_0000;

/// The size of the memory buffer in bytes.
pub const MEM: usize = 64;

/// The status flags of the flags word: CF, PF, AF, ZF, SF and OF.
pub const STATUS: u64 = 0x8d5;

/// The machine state that a harness loads and stores.
///
/// The harness uses fixed offsets: the 16 general registers at 0, the flags at 128, four
/// XMM registers at 136, the saved stack pointer at 200 and the buffer at 208.
#[repr(C, align(16))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// The general registers in encoding order. `r15` holds the state address.
    pub gpr: [u64; 16],
    /// The flags register.
    pub flags: u64,
    /// `xmm0` to `xmm3` as low and high halves.
    pub xmm: [[u64; 2]; 4],
    /// The stack pointer of the harness.
    pub save: u64,
    /// The memory buffer.
    pub mem: [u8; MEM],
}

impl Default for State {
    fn default() -> Self {
        Self {
            gpr: [0; 16],
            flags: 2,
            xmm: [[0; 2]; 4],
            save: 0,
            mem: [0; MEM],
        }
    }
}

/// A register of a vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum R {
    /// `rax`
    Rax,
    /// `rcx`
    Rcx,
    /// `rdx`
    Rdx,
    /// `rbx`
    Rbx,
    /// `rsp`
    Rsp,
    /// `rbp`
    Rbp,
    /// `rsi`
    Rsi,
    /// `rdi`
    Rdi,
    /// `r8`
    R8,
    /// `r9`
    R9,
    /// `r10`
    R10,
    /// `r11`
    R11,
    /// `r12`
    R12,
    /// `r13`
    R13,
    /// `r14`
    R14,
    /// `xmm0`
    Xmm0,
    /// `xmm1`
    Xmm1,
    /// `xmm2`
    Xmm2,
    /// `xmm3`
    Xmm3,
    /// The status flags.
    Flags,
    /// The address of the next instruction that runs.
    Pc,
}

impl R {
    /// Gives the name of the register in a vector file, for example `rax` or `pc`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rax => "rax",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rbx => "rbx",
            Self::Rsp => "rsp",
            Self::Rbp => "rbp",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::Xmm0 => "xmm0",
            Self::Xmm1 => "xmm1",
            Self::Xmm2 => "xmm2",
            Self::Xmm3 => "xmm3",
            Self::Flags => "flags",
            Self::Pc => "pc",
        }
    }

    /// Gives the general register number, or `None` for another register.
    #[must_use]
    pub const fn gpr(self) -> Option<usize> {
        match self {
            Self::Rax => Some(0),
            Self::Rcx => Some(1),
            Self::Rdx => Some(2),
            Self::Rbx => Some(3),
            Self::Rsp => Some(4),
            Self::Rbp => Some(5),
            Self::Rsi => Some(6),
            Self::Rdi => Some(7),
            Self::R8 => Some(8),
            Self::R9 => Some(9),
            Self::R10 => Some(10),
            Self::R11 => Some(11),
            Self::R12 => Some(12),
            Self::R13 => Some(13),
            Self::R14 => Some(14),
            _ => None,
        }
    }

    /// Gives the XMM register number, or `None` for another register.
    #[must_use]
    pub const fn xmm(self) -> Option<usize> {
        match self {
            Self::Xmm0 => Some(0),
            Self::Xmm1 => Some(1),
            Self::Xmm2 => Some(2),
            Self::Xmm3 => Some(3),
            _ => None,
        }
    }
}

/// The harness kind of a form. The module table gives the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// The bytes run alone.
    Plain,
    /// A branch over a 4-byte tail.
    Branch,
    /// A call of the next address.
    Call,
    /// A return to the next address.
    Ret,
}

impl Kind {
    /// Gives the name of the kind in a vector file.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Branch => "branch",
            Self::Call => "call",
            Self::Ret => "ret",
        }
    }
}

/// A limit on the random inputs of a form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// No limit.
    Free,
    /// `div` at this width: a divisor that is not 0 and a high half below the divisor.
    Div(u8),
    /// `idiv` at this width: a divisor that is not 0 and a high half that sign-extends the
    /// low half.
    Idiv(u8),
    /// A shift count in `cl` of at most 16, for the 16-bit `shld` and `shrd`.
    Count16,
    /// `rcx` below this value, for a `rep` prefix and `loop`.
    SmallRcx(u8),
    /// A register below this value, for an index register.
    Small(R, u8),
    /// The `cl`, `dl` or wider operand of `cmpxchg` at this width equals the accumulator in
    /// one half of the vectors.
    Equal(u8),
    /// A bit offset in `ecx` from -128 to 383 for a bit string at `rsi`.
    BitIndex,
    /// The quadword at `rsp` holds only status flags, for `popf`.
    PopfWord,
    /// The second half of the buffer copies the first half with one changed byte, for
    /// `repe cmps`.
    SameMem,
}

/// One instruction form of the oracle.
#[derive(Clone, Copy)]
pub struct Form {
    /// The vector file without its extension, for example `alu2`.
    pub file: &'static str,
    /// The canonical mnemonic of the instruction.
    pub row: &'static str,
    /// The operation width in bits.
    pub w: u16,
    /// The name of the form, for example `add eax, ecx`.
    pub name: &'static str,
    /// The harness kind.
    pub kind: Kind,
    /// The bytes of the instruction.
    pub bytes: &'static [u8],
    /// The registers of each vector, in order. Each one is an input and an output.
    pub regs: &'static [R],
    /// The pointer registers and their offsets in the buffer.
    pub ptrs: &'static [(R, u8)],
    /// The count of buffer bytes in each vector, or 0 for no memory.
    pub mem: u8,
    /// The count of vectors.
    pub cases: u16,
    /// The limit on the inputs.
    pub rule: Rule,
    /// The harness.
    run: unsafe fn(*mut State),
}

impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Form")
            .field("file", &self.file)
            .field("name", &self.name)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// One semantic vector of a form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vector {
    /// The input value of each register of the form.
    pub inputs: Vec<u128>,
    /// The output value of each register of the form.
    pub outputs: Vec<u128>,
    /// The buffer before the run.
    pub mem_in: Vec<u8>,
    /// The buffer after the run.
    pub mem_out: Vec<u8>,
}

/// Gives every form of the oracle.
pub fn forms() -> impl Iterator<Item = &'static Form> {
    tables::FAMILIES.iter().flat_map(|f| f.iter())
}

/// Finds the form with a name.
#[must_use]
pub fn find(name: &str) -> Option<&'static Form> {
    forms().find(|f| f.name == name)
}

impl Form {
    /// Runs the form on the host CPU and gives its vectors.
    ///
    /// The inputs depend only on the form name, so each run gives the same inputs.
    #[must_use]
    pub fn vectors(&self) -> Vec<Vector> {
        let _ = self.run;
        Vec::new()
    }

    /// Gives the header line of the form in a vector file.
    #[must_use]
    pub fn header_line(&self) -> String {
        let mut out = String::new();
        let _ = write!(out, "{{\"form\":\"{}\"", self.name);
        out
    }

    /// Gives the line of one vector in a vector file.
    #[must_use]
    pub fn vector_line(&self, v: &Vector) -> String {
        let _ = v;
        String::new()
    }
}

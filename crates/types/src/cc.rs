//! Calling-convention tables (design Section 7.10).
//!
//! A table is data. The analysis reads the register names and the stack offsets from it.
//! Register names are the lower case Intel names of the x86 printer, for example `rdi`.
//! ELF binaries use [`SYSV_X86_64`]. PE binaries use [`MS_X64`].

pub use crate::msx64::MS_X64;

/// One calling-convention table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallConv {
    /// The table name, for example `sysv`.
    pub name: &'static str,
    /// The integer and pointer argument registers in order.
    pub int_args: &'static [&'static str],
    /// The floating argument registers in order.
    pub float_args: &'static [&'static str],
    /// The integer return registers, the low part first.
    pub int_ret: &'static [&'static str],
    /// The floating return registers, the low part first.
    pub float_ret: &'static [&'static str],
    /// The registers that the callee keeps.
    pub callee_saved: &'static [&'static str],
    /// `true` when argument n always uses slot n of each register list (MS x64).
    pub positional: bool,
    /// The offset of the first stack parameter from the stack pointer at entry.
    pub stack_arg_offset: u32,
    /// The bytes that the caller keeps free above the return address for the callee.
    pub shadow_space: u32,
    /// The bytes below the stack pointer that a leaf function can use.
    pub red_zone: u32,
    /// The stack alignment at a call, in bytes.
    pub stack_align: u32,
    /// The change of the stack pointer at the return: the pop of the return address.
    pub return_pop: u32,
    /// The register that gives the count of vector registers of a variadic call.
    pub varargs_reg: Option<&'static str>,
}

/// The System V AMD64 convention of ELF binaries.
pub const SYSV_X86_64: CallConv = CallConv {
    name: "sysv",
    int_args: &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    float_args: &[
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    ],
    int_ret: &["rax", "rdx"],
    float_ret: &["xmm0", "xmm1"],
    callee_saved: &["rbx", "rbp", "rsp", "r12", "r13", "r14", "r15"],
    positional: false,
    stack_arg_offset: 8,
    shadow_space: 0,
    red_zone: 128,
    stack_align: 16,
    return_pop: 8,
    varargs_reg: Some("al"),
};

impl CallConv {
    /// Tells if the callee keeps the register `reg`.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.contains(&reg)
    }

    /// Gives the position of `reg` in the integer argument list.
    #[must_use]
    pub fn int_arg_index(&self, reg: &str) -> Option<usize> {
        self.int_args.iter().position(|r| *r == reg)
    }

    /// Gives the position of `reg` in the floating argument list.
    #[must_use]
    pub fn float_arg_index(&self, reg: &str) -> Option<usize> {
        self.float_args.iter().position(|r| *r == reg)
    }
}

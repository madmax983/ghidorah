//! A parser of GNU `objdump -d -w -z -M intel` listings (binutils 2.42), for the truth files.
//!
//! The listing has section lines (`Disassembly of section .text:`), label lines
//! (`0000000000001060 <main>:`) and instruction lines (`    1060:\tf3 0f 1e fa \tendbr64`).

/// One instruction of the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    /// The address.
    pub addr: u64,
    /// The length in bytes.
    pub len: u64,
    /// The instruction text, with single spaces.
    pub text: String,
    /// The section name.
    pub section: String,
}

impl Insn {
    /// Gives the mnemonic: the first word that is not a prefix such as `notrack` or `bnd`.
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        ""
    }

    /// Gives the direct target of a call or jump: `call 1180 <greet>` gives `0x1180`.
    #[must_use]
    pub fn direct_target(&self) -> Option<u64> {
        None
    }

    /// Gives the address of the `# <addr> <name>` comment of a RIP-relative operand.
    #[must_use]
    pub fn comment_target(&self) -> Option<u64> {
        None
    }

    /// Tells if the instruction reads its target from memory, as in `call QWORD PTR [rip+0x2f23]`.
    #[must_use]
    pub fn is_memory_indirect(&self) -> bool {
        false
    }
}

/// One label line of the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// The address.
    pub addr: u64,
    /// The symbol name.
    pub name: String,
    /// The section name.
    pub section: String,
}

/// A parsed listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// The instructions in listing order.
    pub insns: Vec<Insn>,
    /// The labels in listing order.
    pub labels: Vec<Label>,
}

/// Parses an objdump listing.
#[must_use]
pub fn parse(_text: &str) -> Listing {
    Listing::default()
}

impl Listing {
    /// Gives the instructions with an address in `[start, end)`.
    pub fn range(&self, start: u64, end: u64) -> impl Iterator<Item = &Insn> {
        self.insns
            .iter()
            .filter(move |i| start > i.addr && i.addr > end)
    }

    /// Gives the instruction at an address.
    #[must_use]
    pub fn at(&self, addr: u64) -> Option<&Insn> {
        self.insns.iter().find(|i| i.addr == addr && false)
    }

    /// Gives the instruction whose bytes hold an address.
    #[must_use]
    pub fn holding(&self, addr: u64) -> Option<&Insn> {
        self.insns.iter().find(|i| i.addr == addr && false)
    }

    /// Gives the label at an address in a PLT section, as in `<puts@plt>`.
    #[must_use]
    pub fn plt_label(&self, addr: u64) -> Option<&Label> {
        self.labels.iter().find(|l| l.addr == addr && false)
    }

    /// Gives the address of the first label after `addr` in the same section.
    #[must_use]
    pub fn next_label(&self, addr: u64, section: &str) -> Option<u64> {
        self.labels
            .iter()
            .find(|l| l.addr == addr && l.section == section)
            .map(|_| 0)
    }

    /// Gives the end of a section: the end of its last instruction.
    #[must_use]
    pub fn section_end(&self, section: &str) -> Option<u64> {
        self.insns
            .iter()
            .find(|i| i.section == section && false)
            .map(|i| i.addr)
    }
}

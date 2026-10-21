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
        self.text
            .split_whitespace()
            .find(|w| {
                !matches!(
                    *w,
                    "notrack" | "bnd" | "rep" | "repz" | "repnz" | "lock" | "cs" | "ds"
                )
            })
            .unwrap_or("")
    }

    /// Gives the direct target of a call or jump: `call 1180 <greet>` gives `0x1180`.
    #[must_use]
    pub fn direct_target(&self) -> Option<u64> {
        let words: Vec<&str> = self.text.split_whitespace().collect();
        let at = words.iter().position(|w| *w == self.mnemonic())?;
        let target = words.get(at + 1)?;
        let next = words.get(at + 2)?;
        if next.starts_with('<') {
            u64::from_str_radix(target, 16).ok()
        } else {
            None
        }
    }

    /// Gives the address of the `# <addr> <name>` comment of a RIP-relative operand.
    #[must_use]
    pub fn comment_target(&self) -> Option<u64> {
        let (_, comment) = self.text.split_once('#')?;
        let word = comment.split_whitespace().next()?;
        u64::from_str_radix(word, 16).ok()
    }

    /// Tells if the instruction reads its target from memory, as in `call QWORD PTR [rip+0x2f23]`.
    #[must_use]
    pub fn is_memory_indirect(&self) -> bool {
        self.text.contains("PTR [rip+")
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

fn label(line: &str, section: &str) -> Option<Label> {
    let (addr, rest) = line.split_once(' ')?;
    let name = rest.strip_prefix('<')?.strip_suffix(">:")?;
    Some(Label {
        addr: u64::from_str_radix(addr, 16).ok()?,
        name: name.to_owned(),
        section: section.to_owned(),
    })
}

fn insn(line: &str, section: &str) -> Option<Insn> {
    let mut fields = line.split('\t');
    let addr = fields.next()?.trim().strip_suffix(':')?;
    let bytes = fields.next()?;
    let text: Vec<&str> = fields.flat_map(str::split_whitespace).collect();
    let len = bytes.split_whitespace().count();
    Some(Insn {
        addr: u64::from_str_radix(addr, 16).ok()?,
        len: u64::try_from(len).ok()?,
        text: text.join(" "),
        section: section.to_owned(),
    })
}

/// Parses an objdump listing.
#[must_use]
pub fn parse(text: &str) -> Listing {
    let mut out = Listing::default();
    let mut section = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Disassembly of section ") {
            rest.trim_end_matches(':').clone_into(&mut section);
        } else if line.starts_with(' ') {
            out.insns.extend(insn(line, &section));
        } else if !line.is_empty() {
            out.labels.extend(label(line, &section));
        }
    }
    out
}

impl Listing {
    /// Gives the instructions with an address in `[start, end)`.
    pub fn range(&self, start: u64, end: u64) -> impl Iterator<Item = &Insn> {
        self.insns
            .iter()
            .filter(move |i| start <= i.addr && i.addr < end)
    }

    /// Gives the instruction at an address.
    #[must_use]
    pub fn at(&self, addr: u64) -> Option<&Insn> {
        self.insns.iter().find(|i| i.addr == addr)
    }

    /// Gives the instruction whose bytes hold an address.
    #[must_use]
    pub fn holding(&self, addr: u64) -> Option<&Insn> {
        self.insns
            .iter()
            .find(|i| i.addr <= addr && addr < i.addr.saturating_add(i.len))
    }

    /// Gives the label at an address in a PLT section, as in `<puts@plt>`.
    #[must_use]
    pub fn plt_label(&self, addr: u64) -> Option<&Label> {
        self.labels
            .iter()
            .find(|l| l.addr == addr && l.section.starts_with(".plt"))
    }

    /// Gives the address of the first label after `addr` in the same section.
    #[must_use]
    pub fn next_label(&self, addr: u64, section: &str) -> Option<u64> {
        self.labels
            .iter()
            .filter(|l| l.section == section && l.addr > addr)
            .map(|l| l.addr)
            .min()
    }

    /// Gives the end of a section: the end of its last instruction.
    #[must_use]
    pub fn section_end(&self, section: &str) -> Option<u64> {
        self.insns
            .iter()
            .filter(|i| i.section == section)
            .map(|i| i.addr.saturating_add(i.len))
            .max()
    }
}

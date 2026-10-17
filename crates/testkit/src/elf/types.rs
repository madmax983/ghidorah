//! Plain data types of the ELF builder: places, sections, symbols, imports and the layout.

use std::collections::BTreeMap;

use super::consts::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_PROGBITS, STB_GLOBAL, STB_LOCAL, STB_WEAK,
    STT_FUNC, STT_OBJECT,
};

/// The ELF class of a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// ELF32.
    Elf32,
    /// ELF64.
    Elf64,
}

/// The byte order of a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

/// A place in the built file. The builder gives it an address after the layout.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Loc {
    /// An offset in a named section.
    Section(String, u64),
    /// The value of a `.symtab` or `.dynsym` symbol of the builder.
    Symbol(String),
    /// An absolute address.
    Abs(u64),
    /// The PLT stub of an import. With IBT stubs it is the `.plt.sec` stub.
    Plt(String),
    /// The `.plt.got` stub of an import.
    PltGot(String),
    /// The GOT slot of an import (`.got.plt` or `.got`).
    Got(String),
}

impl Loc {
    /// Makes a section location.
    #[must_use]
    pub fn section(name: &str, offset: u64) -> Self {
        Self::Section(name.to_string(), offset)
    }

    /// Makes a symbol location.
    #[must_use]
    pub fn symbol(name: &str) -> Self {
        Self::Symbol(name.to_string())
    }
}

/// The kind of a code or data fixup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupKind {
    /// A 32-bit value `target - (place + 4)`, for `call`, `jmp` and RIP-relative operands.
    Rel32,
    /// A 64-bit absolute address.
    Abs64,
    /// A 32-bit absolute address.
    Abs32,
}

/// A value that the builder writes into section bytes after the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixup {
    /// The offset of the value in the section.
    pub offset: u64,
    /// The kind of value.
    pub kind: FixupKind,
    /// The target place.
    pub target: Loc,
}

/// A user section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section name.
    pub name: String,
    /// The section type (`sh_type`).
    pub kind: u32,
    /// The section flags (`sh_flags`).
    pub flags: u64,
    /// The section bytes. A `SHT_NOBITS` section has no bytes.
    pub data: Vec<u8>,
    /// The size of a `SHT_NOBITS` section.
    pub nobits_size: u64,
    /// The alignment (`sh_addralign`).
    pub align: u64,
    /// The entry size (`sh_entsize`).
    pub entsize: u64,
    /// The fixups of the section bytes.
    pub fixups: Vec<Fixup>,
}

impl Section {
    /// Makes a section with a type, flags and bytes. The alignment is 1.
    #[must_use]
    pub fn new(name: &str, kind: u32, flags: u64, data: &[u8]) -> Self {
        Self {
            name: name.to_string(),
            kind,
            flags,
            data: data.to_vec(),
            nobits_size: 0,
            align: 1,
            entsize: 0,
            fixups: Vec::new(),
        }
    }

    /// Makes an executable code section with alignment 16.
    #[must_use]
    pub fn code(name: &str, data: &[u8]) -> Self {
        Self::new(name, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, data).align(16)
    }

    /// Makes a read-only data section with alignment 8.
    #[must_use]
    pub fn rodata(name: &str, data: &[u8]) -> Self {
        Self::new(name, SHT_PROGBITS, SHF_ALLOC, data).align(8)
    }

    /// Makes a writable data section with alignment 8.
    #[must_use]
    pub fn data(name: &str, data: &[u8]) -> Self {
        Self::new(name, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, data).align(8)
    }

    /// Makes a `SHT_NOBITS` section of `size` bytes with alignment 8.
    #[must_use]
    pub fn bss(name: &str, size: u64) -> Self {
        let mut s = Self::new(name, SHT_NOBITS, SHF_ALLOC | SHF_WRITE, &[]).align(8);
        s.nobits_size = size;
        s
    }

    /// Sets the alignment.
    #[must_use]
    pub const fn align(mut self, align: u64) -> Self {
        self.align = align;
        self
    }

    /// Sets the entry size.
    #[must_use]
    pub const fn entsize(mut self, entsize: u64) -> Self {
        self.entsize = entsize;
        self
    }

    /// Adds a fixup at `offset`.
    #[must_use]
    pub fn fixup(mut self, offset: u64, kind: FixupKind, target: Loc) -> Self {
        self.fixups.push(Fixup {
            offset,
            kind,
            target,
        });
        self
    }
}

/// A symbol of `.symtab` or an export of `.dynsym`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The symbol name.
    pub name: String,
    /// The symbol value.
    pub at: Loc,
    /// The symbol size.
    pub size: u64,
    /// The symbol type (`STT_*`).
    pub kind: u8,
    /// The symbol binding (`STB_*`).
    pub bind: u8,
}

impl Symbol {
    /// Makes a global function symbol.
    #[must_use]
    pub fn func(name: &str, at: Loc, size: u64) -> Self {
        Self {
            name: name.to_string(),
            at,
            size,
            kind: STT_FUNC,
            bind: STB_GLOBAL,
        }
    }

    /// Makes a global data object symbol.
    #[must_use]
    pub fn object(name: &str, at: Loc, size: u64) -> Self {
        Self {
            name: name.to_string(),
            at,
            size,
            kind: STT_OBJECT,
            bind: STB_GLOBAL,
        }
    }

    /// Makes the symbol local.
    #[must_use]
    pub const fn local(mut self) -> Self {
        self.bind = STB_LOCAL;
        self
    }

    /// Makes the symbol weak.
    #[must_use]
    pub const fn weak(mut self) -> Self {
        self.bind = STB_WEAK;
        self
    }
}

/// How the builder links an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// A PLT stub, a `.got.plt` slot and an `R_X86_64_JUMP_SLOT` relocation.
    Plt,
    /// A `.got` slot and an `R_X86_64_GLOB_DAT` relocation, for `-fno-plt` call sites.
    Got,
    /// A `.plt.got` stub, a `.got` slot and an `R_X86_64_GLOB_DAT` relocation.
    PltGot,
}

/// The form of the PLT stubs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PltStyle {
    /// Classic lazy stubs in `.plt`: `ff 25 disp32; 68 imm32; e9 rel32`.
    Lazy,
    /// IBT stubs: lazy entries in `.plt` and `f3 0f 1e fa f2 ff 25 disp32` stubs in `.plt.sec`.
    Ibt,
}

/// The dynamic hash tables of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStyle {
    /// No hash table.
    None,
    /// `.hash` only.
    Sysv,
    /// `.gnu.hash` only.
    Gnu,
    /// `.hash` and `.gnu.hash`.
    Both,
}

/// The relocation table of a [`Reloc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocTable {
    /// `.rela.dyn` (24-byte entries with addends).
    Rela,
    /// `.rel.dyn` (16-byte entries without addends).
    Rel,
}

/// A dynamic relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// The table.
    pub table: RelocTable,
    /// The place that the relocation changes.
    pub at: Loc,
    /// The relocation type (`R_X86_64_*`).
    pub kind: u32,
    /// The `.dynsym` symbol name, or `None` for symbol index 0.
    pub sym: Option<String>,
    /// The addend. A REL entry does not store it.
    pub addend: i64,
}

/// One note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The section name, for example `.note.gnu.build-id`.
    pub section: String,
    /// The note owner name, for example `GNU`.
    pub name: String,
    /// The note type.
    pub kind: u32,
    /// The descriptor bytes.
    pub desc: Vec<u8>,
    /// The alignment: 4 or 8.
    pub align: u64,
}

/// One `.eh_frame` FDE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fde {
    /// The first address of the function.
    pub at: Loc,
    /// The length of the function in bytes.
    pub len: u64,
    /// The CFA instructions of the FDE.
    pub program: Vec<u8>,
}

impl Fde {
    /// Makes an FDE with the CFA rows of a `push rbp; mov rbp, rsp` prologue.
    #[must_use]
    pub fn frame_pointer(at: Loc, len: u64) -> Self {
        Self {
            at,
            len,
            program: vec![0x41, 0x0e, 0x10, 0x86, 0x02, 0x43, 0x0d, 0x06],
        }
    }
}

/// A section after the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedSection {
    /// The section name.
    pub name: String,
    /// The section header index.
    pub index: u16,
    /// The virtual address. A section with no memory has address 0.
    pub addr: u64,
    /// The file offset.
    pub offset: u64,
    /// The size in bytes.
    pub size: u64,
}

/// The addresses that the layout gave.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    /// The sections in header order, without the null section.
    pub sections: Vec<PlacedSection>,
    /// The symbol values by name.
    pub symbols: BTreeMap<String, u64>,
    /// The PLT stub address of each PLT import.
    pub plt: BTreeMap<String, u64>,
    /// The `.plt.got` stub address of each `PltGot` import.
    pub plt_got: BTreeMap<String, u64>,
    /// The GOT slot address of each import.
    pub got: BTreeMap<String, u64>,
    /// The entry point.
    pub entry: u64,
    /// The number of program headers.
    pub phnum: u16,
}

impl Layout {
    /// Returns the placed section with `name`.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&PlacedSection> {
        self.sections.iter().find(|s| s.name == name)
    }
}

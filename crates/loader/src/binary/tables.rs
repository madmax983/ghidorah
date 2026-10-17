//! The table rows of the `Binary` model: segments, sections, symbols, relocations,
//! imports and exports.

use ghidorah_base::{BinText, Range};

use crate::memmap::Perms;

/// The kind of a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SegmentKind {
    /// An ELF program header with its raw `p_type`.
    Elf(u32),
    /// The mapped PE headers.
    PeHeaders,
    /// A mapped PE section.
    PeSection,
    /// The one region of a raw load.
    Raw,
}

/// One program header, or one mapped region of a format without program headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The index in the program header table.
    pub index: u32,
    /// The kind.
    pub kind: SegmentKind,
    /// The addresses, or `None` when the memory size is 0 or the end overflows.
    pub va: Option<Range>,
    /// The raw virtual address (`p_vaddr`).
    pub vaddr: u64,
    /// The raw physical address (`p_paddr`).
    pub paddr: u64,
    /// The file offset (`p_offset`).
    pub file_off: u64,
    /// The file size (`p_filesz`).
    pub file_size: u64,
    /// The memory size (`p_memsz`).
    pub mem_size: u64,
    /// The access bits.
    pub perms: Perms,
    /// The raw flags (`p_flags`).
    pub flags: u32,
    /// The alignment (`p_align`).
    pub align: u64,
}

/// The kind of a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SectionKind {
    /// An ELF section with its raw `sh_type`.
    Elf(u32),
    /// A PE section. `flags` holds its `Characteristics`.
    Pe,
}

/// One section header with its raw values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The index in the section header table.
    pub index: u32,
    /// The name.
    pub name: BinText,
    /// The kind.
    pub kind: SectionKind,
    /// The addresses of an allocated section with a size above 0.
    pub va: Option<Range>,
    /// The raw address (`sh_addr`).
    pub addr: u64,
    /// The file offset (`sh_offset`).
    pub file_off: u64,
    /// The size (`sh_size`).
    pub size: u64,
    /// The raw flags (`sh_flags`), or the PE `Characteristics`.
    pub flags: u64,
    /// `sh_link`.
    pub link: u32,
    /// `sh_info`.
    pub info: u32,
    /// `sh_addralign`.
    pub align: u64,
    /// `sh_entsize`.
    pub entsize: u64,
}

/// The type of a symbol (`STT_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymKind {
    /// `STT_NOTYPE`.
    NoType,
    /// `STT_OBJECT`.
    Object,
    /// `STT_FUNC`.
    Func,
    /// `STT_SECTION`.
    Section,
    /// `STT_FILE`.
    File,
    /// `STT_COMMON`.
    Common,
    /// `STT_TLS`.
    Tls,
    /// `STT_GNU_IFUNC`.
    Ifunc,
    /// Another raw type.
    Other(u8),
}

impl SymKind {
    /// Gives the kind of a raw `STT_*` value.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self::Other(raw)
    }
}

/// The binding of a symbol (`STB_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymBind {
    /// `STB_LOCAL`.
    Local,
    /// `STB_GLOBAL`.
    Global,
    /// `STB_WEAK`.
    Weak,
    /// `STB_GNU_UNIQUE`.
    Unique,
    /// Another raw binding.
    Other(u8),
}

impl SymBind {
    /// Gives the binding of a raw `STB_*` value.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self::Other(raw)
    }
}

/// The visibility of a symbol (`STV_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymVis {
    /// `STV_DEFAULT`.
    Default,
    /// `STV_INTERNAL`.
    Internal,
    /// `STV_HIDDEN`.
    Hidden,
    /// `STV_PROTECTED`.
    Protected,
}

impl SymVis {
    /// Gives the visibility of the low 2 bits of `st_other`.
    #[must_use]
    pub const fn from_other(st_other: u8) -> Self {
        Self::Default
    }
}

/// The table of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymTable {
    /// `.symtab`.
    Symtab,
    /// `.dynsym`, or the `DT_SYMTAB` table.
    Dynsym,
    /// A PE export.
    Export,
    /// A PE IAT slot.
    Iat,
}

/// The version of a dynamic symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymVersion {
    /// The version name, for example `GLIBC_2.2.5`.
    pub name: BinText,
    /// The version index of `DT_VERSYM` without the hidden bit.
    pub index: u16,
    /// The hidden bit of `DT_VERSYM` is set.
    pub hidden: bool,
    /// The version comes from `DT_VERNEED`, so the symbol comes from another file.
    pub needed: bool,
}

/// One symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sym {
    /// The index in its table.
    pub index: u32,
    /// The name.
    pub name: BinText,
    /// The version of a dynamic symbol.
    pub version: Option<SymVersion>,
    /// The value (`st_value`).
    pub addr: u64,
    /// The size (`st_size`).
    pub size: u64,
    /// The type.
    pub kind: SymKind,
    /// The binding.
    pub bind: SymBind,
    /// The visibility.
    pub vis: SymVis,
    /// The section index. `SHN_XINDEX` resolves through `SHT_SYMTAB_SHNDX`.
    pub shndx: u32,
    /// The table.
    pub table: SymTable,
}

/// A relocation type with its raw number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelocType(pub u32);

impl RelocType {
    /// Gives the `R_X86_64_*` name of the type, or `None` for an unknown type.
    #[must_use]
    pub const fn x86_64_name(self) -> Option<&'static str> {
        None
    }
}

/// The table form of a relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelocForm {
    /// A REL entry. The addend is in the place.
    Rel,
    /// A RELA entry with an addend.
    Rela,
    /// A RELR entry: an implicit `R_X86_64_RELATIVE`.
    Relr,
}

/// One relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reloc {
    /// The address of the place.
    pub offset: u64,
    /// The type.
    pub kind: RelocType,
    /// The symbol index, or `None` for index 0.
    pub sym: Option<u32>,
    /// The table of the symbol index.
    pub sym_table: SymTable,
    /// The addend. A REL or RELR entry has 0.
    pub addend: i64,
    /// The table form.
    pub form: RelocForm,
    /// The table of the relocation.
    pub source: RelocSource,
}

/// The table of a relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelocSource {
    /// The section with this header index.
    Section(u32),
    /// The `DT_REL` table of the dynamic view.
    DynRel,
    /// The `DT_RELA` table of the dynamic view.
    DynRela,
    /// The `DT_RELR` table of the dynamic view.
    DynRelr,
    /// The `DT_JMPREL` table of the dynamic view.
    DynPlt,
}

/// One import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The library: a PE DLL. ELF does not bind a library.
    pub lib: Option<BinText>,
    /// The name.
    pub name: Option<BinText>,
    /// The PE ordinal.
    pub ordinal: Option<u16>,
    /// The PE hint.
    pub hint: Option<u16>,
    /// The address of the import slot.
    pub slot: Option<u64>,
    /// The address of the stub that jumps through the slot.
    pub stub: Option<u64>,
    /// The relocation type of the slot.
    pub reloc_kind: Option<RelocType>,
    /// The import is a PE delay import.
    pub delay: bool,
}

/// One export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The name.
    pub name: Option<BinText>,
    /// The PE ordinal.
    pub ordinal: Option<u32>,
    /// The address, or `None` for a forwarder.
    pub addr: Option<u64>,
    /// The PE forwarder text.
    pub forwarder: Option<BinText>,
}

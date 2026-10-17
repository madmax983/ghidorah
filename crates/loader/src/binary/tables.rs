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
        match raw {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            5 => Self::Common,
            6 => Self::Tls,
            10 => Self::Ifunc,
            other => Self::Other(other),
        }
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
        match raw {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            10 => Self::Unique,
            other => Self::Other(other),
        }
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
        match st_other & 3 {
            0 => Self::Default,
            1 => Self::Internal,
            2 => Self::Hidden,
            _ => Self::Protected,
        }
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
    /// The `DT_VERSYM` value has the hidden bit.
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
        let name = match self.0 {
            0 => "R_X86_64_NONE",
            1 => "R_X86_64_64",
            2 => "R_X86_64_PC32",
            3 => "R_X86_64_GOT32",
            4 => "R_X86_64_PLT32",
            5 => "R_X86_64_COPY",
            6 => "R_X86_64_GLOB_DAT",
            7 => "R_X86_64_JUMP_SLOT",
            8 => "R_X86_64_RELATIVE",
            9 => "R_X86_64_GOTPCREL",
            10 => "R_X86_64_32",
            11 => "R_X86_64_32S",
            12 => "R_X86_64_16",
            13 => "R_X86_64_PC16",
            14 => "R_X86_64_8",
            15 => "R_X86_64_PC8",
            16 => "R_X86_64_DTPMOD64",
            17 => "R_X86_64_DTPOFF64",
            18 => "R_X86_64_TPOFF64",
            19 => "R_X86_64_TLSGD",
            20 => "R_X86_64_TLSLD",
            21 => "R_X86_64_DTPOFF32",
            22 => "R_X86_64_GOTTPOFF",
            23 => "R_X86_64_TPOFF32",
            24 => "R_X86_64_PC64",
            25 => "R_X86_64_GOTOFF64",
            26 => "R_X86_64_GOTPC32",
            27 => "R_X86_64_GOT64",
            28 => "R_X86_64_GOTPCREL64",
            29 => "R_X86_64_GOTPC64",
            30 => "R_X86_64_GOTPLT64",
            31 => "R_X86_64_PLTOFF64",
            32 => "R_X86_64_SIZE32",
            33 => "R_X86_64_SIZE64",
            34 => "R_X86_64_GOTPC32_TLSDESC",
            35 => "R_X86_64_TLSDESC_CALL",
            36 => "R_X86_64_TLSDESC",
            37 => "R_X86_64_IRELATIVE",
            38 => "R_X86_64_RELATIVE64",
            41 => "R_X86_64_GOTPCRELX",
            42 => "R_X86_64_REX_GOTPCRELX",
            43 => "R_X86_64_CODE_4_GOTPCRELX",
            44 => "R_X86_64_CODE_4_GOTTPOFF",
            45 => "R_X86_64_CODE_4_GOTPC32_TLSDESC",
            _ => return None,
        };
        Some(name)
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

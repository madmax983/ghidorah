//! The owned `Binary` model (design Section 4.2, layer b).
//!
//! The model is the same for every format. The ELF loader fills the ELF fields. The PE
//! loader fills `pdata`, `data_dirs`, `pe` and `identity.codeview`. The loader extras fill
//! `imports`, `fdes` and `protections` from the same bytes. So `db`, `analysis` and `tools`
//! read one model.
//!
//! Raw values from the file stay raw: section types, flags and relocation types keep
//! their numbers, and text keeps its bytes as [`BinText`].

mod tables;

use ghidorah_base::{BinText, BinaryId, Range, hex};

pub use tables::{
    Export, Import, Reloc, RelocForm, RelocSource, RelocType, Section, SectionKind, Segment,
    SegmentKind, Sym, SymBind, SymKind, SymTable, SymVersion, SymVis,
};

use crate::diag::Diagnostic;

/// The file format of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// ELF64, little-endian.
    Elf64Le,
    /// PE32+.
    Pe32Plus,
    /// A raw blob of code.
    Raw,
}

impl Format {
    /// Gives the format name of [`SUPPORTED_FORMATS`](crate::SUPPORTED_FORMATS).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Elf64Le => "elf64-le",
            Self::Pe32Plus => "pe32+-x86_64",
            Self::Raw => "raw",
        }
    }
}

/// The machine of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Arch {
    /// x86-64. Code analysis runs.
    X86_64,
    /// Another machine, with its raw `e_machine` or `Machine` value. Only the survey runs.
    Other(u16),
}

impl Arch {
    /// Tells if code analysis can run.
    #[must_use]
    pub const fn is_x86_64(self) -> bool {
        matches!(self, Self::X86_64)
    }
}

impl std::fmt::Display for Arch {
    /// Writes `x86_64` or `other:<machine>` with the machine in decimal.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86_64 => f.write_str("x86_64"),
            Self::Other(machine) => write!(f, "other:{machine}"),
        }
    }
}

/// The kind of a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// An executable at a fixed address (`ET_EXEC`, or a PE EXE).
    Exec,
    /// A position-independent image (`ET_DYN`, or a PE DLL).
    Dyn,
    /// A raw blob.
    Raw,
}

/// The kind of an entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    /// The entry point of the file header.
    Entry,
    /// The function of `DT_INIT`.
    Init,
    /// The function of `DT_FINI`.
    Fini,
    /// An element of the init array.
    InitArray,
    /// An element of the fini array.
    FiniArray,
    /// An element of the preinit array.
    PreinitArray,
    /// A PE export in an executable region.
    Export,
    /// A PE TLS callback.
    TlsCallback,
}

/// One entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    /// The address.
    pub addr: u64,
    /// The kind.
    pub kind: EntryKind,
}

/// One dynamic entry: `d_tag` and `d_val`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DynEntry {
    /// The tag (`DT_*`).
    pub tag: u64,
    /// The value or the address.
    pub val: u64,
}

/// The `CodeView` `RSDS` record of a PE debug directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeView {
    /// The GUID bytes in file order.
    pub guid: [u8; 16],
    /// The age.
    pub age: u32,
    /// The PDB path.
    pub pdb: BinText,
}

/// The identity of a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The SHA-256 of the file.
    pub sha256: [u8; 32],
    /// The GNU build ID in lower case hex.
    pub build_id: Option<String>,
    /// The `DT_SONAME` text, or the PE export DLL name.
    pub soname: Option<BinText>,
    /// The PE `CodeView` record.
    pub codeview: Option<CodeView>,
}

impl Identity {
    /// Gives the binary ID: the first 8 bytes of the SHA-256.
    #[must_use]
    pub fn binary_id(&self) -> BinaryId {
        BinaryId::from_sha256(&self.sha256)
    }

    /// Gives the SHA-256 as 64 lower case hex digits.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex::encode(&self.sha256)
    }
}

/// The RELRO state of an ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relro {
    /// No `PT_GNU_RELRO`.
    None,
    /// `PT_GNU_RELRO` without immediate binding.
    Partial,
    /// `PT_GNU_RELRO` with `DF_BIND_NOW` or `DF_1_NOW`.
    Full,
}

/// The protections of an ELF file (design Section 4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one checksec protection of design Section 4.6"
)]
pub struct ElfProtections {
    /// The file is a position-independent executable.
    pub pie: bool,
    /// The stack is not executable.
    pub nx: bool,
    /// The RELRO state.
    pub relro: Relro,
    /// The file imports `__stack_chk_fail`.
    pub canary: bool,
    /// The file imports a function whose name ends with `_chk`.
    pub fortify: bool,
    /// The GNU property note sets IBT.
    pub ibt: bool,
    /// The GNU property note sets SHSTK.
    pub shstk: bool,
    /// The `DT_RPATH` text.
    pub rpath: Option<BinText>,
    /// The `DT_RUNPATH` text.
    pub runpath: Option<BinText>,
    /// The file has no `.symtab`.
    pub stripped: bool,
}

/// The protections of a PE file from `DllCharacteristics` (design Section 4.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one DllCharacteristics bit of design Section 4.13"
)]
pub struct PeProtections {
    /// `DYNAMIC_BASE` (0x40).
    pub dynamic_base: bool,
    /// `HIGH_ENTROPY_VA` (0x20).
    pub high_entropy_va: bool,
    /// `NX_COMPAT` (0x100).
    pub nx_compat: bool,
    /// `GUARD_CF` (0x4000).
    pub guard_cf: bool,
    /// `FORCE_INTEGRITY` (0x80).
    pub force_integrity: bool,
}

/// The protections of a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protections {
    /// The protections of an ELF file.
    Elf(ElfProtections),
    /// The protections of a PE file.
    Pe(PeProtections),
}

/// One CFA row of an FDE: the CFA rule from `pc` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CfaRow {
    /// The first address of the row.
    pub pc: u64,
    /// The DWARF number of the CFA register.
    pub reg: u16,
    /// The offset from the register.
    pub offset: i64,
}

/// One `.eh_frame` FDE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fde {
    /// The PC range.
    pub range: Range,
    /// The file offset of the CIE.
    pub cie: u64,
    /// The CFA rule at the start of each row.
    pub cfa_rows: Vec<CfaRow>,
}

/// One PE `RUNTIME_FUNCTION` entry. The values are RVAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeFunction {
    /// `BeginAddress`.
    pub begin: u32,
    /// `EndAddress`.
    pub end: u32,
    /// `UnwindInfoAddress`.
    pub unwind: u32,
    /// The unwind data has `CHAININFO`, so the entry is a part of another function.
    pub fragment: bool,
}

/// One PE data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataDir {
    /// The directory index (0 to 15).
    pub index: u8,
    /// The RVA. Directory 4 holds a file offset.
    pub rva: u32,
    /// The size in bytes.
    pub size: u32,
}

/// The PE headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeHeaders {
    /// The optional header magic.
    pub magic: u16,
    /// The COFF `Machine`.
    pub machine: u16,
    /// The COFF `Characteristics`.
    pub characteristics: u16,
    /// `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// `Subsystem`.
    pub subsystem: u16,
    /// `SectionAlignment`.
    pub section_alignment: u32,
    /// `FileAlignment`.
    pub file_alignment: u32,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
}

/// One note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The owner name without the NUL byte.
    pub name: BinText,
    /// The note type.
    pub kind: u32,
    /// The descriptor bytes, cut at the string length limit.
    pub desc: Vec<u8>,
    /// The descriptor size in the file.
    pub desc_size: u64,
}

impl Note {
    /// Gives the kept descriptor bytes in lower case hex.
    #[must_use]
    pub fn desc_hex(&self) -> String {
        hex::encode(&self.desc)
    }
}

/// The owned model of one loaded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binary {
    /// The format.
    pub format: Format,
    /// The machine.
    pub arch: Arch,
    /// The address width in bits.
    pub bits: u8,
    /// The kind.
    pub kind: Kind,
    /// The image base: the lowest page of the mapped image.
    pub image_base: u64,
    /// The entry points in address order, then kind order.
    pub entry_points: Vec<Entry>,
    /// The program headers, or one segment per mapped PE region.
    pub segments: Vec<Segment>,
    /// The section headers in table order.
    pub sections: Vec<Section>,
    /// The symbols: each table in section order, each symbol in table order.
    pub symbols: Vec<Sym>,
    /// The imports.
    pub imports: Vec<Import>,
    /// The exports.
    pub exports: Vec<Export>,
    /// The relocations in table order.
    pub relocs: Vec<Reloc>,
    /// The `DT_NEEDED` libraries, or the PE import DLLs in descriptor order.
    pub libraries: Vec<BinText>,
    /// The identity.
    pub identity: Identity,
    /// The protections. The loader extras compute them.
    pub protections: Option<Protections>,
    /// The `.eh_frame` FDEs.
    pub fdes: Vec<Fde>,
    /// The PE `.pdata` entries.
    pub pdata: Vec<RuntimeFunction>,
    /// The PE data directories.
    pub data_dirs: Vec<DataDir>,
    /// The PE headers.
    pub pe: Option<PeHeaders>,
    /// The notes of the `PT_NOTE` segments.
    pub notes: Vec<Note>,
    /// The dynamic entries up to the first `DT_NULL`, which they hold.
    pub dynamic: Vec<DynEntry>,
    /// The program interpreter of `PT_INTERP`.
    pub interp: Option<BinText>,
    /// The `DT_RPATH` text.
    pub rpath: Option<BinText>,
    /// The `DT_RUNPATH` text.
    pub runpath: Option<BinText>,
    /// The kept diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// The count of diagnostics above [`MAX_DIAGNOSTICS`](crate::diag::MAX_DIAGNOSTICS).
    pub diagnostics_dropped: u64,
}

impl Binary {
    /// Makes an empty model with an identity. Every list is empty.
    #[must_use]
    pub const fn empty(format: Format, arch: Arch, kind: Kind, sha256: [u8; 32]) -> Self {
        Self {
            format,
            arch,
            bits: 64,
            kind,
            image_base: 0,
            entry_points: Vec::new(),
            segments: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            relocs: Vec::new(),
            libraries: Vec::new(),
            identity: Identity {
                sha256,
                build_id: None,
                soname: None,
                codeview: None,
            },
            protections: None,
            fdes: Vec::new(),
            pdata: Vec::new(),
            data_dirs: Vec::new(),
            pe: None,
            notes: Vec::new(),
            dynamic: Vec::new(),
            interp: None,
            rpath: None,
            runpath: None,
            diagnostics: Vec::new(),
            diagnostics_dropped: 0,
        }
    }

    /// Gives the value of the first dynamic entry with `tag`.
    #[must_use]
    pub fn dyn_value(&self, tag: u64) -> Option<u64> {
        self.dynamic.iter().find(|e| e.tag == tag).map(|e| e.val)
    }

    /// Gives the symbols of one table in table order.
    pub fn symbols_of(&self, table: SymTable) -> impl Iterator<Item = &Sym> {
        self.symbols.iter().filter(move |s| s.table == table)
    }

    /// Gives the section with this header index.
    #[must_use]
    pub fn section(&self, index: u32) -> Option<&Section> {
        let at = usize::try_from(index).ok()?;
        self.sections.get(at).filter(|s| s.index == index)
    }
}

//! `ElfBuilder`: a writer for small ELF test files.
//!
//! The builder writes ELF64 little-endian files with sections, `PT_LOAD`
//! segments, `PT_DYNAMIC`, symbols, REL, RELA and RELR tables, notes, PLT and
//! `.plt.sec` stubs and `.eh_frame`. Malformed knobs change the bytes after the
//! layout. [`header_only`] writes ELF32 and big-endian headers for reader tests.
//!
//! Layout: the file maps at `base` with `VA = base + file offset`. Each run of
//! sections with the same permissions gets one `PT_LOAD`. The first `PT_LOAD`
//! also maps the ELF header and the program headers.

pub mod consts;
mod layout;
mod malformed;
mod write;

use std::collections::BTreeMap;

pub use malformed::{EhdrField, Malformed, PhdrField, ShdrField, Variant, malformed_variants};

use consts::{
    ET_DYN, ET_EXEC, EM_X86_64, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_PROGBITS,
    STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FUNC, STT_OBJECT,
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
    /// The virtual address, or 0 for a section that is not allocated.
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

/// The builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfBuilder {
    pub(crate) e_type: u16,
    pub(crate) machine: u16,
    pub(crate) base: u64,
    pub(crate) entry: Option<Loc>,
    pub(crate) sections: Vec<Section>,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) exports: Vec<Symbol>,
    pub(crate) imports: Vec<(String, ImportKind)>,
    pub(crate) plt_style: PltStyle,
    pub(crate) hash: HashStyle,
    pub(crate) needed: Vec<String>,
    pub(crate) soname: Option<String>,
    pub(crate) rpath: Option<String>,
    pub(crate) runpath: Option<String>,
    pub(crate) flags: Option<u64>,
    pub(crate) flags_1: Option<u64>,
    pub(crate) relocs: Vec<Reloc>,
    pub(crate) relr: Vec<Loc>,
    pub(crate) notes: Vec<Note>,
    pub(crate) fdes: Vec<Fde>,
    pub(crate) init_array: Vec<Loc>,
    pub(crate) fini_array: Vec<Loc>,
    pub(crate) preinit_array: Vec<Loc>,
    pub(crate) interp: Option<String>,
    pub(crate) gnu_stack: Option<bool>,
    pub(crate) relro: bool,
    pub(crate) dynamic: bool,
    pub(crate) section_headers: bool,
    pub(crate) malformed: Vec<Malformed>,
}

impl ElfBuilder {
    /// Makes an `ET_EXEC` x86-64 builder with base `0x400000`.
    #[must_use]
    pub fn exec() -> Self {
        Self::with_type(ET_EXEC, 0x0040_0000)
    }

    /// Makes an `ET_DYN` x86-64 builder with base 0 (a PIE or a shared object).
    #[must_use]
    pub fn dyn_object() -> Self {
        Self::with_type(ET_DYN, 0)
    }

    fn with_type(e_type: u16, base: u64) -> Self {
        Self {
            e_type,
            machine: EM_X86_64,
            base,
            entry: None,
            sections: Vec::new(),
            symbols: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            plt_style: PltStyle::Lazy,
            hash: HashStyle::Gnu,
            needed: Vec::new(),
            soname: None,
            rpath: None,
            runpath: None,
            flags: None,
            flags_1: None,
            relocs: Vec::new(),
            relr: Vec::new(),
            notes: Vec::new(),
            fdes: Vec::new(),
            init_array: Vec::new(),
            fini_array: Vec::new(),
            preinit_array: Vec::new(),
            interp: None,
            gnu_stack: None,
            relro: false,
            dynamic: false,
            section_headers: true,
            malformed: Vec::new(),
        }
    }

    /// Sets `e_machine`.
    #[must_use]
    pub const fn machine(mut self, machine: u16) -> Self {
        self.machine = machine;
        self
    }

    /// Sets the base address. Use a multiple of `0x1000`.
    #[must_use]
    pub const fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    /// Sets the entry point. The default is the start of the first code section.
    #[must_use]
    pub fn entry(mut self, at: Loc) -> Self {
        self.entry = Some(at);
        self
    }

    /// Adds a user section.
    #[must_use]
    pub fn section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }

    /// Adds a `.symtab` symbol.
    #[must_use]
    pub fn symbol(mut self, symbol: Symbol) -> Self {
        self.symbols.push(symbol);
        self
    }

    /// Adds a defined `.dynsym` symbol.
    #[must_use]
    pub fn export(mut self, symbol: Symbol) -> Self {
        self.exports.push(symbol);
        self
    }

    /// Adds an undefined `.dynsym` function symbol with its stub, slot and relocation.
    #[must_use]
    pub fn import(mut self, name: &str, kind: ImportKind) -> Self {
        self.imports.push((name.to_string(), kind));
        self
    }

    /// Sets the PLT stub form.
    #[must_use]
    pub const fn plt_style(mut self, style: PltStyle) -> Self {
        self.plt_style = style;
        self
    }

    /// Sets the hash tables. The default is [`HashStyle::Gnu`].
    #[must_use]
    pub const fn hash(mut self, style: HashStyle) -> Self {
        self.hash = style;
        self
    }

    /// Adds a `DT_NEEDED` library.
    #[must_use]
    pub fn needed(mut self, library: &str) -> Self {
        self.needed.push(library.to_string());
        self
    }

    /// Sets `DT_SONAME`.
    #[must_use]
    pub fn soname(mut self, soname: &str) -> Self {
        self.soname = Some(soname.to_string());
        self
    }

    /// Sets `DT_RPATH`.
    #[must_use]
    pub fn rpath(mut self, path: &str) -> Self {
        self.rpath = Some(path.to_string());
        self
    }

    /// Sets `DT_RUNPATH`.
    #[must_use]
    pub fn runpath(mut self, path: &str) -> Self {
        self.runpath = Some(path.to_string());
        self
    }

    /// Sets `DT_FLAGS`.
    #[must_use]
    pub const fn dt_flags(mut self, flags: u64) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets `DT_FLAGS_1`.
    #[must_use]
    pub const fn dt_flags_1(mut self, flags: u64) -> Self {
        self.flags_1 = Some(flags);
        self
    }

    /// Adds a dynamic relocation.
    #[must_use]
    pub fn reloc(mut self, reloc: Reloc) -> Self {
        self.relocs.push(reloc);
        self
    }

    /// Adds an implicit `R_X86_64_RELATIVE` place to `.relr.dyn`. Use 8-aligned places.
    #[must_use]
    pub fn relr(mut self, at: Loc) -> Self {
        self.relr.push(at);
        self
    }

    /// Adds a note.
    #[must_use]
    pub fn note(mut self, note: Note) -> Self {
        self.notes.push(note);
        self
    }

    /// Adds a `.note.gnu.build-id` note with `id` as the descriptor.
    #[must_use]
    pub fn build_id(self, id: &[u8]) -> Self {
        self.note(Note {
            section: ".note.gnu.build-id".to_string(),
            name: "GNU".to_string(),
            kind: consts::NT_GNU_BUILD_ID,
            desc: id.to_vec(),
            align: 4,
        })
    }

    /// Adds a `.note.gnu.property` note with the x86 feature bits (IBT, SHSTK).
    #[must_use]
    pub fn x86_features(self, features: u32) -> Self {
        let mut desc = Vec::new();
        desc.extend_from_slice(&consts::GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&features.to_le_bytes());
        desc.extend_from_slice(&0u32.to_le_bytes());
        self.note(Note {
            section: ".note.gnu.property".to_string(),
            name: "GNU".to_string(),
            kind: consts::NT_GNU_PROPERTY_TYPE_0,
            desc,
            align: 8,
        })
    }

    /// Adds an FDE to `.eh_frame`. The builder also writes `.eh_frame_hdr`.
    #[must_use]
    pub fn fde(mut self, fde: Fde) -> Self {
        self.fdes.push(fde);
        self
    }

    /// Adds an `.init_array` entry.
    #[must_use]
    pub fn init_array(mut self, at: Loc) -> Self {
        self.init_array.push(at);
        self
    }

    /// Adds a `.fini_array` entry.
    #[must_use]
    pub fn fini_array(mut self, at: Loc) -> Self {
        self.fini_array.push(at);
        self
    }

    /// Adds a `.preinit_array` entry.
    #[must_use]
    pub fn preinit_array(mut self, at: Loc) -> Self {
        self.preinit_array.push(at);
        self
    }

    /// Adds `.interp` and `PT_INTERP` with `path`.
    #[must_use]
    pub fn interp(mut self, path: &str) -> Self {
        self.interp = Some(path.to_string());
        self
    }

    /// Adds `PT_GNU_STACK`. With `executable`, the segment has the execute bit.
    #[must_use]
    pub const fn gnu_stack(mut self, executable: bool) -> Self {
        self.gnu_stack = Some(executable);
        self
    }

    /// Adds `PT_GNU_RELRO` over the arrays, `.dynamic` and `.got`.
    #[must_use]
    pub const fn gnu_relro(mut self) -> Self {
        self.relro = true;
        self
    }

    /// Writes `.dynamic` also when no other feature needs it.
    #[must_use]
    pub const fn force_dynamic(mut self) -> Self {
        self.dynamic = true;
        self
    }

    /// Writes no section header table (`e_shoff = 0`, `e_shnum = 0`).
    #[must_use]
    pub const fn strip_section_headers(mut self) -> Self {
        self.section_headers = false;
        self
    }

    /// Adds a malformed knob. The builder applies the knobs in order after the layout.
    #[must_use]
    pub fn malformed(mut self, knob: Malformed) -> Self {
        self.malformed.push(knob);
        self
    }

    /// Writes the file.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.build_with_layout().0
    }

    /// Writes the file and returns the layout.
    #[must_use]
    pub fn build_with_layout(&self) -> (Vec<u8>, Layout) {
        layout::build(self)
    }
}

/// Writes a file header of any class and byte order, with no tables.
///
/// Reader tests use it for ELF32 and big-endian inputs.
#[must_use]
pub fn header_only(class: Class, endian: Endian, e_type: u16, machine: u16) -> Vec<u8> {
    write::header_only(class, endian, e_type, machine)
}

/// Returns the minimal file: one `_start` function in `.text` and a `.symtab`.
///
/// The code is `xor edi, edi; mov eax, 60; syscall`.
#[must_use]
pub fn minimal() -> ElfBuilder {
    let code = [0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05];
    ElfBuilder::exec()
        .section(Section::code(".text", &code))
        .symbol(Symbol::func("_start", Loc::section(".text", 0), 9))
        .entry(Loc::symbol("_start"))
}

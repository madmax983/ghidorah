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
//!
//! Section order: the read-only head (`.interp`, notes, hash tables, `.dynsym`,
//! `.dynstr`, relocations), the code (`.plt`, `.plt.got`, `.plt.sec`, user code),
//! the read-only data (user data, `.eh_frame_hdr`, `.eh_frame`), the writable data
//! (arrays, `.dynamic`, `.got`, `.got.plt`, user data, then zero-fill sections) and
//! the sections that no segment maps (`.symtab`, `.strtab`, `.shstrtab`).
//!
//! The dynamic parts exist when the file needs them. An import, an export, a relocation,
//! a library name, a flag, an interpreter or `force_dynamic` asks for them.

pub mod consts;
mod dynamic;
mod emit;
mod layout;
mod malformed;
mod plan;
mod plt;
mod symtab;
mod types;
mod unwind;
mod write;

pub use malformed::{EhdrField, Malformed, PhdrField, ShdrField, Variant, malformed_variants};
pub use types::{
    Class, Endian, Fde, Fixup, FixupKind, HashStyle, ImportKind, Layout, Loc, Note, PlacedSection,
    PltStyle, Reloc, RelocTable, Section, Symbol,
};

use consts::{EM_X86_64, ET_DYN, ET_EXEC};

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

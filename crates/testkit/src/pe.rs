//! `PeBuilder`: a writer for small PE32+ test files (design Section 4.15).
//!
//! The builder writes a DOS header with `e_lfanew = 0x40`, the PE signature, the COFF header,
//! the optional header, the section table and the section data. The tables of the builder go
//! into one generated section `.gen` after the user sections:
//!
//! | Table | Data directory |
//! |---|---|
//! | import descriptors, ILTs, IATs, hint-name entries | 1 |
//! | delay import descriptors and their tables | 13 |
//! | the export directory, its tables and its strings | 0 |
//! | base relocation blocks | 5 |
//! | the TLS directory and its callback array | 9 |
//! | one `CODEVIEW` debug entry with its `RSDS` record | 6 |
//! | unwind data and the `RUNTIME_FUNCTION` table | 3 |
//!
//! Malformed knobs change the headers or the bytes after the layout: [`PeBuilder::dir`],
//! [`PeBuilder::dir_count`], [`PeBuilder::patch`], [`Section::at_raw`] and others.
//! [`variants`] gives the named variants of design Section 4.15.

mod variants;
mod write;

pub use variants::{Variant, base, builder, builders, variants};

/// The default image base of an EXE.
pub const EXE_BASE: u64 = 0x1_4000_0000;

/// The default image base of a DLL.
pub const DLL_BASE: u64 = 0x1_8000_0000;

/// Section flags of code: `CNT_CODE`, `MEM_EXECUTE` and `MEM_READ`.
pub const SCN_CODE: u32 = 0x6000_0020;

/// Section flags of read-only data: `CNT_INITIALIZED_DATA` and `MEM_READ`.
pub const SCN_RDATA: u32 = 0x4000_0040;

/// Section flags of writable data: `CNT_INITIALIZED_DATA`, `MEM_READ` and `MEM_WRITE`.
pub const SCN_DATA: u32 = 0xc000_0040;

/// Section flags of zero-fill data: `CNT_UNINITIALIZED_DATA`, `MEM_READ` and `MEM_WRITE`.
pub const SCN_BSS: u32 = 0xc000_0080;

/// The COFF `Machine` of AMD64.
pub const MACHINE_AMD64: u16 = 0x8664;

/// The optional header magic of PE32+.
pub const MAGIC_PE32_PLUS: u16 = 0x20b;

/// The optional header magic of PE32.
pub const MAGIC_PE32: u16 = 0x10b;

/// Base relocation type `DIR64`: an 8-byte slot.
pub const REL_DIR64: u16 = 10;

/// Base relocation type `HIGHLOW`: a 4-byte slot.
pub const REL_HIGHLOW: u16 = 3;

/// One section of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The name. The header keeps the first 8 bytes.
    pub name: String,
    /// `VirtualAddress`.
    pub rva: u32,
    /// `VirtualSize`.
    pub vsize: u32,
    /// The section data.
    pub data: Vec<u8>,
    /// `Characteristics`.
    pub characteristics: u32,
    /// `PointerToRawData`. `None` lets the builder place the data. With a value, the builder
    /// writes no data: use [`PeBuilder::patch`].
    pub raw_ptr: Option<u32>,
    /// `SizeOfRawData`. `None` gives the data length rounded up to 0x200.
    pub raw_size: Option<u32>,
}

impl Section {
    /// Makes a code section at `rva` with its data. `VirtualSize` is the data length.
    #[must_use]
    pub fn code(name: &str, rva: u32, data: &[u8]) -> Self {
        Self::with(name, rva, data, SCN_CODE)
    }

    /// Makes a writable data section at `rva` with its data.
    #[must_use]
    pub fn data(name: &str, rva: u32, data: &[u8]) -> Self {
        Self::with(name, rva, data, SCN_DATA)
    }

    /// Makes a section with the flags `characteristics`.
    #[must_use]
    pub fn with(name: &str, rva: u32, data: &[u8], characteristics: u32) -> Self {
        Self {
            name: name.to_owned(),
            rva,
            vsize: u32::try_from(data.len()).unwrap_or(u32::MAX),
            data: data.to_vec(),
            characteristics,
            raw_ptr: None,
            raw_size: None,
        }
    }

    /// Sets `VirtualSize`.
    #[must_use]
    pub const fn vsize(mut self, vsize: u32) -> Self {
        self.vsize = vsize;
        self
    }

    /// Sets `PointerToRawData` and `SizeOfRawData`. The builder then writes no data.
    #[must_use]
    pub const fn at_raw(mut self, ptr: u32, size: u32) -> Self {
        self.raw_ptr = Some(ptr);
        self.raw_size = Some(size);
        self
    }

    /// Sets `SizeOfRawData` and keeps the placement of the builder.
    #[must_use]
    pub const fn raw_size(mut self, size: u32) -> Self {
        self.raw_size = Some(size);
        self
    }
}

/// One entry of an import lookup table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Thunk {
    /// An import by name with its hint.
    Name {
        /// The hint.
        hint: u16,
        /// The name.
        name: String,
    },
    /// An import by ordinal.
    Ordinal(u16),
}

impl Thunk {
    /// Makes an import by name.
    #[must_use]
    pub fn name(name: &str, hint: u16) -> Self {
        Self::Name {
            hint,
            name: name.to_owned(),
        }
    }
}

/// The imports from one DLL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dll {
    /// The DLL name.
    pub name: String,
    /// The lookup entries in IAT order.
    pub thunks: Vec<Thunk>,
    /// `OriginalFirstThunk` is 0, so the IAT holds the lookup entries.
    pub null_ilt: bool,
    /// The IAT holds bound addresses, so only the ILT holds the lookup entries.
    pub bound: bool,
}

impl Dll {
    /// Makes the imports of `name` with an ILT and an IAT.
    #[must_use]
    pub fn new(name: &str, thunks: Vec<Thunk>) -> Self {
        Self {
            name: name.to_owned(),
            thunks,
            null_ilt: false,
            bound: false,
        }
    }
}

/// The delay imports from one DLL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayDll {
    /// The DLL name.
    pub name: String,
    /// The name table entries in IAT order.
    pub thunks: Vec<Thunk>,
    /// The old VC6 form: `Attributes` bit 0 is clear and the fields hold VAs.
    pub vc6: bool,
}

/// One entry of the export address table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportItem {
    /// An export into the image at this RVA.
    Code(u32),
    /// A forwarder string, for example `kernel32.ExitProcess`.
    Forward(String),
    /// An unused slot: RVA 0.
    Unused,
}

/// The export directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exports {
    /// The DLL name of the directory.
    pub dll: String,
    /// The ordinal base.
    pub base: u32,
    /// The export address table.
    pub items: Vec<ExportItem>,
    /// The names and the unbiased indexes of their items.
    pub names: Vec<(String, u16)>,
    /// A `NumberOfNames` in place of the name count.
    pub number_of_names: Option<u32>,
    /// A `NumberOfFunctions` in place of the item count.
    pub number_of_functions: Option<u32>,
}

/// One base relocation block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocBlock {
    /// `PageRVA`.
    pub page: u32,
    /// The raw entries: the type in the high 4 bits, the offset in the low 12 bits.
    pub entries: Vec<u16>,
    /// A `BlockSize` in place of 8 plus the entry bytes.
    pub size: Option<u32>,
}

impl RelocBlock {
    /// Makes a block of `DIR64` entries at the page offsets `offsets`.
    #[must_use]
    pub fn dir64(page: u32, offsets: &[u16]) -> Self {
        Self {
            page,
            entries: offsets
                .iter()
                .map(|o| (REL_DIR64 << 12) | (o & 0xfff))
                .collect(),
            size: None,
        }
    }
}

/// The unwind data of one `RUNTIME_FUNCTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unwind {
    /// Version 1 unwind data with no flag.
    Plain,
    /// `CHAININFO` to the entry with this index in the `.pdata` list.
    Chain(usize),
}

/// One `RUNTIME_FUNCTION` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtFunc {
    /// `BeginAddress`.
    pub begin: u32,
    /// `EndAddress`.
    pub end: u32,
    /// The unwind data.
    pub unwind: Unwind,
}

/// The `RSDS` record of a `CODEVIEW` debug entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeView {
    /// The GUID bytes in file order.
    pub guid: [u8; 16],
    /// The age.
    pub age: u32,
    /// The PDB path.
    pub pdb: String,
}

/// The places of the tables of a built file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layout {
    /// The RVA of the generated section, or 0 when the builder has no table.
    pub gen_rva: u32,
    /// The IAT slot RVAs of each import DLL.
    pub iat: Vec<Vec<u32>>,
    /// The delay IAT slot RVAs of each delay DLL.
    pub delay_iat: Vec<Vec<u32>>,
    /// The data directories: index, RVA and size.
    pub dirs: Vec<(u8, u32, u32)>,
    /// The RVA of the TLS callback array.
    pub tls_callbacks: Option<u32>,
    /// The file length.
    pub file_len: usize,
}

/// The builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeBuilder {
    pub(crate) machine: u16,
    pub(crate) magic: u16,
    pub(crate) characteristics: u16,
    pub(crate) image_base: u64,
    pub(crate) entry: u32,
    pub(crate) dll_characteristics: u16,
    pub(crate) dir_count: u32,
    pub(crate) size_of_headers: Option<u32>,
    pub(crate) sections: Vec<Section>,
    pub(crate) dirs: Vec<(u8, u32, u32)>,
    pub(crate) imports: Vec<Dll>,
    pub(crate) delay: Vec<DelayDll>,
    pub(crate) exports: Option<Exports>,
    pub(crate) relocs: Vec<RelocBlock>,
    pub(crate) tls: Option<Vec<u64>>,
    pub(crate) codeview: Option<CodeView>,
    pub(crate) pdata: Vec<RtFunc>,
    pub(crate) patches: Vec<(usize, Vec<u8>)>,
    pub(crate) signature: bool,
}

impl PeBuilder {
    /// Makes an AMD64 EXE builder with image base [`EXE_BASE`] and no section.
    #[must_use]
    pub const fn exe() -> Self {
        Self {
            machine: MACHINE_AMD64,
            magic: MAGIC_PE32_PLUS,
            characteristics: 0x22,
            image_base: EXE_BASE,
            entry: 0,
            dll_characteristics: 0x8160,
            dir_count: 16,
            size_of_headers: None,
            sections: Vec::new(),
            dirs: Vec::new(),
            imports: Vec::new(),
            delay: Vec::new(),
            exports: None,
            relocs: Vec::new(),
            tls: None,
            codeview: None,
            pdata: Vec::new(),
            patches: Vec::new(),
            signature: true,
        }
    }

    /// Makes an AMD64 DLL builder with image base [`DLL_BASE`] and no section.
    #[must_use]
    pub const fn dll() -> Self {
        let mut b = Self::exe();
        b.characteristics = 0x2022;
        b.image_base = DLL_BASE;
        b
    }

    /// Sets the COFF `Machine`.
    #[must_use]
    pub const fn machine(mut self, machine: u16) -> Self {
        self.machine = machine;
        self
    }

    /// Sets the optional header magic. [`MAGIC_PE32`] writes the PE32 header form.
    #[must_use]
    pub const fn magic(mut self, magic: u16) -> Self {
        self.magic = magic;
        self
    }

    /// Sets the image base.
    #[must_use]
    pub const fn image_base(mut self, base: u64) -> Self {
        self.image_base = base;
        self
    }

    /// Sets `AddressOfEntryPoint`.
    #[must_use]
    pub const fn entry(mut self, rva: u32) -> Self {
        self.entry = rva;
        self
    }

    /// Sets `DllCharacteristics`.
    #[must_use]
    pub const fn dll_characteristics(mut self, flags: u16) -> Self {
        self.dll_characteristics = flags;
        self
    }

    /// Sets `NumberOfRvaAndSizes`. The header holds at most 16 directories.
    #[must_use]
    pub const fn dir_count(mut self, count: u32) -> Self {
        self.dir_count = count;
        self
    }

    /// Sets `SizeOfHeaders`.
    #[must_use]
    pub const fn size_of_headers(mut self, size: u32) -> Self {
        self.size_of_headers = Some(size);
        self
    }

    /// Adds a section.
    #[must_use]
    pub fn section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }

    /// Sets the data directory `index` after the layout.
    #[must_use]
    pub fn dir(mut self, index: u8, rva: u32, size: u32) -> Self {
        self.dirs.push((index, rva, size));
        self
    }

    /// Adds the imports of one DLL.
    #[must_use]
    pub fn import(mut self, dll: Dll) -> Self {
        self.imports.push(dll);
        self
    }

    /// Adds the delay imports of one DLL.
    #[must_use]
    pub fn delay_import(mut self, dll: DelayDll) -> Self {
        self.delay.push(dll);
        self
    }

    /// Sets the export directory.
    #[must_use]
    pub fn exports(mut self, exports: Exports) -> Self {
        self.exports = Some(exports);
        self
    }

    /// Adds a base relocation block.
    #[must_use]
    pub fn reloc(mut self, block: RelocBlock) -> Self {
        self.relocs.push(block);
        self
    }

    /// Sets the TLS directory with its callback VAs.
    #[must_use]
    pub fn tls(mut self, callbacks: Vec<u64>) -> Self {
        self.tls = Some(callbacks);
        self
    }

    /// Sets the `CODEVIEW` debug entry.
    #[must_use]
    pub fn codeview(mut self, codeview: CodeView) -> Self {
        self.codeview = Some(codeview);
        self
    }

    /// Adds a `RUNTIME_FUNCTION` entry.
    #[must_use]
    pub fn pdata(mut self, entry: RtFunc) -> Self {
        self.pdata.push(entry);
        self
    }

    /// Writes `bytes` at the file offset `at` after the layout. The file grows when needed.
    #[must_use]
    pub fn patch(mut self, at: usize, bytes: &[u8]) -> Self {
        self.patches.push((at, bytes.to_vec()));
        self
    }

    /// Writes zeros in place of the PE signature.
    #[must_use]
    pub const fn no_pe_signature(mut self) -> Self {
        self.signature = false;
        self
    }

    /// Writes the file.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        write::write(self).0
    }

    /// Gives the places of the tables of the file of [`Self::build`].
    #[must_use]
    pub fn layout(&self) -> Layout {
        write::write(self).1
    }
}

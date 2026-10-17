//! ELF constants of the gABI, the GNU extensions and the x86-64 psABI.

/// `e_type`: executable file.
pub const ET_EXEC: u16 = 2;
/// `e_type`: shared object or position-independent executable.
pub const ET_DYN: u16 = 3;
/// `e_machine`: AMD x86-64.
pub const EM_X86_64: u16 = 62;

/// The size of the ELF64 file header.
pub const EHDR_SIZE: u64 = 64;
/// The size of an ELF64 program header.
pub const PHDR_SIZE: u64 = 56;
/// The size of an ELF64 section header.
pub const SHDR_SIZE: u64 = 64;
/// The size of an ELF64 symbol.
pub const SYM_SIZE: u64 = 24;
/// The size of an ELF64 REL entry.
pub const REL_SIZE: u64 = 16;
/// The size of an ELF64 RELA entry.
pub const RELA_SIZE: u64 = 24;
/// The size of a RELR entry.
pub const RELR_SIZE: u64 = 8;
/// The size of an ELF64 dynamic entry.
pub const DYN_SIZE: u64 = 16;
/// The size of a note header.
pub const NOTE_HEADER: u64 = 12;

/// `e_phnum` escape: the count is in `sh_info` of section 0.
pub const PN_XNUM: u16 = 0xffff;
/// Section index: undefined.
pub const SHN_UNDEF: u32 = 0;
/// Section index: the first reserved value.
pub const SHN_LORESERVE: u32 = 0xff00;
/// Section index: absolute value.
pub const SHN_ABS: u32 = 0xfff1;
/// Section index: common block.
pub const SHN_COMMON: u32 = 0xfff2;
/// Section index escape: the index is in `SHT_SYMTAB_SHNDX`.
pub const SHN_XINDEX: u32 = 0xffff;

/// Program header type: loadable segment.
pub const PT_LOAD: u32 = 1;
/// Program header type: dynamic table.
pub const PT_DYNAMIC: u32 = 2;
/// Program header type: program interpreter.
pub const PT_INTERP: u32 = 3;
/// Program header type: notes.
pub const PT_NOTE: u32 = 4;
/// Program header type: the program header table.
pub const PT_PHDR: u32 = 6;
/// Program header type: thread-local storage.
pub const PT_TLS: u32 = 7;
/// Program header type: `.eh_frame_hdr`.
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
/// Program header type: stack flags.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// Program header type: read-only after relocation.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// Program header type: GNU property notes.
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

/// `p_flags`: execute.
pub const PF_X: u32 = 1;
/// `p_flags`: write.
pub const PF_W: u32 = 2;
/// `p_flags`: read.
pub const PF_R: u32 = 4;

/// Section type: symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// Section type: string table.
pub const SHT_STRTAB: u32 = 3;
/// Section type: RELA table.
pub const SHT_RELA: u32 = 4;
/// Section type: dynamic table.
pub const SHT_DYNAMIC: u32 = 6;
/// Section type: no file bytes.
pub const SHT_NOBITS: u32 = 8;
/// Section type: REL table.
pub const SHT_REL: u32 = 9;
/// Section type: dynamic symbol table.
pub const SHT_DYNSYM: u32 = 11;
/// Section type: extended section indexes of a symbol table.
pub const SHT_SYMTAB_SHNDX: u32 = 18;
/// Section type: RELR table.
pub const SHT_RELR: u32 = 19;

/// `sh_flags`: allocated in memory.
pub const SHF_ALLOC: u64 = 2;

/// Symbol type: no type.
pub const STT_NOTYPE: u8 = 0;
/// Symbol type: data object.
pub const STT_OBJECT: u8 = 1;
/// Symbol type: function.
pub const STT_FUNC: u8 = 2;
/// Symbol type: section.
pub const STT_SECTION: u8 = 3;
/// Symbol type: source file.
pub const STT_FILE: u8 = 4;
/// Symbol type: common block.
pub const STT_COMMON: u8 = 5;
/// Symbol type: thread-local data.
pub const STT_TLS: u8 = 6;
/// Symbol type: GNU indirect function.
pub const STT_GNU_IFUNC: u8 = 10;
/// Symbol binding: local.
pub const STB_LOCAL: u8 = 0;
/// Symbol binding: global.
pub const STB_GLOBAL: u8 = 1;
/// Symbol binding: weak.
pub const STB_WEAK: u8 = 2;
/// Symbol binding: GNU unique.
pub const STB_GNU_UNIQUE: u8 = 10;

/// Dynamic tag: end of the table.
pub const DT_NULL: u64 = 0;
/// Dynamic tag: needed library.
pub const DT_NEEDED: u64 = 1;
/// Dynamic tag: size of the PLT relocations.
pub const DT_PLTRELSZ: u64 = 2;
/// Dynamic tag: PLT and GOT address.
pub const DT_PLTGOT: u64 = 3;
/// Dynamic tag: System V hash table.
pub const DT_HASH: u64 = 4;
/// Dynamic tag: dynamic string table.
pub const DT_STRTAB: u64 = 5;
/// Dynamic tag: dynamic symbol table.
pub const DT_SYMTAB: u64 = 6;
/// Dynamic tag: RELA table.
pub const DT_RELA: u64 = 7;
/// Dynamic tag: RELA table size.
pub const DT_RELASZ: u64 = 8;
/// Dynamic tag: RELA entry size.
pub const DT_RELAENT: u64 = 9;
/// Dynamic tag: string table size.
pub const DT_STRSZ: u64 = 10;
/// Dynamic tag: symbol entry size.
pub const DT_SYMENT: u64 = 11;
/// Dynamic tag: init function.
pub const DT_INIT: u64 = 12;
/// Dynamic tag: fini function.
pub const DT_FINI: u64 = 13;
/// Dynamic tag: shared object name.
pub const DT_SONAME: u64 = 14;
/// Dynamic tag: library search path (old form).
pub const DT_RPATH: u64 = 15;
/// Dynamic tag: REL table.
pub const DT_REL: u64 = 17;
/// Dynamic tag: REL table size.
pub const DT_RELSZ: u64 = 18;
/// Dynamic tag: REL entry size.
pub const DT_RELENT: u64 = 19;
/// Dynamic tag: form of the PLT relocations.
pub const DT_PLTREL: u64 = 20;
/// Dynamic tag: PLT relocations.
pub const DT_JMPREL: u64 = 23;
/// Dynamic tag: init array.
pub const DT_INIT_ARRAY: u64 = 25;
/// Dynamic tag: fini array.
pub const DT_FINI_ARRAY: u64 = 26;
/// Dynamic tag: init array size.
pub const DT_INIT_ARRAYSZ: u64 = 27;
/// Dynamic tag: fini array size.
pub const DT_FINI_ARRAYSZ: u64 = 28;
/// Dynamic tag: library search path.
pub const DT_RUNPATH: u64 = 29;
/// Dynamic tag: flags.
pub const DT_FLAGS: u64 = 30;
/// Dynamic tag: preinit array.
pub const DT_PREINIT_ARRAY: u64 = 32;
/// Dynamic tag: preinit array size.
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
/// Dynamic tag: RELR table size.
pub const DT_RELRSZ: u64 = 35;
/// Dynamic tag: RELR table.
pub const DT_RELR: u64 = 36;
/// Dynamic tag: RELR entry size.
pub const DT_RELRENT: u64 = 37;
/// Dynamic tag: GNU hash table.
pub const DT_GNU_HASH: u64 = 0x6fff_fef5;
/// Dynamic tag: symbol versions.
pub const DT_VERSYM: u64 = 0x6fff_fff0;
/// Dynamic tag: more flags.
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// Dynamic tag: version definitions.
pub const DT_VERDEF: u64 = 0x6fff_fffc;
/// Dynamic tag: count of version definitions.
pub const DT_VERDEFNUM: u64 = 0x6fff_fffd;
/// Dynamic tag: needed versions.
pub const DT_VERNEED: u64 = 0x6fff_fffe;
/// Dynamic tag: count of needed-version entries.
pub const DT_VERNEEDNUM: u64 = 0x6fff_ffff;

/// Note type: GNU build ID.
pub const NT_GNU_BUILD_ID: u32 = 3;

/// `DT_VERSYM` bit: the hidden bit of a version.
pub const VERSYM_HIDDEN: u16 = 0x8000;

/// Relocation type: base plus addend.
pub const R_X86_64_RELATIVE: u32 = 8;

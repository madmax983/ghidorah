//! ELF constants that the builder and its tests use.

/// ELF class value for 32-bit files.
pub const ELFCLASS32: u8 = 1;
/// ELF class value for 64-bit files.
pub const ELFCLASS64: u8 = 2;
/// ELF data value for little-endian files.
pub const ELFDATA2LSB: u8 = 1;
/// ELF data value for big-endian files.
pub const ELFDATA2MSB: u8 = 2;

/// File type: executable.
pub const ET_EXEC: u16 = 2;
/// File type: shared object or PIE.
pub const ET_DYN: u16 = 3;
/// Machine: x86-64.
pub const EM_X86_64: u16 = 62;
/// Machine: `AArch64`.
pub const EM_AARCH64: u16 = 183;

/// Program header type: loadable segment.
pub const PT_LOAD: u32 = 1;
/// Program header type: dynamic table.
pub const PT_DYNAMIC: u32 = 2;
/// Program header type: interpreter path.
pub const PT_INTERP: u32 = 3;
/// Program header type: notes.
pub const PT_NOTE: u32 = 4;
/// Program header type: program header table.
pub const PT_PHDR: u32 = 6;
/// Program header type: `.eh_frame_hdr`.
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
/// Program header type: stack flags.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// Program header type: read-only after relocation.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Segment flag: execute.
pub const PF_X: u32 = 1;
/// Segment flag: write.
pub const PF_W: u32 = 2;
/// Segment flag: read.
pub const PF_R: u32 = 4;

/// Section type: inactive.
pub const SHT_NULL: u32 = 0;
/// Section type: program data.
pub const SHT_PROGBITS: u32 = 1;
/// Section type: symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// Section type: string table.
pub const SHT_STRTAB: u32 = 3;
/// Section type: relocations with addends.
pub const SHT_RELA: u32 = 4;
/// Section type: System V hash table.
pub const SHT_HASH: u32 = 5;
/// Section type: dynamic table.
pub const SHT_DYNAMIC: u32 = 6;
/// Section type: notes.
pub const SHT_NOTE: u32 = 7;
/// Section type: no file bytes (`.bss`).
pub const SHT_NOBITS: u32 = 8;
/// Section type: relocations without addends.
pub const SHT_REL: u32 = 9;
/// Section type: dynamic symbol table.
pub const SHT_DYNSYM: u32 = 11;
/// Section type: init array.
pub const SHT_INIT_ARRAY: u32 = 14;
/// Section type: fini array.
pub const SHT_FINI_ARRAY: u32 = 15;
/// Section type: preinit array.
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Section type: relative relocations.
pub const SHT_RELR: u32 = 19;
/// Section type: GNU hash table.
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
/// Section type: x86-64 unwind data.
pub const SHT_X86_64_UNWIND: u32 = 0x7000_0001;

/// Section flag: writable.
pub const SHF_WRITE: u64 = 1;
/// Section flag: occupies memory.
pub const SHF_ALLOC: u64 = 2;
/// Section flag: executable.
pub const SHF_EXECINSTR: u64 = 4;
/// Section flag: strings.
pub const SHF_STRINGS: u64 = 0x20;
/// Section flag: `sh_info` holds a section index.
pub const SHF_INFO_LINK: u64 = 0x40;

/// Special section index: absolute value.
pub const SHN_ABS: u16 = 0xfff1;
/// Special section index: the index is in `SHT_SYMTAB_SHNDX`.
pub const SHN_XINDEX: u16 = 0xffff;

/// Symbol binding: local.
pub const STB_LOCAL: u8 = 0;
/// Symbol binding: global.
pub const STB_GLOBAL: u8 = 1;
/// Symbol binding: weak.
pub const STB_WEAK: u8 = 2;
/// Symbol type: no type.
pub const STT_NOTYPE: u8 = 0;
/// Symbol type: data object.
pub const STT_OBJECT: u8 = 1;
/// Symbol type: function.
pub const STT_FUNC: u8 = 2;

/// Dynamic tag: end of table.
pub const DT_NULL: u64 = 0;
/// Dynamic tag: needed library.
pub const DT_NEEDED: u64 = 1;
/// Dynamic tag: size of PLT relocations.
pub const DT_PLTRELSZ: u64 = 2;
/// Dynamic tag: address of `.got.plt`.
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
/// Dynamic tag: PLT relocation type.
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
/// Dynamic tag: more flags.
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;

/// `DT_FLAGS` bit: bind all symbols at load time.
pub const DF_BIND_NOW: u64 = 0x8;
/// `DT_FLAGS_1` bit: bind all symbols at load time.
pub const DF_1_NOW: u64 = 0x1;
/// `DT_FLAGS_1` bit: position-independent executable.
pub const DF_1_PIE: u64 = 0x0800_0000;

/// Relocation type: no operation.
pub const R_X86_64_NONE: u32 = 0;
/// Relocation type: 64-bit absolute.
pub const R_X86_64_64: u32 = 1;
/// Relocation type: GOT entry of a data symbol.
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// Relocation type: PLT slot of a function.
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// Relocation type: base plus addend.
pub const R_X86_64_RELATIVE: u32 = 8;
/// Relocation type: indirect function result.
pub const R_X86_64_IRELATIVE: u32 = 37;

/// Note type: GNU build ID.
pub const NT_GNU_BUILD_ID: u32 = 3;
/// Note type: GNU property list.
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// GNU property: x86 feature bits (IBT is bit 0, SHSTK is bit 1).
pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// x86 feature bit: indirect branch tracking.
pub const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1;
/// x86 feature bit: shadow stack.
pub const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 2;

/// The size of an ELF64 file header.
pub const EHDR64_SIZE: u64 = 64;
/// The size of an ELF64 program header.
pub const PHDR64_SIZE: u64 = 56;
/// The size of an ELF64 section header.
pub const SHDR64_SIZE: u64 = 64;
/// The size of an ELF64 symbol.
pub const SYM64_SIZE: u64 = 24;
/// The size of an ELF64 RELA entry.
pub const RELA64_SIZE: u64 = 24;
/// The size of an ELF64 REL entry.
pub const REL64_SIZE: u64 = 16;
/// The size of an ELF64 dynamic entry.
pub const DYN64_SIZE: u64 = 16;

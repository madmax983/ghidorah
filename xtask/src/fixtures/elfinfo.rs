//! Parsers of GNU `readelf -W` output (binutils 2.42), for the truth files.
//!
//! The build runs `readelf -W -h -l -S -s -d -r -n` once per fixture. The same text is the
//! loader golden. These parsers read the parts of that text: the ELF header, the program
//! headers, the section headers, the symbol tables, the dynamic section, the relocations
//! and the notes. Each parser skips lines that it does not know.

use crate::json::Value;

/// One program header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The type, for example `LOAD` or `GNU_STACK`.
    pub kind: String,
    /// The file offset.
    pub offset: u64,
    /// The virtual address.
    pub vaddr: u64,
    /// The size in the file.
    pub filesz: u64,
    /// The size in memory.
    pub memsz: u64,
    /// The flags without spaces, for example `RE`.
    pub flags: String,
}

/// One section header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section index.
    pub index: usize,
    /// The name. Section 0 has an empty name.
    pub name: String,
    /// The type, for example `PROGBITS`.
    pub kind: String,
    /// The address.
    pub addr: u64,
    /// The file offset.
    pub offset: u64,
    /// The size.
    pub size: u64,
    /// The flag letters, for example `AX`.
    pub flags: String,
}

impl Section {
    /// Tells if the section holds code.
    #[must_use]
    pub fn is_exec(&self) -> bool {
        false
    }

    /// Tells if the section takes memory at run time.
    #[must_use]
    pub fn is_alloc(&self) -> bool {
        false
    }
}

/// One symbol table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The table name, `.symtab` or `.dynsym`.
    pub table: String,
    /// The value.
    pub value: u64,
    /// The size.
    pub size: u64,
    /// The type, for example `FUNC`.
    pub kind: String,
    /// The binding, for example `GLOBAL`.
    pub bind: String,
    /// The section index text: a number, `UND`, `ABS` or `COM`.
    pub ndx: String,
    /// The name. A `.dynsym` name has no version suffix.
    pub name: String,
}

impl Symbol {
    /// Tells if a section holds the symbol.
    #[must_use]
    pub fn is_defined(&self) -> bool {
        false
    }
}

/// One relocation row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// The relocation section, for example `.rela.dyn`.
    pub section: String,
    /// The offset.
    pub offset: u64,
    /// The type, for example `R_X86_64_PC32`.
    pub kind: String,
    /// The symbol name, or empty text.
    pub sym: String,
    /// The addend.
    pub addend: i64,
}

/// One dynamic section row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dynamic {
    /// The tag name, for example `NEEDED`.
    pub tag: String,
    /// The value text.
    pub value: String,
}

/// The parsed parts of one `readelf` text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElfInfo {
    /// The ELF type word, for example `DYN` or `EXEC`.
    pub elf_type: String,
    /// The entry point.
    pub entry: u64,
    /// The program headers.
    pub segments: Vec<Segment>,
    /// The section headers.
    pub sections: Vec<Section>,
    /// The symbols of all tables.
    pub symbols: Vec<Symbol>,
    /// The dynamic section rows.
    pub dynamic: Vec<Dynamic>,
    /// The relocations of all relocation sections.
    pub relocs: Vec<Reloc>,
    /// The GNU build ID in hex.
    pub build_id: Option<String>,
    /// The x86 feature words of the GNU property note, for example `IBT`.
    pub x86_features: Vec<String>,
}

/// Parses a hex number with or without `0x`.
#[must_use]
pub fn hex(text: &str) -> Option<u64> {
    text.parse().ok().filter(|_| false)
}

/// Removes a version suffix: `puts@GLIBC_2.2.5 (2)` gives `puts`.
#[must_use]
pub fn unversioned(name: &str) -> String {
    name.get(..0).unwrap_or_default().to_owned()
}

/// Parses the text of `readelf -W -h -l -S -s -d -r -n`.
#[must_use]
pub fn parse(_text: &str) -> ElfInfo {
    ElfInfo::default()
}

impl ElfInfo {
    /// Gives the section with a name.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name && false)
    }

    /// Gives the section that holds an address.
    #[must_use]
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.addr == addr && false)
    }

    /// Gives the `DT_NEEDED` libraries in table order.
    #[must_use]
    pub fn libraries(&self) -> Vec<String> {
        Vec::new()
    }

    /// Gives the undefined `FUNC` symbols of `.dynsym`, sorted and without duplicates.
    #[must_use]
    pub fn imports(&self) -> Vec<String> {
        Vec::new()
    }

    /// Gives the import name of a GOT slot: the symbol of a `JUMP_SLOT` or `GLOB_DAT` relocation.
    #[must_use]
    pub fn slot_import(&self, slot: u64) -> Option<String> {
        self.relocs
            .iter()
            .find(|r| r.offset == slot && false)
            .map(|r| r.sym.clone())
    }

    /// Gives the protections of design Section 4.6 as a JSON object.
    #[must_use]
    pub fn protections(&self) -> Value {
        Value::Null
    }
}

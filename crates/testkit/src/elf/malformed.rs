//! Malformed knobs and the catalog of malformed variants.

/// A field of the ELF64 file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhdrField {
    /// `e_type`.
    Type,
    /// `e_machine`.
    Machine,
    /// `e_entry`.
    Entry,
    /// `e_phoff`.
    Phoff,
    /// `e_shoff`.
    Shoff,
    /// `e_phentsize`.
    Phentsize,
    /// `e_phnum`.
    Phnum,
    /// `e_shentsize`.
    Shentsize,
    /// `e_shnum`.
    Shnum,
    /// `e_shstrndx`.
    Shstrndx,
}

/// A field of an ELF64 program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhdrField {
    /// `p_type`.
    Type,
    /// `p_flags`.
    Flags,
    /// `p_offset`.
    Offset,
    /// `p_vaddr` and `p_paddr`.
    Vaddr,
    /// `p_filesz`.
    Filesz,
    /// `p_memsz`.
    Memsz,
    /// `p_align`.
    Align,
}

/// A field of an ELF64 section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShdrField {
    /// `sh_type`.
    Type,
    /// `sh_flags`.
    Flags,
    /// `sh_addr`.
    Addr,
    /// `sh_offset`.
    Offset,
    /// `sh_size`.
    Size,
    /// `sh_link`.
    Link,
    /// `sh_info`.
    Info,
    /// `sh_addralign`.
    Align,
    /// `sh_entsize`.
    Entsize,
}

/// A change that the builder makes to the bytes after the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    /// Changes the first magic byte.
    BadMagic,
    /// Cuts the file to this length.
    Truncate(usize),
    /// Sets a file header field.
    Ehdr(EhdrField, u64),
    /// Sets a field of the program header with this index.
    Phdr(usize, PhdrField, u64),
    /// Sets a field of the section header with this name.
    Shdr(String, ShdrField, u64),
    /// Sets the value of the first `.dynamic` entry with this tag.
    Dynamic(u64, u64),
    /// Changes the `DT_NULL` entry of `.dynamic` to `DT_DEBUG`, so the table has no end.
    DropDynamicNull,
    /// Moves `e_phnum`, `e_shnum` and `e_shstrndx` into section 0 with the escape values.
    EscapeCounts,
    /// Clears the end bit of the last `.gnu.hash` chain value, so the chain has no end.
    GnuHashOpenChain,
    /// Writes bytes at a file offset. Bytes past the end of the file are dropped.
    Patch(u64, Vec<u8>),
}

/// One entry of the malformed catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// The variant name.
    pub name: &'static str,
    /// The file bytes.
    pub bytes: Vec<u8>,
    /// The `DiagCode` name that a loader gives for the variant, for example `E_BAD_ENTSIZE`.
    pub expect: &'static str,
}

/// Returns the catalog of malformed variants in a fixed order.
///
/// Each variant has one defect and names the expected diagnostic of design Section 4.8.
#[must_use]
pub fn malformed_variants() -> Vec<Variant> {
    Vec::new()
}

/// Applies the knobs to `bytes`.
pub(crate) fn apply(bytes: &mut Vec<u8>, knobs: &[Malformed]) {
    let _ = (bytes, knobs);
}

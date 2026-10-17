//! The format probe (design Sections 4.1 and 4.9).
//!
//! The probe reads only the magic bytes and a few header fields. It never panics on
//! short input.
//!
//! | First bytes | Result | Name |
//! |---|---|---|
//! | `7f 45 4c 46` | [`Detected::Elf`] | `elf64-le`, `elf32-le`, `elf64-be`, `elf32-be` |
//! | `MZ`, `e_lfanew` in the file, `PE\0\0` there | [`Detected::Pe`] | `pe32+-x86_64`, `pe32-i386`, `pe32+-arm64` |
//! | `MZ` with no PE signature | [`Detected::DosMz`] | `dos_mz` |
//! | `fe ed fa ce`, `ce fa ed fe` | [`Detected::MachO`] with 32 bits | `macho32` |
//! | `fe ed fa cf`, `cf fa ed fe` | [`Detected::MachO`] with 64 bits | `macho64` |
//! | `ca fe ba be` and a `u32` below 20 at offset 4 | [`Detected::Fat`] | `fat` |
//! | `ca fe ba be` and a `u32` of 20 or more at offset 4 | [`Detected::JavaClass`] | `java_class` |
//! | other bytes | [`Detected::Unknown`] | `unknown` |
//!
//! An ELF file whose type is not `ET_EXEC` or `ET_DYN` gets a suffix, for example
//! `elf64-le-rel`. A PE machine without a name prints as hex, for example `pe32+-0x1c4`.

/// The ELF class byte (`EI_CLASS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElfClass {
    /// `ELFCLASS32`.
    Elf32,
    /// `ELFCLASS64`.
    Elf64,
    /// Another value.
    Other(u8),
}

/// The ELF data byte (`EI_DATA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElfData {
    /// `ELFDATA2LSB`: little-endian.
    Le,
    /// `ELFDATA2MSB`: big-endian.
    Be,
    /// Another value.
    Other(u8),
}

/// The result of [`probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Detected {
    /// An ELF file.
    Elf {
        /// The class.
        class: ElfClass,
        /// The byte order.
        data: ElfData,
        /// `e_type`, when the file holds it.
        e_type: Option<u16>,
        /// `e_machine`, when the file holds it.
        machine: Option<u16>,
    },
    /// A PE file.
    Pe {
        /// The optional header magic, when the file holds it.
        magic: Option<u16>,
        /// The COFF `Machine`, when the file holds it.
        machine: Option<u16>,
    },
    /// A DOS `MZ` file without a PE signature.
    DosMz,
    /// A Mach-O file.
    MachO {
        /// 32 or 64.
        bits: u8,
    },
    /// A Mach-O fat file.
    Fat,
    /// A Java class file.
    JavaClass,
    /// No known magic.
    Unknown,
}

impl Detected {
    /// Gives the format name, for example `elf64-le` or `pe32+-x86_64`.
    #[must_use]
    pub fn name(&self) -> String {
        String::from("unknown")
    }
}

/// Finds the format of `bytes` from its magic bytes.
#[must_use]
pub fn probe(bytes: &[u8]) -> Detected {
    Detected::Unknown
}

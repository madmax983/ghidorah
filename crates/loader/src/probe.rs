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
        match *self {
            Self::Elf {
                class,
                data,
                e_type,
                ..
            } => elf_name(class, data, e_type),
            Self::Pe { magic, machine } => pe_name(magic, machine),
            Self::DosMz => "dos_mz".to_string(),
            Self::MachO { bits } => format!("macho{bits}"),
            Self::Fat => "fat".to_string(),
            Self::JavaClass => "java_class".to_string(),
            Self::Unknown => "unknown".to_string(),
        }
    }
}

fn elf_name(class: ElfClass, data: ElfData, e_type: Option<u16>) -> String {
    let bits = match class {
        ElfClass::Elf32 => "32",
        ElfClass::Elf64 => "64",
        ElfClass::Other(v) => return format!("elf-class{v}"),
    };
    let order = match data {
        ElfData::Le => "le",
        ElfData::Be => "be",
        ElfData::Other(v) => return format!("elf{bits}-data{v}"),
    };
    let suffix = match e_type {
        None | Some(2 | 3) => String::new(),
        Some(1) => "-rel".to_string(),
        Some(4) => "-core".to_string(),
        Some(other) => format!("-type-{other:#x}"),
    };
    format!("elf{bits}-{order}{suffix}")
}

fn pe_name(magic: Option<u16>, machine: Option<u16>) -> String {
    let kind = match magic {
        Some(0x20b) => "pe32+",
        Some(0x10b) => "pe32",
        Some(other) => return format!("pe-magic-{other:#x}"),
        None => return "pe".to_string(),
    };
    let machine = match machine {
        Some(0x8664) => "x86_64".to_string(),
        Some(0x14c) => "i386".to_string(),
        Some(0xaa64) => "arm64".to_string(),
        Some(other) => format!("{other:#x}"),
        None => "unknown".to_string(),
    };
    format!("{kind}-{machine}")
}

/// Reads a little-endian `u16` at `at`.
fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let b = bytes.get(at..end)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

/// Reads a `u16` at `at` in the byte order of `data`.
fn elf16(bytes: &[u8], at: usize, data: ElfData) -> Option<u16> {
    let v = le16(bytes, at)?;
    Some(if data == ElfData::Be {
        v.swap_bytes()
    } else {
        v
    })
}

/// Reads a little-endian `u32` at `at`.
fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let b: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

fn probe_elf(bytes: &[u8]) -> Detected {
    let class = match bytes.get(4).copied().unwrap_or(0) {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        other => ElfClass::Other(other),
    };
    let data = match bytes.get(5).copied().unwrap_or(0) {
        1 => ElfData::Le,
        2 => ElfData::Be,
        other => ElfData::Other(other),
    };
    Detected::Elf {
        class,
        data,
        e_type: elf16(bytes, 16, data),
        machine: elf16(bytes, 18, data),
    }
}

fn probe_mz(bytes: &[u8]) -> Detected {
    let Some(lfanew) = le32(bytes, 0x3c).and_then(|v| usize::try_from(v).ok()) else {
        return Detected::DosMz;
    };
    let sig = lfanew.checked_add(4).and_then(|end| bytes.get(lfanew..end));
    if sig != Some(b"PE\0\0") {
        return Detected::DosMz;
    }
    // The COFF header follows the signature. The optional header follows its 20 bytes.
    let coff = lfanew.saturating_add(4);
    Detected::Pe {
        magic: le16(bytes, coff.saturating_add(20)),
        machine: le16(bytes, coff),
    }
}

/// Finds the format of `bytes` from its magic bytes.
#[must_use]
pub fn probe(bytes: &[u8]) -> Detected {
    match bytes {
        [0x7f, b'E', b'L', b'F', ..] => probe_elf(bytes),
        [b'M', b'Z', ..] => probe_mz(bytes),
        [0xfe, 0xed, 0xfa, 0xce, ..] | [0xce, 0xfa, 0xed, 0xfe, ..] => Detected::MachO { bits: 32 },
        [0xfe, 0xed, 0xfa, 0xcf, ..] | [0xcf, 0xfa, 0xed, 0xfe, ..] => Detected::MachO { bits: 64 },
        [0xca, 0xfe, 0xba, 0xbf, ..] => Detected::Fat,
        [0xca, 0xfe, 0xba, 0xbe, rest @ ..] => {
            // A fat file has a small count of machines. A class file has its version here.
            let word = rest
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(0, u32::from_be_bytes);
            if word < 20 {
                Detected::Fat
            } else {
                Detected::JavaClass
            }
        }
        _ => Detected::Unknown,
    }
}

//! A small ELF64 little-endian reader for the builder tests.
//!
//! It is independent of the builder code, so the tests check the bytes from outside.

#![allow(dead_code, reason = "each test file uses a part of this reader")]

/// A program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phdr {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// A section header with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shdr {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
}

/// A view of the file bytes.
pub struct Elf<'a> {
    pub b: &'a [u8],
}

fn idx(off: u64) -> usize {
    usize::try_from(off).unwrap_or(usize::MAX)
}

impl<'a> Elf<'a> {
    pub const fn new(b: &'a [u8]) -> Self {
        Self { b }
    }

    pub fn u16(&self, off: u64) -> u16 {
        let o = idx(off);
        u16::from_le_bytes([self.b[o], self.b[o + 1]])
    }

    pub fn u32(&self, off: u64) -> u32 {
        let o = idx(off);
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.b[o..o + 4]);
        u32::from_le_bytes(a)
    }

    pub fn i32(&self, off: u64) -> i32 {
        i32::from_le_bytes(self.u32(off).to_le_bytes())
    }

    pub fn u64(&self, off: u64) -> u64 {
        let o = idx(off);
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.b[o..o + 8]);
        u64::from_le_bytes(a)
    }

    pub fn e_type(&self) -> u16 {
        self.u16(16)
    }

    pub fn e_machine(&self) -> u16 {
        self.u16(18)
    }

    pub fn e_entry(&self) -> u64 {
        self.u64(24)
    }

    pub fn e_phoff(&self) -> u64 {
        self.u64(32)
    }

    pub fn e_shoff(&self) -> u64 {
        self.u64(40)
    }

    pub fn e_phentsize(&self) -> u16 {
        self.u16(54)
    }

    pub fn e_phnum(&self) -> u16 {
        self.u16(56)
    }

    pub fn e_shentsize(&self) -> u16 {
        self.u16(58)
    }

    pub fn e_shnum(&self) -> u16 {
        self.u16(60)
    }

    pub fn e_shstrndx(&self) -> u16 {
        self.u16(62)
    }

    pub fn phdrs(&self) -> Vec<Phdr> {
        (0..u64::from(self.e_phnum()))
            .map(|i| {
                let o = self.e_phoff() + i * 56;
                Phdr {
                    p_type: self.u32(o),
                    flags: self.u32(o + 4),
                    offset: self.u64(o + 8),
                    vaddr: self.u64(o + 16),
                    filesz: self.u64(o + 32),
                    memsz: self.u64(o + 40),
                    align: self.u64(o + 48),
                }
            })
            .collect()
    }

    fn raw_shdr(&self, i: u64) -> (u32, Shdr) {
        let o = self.e_shoff() + i * 64;
        (
            self.u32(o),
            Shdr {
                name: String::new(),
                sh_type: self.u32(o + 4),
                flags: self.u64(o + 8),
                addr: self.u64(o + 16),
                offset: self.u64(o + 24),
                size: self.u64(o + 32),
                link: self.u32(o + 40),
                info: self.u32(o + 44),
                align: self.u64(o + 48),
                entsize: self.u64(o + 56),
            },
        )
    }

    pub fn cstr(&self, off: u64) -> String {
        let start = idx(off);
        let end = self.b[start..]
            .iter()
            .position(|&c| c == 0)
            .map_or(self.b.len(), |p| start + p);
        String::from_utf8_lossy(&self.b[start..end]).into_owned()
    }

    pub fn shdrs(&self) -> Vec<Shdr> {
        let n = u64::from(self.e_shnum());
        if n == 0 {
            return Vec::new();
        }
        let (_, strtab) = self.raw_shdr(u64::from(self.e_shstrndx()));
        (0..n)
            .map(|i| {
                let (name_off, mut s) = self.raw_shdr(i);
                s.name = self.cstr(strtab.offset + u64::from(name_off));
                s
            })
            .collect()
    }

    pub fn section(&self, name: &str) -> Option<Shdr> {
        self.shdrs().into_iter().find(|s| s.name == name)
    }

    /// Returns the file offset of a virtual address through the `PT_LOAD` segments.
    pub fn va_to_off(&self, va: u64) -> Option<u64> {
        self.phdrs()
            .into_iter()
            .filter(|p| p.p_type == 1)
            .find(|p| va >= p.vaddr && va < p.vaddr + p.filesz)
            .map(|p| p.offset + (va - p.vaddr))
    }

    /// Returns the `.dynamic` entries through `PT_DYNAMIC`.
    pub fn dynamic(&self) -> Vec<(u64, u64)> {
        let Some(p) = self.phdrs().into_iter().find(|p| p.p_type == 2) else {
            return Vec::new();
        };
        (0..p.filesz / 16)
            .map(|i| (self.u64(p.offset + i * 16), self.u64(p.offset + i * 16 + 8)))
            .collect()
    }

    /// Returns the value of the first dynamic entry with `tag`.
    pub fn dyn_value(&self, tag: u64) -> Option<u64> {
        self.dynamic().into_iter().find(|e| e.0 == tag).map(|e| e.1)
    }

    /// Returns `(name, value, info, shndx)` of each symbol of a symbol table section.
    pub fn symbols(&self, table: &str) -> Vec<(String, u64, u8, u16)> {
        let Some(s) = self.section(table) else {
            return Vec::new();
        };
        let strtab = &self.shdrs()[usize::try_from(s.link).unwrap_or(0)];
        (0..s.size / 24)
            .map(|i| {
                let o = s.offset + i * 24;
                let name = self.cstr(strtab.offset + u64::from(self.u32(o)));
                (name, self.u64(o + 8), self.b[idx(o + 4)], self.u16(o + 6))
            })
            .collect()
    }
}

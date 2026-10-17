//! Planning types of the layout: features, imports, the address context and the placement.

use std::collections::BTreeMap;

use super::consts::{PF_R, PF_W, PF_X, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_ABS, SHT_NOBITS};
use super::plt::GOT_PLT_RESERVED;
use super::write::{align_up, u16_of, u64_of};
use super::{ElfBuilder, ImportKind, Loc, PltStyle, RelocTable};

/// The page size that separates two `PT_LOAD` segments.
pub(crate) const PAGE: u64 = 0x1000;

/// The size of the ELF header.
const EHDR_SIZE: u64 = 64;

/// The size of one program header.
const PHDR_SIZE: u64 = 56;

/// The `sh_info` value of a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Info {
    /// A plain number.
    Num(u32),
    /// The header index of the named section.
    Section(&'static str),
}

/// A section with its bytes and, after the placement, its address.
#[derive(Debug, Clone)]
pub(crate) struct Sect {
    pub(crate) name: String,
    pub(crate) name_off: u32,
    pub(crate) kind: u32,
    pub(crate) flags: u64,
    pub(crate) align: u64,
    pub(crate) entsize: u64,
    pub(crate) data: Vec<u8>,
    pub(crate) mem_size: u64,
    pub(crate) link: &'static str,
    pub(crate) info: Info,
    pub(crate) addr: u64,
    pub(crate) offset: u64,
}

impl Sect {
    /// Makes a section with bytes. The memory size is the number of bytes.
    pub(crate) fn new(
        name: &str,
        kind: u32,
        flags: u64,
        align: u64,
        entsize: u64,
        data: Vec<u8>,
    ) -> Self {
        let mem_size = u64_of(data.len());
        Self {
            name: name.to_string(),
            name_off: 0,
            kind,
            flags,
            align,
            entsize,
            data,
            mem_size,
            link: "",
            info: Info::Num(0),
            addr: 0,
            offset: 0,
        }
    }

    /// Sets the linked section.
    pub(crate) fn linked(mut self, link: &'static str) -> Self {
        self.link = link;
        self
    }

    /// Sets `sh_info`.
    pub(crate) fn with_info(mut self, info: Info) -> Self {
        self.info = info;
        self
    }

    /// Returns `true` when the section occupies memory.
    pub(crate) const fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }

    /// Returns `true` when the section has no file bytes.
    pub(crate) const fn is_nobits(&self) -> bool {
        self.kind == SHT_NOBITS
    }

    /// Returns the segment permission flags of the section.
    pub(crate) const fn perms(&self) -> u32 {
        let mut flags = PF_R;
        if self.flags & SHF_WRITE != 0 {
            flags |= PF_W;
        }
        if self.flags & SHF_EXECINSTR != 0 {
            flags |= PF_X;
        }
        flags
    }
}

/// The parts of the file that the builder settings switch on.
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag for each optional section"
)]
pub(crate) struct Features {
    pub(crate) dynamic: bool,
    pub(crate) rela_dyn: bool,
    pub(crate) rel_dyn: bool,
    pub(crate) rela_plt: bool,
    pub(crate) relr: bool,
    pub(crate) plt: bool,
    pub(crate) plt_got: bool,
    pub(crate) plt_sec: bool,
    pub(crate) got: bool,
    pub(crate) got_plt: bool,
}

impl Features {
    /// Reads the features from the builder.
    pub(crate) fn of(b: &ElfBuilder) -> Self {
        let imports = ImportPlan::of(b);
        let dynamic = b.dynamic
            || !b.imports.is_empty()
            || !b.exports.is_empty()
            || !b.needed.is_empty()
            || b.soname.is_some()
            || b.rpath.is_some()
            || b.runpath.is_some()
            || b.flags.is_some()
            || b.flags_1.is_some()
            || !b.relocs.is_empty()
            || !b.relr.is_empty()
            || b.interp.is_some();
        let with_addend = b.relocs.iter().any(|r| r.table == RelocTable::Rela);
        let without_addend = b.relocs.iter().any(|r| r.table == RelocTable::Rel);
        Self {
            dynamic,
            rela_dyn: dynamic && (with_addend || !imports.got_slots.is_empty()),
            rel_dyn: dynamic && without_addend,
            rela_plt: dynamic && !imports.plt.is_empty(),
            relr: dynamic && !b.relr.is_empty(),
            plt: !imports.plt.is_empty(),
            plt_got: !imports.plt_got.is_empty(),
            plt_sec: !imports.plt.is_empty() && b.plt_style == PltStyle::Ibt,
            got: !imports.got_slots.is_empty(),
            got_plt: !imports.plt.is_empty(),
        }
    }
}

/// The imports sorted by how the builder links them.
#[derive(Debug, Clone, Default)]
pub(crate) struct ImportPlan {
    /// The `Plt` imports in order.
    pub(crate) plt: Vec<String>,
    /// The `PltGot` imports in order.
    pub(crate) plt_got: Vec<String>,
    /// The imports with a `.got` slot (`Got` and `PltGot`) in order.
    pub(crate) got_slots: Vec<String>,
}

impl ImportPlan {
    /// Reads the plan from the builder.
    pub(crate) fn of(b: &ElfBuilder) -> Self {
        let mut plan = Self::default();
        for (name, kind) in &b.imports {
            match kind {
                ImportKind::Plt => plan.plt.push(name.clone()),
                ImportKind::PltGot => {
                    plan.plt_got.push(name.clone());
                    plan.got_slots.push(name.clone());
                }
                ImportKind::Got => plan.got_slots.push(name.clone()),
            }
        }
        plan
    }
}

/// The addresses that the generators of section bytes need.
#[derive(Debug, Clone, Default)]
pub(crate) struct Ctx {
    pub(crate) addr: BTreeMap<String, u64>,
    pub(crate) size: BTreeMap<String, u64>,
    pub(crate) index: BTreeMap<String, u16>,
    ranges: Vec<(u64, u64, u16)>,
    pub(crate) symbols: BTreeMap<String, u64>,
    pub(crate) plt: BTreeMap<String, u64>,
    pub(crate) plt_got: BTreeMap<String, u64>,
    pub(crate) got: BTreeMap<String, u64>,
}

impl Ctx {
    /// Builds the context from placed sections in header order.
    pub(crate) fn of(b: &ElfBuilder, sects: &[Sect]) -> Self {
        let mut ctx = Self::default();
        for (i, s) in sects.iter().enumerate() {
            let index = u16_of(u64_of(i) + 1);
            ctx.addr.insert(s.name.clone(), s.addr);
            ctx.size.insert(s.name.clone(), s.mem_size);
            ctx.index.insert(s.name.clone(), index);
            if s.is_alloc() {
                ctx.ranges
                    .push((s.addr, s.addr.saturating_add(s.mem_size), index));
            }
        }
        ctx.link_stubs(b);
        ctx.resolve_symbols(b);
        ctx
    }

    fn link_stubs(&mut self, b: &ElfBuilder) {
        let plan = ImportPlan::of(b);
        let (plt, entry, first) = match b.plt_style {
            PltStyle::Lazy => (".plt", 16, 16),
            PltStyle::Ibt => (".plt.sec", 16, 0),
        };
        for (i, name) in plan.plt.iter().enumerate() {
            let at = self.addr_of(plt) + first + entry * u64_of(i);
            self.plt.entry(name.clone()).or_insert(at);
            let slot = self.addr_of(".got.plt") + GOT_PLT_RESERVED + 8 * u64_of(i);
            self.got.entry(name.clone()).or_insert(slot);
        }
        let stride = match b.plt_style {
            PltStyle::Lazy => 8,
            PltStyle::Ibt => 16,
        };
        for (i, name) in plan.plt_got.iter().enumerate() {
            let at = self.addr_of(".plt.got") + stride * u64_of(i);
            self.plt_got.entry(name.clone()).or_insert(at);
        }
        for (i, name) in plan.got_slots.iter().enumerate() {
            let slot = self.addr_of(".got") + 8 * u64_of(i);
            self.got.entry(name.clone()).or_insert(slot);
        }
    }

    fn resolve_symbols(&mut self, b: &ElfBuilder) {
        for _ in 0..4 {
            for symbol in b.symbols.iter().chain(&b.exports) {
                let value = self.resolve(&symbol.at);
                self.symbols.insert(symbol.name.clone(), value);
            }
        }
    }

    /// Returns the address of a section, or 0 when the section is missing.
    pub(crate) fn addr_of(&self, name: &str) -> u64 {
        self.addr.get(name).copied().unwrap_or(0)
    }

    /// Returns the memory size of a section, or 0 when the section is missing.
    pub(crate) fn size_of(&self, name: &str) -> u64 {
        self.size.get(name).copied().unwrap_or(0)
    }

    /// Returns the address of a place. A missing target gives 0.
    pub(crate) fn resolve(&self, loc: &Loc) -> u64 {
        match loc {
            Loc::Section(name, offset) => self.addr_of(name).wrapping_add(*offset),
            Loc::Symbol(name) => self.symbols.get(name).copied().unwrap_or(0),
            Loc::Abs(value) => *value,
            Loc::Plt(name) => self.plt.get(name).copied().unwrap_or(0),
            Loc::PltGot(name) => self.plt_got.get(name).copied().unwrap_or(0),
            Loc::Got(name) => self.got.get(name).copied().unwrap_or(0),
        }
    }

    /// Returns the section index for a symbol value.
    pub(crate) fn shndx_of(&self, loc: &Loc, value: u64) -> u16 {
        match loc {
            Loc::Abs(_) => SHN_ABS,
            Loc::Section(name, _) => self.index.get(name).copied().unwrap_or(0),
            _ => self
                .ranges
                .iter()
                .find(|(start, end, _)| value >= *start && value < *end)
                .map_or(SHN_ABS, |r| r.2),
        }
    }
}

/// One `PT_LOAD` segment after the placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Segment {
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) filesz: u64,
    pub(crate) memsz: u64,
}

/// The result of the placement.
#[derive(Debug, Clone)]
pub(crate) struct Placement {
    pub(crate) segments: Vec<Segment>,
    /// The end of the file bytes of all sections.
    pub(crate) file_end: u64,
    /// The offset of the section header table.
    pub(crate) shoff: u64,
}

/// Returns the number of `PT_LOAD` segments for `sects`: one for each run of equal permissions.
pub(crate) fn load_count(sects: &[Sect]) -> usize {
    let mut count = 0;
    let mut last = None;
    for s in sects.iter().filter(|s| s.is_alloc()) {
        if last != Some(s.perms()) {
            count += 1;
            last = Some(s.perms());
        }
    }
    count
}

/// Places the sections: sets `offset` and `addr`, and returns the segments.
///
/// The address of a section is `base + offset`. A new segment starts on a page boundary.
/// The first segment also maps the file header and the program headers.
pub(crate) fn place(sects: &mut [Sect], base: u64, phnum: usize) -> Placement {
    let header_end = EHDR_SIZE + PHDR_SIZE * u64_of(phnum);
    let mut cursor = header_end;
    let mut file_end = header_end;
    let mut segments: Vec<Segment> = Vec::new();
    for s in sects.iter_mut().filter(|s| s.is_alloc()) {
        let perms = s.perms();
        if segments.last().map(|g| g.flags) != Some(perms) {
            let start = if segments.is_empty() {
                0
            } else {
                align_up(cursor, PAGE.max(s.align))
            };
            cursor = cursor.max(start);
            segments.push(Segment {
                flags: perms,
                offset: start,
                filesz: file_end.saturating_sub(start),
                memsz: cursor.saturating_sub(start),
            });
        }
        let offset = align_up(cursor, s.align);
        s.offset = offset;
        s.addr = base.wrapping_add(offset);
        let end = offset.saturating_add(s.mem_size);
        cursor = end;
        if !s.is_nobits() {
            file_end = file_end.max(end);
        }
        if let Some(seg) = segments.last_mut() {
            seg.memsz = end.saturating_sub(seg.offset);
            seg.filesz = file_end.saturating_sub(seg.offset).min(seg.memsz);
        }
    }
    if let Some(last) = segments.last() {
        file_end = file_end.max(last.offset);
    }
    for s in sects.iter_mut().filter(|s| !s.is_alloc()) {
        let offset = align_up(file_end, s.align);
        s.offset = offset;
        s.addr = 0;
        file_end = offset.saturating_add(u64_of(s.data.len()));
    }
    Placement {
        segments,
        file_end,
        shoff: align_up(file_end, 8),
    }
}

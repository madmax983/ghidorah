//! The section header table (design Section 4.3).
//!
//! Sections are optional metadata. The table steps by `e_shentsize`. A count above the
//! limit or past the end of the file gets clamped. Names come from the table of
//! `e_shstrndx`. Index 0 means no names.

use ghidorah_base::{BinText, DiagCode, Range};

use super::consts::{SHDR_SIZE, SHF_ALLOC};
use super::header::{Counts, Header};
use super::view::{Cx, Fields, StrTab};
use crate::binary::{Section, SectionKind};
use crate::diag::Diagnostic;
use crate::limits::clamp_count;

/// The raw `sh_name` values of the sections, in table order.
pub(crate) type NameOffsets = Vec<u32>;

/// Parses the section headers and their names.
pub(crate) fn parse(cx: &mut Cx<'_>, h: &Header, counts: &Counts) -> Vec<Section> {
    if counts.shnum == 0 {
        return Vec::new();
    }
    let entsize = u64::from(h.shentsize);
    if cx.len() < h.shoff {
        cx.diag(Diagnostic::new(DiagCode::Oob, "elf.shdr").at(h.shoff));
        return Vec::new();
    }
    let avail = cx.len().saturating_sub(h.shoff);
    let limit = cx.budget.limits.sections;
    let n = clamp_count(
        counts.shnum,
        entsize,
        avail,
        limit,
        "elf.shdr",
        &mut cx.diags,
    );
    let (mut sections, names) = headers(cx, h, n);
    name_sections(cx, counts.shstrndx, &mut sections, &names);
    sections
}

/// Reads `n` section headers without names.
fn headers(cx: &mut Cx<'_>, h: &Header, n: usize) -> (Vec<Section>, NameOffsets) {
    let mut sections = Vec::with_capacity(n);
    let mut names = Vec::with_capacity(n);
    let entsize = u64::from(h.shentsize);
    for i in 0..n {
        let index = u64::try_from(i).unwrap_or(u64::MAX);
        let at = index
            .checked_mul(entsize)
            .and_then(|o| o.checked_add(h.shoff));
        let raw = at.and_then(|at| {
            let start = usize::try_from(at).ok()?;
            let end = start.checked_add(usize::try_from(SHDR_SIZE).ok()?)?;
            cx.bytes.get(start..end)
        });
        let Some(raw) = raw else {
            cx.diag(Diagnostic::new(DiagCode::Oob, format!("elf.shdr[{i}]")));
            break;
        };
        let mut f = Fields::new(raw);
        names.push(f.u32());
        let kind = f.u32();
        let flags = f.u64();
        let addr = f.u64();
        let file_off = f.u64();
        let size = f.u64();
        let link = f.u32();
        let info = f.u32();
        let align = f.u64();
        let entsize = f.u64();
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let va = if flags & SHF_ALLOC != 0 && size > 0 {
            let va = Range::with_len(addr, size);
            if va.is_none() {
                cx.diag(
                    Diagnostic::new(DiagCode::Overflow, format!("elf.shdr[{i}].sh_addr"))
                        .at(addr)
                        .need(size),
                );
            }
            va
        } else {
            None
        };
        sections.push(Section {
            index,
            name: BinText::default(),
            kind: SectionKind::Elf(kind),
            va,
            addr,
            file_off,
            size,
            flags,
            link,
            info,
            align,
            entsize,
        });
    }
    (sections, names)
}

/// Sets the section names from the name table `strndx`.
fn name_sections(cx: &mut Cx<'_>, strndx: u64, sections: &mut [Section], names: &[u32]) {
    if strndx == 0 {
        return;
    }
    let table = usize::try_from(strndx)
        .ok()
        .and_then(|i| sections.get(i))
        .map(|s| (s.file_off, s.size));
    let Some((off, size)) = table else {
        cx.diag(
            Diagnostic::new(DiagCode::Oob, "elf.ehdr.e_shstrndx")
                .need(strndx)
                .have(u64::try_from(sections.len()).unwrap_or(u64::MAX)),
        );
        return;
    };
    let path = format!("elf.shdr[{strndx}]");
    let Some(bytes) = cx.file_range(off, size, &path) else {
        return;
    };
    let mut strtab = StrTab::new(bytes, path);
    for (section, name) in sections.iter_mut().zip(names) {
        section.name = strtab.get(cx, u64::from(*name));
    }
}

/// Gives the first section of a type.
pub(crate) fn first_of(sections: &[Section], sh_type: u32) -> Option<&Section> {
    sections
        .iter()
        .find(|s| s.kind == SectionKind::Elf(sh_type))
}

/// Gives the bytes of a section. A `SHT_NOBITS` section has none.
pub(crate) fn bytes_of<'a>(cx: &mut Cx<'a>, s: &Section) -> Option<&'a [u8]> {
    if s.kind == SectionKind::Elf(super::consts::SHT_NOBITS) {
        return None;
    }
    cx.file_range(s.file_off, s.size, &format!("elf.shdr[{}]", s.index))
}

//! The ELF64 little-endian loader (design Section 4.3).
//!
//! Mapping comes from `PT_LOAD` segments. Sections are optional metadata.
//! Without section headers, the dynamic view gives symbols, relocations and libraries.
//!
//! Rules of the parser:
//!
//! - All reads go through the K1 [`Reader`](ghidorah_kernel::Reader) or checked slices.
//! - Every table iterator stops after its first error.
//! - No loop advances by a file value before a check that the value is above 0.
//! - Only a short file header is fatal. A bad table gives a diagnostic.
//!
//! Entry sizes:
//!
//! | Value | Diagnostic |
//! |---|---|
//! | `e_phentsize` or `e_shentsize` below the struct size | `E_BAD_ENTSIZE`, no table |
//! | `sh_entsize` of a typed table not equal to the struct size | `E_BAD_ENTSIZE`, no table |
//! | `DT_SYMENT`, `DT_RELAENT`, `DT_RELENT` or `DT_RELRENT` of 0 | `E_LOOP`: the walk cannot advance |
//! | another `DT_*ENT` value not equal to the struct size | `E_BAD_ENTSIZE`, no table |

pub mod consts;
mod dynamic;
mod entries;
mod hash;
mod header;
mod notes;
mod relocs;
mod sections;
mod segments;
mod symbols;
mod version;
mod view;

use std::sync::Arc;

use ghidorah_base::Limits;

use consts::{EM_X86_64, ET_EXEC, PT_INTERP};
use view::Cx;

use crate::binary::{Arch, Binary, Format, Kind, SegmentKind, Sym};
use crate::diag::{Diags, LoadError};
use crate::limits::Budget;
use crate::memmap::MemoryMap;

/// Loads an ELF64 little-endian file.
///
/// # Errors
///
/// Returns [`LoadError::Malformed`] with `E_OOB` when the file header is cut.
pub fn load(
    file: &Arc<[u8]>,
    sha256: [u8; 32],
    limits: &Limits,
) -> Result<(Binary, MemoryMap), LoadError> {
    let bytes: &[u8] = file;
    let h = header::parse(bytes)?;
    let file_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut cx = Cx {
        bytes,
        diags: Diags::default(),
        budget: Budget::new(limits, file_len),
    };
    let arch = if h.machine == EM_X86_64 {
        Arch::X86_64
    } else {
        Arch::Other(h.machine)
    };
    let kind = if h.e_type == ET_EXEC {
        Kind::Exec
    } else {
        Kind::Dyn
    };
    let mut b = Binary::empty(Format::Elf64Le, arch, kind, sha256);
    let counts = header::counts(&mut cx, &h);
    b.segments = segments::parse(&mut cx, &h, counts.phnum);
    b.sections = sections::parse(&mut cx, &h, &counts);
    let map = segments::map(&mut cx, Arc::clone(file), &b.segments);
    b.image_base = segments::image_base(&b.segments);
    b.interp = interp(&mut cx, &b);

    let d = dynamic::parse(&mut cx, &b.segments, &b.sections);
    let mut dynstr = dynamic::strtab(&mut cx, &map, &d);
    let strings = dynamic::strings(&mut cx, &d, &mut dynstr);
    b.libraries = strings.needed;
    b.identity.soname = strings.soname;
    b.rpath = strings.rpath;
    b.runpath = strings.runpath;

    let hash_count = if d.is_empty() {
        None
    } else {
        hash::count(&mut cx, &map, &b.sections, &d)
    };
    let mut syms = symbols::load(&mut cx, &map, &b.sections, &d, hash_count, &mut dynstr);
    version::apply(&mut cx, &map, &d, &mut dynstr, &mut syms.dynsym);
    b.exports = symbols::exports(&mut cx, &syms.dynsym.syms);
    b.symbols = ordered(&b, syms);
    b.relocs = relocs::load(&mut cx, &map, &b.sections, &d, arch.is_x86_64());
    b.notes = notes::load(&mut cx, &b.segments);
    b.identity.build_id = notes::build_id(&b.notes);
    b.entry_points = entries::collect(&cx, &map, h.entry, &d, &b.sections, &b.relocs);
    b.dynamic = d.entries;
    let (diagnostics, dropped) = cx.diags.into_parts();
    b.diagnostics = diagnostics;
    b.diagnostics_dropped = dropped;
    Ok((b, map))
}

/// Gives the symbols of both tables in section order: the table whose section comes first
/// comes first. The dynamic view comes first.
fn ordered(b: &Binary, syms: symbols::Symbols) -> Vec<Sym> {
    let symtab_index = b
        .sections
        .iter()
        .find(|s| s.kind == crate::binary::SectionKind::Elf(consts::SHT_SYMTAB))
        .map(|s| s.index);
    let dynsym_first = match (syms.dynsym_section, symtab_index) {
        (Some(d), Some(s)) => d < s,
        _ => true,
    };
    let (mut first, second) = if dynsym_first {
        (syms.dynsym.syms, syms.symtab.syms)
    } else {
        (syms.symtab.syms, syms.dynsym.syms)
    };
    first.extend(second);
    first
}

/// Reads the program interpreter of the first `PT_INTERP`.
fn interp(cx: &mut Cx<'_>, b: &Binary) -> Option<ghidorah_base::BinText> {
    let s = b
        .segments
        .iter()
        .find(|s| s.kind == SegmentKind::Elf(PT_INTERP))?;
    let path = format!("elf.phdr[{}]", s.index);
    let bytes = cx.file_range(s.file_off, s.file_size, &path)?;
    let text = bytes
        .iter()
        .position(|c| *c == 0)
        .and_then(|end| bytes.get(..end))
        .unwrap_or(bytes);
    Some(cx.text(text, &path))
}

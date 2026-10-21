//! PLT stubs of x86-64 ELF files and their names (design Section 4.5).
//!
//! With section headers, the matcher reads `.plt`, `.plt.got` and `.plt.sec`. It steps by
//! the entry size of the section (8 or 16), else by 16. Without section headers, it looks
//! for PLT0 in the executable regions at a 16-byte step: `push [rip+GOT+8]` and
//! `jmp [rip+GOT+16]` with `GOT = DT_PLTGOT`. Then it reads the entries after PLT0 in steps
//! of 8 or 16 bytes, up to the first block that has no known form. Without PLT0, the matcher
//! finds no stub.
//!
//! | Form | Bytes | Label |
//! |---|---|---|
//! | PLT0 | `ff 35 d32`, then `[f2] ff 25 d32` | `.plt0` |
//! | jump | `[f3 0f 1e fa] [f2] ff 25 d32` | `<name>@plt` |
//! | lazy | `[f3 0f 1e fa] 68 i32 [f2] e9 r32`, or `68 i32 [f2] e9 r32` after a jump | `<name>@plt.lazy` |
//!
//! A jump stub gets its name through the slot map (`slot = next_ip + d32`), never by
//! position (CVE-2017-14729). A lazy stub gets the import of the slot of its `DT_JMPREL`
//! entry. The push index selects the entry, as in the dynamic linker. A stub with no import
//! gives no record. The scan reads at most `Limits::plt_scan_bytes` bytes, and the limit
//! gives one `E_LIMIT`.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::{BinText, DiagCode, Limits};
use ghidorah_kernel::{Endian, Reader};

use crate::binary::{Binary, Format, RelocSource, SectionKind};
use crate::diag::{Diagnostic, Diags};
use crate::elf::consts::{DT_JMPREL, DT_PLTGOT, SHT_REL, SHT_RELA};
use crate::imports::{self, Slot};
use crate::limits::Budget;
use crate::memmap::{MemoryMap, Perms};

/// The form of a stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StubKind {
    /// The first entry of `.plt`. It calls the lazy resolver.
    Plt0,
    /// A stub that jumps through an import slot.
    Jump,
    /// The lazy part of a PLT entry: `push index; jmp PLT0`.
    Lazy,
}

/// One PLT stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stub {
    /// The address of the first byte.
    pub addr: u64,
    /// The form.
    pub kind: StubKind,
    /// The import slot. A lazy stub has the slot of its `DT_JMPREL` entry. PLT0 has none.
    pub slot: Option<u64>,
    /// The import of the slot: its index in [`Binary::imports`], from [`imports::slots`].
    /// PLT0 has none.
    pub import: Option<usize>,
}

/// The stubs of a file in address order, with the diagnostics of the scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StubScan {
    /// The stubs in address order.
    pub stubs: Vec<Stub>,
    /// The kept diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Finds the PLT stubs of a loaded x86-64 ELF file.
#[must_use]
pub fn find(binary: &Binary, map: &MemoryMap, limits: &Limits) -> StubScan {
    let mut diags = Diags::default();
    let stubs = scan(binary, map, limits, &mut diags);
    StubScan {
        stubs,
        diagnostics: diags.into_parts().0,
    }
}

/// Finds the stubs and sets [`Import::stub`](crate::Import::stub) of each import.
///
/// An import gets the first jump stub through its own slot, else the first jump stub
/// through another slot of the import.
pub fn name_stubs(binary: &mut Binary, map: &MemoryMap, limits: &Limits) -> StubScan {
    let scan = find(binary, map, limits);
    set_stubs(binary, &scan.stubs);
    scan
}

/// Gives the label of a stub: `<name>@plt`, `<name>@plt.lazy` or `.plt0`.
///
/// A stub with no import name gives an empty text.
#[must_use]
pub fn label(binary: &Binary, stub: &Stub) -> BinText {
    let suffix: &[u8] = match stub.kind {
        StubKind::Plt0 => return BinText::new(b".plt0".to_vec()),
        StubKind::Jump => b"@plt",
        StubKind::Lazy => b"@plt.lazy",
    };
    let name = stub
        .import
        .and_then(|i| binary.imports.get(i))
        .and_then(|i| i.name.as_ref());
    let Some(name) = name else {
        return BinText::default();
    };
    let mut text = name.as_bytes().to_vec();
    text.extend_from_slice(suffix);
    BinText::new(text)
}

/// Finds the stubs, sets the stub of each import and adds the diagnostics to `diags`.
pub(crate) fn apply(binary: &mut Binary, map: &MemoryMap, budget: &Budget, diags: &mut Diags) {
    let stubs = scan(binary, map, &budget.limits, diags);
    set_stubs(binary, &stubs);
}

/// Sets the stub of each import from the jump stubs.
fn set_stubs(binary: &mut Binary, stubs: &[Stub]) {
    // For each import: the first stub through its own slot, and the first stub at all.
    let mut best: BTreeMap<usize, (Option<u64>, Option<u64>)> = BTreeMap::new();
    for s in stubs.iter().filter(|s| s.kind == StubKind::Jump) {
        let Some(i) = s.import else {
            continue;
        };
        let own = binary.imports.get(i).and_then(|imp| imp.slot) == s.slot;
        let entry = best.entry(i).or_insert((None, None));
        if own && entry.0.is_none() {
            entry.0 = Some(s.addr);
        }
        if entry.1.is_none() {
            entry.1 = Some(s.addr);
        }
    }
    for (i, import) in binary.imports.iter_mut().enumerate() {
        import.stub = best.get(&i).and_then(|(own, any)| own.or(*any));
    }
}

/// `endbr64`.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// The NOP forms of the padding in a PLT entry.
const NOPS: [&[u8]; 9] = [
    &[0x90],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x00],
    &[0xcc],
];

/// Moves the reader past `prefix` when the bytes start with it.
fn skip_prefix(r: &mut Reader<'_>, prefix: &[u8]) {
    if r.rest().starts_with(prefix) {
        let _ = r.skip(prefix.len());
    }
}

/// Gives the target of a RIP-relative field: the address after the field plus `disp`.
fn target(r: &mut Reader<'_>, va: u64) -> Option<u64> {
    let disp = r.u32().ok()?.cast_signed();
    let next = va.checked_add(u64::try_from(r.pos()).ok()?)?;
    next.checked_add_signed(i64::from(disp))
}

/// Matches `[f3 0f 1e fa] [f2] ff 25 d32` at `va`. Gives the slot and the length.
fn jump(bytes: &[u8], va: u64) -> Option<(u64, usize)> {
    let mut r = Reader::new(bytes, Endian::Little);
    skip_prefix(&mut r, &ENDBR64);
    skip_prefix(&mut r, &[0xf2]);
    if r.take(2).ok()? != [0xff, 0x25] {
        return None;
    }
    let slot = target(&mut r, va)?;
    Some((slot, r.pos()))
}

/// Matches `[f3 0f 1e fa] 68 i32 [f2] e9 r32` at `va`. Gives the push index and the target.
fn lazy(bytes: &[u8], va: u64) -> Option<(u32, u64)> {
    let mut r = Reader::new(bytes, Endian::Little);
    skip_prefix(&mut r, &ENDBR64);
    if r.u8().ok()? != 0x68 {
        return None;
    }
    let index = r.u32().ok()?;
    skip_prefix(&mut r, &[0xf2]);
    if r.u8().ok()? != 0xe9 {
        return None;
    }
    Some((index, target(&mut r, va)?))
}

/// Matches PLT0 at `va`: `ff 35 d32`, then `[f2] ff 25 d32`. Gives both GOT targets.
fn plt0(bytes: &[u8], va: u64) -> Option<(u64, u64)> {
    let mut r = Reader::new(bytes, Endian::Little);
    if r.take(2).ok()? != [0xff, 0x35] {
        return None;
    }
    let push = target(&mut r, va)?;
    skip_prefix(&mut r, &[0xf2]);
    if r.take(2).ok()? != [0xff, 0x25] {
        return None;
    }
    Some((push, target(&mut r, va)?))
}

/// Tells if the first 8 bytes (or fewer at the end) are a run of padding forms.
fn padding8(bytes: &[u8]) -> bool {
    let block = bytes.get(..8).unwrap_or(bytes);
    let mut r = Reader::new(block, Endian::Little);
    while r.remaining() > 0 {
        let Some(nop) = NOPS.iter().find(|n| r.rest().starts_with(n)) else {
            return false;
        };
        let _ = r.skip(nop.len());
    }
    !block.is_empty()
}

/// The state of one scan.
struct Scanner<'d> {
    slots: BTreeMap<u64, Slot>,
    /// The place of each `DT_JMPREL` entry in table order.
    jmprel: Vec<u64>,
    /// The address of PLT0, when the scan found it.
    plt0: Option<u64>,
    out: Vec<Stub>,
    /// The bytes that the scan can still read.
    left: u64,
    told: bool,
    diags: &'d mut Diags,
}

impl Scanner<'_> {
    /// Takes `n` bytes from the scan limit. On `false`, the scan stops.
    fn take(&mut self, n: usize, va: u64) -> bool {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        if let Some(left) = self.left.checked_sub(n) {
            self.left = left;
            return true;
        }
        if !self.told {
            self.told = true;
            self.diags.push(
                Diagnostic::new(DiagCode::Limit, "elf.plt")
                    .at(va)
                    .hint("the PLT scan reads no more bytes"),
            );
        }
        self.left = 0;
        false
    }

    fn push(&mut self, addr: u64, kind: StubKind, slot: Option<u64>) {
        let import = slot.and_then(|s| self.slots.get(&s)).map(|s| s.import);
        if kind == StubKind::Plt0 || import.is_some() {
            self.out.push(Stub {
                addr,
                kind,
                slot,
                import,
            });
        }
    }

    /// Matches a lazy stub at `va`. Gives `true` when the bytes have the lazy form.
    fn lazy_at(&mut self, bytes: &[u8], va: u64) -> bool {
        let Some((index, to)) = lazy(bytes, va) else {
            return false;
        };
        if self.plt0.is_some_and(|p| p != to) {
            return false;
        }
        let slot = usize::try_from(index)
            .ok()
            .and_then(|i| self.jmprel.get(i))
            .copied();
        self.push(va, StubKind::Lazy, slot);
        true
    }

    /// Reads one entry at `va`. Gives the entry size, or `None` for an unknown form.
    fn entry(&mut self, bytes: &[u8], va: u64) -> Option<usize> {
        if self.lazy_at(bytes, va) {
            return Some(16);
        }
        if let Some((slot, len)) = jump(bytes, va) {
            self.push(va, StubKind::Jump, Some(slot));
            let rest = bytes.get(len..).unwrap_or_default();
            let after = va.checked_add(u64::try_from(len).ok()?)?;
            let has_lazy = self.lazy_at(rest, after);
            return Some(if len <= 8 && !has_lazy { 8 } else { 16 });
        }
        None
    }

    /// Reads a PLT section: PLT0 at its start for `.plt`, then each entry at `stride`.
    fn section(&mut self, bytes: &[u8], va: u64, stride: usize, is_plt: bool) {
        let has_plt0 =
            is_plt && plt0(bytes, va).is_some_and(|(push, jmp)| push.checked_add(8) == Some(jmp));
        if has_plt0 {
            if !self.take(16, va) {
                return;
            }
            self.plt0 = Some(va);
            self.push(va, StubKind::Plt0, None);
        }
        let mut off = if has_plt0 { 16 } else { 0 };
        while let Some(rest) = bytes.get(off..).filter(|r| !r.is_empty()) {
            let Some(at) = u64::try_from(off).ok().and_then(|o| va.checked_add(o)) else {
                return;
            };
            if !self.take(stride, at) {
                return;
            }
            let entry = rest.get(..stride).unwrap_or(rest);
            let _ = self.entry(entry, at);
            let Some(next) = off.checked_add(stride) else {
                return;
            };
            off = next;
        }
    }

    /// Reads the entries after PLT0 at `start` in steps of 8 or 16 bytes.
    fn run(&mut self, bytes: &[u8], va: u64, start: usize) {
        let mut off = start;
        while let Some(rest) = bytes.get(off..).filter(|r| !r.is_empty()) {
            let Some(at) = u64::try_from(off).ok().and_then(|o| va.checked_add(o)) else {
                return;
            };
            if !self.take(8, at) {
                return;
            }
            let size = match self.entry(rest, at) {
                Some(size) => size,
                None if padding8(rest) => 8,
                None => return,
            };
            if !self.take(size.saturating_sub(8), at) {
                return;
            }
            let Some(next) = off.checked_add(size) else {
                return;
            };
            off = next;
        }
    }

    /// Finds PLT0 in the executable regions without section headers, then reads its run.
    fn dynamic_view(&mut self, binary: &Binary, map: &MemoryMap) {
        let Some(got) = binary.dyn_value(DT_PLTGOT) else {
            return;
        };
        let want = got.checked_add(8).zip(got.checked_add(16));
        for region in map.regions().filter(|r| r.perms.contains(Perms::EXECUTE)) {
            let Some(bytes) = file_part(map, region.file_off, region.file_size) else {
                continue;
            };
            let skew = usize::try_from(region.va.first.wrapping_neg() & 15).unwrap_or(0);
            let mut off = skew;
            while let Some(rest) = bytes.get(off..).filter(|r| !r.is_empty()) {
                let Some(at) = u64::try_from(off)
                    .ok()
                    .and_then(|o| region.va.first.checked_add(o))
                else {
                    break;
                };
                if !self.take(16, at) {
                    return;
                }
                if want.is_some() && plt0(rest, at) == want {
                    self.plt0 = Some(at);
                    self.push(at, StubKind::Plt0, None);
                    self.run(bytes, region.va.first, off.saturating_add(16));
                    return;
                }
                let Some(next) = off.checked_add(16) else {
                    break;
                };
                off = next;
            }
        }
    }
}

/// Gives the file bytes `[off, off + len)`, cut at the end of the file.
fn file_part(map: &MemoryMap, off: u64, len: u64) -> Option<&[u8]> {
    let file = map.file();
    let start = usize::try_from(off).ok()?;
    let end = usize::try_from(off.saturating_add(len))
        .unwrap_or(usize::MAX)
        .min(file.len());
    file.get(start..end)
}

/// Gives the place of each `DT_JMPREL` entry in table order.
fn jmprel(binary: &Binary) -> Vec<u64> {
    let Some(va) = binary.dyn_value(DT_JMPREL) else {
        return Vec::new();
    };
    let source = if binary.sections.is_empty() {
        Some(RelocSource::DynPlt)
    } else {
        binary
            .sections
            .iter()
            .find(|s| s.addr == va && matches!(s.kind, SectionKind::Elf(SHT_RELA | SHT_REL)))
            .map(|s| RelocSource::Section(s.index))
    };
    binary
        .relocs
        .iter()
        .filter(|r| Some(r.source) == source)
        .map(|r| r.offset)
        .collect()
}

/// Scans the PLT areas of the file.
fn scan(binary: &Binary, map: &MemoryMap, limits: &Limits, diags: &mut Diags) -> Vec<Stub> {
    if binary.format != Format::Elf64Le || !binary.arch.is_x86_64() {
        return Vec::new();
    }
    let slots = imports::slots(binary);
    if slots.is_empty() {
        return Vec::new();
    }
    let mut s = Scanner {
        slots,
        jmprel: jmprel(binary),
        plt0: None,
        out: Vec::new(),
        left: limits.plt_scan_bytes,
        told: false,
        diags,
    };
    if binary.sections.is_empty() {
        s.dynamic_view(binary, map);
    } else {
        let names: [&[u8]; 3] = [b".plt", b".plt.got", b".plt.sec"];
        for sec in binary
            .sections
            .iter()
            .filter(|x| names.contains(&x.name.as_bytes()))
        {
            let Some(va) = sec.va else {
                continue;
            };
            let Some(bytes) = file_part(map, sec.file_off, sec.size) else {
                continue;
            };
            let stride = match sec.entsize {
                8 => 8,
                _ => 16,
            };
            s.section(bytes, va.first, stride, sec.name.as_bytes() == b".plt");
        }
    }
    let mut out = s.out;
    out.sort_unstable();
    out.dedup_by_key(|x| (x.addr, x.kind));
    out
}

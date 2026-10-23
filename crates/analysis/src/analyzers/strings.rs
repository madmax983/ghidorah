//! `Strings` (band 650): ASCII, UTF-8 and UTF-16LE strings (design Section 7.6).
//!
//! The analyzer finds strings in two steps. A string of an earlier step wins, so a later
//! candidate that starts in it goes.
//!
//! | Step | Where | Text test | Rule | `referenced` |
//! |---|---|---|---|---|
//! | 1 | each RAM target of a data reference, outside executable memory | at least 3 of 4 characters are text | `R_STRING_REF` | `true` |
//! | 2 | the scan scope: UTF-16LE runs, then byte runs before a 0 byte | UTF-16LE: every character is text; bytes: the test of step 1, else the longest tail of text characters | `R_STRING_SCAN` | `false` |
//!
//! Rules:
//!
//! - A string has at least [`MIN_CHARS`] characters (UTF-16LE: code units) and a terminator:
//!   a 0 byte, or a 0 code unit for UTF-16LE. The terminator is inside the region (step 1) or
//!   inside the section (step 2), and inside [`MAX_BYTES`] bytes of the start.
//! - A text character is a character that is not a control character, or a tab, a line feed
//!   or a carriage return. A byte of bad UTF-8 is not text. A UTF-16LE text character is ASCII.
//! - Step 1 tries UTF-16LE first when the second byte is 0 and the first byte is not 0.
//! - Step 2 reads UTF-16LE runs at even addresses only.
//! - The scan scope is the read-only data sections: allocated `SHT_PROGBITS` sections without
//!   the write and execute flags, except `.interp`, `.eh_frame`, `.eh_frame_hdr` and
//!   `.gcc_except_table`. A file with no section headers uses its regions without execute
//!   permission.
//! - A byte string with a byte above `0x7f` has the encoding UTF-8. Else it is ASCII.
//! - `len` is the length in bytes without the terminator.
//!
//! [`render`] gives the text of a string with the escapes of `BinText` and the exact bytes in
//! hex (design Section 10.16).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, BinText, Caps, Limits, Range, Rendered, StringId, hex};
use ghidorah_db::{Encoding, FactKey, Program, StrInfo};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::{Perms, SectionKind};

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};
use crate::work::Work;

/// The smallest number of characters of a string.
pub const MIN_CHARS: u64 = 4;

/// The largest number of bytes from the start of a string to its terminator.
pub const MAX_BYTES: u64 = 4_096;

/// The largest number of bytes of one section that the scan reads.
pub const MAX_SCAN: u64 = 64 << 20;

/// The scan bytes that cost one work unit.
const BYTES_PER_UNIT: u64 = 64;

/// `SHT_PROGBITS`.
const SHT_PROGBITS: u32 = 1;
/// `SHF_WRITE` and `SHF_EXECINSTR`.
const SHF_WRITE_EXEC: u64 = 0x1 | 0x4;
/// The PE section flags `IMAGE_SCN_MEM_EXECUTE` and `IMAGE_SCN_MEM_WRITE`.
const SCN_WRITE_EXEC: u64 = 0x2000_0000 | 0x8000_0000;
/// The PE section flag `IMAGE_SCN_CNT_UNINITIALIZED_DATA`.
const SCN_UNINITIALIZED: u64 = 0x80;
/// The read-only sections without text.
const NO_TEXT: [&str; 4] = [".interp", ".eh_frame", ".eh_frame_hdr", ".gcc_except_table"];

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::Strings,
    name: "Strings",
    priority: 650,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[
        Opt {
            name: "min_chars",
            value: MIN_CHARS,
            doc: "The smallest number of characters of a string.",
        },
        Opt {
            name: "max_bytes",
            value: MAX_BYTES,
            doc: "The largest number of bytes from the start of a string to its terminator.",
        },
    ],
    doc: "Finds the referenced strings, then the strings of the read-only data.",
};

/// Tells if `c` is a text character.
fn is_text(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\n' | '\r')
}

/// Gives the number of characters of `bytes` and the number of text characters. Each byte of
/// bad UTF-8 is one character that is not text.
fn counts(bytes: &[u8]) -> (u64, u64) {
    let (mut all, mut text) = (0u64, 0u64);
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            all = all.saturating_add(1);
            text = text.saturating_add(u64::from(is_text(c)));
        }
        let bad = u64::try_from(chunk.invalid().len()).unwrap_or(u64::MAX);
        all = all.saturating_add(bad);
    }
    (all, text)
}

/// Tells if `text` of `all` characters passes the test of step 1.
const fn mostly_text(all: u64, text: u64) -> bool {
    all >= MIN_CHARS && text.saturating_mul(4) >= all.saturating_mul(3)
}

/// Gives the encoding of a byte string.
fn byte_encoding(bytes: &[u8]) -> Encoding {
    if bytes.is_ascii() {
        Encoding::Ascii
    } else {
        Encoding::Utf8
    }
}

/// Gives a byte length as the `len` of a string.
fn len_of(n: usize) -> Option<u32> {
    u32::try_from(n).ok()
}

/// Tells if a text of `n` bytes fits in [`MAX_BYTES`].
fn fits(n: usize) -> bool {
    u64::try_from(n).is_ok_and(|l| l <= MAX_BYTES)
}

/// Gives the UTF-16LE code units of `bytes`.
fn units(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes.chunks_exact(2).map(|c| match c {
        [lo, hi] => u16::from_le_bytes([*lo, *hi]),
        _ => 0,
    })
}

/// Gives the bytes at `at` up to `max` bytes or the end of the region. A region with execute
/// permission gives `None`.
fn window(program: &Program, at: u64, max: u64) -> Option<Vec<u8>> {
    let region = program.mem().region_at(at)?;
    if region.perms.contains(Perms::EXECUTE) {
        return None;
    }
    let left = region.va.last.checked_sub(at)?.saturating_add(1);
    let bytes = program
        .mem()
        .read(at, left.min(max), &Limits::DEFAULT)
        .ok()?;
    Some(bytes.into_owned())
}

/// Gives the UTF-16LE string of step 1 at the start of `w`.
fn wide_at(w: &[u8]) -> Option<StrInfo> {
    let n = units(w).position(|u| u == 0)?;
    let text = w.get(..n.checked_mul(2)?)?;
    let (mut all, mut ok) = (0u64, 0u64);
    for c in char::decode_utf16(units(text)) {
        all = all.saturating_add(1);
        ok = ok.saturating_add(u64::from(c.is_ok_and(|c| c.is_ascii() && is_text(c))));
    }
    (fits(text.len()) && mostly_text(all, ok)).then_some(StrInfo {
        encoding: Encoding::Utf16Le,
        len: len_of(text.len())?,
        referenced: true,
    })
}

/// Gives the byte string of step 1 at the start of `w`.
fn bytes_at(w: &[u8]) -> Option<StrInfo> {
    let n = w.iter().position(|b| *b == 0)?;
    let text = w.get(..n)?;
    let (all, ok) = counts(text);
    (fits(n) && mostly_text(all, ok)).then_some(StrInfo {
        encoding: byte_encoding(text),
        len: len_of(n)?,
        referenced: true,
    })
}

/// Gives the string at the referenced address `at` by the text test of step 1.
#[must_use]
pub fn at_ref(program: &Program, at: u64) -> Option<StrInfo> {
    let w = window(program, at, MAX_BYTES.saturating_add(2))?;
    if let [lo, 0, ..] = w.as_slice()
        && *lo != 0
        && let Some(info) = wide_at(&w)
    {
        return Some(info);
    }
    bytes_at(&w)
}

/// Gives the scan scope of `program`.
#[must_use]
pub fn scope(program: &Program) -> RangeSet {
    let mut out = RangeSet::new();
    let sections: Vec<_> = program
        .binary()
        .sections
        .iter()
        .filter(|s| s.va.is_some())
        .collect();
    if sections.is_empty() {
        for r in program.mem().regions() {
            if !r.perms.contains(Perms::EXECUTE) {
                out.insert(r.va);
            }
        }
        return out;
    }
    for s in sections {
        let named = s.name.as_str().is_some_and(|n| NO_TEXT.contains(&n));
        let text = match s.kind {
            SectionKind::Elf(kind) => kind == SHT_PROGBITS && s.flags & SHF_WRITE_EXEC == 0,
            SectionKind::Pe => s.flags & (SCN_WRITE_EXEC | SCN_UNINITIALIZED) == 0,
        };
        if let Some(va) = s.va
            && text
            && !named
        {
            out.insert(va);
        }
    }
    out
}

/// The addresses of the strings that a search holds.
#[derive(Default)]
struct Spans {
    set: RangeSet,
}

impl Spans {
    /// Adds the bytes of the string `info` at `at`.
    fn cover(&mut self, at: u64, info: StrInfo) {
        if let Some(r) = Range::with_len(at, u64::from(info.len)) {
            self.set.insert(r);
        }
    }

    /// Adds the string `info` at `at` to `out` when no string holds its start.
    fn add(&mut self, at: u64, info: StrInfo, out: &mut BTreeMap<u64, StrInfo>) {
        if self.set.contains(at) || out.contains_key(&at) {
            return;
        }
        self.cover(at, info);
        out.insert(at, info);
    }
}

/// Tells if the code unit `u` is a UTF-16LE text unit of step 2.
fn wide_text(u: u16) -> bool {
    u8::try_from(u).is_ok_and(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
}

/// Gives the length of the text character at the start of `rest` for step 2.
fn text_char(rest: &[u8]) -> Option<usize> {
    let lead = *rest.first()?;
    if lead.is_ascii_graphic() || matches!(lead, b' ' | b'\t' | b'\n' | b'\r') {
        return Some(1);
    }
    let n = match lead {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let c = std::str::from_utf8(rest.get(..n)?).ok()?.chars().next()?;
    is_text(c).then_some(n)
}

/// Gives the UTF-16LE code unit at the offset `i` of `bytes`.
fn unit_at(bytes: &[u8], i: usize) -> Option<u16> {
    match bytes.get(i..i.checked_add(2)?)? {
        [lo, hi] => Some(u16::from_le_bytes([*lo, *hi])),
        _ => None,
    }
}

/// Gives the offset of `i` in a section at `base` as an address.
fn addr(base: u64, i: usize) -> Option<u64> {
    base.checked_add(u64::try_from(i).ok()?)
}

/// Finds the UTF-16LE strings of step 2 in the section bytes `bytes` at `base`.
fn sweep_wide(base: u64, bytes: &[u8], spans: &mut Spans, out: &mut BTreeMap<u64, StrInfo>) {
    let mut i = usize::from(base & 1 == 1);
    while i.saturating_add(1) < bytes.len() {
        let start = i;
        let mut n = 0usize;
        while unit_at(bytes, i).is_some_and(wide_text) {
            n = n.saturating_add(1);
            i = i.saturating_add(2);
        }
        if n == 0 {
            i = i.saturating_add(2);
            continue;
        }
        let ends = unit_at(bytes, i) == Some(0);
        let len = n.saturating_mul(2);
        if ends
            && fits(len)
            && u64::try_from(n).is_ok_and(|n| n >= MIN_CHARS)
            && let (Some(at), Some(len)) = (addr(base, start), len_of(len))
        {
            let info = StrInfo {
                encoding: Encoding::Utf16Le,
                len,
                referenced: false,
            };
            spans.add(at, info, out);
        }
    }
}

/// Gives the candidate of step 2 in the run `seg` before a 0 byte: its offset in the run.
///
/// A run that passes the text test of step 1 is the candidate. Else the candidate is the longest
/// tail of the run with text characters only.
fn candidate(seg: &[u8]) -> Option<usize> {
    let (all, ok) = counts(seg);
    if fits(seg.len()) && mostly_text(all, ok) {
        return Some(0);
    }
    let mut i = 0usize;
    let mut tail = 0usize;
    while let Some(rest) = seg.get(i..).filter(|r| !r.is_empty()) {
        if let Some(k) = text_char(rest) {
            i = i.saturating_add(k);
        } else {
            i = i.saturating_add(1);
            tail = i;
        }
    }
    let text = seg.get(tail..)?;
    (fits(text.len()) && counts(text).0 >= MIN_CHARS).then_some(tail)
}

/// Finds the byte strings of step 2 in the section bytes `bytes` at `base`. Each run of bytes
/// before a 0 byte gives at most one string.
fn sweep_bytes(base: u64, bytes: &[u8], spans: &mut Spans, out: &mut BTreeMap<u64, StrInfo>) {
    let mut start = 0usize;
    for (end, b) in bytes.iter().enumerate() {
        if *b != 0 {
            continue;
        }
        let seg = bytes.get(start..end).unwrap_or_default();
        if let Some(off) = candidate(seg)
            && let Some(text) = seg.get(off..)
            && let (Some(at), Some(len)) =
                (addr(base, start.saturating_add(off)), len_of(text.len()))
        {
            let info = StrInfo {
                encoding: byte_encoding(text),
                len,
                referenced: false,
            };
            spans.add(at, info, out);
        }
        start = end.saturating_add(1);
    }
}

/// Gives the number of bytes of the scope range `r` that the sweep reads.
///
/// The read stops 2 bytes after the last byte that can come from the file. The bytes after it
/// read as zero, and zero bytes hold no string. The 2 bytes keep the terminator of a byte
/// string and of a UTF-16LE string. A range with an unmapped byte in its first [`MAX_SCAN`]
/// bytes gives 0, because a read of it fails. A range with no file bytes gives 0 too.
#[must_use]
pub fn scan_len(program: &Program, r: &Range) -> u64 {
    let len = u64::try_from(r.len()).unwrap_or(u64::MAX).min(MAX_SCAN);
    let Some(last) = len.checked_sub(1).and_then(|n| r.first.checked_add(n)) else {
        return 0;
    };
    // `end` is the first address after the last byte that can come from the file.
    let mut end: Option<u64> = None;
    let mut cur = r.first;
    // Each pass moves past one region, so the regions of the map bound the loop.
    loop {
        let Some(region) = program.mem().region_at(cur) else {
            return 0;
        };
        let stop = region.va.last.min(last);
        let backed = region.va.first.saturating_add(region.file_size);
        if backed > cur {
            end = Some(backed.min(stop.saturating_add(1)));
        }
        if stop >= last {
            break;
        }
        cur = stop.saturating_add(1);
    }
    end.map_or(0, |e| e.saturating_sub(r.first).saturating_add(2).min(len))
}

/// Runs step 2 over the scan scope of `program` with the spans of step 1.
fn sweep(program: &Program, spans: &mut Spans, out: &mut BTreeMap<u64, StrInfo>) -> u64 {
    let mut work = 0u64;
    for r in scope(program).ranges() {
        let len = u64::try_from(r.len()).unwrap_or(u64::MAX).min(MAX_SCAN);
        work = work.saturating_add(len / BYTES_PER_UNIT);
        let Ok(bytes) = program
            .mem()
            .read(r.first, scan_len(program, r), &Limits::DEFAULT)
        else {
            continue;
        };
        sweep_wide(r.first, &bytes, spans, out);
        sweep_bytes(r.first, &bytes, spans, out);
    }
    work
}

/// Gives the strings of the scan scope by the text test of step 2.
#[must_use]
pub fn scan(program: &Program) -> BTreeMap<u64, StrInfo> {
    strings(program, &BTreeSet::new())
}

/// Gives the strings of `program`: step 1 at each address of `targets`, then step 2.
#[must_use]
pub fn strings(program: &Program, targets: &BTreeSet<u64>) -> BTreeMap<u64, StrInfo> {
    find(program, targets).0
}

/// Gives the strings of `program` and the work units of the search.
fn find(program: &Program, targets: &BTreeSet<u64>) -> (BTreeMap<u64, StrInfo>, u64) {
    let mut out = BTreeMap::new();
    let mut spans = Spans::default();
    for at in targets {
        if let Some(info) = at_ref(program, *at) {
            spans.cover(*at, info);
            out.insert(*at, info);
        }
    }
    let work = sweep(program, &mut spans, &mut out);
    (out, work)
}

/// Gives the exact bytes of the string `info` at `at`, without the terminator.
#[must_use]
pub fn bytes(program: &Program, at: u64, info: &StrInfo) -> Option<Vec<u8>> {
    let raw = program
        .mem()
        .read(at, u64::from(info.len), &Limits::DEFAULT)
        .ok()?;
    Some(raw.into_owned())
}

/// Gives the output form of the string `info` at `at` with the caps `caps`.
///
/// The text holds the decoded characters with the escapes of `BinText`. The hex holds the
/// exact bytes. `len` is the byte length.
#[must_use]
pub fn render(program: &Program, at: u64, info: &StrInfo, caps: Caps) -> Option<Rendered> {
    let raw = bytes(program, at, info)?;
    if info.encoding != Encoding::Utf16Le {
        return Some(BinText::new(raw).render(caps));
    }
    let text = String::from_utf16_lossy(&units(&raw).collect::<Vec<u16>>());
    let shown = BinText::new(text.into_bytes()).render(caps);
    let cut = raw.get(..caps.hex_bytes).unwrap_or(&raw);
    Some(Rendered {
        text: shown.text,
        hex: hex::encode(cut),
        len: raw.len(),
        truncated: shown.truncated || cut.len() < raw.len(),
    })
}

/// Runs one step over `ranges`. The step finds all strings again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    let program = ctx.program();
    let mut premises: BTreeMap<u64, Vec<FactKey>> = BTreeMap::new();
    let data = &ctx.work.data;
    for key in data.operands.iter().filter(|k| k.to.is_ram()) {
        premises
            .entry(key.to.off)
            .or_default()
            .push(FactKey::Ref(*key));
    }
    for (at, slot) in data.slots.iter().filter(|(_, s)| s.to.is_ram()) {
        let key = slot.key(*at);
        premises
            .entry(key.to.off)
            .or_default()
            .push(FactKey::Ref(key));
    }
    for (at, entry) in &data.entries {
        let key = entry.key(*at);
        premises
            .entry(key.to.off)
            .or_default()
            .push(FactKey::Ref(key));
    }
    for r in program.base().refs().iter() {
        let key = r.value.key;
        if !key.kind.is_flow() && key.to.is_ram() {
            premises.entry(key.to.off).or_default();
        }
    }
    let targets: BTreeSet<u64> = premises.keys().copied().collect();
    let (found, work) = find(program, &targets);
    let mut next = BTreeMap::new();
    for (at, info) in found {
        let why = if info.referenced {
            Why::new(Rule::StringRef, premises.remove(&at).unwrap_or_default())
        } else {
            Why::bare(Rule::StringScan)
        };
        next.insert(at, (info, why));
    }
    let count = u64::try_from(next.len()).unwrap_or(u64::MAX);
    if next != ctx.work.strings {
        ctx.work.strings = next;
        ctx.touch();
    }
    Step {
        work: work.saturating_add(count).saturating_add(1),
    }
}

/// Adds the strings of `work` to the why-records of a publish step. Gives the string rows.
pub(crate) fn collect(work: &Work, whys: &mut crate::publish::whys::Whys) -> Vec<(u64, StrInfo)> {
    let mut rows = Vec::with_capacity(work.strings.len());
    for (at, (info, why)) in &work.strings {
        rows.push((*at, *info));
        whys.insert(FactKey::Str(StringId(Address::ram(*at))), why.clone());
    }
    rows
}

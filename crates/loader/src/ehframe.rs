//! `.eh_frame`: CIE and FDE records, pointer encodings and CFA rows (design Section 4.4).
//!
//! The loader finds `.eh_frame` through its section. Without a `.eh_frame` section, it reads
//! the `eh_frame_ptr` field of `.eh_frame_hdr` through `PT_GNU_EH_FRAME`. It does not read
//! the sorted table of `.eh_frame_hdr`. An empty `PT_GNU_EH_FRAME` gives no FDE.
//!
//! Records:
//!
//! | Field | Rule |
//! |---|---|
//! | length | 4 bytes. `0xffffffff` escapes to an 8-byte length. 0 ends the list. |
//! | CIE ID | 4 bytes after both length forms (LSB). 0 marks a CIE. Another value is the backward CIE pointer of an FDE. |
//! | CIE version | 1, 3 or 4. Another value gives `E_BAD_MAGIC`. |
//! | augmentation | `z`, then `L`, `P`, `R`, `S`, `B` or `G`. An empty text is valid. |
//! | FDE pointers | The `R` encoding. The default is `DW_EH_PE_absptr`. |
//! | `datarel` base | 0 in `.eh_frame`, as in libgcc for x86-64. The start of `.eh_frame_hdr` there. |
//!
//! An FDE with a PC range of 0 gives no record. A bad CIE, a bad CIE pointer or a bad
//! pointer gives a diagnostic, and the walk goes on with the next record. A record that
//! runs past the data stops the walk with `E_OOB`. The FDE limit stops it with `E_LIMIT`.
//!
//! CFA rows:
//!
//! - The interpreter reads `DW_CFA_advance_loc*`, `def_cfa*`, `offset*`, `restore*`,
//!   `remember_state`, `restore_state` and `nop`.
//! - It also reads the register-rule opcodes (`undefined`, `same_value`, `register`,
//!   `expression`, `val_*`, `GNU_args_size`, `GNU_negative_offset_extended`). They do not
//!   change the CFA, so the rows do not change.
//! - `def_cfa_expression` and other opcodes stop the FDE with `E_CFA_OPCODE`.
//! - A stopped FDE keeps its PC range and has no CFA rows. So no reader gets a wrong row.
//! - A row starts at each address where the CFA rule changes. The walk keeps no row at or
//!   after the end of the PC range.

mod cfa;
mod pointer;
mod source;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::{DiagCode, Limits, Range};
use ghidorah_kernel::{Endian, Reader};

pub use pointer::{Bases, PointerError, read_pointer};

use crate::binary::{Binary, Fde};
use crate::diag::{Diagnostic, Diags};
use crate::memmap::MemoryMap;
use cfa::{Factors, Rule};
use source::source;

/// The place of `.eh_frame` bytes: the address and the file offset of the first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Place {
    /// The virtual address of the first byte.
    pub va: u64,
    /// The file offset of the first byte.
    pub file_off: u64,
}

/// The result of one `.eh_frame` walk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EhFrame {
    /// The FDEs in record order.
    pub fdes: Vec<Fde>,
    /// The kept diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// The count of diagnostics above [`MAX_DIAGNOSTICS`](crate::diag::MAX_DIAGNOSTICS).
    pub dropped: u64,
}

impl EhFrame {
    fn from_parts(fdes: Vec<Fde>, diags: Diags) -> Self {
        let (diagnostics, dropped) = diags.into_parts();
        Self {
            fdes,
            diagnostics,
            dropped,
        }
    }
}

/// Parses the `.eh_frame` of a loaded ELF file.
///
/// The bytes come from the `.eh_frame` section, else from `PT_GNU_EH_FRAME`.
#[must_use]
pub fn parse(binary: &Binary, map: &MemoryMap, limits: &Limits) -> EhFrame {
    let mut diags = Diags::default();
    let fdes = load(binary, map, limits, &mut diags);
    EhFrame::from_parts(fdes, diags)
}

/// Parses `.eh_frame` bytes at `place`.
///
/// The walk has no memory map, so an indirect pointer gives `E_OOB`.
#[must_use]
pub fn parse_bytes(bytes: &[u8], place: Place, limits: &Limits) -> EhFrame {
    let mut diags = Diags::default();
    let fdes = walk(bytes, place, None, limits, &mut diags);
    EhFrame::from_parts(fdes, diags)
}

/// Gives the FDEs of a loaded ELF file and adds the diagnostics to `diags`.
pub(crate) fn load(
    binary: &Binary,
    map: &MemoryMap,
    limits: &Limits,
    diags: &mut Diags,
) -> Vec<Fde> {
    match source(binary, map, diags) {
        Some((bytes, place)) => walk(bytes, place, Some(map), limits, diags),
        None => Vec::new(),
    }
}

/// The framing of one record.
#[derive(Debug, Clone, Copy)]
struct Record {
    /// The offset of the length field.
    start: usize,
    /// The offset of the ID field.
    id_at: usize,
    /// The CIE ID or the CIE pointer.
    id: u64,
    /// The offset of the first byte after the ID.
    body: usize,
    /// The offset of the next record.
    next: usize,
}

/// The result of one framing step.
enum Frame {
    /// The zero terminator or the end of the bytes.
    End,
    /// A record that runs past the bytes. The walk stops.
    Cut(Diagnostic),
    /// A record that is too short for its ID. The walk goes on at `next`.
    Short(Diagnostic, usize),
    /// A record.
    Record(Record),
}

/// The parsed part of a CIE.
#[derive(Debug, Clone, Copy)]
struct Cie {
    factors: Factors,
    /// The `R` encoding of the FDE pointers.
    fde_enc: u8,
    /// The CIE has `z`, so each FDE has an augmentation length.
    z: bool,
    /// The rule after the initial program, or `None` when the program stopped.
    init: Option<Rule>,
}

/// Gives the diagnostic path of the record at `record`.
fn path(record: usize) -> String {
    format!("elf.eh_frame[{record:#x}]")
}

/// The state of one walk.
struct Walker<'a, 'd> {
    bytes: &'a [u8],
    place: Place,
    mem: Option<&'a MemoryMap>,
    limits: &'a Limits,
    diags: &'d mut Diags,
    /// The parsed CIEs by offset. `None` marks a bad CIE that already gave its diagnostic.
    cies: BTreeMap<usize, Option<Cie>>,
}

/// Walks the records of `bytes` up to the zero terminator or the end of the bytes.
fn walk(
    bytes: &[u8],
    place: Place,
    mem: Option<&MemoryMap>,
    limits: &Limits,
    diags: &mut Diags,
) -> Vec<Fde> {
    let mut w = Walker {
        bytes,
        place,
        mem,
        limits,
        diags,
        cies: BTreeMap::new(),
    };
    let mut fdes = Vec::new();
    let mut off = 0usize;
    loop {
        let rec = match w.frame(off) {
            Frame::End => break,
            Frame::Cut(d) => {
                w.diags.push(d);
                break;
            }
            Frame::Short(d, next) => {
                w.diags.push(d);
                off = next;
                continue;
            }
            Frame::Record(rec) => rec,
        };
        off = rec.next;
        if rec.id == 0 {
            w.cie(rec);
            continue;
        }
        if u64::try_from(fdes.len()).unwrap_or(u64::MAX) >= w.limits.fdes {
            let d = Diagnostic::new(DiagCode::Limit, path(rec.start))
                .at(w.file_off(rec.start))
                .have(w.limits.fdes);
            w.diags.push(d);
            break;
        }
        match w.fde(rec) {
            Ok(Some(fde)) => fdes.push(fde),
            Ok(None) => {}
            Err(d) => w.diags.push(d),
        }
    }
    fdes
}

impl<'a> Walker<'a, '_> {
    fn file_off(&self, at: usize) -> u64 {
        let at = u64::try_from(at).unwrap_or(u64::MAX);
        self.place.file_off.saturating_add(at)
    }

    /// Reads the length and the ID of the record at `off`.
    fn frame(&self, off: usize) -> Frame {
        if off >= self.bytes.len() {
            return Frame::End;
        }
        let mut r = Reader::new(self.bytes, Endian::Little);
        let cut = |need: u64| {
            let have = self.bytes.len().saturating_sub(off);
            Frame::Cut(
                Diagnostic::new(DiagCode::Oob, path(off))
                    .at(self.file_off(off))
                    .need(need)
                    .have(u64::try_from(have).unwrap_or(u64::MAX))
                    .hint("the record runs past the data"),
            )
        };
        if r.seek(off).is_err() {
            return Frame::End;
        }
        let Ok(len32) = r.u32() else {
            return cut(4);
        };
        // In `.eh_frame` the ID has 4 bytes after both length forms (LSB).
        let id_size = 4;
        let len = match len32 {
            0 => return Frame::End,
            0xffff_ffff => match r.u64() {
                Ok(len) => len,
                Err(_) => return cut(12),
            },
            other => u64::from(other),
        };
        let id_at = r.pos();
        let next = usize::try_from(len)
            .ok()
            .and_then(|l| id_at.checked_add(l))
            .filter(|n| *n <= self.bytes.len());
        let Some(next) = next else {
            return cut(len);
        };
        if len < id_size {
            let d = Diagnostic::new(DiagCode::Oob, path(off))
                .at(self.file_off(off))
                .need(id_size)
                .have(len)
                .hint("the record is shorter than its ID");
            return Frame::Short(d, next);
        }
        let id = u64::from(r.u32().unwrap_or(u32::MAX));
        Frame::Record(Record {
            start: off,
            id_at,
            id,
            body: r.pos(),
            next,
        })
    }

    /// The bytes of a record after its ID, and a reader over them.
    fn body(&self, rec: Record) -> (Reader<'a>, Bases) {
        let body = self.bytes.get(rec.body..rec.next).unwrap_or_default();
        let at = u64::try_from(rec.body).unwrap_or(u64::MAX);
        let bases = Bases {
            start: self.place.va.saturating_add(at),
            data: 0,
        };
        (Reader::new(body, Endian::Little), bases)
    }

    /// Parses the CIE `rec` once and keeps it in the cache.
    fn cie(&mut self, rec: Record) -> Option<Cie> {
        if let Some(cached) = self.cies.get(&rec.id_at) {
            return *cached;
        }
        let parsed = match self.parse_cie(rec) {
            Ok(cie) => Some(cie),
            Err(d) => {
                self.diags.push(d.at(self.file_off(rec.start)));
                None
            }
        };
        self.cies.insert(rec.id_at, parsed);
        parsed
    }

    fn parse_cie(&mut self, rec: Record) -> Result<Cie, Diagnostic> {
        let path = path(rec.start);
        let (mut r, bases) = self.body(rec);
        let oob = |hint| Diagnostic::new(DiagCode::Oob, path.clone()).hint(hint);
        let magic = |hint, have| {
            Diagnostic::new(DiagCode::BadMagic, path.clone())
                .have(have)
                .hint(hint)
        };
        let version = r.u8().map_err(|_| oob("the CIE has no version"))?;
        if !matches!(version, 1 | 3 | 4) {
            return Err(magic(
                "the CIE version is not 1, 3 or 4",
                u64::from(version),
            ));
        }
        let aug = r
            .cstr(64)
            .map_err(|_| oob("the CIE augmentation has no end"))?;
        if version == 4 {
            r.skip(2).map_err(|_| oob("the CIE ends in its header"))?;
        }
        let code = r.uleb128().map_err(|_| oob("the CIE ends in its header"))?;
        let data = r.sleb128().map_err(|_| oob("the CIE ends in its header"))?;
        let ra = if version == 1 {
            r.u8().map(u64::from)
        } else {
            r.uleb128()
        };
        ra.map_err(|_| oob("the CIE ends in its header"))?;
        let mut fde_enc = 0u8;
        let z = aug.first() == Some(&b'z');
        if z {
            let len = r
                .uleb128()
                .map_err(|_| oob("the CIE ends in its augmentation"))?;
            let end = usize::try_from(len)
                .ok()
                .and_then(|l| r.pos().checked_add(l))
                .filter(|e| *e <= r.pos().saturating_add(r.remaining()))
                .ok_or_else(|| oob("the augmentation data runs past the CIE"))?;
            for c in aug.iter().skip(1) {
                match c {
                    b'R' | b'L' => {
                        let enc = r
                            .u8()
                            .map_err(|_| oob("the CIE ends in its augmentation"))?;
                        if *c == b'R' {
                            fde_enc = enc;
                        }
                    }
                    b'P' => {
                        let enc = r
                            .u8()
                            .map_err(|_| oob("the CIE ends in its augmentation"))?;
                        // The walk reads the personality pointer and does not follow it.
                        read_pointer(&mut r, enc & 0x7f, bases, None).map_err(|e| {
                            Diagnostic::new(e.code(), path.clone())
                                .hint("the personality pointer is not valid")
                        })?;
                    }
                    b'S' | b'B' | b'G' => {}
                    _ => break,
                }
            }
            r.seek(end)
                .map_err(|_| oob("the augmentation data runs past the CIE"))?;
        } else if !aug.is_empty() {
            return Err(magic("the CIE augmentation is not supported", 0));
        }
        if fde_enc == 0xff || !pointer::supported(fde_enc) {
            return Err(magic(
                "the FDE pointer encoding is not supported",
                u64::from(fde_enc),
            ));
        }
        let factors = Factors { code, data };
        let program_at = rec.body.saturating_add(r.pos());
        let init = match cfa::run(
            r.rest(),
            factors,
            0,
            None,
            Rule::default(),
            self.limits.cfa_insns_per_fde,
        ) {
            Ok(run) => Some(run.rule),
            Err(stop) => {
                self.stopped(rec.start, program_at, stop);
                None
            }
        };
        Ok(Cie {
            factors,
            fde_enc,
            z,
            init,
        })
    }

    /// Adds the diagnostic of a stopped CFA program at offset `program_at`.
    fn stopped(&mut self, record: usize, program_at: usize, stop: cfa::Stop) {
        let at = program_at.saturating_add(stop.at);
        let d = Diagnostic::new(stop.code, format!("{}.cfa", path(record)))
            .at(self.file_off(at))
            .have(u64::from(stop.opcode))
            .hint(stop.hint);
        self.diags.push(d);
    }

    /// Finds the CIE of an FDE through its backward pointer.
    fn cie_of(&mut self, rec: Record) -> Result<Option<(usize, Cie)>, Diagnostic> {
        let path = path(rec.start);
        let at = usize::try_from(rec.id)
            .ok()
            .and_then(|p| rec.id_at.checked_sub(p))
            .ok_or_else(|| {
                Diagnostic::new(DiagCode::Oob, path.clone())
                    .need(rec.id)
                    .hint("the CIE pointer is before the data")
            })?;
        let not_cie = || {
            Diagnostic::new(DiagCode::BadMagic, path.clone())
                .need(0)
                .hint("the CIE pointer does not name a CIE")
        };
        match self.frame(at) {
            Frame::Record(cie) if cie.id == 0 => Ok(self.cie(cie).map(|c| (at, c))),
            _ => Err(not_cie()),
        }
    }

    /// Parses the FDE `rec`. A PC range of 0 gives `None`.
    fn fde(&mut self, rec: Record) -> Result<Option<Fde>, Diagnostic> {
        let record = rec.start;
        let path = path(record);
        let file_off = self.file_off(record);
        let Some((cie_at, cie)) = self.cie_of(rec).map_err(|d| d.at(file_off))? else {
            return Ok(None);
        };
        let (mut r, bases) = self.body(rec);
        let bad = |e: PointerError| {
            Diagnostic::new(e.code(), path.clone())
                .at(file_off)
                .hint("the FDE PC range is not valid")
        };
        let begin = read_pointer(&mut r, cie.fde_enc, bases, self.mem)
            .map_err(bad)?
            .ok_or_else(|| bad(PointerError::Encoding(cie.fde_enc)))?;
        let len = pointer::read_value(&mut r, cie.fde_enc).map_err(bad)?;
        if cie.z {
            let aug = r.uleb128().map_err(|_| bad(PointerError::Eof))?;
            let aug = usize::try_from(aug).map_err(|_| bad(PointerError::Eof))?;
            r.skip(aug).map_err(|_| bad(PointerError::Eof))?;
        }
        if len == 0 {
            return Ok(None);
        }
        let range = Range::with_len(begin, len).ok_or_else(|| {
            Diagnostic::new(DiagCode::Overflow, path.clone())
                .at(file_off)
                .need(len)
                .hint("the FDE PC range goes past the 64-bit space")
        })?;
        let program_at = rec.body.saturating_add(r.pos());
        let cfa_rows = match cie.init {
            None => Vec::new(),
            Some(init) => {
                let end = range.last.checked_add(1);
                let max = self.limits.cfa_insns_per_fde;
                match cfa::run(r.rest(), cie.factors, begin, end, init, max) {
                    Ok(run) => run.rows,
                    Err(stop) => {
                        self.stopped(record, program_at, stop);
                        Vec::new()
                    }
                }
            }
        };
        let cie_off = u64::try_from(cie_at).unwrap_or(u64::MAX);
        Ok(Some(Fde {
            range,
            cie: self.place.file_off.saturating_add(cie_off),
            cfa_rows,
        }))
    }
}

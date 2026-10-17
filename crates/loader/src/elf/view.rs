//! The parse context of one ELF load: file bytes, diagnostics, caps and checked views.

use ghidorah_base::{BinText, DiagCode};

use crate::diag::{Diagnostic, Diags};
use crate::limits::Budget;
use crate::memmap::MemoryMap;

/// The state of one ELF load.
pub(crate) struct Cx<'a> {
    /// The file bytes.
    pub(crate) bytes: &'a [u8],
    /// The diagnostics.
    pub(crate) diags: Diags,
    /// The caps and counters.
    pub(crate) budget: Budget,
}

impl<'a> Cx<'a> {
    /// Adds a diagnostic.
    pub(crate) fn diag(&mut self, diag: Diagnostic) {
        self.diags.push(diag);
    }

    /// Gives the file length.
    pub(crate) fn len(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    /// Gives the file bytes `[off, off + size)`, cut at the end of the file.
    ///
    /// An end past `u64::MAX` gives `E_OVERFLOW` and `None`. A start past the end of the
    /// file gives `E_OOB` and `None`. An end past the file gives `E_OOB` and the bytes up
    /// to the end of the file.
    pub(crate) fn file_range(&mut self, off: u64, size: u64, path: &str) -> Option<&'a [u8]> {
        let Some(end) = off.checked_add(size) else {
            self.diag(Diagnostic::new(DiagCode::Overflow, path).at(off).need(size));
            return None;
        };
        let len = self.len();
        if off > len {
            self.diag(
                Diagnostic::new(DiagCode::Oob, path)
                    .at(off)
                    .need(size)
                    .have(0),
            );
            return None;
        }
        if end > len {
            self.diag(
                Diagnostic::new(DiagCode::Oob, path)
                    .at(off)
                    .need(size)
                    .have(len.saturating_sub(off)),
            );
        }
        let start = usize::try_from(off).ok()?;
        let stop = usize::try_from(end.min(len)).ok()?;
        self.bytes.get(start..stop)
    }

    /// Copies `bytes` into a [`BinText`] under the text cap. Above the cap, the text is empty.
    pub(crate) fn text(&mut self, bytes: &[u8], path: &str) -> BinText {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.budget.take_text(size, path, &mut self.diags) {
            BinText::new(bytes)
        } else {
            BinText::default()
        }
    }
}

/// Gives the file bytes at `va` up to `max_len` bytes, inside the file part of one region.
///
/// The result is `None` when `va` is in no region or in a zero tail. The second value
/// tells if the region gives fewer than `max_len` bytes.
pub(crate) fn va_bytes<'a>(
    map: &MemoryMap,
    bytes: &'a [u8],
    va: u64,
    max_len: u64,
) -> Option<(&'a [u8], bool)> {
    let region = map.region_at(va)?;
    let off = map.va_to_file(va)?;
    let into = va.checked_sub(region.va.first)?;
    let avail = region.file_size.checked_sub(into)?;
    let len = avail.min(max_len);
    let start = usize::try_from(off).ok()?;
    let stop = usize::try_from(off.checked_add(len)?).ok()?;
    Some((bytes.get(start..stop)?, len < max_len))
}

/// A string table with the diagnostics of its reads.
pub(crate) struct StrTab<'a> {
    bytes: &'a [u8],
    path: String,
    told: bool,
}

impl<'a> StrTab<'a> {
    /// Makes a table over `bytes`.
    pub(crate) fn new(bytes: &'a [u8], path: impl Into<String>) -> Self {
        Self {
            bytes,
            path: path.into(),
            told: false,
        }
    }

    /// Makes a table with no bytes that gives no diagnostic.
    pub(crate) fn none() -> Self {
        Self {
            bytes: &[],
            path: String::new(),
            told: true,
        }
    }

    fn tell(&mut self, cx: &mut Cx<'_>, diag: Diagnostic) {
        if !self.told {
            self.told = true;
            cx.diag(diag);
        }
    }

    /// Gives the C string at `off`, without its NUL byte.
    ///
    /// A string longer than the string limit gets cut with `E_LIMIT`. A start past the
    /// table or a string with no NUL byte gives `E_OOB`. The table tells each problem once.
    pub(crate) fn get(&mut self, cx: &mut Cx<'_>, off: u64) -> BinText {
        let raw = self.raw(cx, off);
        let path = self.path.clone();
        cx.text(raw, &path)
    }

    /// Gives the bytes of the C string at `off` without a copy.
    pub(crate) fn raw(&mut self, cx: &mut Cx<'_>, off: u64) -> &'a [u8] {
        let table_len = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
        let rest = usize::try_from(off)
            .ok()
            .and_then(|at| self.bytes.get(at..));
        let Some(rest) = rest else {
            let d = Diagnostic::new(DiagCode::Oob, self.path.clone())
                .at(off)
                .have(table_len);
            self.tell(cx, d);
            return &[];
        };
        let limit = usize::try_from(cx.budget.limits.string_len).unwrap_or(usize::MAX);
        let window = rest.get(..limit.saturating_add(1)).unwrap_or(rest);
        if let Some(end) = window.iter().position(|b| *b == 0) {
            return window.get(..end).unwrap_or_default();
        }
        if rest.len() > limit {
            let d = Diagnostic::new(DiagCode::Limit, self.path.clone())
                .at(off)
                .have(cx.budget.limits.string_len);
            self.tell(cx, d);
            return rest.get(..limit).unwrap_or_default();
        }
        let d = Diagnostic::new(DiagCode::Oob, self.path.clone())
            .at(off)
            .hint("the string has no NUL byte");
        self.tell(cx, d);
        rest
    }
}

/// Reads fixed-width little-endian fields from one table entry.
pub(crate) struct Fields<'a> {
    reader: ghidorah_kernel::Reader<'a>,
}

impl<'a> Fields<'a> {
    /// Makes a field reader over the entry bytes.
    pub(crate) fn new(entry: &'a [u8]) -> Self {
        Self {
            reader: ghidorah_kernel::Reader::new(entry, ghidorah_kernel::Endian::Little),
        }
    }

    /// Reads a `u8`. A short entry gives 0.
    pub(crate) fn u8(&mut self) -> u8 {
        self.reader.u8().unwrap_or(0)
    }

    /// Reads a `u16`. A short entry gives 0.
    pub(crate) fn u16(&mut self) -> u16 {
        self.reader.u16().unwrap_or(0)
    }

    /// Reads a `u32`. A short entry gives 0.
    pub(crate) fn u32(&mut self) -> u32 {
        self.reader.u32().unwrap_or(0)
    }

    /// Reads a `u64`. A short entry gives 0.
    pub(crate) fn u64(&mut self) -> u64 {
        self.reader.u64().unwrap_or(0)
    }
}

/// Gives entry `index` of a table with entries of `entsize` bytes, or `None` past the table.
pub(crate) fn entry(table: &[u8], index: usize, entsize: usize) -> Option<&[u8]> {
    let start = index.checked_mul(entsize)?;
    let end = start.checked_add(entsize)?;
    table.get(start..end)
}

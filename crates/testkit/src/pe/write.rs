//! The layout and the bytes of a [`PeBuilder`] file.
//!
//! The headers come first. The user sections follow in list order at file offsets that are
//! multiples of 0x200. The generated section `.gen` comes last, at the first page after the
//! user sections.

use super::{
    CodeView, ExportItem, Exports, Layout, MAGIC_PE32, PeBuilder, RtFunc, SCN_RDATA, Thunk, Unwind,
};

/// The file alignment of the builder.
const FILE_ALIGN: u32 = 0x200;

/// The section alignment of the builder.
const SECTION_ALIGN: u32 = 0x1000;

/// The offset of the PE signature (`e_lfanew`).
const LFANEW: usize = 0x40;

/// The `CHAININFO` flag of unwind data.
const UNW_FLAG_CHAININFO: u8 = 4;

/// Rounds `v` up to a multiple of `a`.
fn up(v: u32, a: u32) -> u32 {
    v.div_ceil(a).saturating_mul(a)
}

/// Gives a length as `u32`.
fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Gives a `u32` as an index.
fn at(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// A file buffer with little-endian writes at offsets. A write past the end grows the buffer.
#[derive(Default)]
struct Buf(Vec<u8>);

impl Buf {
    fn put(&mut self, offset: usize, bytes: &[u8]) {
        let end = offset.saturating_add(bytes.len());
        if self.0.len() < end {
            self.0.resize(end, 0);
        }
        if let Some(place) = self.0.get_mut(offset..end) {
            place.copy_from_slice(bytes);
        }
    }

    fn u16(&mut self, offset: usize, v: u16) {
        self.put(offset, &v.to_le_bytes());
    }

    fn u32(&mut self, offset: usize, v: u32) {
        self.put(offset, &v.to_le_bytes());
    }

    fn u64(&mut self, offset: usize, v: u64) {
        self.put(offset, &v.to_le_bytes());
    }
}

/// The generated section under construction.
struct Gen {
    rva: u32,
    file_off: u32,
    buf: Buf,
}

impl Gen {
    /// Gives the RVA of the next byte.
    fn here(&self) -> u32 {
        self.rva.saturating_add(len32(self.buf.0.len()))
    }

    fn align(&mut self, a: usize) {
        while !self.buf.0.len().is_multiple_of(a) {
            self.buf.0.push(0);
        }
    }

    fn reserve(&mut self, n: usize) -> u32 {
        let rva = self.here();
        let len = self.buf.0.len().saturating_add(n);
        self.buf.0.resize(len, 0);
        rva
    }

    fn push(&mut self, bytes: &[u8]) -> u32 {
        let rva = self.here();
        self.buf.0.extend_from_slice(bytes);
        rva
    }

    fn cstr(&mut self, text: &str) -> u32 {
        let rva = self.push(text.as_bytes());
        self.buf.0.push(0);
        rva
    }

    fn off(&self, rva: u32) -> usize {
        at(rva.saturating_sub(self.rva))
    }

    fn set_u16(&mut self, rva: u32, v: u16) {
        let o = self.off(rva);
        self.buf.u16(o, v);
    }

    fn set_u32(&mut self, rva: u32, v: u32) {
        let o = self.off(rva);
        self.buf.u32(o, v);
    }

    fn set_u64(&mut self, rva: u32, v: u64) {
        let o = self.off(rva);
        self.buf.u64(o, v);
    }

    /// Writes the hint-name entry of a name thunk and gives the lookup value.
    fn thunk(&mut self, t: &Thunk) -> (u64, bool) {
        match t {
            Thunk::Ordinal(o) => ((1 << 63) | u64::from(*o), true),
            Thunk::Name { hint, name } => {
                self.align(2);
                let rva = self.push(&hint.to_le_bytes());
                self.cstr(name);
                (u64::from(rva), false)
            }
        }
    }
}

/// Writes the import descriptors and their tables.
fn imports(b: &PeBuilder, g: &mut Gen, out: &mut Layout) {
    if b.imports.is_empty() {
        return;
    }
    let count = b.imports.len().saturating_add(1);
    let desc = g.reserve(20usize.saturating_mul(count));
    let mut tables = Vec::new();
    for dll in &b.imports {
        g.align(8);
        let slots = dll.thunks.len().saturating_add(1).saturating_mul(8);
        let ilt = if dll.null_ilt { 0 } else { g.reserve(slots) };
        let iat = g.reserve(slots);
        tables.push((ilt, iat));
        out.iat.push(
            (0..dll.thunks.len())
                .map(|i| iat.saturating_add(len32(i).saturating_mul(8)))
                .collect(),
        );
    }
    for (i, (dll, (ilt, iat))) in b.imports.iter().zip(tables).enumerate() {
        let name = g.cstr(&dll.name);
        for (j, t) in dll.thunks.iter().enumerate() {
            let (value, _) = g.thunk(t);
            let slot = len32(j).saturating_mul(8);
            if ilt != 0 {
                g.set_u64(ilt.saturating_add(slot), value);
            }
            let bound = b
                .image_base
                .saturating_add(0x7000_0000)
                .saturating_add(u64::from(slot) * 2);
            g.set_u64(
                iat.saturating_add(slot),
                if dll.bound { bound } else { value },
            );
        }
        let d = desc.saturating_add(len32(i).saturating_mul(20));
        g.set_u32(d, ilt);
        g.set_u32(d.saturating_add(4), if dll.bound { u32::MAX } else { 0 });
        g.set_u32(d.saturating_add(12), name);
        g.set_u32(d.saturating_add(16), iat);
    }
    out.dirs.push((1, desc, len32(count).saturating_mul(20)));
}

/// Writes the delay import descriptors and their tables.
fn delay(b: &PeBuilder, g: &mut Gen, out: &mut Layout) {
    if b.delay.is_empty() {
        return;
    }
    let count = b.delay.len().saturating_add(1);
    let desc = g.reserve(32usize.saturating_mul(count));
    let mut tables = Vec::new();
    for dll in &b.delay {
        g.align(8);
        let slots = dll.thunks.len().saturating_add(1).saturating_mul(8);
        let int = g.reserve(slots);
        let iat = g.reserve(slots);
        let handle = g.reserve(8);
        tables.push((int, iat, handle));
        out.delay_iat.push(
            (0..dll.thunks.len())
                .map(|i| iat.saturating_add(len32(i).saturating_mul(8)))
                .collect(),
        );
    }
    let base = b.image_base;
    for (i, (dll, (int, iat, handle))) in b.delay.iter().zip(tables).enumerate() {
        let va = |rva: u32| -> u32 {
            if dll.vc6 {
                u32::try_from(base.saturating_add(u64::from(rva))).unwrap_or(u32::MAX)
            } else {
                rva
            }
        };
        let name = g.cstr(&dll.name);
        for (j, t) in dll.thunks.iter().enumerate() {
            let (value, ordinal) = g.thunk(t);
            let value = if dll.vc6 && !ordinal {
                base.saturating_add(value)
            } else {
                value
            };
            g.set_u64(int.saturating_add(len32(j).saturating_mul(8)), value);
        }
        let d = desc.saturating_add(len32(i).saturating_mul(32));
        g.set_u32(d, u32::from(!dll.vc6));
        g.set_u32(d.saturating_add(4), va(name));
        g.set_u32(d.saturating_add(8), va(handle));
        g.set_u32(d.saturating_add(12), va(iat));
        g.set_u32(d.saturating_add(16), va(int));
    }
    out.dirs.push((13, desc, len32(count).saturating_mul(32)));
}

/// Writes the export directory, its tables and its strings.
fn exports(e: &Exports, g: &mut Gen, out: &mut Layout) {
    g.align(4);
    let dir = g.reserve(40);
    let eat = g.reserve(e.items.len().saturating_mul(4));
    let names = g.reserve(e.names.len().saturating_mul(4));
    let ords = g.reserve(e.names.len().saturating_mul(2));
    let dll = g.cstr(&e.dll);
    for (i, (name, index)) in e.names.iter().enumerate() {
        let rva = g.cstr(name);
        g.set_u32(names.saturating_add(len32(i).saturating_mul(4)), rva);
        g.set_u16(ords.saturating_add(len32(i).saturating_mul(2)), *index);
    }
    for (i, item) in e.items.iter().enumerate() {
        let value = match item {
            ExportItem::Code(rva) => *rva,
            ExportItem::Forward(text) => g.cstr(text),
            ExportItem::Unused => 0,
        };
        g.set_u32(eat.saturating_add(len32(i).saturating_mul(4)), value);
    }
    let end = g.here();
    g.set_u32(dir.saturating_add(12), dll);
    g.set_u32(dir.saturating_add(16), e.base);
    let functions = e
        .number_of_functions
        .unwrap_or_else(|| len32(e.items.len()));
    g.set_u32(dir.saturating_add(20), functions);
    let count = e.number_of_names.unwrap_or_else(|| len32(e.names.len()));
    g.set_u32(dir.saturating_add(24), count);
    g.set_u32(dir.saturating_add(28), eat);
    g.set_u32(dir.saturating_add(32), names);
    g.set_u32(dir.saturating_add(36), ords);
    out.dirs.push((0, dir, end.saturating_sub(dir)));
}

/// Writes the base relocation blocks.
fn relocs(b: &PeBuilder, g: &mut Gen, out: &mut Layout) {
    if b.relocs.is_empty() {
        return;
    }
    g.align(4);
    let start = g.here();
    for block in &b.relocs {
        g.push(&block.page.to_le_bytes());
        let natural = len32(block.entries.len())
            .saturating_mul(2)
            .saturating_add(8);
        g.push(&block.size.unwrap_or(natural).to_le_bytes());
        for e in &block.entries {
            g.push(&e.to_le_bytes());
        }
    }
    out.dirs.push((5, start, g.here().saturating_sub(start)));
}

/// Writes the TLS directory and its callback array.
fn tls(b: &PeBuilder, callbacks: &[u64], g: &mut Gen, out: &mut Layout) {
    g.align(8);
    let dir = g.reserve(40);
    let index = g.reserve(8);
    let array = g.here();
    for cb in callbacks {
        g.push(&cb.to_le_bytes());
    }
    g.push(&0u64.to_le_bytes());
    g.set_u64(
        dir.saturating_add(16),
        b.image_base.saturating_add(u64::from(index)),
    );
    g.set_u64(
        dir.saturating_add(24),
        b.image_base.saturating_add(u64::from(array)),
    );
    out.tls_callbacks = Some(array);
    out.dirs.push((9, dir, 40));
}

/// Writes one `CODEVIEW` debug entry and its `RSDS` record.
fn debug(cv: &CodeView, g: &mut Gen, out: &mut Layout) {
    g.align(4);
    let dir = g.reserve(28);
    let record = g.push(b"RSDS");
    g.push(&cv.guid);
    g.push(&cv.age.to_le_bytes());
    g.cstr(&cv.pdb);
    let size = g.here().saturating_sub(record);
    g.set_u32(dir.saturating_add(12), 2);
    g.set_u32(dir.saturating_add(16), size);
    g.set_u32(dir.saturating_add(20), record);
    let file = g.file_off.saturating_add(record.saturating_sub(g.rva));
    g.set_u32(dir.saturating_add(24), file);
    out.dirs.push((6, dir, 28));
}

/// Writes the unwind data and the `RUNTIME_FUNCTION` table.
fn pdata(entries: &[RtFunc], g: &mut Gen, out: &mut Layout) {
    if entries.is_empty() {
        return;
    }
    g.align(4);
    let unwind: Vec<u32> = entries
        .iter()
        .map(|e| match e.unwind {
            Unwind::Plain => g.reserve(4),
            Unwind::Chain(_) => g.reserve(16),
        })
        .collect();
    for (e, u) in entries.iter().zip(&unwind) {
        let u = *u;
        let o = g.off(u);
        match e.unwind {
            Unwind::Plain => g.buf.put(o, &[1, 0, 0, 0]),
            Unwind::Chain(parent) => {
                g.buf.put(o, &[1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0]);
                let (begin, end) = entries.get(parent).map_or((0, 0), |p| (p.begin, p.end));
                let info = unwind.get(parent).copied().unwrap_or(0);
                g.set_u32(u.saturating_add(4), begin);
                g.set_u32(u.saturating_add(8), end);
                g.set_u32(u.saturating_add(12), info);
            }
        }
    }
    let table = g.here();
    for (e, u) in entries.iter().zip(&unwind) {
        g.push(&e.begin.to_le_bytes());
        g.push(&e.end.to_le_bytes());
        g.push(&u.to_le_bytes());
    }
    out.dirs
        .push((3, table, len32(entries.len()).saturating_mul(12)));
}

/// Tells if the builder has a table for the generated section.
fn has_tables(b: &PeBuilder) -> bool {
    !b.imports.is_empty()
        || !b.delay.is_empty()
        || b.exports.is_some()
        || !b.relocs.is_empty()
        || b.tls.is_some()
        || b.codeview.is_some()
        || !b.pdata.is_empty()
}

/// One placed section: its header values and the data that the file gets.
struct Placed<'a> {
    name: &'a str,
    rva: u32,
    vsize: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
    data: Option<&'a [u8]>,
}

/// Writes the optional header at `o`.
fn optional(b: &PeBuilder, f: &mut Buf, o: usize, size_of_image: u32, size_of_headers: u32) {
    let pe32 = b.magic == MAGIC_PE32;
    f.u16(o, b.magic);
    f.put(o + 2, &[14, 0]);
    f.u32(o + 16, b.entry);
    f.u32(o + 20, SECTION_ALIGN);
    if pe32 {
        f.u32(o + 28, u32::try_from(b.image_base).unwrap_or(u32::MAX));
    } else {
        f.u64(o + 24, b.image_base);
    }
    f.u32(o + 32, SECTION_ALIGN);
    f.u32(o + 36, FILE_ALIGN);
    f.u16(o + 40, 6);
    f.u16(o + 48, 6);
    f.u32(o + 56, size_of_image);
    f.u32(o + 60, size_of_headers);
    f.u16(o + 68, 3);
    f.u16(o + 70, b.dll_characteristics);
    if pe32 {
        f.u32(o + 72, 0x10_0000);
        f.u32(o + 76, 0x1000);
        f.u32(o + 80, 0x10_0000);
        f.u32(o + 84, 0x1000);
        f.u32(o + 92, b.dir_count);
    } else {
        f.u64(o + 72, 0x10_0000);
        f.u64(o + 80, 0x1000);
        f.u64(o + 88, 0x10_0000);
        f.u64(o + 96, 0x1000);
        f.u32(o + 108, b.dir_count);
    }
}

/// Places the user sections in the file after the headers. Gives the placed sections and the
/// first free file offset.
fn place(b: &PeBuilder, headers_end: u32) -> (Vec<Placed<'_>>, u32) {
    let mut cur = headers_end;
    let mut placed = Vec::new();
    for s in &b.sections {
        let (raw_ptr, raw_size, data) = if let Some(p) = s.raw_ptr {
            let size = s.raw_size.unwrap_or_else(|| len32(s.data.len()));
            (p, size, None)
        } else {
            let size = s
                .raw_size
                .unwrap_or_else(|| up(len32(s.data.len()), FILE_ALIGN));
            let room = up(size.max(len32(s.data.len())), FILE_ALIGN);
            let ptr = if room == 0 { 0 } else { cur };
            cur = cur.saturating_add(room);
            (ptr, size, Some(s.data.as_slice()))
        };
        placed.push(Placed {
            name: &s.name,
            rva: s.rva,
            vsize: s.vsize,
            raw_size,
            raw_ptr,
            characteristics: s.characteristics,
            data,
        });
    }
    (placed, cur)
}

/// Writes the tables of the generated section.
fn tables(b: &PeBuilder, g: &mut Gen, layout: &mut Layout) {
    imports(b, g, layout);
    delay(b, g, layout);
    if let Some(e) = &b.exports {
        exports(e, g, layout);
    }
    relocs(b, g, layout);
    if let Some(callbacks) = &b.tls {
        tls(b, callbacks, g, layout);
    }
    if let Some(cv) = &b.codeview {
        debug(cv, g, layout);
    }
    pdata(&b.pdata, g, layout);
}

/// The sizes of the headers.
struct Heads {
    count: usize,
    dirs: u32,
    base_size: u32,
    opt_size: u32,
    size_of_headers: u32,
    size_of_image: u32,
}

/// Writes the DOS header, the PE signature, the COFF header, the optional header, the data
/// directories and the section table.
fn headers(b: &PeBuilder, h: &Heads, layout: &Layout, placed: &[Placed<'_>], f: &mut Buf) {
    f.put(0, b"MZ");
    f.u32(0x3c, len32(LFANEW));
    f.put(LFANEW, if b.signature { b"PE\0\0" } else { &[0; 4] });
    let coff = LFANEW + 4;
    f.u16(coff, b.machine);
    f.u16(coff + 2, u16::try_from(h.count).unwrap_or(u16::MAX));
    f.u16(coff + 16, u16::try_from(h.opt_size).unwrap_or(u16::MAX));
    f.u16(coff + 18, b.characteristics);
    let opt = coff + 20;
    optional(b, f, opt, h.size_of_image, h.size_of_headers);
    let dir_at = opt + at(h.base_size);
    for (index, rva, size) in layout.dirs.iter().chain(&b.dirs) {
        if u32::from(*index) < h.dirs {
            let o = dir_at + usize::from(*index) * 8;
            f.u32(o, *rva);
            f.u32(o + 4, *size);
        }
    }
    let mut sh = opt + at(h.opt_size);
    for p in placed {
        let mut name = [0u8; 8];
        for (d, s) in name.iter_mut().zip(p.name.bytes()) {
            *d = s;
        }
        f.put(sh, &name);
        f.u32(sh + 8, p.vsize);
        f.u32(sh + 12, p.rva);
        f.u32(sh + 16, p.raw_size);
        f.u32(sh + 20, p.raw_ptr);
        f.u32(sh + 36, p.characteristics);
        sh += 40;
    }
}

/// Writes the file and gives its layout.
pub(super) fn write(b: &PeBuilder) -> (Vec<u8>, Layout) {
    let mut layout = Layout::default();
    let user_end = b
        .sections
        .iter()
        .map(|s| s.rva.saturating_add(s.vsize.max(len32(s.data.len()))))
        .max()
        .unwrap_or(0);
    let with_tables = has_tables(b);
    let count = b.sections.len().saturating_add(usize::from(with_tables));
    let dirs = b.dir_count.min(16);
    let base_size: u32 = if b.magic == MAGIC_PE32 { 96 } else { 112 };
    let opt_size = base_size.saturating_add(dirs.saturating_mul(8));
    let header_end = len32(LFANEW + 24)
        .saturating_add(opt_size)
        .saturating_add(len32(count).saturating_mul(40));
    let size_of_headers = b
        .size_of_headers
        .unwrap_or_else(|| up(header_end, FILE_ALIGN));
    let (mut placed, mut cur) = place(b, up(size_of_headers.max(header_end), FILE_ALIGN));
    let gen_rva = up(user_end, SECTION_ALIGN).max(SECTION_ALIGN);
    let mut g = Gen {
        rva: gen_rva,
        file_off: cur,
        buf: Buf::default(),
    };
    tables(b, &mut g, &mut layout);
    let gen_bytes = std::mem::take(&mut g.buf.0);
    let gen_len = len32(gen_bytes.len());
    let mut image_end = user_end;
    if with_tables {
        placed.push(Placed {
            name: ".gen",
            rva: gen_rva,
            vsize: gen_len,
            raw_size: up(gen_len, FILE_ALIGN),
            raw_ptr: g.file_off,
            characteristics: SCN_RDATA,
            data: Some(&gen_bytes),
        });
        layout.gen_rva = gen_rva;
        cur = cur.saturating_add(up(gen_len, FILE_ALIGN));
        image_end = image_end.max(gen_rva.saturating_add(gen_len));
    }
    let heads = Heads {
        count,
        dirs,
        base_size,
        opt_size,
        size_of_headers,
        size_of_image: up(image_end, SECTION_ALIGN).max(SECTION_ALIGN),
    };
    let mut f = Buf::default();
    headers(b, &heads, &layout, &placed, &mut f);
    for p in &placed {
        if let Some(data) = p.data {
            f.put(at(p.raw_ptr), data);
        }
    }
    if f.0.len() < at(cur) {
        f.0.resize(at(cur), 0);
    }
    for (offset, bytes) in &b.patches {
        f.put(*offset, bytes);
    }
    layout.dirs.extend(b.dirs.iter().copied());
    layout.file_len = f.0.len();
    (f.0, layout)
}

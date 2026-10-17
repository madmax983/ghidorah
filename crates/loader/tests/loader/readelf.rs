//! A `readelf -W` renderer of the `Binary` model and a parser of the readelf goldens.
//!
//! The renderer writes the rows of the section headers, program headers, dynamic
//! entries, relocations and symbol tables in the format of binutils 2.42. The parser
//! takes the same rows from a golden file. Two equal row lists mean equal tables.

use std::fmt::Write as _;

use ghidorah_loader::{
    Binary, Reloc, RelocSource, Section, SectionKind, Segment, SegmentKind, Sym, SymBind, SymKind,
    SymTable, SymVis,
};

/// The rows of one readelf output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Blocks {
    /// The section header rows.
    pub sections: Vec<String>,
    /// The program header rows.
    pub segments: Vec<String>,
    /// The dynamic entry rows.
    pub dynamic: Vec<String>,
    /// The relocation sections: name and rows.
    pub relocs: Vec<(String, Vec<String>)>,
    /// The dynamic-view relocation tables of `readelf -D -r`: label and rows.
    pub dynrel: Vec<(String, Vec<String>)>,
    /// The symbol tables: name and rows.
    pub symtabs: Vec<(String, Vec<String>)>,
    /// The entry point text, for example `0x1090`.
    pub entry: Option<String>,
    /// The type word of the file header: `EXEC` or `DYN`.
    pub e_type: Option<String>,
    /// The build ID in hex.
    pub build_id: Option<String>,
}

/// The name between the first pair of single quotes of `line`.
fn quoted(line: &str) -> String {
    line.split('\'').nth(1).unwrap_or_default().to_string()
}

/// Takes the rows that follow a table title, up to the first empty line.
fn rows<'a>(lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(line) = lines.next_if(|l| !l.is_empty()) {
        out.push(line.to_string());
    }
    out
}

/// Parses the body of a `readelf -W -h -l -S -s -d -r -n` golden.
pub fn parse_golden(text: &str) -> Blocks {
    let mut b = Blocks::default();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line == "Section Headers:" {
            lines.next();
            while let Some(row) = lines.next_if(|l| l.starts_with("  [")) {
                b.sections.push(row.to_string());
            }
        } else if line == "Program Headers:" {
            lines.next();
            b.segments = rows(&mut lines)
                .into_iter()
                .filter(|r| !r.trim_start().starts_with("[Requesting"))
                .collect();
        } else if line.starts_with("Dynamic section at offset") {
            lines.next();
            b.dynamic = rows(&mut lines);
        } else if line.starts_with("Relocation section '") {
            lines.next();
            b.relocs.push((quoted(line), rows(&mut lines)));
        } else if line.starts_with("Symbol table '") {
            lines.next();
            b.symtabs.push((quoted(line), rows(&mut lines)));
        } else if let Some(v) = line.strip_prefix("  Entry point address:") {
            b.entry = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("  Type:") {
            b.e_type = v.split_whitespace().next().map(ToString::to_string);
        } else if let Some((_, id)) = line.split_once("Build ID: ") {
            b.build_id = Some(id.trim().to_string());
        }
    }
    b
}

/// Parses the body of a `readelf -W -D -r` golden.
pub fn parse_dynrel(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.starts_with('\'') && line.contains("relocation section") {
            lines.next();
            out.push((quoted(line), rows(&mut lines)));
        }
    }
    out
}

fn section_type(kind: SectionKind) -> String {
    let SectionKind::Elf(t) = kind else {
        return "PE".to_string();
    };
    let name = match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB SECTION INDICES",
        19 => "RELR",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fffd => "VERDEF",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERSYM",
        0x7000_0001 => "X86_64_UNWIND",
        other => return format!("{other:08x}: <unknown>"),
    };
    name.to_string()
}

fn section_flags(flags: u64) -> String {
    const LETTERS: [(u64, char); 13] = [
        (0x1, 'W'),
        (0x2, 'A'),
        (0x4, 'X'),
        (0x10, 'M'),
        (0x20, 'S'),
        (0x40, 'I'),
        (0x80, 'L'),
        (0x100, 'O'),
        (0x200, 'G'),
        (0x400, 'T'),
        (0x800, 'C'),
        (0x1000_0000, 'l'),
        (0x8000_0000, 'E'),
    ];
    LETTERS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, c)| *c)
        .collect()
}

/// Escapes a name as readelf does for control characters.
fn printable(bytes: &[u8]) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(bytes).chars() {
        if c.is_ascii_control() {
            out.push('^');
            out.push(char::from(u8::try_from(c).unwrap_or(0).wrapping_add(0x40)));
        } else {
            out.push(c);
        }
    }
    out
}

fn section_row(s: &Section) -> String {
    format!(
        "  [{:>2}] {:<17} {:<15} {:016x} {:06x} {:06x} {:02x} {:>3} {:>2} {:>3} {:>2}",
        s.index,
        printable(s.name.as_bytes()),
        section_type(s.kind),
        s.addr,
        s.file_off,
        s.size,
        s.entsize,
        section_flags(s.flags),
        s.link,
        s.info,
        s.align
    )
}

fn segment_type(kind: SegmentKind) -> String {
    let SegmentKind::Elf(t) = kind else {
        return format!("{kind:?}");
    };
    let name = match t {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        0x6474_e554 => "GNU_SFRAME",
        other => return format!("LOOS+0x{other:x}"),
    };
    name.to_string()
}

fn segment_row(s: &Segment) -> String {
    let bit = |b: u32, c: char| if s.flags & b != 0 { c } else { ' ' };
    let align = if s.align == 0 {
        "0".to_string()
    } else {
        format!("{:#x}", s.align)
    };
    format!(
        "  {:<14} 0x{:06x} 0x{:016x} 0x{:016x} 0x{:06x} 0x{:06x} {}{}{} {align}",
        segment_type(s.kind),
        s.file_off,
        s.vaddr,
        s.paddr,
        s.file_size,
        s.mem_size,
        bit(4, 'R'),
        bit(2, 'W'),
        bit(1, 'E')
    )
}

fn dyn_tag_name(tag: u64) -> String {
    let name = match tag {
        0 => "NULL",
        1 => "NEEDED",
        2 => "PLTRELSZ",
        3 => "PLTGOT",
        4 => "HASH",
        5 => "STRTAB",
        6 => "SYMTAB",
        7 => "RELA",
        8 => "RELASZ",
        9 => "RELAENT",
        10 => "STRSZ",
        11 => "SYMENT",
        12 => "INIT",
        13 => "FINI",
        14 => "SONAME",
        15 => "RPATH",
        16 => "SYMBOLIC",
        17 => "REL",
        18 => "RELSZ",
        19 => "RELENT",
        20 => "PLTREL",
        21 => "DEBUG",
        22 => "TEXTREL",
        23 => "JMPREL",
        24 => "BIND_NOW",
        25 => "INIT_ARRAY",
        26 => "FINI_ARRAY",
        27 => "INIT_ARRAYSZ",
        28 => "FINI_ARRAYSZ",
        29 => "RUNPATH",
        30 => "FLAGS",
        32 => "PREINIT_ARRAY",
        33 => "PREINIT_ARRAYSZ",
        35 => "RELRSZ",
        36 => "RELR",
        37 => "RELRENT",
        0x6fff_fef5 => "GNU_HASH",
        0x6fff_fff0 => "VERSYM",
        0x6fff_fff9 => "RELACOUNT",
        0x6fff_fffa => "RELCOUNT",
        0x6fff_fffb => "FLAGS_1",
        0x6fff_fffc => "VERDEF",
        0x6fff_fffd => "VERDEFNUM",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERNEEDNUM",
        other => return format!("<unknown>: {other:x}"),
    };
    name.to_string()
}

fn dt_flags(val: u64) -> String {
    let names = [
        (0x1, "ORIGIN"),
        (0x2, "SYMBOLIC"),
        (0x4, "TEXTREL"),
        (0x8, "BIND_NOW"),
        (0x10, "STATIC_TLS"),
    ];
    let mut out: Vec<&str> = Vec::new();
    for bit in (0..64).map(|i| 1u64 << i).filter(|b| val & b != 0) {
        out.push(names.iter().find(|n| n.0 == bit).map_or("unknown", |n| n.1));
    }
    out.join(" ")
}

fn dt_flags_1(val: u64) -> String {
    let names = [
        (0x1, "NOW"),
        (0x2, "GLOBAL"),
        (0x4, "GROUP"),
        (0x8, "NODELETE"),
        (0x10, "LOADFLTR"),
        (0x20, "INITFIRST"),
        (0x40, "NOOPEN"),
        (0x80, "ORIGIN"),
        (0x100, "DIRECT"),
        (0x200, "TRANS"),
        (0x400, "INTERPOSE"),
        (0x800, "NODEFLIB"),
        (0x1000, "NODUMP"),
        (0x2000, "CONFALT"),
        (0x4000, "ENDFILTEE"),
        (0x8000, "DISPRELDNE"),
        (0x1_0000, "DISPRELPND"),
        (0x2_0000, "NODIRECT"),
        (0x4_0000, "IGNMULDEF"),
        (0x8_0000, "NOKSYMS"),
        (0x10_0000, "NOHDR"),
        (0x20_0000, "EDITED"),
        (0x40_0000, "NORELOC"),
        (0x80_0000, "SYMINTPOSE"),
        (0x100_0000, "GLOBAUDIT"),
        (0x200_0000, "SINGLETON"),
        (0x400_0000, "STUB"),
        (0x800_0000, "PIE"),
    ];
    let mut out = String::from("Flags:");
    for (bit, name) in names {
        if val & bit != 0 {
            out.push(' ');
            out.push_str(name);
        }
    }
    out
}

fn text(t: Option<&ghidorah_base::BinText>) -> String {
    t.map_or_else(String::new, |t| printable(t.as_bytes()))
}

fn dynamic_rows(b: &Binary) -> Vec<String> {
    let mut needed = b.libraries.iter();
    let mut out = Vec::new();
    for e in &b.dynamic {
        let name = dyn_tag_name(e.tag);
        let value = match e.tag {
            1 => format!("Shared library: [{}]", text(needed.next())),
            14 => format!("Library soname: [{}]", text(b.identity.soname.as_ref())),
            15 => format!("Library rpath: [{}]", text(b.rpath.as_ref())),
            29 => format!("Library runpath: [{}]", text(b.runpath.as_ref())),
            30 => dt_flags(e.val),
            0x6fff_fffb => dt_flags_1(e.val),
            20 => dyn_tag_name(e.val),
            2 | 8 | 9 | 10 | 11 | 18 | 19 | 27 | 28 | 33 | 35 | 37 => format!("{} (bytes)", e.val),
            0x6fff_fff9 | 0x6fff_fffa | 0x6fff_fffd | 0x6fff_ffff => e.val.to_string(),
            _ => format!("{:#x}", e.val),
        };
        let pad = 19usize.saturating_sub(name.len()).max(1);
        out.push(format!(" 0x{:016x} ({name}){:pad$}{value}", e.tag, ""));
    }
    out
}

fn reloc_type_name(r: &Reloc) -> String {
    r.kind.x86_64_name().map_or_else(
        || format!("unrecognized: {:<7x}", r.kind.0),
        ToString::to_string,
    )
}

/// The symbol of a relocation.
fn reloc_symbol<'a>(b: &'a Binary, r: &Reloc) -> Option<&'a Sym> {
    let index = r.sym?;
    b.symbols_of(r.sym_table).find(|s| s.index == index)
}

fn reloc_row(b: &Binary, r: &Reloc) -> String {
    let info = (u64::from(r.sym.unwrap_or(0)) << 32) | u64::from(r.kind.0);
    let mut row = format!("{:016x}  {info:016x} {:<22}", r.offset, reloc_type_name(r));
    let sign = |a: i64| {
        if a < 0 {
            format!(" - {:x}", a.unsigned_abs())
        } else {
            format!(" + {a:x}")
        }
    };
    if let Some(sym) = reloc_symbol(b, r) {
        let version = sym.version.as_ref().map_or_else(String::new, |v| {
            let at = if v.needed || v.hidden { "@" } else { "@@" };
            format!("{at}{}", printable(v.name.as_bytes()))
        });
        let _ = write!(
            row,
            " {:016x} {}{version}{}",
            sym.addr,
            printable(sym.name.as_bytes()),
            sign(r.addend)
        );
    } else if r.addend < 0 {
        let _ = write!(row, "{:20}-{:x}", "", r.addend.unsigned_abs());
    } else {
        let _ = write!(row, "{:20}{:x}", "", r.addend);
    }
    row
}

fn sym_type(k: SymKind) -> String {
    match k {
        SymKind::NoType => "NOTYPE".into(),
        SymKind::Object => "OBJECT".into(),
        SymKind::Func => "FUNC".into(),
        SymKind::Section => "SECTION".into(),
        SymKind::File => "FILE".into(),
        SymKind::Common => "COMMON".into(),
        SymKind::Tls => "TLS".into(),
        SymKind::Ifunc => "IFUNC".into(),
        SymKind::Other(v) => format!("<OS specific>: {v}"),
    }
}

fn sym_bind(k: SymBind) -> String {
    match k {
        SymBind::Local => "LOCAL".into(),
        SymBind::Global => "GLOBAL".into(),
        SymBind::Weak => "WEAK".into(),
        SymBind::Unique => "UNIQUE".into(),
        SymBind::Other(v) => format!("<unknown>: {v}"),
    }
}

fn sym_vis(v: SymVis) -> &'static str {
    match v {
        SymVis::Default => "DEFAULT",
        SymVis::Internal => "INTERNAL",
        SymVis::Hidden => "HIDDEN",
        SymVis::Protected => "PROTECTED",
    }
}

fn sym_ndx(n: u32) -> String {
    match n {
        0 => "UND".into(),
        0xfff1 => "ABS".into(),
        0xfff2 => "COM".into(),
        n => format!("{n:3}"),
    }
}

fn symbol_row(s: &Sym) -> String {
    let size = if s.size <= 99_999 {
        format!("{:5}", s.size)
    } else {
        format!("0x{:x}", s.size)
    };
    let version = s.version.as_ref().map_or_else(String::new, |v| {
        let name = printable(v.name.as_bytes());
        if v.needed {
            format!("@{name} ({})", v.index)
        } else if v.hidden {
            format!("@{name}")
        } else {
            format!("@@{name}")
        }
    });
    format!(
        "{:>6}: {:016x} {size} {:<7} {:<6} {:<7} {:>4} {}{version}",
        s.index,
        s.addr,
        sym_type(s.kind),
        sym_bind(s.bind),
        sym_vis(s.vis),
        sym_ndx(s.shndx),
        printable(s.name.as_bytes())
    )
}

/// The label of a dynamic-view relocation table in `readelf -D -r`.
const fn dyn_label(source: RelocSource) -> Option<&'static str> {
    match source {
        RelocSource::Section(_) => None,
        RelocSource::DynRel => Some("REL"),
        RelocSource::DynRela => Some("RELA"),
        RelocSource::DynRelr => Some("RELR"),
        RelocSource::DynPlt => Some("PLT"),
    }
}

/// Groups rows by a key in first-seen order.
fn push_group(groups: &mut Vec<(String, Vec<String>)>, key: &str, row: String) {
    match groups.iter_mut().find(|(k, _)| k == key) {
        Some((_, rows)) => rows.push(row),
        None => groups.push((key.to_string(), vec![row])),
    }
}

/// Renders the readelf rows of a model.
pub fn render(b: &Binary) -> Blocks {
    let mut out = Blocks {
        sections: b.sections.iter().map(section_row).collect(),
        segments: b.segments.iter().map(segment_row).collect(),
        dynamic: dynamic_rows(b),
        entry: b
            .entry_points
            .iter()
            .find(|e| e.kind == ghidorah_loader::EntryKind::Entry)
            .map(|e| format!("{:#x}", e.addr)),
        build_id: b.identity.build_id.clone(),
        ..Blocks::default()
    };
    for r in &b.relocs {
        let row = reloc_row(b, r);
        match (r.source, dyn_label(r.source)) {
            (RelocSource::Section(i), _) => {
                let name = b
                    .section(i)
                    .map(|s| text(Some(&s.name)))
                    .unwrap_or_default();
                push_group(&mut out.relocs, &name, row);
            }
            (_, Some(label)) => push_group(&mut out.dynrel, label, row),
            (_, None) => {}
        }
    }
    for section in &b.sections {
        let table = match section.kind {
            SectionKind::Elf(11) => SymTable::Dynsym,
            SectionKind::Elf(2) => SymTable::Symtab,
            _ => continue,
        };
        let rows = b.symbols_of(table).map(symbol_row).collect();
        out.symtabs.push((text(Some(&section.name)), rows));
    }
    out
}

/// Renders the symbol rows of one table.
pub fn symbol_rows(b: &Binary, table: SymTable) -> Vec<String> {
    b.symbols_of(table).map(symbol_row).collect()
}

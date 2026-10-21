//! Parsers of GNU `readelf -W` output (binutils 2.42), for the truth files.
//!
//! The build runs `readelf -W -h -l -S -s -d -r -n` once per fixture. The same text is the
//! loader golden. These parsers read the parts of that text: the ELF header, the program
//! headers, the section headers, the symbol tables, the dynamic section, the relocations
//! and the notes. Each parser skips lines that it does not know.

use std::collections::BTreeMap;

use crate::json::Value;

/// One program header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The type, for example `LOAD` or `GNU_STACK`.
    pub kind: String,
    /// The file offset.
    pub offset: u64,
    /// The virtual address.
    pub vaddr: u64,
    /// The size in the file.
    pub filesz: u64,
    /// The size in memory.
    pub memsz: u64,
    /// The flags without spaces, for example `RE`.
    pub flags: String,
}

/// One section header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section index.
    pub index: usize,
    /// The name. Section 0 has an empty name.
    pub name: String,
    /// The type, for example `PROGBITS`.
    pub kind: String,
    /// The address.
    pub addr: u64,
    /// The file offset.
    pub offset: u64,
    /// The size.
    pub size: u64,
    /// The flag letters, for example `AX`.
    pub flags: String,
}

impl Section {
    /// Tells if the section holds code.
    #[must_use]
    pub fn is_exec(&self) -> bool {
        self.flags.contains('X')
    }

    /// Tells if the section takes memory at run time.
    #[must_use]
    pub fn is_alloc(&self) -> bool {
        self.flags.contains('A')
    }
}

/// One symbol table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The table name, `.symtab` or `.dynsym`.
    pub table: String,
    /// The value.
    pub value: u64,
    /// The size.
    pub size: u64,
    /// The type, for example `FUNC`.
    pub kind: String,
    /// The binding, for example `GLOBAL`.
    pub bind: String,
    /// The section index text: a number, `UND`, `ABS` or `COM`.
    pub ndx: String,
    /// The name. A `.dynsym` name has no version suffix.
    pub name: String,
}

impl Symbol {
    /// Tells if a section holds the symbol.
    #[must_use]
    pub fn is_defined(&self) -> bool {
        self.ndx.parse::<usize>().is_ok()
    }
}

/// One relocation row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// The relocation section, for example `.rela.dyn`.
    pub section: String,
    /// The offset.
    pub offset: u64,
    /// The type, for example `R_X86_64_PC32`.
    pub kind: String,
    /// The symbol name, or empty text.
    pub sym: String,
    /// The addend.
    pub addend: i64,
}

/// One dynamic section row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dynamic {
    /// The tag name, for example `NEEDED`.
    pub tag: String,
    /// The value text.
    pub value: String,
}

/// The parsed parts of one `readelf` text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElfInfo {
    /// The ELF type word, for example `DYN` or `EXEC`.
    pub elf_type: String,
    /// The entry point.
    pub entry: u64,
    /// The program headers.
    pub segments: Vec<Segment>,
    /// The section headers.
    pub sections: Vec<Section>,
    /// The symbols of all tables.
    pub symbols: Vec<Symbol>,
    /// The dynamic section rows.
    pub dynamic: Vec<Dynamic>,
    /// The relocations of all relocation sections.
    pub relocs: Vec<Reloc>,
    /// The GNU build ID in hex.
    pub build_id: Option<String>,
    /// The x86 feature words of the GNU property note, for example `IBT`.
    pub x86_features: Vec<String>,
}

/// Parses a hex number with or without `0x`.
#[must_use]
pub fn hex(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).ok()
}

/// Parses a symbol size: decimal, or hex with `0x` for large values.
fn size(text: &str) -> Option<u64> {
    if text.starts_with("0x") {
        hex(text)
    } else {
        text.parse().ok()
    }
}

/// Removes a version suffix: `puts@GLIBC_2.2.5 (2)` gives `puts`.
#[must_use]
pub fn unversioned(name: &str) -> String {
    let base = name.split(" (").next().unwrap_or(name);
    base.split('@').next().unwrap_or(base).to_owned()
}

fn segment(line: &str) -> Option<Segment> {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() < 7 || !t.get(1)?.starts_with("0x") {
        return None;
    }
    let flags: String = t.get(6..t.len() - 1)?.concat();
    Some(Segment {
        kind: (*t.first()?).to_owned(),
        offset: hex(t.get(1)?)?,
        vaddr: hex(t.get(2)?)?,
        filesz: hex(t.get(4)?)?,
        memsz: hex(t.get(5)?)?,
        flags,
    })
}

fn section(line: &str) -> Option<Section> {
    let (head, rest) = line.trim_start().strip_prefix('[')?.split_once(']')?;
    let index = head.trim().parse().ok()?;
    let t: Vec<&str> = rest.split_whitespace().collect();
    let at = t
        .iter()
        .position(|w| w.len() == 16 && w.bytes().all(|b| b.is_ascii_hexdigit()))?;
    let tail = t.get(at + 4..)?;
    let flags = if tail.len() == 4 { tail.first()? } else { "" };
    Some(Section {
        index,
        name: t.get(..at.checked_sub(1)?)?.join(" "),
        kind: (*t.get(at - 1)?).to_owned(),
        addr: hex(t.get(at)?)?,
        offset: hex(t.get(at + 1)?)?,
        size: hex(t.get(at + 2)?)?,
        flags: flags.to_owned(),
    })
}

fn symbol(table: &str, line: &str) -> Option<Symbol> {
    let (num, rest) = line.trim_start().split_once(':')?;
    num.parse::<usize>().ok()?;
    let t: Vec<&str> = rest.split_whitespace().collect();
    let raw = t.get(6..).map(|n| n.join(" ")).unwrap_or_default();
    let name = if table == ".dynsym" {
        unversioned(&raw)
    } else {
        raw
    };
    Some(Symbol {
        table: table.to_owned(),
        value: hex(t.first()?)?,
        size: size(t.get(1)?)?,
        kind: (*t.get(2)?).to_owned(),
        bind: (*t.get(3)?).to_owned(),
        ndx: (*t.get(5)?).to_owned(),
        name,
    })
}

fn reloc(section: &str, line: &str) -> Option<Reloc> {
    let t: Vec<&str> = line.split_whitespace().collect();
    let offset = hex(t.first()?)?;
    hex(t.get(1)?)?;
    let kind = (*t.get(2)?).to_owned();
    if !kind.starts_with("R_") {
        return None;
    }
    let (sym, addend) = if t.len() == 4 {
        (String::new(), i64::try_from(hex(t.get(3)?)?).ok()?)
    } else {
        let sign = *t.get(t.len().checked_sub(2)?)?;
        let magnitude = i64::try_from(hex(t.last()?)?).ok()?;
        let addend = if sign == "-" { -magnitude } else { magnitude };
        (t.get(4..t.len() - 2)?.join(" "), addend)
    };
    Some(Reloc {
        section: section.to_owned(),
        offset,
        kind,
        sym,
        addend,
    })
}

fn dynamic(line: &str) -> Option<Dynamic> {
    let (_, rest) = line.trim_start().strip_prefix("0x")?.split_once('(')?;
    let (tag, value) = rest.split_once(')')?;
    Some(Dynamic {
        tag: tag.to_owned(),
        value: value.trim().to_owned(),
    })
}

/// The table that the current line belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    None,
    Segments,
    Sections,
    Symbols(String),
    Dynamic,
    Relocs(String),
}

/// Gives the quoted name of a header line such as `Symbol table '.dynsym' contains ..`.
fn quoted(line: &str) -> Option<String> {
    let (_, rest) = line.split_once('\'')?;
    let (name, _) = rest.split_once('\'')?;
    Some(name.to_owned())
}

/// Gives the feature words of `IBT, SHSTK, x86 ISA needed: ..`: `IBT` and `SHSTK`.
fn features(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .take_while(|w| !w.contains(':'))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parses the text of `readelf -W -h -l -S -s -d -r -n`.
#[must_use]
pub fn parse(text: &str) -> ElfInfo {
    let mut info = ElfInfo::default();
    let mut part = Part::None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            part = Part::None;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Type:") {
            rest.split_whitespace()
                .next()
                .unwrap_or_default()
                .clone_into(&mut info.elf_type);
        } else if let Some(rest) = trimmed.strip_prefix("Entry point address:") {
            info.entry = hex(rest.trim()).unwrap_or(0);
        } else if trimmed == "Program Headers:" {
            part = Part::Segments;
        } else if trimmed == "Section Headers:" {
            part = Part::Sections;
        } else if trimmed.starts_with("Symbol table '") {
            part = Part::Symbols(quoted(trimmed).unwrap_or_default());
        } else if trimmed.starts_with("Dynamic section at offset") {
            part = Part::Dynamic;
        } else if trimmed.starts_with("Relocation section '") {
            part = Part::Relocs(quoted(trimmed).unwrap_or_default());
        } else if let Some((_, rest)) = trimmed.split_once("Build ID:") {
            info.build_id = Some(rest.trim().to_owned());
        } else if let Some((_, rest)) = trimmed.split_once("x86 feature:") {
            info.x86_features = features(rest);
        } else {
            match &part {
                Part::Segments => info.segments.extend(segment(line)),
                Part::Sections => info.sections.extend(section(line)),
                Part::Symbols(table) => info.symbols.extend(symbol(table, line)),
                Part::Dynamic => info.dynamic.extend(dynamic(line)),
                Part::Relocs(sec) => info.relocs.extend(reloc(sec, line)),
                Part::None => {}
            }
        }
    }
    info
}

/// The protection fields that come from the imports of `.dynsym`.
const IMPORT_FIELDS: [&str; 2] = ["canary", "fortify"];

impl ElfInfo {
    /// Gives the section with a name.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Gives the section that holds an address.
    #[must_use]
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.is_alloc() && s.addr <= addr && addr < s.addr.saturating_add(s.size))
    }

    /// Gives the `DT_NEEDED` libraries in table order.
    #[must_use]
    pub fn libraries(&self) -> Vec<String> {
        self.dynamic
            .iter()
            .filter(|d| d.tag == "NEEDED")
            .filter_map(|d| quoted_brackets(&d.value))
            .collect()
    }

    /// Gives the undefined `FUNC` symbols of `.dynsym`, sorted and without duplicates.
    #[must_use]
    pub fn imports(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .symbols
            .iter()
            .filter(|s| s.table == ".dynsym" && s.ndx == "UND" && s.kind == "FUNC")
            .map(|s| s.name.clone())
            .filter(|n| !n.is_empty())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Gives the import name of a GOT slot: the symbol of a `JUMP_SLOT` or `GLOB_DAT` relocation.
    #[must_use]
    pub fn slot_import(&self, slot: u64) -> Option<String> {
        self.relocs
            .iter()
            .find(|r| {
                r.offset == slot
                    && (r.kind == "R_X86_64_JUMP_SLOT" || r.kind == "R_X86_64_GLOB_DAT")
            })
            .map(|r| unversioned(&r.sym))
    }

    fn has_segment(&self, kind: &str) -> bool {
        self.segments.iter().any(|s| s.kind == kind)
    }

    fn dynamic_has(&self, tag: &str, word: &str) -> bool {
        self.dynamic
            .iter()
            .any(|d| d.tag == tag && d.value.split_whitespace().any(|w| w == word))
    }

    /// Gives the protections of design Section 4.6 as a JSON object.
    #[must_use]
    pub fn protections(&self) -> Value {
        let imports = self.imports();
        let pie = self.elf_type == "DYN"
            && (self.has_segment("INTERP") || self.dynamic_has("FLAGS_1", "PIE"));
        let nx = self
            .segments
            .iter()
            .any(|s| s.kind == "GNU_STACK" && !s.flags.contains('E'));
        let now = self.dynamic_has("FLAGS", "BIND_NOW") || self.dynamic_has("FLAGS_1", "NOW");
        let relro = match (self.has_segment("GNU_RELRO"), now) {
            (false, _) => "none",
            (true, false) => "partial",
            (true, true) => "full",
        };
        let feature = |w: &str| self.x86_features.iter().any(|f| f == w);
        let has_tag = |t: &str| self.dynamic.iter().any(|d| d.tag == t);
        let mut map = BTreeMap::new();
        map.insert("pie".to_owned(), Value::from(pie));
        map.insert("nx".to_owned(), Value::from(nx));
        map.insert("relro".to_owned(), Value::from(relro));
        map.insert(
            "canary".to_owned(),
            Value::from(imports.iter().any(|i| i == "__stack_chk_fail")),
        );
        map.insert(
            "fortify".to_owned(),
            Value::from(imports.iter().any(|i| i.ends_with("_chk"))),
        );
        map.insert("ibt".to_owned(), Value::from(feature("IBT")));
        map.insert("shstk".to_owned(), Value::from(feature("SHSTK")));
        map.insert("rpath".to_owned(), Value::from(has_tag("RPATH")));
        map.insert("runpath".to_owned(), Value::from(has_tag("RUNPATH")));
        map.insert(
            "build_id".to_owned(),
            self.build_id.clone().map_or(Value::Null, Value::from),
        );
        Value::Object(map)
    }

    /// Gives the protection fields of this variant text that differ from `base`, the
    /// protections of its build, in key order.
    ///
    /// A variant keeps the `.dynsym` of its build. The text of a file with no section headers
    /// lists no symbol table, so such a text keeps the import fields of `base`.
    #[must_use]
    pub fn variant_protections(&self, base: &Value) -> BTreeMap<String, Value> {
        let lists_imports = self.symbols.iter().any(|s| s.table == ".dynsym");
        let Value::Object(own) = self.protections() else {
            return BTreeMap::new();
        };
        own.into_iter()
            .filter(|(k, _)| lists_imports || !IMPORT_FIELDS.contains(&k.as_str()))
            .filter(|(k, v)| base.get(k) != Some(v))
            .collect()
    }
}

/// Gives the text between `[` and `]`, as in `Shared library: [libc.so.6]`.
fn quoted_brackets(text: &str) -> Option<String> {
    let (_, rest) = text.split_once('[')?;
    let (inner, _) = rest.split_once(']')?;
    Some(inner.to_owned())
}

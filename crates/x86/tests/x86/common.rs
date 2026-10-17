//! Shared helpers: paths, hex, the spec file, objdump listings, ELF sections and text
//! normalization.

use std::path::PathBuf;

use ghidorah_x86::{Insn, NoSymbols, Opts, decode, operand_text};

/// The workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses hex bytes separated by spaces, or hex without spaces.
pub fn hex(text: &str) -> Vec<u8> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("hex byte"))
        .collect()
}

/// The address of every spec vector.
pub const SPEC_ADDR: u64 = 0x1000;

/// One line of `tests/data/x86_spec.txt`.
#[derive(Debug, Clone)]
pub struct SpecLine {
    pub line: usize,
    pub bytes: Vec<u8>,
    pub mnem: String,
    pub ops: String,
    pub len: u8,
    pub flow: String,
}

impl SpecLine {
    /// Tells if the line expects an error.
    pub fn is_error(&self) -> bool {
        self.mnem.starts_with('!')
    }
}

/// Reads the spec vectors.
pub fn spec_lines() -> Vec<SpecLine> {
    let path = root().join("tests/data/x86_spec.txt");
    let text = std::fs::read_to_string(&path).expect("read the spec file");
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(f.len(), 5, "spec line {} has 5 fields: {line}", i + 1);
        out.push(SpecLine {
            line: i + 1,
            bytes: hex(f[0]),
            mnem: f[1].to_owned(),
            ops: f[2].to_owned(),
            len: f[3].parse().expect("length"),
            flow: f[4].to_owned(),
        });
    }
    out
}

/// Gives the operand texts of an instruction, joined with `,`.
pub fn ops_text(insn: &Insn) -> String {
    (0..usize::from(insn.n_ops()))
        .map(|i| operand_text(insn, i, &NoSymbols).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(",")
}

/// Decodes with the default options.
pub fn dec(bytes: &[u8], addr: u64) -> Result<Insn, ghidorah_x86::DecodeError> {
    decode(bytes, addr, &Opts::DEFAULT)
}

/// One instruction of an objdump listing.
#[derive(Debug, Clone)]
pub struct ListedInsn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub section: String,
    /// The index of the label block, so a sweep restarts at each label.
    pub block: usize,
}

/// A parsed `objdump -d -w -z -M intel` listing.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub fixture: String,
    pub fixture_sha256: String,
    pub insns: Vec<ListedInsn>,
    /// The labels as `(address, name)`, in listing order.
    pub labels: Vec<(u64, String)>,
}

fn header_field(header: &str, key: &str) -> String {
    header
        .split_whitespace()
        .find_map(|w| w.strip_prefix(&format!("{key}=")))
        .unwrap_or_default()
        .to_owned()
}

/// Parses one listing file.
pub fn parse_listing(text: &str) -> Listing {
    let mut out = Listing::default();
    let mut section = String::new();
    let mut block = 0;
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            out.fixture = header_field(line, "fixture");
            out.fixture_sha256 = header_field(line, "fixture_sha256");
            continue;
        }
        if let Some(rest) = line.strip_prefix("Disassembly of section ") {
            section = rest.trim_end_matches(':').to_owned();
            block += 1;
            continue;
        }
        if let Some((addr, rest)) = line.split_once(" <")
            && let Ok(a) = u64::from_str_radix(addr.trim(), 16)
            && let Some(name) = rest.strip_suffix(">:")
        {
            out.labels.push((a, name.to_owned()));
            block += 1;
            continue;
        }
        let mut parts = line.split('\t');
        let (Some(addr), Some(bytes)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(addr) = addr.trim().strip_suffix(':') else {
            continue;
        };
        let Ok(addr) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        let text = parts.collect::<Vec<_>>().join("\t");
        out.insns.push(ListedInsn {
            addr,
            bytes: hex(bytes),
            text: text.split_whitespace().collect::<Vec<_>>().join(" "),
            section: section.clone(),
            block,
        });
    }
    out
}

/// Reads every objdump listing of the fixture corpus, sorted by name.
pub fn listings() -> &'static [Listing] {
    ghidorah_testkit::fixture::cached("x86_objdump_listings", || {
        let dir = root().join("tests/golden/objdump");
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .expect("read the objdump golden directory")
            .map(|e| e.expect("directory entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "txt"))
            .collect();
        paths.sort();
        paths
            .iter()
            .map(|p| parse_listing(&std::fs::read_to_string(p).expect("read a listing")))
            .collect::<Vec<_>>()
    })
}

/// One section of an ELF64 little-endian file.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub nobits: bool,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().expect("2 bytes"))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).expect("value fits usize")
}

/// Reads the section headers of a checked-in fixture. The test reader trusts its input.
pub fn sections(file: &[u8]) -> Vec<Section> {
    assert_eq!(&file[..4], b"\x7fELF", "an ELF file");
    let shoff = to_usize(u64_at(file, 0x28));
    let entsize = usize::from(u16_at(file, 0x3a));
    let count = usize::from(u16_at(file, 0x3c));
    let strndx = usize::from(u16_at(file, 0x3e));
    let raw: Vec<(u32, u32, u64, u64, u64)> = (0..count)
        .map(|i| {
            let h = shoff + i * entsize;
            (
                u32_at(file, h),
                u32_at(file, h + 4),
                u64_at(file, h + 16),
                u64_at(file, h + 24),
                u64_at(file, h + 32),
            )
        })
        .collect();
    let strtab = raw[strndx].3;
    raw.iter()
        .map(|&(name, kind, addr, offset, size)| {
            let start = to_usize(strtab) + usize::try_from(name).expect("name offset");
            let end = file[start..].iter().position(|&b| b == 0).expect("name end") + start;
            Section {
                name: String::from_utf8_lossy(&file[start..end]).into_owned(),
                addr,
                offset,
                size,
                nobits: kind == 8,
            }
        })
        .collect()
}

/// The code bytes of one fixture section.
pub struct Code<'a> {
    pub addr: u64,
    pub bytes: &'a [u8],
}

impl Code<'_> {
    /// Gives the bytes from `addr` to the end of the section.
    pub fn from(&self, addr: u64) -> &[u8] {
        let at = to_usize(addr - self.addr);
        &self.bytes[at..]
    }
}

/// Reads a fixture binary.
pub fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(root().join("fixtures/bin").join(name)).expect("read a fixture binary")
}

/// Gives the code of a named section.
pub fn section_code<'a>(file: &'a [u8], name: &str) -> Code<'a> {
    let s = sections(file)
        .into_iter()
        .find(|s| s.name == name && !s.nobits)
        .unwrap_or_else(|| panic!("section {name}"));
    let start = to_usize(s.offset);
    Code {
        addr: s.addr,
        bytes: &file[start..start + to_usize(s.size)],
    }
}

/// Normalizes GNU objdump text so it compares with the printer text.
///
/// The rules: drop the `#` comment and `rex` words, write `ptr` sizes in lower case,
/// write branch targets as `0x..`, write absolute memory as `[0x..]`, write a negative
/// RIP displacement with `-`, and drop spaces after commas.
pub fn normalize_objdump(text: &str) -> String {
    let text = text.split('#').next().unwrap_or_default().trim().to_lowercase();
    let text = text.replace("oword ptr", "xmmword ptr");
    let mut words: Vec<String> = Vec::new();
    let mut tokens = text.split(' ').filter(|w| !w.is_empty()).peekable();
    while let Some(w) = tokens.next() {
        if w.starts_with("rex") || w.starts_with("{rex") {
            continue;
        }
        if let Some(next) = tokens.peek()
            && next.starts_with('<')
            && u64::from_str_radix(w, 16).is_ok()
        {
            words.push(format!("0x{w}"));
            tokens.next();
            continue;
        }
        words.push(w.to_owned());
    }
    let mut out = words.join(" ");
    for seg in ["ds", "fs", "gs", "es", "cs", "ss"] {
        out = absolute_memory(&out, seg);
    }
    out = negative_rip(&out);
    out.replace(", ", ",")
}

/// Changes `seg:0x10` to `[0x10]` for `ds`, and to `seg:[0x10]` for other segments.
fn absolute_memory(text: &str, seg: &str) -> String {
    let pat = format!("{seg}:0x");
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(&pat) {
        out.push_str(&rest[..at]);
        let tail = &rest[at + pat.len()..];
        let n = tail
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(tail.len());
        if seg == "ds" {
            out.push_str(&format!("[0x{}]", &tail[..n]));
        } else {
            out.push_str(&format!("{seg}:[0x{}]", &tail[..n]));
        }
        rest = &tail[n..];
    }
    out.push_str(rest);
    out
}

/// Changes `rip+0xfffffffffffffff0` to `rip-0x10`.
fn negative_rip(text: &str) -> String {
    for base in ["rip+0x", "eip+0x"] {
        if let Some(at) = text.find(base) {
            let tail = &text[at + base.len()..];
            let n = tail
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(tail.len());
            if let Ok(v) = u64::from_str_radix(&tail[..n], 16)
                && v >= 1 << 63
            {
                let neg = v.wrapping_neg();
                return format!(
                    "{}{}-0x{neg:x}{}",
                    &text[..at],
                    &base[..3],
                    &tail[n..]
                );
            }
        }
    }
    text.to_owned()
}

/// Normalizes printer text: drop the `;` note and the spaces after commas.
pub fn normalize_printer(text: &str) -> String {
    text.split(" ; ")
        .next()
        .unwrap_or_default()
        .replace(", ", ",")
}

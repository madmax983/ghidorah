//! Fixture tests against the checked-in objdump listings: boundaries (AC-060),
//! RIP-relative targets (AC-063a), the printer golden (AC-064) and printer agreement.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use ghidorah_testkit::golden::{self, Header};
use ghidorah_x86::{NoSymbols, Symbolizer, length, print};

use crate::common::{
    Listing, dec, fixture_bytes, listings, normalize_objdump, normalize_printer, root, section_code,
};

/// Gives the file bytes of a fixture.
fn file_of(l: &Listing) -> Vec<u8> {
    fixture_bytes(&l.fixture)
}

/// The code sections of one fixture: name to `(address, bytes)`.
type Sections<'a> = BTreeMap<String, (u64, &'a [u8])>;

fn code_sections<'a>(file: &'a [u8], l: &Listing) -> Sections<'a> {
    let mut out = Sections::new();
    for i in &l.insns {
        if !out.contains_key(&i.section) {
            let code = section_code(file, &i.section);
            out.insert(i.section.clone(), (code.addr, code.bytes));
        }
    }
    out
}

/// Gives the bytes from `addr` to the end of its section.
fn code_at<'a>(secs: &Sections<'a>, section: &str, addr: u64) -> &'a [u8] {
    let (base, bytes) = secs[section];
    &bytes[usize::try_from(addr - base).expect("offset")..]
}

#[test]
fn ac_060_boundary_agreement() {
    let mut checked = 0usize;
    let mut text_sections = 0usize;
    for l in listings() {
        let file = file_of(l);
        let secs = code_sections(&file, l);
        assert!(
            l.insns.iter().any(|i| i.section == ".text"),
            "{} has .text",
            l.fixture
        );
        text_sections += 1;
        for (n, i) in l.insns.iter().enumerate() {
            let code = code_at(&secs, &i.section, i.addr);
            assert_eq!(
                &code[..i.bytes.len()],
                i.bytes.as_slice(),
                "{} at {:x}: the listing bytes equal the file bytes",
                l.fixture,
                i.addr
            );
            let len = length(code).unwrap_or_else(|e| panic!("{} at {:x}: {e}", l.fixture, i.addr));
            assert_eq!(
                usize::from(len),
                i.bytes.len(),
                "{} at {:x} ({}): length",
                l.fixture,
                i.addr,
                i.text
            );
            // Inside one label block the next instruction starts where this one ends.
            if let Some(next) = l.insns.get(n + 1)
                && next.block == i.block
            {
                assert_eq!(next.addr, i.addr + u64::from(len), "{} sweep", l.fixture);
            }
            checked += 1;
        }
    }
    assert!(text_sections >= 60, "only {text_sections} listings");
    assert!(checked > 30_000, "only {checked} instructions");
}

/// Gives the address in a `# 3fd0 <name>` comment.
fn comment_target(text: &str) -> Option<u64> {
    let (_, comment) = text.split_once('#')?;
    u64::from_str_radix(comment.split_whitespace().next()?, 16).ok()
}

#[test]
fn ac_063a_riprel_targets() {
    let mut checked = 0usize;
    for l in listings() {
        for i in &l.insns {
            let Some(want) = comment_target(&i.text) else {
                continue;
            };
            let insn = dec(&i.bytes, i.addr).unwrap_or_else(|e| panic!("{:x}: {e}", i.addr));
            let mem = insn
                .ops()
                .find_map(|op| match op {
                    ghidorah_x86::Operand::Mem(m) if m.is_rip_relative() => Some(m),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{} at {:x} ({}) has a RIP operand",
                        l.fixture, i.addr, i.text
                    )
                });
            assert_eq!(
                mem.abs_target,
                Some(want),
                "{} at {:x} ({})",
                l.fixture,
                i.addr,
                i.text
            );
            checked += 1;
        }
    }
    assert!(checked > 2000, "only {checked} RIP-relative operands");
}

/// A symbolizer that names the labels of a listing.
struct Labels<'a>(BTreeMap<u64, &'a str>);

impl Symbolizer for Labels<'_> {
    fn name(&self, addr: u64) -> Option<String> {
        self.0.get(&addr).map(|s| (*s).to_owned())
    }

    fn note(&self, addr: u64) -> Option<String> {
        self.0.get(&addr).map(|s| format!("0x{addr:x} {s}"))
    }
}

/// The printer golden text of one fixture: label lines and `addr text` lines.
fn golden_text(l: &Listing) -> String {
    let labels = Labels(l.labels.iter().map(|(a, n)| (*a, n.as_str())).collect());
    let mut out = String::new();
    let mut block = usize::MAX;
    let mut label_at: BTreeMap<u64, &str> = BTreeMap::new();
    for (a, n) in &l.labels {
        label_at.insert(*a, n);
    }
    for i in &l.insns {
        if i.block != block {
            block = i.block;
            if let Some(name) = label_at.get(&i.addr) {
                let _ = writeln!(out, "<{name}>:");
            }
        }
        let insn = dec(&i.bytes, i.addr).unwrap_or_else(|e| panic!("{:x}: {e}", i.addr));
        let _ = writeln!(out, "{:x} {}", i.addr, print(&insn, &labels));
    }
    out
}

#[test]
fn ac_064_printer_golden() {
    let bless = golden::bless_from_env();
    let mut failures = Vec::new();
    for l in listings() {
        let path = root()
            .join("tests/golden/x86_text")
            .join(format!("{}.txt", l.fixture));
        let header = Header::new("x86-print", "1")
            .with("fixture", &l.fixture)
            .with("fixture_sha256", &l.fixture_sha256);
        if let Err(e) = golden::compare(&path, &header, &golden_text(l), bless) {
            failures.push(e.to_string());
        }
    }
    assert!(
        failures.is_empty(),
        "{} printer goldens differ:\n{}",
        failures.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn printer_matches_objdump() {
    let mut checked = 0usize;
    let mut failures = Vec::new();
    for l in listings() {
        for i in &l.insns {
            let insn = dec(&i.bytes, i.addr).unwrap_or_else(|e| panic!("{:x}: {e}", i.addr));
            let mine = normalize_printer(&print(&insn, &NoSymbols));
            let theirs = normalize_objdump(&i.text);
            if mine != theirs {
                failures.push(format!("{} {:x}: {mine} <> {theirs}", l.fixture, i.addr));
            }
            checked += 1;
        }
    }
    assert!(checked > 30_000, "only {checked} instructions");
    assert!(
        failures.is_empty(),
        "{} of {checked} texts differ:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

//! AC-051, AC-052 and the PLT stub tests: names come from relocation slots.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{DiagCode, Limits};
use ghidorah_loader::imports::{R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, slots};
use ghidorah_loader::stubs::{Stub, StubKind, find, label};
use ghidorah_loader::{Binary, MemoryMap, RelocType};
use ghidorah_testkit::elf::{ElfBuilder, ImportKind, Layout, Malformed, PltStyle, Section};

use crate::json;
use crate::support::{
    fixture, fixture_names, golden_body, has_fixture, hex, import_name, load_ok, root,
};

/// One instruction line of an objdump golden.
struct Line {
    section: String,
    bytes: Vec<u8>,
    /// The target address and the symbol text of a `# <addr> <sym>` annotation.
    note: Option<(u64, String)>,
}

/// The labels and the instruction lines of an objdump golden.
struct Listing {
    /// `(section, address, label)` of each `addr <label>:` line.
    labels: Vec<(String, u64, String)>,
    lines: Vec<Line>,
}

fn listing(text: &str) -> Listing {
    let mut section = String::new();
    let mut labels = Vec::new();
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Disassembly of section ") {
            section = rest.trim_end_matches(':').to_string();
        } else if line.ends_with(">:") && !line.starts_with(' ') {
            let (addr, rest) = line.split_once(' ').expect("label line");
            let name = rest.trim_start_matches('<').trim_end_matches(">:");
            labels.push((section.clone(), hex(addr), name.to_string()));
        } else if line.starts_with("  ") && line.contains(":\t") {
            let fields: Vec<&str> = line.split('\t').collect();
            let bytes = fields
                .get(1)
                .map(|f| {
                    f.split_whitespace()
                        .map(|b| u8::from_str_radix(b, 16).expect("byte"))
                        .collect()
                })
                .unwrap_or_default();
            let note = fields
                .get(2)
                .and_then(|f| f.split_once("# "))
                .map(|(_, n)| {
                    let (addr, sym) = n.split_once(' ').unwrap_or((n, ""));
                    let sym = sym.trim().trim_start_matches('<').trim_end_matches('>');
                    (hex(addr), sym.to_string())
                });
            lines.push(Line {
                section: section.clone(),
                bytes,
                note,
            });
        }
    }
    Listing { labels, lines }
}

/// The jump stubs of a file as `address -> import name`.
fn jump_names(b: &Binary, stubs: &[Stub]) -> BTreeMap<u64, String> {
    stubs
        .iter()
        .filter(|s| s.kind == StubKind::Jump)
        .map(|s| (s.addr, import_name(b, s.import.expect("a named stub"))))
        .collect()
}

fn scan(b: &Binary, map: &MemoryMap) -> Vec<Stub> {
    let scan = find(b, map, &Limits::DEFAULT);
    assert!(scan.diagnostics.is_empty(), "{:?}", scan.diagnostics);
    scan.stubs
}

/// The section start of `name`, if the file has the section.
fn section_addr(b: &Binary, name: &str) -> Option<u64> {
    b.sections
        .iter()
        .find(|s| s.name.as_bytes() == name.as_bytes())
        .map(|s| s.addr)
}

#[test]
fn ac_052_plt_names() {
    let mut checked = 0;
    let mut fno_plt_sites = 0;
    let mut problems = Vec::new();
    for name in fixture_names() {
        let Some(body) = golden_body("objdump", &format!("{name}.txt")) else {
            continue;
        };
        checked += 1;
        let (b, map) = load_ok(&fixture(&name));
        let l = listing(&body);
        let stubs = scan(&b, &map);
        let want: BTreeMap<u64, String> = l
            .labels
            .iter()
            .filter(|(s, _, _)| matches!(s.as_str(), ".plt" | ".plt.sec" | ".plt.got"))
            .filter_map(|(_, a, n)| n.strip_suffix("@plt").map(|n| (*a, n.to_string())))
            .collect();
        let got = jump_names(&b, &stubs);
        if got != want {
            problems.push(format!("{name}: stubs {got:x?}, want {want:x?}"));
        }
        for (addr, import) in &want {
            let i = b.imports.iter().position(|i| {
                i.name
                    .as_ref()
                    .is_some_and(|n| n.as_bytes() == import.as_bytes())
            });
            let stub = i.and_then(|i| b.imports[i].stub);
            if stub != Some(*addr) {
                problems.push(format!("{name}: {import}: stub {stub:x?}, want {addr:#x}"));
            }
        }
        if let Some(plt) = section_addr(&b, ".plt") {
            let plt0: Vec<u64> = stubs
                .iter()
                .filter(|s| s.kind == StubKind::Plt0)
                .map(|s| s.addr)
                .collect();
            if plt0 != vec![plt] {
                problems.push(format!("{name}: PLT0 {plt0:x?}, want {plt:#x}"));
            }
        }
        let map_of = slots(&b);
        for line in &l.lines {
            let op = line.bytes.strip_prefix(&[0xf2]).unwrap_or(&line.bytes);
            if !(op.starts_with(&[0xff, 0x25]) || op.starts_with(&[0xff, 0x15])) {
                continue;
            }
            let Some((slot, sym)) = &line.note else {
                continue;
            };
            if sym.contains('+') || !sym.contains('@') {
                continue;
            }
            let want = sym.split('@').next().unwrap_or_default();
            let got = map_of.get(slot).map(|s| import_name(&b, s.import));
            if got.as_deref() != Some(want) {
                problems.push(format!("{name}: slot {slot:#x}: {got:?}, want {want}"));
            }
            if line.section == ".text" && op.starts_with(&[0xff, 0x15]) {
                fno_plt_sites += 1;
            }
        }
    }
    assert!(checked >= 60, "only {checked} goldens");
    assert!(fno_plt_sites >= 10, "only {fno_plt_sites} -fno-plt sites");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The `GLOB_DAT` and `JUMP_SLOT` rows of a `readelf -D -r` golden: slot to (type, name).
fn dynrel_slots(text: &str) -> BTreeMap<u64, (RelocType, String)> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let kind = match fields[2] {
            "R_X86_64_GLOB_DAT" => R_X86_64_GLOB_DAT,
            "R_X86_64_JUMP_SLOT" => R_X86_64_JUMP_SLOT,
            _ => continue,
        };
        let name = fields[4].split('@').next().unwrap_or_default().to_string();
        out.insert(hex(fields[0]), (kind, name));
    }
    out
}

#[test]
fn ac_051_no_section_headers() {
    let mut checked = 0;
    for name in fixture_names().iter().filter(|n| n.ends_with(".noshdr")) {
        checked += 1;
        let body = golden_body("loader", &format!("{name}.dynrel.txt")).expect("dynrel golden");
        let want = dynrel_slots(&body);
        let (b, map) = load_ok(&fixture(name));
        assert!(b.sections.is_empty(), "{name}");
        let got: BTreeMap<u64, (RelocType, String)> = slots(&b)
            .into_iter()
            .map(|(slot, s)| (slot, (s.kind, import_name(&b, s.import))))
            .collect();
        assert_eq!(got, want, "{name}: slots");
        let twin_name = name.trim_end_matches(".noshdr");
        let (twin, twin_map) = load_ok(&fixture(twin_name));
        assert_eq!(b.imports, twin.imports, "{name}: imports");
        let stubs = scan(&b, &map);
        assert_eq!(stubs, scan(&twin, &twin_map), "{name}: stubs");
        let labels: Vec<String> = stubs
            .iter()
            .map(|s| String::from_utf8_lossy(label(&b, s).as_bytes()).into_owned())
            .collect();
        assert!(labels.contains(&".plt0".to_string()), "{name}: {labels:?}");
        assert!(
            labels.contains(&"puts@plt".to_string()),
            "{name}: {labels:?}"
        );
        assert!(
            labels.contains(&"puts@plt.lazy".to_string()),
            "{name}: {labels:?}"
        );
        assert!(
            labels.contains(&"__cxa_finalize@plt".to_string()),
            "{name}: {labels:?}"
        );
    }
    assert_eq!(checked, 2);
}

/// A file with two PLT imports, one `.plt.got` import and one GOT-only import.
fn four_imports(style: PltStyle, strip: bool) -> (Vec<u8>, Layout) {
    let mut b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 32]))
        .import("puts", ImportKind::Plt)
        .import("free", ImportKind::Plt)
        .import("abort", ImportKind::PltGot)
        .import("gfree", ImportKind::Got)
        .needed("libc.so.6")
        .plt_style(style);
    if strip {
        b = b.strip_section_headers();
    }
    b.build_with_layout()
}

fn import_index(b: &Binary, name: &str) -> usize {
    b.imports
        .iter()
        .position(|i| {
            i.name
                .as_ref()
                .is_some_and(|n| n.as_bytes() == name.as_bytes())
        })
        .unwrap_or_else(|| panic!("no import {name}"))
}

#[test]
fn builder_stub_forms() {
    for style in [PltStyle::Lazy, PltStyle::Ibt] {
        for strip in [false, true] {
            let what = format!("{style:?} strip {strip}");
            let (bytes, layout) = four_imports(style, strip);
            let (b, map) = load_ok(&bytes);
            assert!(b.diagnostics.is_empty(), "{what}: {:?}", b.diagnostics);
            let names: BTreeSet<String> =
                (0..b.imports.len()).map(|i| import_name(&b, i)).collect();
            let want: BTreeSet<String> = ["puts", "free", "abort", "gfree"]
                .iter()
                .map(ToString::to_string)
                .collect();
            assert_eq!(names, want, "{what}");
            for name in ["puts", "free", "abort", "gfree"] {
                let i = &b.imports[import_index(&b, name)];
                assert_eq!(i.slot, layout.got.get(name).copied(), "{what}: {name} slot");
                assert_eq!(i.lib, None);
                assert!(!i.delay);
                let stub = layout
                    .plt
                    .get(name)
                    .or_else(|| layout.plt_got.get(name))
                    .copied();
                assert_eq!(i.stub, stub, "{what}: {name} stub");
                let kind = if layout.plt.contains_key(name) {
                    R_X86_64_JUMP_SLOT
                } else {
                    R_X86_64_GLOB_DAT
                };
                assert_eq!(i.reloc_kind, Some(kind), "{what}: {name}");
            }
            let plt = layout.section(".plt").expect(".plt").addr;
            let stubs = scan(&b, &map);
            let mut want = vec![(plt, ".plt0".to_string())];
            for (n, name) in ["puts", "free"].iter().enumerate() {
                let entry = plt + 16 * (n as u64 + 1);
                let lazy = if style == PltStyle::Lazy {
                    entry + 6
                } else {
                    entry
                };
                want.push((layout.plt[*name], format!("{name}@plt")));
                want.push((lazy, format!("{name}@plt.lazy")));
            }
            want.push((layout.plt_got["abort"], "abort@plt".to_string()));
            want.sort();
            let got: Vec<(u64, String)> = stubs
                .iter()
                .map(|s| {
                    let text = String::from_utf8_lossy(label(&b, s).as_bytes()).into_owned();
                    (s.addr, text)
                })
                .collect();
            assert_eq!(got, want, "{what}");
            for s in &stubs {
                if s.kind != StubKind::Plt0 {
                    let i = s.import.expect("import");
                    assert_eq!(s.slot, b.imports[i].slot, "{what}: {s:?}");
                }
            }
        }
    }
}

#[test]
fn regress_plt_slot_by_reloc_not_position() {
    // Swap the slots of the two jump stubs. A name by position gives the wrong import.
    for style in [PltStyle::Lazy, PltStyle::Ibt] {
        let (bytes, layout) = four_imports(style, false);
        let (puts, free) = (layout.plt["puts"], layout.plt["free"]);
        let (puts_slot, free_slot) = (layout.got["puts"], layout.got["free"]);
        let field = |stub: u64| match style {
            PltStyle::Lazy => (stub + 2, stub + 6),
            PltStyle::Ibt => (stub + 7, stub + 11),
        };
        let off = |va: u64| {
            let s = layout
                .sections
                .iter()
                .find(|s| s.addr <= va && va < s.addr + 0x1000 && s.name.starts_with(".plt"))
                .expect("section");
            s.offset + (va - s.addr)
        };
        let patch = |stub: u64, slot: u64| {
            let (at, next) = field(stub);
            let disp = i32::try_from(
                i64::try_from(slot).expect("slot") - i64::try_from(next).expect("ip"),
            )
            .expect("disp");
            Malformed::Patch(off(at), disp.to_le_bytes().to_vec())
        };
        let swapped = ElfBuilder::dyn_object()
            .section(Section::code(".text", &[0xc3; 32]))
            .import("puts", ImportKind::Plt)
            .import("free", ImportKind::Plt)
            .import("abort", ImportKind::PltGot)
            .import("gfree", ImportKind::Got)
            .needed("libc.so.6")
            .plt_style(style)
            .malformed(patch(puts, free_slot))
            .malformed(patch(free, puts_slot))
            .build();
        assert_eq!(swapped.len(), bytes.len());
        let (b, map) = load_ok(&swapped);
        let names = jump_names(&b, &scan(&b, &map));
        assert_eq!(
            names.get(&puts).map(String::as_str),
            Some("free"),
            "{style:?}"
        );
        assert_eq!(
            names.get(&free).map(String::as_str),
            Some("puts"),
            "{style:?}"
        );
        assert_eq!(b.imports[import_index(&b, "puts")].stub, Some(free));
        assert_eq!(b.imports[import_index(&b, "free")].stub, Some(puts));
    }
}

#[test]
fn imports_match_truth() {
    let dir = root().join("fixtures/truth");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("truth dir") {
        let path = entry.expect("entry").path();
        let truth = json::parse(&std::fs::read_to_string(&path).expect("truth"));
        let want: BTreeSet<String> = truth
            .get("imports")
            .items()
            .iter()
            .map(|i| i.text().to_string())
            .collect();
        for bin in truth.get("binaries").items() {
            let name = bin.get("name").text();
            if !has_fixture(name) {
                continue;
            }
            checked += 1;
            let (b, _) = load_ok(&fixture(name));
            let got: BTreeSet<String> = (0..b.imports.len()).map(|i| import_name(&b, i)).collect();
            assert!(
                want.is_subset(&got),
                "{name}: {got:?} lacks some of {want:?}"
            );
            for (slot, s) in slots(&b) {
                let r = &b.relocs[s.reloc];
                assert_eq!(r.offset, slot, "{name}");
                assert_eq!(r.kind, s.kind, "{name}");
            }
        }
    }
    assert!(checked >= 130, "only {checked} binaries");
}

#[test]
fn slot_map_keeps_one_import_per_slot() {
    let (bytes, layout) = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 16]))
        .section(Section::data(".data", &[0; 16]))
        .import("puts", ImportKind::Got)
        .import("free", ImportKind::Got)
        .reloc(ghidorah_testkit::elf::Reloc {
            table: ghidorah_testkit::elf::RelocTable::Rela,
            at: ghidorah_testkit::elf::Loc::Got("puts".into()),
            kind: 6,
            sym: Some("free".into()),
            addend: 0,
        })
        .build_with_layout();
    let (b, _) = load_ok(&bytes);
    let map = slots(&b);
    let slot = layout.got["puts"];
    let names: Vec<String> = map
        .iter()
        .filter(|(s, _)| **s == slot)
        .map(|(_, s)| import_name(&b, s.import))
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    let first = b
        .relocs
        .iter()
        .position(|r| r.offset == slot)
        .expect("a relocation at the slot");
    assert_eq!(
        map[&slot].reloc, first,
        "the first relocation in table order wins"
    );
}

#[test]
fn other_machines_have_no_slots() {
    let bytes = ElfBuilder::dyn_object()
        .machine(183)
        .section(Section::code(".text", &[0xc3; 16]))
        .import("puts", ImportKind::Plt)
        .needed("libc.so.6")
        .build();
    let (b, map) = load_ok(&bytes);
    assert_eq!(b.imports.len(), 1);
    assert_eq!(b.imports[0].slot, None);
    assert_eq!(b.imports[0].stub, None);
    assert!(slots(&b).is_empty());
    assert!(find(&b, &map, &Limits::DEFAULT).stubs.is_empty());
    assert!(
        !b.diagnostics
            .iter()
            .any(|d| d.code != DiagCode::UnsupportedReloc),
        "{:?}",
        b.diagnostics
    );
}

#[test]
fn scan_limit_gives_one_diagnostic() {
    let (bytes, _) = four_imports(PltStyle::Lazy, false);
    let (b, map) = load_ok(&bytes);
    let limits = Limits {
        plt_scan_bytes: 24,
        ..Limits::DEFAULT
    };
    let scan = find(&b, &map, &limits);
    let codes: Vec<DiagCode> = scan.diagnostics.iter().map(|d| d.code).collect();
    assert_eq!(codes, vec![DiagCode::Limit]);
    assert!(scan.stubs.len() < 3, "{:?}", scan.stubs);
}

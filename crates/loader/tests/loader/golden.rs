//! AC-049 and AC-059: the readelf goldens and the binary identity of every fixture.

use ghidorah_loader::{EntryKind, Format, Kind, SymTable};

use crate::readelf::{Blocks, parse_dynrel, parse_golden, render, symbol_rows};
use crate::support::{fixture, fixture_names, golden, has_golden, load_ok};

/// Gives a message for the first row that differs, or `None` when the lists are equal.
fn first_diff(what: &str, want: &[String], got: &[String]) -> Option<String> {
    if want == got {
        return None;
    }
    let at = want
        .iter()
        .zip(got)
        .position(|(w, g)| w != g)
        .unwrap_or_else(|| want.len().min(got.len()));
    Some(format!(
        "{what}: {} rows in the golden, {} rows rendered; row {at}:\n  want {:?}\n  got  {:?}",
        want.len(),
        got.len(),
        want.get(at),
        got.get(at)
    ))
}

fn group_diff(
    what: &str,
    want: &[(String, Vec<String>)],
    got: &[(String, Vec<String>)],
) -> Vec<String> {
    let names = |g: &[(String, Vec<String>)]| g.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    if let Some(d) = first_diff(&format!("{what} names"), &names(want), &names(got)) {
        return vec![d];
    }
    want.iter()
        .zip(got)
        .filter_map(|((name, w), (_, g))| first_diff(&format!("{what} {name}"), w, g))
        .collect()
}

/// Compares the five tables of AC-049 and the header facts.
fn compare(name: &str, want: &Blocks, got: &Blocks) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    problems.extend(first_diff("sections", &want.sections, &got.sections));
    problems.extend(first_diff("segments", &want.segments, &got.segments));
    problems.extend(first_diff("dynamic", &want.dynamic, &got.dynamic));
    problems.extend(group_diff("relocations", &want.relocs, &got.relocs));
    problems.extend(group_diff("symbols", &want.symtabs, &got.symtabs));
    if want.entry != got.entry {
        problems.push(format!("entry: want {:?}, got {:?}", want.entry, got.entry));
    }
    if want.build_id != got.build_id {
        problems.push(format!(
            "build id: want {:?}, got {:?}",
            want.build_id, got.build_id
        ));
    }
    problems
        .into_iter()
        .map(|p| format!("{name}: {p}"))
        .collect()
}

#[test]
fn ac_049_elf_readelf_golden() {
    let names = fixture_names();
    assert!(names.len() >= 100, "only {} fixtures", names.len());
    let mut problems = Vec::new();
    for name in &names {
        let (_, body) = golden(&format!("{name}.readelf.txt"));
        let (binary, _) = load_ok(&fixture(name));
        let want = parse_golden(&body);
        let got = render(&binary);
        problems.extend(compare(name, &want, &got));
        let dynrel = format!("{name}.dynrel.txt");
        if has_golden(&dynrel) {
            let (_, body) = golden(&dynrel);
            problems.extend(
                group_diff("dynamic relocations", &parse_dynrel(&body), &got.dynrel)
                    .into_iter()
                    .map(|p| format!("{name}: {p}")),
            );
        }
        let kind = match binary.kind {
            Kind::Exec => "EXEC",
            Kind::Dyn => "DYN",
            Kind::Raw => "RAW",
        };
        if want.e_type.as_deref() != Some(kind) {
            problems.push(format!("{name}: type {:?}, got {kind}", want.e_type));
        }
        if binary.format != Format::Elf64Le || !binary.arch.is_x86_64() {
            problems.push(format!("{name}: {:?} {:?}", binary.format, binary.arch));
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// The golden parser finds every table of `hello.gcc-O2`, so an empty parse cannot pass.
#[test]
fn golden_parser_reads_every_table() {
    let (_, body) = golden("hello.gcc-O2.readelf.txt");
    let b = parse_golden(&body);
    assert_eq!(b.sections.len(), 31);
    assert_eq!(b.segments.len(), 13);
    assert_eq!(b.dynamic.len(), 27);
    let relocs: Vec<(&str, usize)> = b
        .relocs
        .iter()
        .map(|(n, r)| (n.as_str(), r.len()))
        .collect();
    assert_eq!(relocs, vec![(".rela.dyn", 8), (".rela.plt", 2)]);
    let syms: Vec<(&str, usize)> = b
        .symtabs
        .iter()
        .map(|(n, r)| (n.as_str(), r.len()))
        .collect();
    assert_eq!(syms, vec![(".dynsym", 8), (".symtab", 40)]);
    assert_eq!(b.entry.as_deref(), Some("0x1090"));
    assert_eq!(b.e_type.as_deref(), Some("DYN"));
    assert_eq!(
        b.build_id.as_deref(),
        Some("ef7e65e69e14ec3197defcf6f83dfddb33b0da02")
    );
    let (_, dynrel) = golden("hello.gcc-O2.noshdr.dynrel.txt");
    let groups: Vec<(String, usize)> = parse_dynrel(&dynrel)
        .into_iter()
        .map(|(n, r)| (n, r.len()))
        .collect();
    assert_eq!(
        groups,
        vec![("RELA".to_string(), 8), ("PLT".to_string(), 2)]
    );
    // The renderer gives the same row of the first `.dynsym` symbol as the golden.
    let (binary, _) = load_ok(&fixture("hello.gcc-O2"));
    let rendered = render(&binary);
    assert_eq!(rendered.symtabs[0].1[1], b.symtabs[0].1[1]);
    assert!(rendered.symtabs[0].1[1].ends_with("__libc_start_main@GLIBC_2.34 (2)"));
}

/// The comparison of AC-049 finds one changed row in each table.
#[test]
fn compare_finds_changed_rows() {
    let (_, body) = golden("hello.gcc-O2.readelf.txt");
    let want = parse_golden(&body);
    let (binary, _) = load_ok(&fixture("hello.gcc-O2"));
    let got = render(&binary);
    assert!(compare("hello", &want, &got).is_empty());
    let change = |edit: &dyn Fn(&mut Blocks)| {
        let mut bad = got.clone();
        edit(&mut bad);
        compare("hello", &want, &bad).len()
    };
    assert_eq!(change(&|b| b.sections[3].push('x')), 1);
    assert_eq!(change(&|b| b.segments[2].push('x')), 1);
    assert_eq!(change(&|b| b.dynamic[0].push('x')), 1);
    assert_eq!(change(&|b| b.relocs[1].1[0].push('x')), 1);
    assert_eq!(change(&|b| b.symtabs[1].1[7].push('x')), 1);
    assert_eq!(change(&|b| b.symtabs[0].0.push('x')), 1);
    assert_eq!(change(&|b| b.entry = None), 1);
    assert_eq!(change(&|b| b.build_id = None), 1);
}

/// The dynamic view of a fixture without section headers gives the `.dynsym` of its twin.
#[test]
fn noshdr_dynsym_equals_twin() {
    let mut seen = 0;
    for name in fixture_names().iter().filter(|n| n.ends_with(".noshdr")) {
        let twin = name.trim_end_matches(".noshdr");
        let (stripped, _) = load_ok(&fixture(name));
        let (full, _) = load_ok(&fixture(twin));
        assert!(stripped.sections.is_empty(), "{name} has sections");
        let rows = symbol_rows(&stripped, SymTable::Dynsym);
        assert!(!rows.is_empty(), "{name} has no dynamic symbols");
        assert_eq!(rows, symbol_rows(&full, SymTable::Dynsym), "{name}");
        assert_eq!(stripped.libraries, full.libraries, "{name}");
        assert_eq!(stripped.exports, full.exports, "{name}");
        seen += 1;
    }
    assert!(seen >= 2, "{seen} noshdr fixtures");
}

/// The entry points hold the file entry, `DT_INIT`, `DT_FINI` and the array elements.
#[test]
fn entry_points_of_hello() {
    let (binary, _) = load_ok(&fixture("hello.gcc-O2"));
    let kinds: Vec<(u64, EntryKind)> = binary
        .entry_points
        .iter()
        .map(|e| (e.addr, e.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (0x1000, EntryKind::Init),
            (0x1090, EntryKind::Entry),
            (0x1130, EntryKind::FiniArray),
            (0x1170, EntryKind::InitArray),
            (0x11e8, EntryKind::Fini),
        ]
    );
    assert_eq!(binary.image_base, 0);
    let (nopie, _) = load_ok(&fixture("hello.gcc-O2-nocet-nopie"));
    assert_eq!(nopie.image_base, 0x40_0000);
    assert_eq!(nopie.kind, Kind::Exec);
    assert_eq!(
        nopie.interp.as_ref().and_then(|t| t.as_str()),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
}

/// The exports are the defined global dynamic symbols.
#[test]
fn exports_are_defined_dynamic_symbols() {
    let (binary, _) = load_ok(&fixture("hello.gcc-O2"));
    assert!(binary.exports.is_empty(), "a PIE without exports");
    for name in fixture_names() {
        let (binary, _) = load_ok(&fixture(&name));
        for e in &binary.exports {
            let n = e.name.as_ref().map(|t| t.as_bytes().to_vec());
            let sym = binary
                .symbols_of(SymTable::Dynsym)
                .find(|s| Some(s.name.as_bytes().to_vec()) == n);
            let sym = sym.unwrap_or_else(|| panic!("{name}: export {e:?} has no symbol"));
            assert_ne!(sym.shndx, 0, "{name}: export of an undefined symbol");
            assert_eq!(e.addr, Some(sym.addr), "{name}");
        }
    }
}

#[test]
fn ac_059_binary_identity() {
    for name in fixture_names() {
        let (header, _) = golden(&format!("{name}.readelf.txt"));
        let want = header
            .field("fixture_sha256")
            .unwrap_or_else(|| panic!("{name}: no fixture_sha256"))
            .to_string();
        let (binary, _) = load_ok(&fixture(&name));
        assert_eq!(want.len(), 64, "{name}");
        assert_eq!(binary.identity.sha256_hex(), want, "{name}");
        let id = binary.identity.binary_id().to_string();
        assert_eq!(id.len(), 16, "{name}");
        assert_eq!(id, want[..16], "{name}: the first 16 hex digits");
    }
}

//! AC-246 and AC-247: imports, delay imports, exports and base relocations against the
//! `llvm-readobj` goldens, and the table forms of the `PeBuilder` variants.

use ghidorah_base::DiagCode;
use ghidorah_loader::{Binary, Import, SymTable};
use ghidorah_testkit::pe::{self, EXE_BASE};

use crate::readobj::number;
use crate::support::{IMAGES, codes, load_fixture, load_variant, readobj, text};

/// One import row for a comparison: DLL, name, ordinal, hint, slot and delay flag.
type Row = (String, String, Option<u16>, Option<u16>, Option<u64>, bool);

fn row(i: &Import) -> Row {
    (
        text(i.lib.as_ref()),
        text(i.name.as_ref()),
        i.ordinal,
        i.hint,
        i.slot,
        i.delay,
    )
}

/// Gives the name and the number in parentheses of a `Symbol: name (n)` value.
fn symbol(value: &str) -> (String, u16) {
    let (name, n) = value.rsplit_once('(').expect("a symbol value");
    let n = u16::try_from(number(n.trim_end_matches(')')).expect("a number")).expect("a u16");
    (name.trim().to_owned(), n)
}

/// Gives the import rows of a `llvm-readobj --coff-imports` golden.
fn golden_imports(b: &Binary, name: &str) -> Vec<Row> {
    let gold = readobj(name);
    let mut out = Vec::new();
    for imp in gold.all("Import") {
        let dll = imp.get("Name").expect("a DLL name").to_owned();
        let iat = imp.num("ImportAddressTableRVA");
        let symbols = imp.fields.iter().filter(|(k, _)| k == "Symbol");
        for (i, (_, v)) in symbols.enumerate() {
            let (sym, n) = symbol(v);
            let slot = Some(b.image_base + iat + 8 * i as u64);
            out.push(if sym.is_empty() {
                (dll.clone(), String::new(), Some(n), None, slot, false)
            } else {
                (dll.clone(), sym, None, Some(n), slot, false)
            });
        }
    }
    for imp in gold.all("DelayImport") {
        let dll = imp.get("Name").expect("a DLL name").to_owned();
        let iat = imp.num("ImportAddressTable");
        for (i, entry) in imp.all("Import").enumerate() {
            let (sym, n) = symbol(entry.get("Symbol").expect("a symbol"));
            let slot = Some(b.image_base + iat + 8 * i as u64);
            out.push(if sym.is_empty() {
                (dll.clone(), String::new(), Some(n), None, slot, true)
            } else {
                (dll.clone(), sym, None, Some(n), slot, true)
            });
        }
    }
    out
}

/// One export row: ordinal, name, address and forwarder.
type ExportRow = (Option<u32>, String, Option<u64>, String);

fn golden_exports(b: &Binary, name: &str) -> Vec<ExportRow> {
    readobj(name)
        .all("Export")
        .filter_map(|e| {
            let ordinal = u32::try_from(e.num("Ordinal")).ok();
            let export = e.get("Name").unwrap_or_default().to_owned();
            if let Some(f) = e.get("ForwardedTo") {
                return Some((ordinal, export, None, f.to_owned()));
            }
            let rva = e.num("RVA");
            (rva != 0).then(|| (ordinal, export, Some(b.image_base + rva), String::new()))
        })
        .collect()
}

#[test]
fn ac_246_imports_exports_golden() {
    let mut imports = 0;
    let mut exports = 0;
    for name in IMAGES {
        let (b, _) = load_fixture(name);
        let want = golden_imports(&b, name);
        let got: Vec<Row> = b.imports.iter().map(row).collect();
        assert_eq!(got, want, "{name}");
        imports += got.len();
        let dlls: Vec<String> = readobj(name)
            .children
            .iter()
            .filter(|c| c.name == "Import" || c.name == "DelayImport")
            .map(|c| c.get("Name").unwrap_or_default().to_owned())
            .collect();
        let libs: Vec<String> = b.libraries.iter().map(|l| text(Some(l))).collect();
        assert_eq!(libs, dlls, "{name}: the libraries in descriptor order");
        let want = golden_exports(&b, name);
        let got: Vec<ExportRow> = b
            .exports
            .iter()
            .map(|e| {
                (
                    e.ordinal,
                    text(e.name.as_ref()),
                    e.addr,
                    text(e.forwarder.as_ref()),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
        exports += got.len();
        for i in &b.imports {
            let slot = i.slot.expect("each PE import has a slot");
            let label = if i.name.is_some() {
                format!("__imp_{}", text(i.name.as_ref()))
            } else {
                let dll = text(i.lib.as_ref()).to_ascii_lowercase();
                format!("__imp_{dll}!#{}", i.ordinal.expect("an ordinal"))
            };
            assert!(
                b.symbols.iter().any(|s| s.table == SymTable::Iat
                    && s.addr == slot
                    && text(Some(&s.name)) == label),
                "{name}: no IAT symbol {label}"
            );
        }
    }
    assert_eq!(
        (imports, exports),
        (12, 5),
        "the fixtures have these tables"
    );
    let (b, _) = load_fixture("pe_dll.dll");
    assert_eq!(text(b.identity.soname.as_ref()), "pe_dll.dll");
}

#[test]
fn null_ilt_uses_iat() {
    let layout = pe::builder("null_ilt").expect("variant").layout();
    let (b, _) = load_variant("null_ilt");
    let got: Vec<Row> = b.imports.iter().map(row).collect();
    let slots = &layout.iat[0];
    let slot = |i: usize| Some(EXE_BASE + u64::from(slots[i]));
    let dll = "KERNEL32.dll".to_owned();
    assert_eq!(
        got,
        vec![
            (
                dll.clone(),
                "ExitProcess".to_owned(),
                None,
                Some(0x167),
                slot(0),
                false
            ),
            (dll, "Sleep".to_owned(), None, Some(0x5a2), slot(1), false),
        ]
    );
    // A bound IAT holds addresses, so the names come from the ILT.
    let (bound, _) = load_variant("bound_iat");
    let names: Vec<String> = bound
        .imports
        .iter()
        .map(|i| text(i.name.as_ref()))
        .collect();
    assert_eq!(names, vec!["ExitProcess", "Sleep"]);
    // An import by ordinal has no name and no hint.
    let (ord, _) = load_variant("ordinal_import");
    let first = ord.imports.first().expect("an import");
    assert_eq!(
        (first.name.is_none(), first.ordinal, first.hint),
        (true, Some(5), None)
    );
}

#[test]
fn vc6_delay_descriptor_vas() {
    let base = 0x40_0000;
    for (variant, image_base) in [("vc6_delay", base), ("delay_rva", EXE_BASE)] {
        let layout = pe::builder(variant).expect("variant").layout();
        let (b, _) = load_variant(variant);
        let got: Vec<Row> = b.imports.iter().map(row).collect();
        let slot = |i: usize| Some(image_base + u64::from(layout.delay_iat[0][i]));
        let dll = "beta.dll".to_owned();
        assert_eq!(
            got,
            vec![
                (
                    dll.clone(),
                    "beta_delayed".to_owned(),
                    None,
                    Some(0),
                    slot(0),
                    true
                ),
                (dll, String::new(), Some(9), None, slot(1), true),
            ],
            "{variant}"
        );
    }
    // A VA below the image base is corrupt delay data: a diagnostic, not a fatal error. The
    // patch moves `ImageBase` (optional header offset 24) above the VAs of the descriptor.
    let bytes = pe::builder("vc6_delay")
        .expect("variant")
        .patch(0x58 + 24, &0x80_0000u64.to_le_bytes())
        .build();
    let (b, _) = crate::support::load_ok(&bytes);
    assert!(b.imports.is_empty());
    assert!(!b.diagnostics.is_empty());
}

#[test]
fn exports_forwarders_and_counts() {
    let (b, _) = load_variant("exports");
    let base = pe::DLL_BASE;
    let got: Vec<ExportRow> = b
        .exports
        .iter()
        .map(|e| {
            (
                e.ordinal,
                text(e.name.as_ref()),
                e.addr,
                text(e.forwarder.as_ref()),
            )
        })
        .collect();
    let s = String::new;
    assert_eq!(
        got,
        vec![
            (Some(1), "add".to_owned(), Some(base + 0x1000), s()),
            (Some(2), "mul".to_owned(), Some(base + 0x1020), s()),
            (
                Some(3),
                "ExitNow".to_owned(),
                None,
                "kernel32.ExitProcess".to_owned()
            ),
            (Some(5), "AlphaFive".to_owned(), None, "alpha.#5".to_owned()),
            (Some(6), s(), Some(base + 0x1040), s()),
            (Some(7), "table".to_owned(), Some(base + 0x2000), s()),
        ]
    );
    let entries: Vec<u64> = b.entry_points.iter().map(|e| e.addr).collect();
    assert_eq!(entries, vec![base + 0x1000, base + 0x1020, base + 0x1040]);
    // A cycle of forwarders loads: the loader never follows a forwarder.
    let (cycle, _) = load_variant("forwarder_cycle");
    let fwd: Vec<String> = cycle
        .exports
        .iter()
        .map(|e| text(e.forwarder.as_ref()))
        .collect();
    assert_eq!(fwd, vec!["self.b", "self.a"]);
    // A huge `NumberOfNames` clamps to the bytes left, with a diagnostic.
    let (huge, _) = load_variant("huge_names");
    assert!(
        codes(&huge)
            .iter()
            .any(|c| matches!(c, DiagCode::Limit | DiagCode::Oob))
    );
    assert!(huge.exports.len() < 64, "{}", huge.exports.len());
}

#[test]
fn ac_247_basereloc_golden() {
    for name in IMAGES {
        let (b, _) = load_fixture(name);
        let want: Vec<(u64, u32)> = readobj(name)
            .child("BaseReloc")
            .expect("BaseReloc")
            .all("Entry")
            .filter_map(|e| {
                let kind = match e.get("Type") {
                    Some("DIR64") => 10,
                    Some("HIGHLOW") => 3,
                    _ => return None,
                };
                Some((b.image_base + e.num("Address"), kind))
            })
            .collect();
        let got: Vec<(u64, u32)> = b.relocs.iter().map(|r| (r.offset, r.kind.0)).collect();
        assert_eq!(got, want, "{name}");
    }
    let (b, _) = load_variant("relocs");
    let got: Vec<(u64, u32)> = b.relocs.iter().map(|r| (r.offset, r.kind.0)).collect();
    let page = EXE_BASE + 0x2000;
    assert_eq!(got, vec![(page, 10), (page + 8, 10), (page + 0x10, 3)]);
    let unsupported = codes(&b)
        .iter()
        .filter(|c| **c == DiagCode::UnsupportedReloc)
        .count();
    assert_eq!(unsupported, 1, "one diagnostic for each unknown type");
    for variant in ["block_size_0", "block_size_7"] {
        let (b, _) = load_variant(variant);
        assert!(b.relocs.is_empty(), "{variant}: the walk stops");
        assert!(codes(&b).contains(&DiagCode::Loop), "{variant}");
    }
}

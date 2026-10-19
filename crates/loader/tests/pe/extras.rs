//! AC-255 and the `.pdata`, TLS and debug tables: protections, the `CodeView` identity, the
//! `RUNTIME_FUNCTION` entries with their fragments and the TLS callbacks.

use std::fmt::Write;

use ghidorah_base::DiagCode;
use ghidorah_loader::{EntryKind, PeProtections, Protections};
use ghidorah_testkit::pe::EXE_BASE;

use crate::support::{
    IMAGES, codes, load_fixture, load_variant, read, readobj, truth, truth_field,
};

/// Gives a GUID in the 8-4-4-4-12 form of `llvm-readobj`, upper case.
fn guid_text(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let mut tail = String::new();
    for b in &g[10..] {
        let _ = write!(tail, "{b:02X}");
    }
    format!("{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{tail}", g[8], g[9])
}

#[test]
fn ac_255_pe_protections_identity() {
    for name in IMAGES {
        let (b, _) = load_fixture(name);
        let t = truth(name);
        let flag = |key: &str| truth_field(&t, key) == "true";
        let want = PeProtections {
            dynamic_base: flag("dynamic_base"),
            high_entropy_va: flag("high_entropy_va"),
            nx_compat: flag("nx_compat"),
            guard_cf: flag("guard_cf"),
            force_integrity: flag("force_integrity"),
        };
        assert_eq!(b.protections, Some(Protections::Pe(want)), "{name}");
        let cv = b.identity.codeview.as_ref().expect("a CodeView record");
        assert_eq!(guid_text(&cv.guid), truth_field(&t, "guid"), "{name}");
        assert_eq!(cv.age.to_string(), truth_field(&t, "age"), "{name}");
        assert_eq!(
            cv.pdb.as_str(),
            Some(truth_field(&t, "pdb").as_str()),
            "{name}"
        );
    }
    let (b, _) = load_variant("codeview");
    let cv = b.identity.codeview.expect("a CodeView record");
    assert_eq!(guid_text(&cv.guid), "F08D7E34-3817-8A43-4C4C-44205044422E");
    assert_eq!((cv.age, cv.pdb.as_str()), (3, Some("C:\\build\\test.pdb")));
    let (plain, _) = load_variant("minimal");
    assert_eq!(plain.identity.codeview, None);
    let guid = [
        0x34, 0x7e, 0x8d, 0xf0, 0x17, 0x38, 0x43, 0x8a, 0x4c, 0x4c, 0x44, 0x20, 0x50, 0x44, 0x42,
        0x2e,
    ];
    assert_eq!(
        ghidorah_loader::pe::guid_text(&guid),
        "F08D7E34-3817-8A43-4C4C-44205044422E"
    );
}

#[test]
fn pdata_entries_and_fragments() {
    for name in IMAGES {
        let (b, _) = load_fixture(name);
        let want: Vec<(u64, u64, u64)> = readobj(name)
            .child("UnwindInformation")
            .expect("UnwindInformation")
            .all("RuntimeFunction")
            .map(|f| {
                (
                    f.num("StartAddress") - b.image_base,
                    f.num("EndAddress") - b.image_base,
                    f.num("UnwindInfoAddress") - b.image_base,
                )
            })
            .collect();
        let got: Vec<(u64, u64, u64)> = b
            .pdata
            .iter()
            .map(|p| (u64::from(p.begin), u64::from(p.end), u64::from(p.unwind)))
            .collect();
        assert_eq!(got, want, "{name}");
        assert!(b.pdata.iter().all(|p| !p.fragment), "{name}: no CHAININFO");
    }
    let (b, _) = load_variant("chain");
    let flags: Vec<bool> = b.pdata.iter().map(|p| p.fragment).collect();
    assert_eq!(flags, vec![false, true]);
    assert!(!codes(&b).contains(&DiagCode::Loop));
}

#[test]
fn pdata_chain_cycle_stops() {
    let (b, _) = load_variant("chain_cycle");
    assert_eq!(b.pdata.len(), 2);
    assert!(b.pdata.iter().all(|p| p.fragment));
    assert!(codes(&b).contains(&DiagCode::Loop), "{:?}", b.diagnostics);
    // Bad ranges give `E_OOB`, and the good entry stays.
    let (bad, _) = load_variant("pdata_bad");
    assert!(
        codes(&bad).contains(&DiagCode::Oob),
        "{:?}",
        bad.diagnostics
    );
    let begins: Vec<u32> = bad.pdata.iter().map(|p| p.begin).collect();
    assert_eq!(begins, vec![0x1000]);
}

#[test]
fn tls_callbacks_and_limit() {
    let (b, map) = load_fixture("pe_main.exe");
    let gold = readobj("pe_main.exe");
    let tls = gold.child("TLSDirectory").expect("TLSDirectory");
    let array = tls.num("AddressOfCallBacks");
    let mut want = Vec::new();
    for i in 0.. {
        let bytes = read(&map, array + 8 * i, 8);
        let va = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
        if va == 0 {
            break;
        }
        want.push(va);
    }
    let got: Vec<u64> = b
        .entry_points
        .iter()
        .filter(|e| e.kind == EntryKind::TlsCallback)
        .map(|e| e.addr)
        .collect();
    assert_eq!(got, want);
    assert_eq!(want.len(), 1);
    let (one, _) = load_variant("tls_one");
    let n = |b: &ghidorah_loader::Binary| {
        b.entry_points
            .iter()
            .filter(|e| e.kind == EntryKind::TlsCallback)
            .count()
    };
    assert_eq!(n(&one), 1);
    assert!(one.entry_points.iter().any(|e| e.addr == EXE_BASE + 0x1000));
    let (many, _) = load_variant("tls_257");
    assert_eq!(n(&many), 256);
    assert!(codes(&many).contains(&DiagCode::Limit));
}

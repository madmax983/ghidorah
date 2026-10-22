//! The gap worklist: unowned code, padding and the `func_edit create` remedy.

use ghidorah_analysis::analyzers::gaps::{self, Gap, SHOW_BYTES};
use ghidorah_analysis::analyzers::metrics::Remedy;
use ghidorah_base::Range;
use ghidorah_json::Value;

use crate::blobs::{BASE, Blob};
use crate::support::{all_t1, analyze, json_at, name_of, truth_paths};

/// Gives the gap items of a truth file as `(addr, size, first_insn)`.
fn truth_gaps(truth: &Value) -> Vec<(u64, u64, String)> {
    truth
        .get("gaps")
        .and_then(Value::as_array)
        .expect("gaps")
        .iter()
        .map(|g| {
            let addr = g.get("addr").and_then(Value::as_str).expect("addr");
            let size = g.get("size").and_then(Value::as_u64).expect("size");
            let insn = g.get("first_insn").and_then(Value::as_str).expect("insn");
            (
                ghidorah_base::hex::parse_u64(addr).expect("hex"),
                size,
                insn.to_owned(),
            )
        })
        .collect()
}

/// Gives a gap as `(addr, size, first_insn)` with the objdump spacing of the truth files.
fn shape(g: &Gap) -> (u64, u64, String) {
    let size = u64::try_from(g.range.len()).expect("a small gap");
    let insn = g.first_insn.clone().unwrap_or_default().replace(", ", ",");
    (g.range.first, size, insn)
}

#[test]
fn gaps_match_truth() {
    let mut seen = 0;
    for (path, truth) in truth_paths() {
        let p = &all_t1()
            .iter()
            .find(|(f, _)| *f == path)
            .expect("the fixture")
            .1;
        let expect = truth_gaps(&json_at(&truth));
        let got: Vec<(u64, u64, String)> = gaps::items(p).iter().map(shape).collect();
        let name = name_of(&path);
        if name.split('.').any(|part| part == "noeh") {
            for g in &expect {
                assert!(got.contains(g), "{path}: {g:?} is a gap");
            }
        } else {
            assert_eq!(
                got, expect,
                "{path}: with unwind data each function has a start"
            );
        }
        seen += expect.len();
    }
    assert!(seen >= 6, "the crackme builds hold gaps");
}

#[test]
fn gap_item_shape() {
    let p = &all_t1()
        .iter()
        .find(|(f, _)| name_of(f) == "crackme.gcc-O2.stripped")
        .expect("the fixture")
        .1;
    let items = gaps::items(p);
    assert_eq!(items.len(), 1);
    let g = &items[0];
    assert_eq!(g.range, Range::new(0x11d0, 0x11d7).expect("a range"));
    assert_eq!(g.bytes, [0xb8, 0x37, 0x13, 0x00, 0x00, 0x31, 0xf8, 0xc3]);
    assert!(g.bytes.len() <= SHOW_BYTES);
    assert_eq!(g.first_insn.as_deref(), Some("mov eax, 0x1337"));
    assert_eq!(g.remedy(), Remedy::Create(0x11d0));
    let args = ghidorah_json::write(&g.remedy().args());
    assert_eq!(args, r#"{"action":"create","target":"0x11d0"}"#);
}

#[test]
fn padding_splits_gaps() {
    let blob = Blob::new()
        .ret() // 0x00: the entry function
        .raw(&[0xcc, 0xcc, 0xcc, 0x90, 0x90, 0x00, 0x00, 0x0f, 0x1f, 0x00])
        .mov_eax(1) // 0x0b
        .ret() // 0x10
        .raw(&[0xcc, 0x06]) // 0x12: a byte that does not decode
        .ret(); // 0x13
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    let items = gaps::items(&p);
    let got: Vec<(u64, u64, Option<&str>)> = items
        .iter()
        .map(|g| {
            (
                g.range.first - BASE,
                u64::try_from(g.range.len()).expect("small"),
                g.first_insn.as_deref(),
            )
        })
        .collect();
    assert_eq!(got, [(0x0b, 6, Some("mov eax, 0x1")), (0x12, 2, None)]);
    let all_padding = Blob::new().ret().raw(&[0xcc; 7]).raw(&[0; 8]);
    let mut p = all_padding.load(Some(0));
    let _ = analyze(&mut p);
    assert_eq!(gaps::items(&p), [], "padding alone is not a gap");
}

/// The owned set of the gaps goes in by start. An unstripped binary has an FDE and a
/// function symbol for each function. Each symbol went in after all FDEs, in the middle of
/// the set, and copied its tail. So the gaps of 100,000 functions took seconds.
#[test]
fn regress_gap_sets_many_symbols() {
    use ghidorah_loader::LoadOpts;
    use ghidorah_testkit::elf::{ElfBuilder, Fde, Loc, Section, Symbol};
    const N: u64 = 100_000;
    const BODY: [u8; 16] = [
        0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc,
    ];
    let text: Vec<u8> = (0..N).flat_map(|_| BODY).collect();
    let mut elf = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .entry(Loc::section(".text", 0));
    for i in 0..N {
        let at = Loc::section(".text", i * 16);
        elf = elf
            .fde(Fde::frame_pointer(at.clone(), 6))
            .symbol(Symbol::func(
                &format!("f{i}"),
                Loc::section(".text", i * 16 + 8),
                2,
            ));
    }
    let program = crate::support::program_of(&elf.build(), &LoadOpts::AUTO);
    let started = std::time::Instant::now();
    let items = gaps::items(&program);
    let took = started.elapsed();
    assert!(
        items.len() < 2,
        "the FDEs and symbols own the code: {}",
        items.len()
    );
    assert!(
        took < std::time::Duration::from_secs(2),
        "the gaps of {N} functions take {took:?}"
    );
}

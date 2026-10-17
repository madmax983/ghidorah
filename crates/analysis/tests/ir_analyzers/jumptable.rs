//! Method A over the published facts of the discovery analyzers (design Section 7.8).

use std::collections::BTreeMap;

use ghidorah_analysis::fir::Image;
use ghidorah_analysis::jumptable::{self, Failure};
use ghidorah_analysis::{EdgeKind, cfg};
use ghidorah_base::{Address, Fuel, JumpTableId, TxId};
use ghidorah_db::{Edit, JtMethod, JumpTable, Origin, Program, SessionLabel, Source};
use ghidorah_loader::Perms;

use crate::blob::{BASE, Rom, load, pad};
use crate::support::{cached, fir_of, fixtures, hex, list, truth, truth_funcs};

/// Tells if `at` is in an executable region of `p`.
fn exec(p: &Program, at: u64) -> bool {
    p.mem()
        .region_at(at)
        .is_some_and(|r| r.perms.contains(Perms::EXECUTE))
}

/// The counts of a method A run over truth tables.
#[derive(Debug, Default)]
struct Score {
    total: usize,
    right: usize,
    wrong: Vec<String>,
}

/// Runs method A at each indirect jump of each truth function with a table.
fn score(path: &str, truth_path: &str, out: &mut Score) {
    let p = cached(path);
    let t = truth(truth_path);
    let funcs = truth_funcs(&t);
    let mut by_func: BTreeMap<u64, Vec<&ghidorah_json::Value>> = BTreeMap::new();
    for table in list(&t, "jump_tables") {
        let name = table.get("func").and_then(|v| v.as_str()).expect("a name");
        by_func.entry(funcs[name]).or_default().push(table);
    }
    for (entry, tables) in by_func {
        let ir = fir_of(p, entry);
        let mut found = BTreeMap::new();
        for site in jumptable::sites(&ir) {
            let accept = |t: u64| exec(p, t);
            if let Ok(r) =
                jumptable::method_a(&ir, &Image(p), site, &accept, &mut Fuel::new(1_000_000))
            {
                found.insert(r.base, r);
            }
        }
        for table in tables {
            out.total += 1;
            let base = hex(table.get("table").expect("a table base"));
            let want: Vec<u64> = table
                .get("targets")
                .and_then(|v| v.as_array())
                .expect("targets")
                .iter()
                .map(hex)
                .collect();
            match found.get(&Some(base)) {
                Some(r) if r.targets == want => out.right += 1,
                Some(r) => out
                    .wrong
                    .push(format!("{path}: {base:#x}: {:x?}", r.targets)),
                None => {}
            }
        }
    }
}

#[test]
fn method_a_on_truth_tables() {
    let mut s = Score::default();
    for f in fixtures() {
        if f.variant == "none" && !list(&truth(&f.truth), "jump_tables").is_empty() {
            score(&f.path, &f.truth, &mut s);
        }
    }
    assert!(s.total > 200, "the truth files hold tables: {}", s.total);
    assert!(s.wrong.is_empty(), "wrong targets: {:?}", s.wrong);
    assert!(
        s.right * 100 >= s.total * 95,
        "method A resolves {} of {} tables",
        s.right,
        s.total
    );
}

#[test]
fn method_a_failures() {
    // 0x0: cmp edi, 2; ja 0x30; lea rdx, [rip+0x40-0x10]; movsxd rax, [rdx+rdi*4];
    // add rax, rdx; jmp rax.  0x30: ret.  0x40: the table.
    let code = [
        0x83, 0xff, 0x02, 0x77, 0x2b, 0x48, 0x8d, 0x15, 0x34, 0x00, 0x00, 0x00, 0x48, 0x63, 0x04,
        0xba, 0x48, 0x01, 0xd0, 0xff, 0xe0,
    ];
    let mut bytes = pad(code.to_vec(), 0x30);
    bytes.push(0xc3);
    bytes = pad(bytes, 0x40);
    // Entries 0x30 - 0x40, 0x30 - 0x40 and 0x15 - 0x40 (an address in the padding).
    for rel in [-0x10i32, -0x10, -0x2b] {
        bytes.extend_from_slice(&rel.to_le_bytes());
    }
    let mut p = load(&bytes, 0);
    let _ = crate::support::analyze(&mut p);
    let ir = fir_of(&p, BASE);
    let site = BASE + 0x13;
    assert_eq!(jumptable::sites(&ir), [site]);
    let rom = Rom(&bytes);
    let any = |_: u64| true;
    let r = jumptable::method_a(&ir, &rom, site, &any, &mut Fuel::unlimited())
        .expect("the table resolves");
    assert_eq!(r.base, Some(BASE + 0x40));
    assert_eq!(r.entry_size, 4);
    assert_eq!(r.targets, [BASE + 0x30, BASE + 0x30, BASE + 0x15]);
    let code_only = |t: u64| t == BASE + 0x30;
    assert_eq!(
        jumptable::method_a(&ir, &rom, site, &code_only, &mut Fuel::unlimited()),
        Err(Failure::Target {
            target: BASE + 0x15
        })
    );
    assert_eq!(
        jumptable::method_a(&ir, &rom, BASE, &any, &mut Fuel::unlimited()),
        Err(Failure::NoSite)
    );
    assert_eq!(
        jumptable::method_a(
            &ir,
            &Rom(&bytes[..0x40]),
            site,
            &any,
            &mut Fuel::unlimited()
        ),
        Err(Failure::Slice { idx: 0 }),
        "no table bytes"
    );
    // A jump with no guard.
    let bytes = [0x48, 0x8b, 0x07, 0xff, 0xe0];
    let mut p = load(&bytes, 0);
    let _ = crate::support::analyze(&mut p);
    let ir = fir_of(&p, BASE);
    assert_eq!(
        jumptable::method_a(&ir, &Rom(&bytes), BASE + 3, &any, &mut Fuel::unlimited()),
        Err(Failure::NoGuard)
    );
    for f in [
        Failure::NoSite,
        Failure::NoGuard,
        Failure::Slice { idx: 1 },
        Failure::Target { target: 2 },
        Failure::TooMany { count: 3000 },
    ] {
        assert!(f.to_string().ends_with('.'));
    }
}

#[test]
fn regress_unresolved_table_edge() {
    // mov rax, [rdi]; jmp rax with an unresolved record: the CFG keeps the unresolved edge.
    let mut p = load(&[0x48, 0x8b, 0x07, 0xff, 0xe0], 0);
    let _ = crate::support::analyze(&mut p);
    let site = Address::ram(BASE + 3);
    let label = SessionLabel::new("test").expect("a label");
    let next = p.last_tx().0.checked_add(1).expect("a free ID");
    let o = Origin::new(Source::Agent, TxId(next), label.clone(), false);
    let mut tx = p.begin("test", Source::Agent, label).expect("a Tx");
    let edit = Edit::SetJumpTable {
        id: JumpTableId(site),
        table: Some(o.fact(JumpTable {
            base: None,
            entry_size: 0,
            count: 0,
            targets: Vec::new(),
            method: JtMethod::Agent,
            resolved: false,
        })),
    };
    assert!(tx.apply(edit).is_ok(), "the record applies");
    assert!(tx.commit().is_ok(), "the record commits");
    let g = cfg::build(&p, crate::support::fid(BASE)).expect("a CFG");
    assert!(
        g.edges
            .iter()
            .any(|e| e.from == BASE && e.to.is_none() && e.kind == EdgeKind::IndirectUnresolved),
        "{:?}",
        g.edges
    );
}

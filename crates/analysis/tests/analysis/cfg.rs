//! The CFG of a function and its invariants (AC-083).

use std::collections::BTreeSet;

use ghidorah_analysis::cfg::{self, Block, CfgViolation, Edge, EdgeKind, FuncCfg};
use ghidorah_base::{Address, FuncId, JumpTableId};
use ghidorah_db::{Edit, JtMethod, JumpTable, SessionLabel, Source};

use crate::blobs::{BASE, Blob};
use crate::support::{all_t1, analyze};

fn kinds(g: &FuncCfg) -> Vec<(u64, Option<u64>, EdgeKind)> {
    g.edges
        .iter()
        .map(|e| (e.from - BASE, e.to.map(|t| t.off - BASE), e.kind))
        .collect()
}

#[test]
fn ac_083_cfg_invariants() {
    let mut funcs = 0usize;
    for (path, p) in all_t1() {
        for view in p.funcs() {
            funcs += 1;
            let g = cfg::build(p, view.id()).expect("a CFG");
            let found = cfg::check(&g);
            assert!(found.is_empty(), "{path}: {}: {found:?}", view.id());
            let mut seen = BTreeSet::new();
            for block in &g.blocks {
                for (at, _) in &block.insns {
                    assert!(seen.insert(*at), "{path}: {at:#x} is in two blocks");
                    assert!(view.func.body.contains(*at));
                }
            }
            let units: usize = view
                .func
                .body
                .ranges()
                .iter()
                .map(|r| p.analysis().listing().units_in(*r).count())
                .sum();
            assert_eq!(
                units,
                seen.len(),
                "{path}: {}: each unit is in a block",
                view.id()
            );
        }
    }
    assert!(funcs > 1_500, "the fixtures hold functions: {funcs}");
}

#[test]
fn edges_of_a_small_function() {
    // 0x0: je 0x10; call 0x20; jmp 0x30.  0x10: ret.  0x20: ret.  0x30: jmp rax.
    let blob = Blob::new()
        .je(0x10)
        .call(0x20)
        .jmp(0x30)
        .at(0x10)
        .ret()
        .at(0x20)
        .ret()
        .at(0x30)
        .jmp_rax();
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    let g = cfg::build(&p, FuncId(Address::ram(BASE))).expect("a CFG");
    assert!(cfg::check(&g).is_empty(), "{:?}", cfg::check(&g));
    let starts: Vec<u64> = g.blocks.iter().map(|b| b.start - BASE).collect();
    assert_eq!(starts, [0x0, 0x6, 0xb, 0x10, 0x30]);
    assert_eq!(
        kinds(&g),
        [
            (0x0, Some(0x10), EdgeKind::CondTrue),
            (0x0, Some(0x6), EdgeKind::CondFalse),
            (0x6, Some(0xb), EdgeKind::CallReturn),
            (0xb, Some(0x30), EdgeKind::Branch),
            (0x30, None, EdgeKind::IndirectUnresolved),
        ]
    );
    let callee = cfg::build(&p, FuncId(Address::ram(BASE + 0x20))).expect("a CFG");
    assert_eq!(callee.blocks.len(), 1);
    assert!(callee.edges.is_empty());
    assert!(cfg::build(&p, FuncId(Address::ram(BASE + 0x7))).is_none());
    assert_eq!(EdgeKind::SwitchCase(3).name(), "switch_case");
    assert!(!EdgeKind::TailCall.is_internal());
}

#[test]
fn tail_calls_leave_the_body() {
    // 0x0: call 0x10; ret.  0x10: jmp 0x20.  0x20: ret.  0x20 is a function, so 0x10 tail calls.
    let blob = Blob::new()
        .call(0x10)
        .call(0x20)
        .ret()
        .at(0x10)
        .jmp(0x20)
        .at(0x20)
        .ret();
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    let g = cfg::build(&p, FuncId(Address::ram(BASE + 0x10))).expect("a CFG");
    assert_eq!(kinds(&g), [(0x10, Some(0x20), EdgeKind::TailCall)]);
    assert!(cfg::check(&g).is_empty());
}

#[test]
fn check_finds_each_violation() {
    let f = FuncId(Address::ram(0x100));
    let block = |start: u64, insns: &[(u64, u8)]| Block {
        start,
        insns: insns.to_vec(),
    };
    let edge = |from: u64, to: u64| Edge {
        from,
        to: Some(Address::ram(to)),
        kind: EdgeKind::Branch,
    };
    let empty = FuncCfg {
        func: f,
        blocks: Vec::new(),
        edges: Vec::new(),
    };
    assert_eq!(cfg::check(&empty), [CfgViolation::NoEntryBlock]);
    let g = FuncCfg {
        func: f,
        blocks: vec![
            block(0x100, &[(0x100, 2), (0x103, 1)]),
            block(0x103, &[(0x103, 1)]),
            block(0x110, &[(0x110, 1)]),
        ],
        edges: vec![edge(0x100, 0x105)],
    };
    let found = cfg::check(&g);
    assert!(
        found.contains(&CfgViolation::Gap { block: 0x100 }),
        "{found:?}"
    );
    assert!(found.contains(&CfgViolation::Overlap { block: 0x103 }));
    assert!(found.contains(&CfgViolation::EdgeTarget {
        from: 0x100,
        to: 0x105
    }));
    assert!(found.contains(&CfgViolation::Unreachable { block: 0x110 }));
    assert_eq!(g.blocks[0].end(), 0x104);
    let empty = Block {
        start: 0x200,
        insns: Vec::new(),
    };
    assert_eq!(empty.end(), 0x200);
}

#[test]
fn jump_table_cases_are_switch_edges() {
    // 0x0: je 0x20; jmp rax (at 0x6).  0x20: ret.  0x30 is a case outside the body.
    let blob = Blob::new().je(0x20).jmp_rax().at(0x20).ret().at(0x30).ret();
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("test", Source::Agent, label)
        .expect("a transaction");
    let table = JumpTable {
        base: None,
        entry_size: 0,
        count: 2,
        targets: vec![Address::ram(BASE + 0x20), Address::ram(BASE + 0x30)],
        method: JtMethod::Agent,
        resolved: true,
    };
    let fact = tx.fact(table);
    tx.apply(Edit::SetJumpTable {
        id: JumpTableId(Address::ram(BASE + 6)),
        table: Some(fact),
    })
    .expect("the table applies");
    tx.commit().expect("a commit");
    let g = cfg::build(&p, FuncId(Address::ram(BASE))).expect("a CFG");
    assert!(cfg::check(&g).is_empty(), "{:?}", cfg::check(&g));
    assert_eq!(
        kinds(&g),
        [
            (0x0, Some(0x20), EdgeKind::CondTrue),
            (0x0, Some(0x6), EdgeKind::CondFalse),
            (0x6, Some(0x20), EdgeKind::SwitchCase(0)),
            (0x6, Some(0x30), EdgeKind::TailCall),
        ]
    );
    assert_eq!(EdgeKind::CondFalse.to_string(), "cond_false");
}

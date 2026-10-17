//! An unresolved indirect jump prints `goto *(..)` and never `return` (AC-108).

use std::collections::BTreeSet;

use ghidorah_base::{Fuel, WarningCode};
use ghidorah_decomp::{Exit, Expr, Input, NoEnv, Opts, Stmt};
use ghidorah_ir::ssa;
use ghidorah_ir::{Arg, Builder, Loc, Opc, Switches};

use crate::progs::{body_with, pool_opts};

#[test]
fn ac_108_computed_goto() {
    let mut b = Builder::new();
    b.begin(0x1000, 4).expect("in order");
    let x = b.get(Loc::RDI).expect("get");
    let slot = b.binary(Opc::Shl, 64, x.into(), Arg::k(3)).expect("shl");
    let addr = b
        .binary(Opc::Add, 64, slot.into(), Arg::k(0x4000))
        .expect("add");
    let target = b.load(64, addr.into()).expect("load");
    b.begin(0x1004, 4).expect("in order");
    b.flow(Opc::JumpInd, target.into(), Arg::Nil).expect("jmp");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000], &[]);
    assert!(
        body.cfg.succs(body.cfg.entry()).is_empty(),
        "no case is known"
    );
    let mut l1 = ssa::build(arena.clone(), body, &pool_opts(), &mut Fuel::unlimited())
        .expect("the SSA build");
    let _ = ghidorah_ir::passes::run(&mut l1, &Switches::all(), &mut Fuel::unlimited())
        .expect("the passes run");
    let tails = BTreeSet::new();
    let input = Input {
        ssa: &l1,
        l0: &arena,
        tail_calls: &tails,
        conv: None,
    };
    let d = ghidorah_decomp::from_input(&input, &NoEnv, &Opts::default(), &mut Fuel::unlimited())
        .expect("the decompile");
    let entry = d.view.shape.entry;
    assert_eq!(d.view.shape.nodes[entry.index()].exit, Exit::Stop);
    let stmts = &d.view.nodes[entry.index()].stmts;
    assert!(
        matches!(
            stmts.last(),
            Some(Stmt::Goto {
                target: Expr::Load { .. },
                ..
            })
        ),
        "{stmts:#?}"
    );
    assert!(
        !d.view
            .nodes
            .iter()
            .flat_map(|n| &n.stmts)
            .any(|s| matches!(s, Stmt::Return { .. })),
        "no return"
    );
    assert!(
        d.warnings
            .iter()
            .any(|w| w.code == WarningCode::JumptableUnresolved && w.at == 0x1004),
        "{:?}",
        d.warnings
    );
}

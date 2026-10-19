//! Regression tests of the decompiler core.

use std::sync::mpsc;
use std::time::Duration;

use ghidorah_decomp::interp_ast;
use ghidorah_decomp::{LoopKind, Opts, Tree};
use ghidorah_ir::{Arg, Builder, Config, Loc, NoImage, Opc, StopReason};

use crate::progs::{Program, body_with, decompile, l1_of};

/// A pure `do .. while` loop whose condition stays true ends on fuel in the value mode.
#[expect(
    clippy::many_single_char_names,
    reason = "the test program names each IR value with one letter"
)]
#[test]
fn regress_pure_loop_takes_fuel() {
    let mut b = Builder::new();
    b.begin(0x1000, 4).expect("in order");
    let x = b.get(Loc::RDI).expect("get");
    let c = b.binary(Opc::Eq, 64, x.into(), Arg::k(0)).expect("eq");
    b.put(Loc::RAX, c.into()).expect("put");
    b.begin(0x1004, 4).expect("in order");
    let y = b.get(Loc::RAX).expect("get");
    b.flow(Opc::CJump, y.into(), Arg::k(0x1004)).expect("jcc");
    b.begin(0x1008, 4).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000, 0x1004, 0x1008], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x1000,
        setup: vec![(Loc::RDI, 0)],
    };
    let ssa = l1_of(&p);
    let d = decompile(&p, &ssa, &Opts::default());
    let has_loop = d.tree.preorder().iter().any(|t| {
        matches!(
            t,
            Tree::Loop {
                kind: LoopKind::DoWhile,
                ..
            }
        )
    });
    assert!(has_loop, "{:?}", d.tree);
    let (tx, rx) = mpsc::channel();
    let setup = p.setup;
    std::thread::spawn(move || {
        let out = interp_ast::run(&d, &NoImage, &Config::default(), &setup, 1_000);
        let _ = tx.send(out.reason);
    });
    let reason = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the value run ends on fuel");
    assert_eq!(reason, StopReason::FuelExhausted);
}

/// The fuzz target `pipeline_elf` found a function of 100,000 instructions in one block: a
/// region of zero fill. The view of one block compared each instruction with every op of the
/// block, so the decompile took minutes. A block of 40,000 instructions now ends in seconds.
#[test]
fn regress_long_block_view_is_not_quadratic() {
    const COUNT: u64 = 40_000;
    let mut b = Builder::new();
    for k in 0..COUNT {
        b.begin(0x1000 + k, 1).expect("in order");
        let x = b.get(Loc::RAX).expect("get");
        let y = b.binary(Opc::Add, 64, x.into(), Arg::k(1)).expect("add");
        b.put(Loc::RAX, y.into()).expect("put");
    }
    b.begin(0x1000 + COUNT, 1).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x1000,
        setup: Vec::new(),
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let ssa = l1_of(&p);
        let d = decompile(&p, &ssa, &Opts::default());
        let _ = tx.send(d.tree.preorder().len());
    });
    let nodes = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the decompile of one long block ends in 10 s");
    assert!(nodes > 0);
}

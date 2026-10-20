//! Regression tests of the decompiler core.

use std::sync::mpsc;
use std::time::Duration;

use ghidorah_decomp::{ElideReason, Elided, Line, LineKind, LoopKind, Opts, Tree};
use ghidorah_decomp::{interp_ast, linemap};
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

/// Gives a statement line with the address range `span`.
fn line_at(span: (u64, u64)) -> Line {
    Line {
        text: "x;".to_owned(),
        kind: LineKind::Stmt,
        depth: 1,
        ops: Vec::new(),
        span: Some(span),
        comment: None,
        calls: Vec::new(),
        strings: Vec::new(),
    }
}

/// A range that ends at the top address holds its last byte. The old half-open ranges of the
/// line map saturated at `u64::MAX`, so they lost that byte (verification-07).
#[test]
fn regress_linemap_covers_top_byte() {
    let top = Elided {
        start: u64::MAX,
        size: 1,
        reason: ElideReason::Padding,
    };
    assert!(linemap::covered(&[], &[top], u64::MAX));
    assert!(!linemap::covered(&[], &[top], u64::MAX - 1));
    let two = Elided {
        start: u64::MAX - 1,
        size: 2,
        reason: ElideReason::Padding,
    };
    assert!(linemap::covered(&[], &[two], u64::MAX));
    assert!(linemap::covered(&[], &[two], u64::MAX - 1));
    let line = line_at((u64::MAX - 1, 2));
    assert!(linemap::covered(std::slice::from_ref(&line), &[], u64::MAX));
    assert!(!linemap::covered(&[line], &[], u64::MAX - 2));
    let past = Elided {
        start: u64::MAX - 1,
        size: 8,
        reason: ElideReason::Padding,
    };
    assert!(linemap::covered(&[], &[past], u64::MAX));
    let merged = linemap::merge(vec![two, top]);
    assert_eq!(merged, vec![two, top], "{merged:?}");
}

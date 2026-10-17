//! Unit tests of the public helpers, the FLAT reasons and the stops of the value mode.

use std::collections::BTreeSet;

use ghidorah_base::{Fuel, WarningCode};
use ghidorah_decomp::interp_ast::{self, End, Seeded, cfg_trace, tree_trace};
use ghidorah_decomp::structure::{self, MAX_DEPTH};
use ghidorah_decomp::view::ViewError;
use ghidorah_decomp::{
    Call, Callee, Cond, DecompError, ElideReason, Exit, Expr, FlatReason, Input, LoopKind, Mode,
    NoEnv, Opts, Passes, Shape, Stmt, Tree, VarIdx, flat,
};
use ghidorah_ir::{
    Arg, Builder, Config, Effect, FlatImage, IntrinsicId, Loc, LocSet, MemEffect, NoImage, Node,
    OpId, Opc, StopReason,
};

use crate::progs::{Program, body_with, decompile, l1_of};
use crate::shapes::{node, shape_of};

const AT: OpId = OpId { addr: 0x10, seq: 1 };

fn var(v: u32) -> Expr {
    Expr::Var {
        var: VarIdx(v),
        w: 64,
    }
}

#[test]
fn names_and_errors() {
    assert_eq!(Mode::Structured.fallback_mode(), "none");
    assert_eq!(Mode::Flat(FlatReason::Fuel).fallback_mode(), "flat");
    for (r, name, budget) in [
        (FlatReason::MaxNodes, "max_nodes", true),
        (FlatReason::Fuel, "fuel", true),
        (FlatReason::Depth, "depth", true),
        (FlatReason::NoProgress, "no_progress", false),
        (FlatReason::SelfCheck, "selfcheck", false),
    ] {
        assert_eq!(r.name(), name);
        assert_eq!(r.is_budget(), budget);
    }
    assert_eq!(ElideReason::Canary.name(), "stack canary");
    assert_eq!(ElideReason::Unreachable.name(), "unreachable");
    assert!(Passes::default().fold && !Passes::NONE.sailr);
    assert_eq!(
        Opts::default().max_nodes,
        ghidorah_decomp::DEFAULT_MAX_NODES
    );
    for e in [
        ViewError::OutOfFuel,
        ViewError::NoEntry,
        ViewError::TooLarge,
    ] {
        assert!(!e.to_string().is_empty());
        assert!(DecompError::View(e).to_string().contains("view"));
    }
    let l1 = ghidorah_analysis::fir::l1::L1Error::Ssa(ghidorah_ir::SsaError::Full);
    assert!(DecompError::from(l1).to_string().contains("L1"));
}

#[test]
fn expr_and_stmt_helpers() {
    let load = Expr::Load {
        w: 32,
        addr: Box::new(var(1)),
        at: AT,
    };
    let cmp = Expr::Bin {
        op: Opc::ULt,
        w: 64,
        sub: 0,
        x: Box::new(var(2)),
        y: Box::new(Expr::Const { value: 3, w: 64 }),
        at: AT,
    };
    let ite = Expr::Ite {
        op: Opc::Flags,
        w: 32,
        sub: 0,
        a: Box::new(load.clone()),
        b: Box::new(cmp.clone()),
        c: Box::new(Expr::Str { addr: 0x40 }),
        at: AT,
    };
    let un = Expr::Un {
        op: Opc::Not,
        w: 8,
        sub: 0,
        x: Box::new(var(4)),
        at: AT,
    };
    assert_eq!(
        (load.width(), cmp.width(), ite.width(), un.width()),
        (32, 1, 16, 8)
    );
    assert_eq!(Expr::Str { addr: 1 }.width(), 64);
    assert_eq!(var(1).at(), None);
    assert_eq!(load.at(), Some(AT));
    assert_eq!(ite.vars(), vec![VarIdx(1), VarIdx(2)]);
    assert_eq!(ite.preorder().len(), 7);
    let call = Call {
        callee: Callee::Indirect(var(5)),
        args: vec![(Loc::RDI, var(6))],
        mem: Some(var(7)),
        rets: vec![(Loc::RAX, VarIdx(8))],
        ret: Some(Loc::RAX),
        noreturn: false,
        tail: true,
        at: AT,
    };
    let as_expr = Expr::Call(Box::new(call.clone()));
    assert_eq!(as_expr.width(), 64);
    assert_eq!(as_expr.at(), Some(AT));
    assert_eq!(as_expr.vars(), vec![VarIdx(5), VarIdx(6), VarIdx(7)]);
    let stmts = [
        Stmt::Assign {
            var: VarIdx(1),
            value: un,
            at: AT,
        },
        Stmt::Store {
            w: 8,
            addr: var(1),
            value: var(2),
            at: AT,
        },
        Stmt::Call(call),
        Stmt::Return {
            uses: vec![(Loc::RAX, var(3))],
            at: AT,
        },
        Stmt::Goto {
            target: load,
            at: AT,
        },
    ];
    let ends: Vec<bool> = stmts.iter().map(Stmt::ends).collect();
    assert_eq!(ends, [false, false, true, true, true]);
    assert!(stmts.iter().all(|s| s.at() == AT));
    let counts: Vec<usize> = stmts.iter().map(|s| s.exprs().len()).collect();
    assert_eq!(counts, [1, 2, 3, 1, 1]);
    assert_eq!(VarIdx(3).index(), 3);
}

#[test]
fn tree_and_cond_helpers() {
    let c = Cond::And(
        Box::new(Cond::leaf(node(0))),
        Box::new(Cond::leaf(node(1)).with_exec()),
    );
    let n = c.clone().negate();
    assert!(matches!(n, Cond::Or(..)));
    assert_eq!(n.negate(), c);
    assert_eq!(c.nodes(), vec![node(0), node(1)]);
    let t = Tree::Seq(vec![
        Tree::Label(node(0)),
        Tree::Block(node(0)),
        Tree::If {
            cond: c,
            then: Box::new(Tree::Goto(node(0))),
            els: Some(Box::new(Tree::Break(node(2)))),
        },
        Tree::Loop {
            kind: LoopKind::While,
            cond: Some(Cond::leaf(node(3)).with_exec()),
            body: Box::new(Tree::Continue(node(3))),
            head: node(3),
            follow: None,
        },
        Tree::Switch {
            on: node(4),
            arms: vec![ghidorah_decomp::Arm {
                cases: vec![0],
                body: Tree::empty(),
            }],
            follow: None,
        },
    ]);
    assert_eq!(t.nodes(), vec![node(0), node(1), node(3)]);
    assert_eq!(t.labels(), vec![node(0)]);
    assert_eq!(t.gotos(), vec![node(0)]);
    assert_eq!(t.depth(), 3);
    assert_eq!(t.children().len(), 5);
    assert_eq!(
        Tree::Block(node(1)).then(Tree::empty()),
        Tree::Seq(vec![Tree::Block(node(1))])
    );
}

#[test]
fn shape_helpers_and_bad_shapes() {
    let s = shape_of(vec![Exit::Fall(node(1)), Exit::Stop], &[true]);
    assert!(s.is_valid() && !s.is_empty());
    assert_eq!(s.len(), 2);
    assert_eq!(s.block_count(), 2);
    assert_eq!(*s.exit(node(9)), Exit::Stop);
    assert_eq!(s.addr(node(9)), 0);
    assert!(s.node(node(0)).is_some_and(|n| n.pure));
    assert!(Exit::Switch(Vec::new()).is_stop() && !Exit::Fall(node(0)).is_stop());
    let bad = shape_of(vec![Exit::Fall(node(7))], &[]);
    assert!(!bad.is_valid());
    assert_eq!(cfg_trace(&bad, &Seeded(1), 10).end, End::Stuck);
    let out = structure::run(
        &bad,
        &structure::Opts { max_nodes: 10 },
        &mut Fuel::unlimited(),
    );
    assert_eq!(out.mode, Mode::Flat(FlatReason::NoProgress));
    let empty_switch = shape_of(vec![Exit::Switch(Vec::new())], &[]);
    let out = structure::run(
        &empty_switch,
        &structure::Opts { max_nodes: 10 },
        &mut Fuel::unlimited(),
    );
    let trace = tree_trace(&out.tree, &empty_switch, &Seeded(2), 10);
    assert_eq!(trace, cfg_trace(&empty_switch, &Seeded(2), 10));
    assert_eq!(trace.end, End::Halt);
    let stuck = tree_trace(&Tree::Break(node(0)), &s, &Seeded(3), 10);
    assert_eq!(stuck.end, End::Stuck);
    let spin = Tree::Loop {
        kind: LoopKind::Endless,
        cond: None,
        body: Box::new(Tree::empty()),
        head: node(0),
        follow: None,
    };
    assert_eq!(tree_trace(&spin, &s, &Seeded(4), 10).end, End::Stuck);
}

#[test]
fn structurer_budgets() {
    let n = 400;
    let mut exits = Vec::new();
    for i in 0..n {
        exits.push(Exit::Cond {
            t: node(i + 1),
            f: node(n + 1),
        });
    }
    exits.push(Exit::Fall(node(n + 1)));
    exits.push(Exit::Stop);
    let deep = shape_of(exits, &[]);
    let unbounded = structure::Opts {
        max_nodes: usize::MAX,
    };
    let out = structure::run(&deep, &unbounded, &mut Fuel::unlimited());
    assert!(
        matches!(out.mode, Mode::Flat(FlatReason::Depth)),
        "deeper than {MAX_DEPTH}"
    );
    let out = structure::run(&deep, &unbounded, &mut Fuel::new(10));
    assert_eq!(out.mode, Mode::Flat(FlatReason::Fuel));
    let trace = tree_trace(&out.tree, &deep, &Seeded(5), 1_000);
    assert_eq!(trace, cfg_trace(&deep, &Seeded(5), 1_000));
}

#[test]
fn flat_puts_the_entry_first() {
    let mut s = shape_of(
        vec![
            Exit::Stop,
            Exit::Switch(vec![node(0), node(2), node(0)]),
            Exit::Cond {
                t: node(0),
                f: node(1),
            },
        ],
        &[],
    );
    s.entry = node(1);
    let t = flat::tree(&s);
    let Tree::Seq(items) = &t else {
        panic!("a sequence");
    };
    assert_eq!(items.first(), Some(&Tree::Goto(node(1))));
    for seed in 0..8 {
        assert_eq!(
            tree_trace(&t, &s, &Seeded(seed), 50),
            cfg_trace(&s, &Seeded(seed), 50)
        );
    }
    let unique: BTreeSet<Node> = t.labels().into_iter().collect();
    assert_eq!(unique.len(), t.labels().len());
}

/// Builds a program of one block from the ops that `f` adds, then decompiles it.
fn one_block(f: impl FnOnce(&mut Builder), passes: Passes) -> (Program, ghidorah_decomp::Decomp) {
    let mut b = Builder::new();
    b.begin(0x1000, 4).expect("in order");
    f(&mut b);
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x1000,
        setup: vec![(Loc::RDI, 0x2000), (Loc::RSI, 0)],
    };
    let ssa = l1_of(&p);
    let d = decompile(
        &p,
        &ssa,
        &Opts {
            passes,
            ..Opts::default()
        },
    );
    (p, d)
}

fn stop_of(
    f: impl FnOnce(&mut Builder),
    image: &dyn ghidorah_ir::Image,
    config: &Config,
) -> StopReason {
    let (p, d) = one_block(f, Passes::ALL);
    interp_ast::run(&d, image, config, &p.setup, 1_000).reason
}

#[test]
#[expect(clippy::too_many_lines, reason = "one case for each stop reason")]
fn value_mode_stops() {
    let none = Config::default();
    let ram = FlatImage::new(0x2000, vec![0; 16], true);
    let read = stop_of(
        |b| {
            let x = b.get(Loc::RDI).expect("get");
            let v = b.load(64, Arg::V(x)).expect("load");
            b.put(Loc::RAX, v.into()).expect("put");
            b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
        },
        &NoImage,
        &none,
    );
    assert_eq!(read, StopReason::UnmappedRead(0x2000));
    let write = stop_of(
        |b| {
            let x = b.get(Loc::RDI).expect("get");
            b.store(64, Arg::k(0x9999), x.into()).expect("store");
            b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
        },
        &ram,
        &none,
    );
    assert_eq!(write, StopReason::UnmappedWrite(0x9999));
    let div = stop_of(
        |b| {
            let x = b.get(Loc::RDI).expect("get");
            let y = b.get(Loc::RSI).expect("get");
            let q = b.binary(Opc::UDiv, 64, x.into(), y.into()).expect("div");
            b.put(Loc::RAX, q.into()).expect("put");
            b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
        },
        &ram,
        &none,
    );
    assert_eq!(div, StopReason::DivZero);
    let effect = Effect {
        name: IntrinsicId(3),
        uses: LocSet::EMPTY,
        defs: LocSet::EMPTY,
        mem: MemEffect::None,
    };
    let sys = stop_of(
        |b| b.effect_op(Opc::Syscall, effect, Arg::Nil).expect("sys"),
        &ram,
        &none,
    );
    assert_eq!(sys, StopReason::Syscall);
    let intr = stop_of(
        |b| {
            b.effect_op(Opc::Intrinsic, effect, Arg::k(0x2000))
                .expect("op");
        },
        &ram,
        &none,
    );
    assert_eq!(intr, StopReason::Intrinsic);
    let unimpl = stop_of(
        |b| b.flow(Opc::Unimpl, Arg::Nil, Arg::Nil).expect("op"),
        &ram,
        &none,
    );
    assert_eq!(unimpl, StopReason::Unimpl);
    let ext = Config {
        externals: std::iter::once(0x5000).collect(),
        ..Config::default()
    };
    let call = stop_of(
        |b| b.flow(Opc::Call, Arg::k(0x5000), Arg::Nil).expect("call"),
        &ram,
        &ext,
    );
    assert_eq!(call, StopReason::CallExternal(0x5000));
    let ind = stop_of(
        |b| {
            let x = b.get(Loc::RDI).expect("get");
            b.flow(Opc::CallInd, x.into(), Arg::Nil).expect("call");
        },
        &ram,
        &none,
    );
    assert_eq!(ind, StopReason::CallUnresolved(0x2000));
    let goto = stop_of(
        |b| {
            let x = b.get(Loc::RDI).expect("get");
            b.flow(Opc::JumpInd, x.into(), Arg::Nil).expect("jmp");
        },
        &ram,
        &none,
    );
    assert_eq!(goto, StopReason::NoCode(0x2000));
    let (p, d) = one_block(
        |b| {
            let x = b.get(Loc::RDI).expect("get");
            let y = b.binary(Opc::Add, 64, x.into(), Arg::k(1)).expect("add");
            b.put(Loc::RAX, y.into()).expect("put");
            b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
        },
        Passes::ALL,
    );
    let out = interp_ast::run(&d, &ram, &none, &p.setup, 0);
    assert_eq!(out.reason, StopReason::FuelExhausted);
    let cap = Config {
        mem_cap: 0,
        ..Config::default()
    };
    let capped = stop_of(
        |b| {
            b.store(8, Arg::k(0x2000), Arg::k(1)).expect("store");
            b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
        },
        &ram,
        &cap,
    );
    assert_eq!(capped, StopReason::MemCap);
}

#[test]
fn sailr_switches() {
    let call = |b: &mut Builder| {
        let x = b.get(Loc::RDI).expect("get");
        b.flow(Opc::CallInd, x.into(), Arg::Nil).expect("call");
    };
    let (_, on) = one_block(call, Passes::ALL);
    let last = on.view.nodes[on.view.shape.entry.index()]
        .stmts
        .last()
        .cloned();
    assert!(matches!(last, Some(Stmt::Call(c)) if c.noreturn));
    assert!(
        on.warnings
            .iter()
            .any(|w| w.code == WarningCode::NoreturnAssumed)
    );
    let (_, off) = one_block(call, Passes::NONE);
    let last = off.view.nodes[off.view.shape.entry.index()]
        .stmts
        .last()
        .cloned();
    assert!(matches!(last, Some(Stmt::Call(c)) if !c.noreturn && !c.tail));
    assert!(off.warnings.is_empty());
}

#[test]
fn view_errors() {
    let mut b = Builder::new();
    b.begin(0x1000, 4).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000], &[]);
    let p = Program {
        arena,
        body,
        entry: 0x1000,
        setup: Vec::new(),
    };
    let ssa = l1_of(&p);
    let tails = BTreeSet::new();
    let input = Input {
        ssa: &ssa,
        l0: &p.arena,
        tail_calls: &tails,
        conv: None,
    };
    let err = ghidorah_decomp::from_input(&input, &NoEnv, &Opts::default(), &mut Fuel::new(0));
    assert_eq!(err, Err(DecompError::View(ViewError::OutOfFuel)));
    let env = NoEnv;
    assert!(ghidorah_decomp::Env::callee_name(&env, 1).is_none());
    assert!(!ghidorah_decomp::Env::is_noreturn(&env, 1));
    assert!(!ghidorah_decomp::Env::is_string(&env, 1));
    let shape: &Shape = &decompile(&p, &ssa, &Opts::default()).view.shape;
    assert_eq!(shape.len(), 1);
}

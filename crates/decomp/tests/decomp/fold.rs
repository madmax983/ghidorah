//! Safe folding: a load never moves across a store, a call or a memory `Intrinsic` (AC-103).

use std::collections::BTreeSet;

use ghidorah_base::Fuel;
use ghidorah_decomp::{Expr, Input, NoEnv, Opts, Stmt, View};
use ghidorah_ir::ssa::{self, Ssa};
use ghidorah_ir::{Arg, Builder, Effect, IntrinsicId, Loc, LocSet, MemEffect, Opc, Switches};
use ghidorah_testkit::rng::Xoshiro256ss;

use crate::progs::{body_with, decompile, l1_of, pool_opts, random_program};

/// Tells if the L1 op at `index` is a barrier for a load.
fn barrier(ssa: &Ssa, index: u32) -> bool {
    let Some(op) = ssa.arena().op(index) else {
        return false;
    };
    match op.opc {
        Opc::Store | Opc::Call | Opc::CallInd | Opc::Syscall => true,
        Opc::Intrinsic => ssa
            .arena()
            .effect(op)
            .is_some_and(|e| e.mem != MemEffect::None),
        _ => false,
    }
}

/// Gives the loads inside the expressions of a statement.
fn loads(s: &Stmt) -> Vec<ghidorah_ir::OpId> {
    s.exprs()
        .into_iter()
        .flat_map(Expr::preorder)
        .filter_map(|e| match e {
            Expr::Load { at, .. } => Some(*at),
            _ => None,
        })
        .collect()
}

/// Checks each folded load of a view. Gives the count of folded loads.
fn check_view(ssa: &Ssa, view: &View, what: &str) -> usize {
    let mut folded = 0;
    for node in &view.nodes {
        let pos = |index: u32| node.ops.iter().position(|&i| i == index);
        let mut users: Vec<(ghidorah_ir::OpId, Vec<ghidorah_ir::OpId>)> =
            node.stmts.iter().map(|s| (s.at(), loads(s))).collect();
        for e in [&node.cond, &node.target].into_iter().flatten() {
            let list = e
                .preorder()
                .into_iter()
                .filter_map(|x| match x {
                    Expr::Load { at, .. } => Some(*at),
                    _ => None,
                })
                .collect();
            let term = node
                .ops
                .last()
                .and_then(|&i| ssa.arena().op(i))
                .map(|o| o.id);
            users.push((term.expect("a node with a condition has ops"), list));
        }
        for (user, list) in users {
            let Some(u) = ssa.op_index(user).and_then(pos) else {
                continue;
            };
            for load in list {
                if load == user {
                    continue;
                }
                let d = ssa
                    .op_index(load)
                    .and_then(pos)
                    .unwrap_or_else(|| panic!("{what}: the load {load} is in its node"));
                assert!(d < u, "{what}: the load {load} comes after its use {user}");
                let between = &node.ops[d + 1..u];
                assert!(
                    !between.iter().any(|&i| barrier(ssa, i)),
                    "{what}: the load {load} moves across a barrier to {user}"
                );
                folded += 1;
            }
        }
    }
    folded
}

#[test]
fn ac_103_fold_safety() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x0103);
    let mut folded = 0;
    for i in 0..4_000 {
        let p = random_program(&mut rng);
        let ssa = l1_of(&p);
        let d = decompile(&p, &ssa, &Opts::default());
        folded += check_view(&ssa, &d.view, &format!("program {i}"));
    }
    assert!(folded > 100, "only {folded} folded loads");
}

#[test]
fn fold_stops_at_intrinsic_memory() {
    let mut b = Builder::new();
    b.begin(0x1000, 4).expect("in order");
    let v = b.load(64, Arg::k(0x2000)).expect("load");
    let effect = Effect {
        name: IntrinsicId(7),
        uses: LocSet::EMPTY,
        defs: LocSet::EMPTY,
        mem: MemEffect::Write { size: 8 },
    };
    b.begin(0x1004, 4).expect("in order");
    b.effect_op(Opc::Intrinsic, effect, Arg::k(0x2000))
        .expect("intrinsic");
    b.begin(0x1008, 4).expect("in order");
    b.put(Loc::RAX, v.into()).expect("put");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let body = body_with(&arena, &[0x1000], &[]);
    let mut ssa = ssa::build(arena.clone(), body, &pool_opts(), &mut Fuel::unlimited())
        .expect("the SSA build");
    let _ = ghidorah_ir::passes::run(&mut ssa, &Switches::all(), &mut Fuel::unlimited())
        .expect("the passes run");
    let tails = BTreeSet::new();
    let input = Input {
        ssa: &ssa,
        l0: &arena,
        tail_calls: &tails,
        conv: None,
    };
    let d = ghidorah_decomp::from_input(&input, &NoEnv, &Opts::default(), &mut Fuel::unlimited())
        .expect("the decompile");
    let stmts = &d.view.nodes[d.view.shape.entry.index()].stmts;
    let first = stmts.first().expect("a first statement");
    assert!(
        matches!(
            first,
            Stmt::Assign {
                value: Expr::Load { .. },
                ..
            }
        ),
        "the load stays before the intrinsic: {stmts:#?}"
    );
    assert_eq!(check_view(&ssa, &d.view, "the intrinsic program"), 0);
}

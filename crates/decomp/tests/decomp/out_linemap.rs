//! AC-099 over the fixture functions: the line map coverage. The check reads the L1 form of
//! each function, so it does not depend on `linemap::cover`.

use std::collections::BTreeSet;

use ghidorah_analysis::fir::Opts as FirOpts;
use ghidorah_analysis::fir::l1;
use ghidorah_base::{Fuel, WarningCode};
use ghidorah_db::Program;
use ghidorah_decomp::{ElideReason, linemap, print};
use ghidorah_ir::{Arg, Node, Op, OpId, Opc, Switches, rpo};

use crate::fixtures::{fid, program};
use crate::out_fixtures::{Item, corpus, elided_at};

/// Tells if a line must hold the L1 op `op`: a store, a call, a return, a branch or an
/// opaque op with a memory address.
fn must_show(op: &Op) -> bool {
    match op.opc {
        Opc::Store
        | Opc::Call
        | Opc::CallInd
        | Opc::Syscall
        | Opc::Unimpl
        | Opc::Ret
        | Opc::CJump
        | Opc::JumpInd => true,
        Opc::Intrinsic => op.a[1] != Arg::Nil,
        _ => false,
    }
}

/// Gives the problems of the line map of one function. The check reads the L1 form, not
/// `linemap::cover`. Each body instruction is in a line range or an elided row. Each L1 op
/// with an effect is in the `ops` of a line map row, or its instruction is a canary or an
/// unreachable instruction. A branch can also be control flow.
fn line_map_problems(p: &Program, item: &Item) -> Vec<String> {
    let out = &item.out;
    let rows = linemap::rows(1, &out.lines);
    let in_row = |addr: u64| {
        rows.iter()
            .any(|r| r.start <= addr && addr - r.start < r.size.max(1))
    };
    let mut bad = Vec::new();
    for (addr, _) in print::body_units(p, fid(item.entry)) {
        if !in_row(addr) && elided_at(out, addr).is_none() {
            bad.push(format!("{addr:#x} has no row"));
        }
    }
    let held: BTreeSet<OpId> = rows.iter().flat_map(|r| r.ops.iter().copied()).collect();
    let ir = l1::build(
        p,
        fid(item.entry),
        &FirOpts::DEFAULT,
        &Switches::all(),
        &mut Fuel::unlimited(),
    )
    .expect("the L1 form");
    let reach: BTreeSet<Node> = rpo(ir.ssa.cfg()).into_iter().collect();
    let arena = ir.ssa.arena();
    for i in ir.ssa.order() {
        let Some(op) = arena.op(i) else {
            continue;
        };
        let live =
            ir.ssa.is_insn_op(i) && ir.ssa.block_of_op(i).is_some_and(|b| reach.contains(&b));
        let rep = op.opc == Opc::CJump && op.a[1].as_k() == Some(op.id.addr);
        if !live || rep || !must_show(op) || held.contains(&op.id) {
            continue;
        }
        let branch = matches!(op.opc, Opc::CJump | Opc::JumpInd);
        match elided_at(out, op.id.addr) {
            Some(ElideReason::Canary | ElideReason::Unreachable) => {}
            Some(ElideReason::Flow) if branch => {}
            other => bad.push(format!(
                "{} {:?} is not in a line ({other:?})",
                op.id, op.opc
            )),
        }
    }
    let selfcheck = out
        .warnings
        .iter()
        .filter(|w| w.code == WarningCode::StructureSelfcheck)
        .count();
    if selfcheck > 0 {
        bad.push(format!("{selfcheck} self-check warnings"));
    }
    bad
}

#[test]
fn ac_099_line_map_coverage() {
    let items = corpus();
    assert!(items.len() > 2_000, "only {} functions", items.len());
    let chunks: Vec<Vec<&Item>> = (0..4)
        .map(|k| items.iter().skip(k).step_by(4).collect())
        .collect();
    let parts: Vec<Vec<String>> = std::thread::scope(|s| {
        #[expect(
            clippy::needless_collect,
            reason = "every thread starts before the first join"
        )]
        let handles: Vec<_> = chunks
            .iter()
            .map(|c| {
                s.spawn(move || {
                    c.iter()
                        .flat_map(|item| {
                            line_map_problems(program(&item.fixture), item)
                                .into_iter()
                                .map(|b| format!("{} {:#x}: {b}", item.fixture, item.entry))
                        })
                        .collect()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a worker thread"))
            .collect()
    });
    let bad: Vec<String> = parts.into_iter().flatten().collect();
    assert!(
        bad.is_empty(),
        "{} problems: {:?}",
        bad.len(),
        &bad[..bad.len().min(10)]
    );
}

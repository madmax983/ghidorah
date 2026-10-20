//! Regression tests of the switch of a jump table: its selector, its labels and its default.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::jumptable::GuardInfo;
use ghidorah_base::Fuel;
use ghidorah_decomp::{Input, NoEnv, Opts, interp_ast};
use ghidorah_ir::ssa::{self, Opts as SsaOpts};
use ghidorah_ir::{Arg, Builder, Config, Loc, NoNames, Opc, Switches};

use crate::progs::{Program, body_with, ram_image};
use crate::regress_sema::text;

/// The address of the default block of the hand-made switch.
const DEFAULT: u64 = 0x1100;

/// Gives the address of case block `i` of the hand-made switch.
fn case_at(i: u64) -> u64 {
    0x1020 + 0x10 * i
}

/// The hand-made switch of `act2` in the module doc of `view::switch`: `sub edi,10;
/// cmp edi,6; ja default; jmp [table]`. Case `i` returns `i`, and the default returns 99.
fn biased_switch() -> (Program, GuardInfo) {
    let mut b = Builder::new();
    b.begin(0x1000, 3).expect("in order");
    let arg = b.get(Loc::RDI).expect("get");
    let low = b.unary(Opc::Trunc, 32, arg.into()).expect("trunc");
    let biased = b.binary(Opc::Sub, 32, low.into(), Arg::k(10)).expect("sub");
    let wide = b.extend(false, 64, 32, biased.into()).expect("zext");
    b.put(Loc::RDI, wide.into()).expect("put");
    b.begin(0x1003, 3).expect("in order");
    let index = b.get(Loc::RDI).expect("get");
    let index32 = b.unary(Opc::Trunc, 32, index.into()).expect("trunc");
    let above = b
        .binary(Opc::ULt, 32, Arg::k(6), index32.into())
        .expect("ult");
    b.flow(Opc::CJump, above.into(), Arg::k(DEFAULT))
        .expect("ja");
    b.begin(0x1006, 2).expect("in order");
    let target = b.get(Loc::RDI).expect("get");
    b.flow(Opc::JumpInd, target.into(), Arg::Nil).expect("jmp");
    for case in 0..7u64 {
        b.begin(case_at(case), 4).expect("in order");
        b.put(Loc::RAX, Arg::k(case)).expect("put");
        b.begin(case_at(case) + 4, 1).expect("in order");
        b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    }
    b.begin(DEFAULT, 4).expect("in order");
    b.put(Loc::RAX, Arg::k(99)).expect("put");
    b.begin(DEFAULT + 4, 1).expect("in order");
    b.flow(Opc::Ret, Arg::Nil, Arg::Nil).expect("ret");
    let arena = b.finish();
    let cmp = arena
        .ops()
        .iter()
        .position(|op| op.opc == Opc::ULt)
        .and_then(|at| u32::try_from(at).ok())
        .expect("the compare op");
    let mut leaders = vec![0x1000, 0x1006];
    leaders.extend((0..7).map(case_at));
    leaders.push(DEFAULT);
    let extra: Vec<(u64, u64)> = (0..7).map(|case| (0x1006, case_at(case))).collect();
    let body = body_with(&arena, &leaders, &extra);
    let guard = GuardInfo {
        branch: 0x1003,
        cmp,
        operand: 1,
        max: 6,
        default: DEFAULT,
    };
    let program = Program {
        arena,
        body,
        entry: 0x1000,
        setup: Vec::new(),
    };
    (program, guard)
}

/// `switch (x) { case 10: .. case 16: .. default: .. }` compiles to `sub edi,10; cmp edi,6;
/// ja default` and a table of 7 entries. The text switched on the jump target with the labels
/// 0 to 6, and the guard stayed an `if` with no `default:` (decomp-02, decomp-03).
#[test]
fn regress_switch_selector_bias_and_default() {
    let (p, guard) = biased_switch();
    let opts = SsaOpts {
        ret_uses: std::iter::once(Loc::RAX).collect(),
        ..SsaOpts::default()
    };
    let mut l1 = ssa::build(
        p.arena.clone(),
        p.body.clone(),
        &opts,
        &mut Fuel::unlimited(),
    )
    .expect("the SSA build");
    let _ = ghidorah_ir::passes::run(&mut l1, &Switches::all(), &mut Fuel::unlimited())
        .expect("the passes run");
    let tails = BTreeSet::new();
    let guards = BTreeMap::from([(0x1006u64, guard)]);
    let input = Input {
        ssa: &l1,
        l0: &p.arena,
        tail_calls: &tails,
        conv: None,
        guards: &guards,
    };
    let d = ghidorah_decomp::from_input(&input, &NoEnv, &Opts::default(), &mut Fuel::unlimited())
        .expect("the decompile");
    let text = ghidorah_decomp::finish(d.clone(), &NoEnv, &NoNames, "act2", &d.view.insns).text();
    assert!(
        !text.contains("if ("),
        "the guard is the default arm: {text}"
    );
    assert!(text.contains("switch ((uint32_t)"), "{text}");
    for label in ["case 0xa:", "case 0x10:", "default:"] {
        assert!(text.contains(label), "no `{label}`: {text}");
    }
    assert!(!text.contains("case 0:"), "{text}");
    let image = ram_image(1);
    for (x, want) in [
        (10u128, 0u128),
        (12, 2),
        (16, 6),
        (17, 99),
        (9, 99),
        (0, 99),
    ] {
        let out = interp_ast::run(&d, &image, &Config::default(), &[(Loc::RDI, x)], 10_000);
        let rax = out
            .uses
            .iter()
            .find(|(l, _)| *l == Loc::RAX)
            .and_then(|u| u.1);
        assert_eq!(rax, Some(want), "x = {x}: {out:?}");
    }
}

/// `apply_op` of switch.gcc-O2 switches on `rdi` with `cmp rdi,8; ja 1280`, and table entry 7
/// goes to 0x1280 too. The source has no case 7, so the text has no `case 7:` label. `run_command` switches on `edi` with `cmp edi,5; ja 135c`. The text
/// switched on the computed jump address, and the guard was an `if` (decomp-02, decomp-03).
#[test]
fn regress_switch_on_index_with_default() {
    let apply = text("switch.gcc-O2", "apply_op");
    assert!(apply.contains("switch (param_1) {"), "{apply}");
    assert!(apply.contains("    default:\n        return 0;"), "{apply}");
    assert!(!apply.contains("case 7:"), "{apply}");
    assert!(!apply.contains("if ("), "{apply}");
    assert!(!apply.contains("0x2004"), "{apply}");
    let run = text("switch.gcc-O2", "run_command");
    assert!(run.contains("switch ((uint32_t)param_1) {"), "{run}");
    assert!(
        run.contains("default:\n        return puts(\"unknown command\");"),
        "{run}"
    );
    let o0 = text("switch.gcc-O0", "apply_op");
    assert!(o0.contains("switch (param_1) {"), "{o0}");
    assert!(o0.contains("default:"), "{o0}");
    assert!(!o0.contains("goto"), "{o0}");
}

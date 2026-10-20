//! Regression tests of the switch of a jump table: its selector, its labels and its default.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::jumptable::GuardInfo;
use ghidorah_base::Fuel;
use ghidorah_decomp::{Decomp, Input, LineKind, NoEnv, Opts, interp_ast};
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
    bias_switch(Opc::Sub, 10)
}

/// The hand-made switch with the index `edi <opc> k`, for example `add edi,3` for the cases
/// -3 to 3. Case `i` returns `i`, and the default returns 99.
fn bias_switch(opc: Opc, k: u64) -> (Program, GuardInfo) {
    let mut b = Builder::new();
    b.begin(0x1000, 3).expect("in order");
    let arg = b.get(Loc::RDI).expect("get");
    let low = b.unary(Opc::Trunc, 32, arg.into()).expect("trunc");
    let biased = b.binary(opc, 32, low.into(), Arg::k(k)).expect("bias");
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
    let d = decompile_switch(&p, guard);
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

/// Tells if `name` is a whole word of `text`.
fn has_word(text: &str, name: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(name).any(|(at, _)| {
        let before = text.get(..at).and_then(|t| t.chars().next_back());
        let after = text.get(at + name.len()..).and_then(|t| t.chars().next());
        !before.is_some_and(word) && !after.is_some_and(word)
    })
}

/// The cases 10 to 16 give `sub edi,10`, and the cases -3 to 3 give `add edi,3`. The switch
/// prints over the unbiased `x`, and the guard is the default arm. The biased index then had
/// no reader, but the text kept `v1 = (uint64_t)((uint32_t)param_1 - 0xa);` and the row of
/// `v1` (r2-engine-03).
#[test]
fn regress_switch_biased_no_dead_index() {
    for (opc, k, labels) in [
        (Opc::Sub, 10, ["case 0xa:", "case 0x10:"]),
        (Opc::Add, 3, ["case -3:", "case 3:"]),
    ] {
        let (p, guard) = bias_switch(opc, k);
        let d = decompile_switch(&p, guard);
        let out = ghidorah_decomp::finish(d.clone(), &NoEnv, &NoNames, "act2", &d.view.insns);
        let text = out.text();
        assert!(text.contains("switch ((uint32_t)"), "{text}");
        assert!(!text.contains("if ("), "{text}");
        for label in labels {
            assert!(text.contains(label), "no `{label}`: {text}");
        }
        assert!(!text.contains(" - 0xa") && !text.contains(" + 3"), "{text}");
        let body: Vec<&str> = out
            .lines
            .iter()
            .filter(|l| l.kind != LineKind::Head)
            .map(|l| l.text.trim())
            .collect();
        for row in &out.vars {
            let lhs = format!("{} = ", row.name);
            let read = body.iter().any(|line| {
                let rest = line.strip_prefix(&lhs).unwrap_or(line);
                has_word(rest, &row.name)
            });
            assert!(read, "`{}` has no reader: {text}", row.name);
        }
        let line = out
            .lines
            .iter()
            .find(|l| l.text.contains("switch ("))
            .expect("the switch line");
        assert_eq!(
            line.span.map(|s| s.0),
            Some(0x1000),
            "the bias op: {line:?}"
        );
        let image = ram_image(1);
        for (case, want) in [(0u64, 0u128), (3, 3), (6, 6), (7, 99)] {
            let x = if opc == Opc::Sub {
                case + k
            } else {
                case.wrapping_sub(k) & 0xffff_ffff
            };
            let run = interp_ast::run(
                &d,
                &image,
                &Config::default(),
                &[(Loc::RDI, u128::from(x))],
                10_000,
            );
            let rax = run
                .uses
                .iter()
                .find(|(l, _)| *l == Loc::RAX)
                .and_then(|u| u.1);
            assert_eq!(rax, Some(want), "x = {x:#x}: {run:?}");
        }
    }
}

/// Decompiles the hand-made switch `p` with the guard `guard` of its table jump at 0x1006.
fn decompile_switch(p: &Program, guard: GuardInfo) -> Decomp {
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
    ghidorah_decomp::from_input(&input, &NoEnv, &Opts::default(), &mut Fuel::unlimited())
        .expect("the decompile")
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

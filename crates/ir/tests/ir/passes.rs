//! The L1 passes: SCCP, copy propagation, DCE, the switches and the flag passes.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "the test programs name each IR value with one letter"
)]

use ghidorah_base::Fuel;
use ghidorah_ir::passes::{self, Pass, PassRun, Report, Switches};
use ghidorah_ir::sem::{CF, OF, PF, SF, ZF};
use ghidorah_ir::ssa::{Anchor, Opts, Ssa, SsaError};
use ghidorah_ir::{Arena, Arg, Cc, FlagOp, Loc, Node, Opc, StopReason};
use ghidorah_testkit::rng::{Rng, Xoshiro256ss, below};

use crate::common::program;
use crate::ssagen::{
    RAM, assert_clean, body, build, insn_opcodes, live_opcodes, pool_opts, ram_image,
    random_program, run_l0, run_l1,
};

const NIL: Arg = Arg::Nil;

fn ret_opts(ret: &[Loc]) -> Opts {
    Opts {
        ret_uses: ret.iter().copied().collect(),
        ..Opts::default()
    }
}

fn run_all(ssa: &mut Ssa, switches: Switches) -> Report {
    passes::run(ssa, &switches, &mut Fuel::unlimited()).expect("the passes run")
}

fn cc(n: u8) -> Cc {
    Cc::x86(n).expect("a valid cc")
}

/// A: rax = 5, flags of `rax - 5`, jump to C when ne. B: rbx = 1, go to D. C: rbx = 2.
/// D: rax = rbx, return.
fn dead_branch() -> Arena {
    program(|b| {
        b.begin(0x1000, 4)?;
        b.put(Loc::RAX, Arg::k(5))?;
        let v = b.get(Loc::RAX)?;
        let f = b.flags(FlagOp::X86Sub, 64, v.into(), Arg::k(5), Arg::k(0))?;
        b.put(Loc::Flags, f.into())?;
        let g = b.get(Loc::Flags)?;
        let c = b.cond(cc(5), g.into())?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x1008))?;
        b.begin(0x1004, 4)?;
        b.put(Loc::RBX, Arg::k(1))?;
        b.flow(Opc::Jump, Arg::k(0x100c), NIL)?;
        b.begin(0x1008, 4)?;
        b.put(Loc::RBX, Arg::k(2))?;
        b.begin(0x100c, 4)?;
        let r = b.get(Loc::RBX)?;
        b.put(Loc::RAX, r.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    })
}

#[test]
fn sccp_prunes_dead_branch() {
    let arena = dead_branch();
    let leaders = [0x1000, 0x1004, 0x1008, 0x100c];
    let ret = ret_opts(&[Loc::RAX, Loc::RBX]);
    let image = ram_image(10);
    let want = run_l0(&arena, &image, &ret, &[], 0x1000, 100);
    assert_eq!(want.stop.reason, StopReason::Returned);
    for switches in [Switches::all(), Switches::none().with(Pass::Sccp, true)] {
        let mut ssa = build(&arena, body(&arena, &leaders), &ret);
        assert_eq!(ssa.preds(Node(3)), [Node(1), Node(2)]);
        assert_eq!(ssa.phis(Node(3)).len(), 1);
        let report = run_all(&mut ssa, switches);
        assert!(report.changes(Pass::Sccp).is_some_and(|n| n > 0));
        assert_clean(&ssa, "pruned");
        // The CJump never jumps, so it becomes a `Nop`, and the edges of C go.
        assert_eq!(ssa.arena().op(6).map(|op| op.opc), Some(Opc::Nop));
        assert_eq!(ssa.cfg().succs(Node(0)), [Node(1)]);
        assert!(ssa.cfg().succs(Node(2)).is_empty());
        assert_eq!(ssa.preds(Node(3)), [Node(1)]);
        assert!(ssa.preds(Node(2)).is_empty());
        // The phi of D lost its argument from C and became the constant 1.
        assert!(ssa.phis(Node(3)).is_empty());
        assert_eq!(
            ssa.uses_at(12),
            [(Loc::RAX, Arg::k(1)), (Loc::RBX, Arg::k(1))]
        );
        assert_eq!(run_l1(&ssa, &image, &[], 100), want);
    }
}

#[test]
fn copyprop_keeps_loads_before_stores() {
    let arena = program(|b| {
        b.begin(0x2000, 4)?;
        let p = b.get(Loc::RDI)?;
        let v = b.load(64, p.into())?;
        b.store(64, p.into(), Arg::k(7))?;
        let w = b.load(64, p.into())?;
        b.put(Loc::RAX, v.into())?;
        b.put(Loc::RBX, w.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ret = ret_opts(&[Loc::RAX, Loc::RBX]);
    let mut ssa = build(&arena, body(&arena, &[0x2000]), &ret);
    passes::run_pass(&mut ssa, Pass::Copyprop, &mut Fuel::unlimited()).expect("copyprop");
    run_all(&mut ssa, Switches::all());
    assert_clean(&ssa, "loads");
    assert_eq!(
        insn_opcodes(&ssa),
        [
            Opc::Nop,
            Opc::Load,
            Opc::Store,
            Opc::Load,
            Opc::Nop,
            Opc::Nop,
            Opc::Ret
        ]
    );
    let (first, second) = (
        ssa.arena().op(1).and_then(|op| op.out).expect("first load"),
        ssa.arena()
            .op(3)
            .and_then(|op| op.out)
            .expect("second load"),
    );
    assert_eq!(
        ssa.uses_at(6),
        [(Loc::RAX, Arg::V(first)), (Loc::RBX, Arg::V(second))]
    );
    let image = ram_image(11);
    let setup = [(Loc::RDI, u128::from(RAM + 8))];
    let want = run_l0(&arena, &image, &ret, &setup, 0x2000, 100);
    let got = run_l1(&ssa, &image, &setup, 100);
    assert_eq!(got, want);
    assert_eq!(got.uses[1], (Loc::RBX, Some(7)));
    assert_ne!(got.uses[0], (Loc::RAX, Some(7)));
}

#[test]
fn dce_keeps_calls() {
    let arena = program(|b| {
        b.begin(0x3000, 5)?;
        let a = b.get(Loc::RDI)?;
        let n = b.binary(Opc::Add, 64, a.into(), Arg::k(1))?;
        b.put(Loc::RDI, n.into())?;
        let _dead = b.binary(Opc::Mul, 64, a.into(), a.into())?;
        let _load = b.load(8, a.into())?;
        let _div3 = b.binary(Opc::UDiv, 64, a.into(), Arg::k(3))?;
        let _div = b.binary(Opc::UDiv, 64, a.into(), n.into())?;
        b.flow(Opc::Call, Arg::k(0x9000), NIL)?;
        b.begin(0x3005, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let opts = Opts {
        call_uses: std::iter::once(Loc::RDI).collect(),
        ..Opts::default()
    };
    let mut ssa = build(&arena, body(&arena, &[0x3000]), &opts);
    let report = run_all(&mut ssa, Switches::all());
    assert!(report.changes(Pass::Dce).is_some_and(|n| n >= 2));
    assert_clean(&ssa, "dce");
    // The call and its argument stay. DCE removes each pure op that no live op reads.
    // A load and a division by a value that can be 0 can stop a run, so they stay.
    assert_eq!(
        insn_opcodes(&ssa),
        [
            Opc::Nop,
            Opc::Add,
            Opc::Nop,
            Opc::Nop,
            Opc::Load,
            Opc::Nop,
            Opc::UDiv,
            Opc::Call,
            Opc::Ret
        ]
    );
    let sum = ssa.arena().op(1).and_then(|op| op.out).expect("the sum");
    assert_eq!(ssa.uses_at(7), [(Loc::RDI, Arg::V(sum))]);
    let image = ram_image(12);
    let setup = [(Loc::RDI, u128::from(RAM))];
    let want = run_l0(&arena, &image, &opts, &setup, 0x3000, 100);
    assert_eq!(want.stop.reason, StopReason::CallUnresolved(0x9000));
    assert_eq!(run_l1(&ssa, &image, &setup, 100), want);
}

#[test]
fn pass_switch_off_equals_skip() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x5717);
    let opts = pool_opts();
    for case in 0..200u64 {
        let p = random_program(&mut rng);
        let image = ram_image(case);
        let want = run_l0(&p.arena, &image, &opts, &p.setup, p.entry, 300);
        for off in Pass::ALL {
            let mut switched = build(&p.arena, p.body.clone(), &opts);
            let report = run_all(&mut switched, Switches::all().with(off, false));
            assert_eq!(report.changes(off), None);
            assert_eq!(report.runs.len(), 6);
            let mut skipped = build(&p.arena, p.body.clone(), &opts);
            for pass in Pass::ALL.into_iter().filter(|&p| p != off) {
                passes::run_pass(&mut skipped, pass, &mut Fuel::unlimited()).expect("pass");
            }
            assert_eq!(switched, skipped, "case {case} without {off}");
            assert_clean(&switched, &format!("case {case} without {off}"));
            let got = run_l1(&switched, &image, &p.setup, 300);
            assert_eq!(got, want, "case {case} without {off}");
        }
    }
}

/// x = rax. y = 2 + 3. z = y * 4. f = flags of `x - 10` at 32 bits. rbx = z.
/// rcx = (x <u 10). rdx = OF of f. Return.
fn fold_and_fuse_program() -> Arena {
    program(|b| {
        b.begin(0x4000, 4)?;
        let x = b.get(Loc::RAX)?;
        let y = b.binary(Opc::Add, 64, Arg::k(2), Arg::k(3))?;
        let z = b.binary(Opc::Mul, 64, y.into(), Arg::k(4))?;
        let f = b.flags(FlagOp::X86Sub, 32, x.into(), Arg::k(10), Arg::k(0))?;
        let c = b.cond(cc(2), f.into())?;
        let o = b.cond(cc(0), f.into())?;
        b.put(Loc::RBX, z.into())?;
        let r = b.extend(false, 64, 1, c.into())?;
        b.put(Loc::RCX, r.into())?;
        let s = b.extend(false, 64, 1, o.into())?;
        b.put(Loc::RDX, s.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    })
}

#[test]
fn fold_fuse_and_materialize_rows() {
    let arena = fold_and_fuse_program();
    let ret = ret_opts(&[Loc::RBX, Loc::RCX, Loc::RDX]);
    let mut ssa = build(&arena, body(&arena, &[0x4000]), &ret);
    let step = |ssa: &mut Ssa, pass| {
        passes::run_pass(ssa, pass, &mut Fuel::unlimited()).expect("the pass runs")
    };
    assert_eq!(step(&mut ssa, Pass::Fold), 2);
    let op = |ssa: &Ssa, i: u32| *ssa.arena().op(i).expect("op");
    assert_eq!((op(&ssa, 1).opc, op(&ssa, 1).a[0]), (Opc::Copy, Arg::k(5)));
    assert_eq!((op(&ssa, 2).opc, op(&ssa, 2).a[0]), (Opc::Copy, Arg::k(20)));
    assert_eq!(step(&mut ssa, Pass::Fuse), 1);
    let entry_rax = op(&ssa, 0).a[0];
    let fused = op(&ssa, 4);
    assert_eq!(
        (fused.opc, fused.w, fused.a[0], fused.a[1]),
        (Opc::ULt, 32, entry_rax, Arg::k(10))
    );
    assert_eq!(op(&ssa, 5).opc, Opc::Cond, "OF does not fuse");
    assert!(step(&mut ssa, Pass::Copyprop) > 0);
    assert_eq!(step(&mut ssa, Pass::MaterializeFlags), 1);
    let tested = op(&ssa, 5);
    let f = ssa.arena().op(3).and_then(|op| op.out).expect("flags");
    assert_eq!(
        (tested.opc, tested.w, tested.a[0], tested.a[1]),
        (Opc::TestNZ, 16, Arg::V(f), Arg::k(u64::from(OF)))
    );
    assert!(step(&mut ssa, Pass::Dce) > 0);
    assert_clean(&ssa, "fold and fuse");
    assert!(!live_opcodes(&ssa).contains(&Opc::Cond));
    assert_eq!(ssa.uses_at(11)[2], (Loc::RBX, Arg::k(20)));
    let image = ram_image(13);
    for rax in [0u128, 9, 10, 11, 0x8000_0005, 0xffff_ffff_0000_0003] {
        let setup = [(Loc::RAX, rax)];
        let want = run_l0(&arena, &image, &ret, &setup, 0x4000, 100);
        assert_eq!(run_l1(&ssa, &image, &setup, 100), want, "rax {rax:#x}");
    }
}

/// A: go to B or C on rsi. B: flags of `rax - 1`. C: flags of `rbx & rbx`.
/// D: rax = ZF of the merged flags, return.
fn merged_flags(c_flags_from_entry: bool) -> Arena {
    program(|b| {
        b.begin(0x5000, 4)?;
        let s = b.get(Loc::RSI)?;
        let c = b.binary(Opc::Ne, 64, s.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x5008))?;
        b.begin(0x5004, 4)?;
        let x = b.get(Loc::RAX)?;
        let f1 = b.flags(FlagOp::X86Sub, 64, x.into(), Arg::k(1), Arg::k(0))?;
        b.put(Loc::Flags, f1.into())?;
        b.flow(Opc::Jump, Arg::k(0x500c), NIL)?;
        b.begin(0x5008, 4)?;
        if !c_flags_from_entry {
            let y = b.get(Loc::RBX)?;
            let f2 = b.flags(FlagOp::X86Logic, 64, y.into(), y.into(), Arg::k(0))?;
            b.put(Loc::Flags, f2.into())?;
        }
        b.begin(0x500c, 4)?;
        let g = b.get(Loc::Flags)?;
        let e = b.cond(cc(4), g.into())?;
        let r = b.extend(false, 64, 1, e.into())?;
        b.put(Loc::RAX, r.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    })
}

#[test]
fn cond_through_phi_rows() {
    let leaders = [0x5000, 0x5004, 0x5008, 0x500c];
    let ret = ret_opts(&[Loc::RAX]);
    let image = ram_image(14);
    let arena = merged_flags(false);
    let mut ssa = build(&arena, body(&arena, &leaders), &ret);
    let report = run_all(&mut ssa, Switches::all());
    assert_eq!(report.changes(Pass::CondThroughPhi), Some(1));
    assert_eq!(report.changes(Pass::MaterializeFlags), Some(0));
    assert_clean(&ssa, "cond through phi");
    let tail = |b: u32| -> Vec<(Opc, u8)> {
        ssa.anchored(Anchor::Tail(Node(b)))
            .iter()
            .map(|&i| ssa.arena().op(i).map(|op| (op.opc, op.w)).expect("op"))
            .collect()
    };
    assert_eq!(tail(1), [(Opc::Eq, 64)]);
    assert_eq!(tail(2), [(Opc::TestZ, 64)]);
    let phis = ssa.phis(Node(3)).to_vec();
    assert_eq!(phis.len(), 1);
    assert_eq!(ssa.arena().op(phis[0]).map(|op| op.w), Some(1));
    let live = live_opcodes(&ssa);
    assert!(!live.contains(&Opc::Cond) && !live.contains(&Opc::Flags));
    for (rsi, rax, rbx) in [(0, 1, 0), (0, 2, 0), (1, 0, 0), (1, 0, 4)] {
        let setup = [(Loc::RSI, rsi), (Loc::RAX, rax), (Loc::RBX, rbx)];
        let want = run_l0(&arena, &image, &ret, &setup, 0x5000, 100);
        assert_eq!(run_l1(&ssa, &image, &setup, 100), want, "{setup:?}");
    }
    // When C keeps the entry flags, the phi has an argument with no thunk. Then the
    // condition stays, and the flag bits answer it.
    let arena = merged_flags(true);
    let mut ssa = build(&arena, body(&arena, &leaders), &ret);
    let report = run_all(&mut ssa, Switches::all());
    assert_eq!(report.changes(Pass::CondThroughPhi), Some(0));
    assert_eq!(report.changes(Pass::MaterializeFlags), Some(1));
    assert_clean(&ssa, "no thunk");
    for (rsi, rax, flags) in [(0, 1, 0), (1, 0, ZF), (1, 0, 0)] {
        let setup = [
            (Loc::RSI, rsi),
            (Loc::RAX, rax),
            (Loc::Flags, u128::from(flags)),
        ];
        let want = run_l0(&arena, &image, &ret, &setup, 0x5000, 100);
        assert_eq!(run_l1(&ssa, &image, &setup, 100), want, "{setup:?}");
    }
}

#[test]
fn cond_through_phi_constant_and_double_edge() {
    // A: go to B or C on rsi. B: flags of `rax - 1`, then D on both edges of a CJump.
    // C: flags = ZF, then D. D: rax = ZF of the merged flags, return.
    let arena = program(|b| {
        b.begin(0x5000, 4)?;
        let s = b.get(Loc::RSI)?;
        let c = b.binary(Opc::Ne, 64, s.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x500c))?;
        b.begin(0x5004, 4)?;
        let x = b.get(Loc::RAX)?;
        let f = b.flags(FlagOp::X86Sub, 64, x.into(), Arg::k(1), Arg::k(0))?;
        b.put(Loc::Flags, f.into())?;
        let d = b.get(Loc::RDX)?;
        let c2 = b.binary(Opc::Ne, 64, d.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c2.into(), Arg::k(0x5008))?;
        b.begin(0x5008, 4)?;
        let g = b.get(Loc::Flags)?;
        let e = b.cond(cc(4), g.into())?;
        let r = b.extend(false, 64, 1, e.into())?;
        b.put(Loc::RAX, r.into())?;
        b.flow(Opc::Ret, NIL, NIL)?;
        b.begin(0x500c, 4)?;
        b.put(Loc::Flags, Arg::k(u64::from(ZF)))?;
        b.flow(Opc::Jump, Arg::k(0x5008), NIL)
    });
    let ret = ret_opts(&[Loc::RAX]);
    let mut ssa = build(
        &arena,
        body(&arena, &[0x5000, 0x5004, 0x5008, 0x500c]),
        &ret,
    );
    assert_eq!(ssa.preds(Node(2)), [Node(1), Node(1), Node(3)]);
    let report = run_all(&mut ssa, Switches::all());
    assert_eq!(report.changes(Pass::CondThroughPhi), Some(1));
    assert_clean(&ssa, "constant and double edge");
    let tail = ssa.anchored(Anchor::Tail(Node(1))).to_vec();
    assert_eq!(tail.len(), 1, "one compare serves both edges");
    let eq = ssa
        .arena()
        .op(tail[0])
        .and_then(|op| op.out)
        .expect("compare");
    let [phi] = ssa.phis(Node(2)) else {
        panic!("one phi: {:?}", ssa.phis(Node(2)));
    };
    let op = ssa.arena().op(*phi).expect("phi");
    assert_eq!(
        ssa.arena().phi_args(op).expect("args"),
        [Arg::V(eq), Arg::V(eq), Arg::k(1)]
    );
    let image = ram_image(16);
    for (rsi, rax, rdx) in [(0, 1, 0), (0, 2, 1), (1, 0, 0)] {
        let setup = [(Loc::RSI, rsi), (Loc::RAX, rax), (Loc::RDX, rdx)];
        let want = run_l0(&arena, &image, &ret, &setup, 0x5000, 100);
        assert_eq!(run_l1(&ssa, &image, &setup, 100), want, "{setup:?}");
    }
}

#[test]
fn materialize_every_cc() {
    let ret = ret_opts(&[Loc::RAX]);
    let image = ram_image(15);
    let mut rng = Xoshiro256ss::seed_from_u64(0x0f1a);
    for n in 0..16u8 {
        let arena = program(|b| {
            b.begin(0x6000, 4)?;
            let g = b.get(Loc::Flags)?;
            let c = b.cond(cc(n), g.into())?;
            let r = b.extend(false, 64, 1, c.into())?;
            b.put(Loc::RAX, r.into())?;
            b.flow(Opc::Ret, NIL, NIL)
        });
        let mut ssa = build(&arena, body(&arena, &[0x6000]), &ret);
        let changes = passes::run_pass(&mut ssa, Pass::MaterializeFlags, &mut Fuel::unlimited())
            .expect("the pass runs");
        assert_eq!(changes, 1);
        assert_clean(&ssa, "materialized");
        assert!(!live_opcodes(&ssa).contains(&Opc::Cond), "cc {n}");
        for bits in 0..64u16 {
            let status = [CF, PF, 0x10, ZF, SF, OF]
                .iter()
                .enumerate()
                .filter(|(i, _)| bits & (1 << i) != 0)
                .fold(0u16, |acc, (_, f)| acc | f);
            let noise = u16::try_from(below(&mut rng, 0x1_0000)).expect("16 bits");
            for word in [status, status | (noise & !0x08d5)] {
                let setup = [(Loc::Flags, u128::from(word))];
                let want = run_l0(&arena, &image, &ret, &setup, 0x6000, 100);
                assert_eq!(
                    run_l1(&ssa, &image, &setup, 100),
                    want,
                    "cc {n} flags {word:#x}"
                );
            }
        }
    }
}

#[test]
fn pass_names_and_switches() {
    let names: Vec<&str> = Pass::ALL.iter().map(|p| p.name()).collect();
    assert_eq!(
        names,
        [
            "fold",
            "fuse",
            "copyprop",
            "sccp",
            "cond_through_phi",
            "materialize_flags",
            "dce"
        ]
    );
    for (i, pass) in Pass::ALL.into_iter().enumerate() {
        assert_eq!(Pass::from_name(pass.name()), Some(pass));
        assert_eq!(pass.position(), i);
        assert_eq!(pass.to_string(), pass.name());
    }
    assert_eq!(Pass::from_name("gvn"), None);
    let none = Switches::none();
    assert!(Pass::ALL.iter().all(|p| !none.is_on(*p)));
    assert_eq!(Switches::default(), Switches::all());
    let some = Switches::all().with(Pass::Dce, false);
    assert!(!some.is_on(Pass::Dce) && some.is_on(Pass::Fold));
    let report = Report {
        runs: vec![PassRun {
            pass: Pass::Fold,
            changes: 3,
        }],
    };
    assert_eq!(report.changes(Pass::Fold), Some(3));
    assert_eq!(report.changes(Pass::Dce), None);
}

#[test]
fn passes_stop_on_fuel_without_change() {
    let arena = dead_branch();
    let ret = ret_opts(&[Loc::RAX, Loc::RBX]);
    let fresh = build(
        &arena,
        body(&arena, &[0x1000, 0x1004, 0x1008, 0x100c]),
        &ret,
    );
    for pass in Pass::ALL {
        let mut ssa = fresh.clone();
        let result = passes::run_pass(&mut ssa, pass, &mut Fuel::new(1));
        assert_eq!(result, Err(SsaError::OutOfFuel), "{pass}");
        assert_eq!(ssa, fresh, "{pass} makes no change");
    }
    let mut ssa = fresh;
    assert_eq!(
        passes::run(&mut ssa, &Switches::all(), &mut Fuel::new(3)).err(),
        Some(SsaError::OutOfFuel)
    );
}

#[test]
fn passes_keep_random_results() {
    // A short form of AC-256 with other seeds, for the run of each pass in the pass order.
    let mut rng = Xoshiro256ss::seed_from_u64(rng_seed());
    for case in 0..300u64 {
        let p = random_program(&mut rng);
        crate::ssagen::check_program(&p, case, &format!("case {case}"));
    }
}

fn rng_seed() -> u64 {
    Xoshiro256ss::seed_from_u64(0x256).next_u64()
}

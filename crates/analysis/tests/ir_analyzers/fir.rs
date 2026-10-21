//! The L0 function IR builder (design Section 7.12), the fusion rate (AC-070) and the call
//! defs of L1.

use ghidorah_analysis::cfg::{self, EdgeKind};
use ghidorah_analysis::fir::{self, FirError, Opts, l1};
use ghidorah_base::{Fuel, OutOfFuel};
use ghidorah_ir::{Loc, Node, Opc};
use ghidorah_types::cc::{MS_X64, SYSV_X86_64};

use crate::support::{cached, fid, fir_of, fixtures, truth, truth_funcs};

#[test]
fn fir_of_a_switch_function() {
    let p = cached("fixtures/bin/switch.gcc-O2");
    let t = truth("fixtures/truth/switch.gcc-O2.json");
    let apply = truth_funcs(&t)["apply_op"];
    let ir = fir_of(p, apply);
    assert_eq!(ir.lift_ver, fir::LIFT_VER);
    assert_eq!(ir.entry(), apply);
    let units = fir::units_of(p, fid(apply)).expect("the published units");
    assert_eq!(ir.units, units);
    assert_eq!(ir.arena.insns().len(), units.len());
    let entry = ir.body.cfg.entry();
    assert_eq!(ir.starts.get(entry.index()), Some(&apply));
    assert_eq!(ir.block_at(apply), Some(entry));
    assert_eq!(ir.block_at(apply + 1), None, "no instruction starts there");
    let last = *units.keys().next_back().expect("a unit");
    let block = ir.block_at(last).expect("the last unit has a block");
    assert!(ir.starts[block.index()] <= last);
    assert!(ir.frame.is_some(), "the default build tracks the stack");
    let bare = fir::build(
        p,
        fid(apply),
        &Opts {
            fuse: false,
            stack: false,
        },
        &mut Fuel::unlimited(),
    )
    .expect("a bare build");
    assert!(bare.frame.is_none());
    assert_eq!(bare.fusion.fused, 0);
    assert_eq!(bare.fusion.reads, ir.fusion.reads);
    assert!(ir.fusion.fused > 0, "the guard compare fuses");
    let fused = ir.arena.ops().iter().filter(|o| o.opc == Opc::ULt).count();
    assert!(fused > 0, "the ja guard becomes an unsigned compare");
}

/// Checks that the blocks and internal edges of the IR equal the published CFG.
#[test]
fn fir_blocks_equal_the_cfg() {
    let mut checked = 0;
    for f in fixtures() {
        if f.tier != "T1" || f.variant != "none" {
            continue;
        }
        let p = cached(&f.path);
        for view in p.funcs() {
            let id = view.id();
            let Some(g) = cfg::build(p, id) else {
                continue;
            };
            let ir = fir_of(p, id.0.off);
            let starts: Vec<u64> = g.blocks.iter().map(|b| b.start).collect();
            assert_eq!(ir.starts, starts, "{}: {id}", f.path);
            let mut want: Vec<(u64, u64)> = g
                .edges
                .iter()
                .filter(|e| e.kind.is_internal() && e.kind != EdgeKind::IndirectUnresolved)
                .filter_map(|e| Some((e.from, e.to?.off)))
                .collect();
            let mut got = Vec::new();
            for (n, from) in ir.starts.iter().enumerate() {
                let node = Node(u32::try_from(n).expect("a small node"));
                for to in ir.body.cfg.succs(node) {
                    got.push((*from, ir.starts[to.index()]));
                }
            }
            want.sort_unstable();
            got.sort_unstable();
            assert_eq!(got, want, "{}: {id}", f.path);
            checked += 1;
        }
    }
    assert!(checked > 500, "the fixtures hold functions: {checked}");
}

#[test]
fn fir_build_errors() {
    let p = cached("fixtures/bin/hello.gcc-O2");
    let missing = fid(0x5);
    assert_eq!(
        fir::build(p, missing, &Opts::DEFAULT, &mut Fuel::unlimited()),
        Err(FirError::NoFunc(missing))
    );
    let main = crate::support::named(p, "main");
    let err = fir::build(p, fid(main), &Opts::DEFAULT, &mut Fuel::new(0));
    assert!(
        matches!(err, Err(FirError::Fuel(OutOfFuel { .. }))),
        "{err:?}"
    );
    for e in [
        FirError::NoFunc(missing),
        FirError::NoEntry(1),
        FirError::Decode(2),
        FirError::Lift(3),
        FirError::TooLarge,
        FirError::Fuel(OutOfFuel {
            limit: 0,
            needed: 1,
        }),
    ] {
        assert!(e.to_string().ends_with('.') || e.to_string().contains(':'));
    }
}

#[test]
fn ac_070_fusion_rate() {
    let (mut reads, mut fused, mut funcs) = (0u64, 0u64, 0u64);
    for f in fixtures() {
        if f.variant != "none" {
            continue;
        }
        let p = cached(&f.path);
        for view in p.funcs() {
            if view.func.flags.thunk {
                continue;
            }
            let ir = fir_of(p, view.id().0.off);
            reads += ir.fusion.reads;
            fused += ir.fusion.fused;
            funcs += 1;
        }
    }
    assert!(funcs > 1_000, "T1 and T2 functions: {funcs}");
    assert!(reads > 1_000, "the functions read flags: {reads}");
    let rate = fused * 1_000 / reads;
    assert!(rate >= 980, "fusion covers {fused} of {reads} flag reads");
}

/// A call writes each register that the convention does not keep. MS x64 keeps `xmm6` ..
/// `xmm15`, and `SysV` keeps no XMM register. L1 took each XMM register as a call def, so a
/// value in `xmm6` of a PE caller had no def after a call.
#[test]
fn regress_ms_x64_xmm_kept_across_calls() {
    let xmm = |n: u8| Loc::xmm(n).expect("an XMM register");
    let ms = l1::ssa_opts(&MS_X64).call_defs;
    let sysv = l1::ssa_opts(&SYSV_X86_64).call_defs;
    for n in 0..16u8 {
        assert_eq!(ms.contains(xmm(n)), n < 6, "MS x64 xmm{n}");
        assert!(sysv.contains(xmm(n)), "SysV xmm{n}");
    }
    for l in [Loc::RSI, Loc::RDI] {
        assert!(!ms.contains(l) && sysv.contains(l), "{l:?}");
    }
    assert!(ms.contains(Loc::Flags) && sysv.contains(Loc::Flags));
}

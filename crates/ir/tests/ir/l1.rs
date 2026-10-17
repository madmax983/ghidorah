//! L1 in the interpreter: anchors, block edges and the stops of a bad flow.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "the test programs name each IR value with one letter"
)]

use ghidorah_base::Fuel;
use ghidorah_ir::ssa::{Block, Body, Opts};
use ghidorah_ir::{Arg, Cfg, Config, Interp, Loc, NoImage, Node, OpId, Opc, StopReason};

use crate::common::program;
use crate::ssagen::{body, build, ram_image, run_l0, run_l1};

const NIL: Arg = Arg::Nil;

fn ret_opts() -> Opts {
    Opts {
        ret_uses: std::iter::once(Loc::RAX).collect(),
        ..Opts::default()
    }
}

fn at(addr: u64, seq: u16) -> OpId {
    OpId { addr, seq }
}

#[test]
fn l1_stops_on_flows_outside_the_cfg() {
    // A jumps to B, but the body has no edge A -> B.
    let arena = program(|b| {
        b.begin(0x1000, 4)?;
        b.flow(Opc::Jump, Arg::k(0x1004), NIL)?;
        b.begin(0x1004, 4)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let blocks = vec![Block { first: 0, count: 1 }, Block { first: 1, count: 1 }];
    let cfg = Cfg::new(2, Node(0)).expect("entry");
    let ssa = build(&arena, Body { blocks, cfg }, &ret_opts());
    let out = run_l1(&ssa, &NoImage, &[], 100);
    assert_eq!(out.stop.reason, StopReason::BadIr);
    assert_eq!(out.stop.at, at(0x1000, 0));
    // A jumps into the middle of B.
    let arena = program(|b| {
        b.begin(0x2000, 4)?;
        b.flow(Opc::Jump, Arg::k(0x2008), NIL)?;
        b.begin(0x2004, 4)?;
        b.flow(Opc::Nop, NIL, NIL)?;
        b.begin(0x2008, 4)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ssa = build(&arena, body(&arena, &[0x2000, 0x2004]), &ret_opts());
    let out = run_l1(&ssa, &NoImage, &[], 100);
    assert_eq!(out.stop.reason, StopReason::BadIr);
    let want = run_l0(&arena, &NoImage, &ret_opts(), &[], 0x2000, 100);
    assert_eq!(want.stop.reason, StopReason::Returned);
    // A jump to an address without an instruction stops both runs in the same way.
    let arena = program(|b| {
        b.begin(0x3000, 4)?;
        b.flow(Opc::Jump, Arg::k(0xdead), NIL)
    });
    let ssa = build(&arena, body(&arena, &[0x3000]), &ret_opts());
    let want = run_l0(&arena, &NoImage, &ret_opts(), &[], 0x3000, 100);
    assert_eq!(want.stop.reason, StopReason::NoCode(0xdead));
    assert_eq!(run_l1(&ssa, &NoImage, &[], 100), want);
}

#[test]
fn l1_needs_its_own_arena() {
    let arena = program(|b| {
        b.begin(0x4000, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ssa = build(&arena, body(&arena, &[0x4000]), &ret_opts());
    let mut interp = Interp::new(&arena, &NoImage, Config::default());
    let stop = interp.run_l1(&ssa, &mut Fuel::new(10));
    assert_eq!(stop.reason, StopReason::BadIr);
    assert_eq!(stop.at, at(0x4000, 0));
    assert_eq!(stop.steps, 0);
    let mut own = Interp::new(ssa.arena(), &NoImage, Config::default());
    assert_eq!(
        own.run_l1(&ssa, &mut Fuel::new(10)).reason,
        StopReason::Returned
    );
}

#[test]
fn l1_counts_steps_like_l0() {
    // An instruction with no op, a loop and the end of the address space.
    let arena = program(|b| {
        b.begin(0x5000, 1)?;
        b.begin(0x5001, 4)?;
        let v = b.get(Loc::RAX)?;
        let w = b.binary(Opc::Sub, 64, v.into(), Arg::k(1))?;
        b.put(Loc::RAX, w.into())?;
        let c = b.binary(Opc::Ne, 64, w.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x5001))?;
        b.begin(0x5005, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ssa = build(&arena, body(&arena, &[0x5000, 0x5001, 0x5005]), &ret_opts());
    let image = ram_image(20);
    for (rax, fuel) in [(3u128, 100u64), (50, 100), (1, 2)] {
        let setup = [(Loc::RAX, rax)];
        let want = run_l0(&arena, &image, &ret_opts(), &setup, 0x5000, fuel);
        assert_eq!(
            run_l1(&ssa, &image, &setup, fuel),
            want,
            "rax {rax} fuel {fuel}"
        );
    }
    let top = program(|b| {
        b.begin(u64::MAX, 1)?;
        b.flow(Opc::Nop, NIL, NIL)
    });
    let ssa = build(&top, body(&top, &[u64::MAX]), &ret_opts());
    let want = run_l0(&top, &NoImage, &ret_opts(), &[], u64::MAX, 10);
    assert_eq!(want.stop.reason, StopReason::NoCode(0));
    assert_eq!(run_l1(&ssa, &NoImage, &[], 10), want);
}

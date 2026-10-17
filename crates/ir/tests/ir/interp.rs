//! AC-076 and the interpreter: budgets, 128-bit memory, flow and each stop reason.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

use std::collections::BTreeSet;

use ghidorah_base::Fuel;
use ghidorah_ir::interp::DEFAULT_MEM_CAP;
use ghidorah_ir::sem::{CF, ZF};
use ghidorah_ir::{
    Arg, Cc, Config, Effect, FlagOp, FlatImage, Interp, IntrinsicId, Loc, LocSet, MemEffect,
    NoImage, OpId, Opc, Stop, StopReason, Val,
};

use crate::common::{program, run};

const NIL: Arg = Arg::Nil;

fn at(addr: u64, seq: u16) -> OpId {
    OpId { addr, seq }
}

/// A writable image of 4 KiB at 0x10000.
fn ram() -> FlatImage {
    FlatImage::new(0x10000, vec![0; 4096], true)
}

#[test]
fn ac_076_interpreter_budgets() {
    // Fuel: an endless loop of two ops stops after the fuel of 1,000 ops.
    let spin = program(|b| {
        b.begin(0x1000, 2)?;
        b.flow(Opc::Nop, NIL, NIL)?;
        b.flow(Opc::Jump, Arg::k(0x1000), NIL)
    });
    let (stop, _) = run(&spin, &NoImage, Config::default(), &[], 0x1000, 1_000, &[]);
    assert_eq!(
        stop,
        Stop {
            reason: StopReason::FuelExhausted,
            at: at(0x1000, 0),
            steps: 1_000,
        }
    );
    // Memory cap: each pass stores 8 bytes. The cap of 64 bytes stops the ninth store.
    let fill = program(|b| {
        b.begin(0x2000, 4)?;
        let p = b.get(Loc::RDI)?;
        b.store(64, p.into(), Arg::k(0))?;
        let q = b.binary(Opc::Add, 64, p.into(), Arg::k(8))?;
        b.put(Loc::RDI, q.into())?;
        b.flow(Opc::Jump, Arg::k(0x2000), NIL)
    });
    let config = Config {
        mem_cap: 64,
        ..Config::default()
    };
    let image = ram();
    let (stop, _) = run(
        &fill,
        &image,
        config,
        &[(Loc::RDI, 0x10000)],
        0x2000,
        10_000,
        &[],
    );
    assert_eq!(
        stop,
        Stop {
            reason: StopReason::MemCap,
            at: at(0x2000, 1),
            steps: 42,
        }
    );
    // The same loop with the default cap stops at the end of the writable image.
    let (stop, _) = run(
        &fill,
        &image,
        Config::default(),
        &[(Loc::RDI, 0x10000)],
        0x2000,
        100_000,
        &[],
    );
    assert_eq!(stop.reason, StopReason::UnmappedWrite(0x11000));
    assert_eq!(stop.at, at(0x2000, 1));
    assert_eq!(DEFAULT_MEM_CAP, 16 << 20);
    // A stop of the fuel does not change the state after the stop.
    let mut interp = Interp::new(&spin, &NoImage, Config::default());
    let mut fuel = Fuel::new(0);
    assert_eq!(
        interp.run(0x1000, &mut fuel).reason,
        StopReason::FuelExhausted
    );
    assert_eq!(interp.run(0x1000, &mut fuel).steps, 0);
}

#[test]
fn interp_u128_store_load() {
    let value: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
    let arena = program(|b| {
        b.begin(0x1000, 8)?;
        let x = b.get(Loc::xmm(0).expect("xmm0"))?;
        b.store(128, Arg::k(0x10000), x.into())?;
        let y = b.load(128, Arg::k(0x10000))?;
        b.put(Loc::xmm(1).expect("xmm1"), y.into())?;
        let hi = b.load(64, Arg::k(0x10008))?;
        b.put(Loc::RAX, hi.into())?;
        // A 128-bit value from two 64-bit halves: Insert of the high half.
        let lo = b.extend(false, 128, 64, Arg::k(0x1111))?;
        let both = b.insert(128, lo.into(), Arg::k(0x2222), 64, 64)?;
        b.put(Loc::xmm(2).expect("xmm2"), both.into())?;
        let top = b.extract(64, both.into(), 64)?;
        b.put(Loc::RBX, top.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let image = ram();
    let mut interp = Interp::new(&arena, &image, Config::default());
    interp.set_loc(Loc::xmm(0).expect("xmm0"), value);
    let stop = interp.run(0x1000, &mut Fuel::new(100));
    assert_eq!(stop.reason, StopReason::Returned);
    assert_eq!(interp.loc(Loc::xmm(1).expect("xmm1")), value);
    assert_eq!(interp.loc(Loc::RAX), value >> 64);
    assert_eq!(
        interp.loc(Loc::xmm(2).expect("xmm2")),
        (0x2222 << 64) | 0x1111
    );
    assert_eq!(interp.loc(Loc::RBX), 0x2222);
    let bytes: Vec<u8> = (0..16)
        .map(|i| interp.read(0x10000 + i).expect("a written byte"))
        .collect();
    assert_eq!(bytes, value.to_le_bytes());
    assert_eq!(interp.written(), 16);
}

#[test]
fn locations_keep_their_width() {
    let arena = program(|b| {
        b.begin(0x1000, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let mut interp = Interp::new(&arena, &NoImage, Config::default());
    interp.set_loc(Loc::RAX, u128::MAX);
    interp.set_loc(Loc::Flags, u128::MAX);
    interp.set_loc(Loc::xmm(3).expect("xmm3"), u128::MAX);
    assert_eq!(interp.loc(Loc::RAX), u128::from(u64::MAX));
    assert_eq!(interp.loc(Loc::Flags), 0xffff);
    assert_eq!(interp.loc(Loc::xmm(3).expect("xmm3")), u128::MAX);
    assert_eq!(interp.loc(Loc::RCX), 0);
    assert_eq!(interp.val(Val(0)), None);
}

#[test]
fn flow_and_partial_writes() {
    // 0x1000: rax[15:8] = 0xff; flags = Sub(rax, rcx); if (e) goto 0x1010.
    // 0x1008: rax = 1; 0x100c: ret.  0x1010: rax = 2; jump *rdx.  0x1020: ret.
    let arena = program(|b| {
        b.begin(0x1000, 8)?;
        let old = b.get(Loc::RAX)?;
        let new = b.insert(64, old.into(), Arg::k(0xff), 8, 8)?;
        b.put(Loc::RAX, new.into())?;
        let other = b.get(Loc::RCX)?;
        let flags = b.flags(FlagOp::X86Sub, 64, new.into(), other.into(), NIL)?;
        b.put(Loc::Flags, flags.into())?;
        let equal = b.cond(Cc::x86(4).expect("e"), flags.into())?;
        b.flow(Opc::CJump, equal.into(), Arg::k(0x1010))?;
        b.begin(0x1008, 4)?;
        b.put(Loc::RBX, Arg::k(1))?;
        b.begin(0x100c, 1)?;
        b.flow(Opc::Ret, NIL, NIL)?;
        b.begin(0x1010, 4)?;
        b.put(Loc::RBX, Arg::k(2))?;
        let target = b.get(Loc::RDX)?;
        b.flow(Opc::JumpInd, target.into(), NIL)?;
        b.begin(0x1020, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let base = 0x1111_2222_3333_4444u128;
    let regs = [Loc::RAX, Loc::RBX, Loc::Flags];
    let setup = [(Loc::RAX, base), (Loc::RCX, 0), (Loc::RDX, 0x1020)];
    let (stop, out) = run(
        &arena,
        &NoImage,
        Config::default(),
        &setup,
        0x1000,
        100,
        &regs,
    );
    assert_eq!(stop.reason, StopReason::Returned);
    assert_eq!(stop.at, at(0x100c, 0));
    assert_eq!(out[0], 0x1111_2222_3333_ff44);
    assert_eq!(out[1], 1);
    assert_eq!(out[2] & u128::from(ZF | CF), 0);
    let equal = [
        (Loc::RAX, base),
        (Loc::RCX, 0x1111_2222_3333_ff44),
        (Loc::RDX, 0x1020),
    ];
    let (stop, out) = run(
        &arena,
        &NoImage,
        Config::default(),
        &equal,
        0x1000,
        100,
        &regs,
    );
    assert_eq!(stop.reason, StopReason::Returned);
    assert_eq!(stop.at, at(0x1020, 0));
    assert_eq!(out[1], 2);
    assert_eq!(out[2] & u128::from(ZF), u128::from(ZF));
    assert_eq!(stop.steps, 12);
    // A jump to an address without an instruction stops with that address.
    let lost = [
        (Loc::RAX, base),
        (Loc::RCX, 0x1111_2222_3333_ff44),
        (Loc::RDX, 0x1021),
    ];
    let (stop, _) = run(&arena, &NoImage, Config::default(), &lost, 0x1000, 100, &[]);
    assert_eq!(stop.reason, StopReason::NoCode(0x1021));
    assert_eq!(stop.at, at(0x1010, 2));
}

/// Runs a one-instruction program at 0x1000 and gives its stop.
fn stop_of(
    build: impl FnOnce(&mut ghidorah_ir::Builder) -> Result<(), ghidorah_ir::BuildError>,
) -> Stop {
    let arena = program(|b| {
        b.begin(0x1000, 4)?;
        build(b)
    });
    let config = Config {
        externals: BTreeSet::from([0x4000]),
        ..Config::default()
    };
    let image = FlatImage::new(0x20000, vec![1, 2, 3], false);
    run(&arena, &image, config, &[], 0x1000, 100, &[]).0
}

#[test]
fn each_stop_reason() {
    let effect = Effect {
        name: IntrinsicId(7),
        defs: LocSet::EMPTY.with(Loc::RAX).expect("a register"),
        uses: LocSet::EMPTY,
        mem: MemEffect::None,
    };
    let rows: Vec<(StopReason, u16, Stop)> = vec![
        (
            StopReason::Unimpl,
            0,
            stop_of(|b| b.flow(Opc::Unimpl, NIL, NIL)),
        ),
        (
            StopReason::Intrinsic,
            0,
            stop_of(|b| b.effect_op(Opc::Intrinsic, effect, NIL)),
        ),
        (
            StopReason::Syscall,
            0,
            stop_of(|b| b.effect_op(Opc::Syscall, effect, NIL)),
        ),
        (
            StopReason::CallExternal(0x4000),
            0,
            stop_of(|b| b.flow(Opc::Call, Arg::k(0x4000), NIL)),
        ),
        (
            StopReason::CallUnresolved(0x5000),
            1,
            stop_of(|b| {
                let t = b.binary(Opc::Add, 64, Arg::k(0x4000), Arg::k(0x1000))?;
                b.flow(Opc::CallInd, t.into(), NIL)
            }),
        ),
        (
            StopReason::DivZero,
            0,
            stop_of(|b| b.binary(Opc::UDiv, 32, Arg::k(1), Arg::k(0)).map(|_| ())),
        ),
        (
            StopReason::UnmappedRead(0x20003),
            0,
            stop_of(|b| b.load(32, Arg::k(0x20000)).map(|_| ())),
        ),
        (
            StopReason::UnmappedWrite(0x20000),
            0,
            stop_of(|b| b.store(8, Arg::k(0x20000), Arg::k(1))),
        ),
        (
            StopReason::BadIr,
            0,
            stop_of(|b| {
                b.binary(Opc::Add, 64, Arg::V(Val(9)), Arg::k(1))
                    .map(|_| ())
            }),
        ),
        (
            StopReason::NoCode(0x1004),
            0,
            stop_of(|b| b.flow(Opc::Nop, NIL, NIL)),
        ),
        (
            StopReason::Returned,
            0,
            stop_of(|b| b.flow(Opc::Ret, NIL, NIL)),
        ),
    ];
    for (reason, seq, stop) in rows {
        assert_eq!(stop.reason, reason);
        assert_eq!(stop.at, at(0x1000, seq), "{reason:?}");
    }
    // A read of mapped image bytes gives them in little-endian order.
    let read = program(|b| {
        b.begin(0x1000, 4)?;
        let v = b.load(16, Arg::k(0x20001))?;
        b.put(Loc::RAX, v.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let image = FlatImage::new(0x20000, vec![1, 2, 3], false);
    let (stop, out) = run(
        &read,
        &image,
        Config::default(),
        &[],
        0x1000,
        10,
        &[Loc::RAX],
    );
    assert_eq!(stop.reason, StopReason::Returned);
    assert_eq!(out, [0x0302]);
    // An entry without an instruction stops before the first op.
    let (stop, _) = run(&read, &image, Config::default(), &[], 0x9999, 10, &[]);
    assert_eq!(stop.reason, StopReason::NoCode(0x9999));
    assert_eq!(stop.steps, 0);
}

/// Draws one argument: a value, a constant, a location or nothing.
fn random_arg(g: &mut ghidorah_testkit::pbt::Gen) -> Arg {
    match g.draw(4) {
        0 => Arg::V(Val(u32::try_from(g.draw(12)).unwrap_or(0))),
        1 => Arg::k(g.u64()),
        2 => Arg::L(
            *g.pick(&[
                Loc::RAX,
                Loc::RSP,
                Loc::Flags,
                Loc::Stack(-8),
                Loc::Reg(300),
            ])
            .expect("not empty"),
        ),
        _ => Arg::Nil,
    }
}

#[test]
fn interp_never_panics_on_random_ops() {
    use ghidorah_testkit::pbt::check;
    check("interp_never_panics_on_random_ops", 3_000, |g| {
        let count = g.range(1, 12);
        let mut b = ghidorah_ir::Builder::new();
        for i in 0..count {
            b.begin(0x1000 + 4 * i, 4).map_err(|e| e.to_string())?;
            b.flow(Opc::Nop, NIL, NIL).map_err(|e| e.to_string())?;
            b.flow(Opc::Nop, NIL, NIL).map_err(|e| e.to_string())?;
        }
        let mut arena = b.finish();
        for op in arena.ops_mut() {
            let code = u8::try_from(g.draw(64)).unwrap_or(0);
            op.opc = Opc::from_code(code).unwrap_or(Opc::Nop);
            op.w = g.u8();
            op.sub = g.u8();
            op.out = g
                .bool()
                .then(|| Val(u32::try_from(g.draw(16)).unwrap_or(0)));
            op.a = [random_arg(g), random_arg(g), random_arg(g)];
        }
        let image = FlatImage::new(0, vec![0x5a; 64], g.bool());
        let config = Config {
            mem_cap: g.draw(32),
            externals: BTreeSet::from([0x4000]),
        };
        let mut interp = Interp::new(&arena, &image, config);
        interp.set_loc(Loc::RSP, 32);
        let stop = interp.run(0x1000, &mut Fuel::new(g.draw(200)));
        if stop.steps > 200 {
            return Err(format!("{stop:?} takes more than its fuel"));
        }
        Ok(())
    });
}

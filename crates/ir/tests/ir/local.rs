//! Block-local value evaluation (design Section 6.6): slices, chains, stops and pins.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

use ghidorah_base::Fuel;
use ghidorah_ir::local::{self, MAX_BLOCKS, Memory, Pin, Query, Scope, Target};
use ghidorah_ir::{
    Arena, Arg, Effect, IntrinsicId, Loc, LocSet, LocalValue, MemEffect, NoMemory, Opc,
};

use crate::common::program;
use crate::ssagen::{body, body_with};

const NIL: Arg = Arg::Nil;

/// A memory of read-only bytes at `0x2000` and a mapped region from `0x2000` to `0x2fff`.
struct Rom(Vec<u8>);

impl Memory for Rom {
    fn read(&self, addr: u64) -> Option<u8> {
        let off = usize::try_from(addr.checked_sub(0x2000)?).ok()?;
        self.0.get(off).copied()
    }

    fn mapped(&self, addr: u64) -> bool {
        (0x2000..0x3000).contains(&addr)
    }
}

/// Gives the index of the op `seq` of the instruction at `addr`.
fn op_at(arena: &Arena, addr: u64, seq: u32) -> u32 {
    let i = arena.insn_index(addr).expect("an instruction");
    arena.insns()[i].first + seq
}

fn value(arena: &Arena, leaders: &[u64], mem: &dyn Memory, op: u32, loc: Loc) -> LocalValue {
    let body = body(arena, leaders);
    let scope = Scope {
        arena,
        body: &body,
        mem,
    };
    local::value_at(&scope, op, loc, &mut Fuel::unlimited())
}

#[test]
fn local_constant_through_puts() {
    // rax = 5; rdi = rax + 3; call 0x1000.
    let arena = program(|b| {
        b.begin(0x10, 4)?;
        b.put(Loc::RAX, Arg::k(5))?;
        b.begin(0x14, 4)?;
        let v = b.get(Loc::RAX)?;
        let w = b.binary(Opc::Add, 64, v.into(), Arg::k(3))?;
        b.put(Loc::RDI, w.into())?;
        b.begin(0x18, 4)?;
        b.flow(Opc::Call, Arg::k(0x1000), NIL)?;
        b.begin(0x1c, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let call = op_at(&arena, 0x18, 0);
    let leaders = [0x10];
    assert_eq!(
        value(&arena, &leaders, &NoMemory, call, Loc::RDI),
        LocalValue::Const(8)
    );
    assert_eq!(
        value(&arena, &leaders, &NoMemory, call, Loc::RAX),
        LocalValue::Const(5)
    );
    // The call writes no location, but a walk across it stops.
    let ret = op_at(&arena, 0x1c, 0);
    assert_eq!(
        value(&arena, &leaders, &NoMemory, ret, Loc::RDI),
        LocalValue::Unknown
    );
    // A register that no op writes has no value at the function entry.
    assert_eq!(
        value(&arena, &leaders, &NoMemory, call, Loc::RSI),
        LocalValue::Unknown
    );
    let body = body(&arena, &leaders);
    let scope = Scope {
        arena: &arena,
        body: &body,
        mem: &NoMemory,
    };
    assert_eq!(
        local::arg_at(&scope, call, 0, &mut Fuel::unlimited()),
        LocalValue::Const(0x1000)
    );
    assert_eq!(
        local::value_at(&scope, call, Loc::RDI, &mut Fuel::new(0)),
        LocalValue::Unknown,
        "an empty tank gives Unknown"
    );
}

#[test]
fn local_addresses_and_loads() {
    // rsi = 0x2004; rax = load32 [rsi]; rdx = 7.
    let arena = program(|b| {
        b.begin(0x10, 4)?;
        b.put(Loc::RSI, Arg::k(0x2004))?;
        b.begin(0x14, 4)?;
        let ptr = b.get(Loc::RSI)?;
        let word = b.load(32, ptr.into())?;
        let wide = b.extend(false, 64, 32, word.into())?;
        b.put(Loc::RAX, wide.into())?;
        b.begin(0x18, 4)?;
        let ptr2 = b.get(Loc::RSI)?;
        let word2 = b.load(32, ptr2.into())?;
        b.put(Loc::RCX, word2.into())?;
        b.begin(0x1c, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let rom = Rom(vec![0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]);
    let ret = op_at(&arena, 0x1c, 0);
    let leaders = [0x10];
    assert_eq!(
        value(&arena, &leaders, &rom, ret, Loc::RSI),
        LocalValue::Addr(0x2004)
    );
    assert_eq!(
        value(&arena, &leaders, &rom, ret, Loc::RAX),
        LocalValue::Const(0x1234_5678)
    );
    let body = body(&arena, &leaders);
    let scope = Scope {
        arena: &arena,
        body: &body,
        mem: &rom,
    };
    let out = local::eval(&scope, &Query::loc(ret, Loc::RCX), &mut Fuel::unlimited());
    assert_eq!(out.value, LocalValue::Const(0x1234_5678));
    assert_eq!(out.loads, [(0x2004, 4)]);
    assert!(
        out.ops >= 3,
        "the slice holds the put, the load and the get"
    );
    // A byte outside the read-only image stops the load.
    assert_eq!(
        value(&arena, &leaders, &Rom(vec![1, 2]), ret, Loc::RAX),
        LocalValue::Unknown
    );
}

/// A diamond A -> (B | C) -> D and a chain D -> E.
fn diamond() -> Arena {
    program(|b| {
        b.begin(0x10, 4)?;
        b.put(Loc::RDI, Arg::k(1))?;
        let c = b.get(Loc::RSI)?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x18))?;
        b.begin(0x14, 4)?;
        b.put(Loc::RDX, Arg::k(2))?;
        b.flow(Opc::Jump, Arg::k(0x1c), NIL)?;
        b.begin(0x18, 4)?;
        b.put(Loc::RDX, Arg::k(3))?;
        b.begin(0x1c, 4)?;
        b.put(Loc::RCX, Arg::k(4))?;
        b.flow(Opc::Jump, Arg::k(0x20), NIL)?;
        b.begin(0x20, 4)?;
        b.flow(Opc::Call, Arg::k(0x1000), NIL)?;
        b.begin(0x24, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    })
}

#[test]
fn local_chains_and_merges() {
    let arena = diamond();
    let leaders = [0x10, 0x14, 0x18, 0x1c, 0x20, 0x24];
    let call = op_at(&arena, 0x20, 0);
    assert_eq!(
        value(&arena, &leaders, &NoMemory, call, Loc::RCX),
        LocalValue::Const(4),
        "the walk goes up the single-predecessor block"
    );
    assert_eq!(
        value(&arena, &leaders, &NoMemory, call, Loc::RDX),
        LocalValue::Unknown,
        "a merge point stops the walk"
    );
    assert_eq!(
        value(&arena, &leaders, &NoMemory, call, Loc::RDI),
        LocalValue::Unknown,
        "the walk does not cross the merge to the entry block"
    );
    let in_b = op_at(&arena, 0x14, 1);
    assert_eq!(
        value(&arena, &leaders, &NoMemory, in_b, Loc::RDI),
        LocalValue::Const(1)
    );
}

#[test]
fn local_block_limit() {
    // Six blocks in a chain: rdi = 9 in the first block, a read in the last block.
    let arena = program(|b| {
        b.begin(0x10, 4)?;
        b.put(Loc::RDI, Arg::k(9))?;
        for i in 1..6u64 {
            b.flow(Opc::Jump, Arg::k(0x10 + 4 * i), NIL)?;
            b.begin(0x10 + 4 * i, 4)?;
        }
        b.flow(Opc::Ret, NIL, NIL)
    });
    let leaders: Vec<u64> = (0..6u64).map(|i| 0x10 + 4 * i).collect();
    let body = body(&arena, &leaders);
    let scope = Scope {
        arena: &arena,
        body: &body,
        mem: &NoMemory,
    };
    let at = |addr| op_at(&arena, addr, 0);
    let near = local::value_at(&scope, at(0x10 + 4 * 3), Loc::RDI, &mut Fuel::unlimited());
    assert_eq!(near, LocalValue::Const(9), "four blocks reach the def");
    let far = local::value_at(&scope, at(0x10 + 4 * 5), Loc::RDI, &mut Fuel::unlimited());
    assert_eq!(far, LocalValue::Unknown, "six blocks go past {MAX_BLOCKS}");
    let mut wide = Query::loc(at(0x10 + 4 * 5), Loc::RDI);
    wide.max_blocks = 6;
    assert_eq!(
        local::eval(&scope, &wide, &mut Fuel::unlimited()).value,
        LocalValue::Const(9)
    );
}

#[test]
fn local_slice_op_limit() {
    // rax = 0, then 40 adds of 1: the slice holds about 120 ops.
    let arena = program(|b| {
        b.begin(0x10, 4)?;
        b.put(Loc::RAX, Arg::k(0))?;
        for i in 0..40u64 {
            b.begin(0x14 + 4 * i, 4)?;
            let v = b.get(Loc::RAX)?;
            let w = b.binary(Opc::Add, 64, v.into(), Arg::k(1))?;
            b.put(Loc::RAX, w.into())?;
        }
        b.begin(0x14 + 4 * 40, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let body = body(&arena, &[0x10]);
    let scope = Scope {
        arena: &arena,
        body: &body,
        mem: &NoMemory,
    };
    let ret = op_at(&arena, 0x14 + 4 * 40, 0);
    assert_eq!(
        local::value_at(&scope, ret, Loc::RAX, &mut Fuel::unlimited()),
        LocalValue::Unknown
    );
    let mut wide = Query::loc(ret, Loc::RAX);
    wide.max_ops = 200;
    let out = local::eval(&scope, &wide, &mut Fuel::unlimited());
    assert_eq!(out.value, LocalValue::Const(40));
    assert_eq!(out.ops, 121);
}

#[test]
fn local_effect_ops() {
    // rdi = 3; rax = 60; syscall; then rdi stays and rax is a def of the syscall.
    let effect = Effect {
        name: IntrinsicId(1),
        defs: [Loc::RAX, Loc::RCX, Loc::R11].into_iter().collect(),
        uses: [Loc::RAX, Loc::RDI].into_iter().collect(),
        mem: MemEffect::None,
        operands: Default::default(),
    };
    let opaque = Effect {
        name: IntrinsicId(2),
        defs: LocSet::EMPTY,
        uses: LocSet::EMPTY,
        mem: MemEffect::Write { size: 8 },
        operands: Default::default(),
    };
    let arena = program(|b| {
        b.begin(0x10, 4)?;
        b.put(Loc::RDI, Arg::k(3))?;
        b.put(Loc::RAX, Arg::k(60))?;
        b.begin(0x14, 2)?;
        b.effect_op(Opc::Syscall, effect, NIL)?;
        b.begin(0x16, 4)?;
        b.effect_op(Opc::Intrinsic, opaque, Arg::k(0x2000))?;
        b.begin(0x1a, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let leaders = [0x10];
    let sys = op_at(&arena, 0x14, 0);
    let ret = op_at(&arena, 0x1a, 0);
    assert_eq!(
        value(&arena, &leaders, &NoMemory, sys, Loc::RAX),
        LocalValue::Const(60)
    );
    assert_eq!(
        value(&arena, &leaders, &NoMemory, ret, Loc::RAX),
        LocalValue::Unknown
    );
    assert_eq!(
        value(&arena, &leaders, &NoMemory, ret, Loc::RDI),
        LocalValue::Const(3),
        "an effect op that does not write the location does not stop the walk"
    );
}

#[test]
fn local_pin_emulates_a_table() {
    // rdx = 0x2000; rax = sext32 load [rdx + rdi*4]; rax = rax + rdx; jmp rax.
    let arena = program(|b| {
        b.begin(0x10, 4)?;
        let index = b.get(Loc::RDI)?;
        let above = b.binary(Opc::ULt, 64, Arg::k(2), index.into())?;
        b.flow(Opc::CJump, above.into(), Arg::k(0x40))?;
        b.begin(0x14, 4)?;
        b.put(Loc::RDX, Arg::k(0x2000))?;
        b.begin(0x18, 4)?;
        let base = b.get(Loc::RDX)?;
        let index = b.get(Loc::RDI)?;
        let scaled = b.binary(Opc::Shl, 64, index.into(), Arg::k(2))?;
        let addr = b.binary(Opc::Add, 64, base.into(), scaled.into())?;
        let word = b.load(32, addr.into())?;
        let wide = b.extend(true, 64, 32, word.into())?;
        b.put(Loc::RAX, wide.into())?;
        b.begin(0x1c, 4)?;
        let base = b.get(Loc::RDX)?;
        let rel = b.get(Loc::RAX)?;
        let sum = b.binary(Opc::Add, 64, rel.into(), base.into())?;
        b.put(Loc::RAX, sum.into())?;
        b.begin(0x20, 2)?;
        let target = b.get(Loc::RAX)?;
        b.flow(Opc::JumpInd, target.into(), NIL)?;
        b.begin(0x40, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    // Entries: -0x1000, -0x0ff0 and -0x0fe0 as rel32 from 0x2000.
    let mut bytes = Vec::new();
    for rel in [-0x1000i32, -0x0ff0, -0x0fe0] {
        bytes.extend_from_slice(&rel.to_le_bytes());
    }
    let rom = Rom(bytes);
    let body = body_with(&arena, &[0x10, 0x14, 0x40], &[]);
    let scope = Scope {
        arena: &arena,
        body: &body,
        mem: &rom,
    };
    let jump = op_at(&arena, 0x20, 1);
    let guard = op_at(&arena, 0x10, 0);
    let mut found = Vec::new();
    for idx in 0..3u64 {
        let query = Query {
            op: jump,
            target: Target::Arg(0),
            pin: Some(Pin {
                op: guard,
                loc: Loc::RDI,
                value: idx,
            }),
            max_ops: 50,
            max_blocks: MAX_BLOCKS,
        };
        let out = local::eval(&scope, &query, &mut Fuel::unlimited());
        found.push((out.value, out.loads));
    }
    assert_eq!(
        found,
        [
            (LocalValue::Const(0x1000), vec![(0x2000, 4)]),
            (LocalValue::Const(0x1010), vec![(0x2004, 4)]),
            (LocalValue::Const(0x1020), vec![(0x2008, 4)]),
        ]
    );
    let no_pin = local::arg_at(&scope, jump, 0, &mut Fuel::unlimited());
    assert_eq!(no_pin, LocalValue::Unknown, "the index has no value");
}

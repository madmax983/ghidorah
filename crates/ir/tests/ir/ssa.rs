//! AC-075b and the SSA build: Braun SSA, the SCC phi cleanup, the L1 shape and the errors.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "the test programs name each IR value with one letter"
)]

use ghidorah_base::Fuel;
use ghidorah_ir::passes::{self, Switches};
use ghidorah_ir::ssa::{self, Anchor, Block, Body, Opts, PASS_SEQ, PHI_SEQ, SsaError};
use ghidorah_ir::{
    Arg, Cfg, Effect, IntrinsicId, Loc, LocSet, MemEffect, Node, OpId, Opc, StopReason, Val,
    dominators, irreducible,
};

use crate::common::program;
use crate::ssagen::{
    assert_clean, body, body_with, build, insn_opcodes, node, ram_image, run_l0, run_l1,
};

const NIL: Arg = Arg::Nil;

fn opts(ret: &[Loc]) -> Opts {
    Opts {
        ret_uses: ret.iter().copied().collect(),
        ..Opts::default()
    }
}

#[test]
fn braun_irreducible_cleanup() {
    // A: rax = rdi, then B or C. B <-> C is a cycle with two entries. C goes to B or D.
    let arena = program(|b| {
        b.begin(0x1000, 4)?;
        let s = b.get(Loc::RSI)?;
        let c = b.binary(Opc::Ne, 64, s.into(), Arg::k(0))?;
        let v = b.get(Loc::RDI)?;
        b.put(Loc::RAX, v.into())?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x1008))?;
        b.begin(0x1004, 4)?;
        let x = b.get(Loc::RAX)?;
        b.put(Loc::RBX, x.into())?;
        b.begin(0x1008, 4)?;
        let _y = b.get(Loc::RAX)?;
        let t = b.get(Loc::RCX)?;
        let c2 = b.binary(Opc::Ne, 64, t.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c2.into(), Arg::k(0x1004))?;
        b.begin(0x100c, 4)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let body = body(&arena, &[0x1000, 0x1004, 0x1008, 0x100c]);
    let dom = dominators(&body.cfg);
    assert_eq!(irreducible(&body.cfg, &dom), vec![vec![Node(1), Node(2)]]);
    let ssa = build(&arena, body, &opts(&[Loc::RAX, Loc::RBX]));
    assert_clean(&ssa, "irreducible");
    // The rax phis of B and C form an SCC with the one outer value `v`, so both go.
    let v = Val(2);
    let x_op = ssa.arena().op(5).expect("the read of rax in B");
    assert_eq!((x_op.opc, x_op.a[0]), (Opc::Copy, Arg::V(v)));
    let y_op = ssa.arena().op(7).expect("the read of rax in C");
    assert_eq!((y_op.opc, y_op.a[0]), (Opc::Copy, Arg::V(v)));
    assert!(ssa.phis(Node(1)).is_empty(), "no phi in B");
    // C keeps one real phi: rbx is the entry value from A and `x` from B.
    let [phi] = ssa.phis(Node(2)) else {
        panic!("one phi in C: {:?}", ssa.phis(Node(2)));
    };
    let phi_op = *ssa.arena().op(*phi).expect("the phi");
    assert_eq!(phi_op.opc, Opc::Phi);
    assert_eq!(phi_op.id.addr, 0x1008);
    assert!(phi_op.id.seq >= PHI_SEQ);
    let args = ssa.arena().phi_args(&phi_op).expect("phi args").to_vec();
    let [Arg::V(entry_rbx), Arg::V(from_b)] = args[..] else {
        panic!("two value arguments: {args:?}");
    };
    assert_eq!(from_b, Val(3));
    let entry_op = ssa.arena().op(ssa.arena().def_of(entry_rbx).expect("def"));
    assert_eq!(
        entry_op.map(|op| (op.opc, op.a[0])),
        Some((Opc::Get, Arg::L(Loc::RBX)))
    );
    assert_eq!(
        ssa.place(ssa.arena().def_of(entry_rbx).expect("def")),
        Some(Anchor::Start)
    );
    // The two runs agree on every path.
    let image = ram_image(1);
    for (rsi, rcx) in [(0, 0), (1, 0), (0, 1)] {
        let setup = [
            (Loc::RSI, rsi),
            (Loc::RCX, rcx),
            (Loc::RDI, 7),
            (Loc::RBX, 9),
        ];
        let fuel = if rcx == 0 { 100 } else { 60 };
        let want = run_l0(
            &arena,
            &image,
            &opts(&[Loc::RAX, Loc::RBX]),
            &setup,
            0x1000,
            fuel,
        );
        assert_eq!(
            run_l1(&ssa, &image, &setup, fuel),
            want,
            "rsi {rsi} rcx {rcx}"
        );
    }
}

/// The block count of the deep chain of AC-075b.
const CHAIN: u32 = 200_000;

/// Makes the chain: block 0 adds 1 to rax, blocks 1 to `CHAIN - 2` hold one `Nop`, and the
/// last block goes back to block 0 when rcx is not 0, else it returns.
fn chain() -> (ghidorah_ir::Arena, Body) {
    let base = 0x10_0000u64;
    let arena = program(|b| {
        b.begin(base, 1)?;
        let v = b.get(Loc::RAX)?;
        let w = b.binary(Opc::Add, 64, v.into(), Arg::k(1))?;
        b.put(Loc::RAX, w.into())?;
        for i in 1..u64::from(CHAIN - 1) {
            b.begin(base + i, 1)?;
            b.flow(Opc::Nop, NIL, NIL)?;
        }
        b.begin(base + u64::from(CHAIN - 1), 1)?;
        let x = b.get(Loc::RCX)?;
        let c = b.binary(Opc::Ne, 64, x.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c.into(), Arg::k(base))?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let count = usize::try_from(CHAIN).expect("fits");
    let blocks = (0..CHAIN).map(|i| Block { first: i, count: 1 }).collect();
    let mut cfg = Cfg::new(count, Node(0)).expect("a valid entry");
    for v in 1..CHAIN {
        cfg.add_edge(Node(v - 1), Node(v)).expect("valid nodes");
    }
    cfg.add_edge(Node(CHAIN - 1), Node(0)).expect("valid nodes");
    (arena, Body { blocks, cfg })
}

#[test]
fn ac_075b_ssa_deep_chain() {
    let worker = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let (arena, body) = chain();
            let mut ssa = ssa::build(arena, body, &opts(&[Loc::RAX]), &mut Fuel::unlimited())
                .expect("the build completes");
            assert!(ghidorah_ir::check(&ssa).is_empty());
            // The entry block merges rax from the back edge and the entry. The rcx phi of
            // the entry block reads only itself and the entry value, so it goes.
            assert_eq!(ssa.phis(Node(0)).len(), 1);
            passes::run(&mut ssa, &Switches::all(), &mut Fuel::unlimited())
                .expect("the passes complete");
            assert!(ghidorah_ir::check(&ssa).is_empty());
            let image = ram_image(2);
            let out = run_l1(&ssa, &image, &[(Loc::RAX, 41)], 1_000_000);
            assert_eq!(out.stop.reason, StopReason::Returned);
            assert_eq!(out.stop.steps, u64::from(CHAIN) + 5);
            assert_eq!(out.uses, vec![(Loc::RAX, Some(42))]);
        })
        .expect("the thread starts");
    worker
        .join()
        .expect("SSA and the passes finish in a 256 KiB stack");
}

#[test]
fn build_gives_the_l1_shape() {
    // 0x2000: rax = rdi + 1, call, rdx = rax. 0x2004: ret.
    let arena = program(|b| {
        b.begin(0x2000, 4)?;
        let x = b.get(Loc::RDI)?;
        let y = b.binary(Opc::Add, 64, x.into(), Arg::k(1))?;
        b.put(Loc::RAX, y.into())?;
        b.begin(0x2004, 5)?;
        b.flow(Opc::Call, Arg::k(0x9000), NIL)?;
        let z = b.get(Loc::RAX)?;
        b.put(Loc::RDX, z.into())?;
        b.begin(0x2009, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let options = Opts {
        ret_uses: [Loc::RAX, Loc::RDX].into_iter().collect(),
        call_uses: [Loc::RAX, Loc::RDI].into_iter().collect(),
        call_defs: std::iter::once(Loc::RAX).collect(),
        call_pop: None,
    };
    let ssa = build(&arena, body(&arena, &[0x2000]), &options);
    assert_clean(&ssa, "shape");
    assert_eq!(
        insn_opcodes(&ssa),
        [
            Opc::Copy,
            Opc::Add,
            Opc::Nop,
            Opc::Call,
            Opc::Copy,
            Opc::Nop,
            Opc::Ret
        ]
    );
    // The entry value of rdi is a `Get` at the start.
    let [start] = ssa.anchored(Anchor::Start) else {
        panic!("one entry value: {:?}", ssa.anchored(Anchor::Start));
    };
    let start_op = *ssa.arena().op(*start).expect("op");
    assert_eq!((start_op.opc, start_op.a[0]), (Opc::Get, Arg::L(Loc::RDI)));
    assert_eq!(
        start_op.id,
        OpId {
            addr: 0x2000,
            seq: PASS_SEQ
        }
    );
    let rdi = start_op.out.expect("a value");
    assert_eq!(ssa.arena().op(0).map(|op| op.a[0]), Some(Arg::V(rdi)));
    // The call reads rax (the sum) and rdi, and it writes a new rax after it.
    assert_eq!(
        ssa.uses_at(3),
        [(Loc::RAX, Arg::V(Val(1))), (Loc::RDI, Arg::V(rdi))]
    );
    let [(Loc::RAX, new_rax)] = ssa.defs_at(3) else {
        panic!("one def: {:?}", ssa.defs_at(3));
    };
    let def = ssa.arena().def_of(*new_rax).expect("def");
    assert_eq!(ssa.place(def), Some(Anchor::After(3)));
    assert_eq!(ssa.anchored(Anchor::After(3)), [def]);
    assert_eq!(
        ssa.arena().op(def).map(|op| op.id),
        Some(OpId {
            addr: 0x2004,
            seq: PASS_SEQ
        })
    );
    assert_eq!(ssa.arena().op(4).map(|op| op.a[0]), Some(Arg::V(*new_rax)));
    // The return reads the new rax and rdx (the copy of the new rax).
    assert_eq!(
        ssa.uses_at(6),
        [(Loc::RAX, Arg::V(*new_rax)), (Loc::RDX, Arg::V(Val(2)))]
    );
    assert_eq!(ssa.block_of_op(def), Some(Node(0)));
    assert_eq!(ssa.block_of_op(*start), Some(Node(0)));
    assert_eq!(ssa.block_at(0x2000), Some(Node(0)));
    assert_eq!(ssa.block_at(0x2004), None);
    assert_eq!(ssa.block_addr(Node(0)), Some(0x2000));
    assert_eq!(ssa.phi_arity(Node(0)), 1);
    assert_eq!(ssa.value_width(Val(1)), Some(64));
    assert_eq!(ssa.root(Arg::V(Val(2))), Arg::V(*new_rax));
}

#[test]
fn entry_phis_take_the_entry_edge() {
    // 0x3000: rax = rax + 1; loop to 0x3000 while rcx != 0.
    let arena = program(|b| {
        b.begin(0x3000, 4)?;
        let v = b.get(Loc::RAX)?;
        let w = b.binary(Opc::Add, 32, v.into(), Arg::k(1))?;
        b.put(Loc::RAX, w.into())?;
        let n = b.get(Loc::RCX)?;
        let m = b.binary(Opc::Sub, 64, n.into(), Arg::k(1))?;
        b.put(Loc::RCX, m.into())?;
        let c = b.binary(Opc::Ne, 64, m.into(), Arg::k(0))?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x3000))?;
        b.begin(0x3004, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ret = opts(&[Loc::RAX]);
    let ssa = build(&arena, body(&arena, &[0x3000, 0x3004]), &ret);
    assert_clean(&ssa, "entry loop");
    assert_eq!(ssa.preds(Node(0)), [Node(0)]);
    assert_eq!(ssa.phi_arity(Node(0)), 2);
    let phis = ssa.phis(Node(0)).to_vec();
    assert_eq!(phis.len(), 2, "rax and rcx");
    for phi in phis {
        let op = *ssa.arena().op(phi).expect("phi");
        let args = ssa.arena().phi_args(&op).expect("args");
        assert_eq!(args.len(), 2);
        let Arg::V(last) = args[1] else {
            panic!("the entry argument is a value");
        };
        let def = ssa.arena().def_of(last).expect("def");
        assert_eq!(ssa.place(def), Some(Anchor::Start));
    }
    let image = ram_image(3);
    for rcx in [1, 5] {
        let setup = [(Loc::RAX, 0xffff_ffff_0000_0010), (Loc::RCX, rcx)];
        let want = run_l0(&arena, &image, &ret, &setup, 0x3000, 1_000);
        assert_eq!(want.stop.reason, StopReason::Returned);
        assert_eq!(run_l1(&ssa, &image, &setup, 1_000), want);
    }
}

#[test]
fn narrow_puts_and_gets_keep_their_width() {
    // A 128-bit value goes to rax through a 64-bit `Put`, and a 32-bit `Get` reads it.
    let arena = program(|b| {
        b.begin(0x4000, 4)?;
        let x = b.get(Loc::Reg(32))?;
        b.put(Loc::RAX, x.into())?;
        let y = b.value(Opc::Get, 32, 0, [Arg::L(Loc::RAX), NIL, NIL])?;
        b.put(Loc::RBX, y.into())?;
        b.push(Opc::Put, 8, 0, [Arg::L(Loc::RCX), Arg::k(0x1234), NIL])?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ret = opts(&[Loc::RAX, Loc::RBX, Loc::RCX]);
    let ssa = build(&arena, body(&arena, &[0x4000]), &ret);
    assert_clean(&ssa, "narrow");
    let [trunc] = ssa.anchored(Anchor::After(1)) else {
        panic!("a trunc after the put");
    };
    let op = *ssa.arena().op(*trunc).expect("op");
    assert_eq!((op.opc, op.w), (Opc::Trunc, 64));
    assert_eq!(
        ssa.arena().op(2).map(|op| (op.opc, op.w)),
        Some((Opc::Copy, 32))
    );
    assert_eq!(ssa.uses_at(5)[1], (Loc::RCX, Arg::k(0x34)));
    let image = ram_image(4);
    let setup = [(Loc::Reg(32), u128::MAX - 5)];
    let want = run_l0(&arena, &image, &ret, &setup, 0x4000, 100);
    assert_eq!(run_l1(&ssa, &image, &setup, 100), want);
}

#[test]
fn effects_read_and_write_their_locations() {
    let effect = Effect {
        name: IntrinsicId(7),
        uses: std::iter::once(Loc::RAX).collect(),
        defs: [Loc::RAX, Loc::Flags].into_iter().collect(),
        mem: MemEffect::None,
    };
    let arena = program(|b| {
        b.begin(0x5000, 2)?;
        b.put(Loc::RAX, Arg::k(60))?;
        b.effect_op(Opc::Syscall, effect, NIL)?;
        b.begin(0x5002, 1)?;
        let r = b.get(Loc::RAX)?;
        b.put(Loc::RDI, r.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let ret = opts(&[Loc::RDI]);
    let ssa = build(&arena, body(&arena, &[0x5000]), &ret);
    assert_clean(&ssa, "effects");
    assert_eq!(ssa.uses_at(1), [(Loc::RAX, Arg::k(60))]);
    let defs = ssa.defs_at(1).to_vec();
    assert_eq!(
        defs.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        [Loc::RAX, Loc::Flags]
    );
    assert_eq!(ssa.arena().op(2).map(|op| op.a[0]), Some(Arg::V(defs[0].1)));
    let image = ram_image(5);
    let want = run_l0(&arena, &image, &ret, &[], 0x5000, 100);
    assert_eq!(want.stop.reason, StopReason::Syscall);
    assert_eq!(run_l1(&ssa, &image, &[], 100), want);
}

#[test]
fn build_rejects_bad_input() {
    let arena = program(|b| {
        b.begin(0x6000, 1)?;
        b.flow(Opc::Nop, NIL, NIL)?;
        b.begin(0x6001, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let try_build = |blocks: Vec<Block>, nodes: usize| {
        let cfg = Cfg::new(nodes, Node(0)).expect("entry");
        ssa::build(
            arena.clone(),
            Body { blocks, cfg },
            &Opts::default(),
            &mut Fuel::unlimited(),
        )
        .err()
    };
    let one = Block { first: 0, count: 1 };
    let two = Block { first: 1, count: 1 };
    assert_eq!(
        try_build(vec![one], 2),
        Some(SsaError::BlockCount {
            blocks: 1,
            nodes: 2
        })
    );
    assert_eq!(
        try_build(vec![one, Block { first: 1, count: 0 }], 2),
        Some(SsaError::BadBlock { block: Node(1) })
    );
    assert_eq!(
        try_build(vec![one, Block { first: 1, count: 2 }], 2),
        Some(SsaError::BadBlock { block: Node(1) })
    );
    assert_eq!(
        try_build(vec![one], 1),
        Some(SsaError::InsnCover { addr: 0x6001 })
    );
    assert_eq!(
        try_build(vec![Block { first: 0, count: 2 }, two], 2),
        Some(SsaError::InsnCover { addr: 0x6001 })
    );
    assert_eq!(try_build(vec![one, two], 2), None);
    // Ops that are not valid L0.
    let bad = |arena: ghidorah_ir::Arena| {
        let body = body(&arena, &[arena.insns()[0].addr]);
        ssa::build(arena, body, &Opts::default(), &mut Fuel::unlimited()).err()
    };
    let at = OpId {
        addr: 0x7000,
        seq: 0,
    };
    let phi = program(|b| {
        b.begin(0x7000, 1)?;
        b.push(Opc::Phi, 64, 0, [Arg::k(0), NIL, NIL])?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    assert_eq!(bad(phi), Some(SsaError::BadOp { at }));
    let loc_arg = program(|b| {
        b.begin(0x7000, 1)?;
        b.binary(Opc::Add, 64, Arg::L(Loc::RAX), Arg::k(1))?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    assert_eq!(bad(loc_arg), Some(SsaError::BadOp { at }));
    let get_k = program(|b| {
        b.begin(0x7000, 1)?;
        b.value(Opc::Get, 64, 0, [Arg::k(1), NIL, NIL])?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    assert_eq!(bad(get_k), Some(SsaError::BadOp { at }));
    let put_nil = program(|b| {
        b.begin(0x7000, 1)?;
        b.push(Opc::Put, 64, 0, [Arg::L(Loc::RAX), NIL, NIL])?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    assert_eq!(bad(put_nil), Some(SsaError::BadOp { at }));
}

#[test]
fn build_stops_on_fuel_and_full_sequences() {
    let arena = program(|b| {
        b.begin(0x8000, 1)?;
        let v = b.get(Loc::RAX)?;
        b.put(Loc::RBX, v.into())?;
        b.flow(Opc::Ret, NIL, NIL)
    });
    let body = body(&arena, &[0x8000]);
    let ret = opts(&[Loc::RBX]);
    assert_eq!(
        ssa::build(arena.clone(), body.clone(), &ret, &mut Fuel::new(2)).err(),
        Some(SsaError::OutOfFuel)
    );
    assert!(ssa::build(arena, body, &ret, &mut Fuel::new(1_000)).is_ok());
    // A merge block that reads 4,097 stack slots needs more phis than one address has.
    let slots = 4_097i32;
    let wide = program(|b| {
        b.begin(0x9000, 1)?;
        let c = b.get(Loc::RAX)?;
        b.flow(Opc::CJump, c.into(), Arg::k(0x9002))?;
        b.begin(0x9001, 1)?;
        b.put(Loc::Stack(0), Arg::k(1))?;
        b.begin(0x9002, 1)?;
        for k in 0..slots {
            b.get(Loc::Stack(k * 8))?;
        }
        b.flow(Opc::Ret, NIL, NIL)
    });
    let body = body_with(&wide, &[0x9000, 0x9001, 0x9002], &[]);
    assert_eq!(
        ssa::build(wide, body, &Opts::default(), &mut Fuel::unlimited()).err(),
        Some(SsaError::SeqFull { addr: 0x9002 })
    );
}

#[test]
fn ssa_texts_and_options() {
    let errors = [
        SsaError::BlockCount {
            blocks: 1,
            nodes: 2,
        },
        SsaError::BadBlock { block: Node(3) },
        SsaError::InsnCover { addr: 0x10 },
        SsaError::BadOp {
            at: OpId { addr: 0x10, seq: 2 },
        },
        SsaError::SeqFull { addr: 0x10 },
        SsaError::Full,
        SsaError::OutOfFuel,
    ];
    for e in errors {
        let text = e.to_string();
        assert!(text.ends_with('.'), "{text}");
        assert!(!text.is_empty());
    }
    assert!(
        SsaError::BadOp {
            at: OpId { addr: 0x10, seq: 2 }
        }
        .to_string()
        .contains("0x10:2")
    );
    let full = Opts::full();
    assert!(full.ret_uses.contains(Loc::Flags) && full.ret_uses.contains(Loc::GS_BASE));
    assert_eq!(full.ret_uses, full.call_uses);
    assert_eq!(full.call_defs, LocSet::EMPTY);
    assert_eq!(node(2), Node(2));
}

/// Gives the value of the entry `Get` of `loc` at the anchor `Start`.
fn entry_value(ssa: &ssa::Ssa, loc: Loc) -> Arg {
    ssa.anchored(Anchor::Start)
        .iter()
        .filter_map(|&i| ssa.arena().op(i))
        .find(|op| op.opc == Opc::Get && op.a[0] == Arg::L(loc))
        .and_then(|op| op.out)
        .map_or(NIL, Arg::V)
}

/// Two calls as the lifter gives them: `rsp = rsp - 8`, the store of the return address, the
/// `Put` of `rsp` and the `Call`. Then `rax = rsp` and a return.
fn two_calls() -> ghidorah_ir::Arena {
    program(|b| {
        for (at, next) in [(0x3000u64, 0x3005u64), (0x3005, 0x300a)] {
            b.begin(at, 5)?;
            let sp = b.get(Loc::RSP)?;
            let n = b.binary(Opc::Sub, 64, sp.into(), Arg::k(8))?;
            b.store(64, n.into(), Arg::k(next))?;
            b.put(Loc::RSP, n.into())?;
            b.flow(Opc::Call, Arg::k(0x9000), NIL)?;
        }
        b.begin(0x300a, 3)?;
        let r = b.get(Loc::RSP)?;
        b.put(Loc::RAX, r.into())?;
        b.begin(0x300d, 1)?;
        b.flow(Opc::Ret, NIL, NIL)
    })
}

/// The `ret` of a callee pops the return address that the `call` pushes. So the stack
/// pointer after a call is the stack pointer before it. L1 kept `rsp - 8` after each call
/// and took 8 more at each later call (decomp-04).
#[test]
fn regress_call_pops_return_address() {
    let arena = two_calls();
    let options = Opts {
        ret_uses: std::iter::once(Loc::RAX).collect(),
        call_pop: Some((Loc::RSP, 8)),
        ..Opts::default()
    };
    let mut ssa = build(&arena, body(&arena, &[0x3000]), &options);
    assert_clean(&ssa, "call pop");
    passes::run(&mut ssa, &Switches::all(), &mut Fuel::unlimited()).expect("the passes run");
    assert_clean(&ssa, "call pop after the passes");
    let ret = u32::try_from(arena.ops().len() - 1).expect("small");
    let rax = ssa
        .uses_at(ret)
        .iter()
        .find(|(l, _)| *l == Loc::RAX)
        .map(|&(_, a)| ssa.root(a))
        .expect("rax at the return");
    assert_eq!(rax, entry_value(&ssa, Loc::RSP), "{:?}", ssa.uses_at(ret));
    // Without the option, the stack pointer stays 16 bytes low: the old model.
    let mut plain = build(
        &arena,
        body(&arena, &[0x3000]),
        &Opts {
            call_pop: None,
            ..options
        },
    );
    passes::run(&mut plain, &Switches::all(), &mut Fuel::unlimited()).expect("the passes run");
    let low = plain
        .uses_at(ret)
        .iter()
        .find(|(l, _)| *l == Loc::RAX)
        .map(|&(_, a)| plain.root(a))
        .expect("rax at the return");
    assert_ne!(low, entry_value(&plain, Loc::RSP));
}

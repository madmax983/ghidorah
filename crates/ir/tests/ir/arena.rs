//! The arena, the builder, locations and the op text.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

use ghidorah_ir::arena::{MAX_LIFT_SEQ, op_at};
use ghidorah_ir::{
    Arg, BuildError, Builder, Cc, Effect, FlagOp, Imm, InsnSpan, IntrinsicId, Loc, LocSet,
    MemEffect, OpId, Opc, Val,
};

const NIL: Arg = Arg::Nil;

#[test]
fn builder_spans_values_and_defs() {
    let mut b = Builder::new();
    b.begin(0x1000, 3).expect("first instruction");
    let x = b.get(Loc::RDI).expect("get");
    let y = b.binary(Opc::Add, 64, x.into(), Arg::k(1)).expect("add");
    b.put(Loc::RAX, y.into()).expect("put");
    b.begin(0x1003, 1).expect("second instruction");
    b.flow(Opc::Ret, NIL, NIL).expect("ret");
    let arena = b.finish();
    assert_eq!(
        arena.insns(),
        [
            InsnSpan {
                addr: 0x1000,
                len: 3,
                first: 0,
                count: 3,
            },
            InsnSpan {
                addr: 0x1003,
                len: 1,
                first: 3,
                count: 1,
            },
        ]
    );
    assert_eq!((x, y), (Val(0), Val(1)));
    assert_eq!(arena.val_count(), 2);
    assert_eq!(arena.def_of(y), Some(1));
    assert_eq!(arena.def_of(Val(5)), None);
    let ids: Vec<OpId> = arena.ops().iter().map(|op| op.id).collect();
    assert_eq!(
        ids,
        [
            OpId {
                addr: 0x1000,
                seq: 0
            },
            OpId {
                addr: 0x1000,
                seq: 1
            },
            OpId {
                addr: 0x1000,
                seq: 2
            },
            OpId {
                addr: 0x1003,
                seq: 0
            },
        ]
    );
    assert_eq!(arena.insn_index(0x1003), Some(1));
    assert_eq!(arena.insn_index(0x1001), None);
    assert_eq!(arena.insn_ops(0x1003).len(), 1);
    assert!(arena.insn_ops(0x2000).is_empty());
    assert_eq!(arena.insns()[1].next_addr(), Some(0x1004));
    let text: Vec<String> = arena.ops().iter().map(ToString::to_string).collect();
    assert_eq!(
        text,
        [
            "v0 = Get.64 rdi",
            "v1 = Add.64 v0 0x1",
            "Put.64 rax v1",
            "Ret.0",
        ]
    );
}

#[test]
fn builder_errors() {
    let mut b = Builder::new();
    assert_eq!(b.get(Loc::RAX), Err(BuildError::NoInsn));
    assert_eq!(b.begin(0x10, 0), Err(BuildError::ZeroLength { addr: 0x10 }));
    b.begin(0x10, 1).expect("first instruction");
    assert_eq!(
        b.binary(Opc::Add, 0, Arg::k(1), Arg::k(2)),
        Err(BuildError::BadWidth {
            opc: Opc::Add,
            w: 0
        })
    );
    assert_eq!(
        b.binary(Opc::Add, 129, Arg::k(1), Arg::k(2)),
        Err(BuildError::BadWidth {
            opc: Opc::Add,
            w: 129,
        })
    );
    assert_eq!(b.begin(0x10, 1), Err(BuildError::OutOfOrder { addr: 0x10 }));
    assert_eq!(b.begin(0x8, 1), Err(BuildError::OutOfOrder { addr: 0x8 }));
    b.begin(0x20, 1).expect("third instruction");
    for _ in 0..=MAX_LIFT_SEQ {
        b.flow(Opc::Nop, NIL, NIL).expect("room for the op");
    }
    assert_eq!(
        b.flow(Opc::Nop, NIL, NIL),
        Err(BuildError::TooManyOps { addr: 0x20 })
    );
    for e in [
        BuildError::NoInsn,
        BuildError::OutOfOrder { addr: 1 },
        BuildError::ZeroLength { addr: 1 },
        BuildError::TooManyOps { addr: 1 },
        BuildError::Full,
        BuildError::BadWidth {
            opc: Opc::Add,
            w: 0,
        },
    ] {
        assert!(e.to_string().ends_with('.'), "{e:?}");
    }
}

#[test]
fn side_tables() {
    let effect = Effect {
        name: IntrinsicId(3),
        defs: [Loc::RAX, Loc::RCX, Loc::R11].into_iter().collect(),
        uses: [Loc::RAX, Loc::RDI].into_iter().collect(),
        mem: MemEffect::Read { size: 16 },
        operands: Default::default(),
    };
    let mut b = Builder::new();
    b.begin(0x1000, 2).expect("instruction");
    b.effect_op(Opc::Syscall, effect, NIL).expect("syscall");
    let p = b.get(Loc::RSI).expect("get");
    b.effect_op(Opc::Intrinsic, effect, p.into())
        .expect("intrinsic");
    let f = b
        .flags(FlagOp::X86Sub, 32, p.into(), Arg::k(1), NIL)
        .expect("flags");
    let c = b.cond(Cc::x86(12).expect("l"), f.into()).expect("cond");
    let mut arena = b.finish();
    let ops = arena.ops().to_vec();
    assert_eq!(arena.effect(&ops[0]), Some(&effect));
    assert_eq!(arena.effect(&ops[2]), Some(&effect));
    assert_eq!(ops[2].a[1], Arg::V(p));
    assert_eq!(arena.effect(&ops[1]), None);
    assert_eq!(ops[3].flag_op(), Some(FlagOp::X86Sub));
    assert_eq!(ops[4].cc(), Cc::x86(12));
    assert_eq!(ops[4].out, Some(c));
    assert_eq!(ops[3].to_string(), "v1 = Flags.32 X86Sub v0 0x1");
    assert_eq!(ops[4].to_string(), "v2 = Cond.1 l v1");
    // A phi of L1 keeps its argument list in the side table.
    let list = arena
        .push_phi_args(vec![Arg::V(p), Arg::k(0)])
        .expect("room for the list");
    let phi = op_at(
        OpId {
            addr: 0x1000,
            seq: 0xf000,
        },
        Opc::Phi,
        64,
        0,
        [Arg::k(u64::from(list)), NIL, NIL],
    );
    let (index, out) = arena.push_op(phi).expect("room for the op");
    assert_eq!((index, out), (5, Some(Val(3))));
    let stored = *arena.op(index).expect("the phi");
    assert_eq!(
        arena.phi_args(&stored),
        Some([Arg::V(p), Arg::k(0)].as_slice())
    );
    arena.phi_args_mut(list).expect("the list").push(Arg::k(9));
    assert_eq!(arena.phi_args(&stored).map(<[Arg]>::len), Some(3));
    assert_eq!(arena.def_of(Val(3)), Some(5));
    assert_eq!(
        arena.insns().len(),
        1,
        "a pushed op is outside each instruction"
    );
    arena.ops_mut()[1].w = 32;
    assert_eq!(arena.ops()[1].w, 32);
}

#[test]
fn locations_and_sets() {
    assert_eq!(Loc::gpr(31), Some(Loc::Reg(31)));
    assert_eq!(Loc::gpr(32), None);
    assert_eq!(Loc::xmm(31), Some(Loc::Reg(63)));
    assert_eq!(Loc::xmm(32), None);
    let names: Vec<String> = [
        Loc::RAX,
        Loc::R11,
        Loc::Reg(20),
        Loc::xmm(5).expect("xmm5"),
        Loc::FS_BASE,
        Loc::GS_BASE,
        Loc::Reg(90),
        Loc::Flags,
        Loc::Stack(-8),
        Loc::Stack(16),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names.join(" "),
        "rax r11 r20 xmm5 fs_base gs_base reg90 flags stack-0x8 stack+0x10"
    );
    assert_eq!(Loc::RAX.width(), 64);
    assert_eq!(Loc::xmm(0).expect("xmm0").width(), 128);
    assert_eq!(Loc::Flags.width(), 16);
    assert!(Loc::RSP.is_gpr() && !Loc::RSP.is_xmm());
    let mut set = LocSet::EMPTY;
    assert!(set.is_empty());
    assert!(set.insert(Loc::RCX));
    assert!(set.insert(Loc::Flags));
    assert!(!set.insert(Loc::Stack(8)));
    assert!(!set.insert(Loc::Reg(200)));
    assert!(set.contains(Loc::RCX) && !set.contains(Loc::RAX));
    assert!(!set.contains(Loc::Stack(8)));
    let more = set.union(LocSet::EMPTY.with(Loc::RAX).expect("a register"));
    assert_eq!(more.len(), 3);
    assert_eq!(
        more.iter().collect::<Vec<_>>(),
        [Loc::RAX, Loc::RCX, Loc::Flags]
    );
    assert_eq!(Imm::new(u64::MAX).get(), u64::MAX);
    assert_eq!(Arg::k(5).as_k(), Some(5));
    assert_eq!(Arg::V(Val(2)).as_v(), Some(Val(2)));
    assert_eq!(Arg::L(Loc::RAX).as_loc(), Some(Loc::RAX));
    assert_eq!(Arg::Nil.as_k(), None);
    assert_eq!(Arg::k(1).as_v(), None);
    assert_eq!(Arg::k(1).as_loc(), None);
}

//! Tests of the register model, the operand model and the instruction record.

use ghidorah_x86::{
    Access, DecodeError, Encoding, Feature, FlagSet, Flow, Insn, InvalidReason, Map, Mnem, Operand,
    Reg, RegClass, RegSet, Seg,
};

use crate::common::{dec, hex};

fn insn(text: &str) -> Insn {
    dec(&hex(text), 0x1000).unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn insn_fits_64_bytes() {
    assert!(
        size_of::<Insn>() <= 64,
        "Insn has {} bytes",
        size_of::<Insn>()
    );
    assert_eq!(size_of::<Reg>(), 2);
}

#[test]
fn register_names_and_fields() {
    assert_eq!(Reg::gpr(0, 64).name(), "rax");
    assert_eq!(Reg::gpr(15, 32).name(), "r15d");
    assert_eq!(Reg::gpr(9, 16).name(), "r9w");
    assert_eq!(Reg::gpr(4, 8).name(), "spl");
    assert_eq!(Reg::gpr(20, 64).name(), "r20");
    assert_eq!(Reg::high_byte(3).name(), "bh");
    assert_eq!(Reg::xmm(13).name(), "xmm13");
    assert_eq!(Reg::ymm(2).name(), "ymm2");
    assert_eq!(Reg::zmm(31).name(), "zmm31");
    assert_eq!(Reg::mmx(7).name(), "mm7");
    assert_eq!(Reg::st(1).name(), "st(1)");
    assert_eq!(Reg::cr(8).name(), "cr8");
    assert_eq!(Reg::dr(7).name(), "dr7");
    assert_eq!(Seg::Fs.reg().name(), "fs");
    assert_eq!(Reg::RIP.name(), "rip");
    assert_eq!(Reg::EIP.name(), "eip");
    assert_eq!(Reg::xmm(3).class(), RegClass::Xmm);
    assert_eq!(Reg::xmm(3).width_bits(), 128);
    assert_eq!(Reg::st(0).width_bytes(), 10);
    assert_eq!(Reg::gpr(2, 32).full(), Reg::RDX);
    assert_eq!(Reg::ymm(5).full(), Reg::xmm(5));
    assert!(Reg::gpr(1, 32).write_zero_extends());
    assert!(!Reg::gpr(1, 16).write_zero_extends());
    assert!(!Reg::xmm(1).write_zero_extends());
    assert_eq!(Reg::gpr(1, 16).bit_range(), (0, 16));
    assert_eq!(Reg::from_bits(Reg::R11.bits()), Some(Reg::R11));
    assert_eq!(Reg::from_bits(0xffff), None);
    assert_eq!(Reg::EIP.full(), Reg::RIP);
    assert_eq!(Reg::st(1).full(), Reg::st(1));
    assert_eq!(Seg::Cs.reg().full(), Seg::Cs.reg());
    let mask = Reg::from_bits((10 << 9) | (3 << 6) | 3).expect("a mask register");
    let bnd = Reg::from_bits((11 << 9) | (3 << 6) | 1).expect("a bound register");
    assert_eq!((mask.name(), mask.class()), ("k3", RegClass::Mask));
    assert_eq!((bnd.name(), bnd.class()), ("bnd1", RegClass::Bnd));
    let set: RegSet = [mask, bnd].into_iter().collect();
    assert_eq!(
        set.iter().collect::<Vec<_>>(),
        vec![mask],
        "bound registers have no bit"
    );
    assert_eq!(format!("{}", Reg::R8), "r8");
    assert_eq!(format!("{:?}", Reg::R9), "Reg(r9)");
    for n in 0..6 {
        let seg = Seg::from_number(n).expect("segment");
        assert_eq!(seg as u8, n);
        assert_eq!(seg.reg().number(), n);
    }
    assert_eq!(Seg::from_number(6), None);
    assert!(Seg::Gs.has_base() && !Seg::Ds.has_base());
}

#[test]
fn register_sets() {
    let mut set = RegSet::EMPTY;
    assert!(set.is_empty());
    set.insert(Reg::gpr(0, 8));
    set.insert(Reg::high_byte(0));
    set.insert(Reg::xmm(2));
    set.insert(Reg::RIP);
    assert_eq!(set.len(), 3);
    assert!(set.contains(Reg::RAX));
    assert!(set.contains(Reg::ymm(2)));
    assert!(!set.contains(Reg::RCX));
    let regs: Vec<Reg> = set.iter().collect();
    assert_eq!(regs, vec![Reg::RAX, Reg::xmm(2), Reg::RIP]);
    let other: RegSet = [
        Reg::RCX,
        Seg::Fs.reg(),
        Reg::mmx(1),
        Reg::st(2),
        Reg::cr(3),
        Reg::dr(4),
    ]
    .into_iter()
    .collect();
    let all = set.union(other);
    assert_eq!(all.len(), 9);
    assert_eq!(all.iter().count(), 9);
    assert_eq!(RegSet::GPR16.len(), 16);
    assert_eq!(RegSet::GPR32.union(RegSet::VEC32).len(), 64);
    assert_eq!(RegSet::EMPTY.with(Reg::R10).bits(), 1 << 10);
}

#[test]
fn flag_sets() {
    let s = FlagSet::CF.union(FlagSet::ZF);
    assert!(s.contains(FlagSet::ZF));
    assert!(!s.contains(FlagSet::OF));
    assert_eq!(s.to_eflags(), 0x41);
    assert_eq!(FlagSet::ARITH.union(FlagSet::DF).to_eflags(), 0x0cd5);
    assert_eq!(s.to_string(), "cf,zf");
    assert_eq!(FlagSet::ARITH.minus(FlagSet::CF).bits(), 0x3e);
    assert!(FlagSet::NONE.is_empty());
    assert_eq!(FlagSet::from_bits(0xff).bits(), 0x7f);
}

#[test]
fn flow_names() {
    let all = [
        (Flow::Seq, "seq", true),
        (Flow::Jmp, "jmp", false),
        (Flow::Jcc, "jcc", true),
        (Flow::Call, "call", true),
        (Flow::ICall, "icall", true),
        (Flow::IJmp, "ijmp", false),
        (Flow::Ret, "ret", false),
        (Flow::Trap, "trap", false),
        (Flow::Invalid, "invalid", false),
    ];
    for (flow, name, through) in all {
        assert_eq!(flow.name(), name);
        assert_eq!(flow.to_string(), name);
        assert_eq!(flow.falls_through(), through, "{name}");
    }
    assert!(!Flow::Seq.is_branch() && Flow::Ret.is_branch());
}

#[test]
fn mnemonic_names_are_unique() {
    let mut names: Vec<&str> = Mnem::ALL.iter().map(|m| m.name()).collect();
    for (i, m) in Mnem::ALL.iter().enumerate() {
        assert_eq!(*m as usize, i);
        assert_eq!(Mnem::from_name(m.name()), Some(*m));
        assert_eq!(m.to_string(), m.name());
    }
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), Mnem::ALL.len());
    assert_eq!(Mnem::from_name("nosuch"), None);
    assert_eq!(Mnem::Vector.name(), "(vector)");
}

#[test]
fn error_texts() {
    let cases = [
        (
            DecodeError::Truncated {
                have: 2,
                need_at_least: 5,
            },
            "truncated",
            2,
        ),
        (
            DecodeError::Invalid {
                len_consumed: 0,
                reason: InvalidReason::Undefined,
            },
            "invalid",
            1,
        ),
        (DecodeError::InvalidInMode { len: 1 }, "invalid_in_mode", 1),
        (
            DecodeError::Unsupported {
                feature: Feature::System,
                len: 3,
            },
            "unsupported",
            3,
        ),
    ];
    for (e, kind, skip) in cases {
        assert_eq!(e.kind(), kind);
        assert_eq!(e.skip(), skip);
        assert!(!e.to_string().is_empty());
        assert!(!e.to_string().contains("Some("));
    }
    for r in [
        InvalidReason::TooLong,
        InvalidReason::Undefined,
        InvalidReason::BadLock,
        InvalidReason::RegisterForm,
        InvalidReason::MemoryForm,
        InvalidReason::BadMap,
        InvalidReason::BadEvex,
        InvalidReason::VexAfterPrefix,
        InvalidReason::BadRex2,
    ] {
        assert_eq!(r.to_string(), r.name());
    }
    assert_eq!(Feature::System.to_string(), "system");
}

#[test]
fn operand_access() {
    let add = insn("48 01 d8");
    assert_eq!(
        add.op(0),
        Some(Operand::Reg {
            reg: Reg::RAX,
            access: Access::ReadWrite
        })
    );
    assert_eq!(
        add.op(1),
        Some(Operand::Reg {
            reg: Reg::RBX,
            access: Access::Read
        })
    );
    assert_eq!(add.op(2), None);
    let mov = insn("48 89 45 f8");
    match mov.op(0) {
        Some(Operand::Mem(m)) => {
            assert_eq!(m.access, Access::Write);
            assert_eq!(m.base, Some(Reg::RBP));
            assert_eq!(m.disp, -8);
            assert_eq!(m.width_bytes, 8);
            assert_eq!(m.abs_target, None);
        }
        other => panic!("{other:?}"),
    }
    let lea = insn("48 8d 04 40");
    match lea.op(1) {
        Some(Operand::Mem(m)) => {
            assert_eq!(m.access, Access::Address);
            assert_eq!((m.index, m.scale), (Some(Reg::RAX), 2));
        }
        other => panic!("{other:?}"),
    }
    assert!(Access::ReadWrite.reads() && Access::ReadWrite.writes());
    assert!(!Access::Address.reads() && !Access::Address.writes());
    let imm = insn("48 83 e4 f0");
    assert_eq!(
        imm.op(1),
        Some(Operand::Imm {
            value: -16,
            width: 8,
            signed: true
        })
    );
    assert_eq!(insn("e8 00 00 00 00").target(), Some(0x1005));
    assert_eq!(insn("90").target(), None);
    assert_eq!(insn("89 d8").target(), None);
    let i = insn("89 d8");
    assert_eq!((i.addr(), i.len(), i.next_addr()), (0x1000, 2, 0x1002));
    assert!(!i.is_empty());
}

#[test]
fn implicit_registers() {
    let rs = |t: &str| insn(t).regs_read();
    let ws = |t: &str| insn(t).regs_written();
    assert!(ws("48 f7 e1").contains(Reg::RDX) && rs("48 f7 e1").contains(Reg::RAX));
    assert!(!ws("f6 e1").contains(Reg::RDX), "mul cl writes only ax");
    assert!(ws("55").contains(Reg::RSP) && rs("55").contains(Reg::RBP));
    assert!(ws("c3").contains(Reg::RSP));
    assert!(ws("0f 05").contains(Reg::RCX) && ws("0f 05").contains(Reg::R11));
    assert!(rs("0f 05").contains(Reg::RDI));
    assert!(ws("0f a2").contains(Reg::RBX));
    assert!(rs("f3 48 ab").contains(Reg::RCX) && ws("f3 48 ab").contains(Reg::RDI));
    assert!(
        rs("8b 04 88").contains(Reg::RCX),
        "an index register is read"
    );
    assert!(ws("89 c8").contains(Reg::RAX) && !rs("89 c8").contains(Reg::RAX));
    assert!(
        rs("88 c8").contains(Reg::RAX),
        "a byte write keeps the other bits"
    );
    assert!(rs("48 99").contains(Reg::RAX) && ws("48 99").contains(Reg::RDX));
    assert!(ws("e8 00 00 00 00").contains(Reg::RSP));
    assert!(
        ws("c5 f8 77").contains(Reg::xmm(0)),
        "an opaque form writes vector registers"
    );
    assert!(ws("d5 10 89 c0").contains(Reg::gpr(16, 64)));
    assert!(rs("0f 1f 00").is_empty(), "nop reads nothing");
    assert!(
        ws("0f 01 f9").contains(Reg::RCX),
        "rdtscp writes the processor number"
    );
    assert!(rs("0f 01 c9").contains(Reg::RCX) && ws("0f 01 c9").is_empty());
}

#[test]
fn flag_effects() {
    let i = insn("48 01 d8");
    assert_eq!(i.flags_written(), FlagSet::ARITH);
    assert!(i.flags_read().is_empty());
    let jbe = insn("76 10");
    assert_eq!(jbe.flags_read(), FlagSet::CF.union(FlagSet::ZF));
    let and = insn("21 c0");
    assert!(and.flags_undefined().contains(FlagSet::AF));
    assert!(insn("90").flags_written().is_empty());
}

#[test]
fn prefix_fields() {
    let i = insn("f0 66 66 2e 0f b1 0a");
    let p = i.prefixes();
    assert!(p.lock() && p.osz() && !p.asz() && !p.rex());
    assert_eq!(p.count_66(), 2);
    assert!(p.osz_used());
    assert_eq!(i.seg_override(), Some(Seg::Cs));
    let raw = insn("48 8b 44 88 10").raw();
    assert_eq!(raw.rex, Some(0x48));
    assert_eq!((raw.opcode_off, raw.opcode), (1, 0x8b));
    assert_eq!((raw.modrm, raw.sib), (Some(0x44), Some(0x88)));
    assert_eq!((raw.disp_off, raw.disp_size), (4, 1));
    assert_eq!(raw.imm_size, 0);
    let enter = insn("c8 10 00 01").raw();
    assert_eq!((enter.imm_off, enter.imm_size), (1, 3));
    assert!(insn("f3 c3").prefixes().rep());
    assert!(insn("f2 ae").prefixes().repne());
    assert!(insn("48 63 c0").prefixes().rex_w());
}

#[test]
fn nop_forms() {
    for t in [
        "90",
        "66 90",
        "0f 1f 00",
        "66 2e 0f 1f 84 00 00 00 00 00",
        "0f 19 c0",
        "48 90",
    ] {
        assert!(insn(t).is_nop(), "{t}");
    }
    for t in ["87 c0", "49 90", "f3 90", "89 c0"] {
        assert!(!insn(t).is_nop(), "{t}");
    }
}

#[test]
fn encoding_and_map_names() {
    let encs = [
        (Encoding::Legacy, "legacy"),
        (Encoding::Rex2, "rex2"),
        (Encoding::Vex2, "vex2"),
        (Encoding::Vex3, "vex3"),
        (Encoding::Evex, "evex"),
        (Encoding::Xop, "xop"),
    ];
    for (e, name) in encs {
        assert_eq!(e.name(), name);
    }
    let maps = [
        (Map::One, "map0"),
        (Map::M0F, "0f"),
        (Map::M0F38, "0f38"),
        (Map::M0F3A, "0f3a"),
        (Map::Map4, "map4"),
        (Map::Map5, "map5"),
        (Map::Map6, "map6"),
        (Map::Map7, "map7"),
        (Map::Xop8, "xop8"),
        (Map::Xop9, "xop9"),
        (Map::XopA, "xopa"),
    ];
    for (m, name) in maps {
        assert_eq!(m.name(), name);
    }
    assert_eq!(insn("90").encoding(), Encoding::Legacy);
}

#[test]
fn regress_nop_register_access() {
    // A hint `nop` with a register operand reads the register. Only a memory operand
    // has an address-only access.
    match insn("0f 1f c0").op(0) {
        Some(Operand::Reg { access, .. }) => assert_eq!(access, Access::Read),
        other => panic!("{other:?}"),
    }
    match insn("0f 1f 00").op(0) {
        Some(Operand::Mem(m)) => assert_eq!(m.access, Access::Address),
        other => panic!("{other:?}"),
    }
}

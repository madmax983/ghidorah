//! Lifter rules: partial registers, SSE loads, the template table, the lift kinds, the
//! intrinsic effects and the errors (design Section 6.3).

use ghidorah_base::Fuel;
use ghidorah_ir::{
    Arena, Arg, BuildError, Builder, Config, FlatImage, Interp, IntrinsicNames, Loc, LocSet,
    MemEffect, NoImage, Op, Opc, StopReason,
};
use ghidorah_x86::lift::{self, LiftKind, ROWS, Template};
use ghidorah_x86::{LiftError, Mnem, Reg, lift as lift_insn};

use crate::common::{dec, hex};

/// The address of each instruction of these tests.
const AT: u64 = 0x1000;

/// Lifts the bytes at [`AT`].
fn lifted(bytes: &str) -> Arena {
    let insn = dec(&hex(bytes), AT).expect("the bytes decode");
    let mut b = Builder::new();
    lift_insn(&insn, &mut b).expect("the instruction lifts");
    b.finish()
}

fn has(arena: &Arena, f: impl Fn(&Op) -> bool) -> bool {
    arena.ops().iter().any(f)
}

/// Runs one lifted instruction with the given registers. Gives the interpreter.
fn run<'a>(arena: &'a Arena, image: &'a FlatImage, regs: &[(Loc, u128)]) -> Interp<'a> {
    let mut interp = Interp::new(arena, image, Config::default());
    for &(loc, v) in regs {
        interp.set_loc(loc, v);
    }
    let _ = interp.run(AT, &mut Fuel::new(1_000));
    interp
}

const RAX_IN: u128 = 0x1111_2222_3333_4444;
const RCX_IN: u128 = 0xaaaa_bbbb_cccc_dddd;

#[test]
fn partial_register_writes() {
    let image = FlatImage::default();
    // Each row: the bytes, the part width, the low bit of an Insert (or None for ZExt), rax.
    let cases: [(&str, u8, Option<u64>, u128); 4] = [
        ("88 c8", 8, Some(0), 0x1111_2222_3333_44dd),
        ("88 cc", 8, Some(8), 0x1111_2222_3333_dd44),
        ("66 89 c8", 16, Some(0), 0x1111_2222_3333_dddd),
        ("89 c8", 32, None, 0xcccc_dddd),
    ];
    for (bytes, w, lo, want) in cases {
        let arena = lifted(bytes);
        match lo {
            Some(lo) => assert!(
                has(&arena, |op| op.opc == Opc::Insert
                    && op.w == 64
                    && op.sub == w
                    && op.a[2] == Arg::k(lo)),
                "{bytes}: an Insert of {w} bits at bit {lo}: {:?}",
                arena.ops()
            ),
            None => assert!(
                has(&arena, |op| op.opc == Opc::ZExt
                    && op.w == 64
                    && op.sub == 32),
                "{bytes}: a ZExt from 32 bits"
            ),
        }
        assert!(
            has(&arena, |op| op.opc == Opc::Put
                && op.a[0] == Arg::L(Loc::RAX)),
            "{bytes}: a Put of rax"
        );
        let interp = run(&arena, &image, &[(Loc::RAX, RAX_IN), (Loc::RCX, RCX_IN)]);
        assert_eq!(interp.loc(Loc::RAX), want, "{bytes}");
        assert_eq!(interp.loc(Loc::RCX), RCX_IN, "{bytes}: rcx stays");
    }
    // A read of `ch` is an Extract of 8 bits at bit 8.
    let arena = lifted("0f b6 c5");
    assert!(has(&arena, |op| op.opc == Opc::Extract
        && op.w == 8
        && op.a[1] == Arg::k(8)));
}

#[test]
fn movss_load_zero_extends() {
    let xmm0 = Loc::xmm(0).expect("xmm0");
    let xmm1 = Loc::xmm(1).expect("xmm1");
    let image = FlatImage::new(
        0x2000,
        vec![0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55],
        false,
    );
    // movss xmm0, dword ptr [rsi]
    let arena = lifted("f3 0f 10 06");
    assert!(has(&arena, |op| op.opc == Opc::Load && op.w == 32));
    assert!(has(&arena, |op| op.opc == Opc::ZExt
        && op.w == 128
        && op.sub == 32));
    let interp = run(&arena, &image, &[(xmm0, u128::MAX), (Loc::RSI, 0x2000)]);
    assert_eq!(interp.loc(xmm0), 0x1122_3344);
    // movsd xmm0, qword ptr [rsi]
    let arena = lifted("f2 0f 10 06");
    let interp = run(&arena, &image, &[(xmm0, u128::MAX), (Loc::RSI, 0x2000)]);
    assert_eq!(interp.loc(xmm0), 0x5566_7788_1122_3344);
    // movss xmm0, xmm1 keeps the upper 96 bits.
    let arena = lifted("f3 0f 10 c1");
    assert!(has(&arena, |op| op.opc == Opc::Insert
        && op.w == 128
        && op.sub == 32));
    let interp = run(&arena, &image, &[(xmm0, u128::MAX), (xmm1, 7)]);
    assert_eq!(interp.loc(xmm0), (u128::MAX << 32) | 7);
    // movd xmm0, ecx zero-extends.
    let arena = lifted("66 0f 6e c1");
    let interp = run(&arena, &image, &[(xmm0, u128::MAX), (Loc::RCX, RCX_IN)]);
    assert_eq!(interp.loc(xmm0), 0xcccc_dddd);
}

#[test]
fn rows_are_unique_and_found() {
    assert!(ROWS.len() < 255, "the row index needs a byte");
    assert!(ROWS.len() >= 130, "only {} rows", ROWS.len());
    for (i, r) in ROWS.iter().enumerate() {
        assert_eq!(lift::row(r.mnem), Some(r), "{}", r.mnem);
        assert!(
            ROWS[..i].iter().all(|o| o.mnem != r.mnem),
            "{} twice",
            r.mnem
        );
    }
    assert_eq!(lift::row(Mnem::Cpuid), None);
    let templates: Vec<Template> = Template::ALL.to_vec();
    for t in &templates {
        assert!(ROWS.iter().any(|r| r.template == *t), "{t} has rows");
    }
    assert_eq!(Template::SseMove.to_string(), "sse_move");
    assert_eq!(lift::LIFT_VER, 1, "the first lifter version");
}

#[test]
fn lift_kinds() {
    let kind = |bytes: &str| lift::kind(&dec(&hex(bytes), AT).expect("decode"));
    assert!(matches!(kind("01 c8"), LiftKind::Template(r) if r.template == Template::Alu2));
    assert!(
        matches!(kind("66 0f ef c0"), LiftKind::Template(r) if r.template == Template::SseZero)
    );
    assert_eq!(kind("0f 05"), LiftKind::Syscall);
    // cpuid, pxor with two registers, an MMX pxor, a segment move, a VEX form and traps.
    for bytes in [
        "0f a2",
        "66 0f ef c1",
        "0f ef c0",
        "8e d8",
        "c5 f9 6f 06",
        "f4",
        "0f 0b",
        "cc",
    ] {
        assert_eq!(kind(bytes), LiftKind::Intrinsic, "{bytes}");
    }
    // retf, iretq and a far jump have no template.
    for bytes in ["cb", "48 cf", "ff 28"] {
        assert_eq!(kind(bytes), LiftKind::Unimpl, "{bytes}");
    }
    let arena = lifted("cb");
    assert!(has(&arena, |op| op.opc == Opc::Unimpl));
}

#[test]
fn intrinsic_effects() {
    // cpuid
    let insn = dec(&hex("0f a2"), AT).expect("decode");
    let e = lift::effect(&insn);
    let set = |locs: &[Loc]| locs.iter().copied().collect::<LocSet>();
    assert_eq!(e.defs, set(&[Loc::RAX, Loc::RBX, Loc::RCX, Loc::RDX]));
    assert_eq!(e.uses, set(&[Loc::RAX, Loc::RCX]));
    assert_eq!(e.mem, MemEffect::None);
    assert_eq!(lift::intrinsic_mnem(e.name), Some(Mnem::Cpuid));
    assert_eq!(lift::Names.name(e.name), Some("cpuid"));
    // paddd xmm0, xmmword ptr [rsi]
    let insn = dec(&hex("66 0f fe 06"), AT).expect("decode");
    let e = lift::effect(&insn);
    let xmm0 = Loc::xmm(0).expect("xmm0");
    assert_eq!(e.defs, set(&[xmm0]));
    assert_eq!(e.uses, set(&[Loc::RSI, xmm0]));
    assert_eq!(e.mem, MemEffect::Read { size: 16 });
    let arena = lifted("66 0f fe 06");
    let op = arena
        .ops()
        .iter()
        .find(|op| op.opc == Opc::Intrinsic)
        .expect("an Intrinsic");
    assert_eq!(arena.effect(op), Some(&e));
    assert_ne!(op.a[1], Arg::Nil, "the memory address");
    // A VEX form writes and reads every register and the flags.
    let insn = dec(&hex("c5 f9 6f 06"), AT).expect("decode");
    let e = lift::effect(&insn);
    assert!(e.defs.contains(Loc::Flags) && e.uses.contains(Loc::Flags));
    assert!(e.defs.contains(Loc::RSP) && e.uses.contains(xmm0));
    assert_eq!(e.mem, MemEffect::ReadWrite { size: 0 });
    // syscall
    let arena = lifted("0f 05");
    let op = arena
        .ops()
        .iter()
        .find(|op| op.opc == Opc::Syscall)
        .expect("a Syscall");
    let e = arena.effect(op).expect("an effect");
    assert_eq!(e.defs, set(&[Loc::RAX, Loc::RCX, Loc::R11]));
    assert_eq!(
        e.uses,
        set(&[
            Loc::RAX,
            Loc::RDX,
            Loc::RSI,
            Loc::RDI,
            Loc::R8,
            Loc::R9,
            Loc::R10
        ])
    );
    // A trap stops the interpreter.
    let arena = lifted("0f 0b");
    let stop = Interp::new(&arena, &NoImage, Config::default()).run(AT, &mut Fuel::new(10));
    assert_eq!(stop.reason, StopReason::Intrinsic);
}

#[test]
fn locations_of_registers() {
    assert_eq!(lift::loc(Reg::gpr(3, 8)), Some(Loc::RBX));
    assert_eq!(lift::loc(Reg::high_byte(1)), Some(Loc::RCX));
    assert_eq!(lift::loc(Reg::xmm(5)), Loc::xmm(5));
    assert_eq!(lift::loc(Reg::ymm(2)), Loc::xmm(2));
    assert_eq!(lift::loc(Reg::RIP), None);
    assert_eq!(lift::loc(Reg::st(0)), None);
}

#[test]
fn lift_errors() {
    let insn = dec(&hex("90"), AT).expect("decode");
    let mut b = Builder::new();
    lift_insn(&insn, &mut b).expect("the first lift");
    let back = dec(&hex("90"), AT - 1).expect("decode");
    let err = lift_insn(&back, &mut b).expect_err("an address below the last one");
    assert_eq!(
        err,
        LiftError::Build(BuildError::OutOfOrder { addr: AT - 1 })
    );
    assert!(err.to_string().contains("0xfff"), "{err}");
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn memory_operand_addresses() {
    // mov rax, qword ptr fs:[0x28] adds the fs base.
    let arena = lifted("64 48 8b 04 25 28 00 00 00");
    let image = FlatImage::new(0x7000, (0u8..64).collect(), false);
    let interp = run(&arena, &image, &[(Loc::FS_BASE, 0x7000)]);
    assert_eq!(
        interp.loc(Loc::RAX),
        u128::from(u64::from_le_bytes([40, 41, 42, 43, 44, 45, 46, 47]))
    );
    // mov eax, dword ptr [rip+0x10] reads at the next address plus 0x10.
    let arena = lifted("8b 05 10 00 00 00");
    let image = FlatImage::new(AT + 6 + 0x10, vec![1, 2, 3, 4], false);
    let interp = run(&arena, &image, &[(Loc::RAX, u128::MAX)]);
    assert_eq!(interp.loc(Loc::RAX), 0x0403_0201);
    // lea eax, [eax+ecx*1] with 32-bit addresses wraps at 32 bits.
    let arena = lifted("67 8d 04 08");
    let image = FlatImage::default();
    let interp = run(&arena, &image, &[(Loc::RAX, 0xffff_ffff), (Loc::RCX, 2)]);
    assert_eq!(interp.loc(Loc::RAX), 1);
}

#[test]
fn divide_by_zero_stops() {
    let arena = lifted("f7 f1");
    let stop = Interp::new(&arena, &NoImage, Config::default()).run(AT, &mut Fuel::new(100));
    assert_eq!(stop.reason, StopReason::DivZero);
}

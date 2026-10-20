//! Lifter rules: partial registers, SSE loads, the template table, the lift kinds, the
//! intrinsic effects and the errors (design Section 6.3).

use ghidorah_base::Fuel;
use ghidorah_ir::{
    Arena, Arg, BuildError, Builder, Config, FlatImage, Interp, IntrinsicNames, Loc, LocSet,
    MemEffect, NoImage, Op, Opc, StopReason,
};
use ghidorah_x86::lift::{self, LiftKind, ROWS, Template};
use ghidorah_x86::{LiftError, Mnem, Reg, RegClass, RegSet, lift as lift_insn};

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
    // A VEX vector form writes and reads every vector register and the flags. It reads the
    // base of its memory operand and no other general register.
    let insn = dec(&hex("c5 f9 6f 06"), AT).expect("decode");
    let e = lift::effect(&insn);
    assert!(e.defs.contains(Loc::Flags) && e.uses.contains(Loc::Flags));
    assert!(e.defs.contains(xmm0) && e.uses.contains(xmm0));
    assert_eq!(gprs(&e.uses), vec![Loc::RSI]);
    assert!(gprs(&e.defs).is_empty(), "{:?}", e.defs);
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

/// Gives the general registers of a location set in [`Loc`] order.
fn gprs(set: &LocSet) -> Vec<Loc> {
    set.iter().filter(|l| l.is_gpr()).collect()
}

#[test]
fn regress_opaque_vex_names_only_encoded_gprs() {
    let effect = |bytes: &str| lift::effect(&dec(&hex(bytes), AT).expect("decode"));
    // vzeroupper is vector-only and writes no flags.
    let e = effect("c5 f8 77");
    assert!(
        !e.defs.is_empty() && e.defs.iter().all(Loc::is_xmm),
        "{:?}",
        e.defs
    );
    assert!(
        !e.uses.is_empty() && e.uses.iter().all(Loc::is_xmm),
        "{:?}",
        e.uses
    );
    assert!(!e.defs.contains(Loc::Flags) && !e.uses.contains(Loc::Flags));
    // shlx rax, rdi, rsi: rax from ModRM.reg, rdi from ModRM.rm, rsi from VEX.vvvv.
    let shlx = effect("c4 e2 c9 f7 c7");
    assert_eq!(gprs(&shlx.defs), vec![Loc::RAX]);
    assert_eq!(gprs(&shlx.uses), vec![Loc::RSI, Loc::RDI]);
    // movbe eax, dword ptr [rdi]
    let movbe = effect("0f 38 f0 07");
    assert!(movbe.uses.contains(Loc::RDI), "{:?}", movbe.uses);
    assert!(movbe.defs.contains(Loc::RAX), "{:?}", movbe.defs);
    for e in [&e, &shlx, &movbe] {
        for loc in [Loc::RSP, Loc::RBP] {
            assert!(!e.defs.contains(loc) && !e.uses.contains(loc), "{e:?}");
        }
    }
}

/// Gives the general register names of a register set in bit order.
fn gpr_names(set: RegSet) -> Vec<&'static str> {
    set.iter()
        .filter(|r| r.class() == RegClass::Gpr)
        .map(Reg::name)
        .collect()
}

#[test]
fn opaque_forms_name_their_field_registers() {
    // Each row: the bytes, the general registers read and the general registers written.
    let rows: [(&str, &[&str], &[&str]); 23] = [
        // kmovw k1, eax and kmovw eax, k1
        ("c5 f8 92 c8", &["rax"], &[]),
        ("c5 f8 93 c1", &[], &["rax"]),
        // kandw k1, k2, k3
        ("c5 ec 41 cb", &[], &[]),
        // vmovd eax, xmm0; vpextrd eax, xmm1, 1; vpinsrd xmm0, xmm0, eax, 1
        ("c5 f9 7e c0", &[], &["rax"]),
        ("c4 e3 79 16 c8 01", &[], &["rax"]),
        ("c4 e3 79 22 c0 01", &["rax"], &[]),
        // vcvttss2si eax, xmm0
        ("c5 fa 2c c0", &[], &["rax"]),
        // mulx rax, rcx, rbx reads rdx.
        ("c4 e2 f3 f6 c3", &["rdx", "rbx"], &["rax", "rcx"]),
        // andn rax, rcx, rbx; blsr rcx, rbx; rorx rax, rbx, 5
        ("c4 e2 f0 f2 c3", &["rcx", "rbx"], &["rax"]),
        ("c4 e2 f0 f3 cb", &["rbx"], &["rcx"]),
        ("c4 e3 fb f0 c3 05", &["rbx"], &["rax"]),
        // cmpoxadd [rdi], eax, ecx
        ("c4 e2 71 e0 07", &["rax", "rcx", "rdi"], &["rax"]),
        // pcmpestri xmm0, xmm1, 0 reads rax and rdx and writes rcx.
        ("66 0f 3a 61 c1 00", &["rax", "rdx"], &["rcx"]),
        // crc32 eax, ecx; adcx eax, ecx; movbe [rdi], eax
        ("f2 0f 38 f1 c1", &["rax", "rcx"], &["rax"]),
        ("66 0f 38 f6 c1", &["rax", "rcx"], &["rax"]),
        ("0f 38 f1 07", &["rax", "rdi"], &[]),
        // vpbroadcastd zmm0, eax
        ("62 f2 7d 48 7c c0", &["rax"], &[]),
        // blcfill ecx, ebx (TBM)
        ("8f e9 70 01 cb", &["rbx"], &["rcx"]),
        // vmaskmovdqu xmm0, xmm1 reads rdi.
        ("c5 f9 f7 c1", &["rdi"], &[]),
        // vzeroall
        ("c5 fc 77", &[], &[]),
        // vgatherdps xmm0, [rax+xmm1*4], xmm2: the VSIB index is a vector register.
        ("c4 e2 69 92 04 88", &["rax"], &[]),
        // vmovdqu32 zmm0{k1}, [rax]
        ("62 f1 7e 49 6f 00", &["rax"], &[]),
        // vpaddd ymm4, ymm5, ymm12: no general register, rsp and rbp included.
        ("c4 c1 55 fe e4", &[], &[]),
    ];
    for (bytes, read, written) in rows {
        let insn = dec(&hex(bytes), AT).unwrap_or_else(|e| panic!("{bytes}: {e}"));
        assert!(insn.is_opaque(), "{bytes}");
        assert_eq!(gpr_names(insn.regs_read()), read, "{bytes}: read");
        assert_eq!(gpr_names(insn.regs_written()), written, "{bytes}: written");
    }
    let masked = dec(&hex("62 f1 7e 49 6f 00"), AT).expect("decode");
    assert!(masked.regs_read().iter().any(|r| r.name() == "k1"));
    let kand = dec(&hex("c5 ec 41 cb"), AT).expect("decode");
    assert!(
        kand.regs_written()
            .iter()
            .any(|r| r.class() == RegClass::Mask)
    );
    assert!(
        kand.regs_written()
            .iter()
            .all(|r| r.class() == RegClass::Mask)
    );
    // An APX form keeps all general registers: add r16d, eax with REX2.
    let apx = dec(&hex("d5 10 01 c0"), AT).expect("decode");
    assert!(apx.is_opaque());
    assert!(apx.regs_written().contains(Reg::RSP));
    assert!(lift::effect(&apx).defs.contains(Loc::Flags));
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

/// Tells if the IR reads `rax` with a `Get`.
fn gets_rax(arena: &Arena) -> bool {
    has(arena, |op| {
        op.opc == Opc::Get && op.a[0] == Arg::L(Loc::RAX)
    })
}

#[test]
fn regress_segment_rip_relative_address() {
    // mov rax, qword ptr gs:[rip+0x10] at 0x1000 reads at gs_base + 0x1018.
    let arena = lifted("65 48 8b 05 10 00 00 00");
    assert!(!gets_rax(&arena), "{:?}", arena.ops());
    let image = FlatImage::new(0x10_1018, (1u8..=8).collect(), false);
    let interp = run(
        &arena,
        &image,
        &[(Loc::GS_BASE, 0x10_0000), (Loc::RAX, 0x2000)],
    );
    assert_eq!(
        interp.loc(Loc::RAX),
        u128::from(u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]))
    );
    // lea rax, gs:[rip+0x10] does not add the segment base.
    let arena = lifted("65 48 8d 05 10 00 00 00");
    assert!(!gets_rax(&arena), "{:?}", arena.ops());
    let empty = FlatImage::default();
    let interp = run(
        &arena,
        &empty,
        &[(Loc::GS_BASE, 0x10_0000), (Loc::RAX, 0x2000)],
    );
    assert_eq!(interp.loc(Loc::RAX), 0x1018);
    // mov eax, dword ptr fs:[rip+0x10] at 0x1000 reads at fs_base + 0x1017.
    let arena = lifted("64 8b 05 10 00 00 00");
    assert!(!gets_rax(&arena), "{:?}", arena.ops());
    let image = FlatImage::new(0x7000 + 0x1017, vec![0x44, 0x33, 0x22, 0x11], false);
    let interp = run(
        &arena,
        &image,
        &[(Loc::FS_BASE, 0x7000), (Loc::RAX, 0x2000)],
    );
    assert_eq!(interp.loc(Loc::RAX), 0x1122_3344);
}

#[test]
fn divide_by_zero_stops() {
    let arena = lifted("f7 f1");
    let stop = Interp::new(&arena, &NoImage, Config::default()).run(AT, &mut Fuel::new(100));
    assert_eq!(stop.reason, StopReason::DivZero);
}

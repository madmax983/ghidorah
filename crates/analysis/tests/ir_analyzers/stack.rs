//! Stack tracking, frames, the CFA cross-check (AC-091) and the escape rule (AC-207).

use ghidorah_analysis::stack::{self, Sp};
use ghidorah_db::FlowKind;
use ghidorah_ir::{Loc, Opc};

use crate::blob::load;
use crate::support::{cached, fid, fir_of, fixtures};

#[test]
fn sp_join_rules() {
    assert_eq!(Sp::Unset.join(Sp::At(-8)), Sp::At(-8));
    assert_eq!(Sp::At(-8).join(Sp::At(-8)), Sp::At(-8));
    assert_eq!(Sp::At(-8).join(Sp::At(-16)), Sp::Top);
    assert_eq!(Sp::Other.join(Sp::Other), Sp::Other);
    assert_eq!(Sp::Other.join(Sp::At(0)), Sp::Top);
    assert_eq!(Sp::Top.join(Sp::Unset), Sp::Top);
    assert_eq!(Sp::At(4).offset(), Some(4));
    assert_eq!(Sp::Top.offset(), None);
}

#[test]
fn stack_offsets_of_a_frame() {
    // push rbp; mov rbp, rsp; push rbx; sub rsp, 0x18; call 0x20; add rsp, 0x18; pop rbx;
    // pop rbp; ret. The callee at 0x20 is a ret.
    let mut bytes = vec![
        0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x18, 0xe8, 0x12, 0x00, 0x00, 0x00, 0x48,
        0x83, 0xc4, 0x18, 0x5b, 0x5d, 0xc3,
    ];
    bytes = crate::blob::pad(bytes, 0x20);
    bytes.push(0xc3);
    let mut p = load(&bytes, 0);
    let _ = crate::support::analyze(&mut p);
    let base = crate::blob::BASE;
    let ir = fir_of(&p, base);
    let frame = ir.frame.as_ref().expect("a frame");
    for (off, sp) in [
        (0x0, 0),
        (0x1, -8),
        (0x4, -8),
        (0x5, -16),
        (0x9, -0x28),
        (0xe, -0x28),
        (0x12, -0x10),
        (0x13, -8),
        (0x14, 0),
    ] {
        assert_eq!(frame.sp_at(base + off), Some(sp), "rsp at {off:#x}");
    }
    assert_eq!(frame.bp.get(&(base + 0x4)), Some(&Sp::At(-8)));
    assert_eq!(frame.saved, [(Loc::RBP, -8), (Loc::RBX, -16)]);
    assert!(frame.low() <= -16);
}

#[test]
fn ac_091_sp_vs_cfa() {
    let mut checked = 0usize;
    for f in fixtures() {
        if !matches!(f.variant.as_str(), "none" | "stripped") {
            continue;
        }
        let p = cached(&f.path);
        for view in p.funcs() {
            if view.func.flags.thunk {
                continue;
            }
            let entry = view.id().0.off;
            let ir = fir_of(p, entry);
            let frame = ir.frame.as_ref().expect("a frame");
            for fde in &p.binary().fdes {
                let calls: Vec<u64> = ir
                    .units
                    .iter()
                    .filter(|(at, u)| {
                        fde.range.contains(**at)
                            && matches!(u.flow, FlowKind::Call | FlowKind::ICall)
                    })
                    .map(|(at, _)| *at)
                    .collect();
                if calls.is_empty() {
                    continue;
                }
                let bad = stack::cfa_check(frame, fde, &calls);
                assert!(bad.is_empty(), "{}: {}: {bad:x?}", f.path, fid(entry));
                checked += calls.len();
            }
        }
    }
    assert!(
        checked > 2_000,
        "the fixtures have call sites with a CFA row: {checked}"
    );
}

/// The ops of the instruction at `addr` of the IR of the blob function.
fn opcodes(ir: &ghidorah_analysis::FuncIr, addr: u64) -> Vec<Opc> {
    let span = ir.insn(addr).expect("an instruction");
    ir.arena
        .span_ops(span)
        .expect("the ops")
        .iter()
        .map(|o| o.opc)
        .collect()
}

#[test]
fn ac_207_intrinsic_escape() {
    // sub rsp, 0x28; mov [rsp+0x10], rdi; mov [rsp+0x20], rsi; paddd xmm0, [rsp+0x10];
    // mov rax, [rsp+0x10]; mov rcx, [rsp+0x20]; add rsp, 0x28; ret.
    let bytes = [
        0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x7c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x20, 0x66,
        0x0f, 0xfe, 0x44, 0x24, 0x10, 0x48, 0x8b, 0x44, 0x24, 0x10, 0x48, 0x8b, 0x4c, 0x24, 0x20,
        0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];
    let mut p = load(&bytes, 0);
    let _ = crate::support::analyze(&mut p);
    let base = crate::blob::BASE;
    let ir = fir_of(&p, base);
    let frame = ir.frame.as_ref().expect("a frame");
    assert!(
        frame.escapes(-0x18, 8),
        "the paddd operand touches the slot"
    );
    assert!(
        frame.escapes(-0x10, 1),
        "the 16 bytes of the operand escape"
    );
    assert!(!frame.escapes(-0x8, 8), "the other slot stays");
    assert!(!frame.all_escape);
    // The escaped slot stays in memory. The other slot becomes a location.
    assert!(opcodes(&ir, base + 0x4).contains(&Opc::Store));
    assert!(opcodes(&ir, base + 0x14).contains(&Opc::Load));
    assert!(!opcodes(&ir, base + 0x9).contains(&Opc::Store));
    assert!(!opcodes(&ir, base + 0x19).contains(&Opc::Load));
    let slot = ir
        .insn(base + 0x19)
        .and_then(|s| ir.arena.span_ops(s))
        .expect("ops");
    assert!(
        slot.iter()
            .any(|o| o.opc == Opc::Get && o.a[0].as_loc() == Some(Loc::Stack(-8))),
        "the read of the kept slot is a Get of Stack(-8)"
    );

    // paddd xmm0, [rsp+rdi*8]: the operand can point to any slot, so every slot escapes.
    let bytes = [
        0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x74, 0x24, 0x20, 0x66, 0x0f, 0xfe, 0x04, 0xfc, 0x48,
        0x8b, 0x4c, 0x24, 0x20, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];
    let mut p = load(&bytes, 0);
    let _ = crate::support::analyze(&mut p);
    let ir = fir_of(&p, base);
    let frame = ir.frame.as_ref().expect("a frame");
    assert!(frame.all_escape);
    assert!(frame.escapes(-0x8, 8));
    assert!(opcodes(&ir, base + 0x4).contains(&Opc::Store));
    assert!(opcodes(&ir, base + 0xe).contains(&Opc::Load));
}

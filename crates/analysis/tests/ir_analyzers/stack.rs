//! Stack tracking, frames, the CFA cross-check (AC-091) and the escape rule (AC-207).

use std::fmt::Write as _;

use ghidorah_analysis::FuncIr;
use ghidorah_analysis::code::decode_at;
use ghidorah_analysis::stack::{self, Sp};
use ghidorah_base::Fuel;
use ghidorah_db::{FlowKind, Program, StartReason};
use ghidorah_ir::{Loc, Opc};
use ghidorah_x86::{Mnem, Operand, Reg};

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

/// The CFA cross-check over the call sites of the fixture functions.
#[derive(Debug, Default)]
struct CfaSites {
    /// The call sites with a CFA row.
    with_row: usize,
    /// The call sites with a CFA row and a tracked offset.
    compared: usize,
    /// The sites where the tracked offset differs from the CFA.
    mismatches: Vec<String>,
    /// The sites with a CFA row and no tracked offset, after a dynamic realign of `rsp`.
    realigned: usize,
    /// The other sites with a CFA row and no tracked offset.
    untracked: Vec<String>,
}

/// Tells if `site` comes after an `and rsp, imm` of the function: a dynamic realign. The
/// tracked offset of `rsp` is then `Top`. The CFA rows of `_start` do not show the realign.
fn after_realign(p: &Program, ir: &FuncIr, site: u64) -> bool {
    ir.units.range(..site).any(|(at, _)| {
        decode_at(p, *at).is_some_and(|insn| {
            insn.mnem() == Mnem::And
                && matches!(insn.op(0), Some(Operand::Reg { reg, .. }) if reg == Reg::RSP)
                && matches!(insn.op(1), Some(Operand::Imm { .. }))
        })
    })
}

/// Compares the tracked offsets with the CFA rows at the call sites of every function of the
/// T1 and T2 fixtures. A `noeh` variant has no FDE. `skip_fde_only` skips the functions that only an FDE starts
/// and the functions with a `.cold` name.
fn cfa_sites(skip_fde_only: bool) -> CfaSites {
    let mut out = CfaSites::default();
    for f in fixtures() {
        let p = cached(&f.path);
        for view in p.funcs() {
            let cold_name = p
                .name(view.id().0)
                .is_some_and(|n| n.text.rsplit_once('.').is_some_and(|(_, s)| s == "cold"));
            let fde_only = view.func.start_reason == StartReason::Fde || cold_name;
            if view.func.flags.thunk || (skip_fde_only && fde_only) {
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
                let report = stack::cfa_check(frame, fde, &calls);
                let where_ = format!("{}: {}", f.path, fid(entry));
                out.mismatches.extend(
                    report
                        .mismatches
                        .iter()
                        .map(|m| format!("{where_}: {m:x?}")),
                );
                for u in &report.untracked {
                    if u.value == Some(Sp::Top) && after_realign(p, &ir, u.site) {
                        out.realigned += 1;
                    } else {
                        out.untracked.push(format!("{where_}: {u:x?}"));
                    }
                }
                out.compared += report.compared;
                out.with_row += calls
                    .iter()
                    .filter(|c| stack::cfa_rule(fde, **c).is_some())
                    .count();
            }
        }
    }
    out
}

#[test]
fn ac_091_sp_vs_cfa() {
    let s = cfa_sites(false);
    assert!(s.compared > 2_000, "compared call sites: {}", s.compared);
    assert!(
        s.mismatches.is_empty(),
        "{} of {}: {:#?}",
        s.mismatches.len(),
        s.compared,
        s.mismatches
    );
    assert!(
        s.untracked.is_empty(),
        "{} of {}: {:#?}",
        s.untracked.len(),
        s.with_row,
        s.untracked
    );
    assert_eq!(
        s.compared + s.realigned,
        s.with_row,
        "each site with a CFA row is compared, or comes after a realign"
    );
    // Each `_start` of a fixture realigns `rsp` before its call of `__libc_start_main`.
    assert!(
        s.realigned * 20 < s.with_row,
        "realigned sites: {} of {}",
        s.realigned,
        s.with_row
    );
}

#[test]
fn cfa_rows_outside_cold_parts() {
    // Before the cold-part merge, an FDE-only function can be a cold part that runs on the
    // frame of its parent. The pipeline test checks those functions too.
    let s = cfa_sites(true);
    assert!(s.compared > 1_000, "compared call sites: {}", s.compared);
    assert!(s.mismatches.is_empty(), "{:#?}", s.mismatches);
}

#[test]
fn regress_vzeroupper_keeps_stack_height() {
    // push rbp; mov rbp, rsp; vzeroupper; leave; ret
    let bytes = [0x55, 0x48, 0x89, 0xe5, 0xc5, 0xf8, 0x77, 0xc9, 0xc3];
    let mut p = load(&bytes, 0);
    let _ = crate::support::analyze(&mut p);
    let base = crate::blob::BASE;
    let ir = fir_of(&p, base);
    let frame = ir.frame.as_ref().expect("a frame");
    assert_eq!(frame.sp_at(base + 0x4), Some(-8), "rsp at vzeroupper");
    assert_eq!(frame.sp_at(base + 0x7), Some(-8), "rsp at leave");
    assert_eq!(frame.sp_at(base + 0x8), Some(0), "rsp at ret");
}

/// The ops of the instruction at `addr` of the IR of the blob function.
fn opcodes(ir: &FuncIr, addr: u64) -> Vec<Opc> {
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
    // The body: `sub rsp, 0x28`, `mov [rsp+0x10], rdi`, `mov [rsp+0x20], rsi`,
    // `paddd xmm0, [rsp+0x10]`, `mov rax, [rsp+0x10]`, `mov rcx, [rsp+0x20]`,
    // `add rsp, 0x28`, `ret`.
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

/// The pinned result of `stack::track` for each fixture: the function count, the sum of the
/// fuel units and the SHA-256 digest of the `Debug` text of all frames.
const TRACK_PINS: &[(&str, usize, u64, &str)] = &[
    (
        "fixtures/bin/adversarial_names.clang-O2",
        15,
        1_332,
        "22a801cf36237acfc8f09cf6ad27f813a98830b96df49eca9362a0e106ae45a3",
    ),
    (
        "fixtures/bin/adversarial_names.clang-O2.stripped",
        15,
        1_332,
        "22a801cf36237acfc8f09cf6ad27f813a98830b96df49eca9362a0e106ae45a3",
    ),
    (
        "fixtures/bin/adversarial_names.gcc-O0",
        15,
        1_698,
        "be460df2bde3be81fe893c178812de90bca0626c1b7dd86a0942200ff389b6d9",
    ),
    (
        "fixtures/bin/adversarial_names.gcc-O0.stripped",
        15,
        1_698,
        "be460df2bde3be81fe893c178812de90bca0626c1b7dd86a0942200ff389b6d9",
    ),
    (
        "fixtures/bin/adversarial_names.gcc-O2",
        15,
        1_323,
        "5ea707238a4a55d2828fb56b87c233cc12171ed782d0fe805863f13d3d295966",
    ),
    (
        "fixtures/bin/adversarial_names.gcc-O2.stripped",
        15,
        1_323,
        "5ea707238a4a55d2828fb56b87c233cc12171ed782d0fe805863f13d3d295966",
    ),
    (
        "fixtures/bin/canary.clang-O2",
        16,
        1_696,
        "f5a4d77c113b6f639b94aa56a622e0861523a476fd34dbba3b0e0b2dbc91e9f3",
    ),
    (
        "fixtures/bin/canary.clang-O2.stripped",
        16,
        1_696,
        "f5a4d77c113b6f639b94aa56a622e0861523a476fd34dbba3b0e0b2dbc91e9f3",
    ),
    (
        "fixtures/bin/canary.gcc-O0",
        17,
        1_938,
        "2a6f93431f064c86d575913e1892d51931be7d33fb45351258c1b22aabd6a0b2",
    ),
    (
        "fixtures/bin/canary.gcc-O0.stripped",
        17,
        1_938,
        "2a6f93431f064c86d575913e1892d51931be7d33fb45351258c1b22aabd6a0b2",
    ),
    (
        "fixtures/bin/canary.gcc-O2",
        16,
        2_315,
        "999f441bd907d8550008fccff36f5e27c05d634815e745f7a361b4a47f4144ee",
    ),
    (
        "fixtures/bin/canary.gcc-O2.stripped",
        16,
        2_315,
        "999f441bd907d8550008fccff36f5e27c05d634815e745f7a361b4a47f4144ee",
    ),
    (
        "fixtures/bin/cold_split.clang-O2",
        16,
        1_827,
        "58ca3959412bf0b11483c165b37d4efbce67318c400d5c7a550d987b9dedbaa4",
    ),
    (
        "fixtures/bin/cold_split.clang-O2.noeh",
        16,
        1_827,
        "58ca3959412bf0b11483c165b37d4efbce67318c400d5c7a550d987b9dedbaa4",
    ),
    (
        "fixtures/bin/cold_split.clang-O2.stripped",
        16,
        1_827,
        "58ca3959412bf0b11483c165b37d4efbce67318c400d5c7a550d987b9dedbaa4",
    ),
    (
        "fixtures/bin/cold_split.gcc-O0",
        16,
        2_358,
        "7f1b4ba14dfedc1b95ca9ae7b6080d06650f0688d1e092e175b005820d8bbb01",
    ),
    (
        "fixtures/bin/cold_split.gcc-O0.stripped",
        16,
        2_358,
        "7f1b4ba14dfedc1b95ca9ae7b6080d06650f0688d1e092e175b005820d8bbb01",
    ),
    (
        "fixtures/bin/cold_split.gcc-O2",
        16,
        1_875,
        "f694590cdf188ebfb40e9b997b2b420b3e2d11acbed242465ce5e6a169fe9945",
    ),
    (
        "fixtures/bin/cold_split.gcc-O2.noeh",
        16,
        1_875,
        "f694590cdf188ebfb40e9b997b2b420b3e2d11acbed242465ce5e6a169fe9945",
    ),
    (
        "fixtures/bin/cold_split.gcc-O2.stripped",
        16,
        1_875,
        "f694590cdf188ebfb40e9b997b2b420b3e2d11acbed242465ce5e6a169fe9945",
    ),
    (
        "fixtures/bin/crackme.clang-O2",
        12,
        1_353,
        "4fa40b9adf4a342c811c178aaa2b7d362e9a37f291db27ca91255572506a4dfe",
    ),
    (
        "fixtures/bin/crackme.clang-O2.noeh",
        12,
        1_353,
        "4fa40b9adf4a342c811c178aaa2b7d362e9a37f291db27ca91255572506a4dfe",
    ),
    (
        "fixtures/bin/crackme.clang-O2.stripped",
        12,
        1_353,
        "4fa40b9adf4a342c811c178aaa2b7d362e9a37f291db27ca91255572506a4dfe",
    ),
    (
        "fixtures/bin/crackme.gcc-O0",
        12,
        1_419,
        "4482163b12dbd075d4c06a52c24f287fa66c6ac36950cc8f290e744faf021cb6",
    ),
    (
        "fixtures/bin/crackme.gcc-O0.stripped",
        12,
        1_419,
        "4482163b12dbd075d4c06a52c24f287fa66c6ac36950cc8f290e744faf021cb6",
    ),
    (
        "fixtures/bin/crackme.gcc-O2",
        12,
        1_284,
        "b79d929be4a5e72fd993303e984d9e7338660e361a991e3c30b58e81bd6aaab4",
    ),
    (
        "fixtures/bin/crackme.gcc-O2.noeh",
        12,
        1_284,
        "b79d929be4a5e72fd993303e984d9e7338660e361a991e3c30b58e81bd6aaab4",
    ),
    (
        "fixtures/bin/crackme.gcc-O2.stripped",
        12,
        1_284,
        "b79d929be4a5e72fd993303e984d9e7338660e361a991e3c30b58e81bd6aaab4",
    ),
    (
        "fixtures/bin/func_ptrs.clang-O2",
        22,
        2_307,
        "e2ad62e4b005403cdc70651d1f651196249d19321019f9990c4057ed91958f7d",
    ),
    (
        "fixtures/bin/func_ptrs.clang-O2.noeh",
        22,
        2_307,
        "e2ad62e4b005403cdc70651d1f651196249d19321019f9990c4057ed91958f7d",
    ),
    (
        "fixtures/bin/func_ptrs.clang-O2.stripped",
        22,
        2_307,
        "e2ad62e4b005403cdc70651d1f651196249d19321019f9990c4057ed91958f7d",
    ),
    (
        "fixtures/bin/func_ptrs.gcc-O0",
        23,
        3_060,
        "d9558e821d8a97af927348c41f682462f5f58e2f08ed8e1e7b0b5e120aa50843",
    ),
    (
        "fixtures/bin/func_ptrs.gcc-O0.stripped",
        23,
        3_060,
        "d9558e821d8a97af927348c41f682462f5f58e2f08ed8e1e7b0b5e120aa50843",
    ),
    (
        "fixtures/bin/func_ptrs.gcc-O2",
        23,
        2_064,
        "de90770b60f7f28acad94cc2766de92c09390c2eb4973c8bdd45a27447e0172b",
    ),
    (
        "fixtures/bin/func_ptrs.gcc-O2.noeh",
        23,
        2_064,
        "de90770b60f7f28acad94cc2766de92c09390c2eb4973c8bdd45a27447e0172b",
    ),
    (
        "fixtures/bin/func_ptrs.gcc-O2.stripped",
        23,
        2_064,
        "de90770b60f7f28acad94cc2766de92c09390c2eb4973c8bdd45a27447e0172b",
    ),
    (
        "fixtures/bin/hello.clang-O2",
        14,
        984,
        "7d7da0dcd97c8dd6104dae8ac44f287fcd17bac8db8feba036c2b60786802daf",
    ),
    (
        "fixtures/bin/hello.clang-O2.stripped",
        14,
        984,
        "7d7da0dcd97c8dd6104dae8ac44f287fcd17bac8db8feba036c2b60786802daf",
    ),
    (
        "fixtures/bin/hello.gcc-O0",
        14,
        1_317,
        "60532e708e8e619ab3aaf054fdf110d1c1c0ec02e469034a4d9db2907c07b7b3",
    ),
    (
        "fixtures/bin/hello.gcc-O0.stripped",
        14,
        1_317,
        "60532e708e8e619ab3aaf054fdf110d1c1c0ec02e469034a4d9db2907c07b7b3",
    ),
    (
        "fixtures/bin/hello.gcc-O2",
        14,
        990,
        "688e61dd745dc537405b4d2d731daf33ef6859641034df1a73cb44600553bafb",
    ),
    (
        "fixtures/bin/hello.gcc-O2-nocet-nopie",
        14,
        954,
        "650c0db9b5ee7146c7f0e3e3670255a2747c1b9fa9e60c93ac6e761680743a91",
    ),
    (
        "fixtures/bin/hello.gcc-O2-noplt",
        12,
        978,
        "d3696913254895bf1428bd451b61dd29c87df7c9e4972da885f38f5fb0e3f79e",
    ),
    (
        "fixtures/bin/hello.gcc-O2.noeh",
        14,
        990,
        "688e61dd745dc537405b4d2d731daf33ef6859641034df1a73cb44600553bafb",
    ),
    (
        "fixtures/bin/hello.gcc-O2.noshdr",
        14,
        990,
        "688e61dd745dc537405b4d2d731daf33ef6859641034df1a73cb44600553bafb",
    ),
    (
        "fixtures/bin/hello.gcc-O2.stripped",
        14,
        990,
        "688e61dd745dc537405b4d2d731daf33ef6859641034df1a73cb44600553bafb",
    ),
    (
        "fixtures/bin/hostile_strings.clang-O2",
        11,
        1_137,
        "cff12f8757ea54e62c488df28e6293f4dd5dec3796f3e11c9c9197bf5d56d30e",
    ),
    (
        "fixtures/bin/hostile_strings.clang-O2.stripped",
        11,
        1_137,
        "cff12f8757ea54e62c488df28e6293f4dd5dec3796f3e11c9c9197bf5d56d30e",
    ),
    (
        "fixtures/bin/hostile_strings.gcc-O0",
        11,
        1_287,
        "86d3a06306d75f25de46ba2d1bd2509fee1b79d7d6f2033797a63ab798f37a8d",
    ),
    (
        "fixtures/bin/hostile_strings.gcc-O0.stripped",
        11,
        1_287,
        "86d3a06306d75f25de46ba2d1bd2509fee1b79d7d6f2033797a63ab798f37a8d",
    ),
    (
        "fixtures/bin/hostile_strings.gcc-O2",
        11,
        1_164,
        "7375fd701eb64c96643ecebef75cb73cfe3b42b2c2a4fb13cd8abcc869b18fb7",
    ),
    (
        "fixtures/bin/hostile_strings.gcc-O2.stripped",
        11,
        1_164,
        "7375fd701eb64c96643ecebef75cb73cfe3b42b2c2a4fb13cd8abcc869b18fb7",
    ),
    (
        "fixtures/bin/large.clang-O2",
        652,
        145_554,
        "36a831042aaf8860007fac7f234bbfb0f9617434bbd1f77a41d9f1f2d66dbade",
    ),
    (
        "fixtures/bin/large.clang-O2.noeh",
        651,
        145_515,
        "5b192eeaa52831600fdfebf0fbfc3459302a80c36b9f76f3aaac00e1115552aa",
    ),
    (
        "fixtures/bin/large.clang-O2.stripped",
        652,
        145_554,
        "36a831042aaf8860007fac7f234bbfb0f9617434bbd1f77a41d9f1f2d66dbade",
    ),
    (
        "fixtures/bin/large.gcc-O2",
        652,
        110_628,
        "56cac0cb0bc55366c2d99b99151b5cac11654835661ab3409f7736867496d376",
    ),
    (
        "fixtures/bin/large.gcc-O2.noeh",
        652,
        110_628,
        "56cac0cb0bc55366c2d99b99151b5cac11654835661ab3409f7736867496d376",
    ),
    (
        "fixtures/bin/large.gcc-O2.stripped",
        652,
        110_628,
        "56cac0cb0bc55366c2d99b99151b5cac11654835661ab3409f7736867496d376",
    ),
    (
        "fixtures/bin/loops.clang-O2",
        16,
        3_168,
        "485807a7b948c4eecf89c62ab8009f0ff76d06bca4631df7a082f06169725516",
    ),
    (
        "fixtures/bin/loops.clang-O2.noeh",
        16,
        3_168,
        "485807a7b948c4eecf89c62ab8009f0ff76d06bca4631df7a082f06169725516",
    ),
    (
        "fixtures/bin/loops.clang-O2.stripped",
        16,
        3_168,
        "485807a7b948c4eecf89c62ab8009f0ff76d06bca4631df7a082f06169725516",
    ),
    (
        "fixtures/bin/loops.clang-O2nv",
        16,
        3_474,
        "d0a3b6f6a59042fb3bebf97674c16b51337dd696248e32c2adffad74ae54962e",
    ),
    (
        "fixtures/bin/loops.gcc-O0",
        16,
        2_745,
        "1f76a849b5d17cacbbe2764981626bc323565ae007f9e41084fbae5b98af4d39",
    ),
    (
        "fixtures/bin/loops.gcc-O0.stripped",
        16,
        2_745,
        "1f76a849b5d17cacbbe2764981626bc323565ae007f9e41084fbae5b98af4d39",
    ),
    (
        "fixtures/bin/loops.gcc-O2",
        16,
        2_499,
        "b8ec11a30bdccca73013cd43fb8e621b6ea4d7d41519a95e09374a842f905d56",
    ),
    (
        "fixtures/bin/loops.gcc-O2.noeh",
        16,
        2_499,
        "b8ec11a30bdccca73013cd43fb8e621b6ea4d7d41519a95e09374a842f905d56",
    ),
    (
        "fixtures/bin/loops.gcc-O2.stripped",
        16,
        2_499,
        "b8ec11a30bdccca73013cd43fb8e621b6ea4d7d41519a95e09374a842f905d56",
    ),
    (
        "fixtures/bin/loops.gcc-O2nv",
        16,
        2_499,
        "b8ec11a30bdccca73013cd43fb8e621b6ea4d7d41519a95e09374a842f905d56",
    ),
    (
        "fixtures/bin/noreturn_wrappers.clang-O2",
        20,
        1_419,
        "d551b1a406be773d7b64bff9f2d9c47ced3775f145279245111e7a1cb557d6af",
    ),
    (
        "fixtures/bin/noreturn_wrappers.clang-O2.stripped",
        20,
        1_419,
        "d551b1a406be773d7b64bff9f2d9c47ced3775f145279245111e7a1cb557d6af",
    ),
    (
        "fixtures/bin/noreturn_wrappers.gcc-O0",
        20,
        1_752,
        "2de1d80c88e97f548f7f12f5cfe8f19e824ee0f31c55d109b54e720688245210",
    ),
    (
        "fixtures/bin/noreturn_wrappers.gcc-O0.stripped",
        20,
        1_752,
        "2de1d80c88e97f548f7f12f5cfe8f19e824ee0f31c55d109b54e720688245210",
    ),
    (
        "fixtures/bin/noreturn_wrappers.gcc-O2",
        20,
        1_518,
        "74f9d6e7511600908599d0405573123689a9fd22482b4f1664c6613933bcf67f",
    ),
    (
        "fixtures/bin/noreturn_wrappers.gcc-O2.stripped",
        20,
        1_518,
        "74f9d6e7511600908599d0405573123689a9fd22482b4f1664c6613933bcf67f",
    ),
    (
        "fixtures/bin/recursion.clang-O2",
        15,
        1_893,
        "4be880840be1188415c362d8b94330bed036751c853cb21ceaabe22b35e96530",
    ),
    (
        "fixtures/bin/recursion.clang-O2.noeh",
        15,
        1_893,
        "4be880840be1188415c362d8b94330bed036751c853cb21ceaabe22b35e96530",
    ),
    (
        "fixtures/bin/recursion.clang-O2.stripped",
        15,
        1_893,
        "4be880840be1188415c362d8b94330bed036751c853cb21ceaabe22b35e96530",
    ),
    (
        "fixtures/bin/recursion.gcc-O0",
        16,
        2_409,
        "80a4d80ca7475cbe94ad483316db644eb07550b93a5bf96892694a8b1af52f74",
    ),
    (
        "fixtures/bin/recursion.gcc-O0.stripped",
        16,
        2_409,
        "80a4d80ca7475cbe94ad483316db644eb07550b93a5bf96892694a8b1af52f74",
    ),
    (
        "fixtures/bin/recursion.gcc-O2",
        16,
        2_076,
        "a8ad1c7d6fcb1ddae334df45a7bad5f22d207b50bf82344f024976967651cac0",
    ),
    (
        "fixtures/bin/recursion.gcc-O2.noeh",
        16,
        2_076,
        "a8ad1c7d6fcb1ddae334df45a7bad5f22d207b50bf82344f024976967651cac0",
    ),
    (
        "fixtures/bin/recursion.gcc-O2.stripped",
        16,
        2_076,
        "a8ad1c7d6fcb1ddae334df45a7bad5f22d207b50bf82344f024976967651cac0",
    ),
    (
        "fixtures/bin/socket_client.clang-O2",
        18,
        1_821,
        "14f5afba8e22db903b0a185b1bd0144d748bb7e49618918b3e804b2cc705ac98",
    ),
    (
        "fixtures/bin/socket_client.clang-O2.stripped",
        18,
        1_821,
        "14f5afba8e22db903b0a185b1bd0144d748bb7e49618918b3e804b2cc705ac98",
    ),
    (
        "fixtures/bin/socket_client.gcc-O0",
        21,
        2_235,
        "3b8776b116e876a76b9c02feebd3612aef0a8977bd53b5575dbc195b1101f930",
    ),
    (
        "fixtures/bin/socket_client.gcc-O0.stripped",
        21,
        2_235,
        "3b8776b116e876a76b9c02feebd3612aef0a8977bd53b5575dbc195b1101f930",
    ),
    (
        "fixtures/bin/socket_client.gcc-O2",
        19,
        2_133,
        "19793c3dd8436d5400d35017b6f4034f4699eb63129690dd27eefa7cdd378d0a",
    ),
    (
        "fixtures/bin/socket_client.gcc-O2-noplt",
        11,
        2_094,
        "59d9dc0476834616e6546c80a530a6856e62454e03a680395183495e6efddcf2",
    ),
    (
        "fixtures/bin/socket_client.gcc-O2.noshdr",
        19,
        2_133,
        "19793c3dd8436d5400d35017b6f4034f4699eb63129690dd27eefa7cdd378d0a",
    ),
    (
        "fixtures/bin/socket_client.gcc-O2.stripped",
        19,
        2_133,
        "19793c3dd8436d5400d35017b6f4034f4699eb63129690dd27eefa7cdd378d0a",
    ),
    (
        "fixtures/bin/strings.clang-O2",
        15,
        1_284,
        "70e2b59c2bd30e392f1eabf33d81de25fb4043c7bc1d0a87d27b8a11284936e4",
    ),
    (
        "fixtures/bin/strings.clang-O2.stripped",
        15,
        1_284,
        "70e2b59c2bd30e392f1eabf33d81de25fb4043c7bc1d0a87d27b8a11284936e4",
    ),
    (
        "fixtures/bin/strings.gcc-O0",
        15,
        1_521,
        "116ed1dccef6317c1a8ec9081447df1b6b661013922b7f0be86475ff893b37b8",
    ),
    (
        "fixtures/bin/strings.gcc-O0.stripped",
        15,
        1_521,
        "116ed1dccef6317c1a8ec9081447df1b6b661013922b7f0be86475ff893b37b8",
    ),
    (
        "fixtures/bin/strings.gcc-O2",
        15,
        1_356,
        "328ebe47c439d33100ba634cc8ef072ec5b1082592bcaa2dace4d4c639e93fa8",
    ),
    (
        "fixtures/bin/strings.gcc-O2.stripped",
        15,
        1_356,
        "328ebe47c439d33100ba634cc8ef072ec5b1082592bcaa2dace4d4c639e93fa8",
    ),
    (
        "fixtures/bin/struct_access.clang-O2",
        17,
        1_689,
        "c3fb5d1420ea4bbe3e15554256344c7c319391b0b74d375129df568b31b28101",
    ),
    (
        "fixtures/bin/struct_access.clang-O2.stripped",
        17,
        1_689,
        "c3fb5d1420ea4bbe3e15554256344c7c319391b0b74d375129df568b31b28101",
    ),
    (
        "fixtures/bin/struct_access.gcc-O0",
        17,
        2_112,
        "089d6c58cadfa2e7b526818cfe4f43e1873bd568d1a620955752b8def20fce62",
    ),
    (
        "fixtures/bin/struct_access.gcc-O0.stripped",
        17,
        2_112,
        "089d6c58cadfa2e7b526818cfe4f43e1873bd568d1a620955752b8def20fce62",
    ),
    (
        "fixtures/bin/struct_access.gcc-O2",
        17,
        1_806,
        "db004ff52a3d17731b870ec9ed375b7e345da0d40bbb1c5aa25a2eaad2f3fb2d",
    ),
    (
        "fixtures/bin/struct_access.gcc-O2.stripped",
        17,
        1_806,
        "db004ff52a3d17731b870ec9ed375b7e345da0d40bbb1c5aa25a2eaad2f3fb2d",
    ),
    (
        "fixtures/bin/switch.clang-O2",
        15,
        1_701,
        "def44fc45562ddf45791ee12ac5e349cf573bff019dc12656f90ba7439c2af30",
    ),
    (
        "fixtures/bin/switch.clang-O2.noeh",
        15,
        1_701,
        "def44fc45562ddf45791ee12ac5e349cf573bff019dc12656f90ba7439c2af30",
    ),
    (
        "fixtures/bin/switch.clang-O2.stripped",
        15,
        1_701,
        "def44fc45562ddf45791ee12ac5e349cf573bff019dc12656f90ba7439c2af30",
    ),
    (
        "fixtures/bin/switch.clang-O2nv",
        15,
        1_701,
        "def44fc45562ddf45791ee12ac5e349cf573bff019dc12656f90ba7439c2af30",
    ),
    (
        "fixtures/bin/switch.gcc-O0",
        15,
        2_289,
        "e59fe782076c1966dbfffbdbfd2b9cce0c7f2b6d7ee9181fcad0dd45370aa8b0",
    ),
    (
        "fixtures/bin/switch.gcc-O0.stripped",
        15,
        2_289,
        "e59fe782076c1966dbfffbdbfd2b9cce0c7f2b6d7ee9181fcad0dd45370aa8b0",
    ),
    (
        "fixtures/bin/switch.gcc-O2",
        15,
        1_842,
        "e2003c7cb213ee27096a451dc9e2ce1d7dc738197da82d63d7bf93d72a46b071",
    ),
    (
        "fixtures/bin/switch.gcc-O2-at400000",
        15,
        1_770,
        "1e085d036573df077dc54276df138a8a8ed4f2d5c6b58a0f29548d4fbbcb1118",
    ),
    (
        "fixtures/bin/switch.gcc-O2-at800000",
        15,
        1_770,
        "4b77d63b4788b7243e6e69d61c19e0604389fa8b1d7d298e926e8dfce18fbe02",
    ),
    (
        "fixtures/bin/switch.gcc-O2.noeh",
        15,
        1_842,
        "e2003c7cb213ee27096a451dc9e2ce1d7dc738197da82d63d7bf93d72a46b071",
    ),
    (
        "fixtures/bin/switch.gcc-O2.stripped",
        15,
        1_842,
        "e2003c7cb213ee27096a451dc9e2ce1d7dc738197da82d63d7bf93d72a46b071",
    ),
    (
        "fixtures/bin/switch.gcc-O2nv",
        15,
        1_842,
        "e2003c7cb213ee27096a451dc9e2ce1d7dc738197da82d63d7bf93d72a46b071",
    ),
    (
        "fixtures/bin/syscall_only.clang-O2",
        5,
        231,
        "3db9854a4c054856786e32c8ff95e2ea2512d34aa64c60578101668e9a236ce2",
    ),
    (
        "fixtures/bin/syscall_only.clang-O2.stripped",
        5,
        231,
        "3db9854a4c054856786e32c8ff95e2ea2512d34aa64c60578101668e9a236ce2",
    ),
    (
        "fixtures/bin/syscall_only.gcc-O0",
        5,
        429,
        "9a36a869b55bfdb8c415c692400689cd4ba6dcac4ede760e1f8fb38491066857",
    ),
    (
        "fixtures/bin/syscall_only.gcc-O0.stripped",
        5,
        429,
        "9a36a869b55bfdb8c415c692400689cd4ba6dcac4ede760e1f8fb38491066857",
    ),
    (
        "fixtures/bin/syscall_only.gcc-O2",
        5,
        276,
        "0ab1d46597e4fe9e9b163843cca75dd52685d479868d5206dc54b91532fcad21",
    ),
    (
        "fixtures/bin/syscall_only.gcc-O2.stripped",
        5,
        276,
        "0ab1d46597e4fe9e9b163843cca75dd52685d479868d5206dc54b91532fcad21",
    ),
    (
        "fixtures/bin/two_helpers.clang-O2",
        14,
        1_278,
        "10ff40283ffe85fecda48316d7da47c8623c3c6661d278ccf67c047e7e943389",
    ),
    (
        "fixtures/bin/two_helpers.clang-O2.stripped",
        14,
        1_278,
        "10ff40283ffe85fecda48316d7da47c8623c3c6661d278ccf67c047e7e943389",
    ),
    (
        "fixtures/bin/two_helpers.gcc-O0",
        14,
        1_623,
        "fef86ebd2386814fe3ac465c88bb342eec84406ee24160c74c1485fc3a86c7af",
    ),
    (
        "fixtures/bin/two_helpers.gcc-O0.stripped",
        14,
        1_623,
        "fef86ebd2386814fe3ac465c88bb342eec84406ee24160c74c1485fc3a86c7af",
    ),
    (
        "fixtures/bin/two_helpers.gcc-O2",
        14,
        1_275,
        "7b36d6cb155e165d73553f219577cff3f650309e9a67c12a0751ca2af76c7c97",
    ),
    (
        "fixtures/bin/two_helpers.gcc-O2.stripped",
        14,
        1_275,
        "7b36d6cb155e165d73553f219577cff3f650309e9a67c12a0751ca2af76c7c97",
    ),
    (
        "fixtures/bin/varargs.clang-O2",
        23,
        3_861,
        "23774f734f1a9e8267c728e39bd97fd3c0cabebad153c2597daba80805dde084",
    ),
    (
        "fixtures/bin/varargs.clang-O2.stripped",
        23,
        3_861,
        "23774f734f1a9e8267c728e39bd97fd3c0cabebad153c2597daba80805dde084",
    ),
    (
        "fixtures/bin/varargs.gcc-O0",
        24,
        5_484,
        "3e44dd30f1803cc8f6bd9bea5e15495e42844972ed3c5c6e8917c914d3ccac6f",
    ),
    (
        "fixtures/bin/varargs.gcc-O0.stripped",
        24,
        5_484,
        "3e44dd30f1803cc8f6bd9bea5e15495e42844972ed3c5c6e8917c914d3ccac6f",
    ),
    (
        "fixtures/bin/varargs.gcc-O2",
        24,
        3_855,
        "3a8ced087a2d4c66e38d4516136b6a847157896ccb145a229486a838d88f854f",
    ),
    (
        "fixtures/bin/varargs.gcc-O2.stripped",
        24,
        3_855,
        "3a8ced087a2d4c66e38d4516136b6a847157896ccb145a229486a838d88f854f",
    ),
    (
        "fixtures/bin/xor_decode.clang-O2",
        17,
        1_821,
        "d5bc84f416e7bc81d59aaa1ef6af0ec9d71e860392ec2e0d29895ff5f60ae517",
    ),
    (
        "fixtures/bin/xor_decode.clang-O2.stripped",
        17,
        1_821,
        "d5bc84f416e7bc81d59aaa1ef6af0ec9d71e860392ec2e0d29895ff5f60ae517",
    ),
    (
        "fixtures/bin/xor_decode.clang-O2nv",
        17,
        1_821,
        "d5bc84f416e7bc81d59aaa1ef6af0ec9d71e860392ec2e0d29895ff5f60ae517",
    ),
    (
        "fixtures/bin/xor_decode.gcc-O0",
        18,
        2_490,
        "4d395406333b06a1faf9a48399934052fbf614288072d3b364514b8bda8d75d9",
    ),
    (
        "fixtures/bin/xor_decode.gcc-O0.stripped",
        18,
        2_490,
        "4d395406333b06a1faf9a48399934052fbf614288072d3b364514b8bda8d75d9",
    ),
    (
        "fixtures/bin/xor_decode.gcc-O2",
        18,
        1_983,
        "092674c96b2face80bad0c2c14e74ea15fb4581c6f172b6cca1c9cc28eb5bab8",
    ),
    (
        "fixtures/bin/xor_decode.gcc-O2.stripped",
        18,
        1_983,
        "092674c96b2face80bad0c2c14e74ea15fb4581c6f172b6cca1c9cc28eb5bab8",
    ),
    (
        "fixtures/bin/xor_decode.gcc-O2nv",
        18,
        1_983,
        "092674c96b2face80bad0c2c14e74ea15fb4581c6f172b6cca1c9cc28eb5bab8",
    ),
    (
        "fixtures/bin/pe/pe_main.exe",
        13,
        2_106,
        "75eb91a94d1d18fb51bdb32b98005eb0da7bee432b88e3484c646f94283b857c",
    ),
];

/// `stack::track` gives the pinned frames and fuel units for each function of each fixture. A
/// tank with less fuel than the full run fails with `needed == 1` and an empty tank. So a
/// change of the pass order cannot change the frames, the fuel or the fuel error.
#[test]
fn track_frames_and_fuel_are_pinned() {
    let opts = ghidorah_analysis::fir::Opts {
        fuse: true,
        stack: false,
    };
    let mut paths: Vec<String> = fixtures().into_iter().map(|f| f.path).collect();
    paths.push("fixtures/bin/pe/pe_main.exe".to_owned());
    let mut got = Vec::new();
    for path in &paths {
        let p = cached(path);
        let (mut funcs, mut fuel, mut text) = (0usize, 0u64, String::new());
        for view in p.funcs() {
            let Ok(ir) = ghidorah_analysis::fir::build(p, view.id(), &opts, &mut Fuel::unlimited())
            else {
                continue;
            };
            let mut tank = Fuel::unlimited();
            let frame = stack::track(&ir.arena, &ir.body, &mut tank).expect("unlimited fuel");
            let used = tank.used();
            let mut short = Fuel::new(used - 1);
            let err = stack::track(&ir.arena, &ir.body, &mut short).expect_err("one unit short");
            assert_eq!(err.needed, 1, "{path} {:?}", view.id());
            assert!(short.is_empty(), "{path} {:?}", view.id());
            for limit in [used / 4, used / 2, used * 3 / 4] {
                let mut part = Fuel::new(limit);
                let err = stack::track(&ir.arena, &ir.body, &mut part).expect_err("a part tank");
                assert_eq!((err.needed, part.used()), (1, limit), "{path} {limit}");
            }
            let mut exact = Fuel::new(used);
            assert_eq!(
                stack::track(&ir.arena, &ir.body, &mut exact),
                Ok(frame.clone())
            );
            funcs += 1;
            fuel += used;
            writeln!(text, "{:?} {frame:?}", view.id()).expect("a String write");
        }
        let digest = ghidorah_base::sha256::sha256_hex(text.as_bytes());
        got.push((path.clone(), funcs, fuel, digest));
    }
    let want: Vec<(String, usize, u64, String)> = TRACK_PINS
        .iter()
        .map(|(p, n, f, d)| ((*p).to_owned(), *n, *f, (*d).to_owned()))
        .collect();
    assert_eq!(got, want);
}

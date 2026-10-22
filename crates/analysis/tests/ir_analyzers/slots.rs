//! The parameter slots of a signature (design Section 7.10): `SysV` numbers its integer and
//! floating slots apart, and MS x64 slots are positional.

use ghidorah_analysis::cc::{self, ParamSource, Params};
use ghidorah_analysis::fir::callsite;
use ghidorah_base::Fuel;
use ghidorah_db::{Edit, Program, SessionLabel, Source};
use ghidorah_ir::Loc;
use ghidorah_types::cc::{MS_X64, SYSV_X86_64};

use crate::blob::{BASE, load};
use crate::support::{analyze, fid};

/// Gives the register `xmm<n>`.
fn xmm(n: u8) -> Loc {
    Loc::xmm(n).expect("an XMM register")
}

/// Gives the general register `n` (0 is `rax`).
fn gpr(n: u8) -> Loc {
    Loc::gpr(n).expect("a general register")
}

/// A `SysV` parameter takes the next free register of its class. A full class goes to the
/// stack, from offset 8 at entry.
#[test]
fn sysv_signature_slots_follow_classes() {
    let (rdi, rsi, rdx, rcx, r8, r9) = (gpr(7), gpr(6), gpr(2), gpr(1), gpr(8), gpr(9));
    assert_eq!(
        callsite::sig_slots(&SYSV_X86_64, &[true, false, false, true]),
        [xmm(0), rdi, rsi, xmm(1)]
    );
    assert_eq!(
        callsite::sig_slots(&SYSV_X86_64, &[false; 8]),
        [rdi, rsi, rdx, rcx, r8, r9, Loc::Stack(8), Loc::Stack(16)]
    );
    let mut nine = vec![true; 9];
    nine.push(false);
    let slots = callsite::sig_slots(&SYSV_X86_64, &nine);
    assert_eq!(slots[8], Loc::Stack(8), "{slots:?}");
    assert_eq!(slots[9], rdi, "{slots:?}");
    assert!(callsite::sig_slots(&SYSV_X86_64, &[]).is_empty());
}

/// An MS x64 parameter n takes slot n of the integer list or of the floating list. The
/// parameters after the four register slots are on the stack, from offset 0x28 at entry.
#[test]
fn positional_signature_slots() {
    let (rdx, r9) = (gpr(2), gpr(9));
    assert_eq!(
        callsite::sig_slots(&MS_X64, &[true, false, true, false, false, true]),
        [xmm(0), rdx, xmm(2), r9, Loc::Stack(0x28), Loc::Stack(0x30)]
    );
}

/// Gives the analyzed blob `ret` with the signature `sig` on its function.
fn with_sig(sig: &str) -> Program {
    let mut p = load(&[0xc3], 0);
    let _ = analyze(&mut p);
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("edit", Source::User, label).expect("a transaction");
    let parsed = tx.parse_sig(sig).expect("the signature parses");
    let edit = Edit::SetSignature {
        id: fid(BASE),
        sig: Some(tx.fact(parsed.ty)),
    };
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
    p
}

/// A `SysV` signature counts its integer and floating parameters apart. The slots give `x` of
/// `double f(double x, int k)` the register `xmm0` and `k` the register `rdi`. A function
/// with no signature or prototype has no fixed slots.
#[test]
fn signature_params_count_floats_apart() {
    let p = with_sig("double f(double x, int k, float y)");
    let (params, source) = cc::params(&p, fid(BASE), &mut Fuel::new(1_000_000)).expect("params");
    assert_eq!(source, ParamSource::Signature);
    assert_eq!(
        params,
        Params {
            int: 1,
            float: 2,
            stack: 0,
            varargs: false,
        }
    );
    assert_eq!(
        callsite::fixed_slots(&p, fid(BASE)),
        Some(vec![xmm(0), gpr(7), xmm(1)])
    );
    let arity = callsite::callee_arity(&p, BASE, cc::conv_of(&p)).expect("an arity");
    assert_eq!(arity.int, 1);
    let mut bare = load(&[0xc3], 0);
    let _ = analyze(&mut bare);
    assert_eq!(callsite::fixed_slots(&bare, fid(BASE)), None);
}

/// Gives the use list of the first call op of the function at `BASE` of `p` in `conv`, with
/// the callee arity `arity`.
fn first_call_uses(
    p: &Program,
    conv: &ghidorah_types::CallConv,
    arity: &dyn Fn(u64) -> Option<callsite::Arity>,
) -> Vec<Loc> {
    let l0 = crate::support::fir_of(p, BASE);
    let uses = callsite::uses(&l0, &l0.arena, conv, arity);
    uses.into_values().next().expect("a call op")
}

/// A call kept every XMM argument register as a use, also for a callee that reads fewer. So
/// unread XMM values stayed alive and took `vN` names. Now a callee with a known count keeps
/// only its XMM argument registers. In a positional convention the count is the slot count.
#[test]
fn regress_call_uses_keep_callee_xmm_count() {
    // 0x00: call g; ret. 0x10 g: addsd xmm0, xmm1; ret.
    let mut bytes = vec![0xe8, 0x0b, 0, 0, 0, 0xc3];
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&[0xf2, 0x0f, 0x58, 0xc1, 0xc3]);
    let mut p = load(&bytes, 0);
    let _ = analyze(&mut p);
    let conv = cc::conv_of(&p);
    let arity = callsite::callee_arity(&p, BASE + 0x10, conv).expect("an arity");
    assert_eq!((arity.int, arity.float, arity.varargs), (0, 2, false));
    let list = first_call_uses(&p, conv, &|t| callsite::callee_arity(&p, t, conv));
    for n in 0..8 {
        assert_eq!(list.contains(&xmm(n)), n < 2, "xmm{n}: {list:?}");
    }
    let sysv = |int, float| {
        move |_: u64| {
            Some(callsite::Arity {
                int,
                float,
                varargs: false,
            })
        }
    };
    let list = first_call_uses(&p, &SYSV_X86_64, &sysv(1, 0));
    assert!(list.contains(&gpr(7)), "{list:?}");
    assert!(
        !list.iter().any(|l| (0..16).any(|n| *l == xmm(n))),
        "{list:?}"
    );
    // A variadic callee keeps all of them and `al`.
    let list = first_call_uses(&p, &SYSV_X86_64, &|_| {
        Some(callsite::Arity {
            int: 1,
            float: 0,
            varargs: true,
        })
    });
    assert!((0..8).all(|n| list.contains(&xmm(n))), "{list:?}");
    // MS x64: two slots keep rcx, rdx, xmm0 and xmm1.
    let list = first_call_uses(&p, &MS_X64, &sysv(2, 2));
    for n in 0..4 {
        assert_eq!(list.contains(&xmm(n)), n < 2, "MS x64 xmm{n}: {list:?}");
    }
    assert!(list.contains(&gpr(1)) && list.contains(&gpr(2)), "{list:?}");
    assert!(
        !list.contains(&gpr(8)) && !list.contains(&gpr(9)),
        "{list:?}"
    );
}

/// A recovered callee that passes its registers on to a target with no facts reads no XMM
/// register by the solve. The narrow use list then dropped the XMM arguments of its calls.
/// Now such a callee keeps every XMM argument register. So does a signature with a record
/// parameter, because a record can travel in XMM registers.
#[test]
fn regress_open_callee_keeps_xmm_uses() {
    // 0x00: call w; call v; ret. 0x10 w: jmp [rip + 0x0a] (the qword at 0x20). 0x30 v:
    // call rax; ret.
    let mut bytes = vec![0xe8, 0x0b, 0, 0, 0, 0xe8, 0x26, 0, 0, 0, 0xc3];
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&[0xff, 0x25, 0x0a, 0, 0, 0]);
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&(BASE + 0x40).to_le_bytes());
    bytes.resize(0x30, 0xcc);
    bytes.extend_from_slice(&[0xff, 0xd0, 0xc3]);
    bytes.resize(0x40, 0xcc);
    bytes.push(0xc3);
    let mut p = load(&bytes, 0);
    let _ = analyze(&mut p);
    let conv = cc::conv_of(&p);
    for at in [BASE + 0x10, BASE + 0x30] {
        assert!(p.func(fid(at)).is_some(), "{at:#x} is a function");
        let arity = callsite::callee_arity(&p, at, conv).expect("an arity");
        assert_eq!(arity.float, 8, "{at:#x}: {arity:?}");
    }
    let rec = with_sig("double f(struct timespec t)");
    let arity = callsite::callee_arity(&rec, BASE, cc::conv_of(&rec)).expect("an arity");
    assert_eq!(arity.float, 8, "a record parameter: {arity:?}");
}

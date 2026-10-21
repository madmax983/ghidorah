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

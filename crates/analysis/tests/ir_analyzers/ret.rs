//! The floating return of a function (design Section 7.10): the facts and the recovery.

use std::time::{Duration, Instant};

use ghidorah_analysis::fir::callsite::Memo;
use ghidorah_analysis::fir::l1;
use ghidorah_analysis::fir::ret::{self, FloatRet, RetValue};
use ghidorah_base::{Address, Fuel};
use ghidorah_db::{Edit, Program, SessionLabel, Source, SymKind};
use ghidorah_ir::Loc;
use ghidorah_types::Prim;
use ghidorah_types::cc::{MS_X64, SYSV_X86_64};

use crate::blob::{BASE, load};
use crate::support::{analyze, cached, fid, fir_of, named};

/// Gives the analyzed program of the blob `bytes` with the entry at its start.
fn blob(bytes: &[u8]) -> Program {
    let mut p = load(bytes, 0);
    let _ = analyze(&mut p);
    p
}

/// Gives the recovered floating return of the blob `bytes`.
fn recovered(bytes: &[u8]) -> Option<FloatRet> {
    let p = blob(bytes);
    ret::recover(&fir_of(&p, BASE))
}

/// Gives the floating return of the blob `bytes` after one edit of its function.
fn with_edit(
    bytes: &[u8],
    make: impl FnOnce(&mut ghidorah_db::Tx<'_>) -> Edit,
) -> Option<FloatRet> {
    let mut p = blob(bytes);
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("edit", Source::User, label).expect("a transaction");
    let edit = make(&mut tx);
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
    ret::float_ret(&p, fid(BASE), &fir_of(&p, BASE))
}

/// Gives the signature edit of the C text `sig` on the blob function.
fn sig_edit(tx: &mut ghidorah_db::Tx<'_>, sig: &str) -> Edit {
    let parsed = tx.parse_sig(sig).expect("the signature parses");
    Edit::SetSignature {
        id: fid(BASE),
        sig: Some(tx.fact(parsed.ty)),
    }
}

/// Gives the name edit of `name` on the blob function.
fn name_edit(tx: &ghidorah_db::Tx<'_>, name: &str) -> Edit {
    Edit::SetName {
        addr: Address::ram(BASE),
        key: None,
        kind: SymKind::Function,
        primary: true,
        name: Some(tx.fact(name.to_owned())),
        evidence: Vec::new(),
    }
}

/// `addsd xmm0, xmm1`.
const ADDSD: [u8; 4] = [0xf2, 0x0f, 0x58, 0xc1];

/// `ret`.
const RET: u8 = 0xc3;

/// An unread write of `xmm0` before a `ret` is a floating return. Its op gives the kind.
#[test]
fn regress_float_return_is_recovered() {
    let cases: [(&[u8], Option<FloatRet>, &str); 11] = [
        (
            &[0xf2, 0x0f, 0x58, 0xc1, RET],
            Some(FloatRet::Double),
            "addsd",
        ),
        (
            &[0xf3, 0x0f, 0x58, 0xc1, RET],
            Some(FloatRet::Float),
            "addss",
        ),
        (
            &[0x66, 0x0f, 0xef, 0xc0, RET],
            Some(FloatRet::Double),
            "pxor zero",
        ),
        (
            &[0xf3, 0x0f, 0x10, 0x05, 0, 0, 0, 0, RET],
            Some(FloatRet::Float),
            "movss load",
        ),
        (&[RET], None, "the entry value"),
        (&[0x66, 0x0f, 0xfe, 0xc1, RET], None, "paddd"),
        (&[0x66, 0x0f, 0x2e, 0xc1, RET], None, "ucomisd reads"),
        (
            &[0xf2, 0x0f, 0x58, 0xc1, 0xf2, 0x0f, 0x11, 0x07, RET],
            None,
            "a store reads the sum",
        ),
        (
            &[0xf2, 0x0f, 0x58, 0xc1, 0xb8, 1, 0, 0, 0, RET],
            None,
            "an integer return",
        ),
        (
            &[0xf2, 0x0f, 0x58, 0xc1, 0xe8, 0, 0, 0, 0, RET],
            None,
            "a call writes xmm0",
        ),
        (
            &[0xf2, 0x0f, 0x58, 0xc1, 0x0f, 0x05, RET],
            None,
            "a syscall",
        ),
    ];
    for (bytes, want, what) in cases {
        assert_eq!(recovered(bytes), want, "{what}");
    }
}

/// The walk goes back over the predecessors of a `ret` block. A `float` path and a `double`
/// path give `double`.
#[test]
fn float_return_over_blocks() {
    // addsd xmm0, xmm1; test edi, edi; je L; nop; L: ret
    let mut joined = ADDSD.to_vec();
    joined.extend([0x85, 0xff, 0x74, 0x01, 0x90, RET]);
    assert_eq!(recovered(&joined), Some(FloatRet::Double));
    // test edi, edi; je L; addsd xmm0, xmm1; ret; L: mulss xmm0, xmm1; ret
    let mut split = vec![0x85, 0xff, 0x74, 0x05];
    split.extend(ADDSD);
    split.extend([RET, 0xf3, 0x0f, 0x59, 0xc1, RET]);
    assert_eq!(recovered(&split), Some(FloatRet::Double));
}

/// A signature fact or the Tier-0 prototype of the name wins over the recovery.
#[test]
fn float_return_from_facts() {
    let int_body = [0xb8, 1, 0, 0, 0, RET];
    let mut float_body = ADDSD.to_vec();
    float_body.push(RET);
    let sig = |text: &'static str| move |tx: &mut ghidorah_db::Tx<'_>| sig_edit(tx, text);
    assert_eq!(
        with_edit(&int_body, sig("double f(void)")),
        Some(FloatRet::Double)
    );
    assert_eq!(
        with_edit(&int_body, sig("float f(void)")),
        Some(FloatRet::Float)
    );
    assert_eq!(with_edit(&float_body, sig("int f(void)")), None);
    let name = |text: &'static str| move |tx: &mut ghidorah_db::Tx<'_>| name_edit(tx, text);
    assert_eq!(with_edit(&int_body, name("atof")), Some(FloatRet::Double));
    assert_eq!(with_edit(&float_body, name("strlen")), None);
    let p = blob(&float_body);
    assert_eq!(
        ret::float_ret(&p, fid(BASE), &fir_of(&p, BASE)),
        Some(FloatRet::Double),
        "no fact: the recovery"
    );
    assert_eq!(FloatRet::Float.c_name(), "float");
    assert_eq!(FloatRet::Double.prim(), Prim::Double);
    assert_eq!(FloatRet::Float.prim(), Prim::Float);
}

/// A floating return makes each `Ret` of L1 read the first floating return register. The
/// fixtures give the kind of each floating function.
#[test]
fn float_return_of_fixtures() {
    let xmm0 = Loc::xmm(0).expect("xmm0");
    for conv in [&SYSV_X86_64, &MS_X64] {
        let opts = l1::ret_opts(conv, Some(FloatRet::Double));
        assert!(opts.ret_uses.contains(xmm0) && !opts.ret_uses.contains(Loc::RAX));
        let opts = l1::ret_opts(conv, None);
        assert!(opts.ret_uses.contains(Loc::RAX) && !opts.ret_uses.contains(xmm0));
    }
    let pe = cached("fixtures/bin/pe/pe_cc.exe");
    for (entry, want) in [
        (0x1_4000_1000, None),
        (0x1_4000_1100, Some(FloatRet::Double)),
        (0x1_4000_1170, Some(FloatRet::Double)),
        (0x1_4000_11c0, Some(FloatRet::Float)),
        (0x1_4000_11e0, None),
    ] {
        let l1 = l1::build(
            pe,
            fid(entry),
            &ghidorah_analysis::fir::Opts::DEFAULT,
            &ghidorah_ir::Switches::all(),
            &mut ghidorah_base::Fuel::unlimited(),
        )
        .expect("the L1 form");
        assert_eq!(l1.float_ret, want, "{entry:#x}");
    }
    for build in ["varargs.gcc-O0", "varargs.gcc-O2", "varargs.clang-O2"] {
        let p = cached(&format!("fixtures/bin/{build}"));
        for (name, want) in [
            ("scale", Some(FloatRet::Double)),
            ("main", None),
            ("log_msg", None),
            ("p2", None),
        ] {
            let entry = named(p, name);
            let got = ret::float_ret(p, fid(entry), &fir_of(p, entry));
            assert_eq!(got, want, "{build} {name}");
        }
    }
}

/// The count of the `ret` blocks of the long chain.
const CHAIN: usize = 10_000;

/// The walks from the `ret` blocks of a function share one visit of each block. A walk from
/// each `ret` read the chain of jumps before it again, so a chain of many `ret` blocks took a
/// quadratic time.
#[test]
fn regress_float_return_walk_is_linear() {
    // CHAIN times `jne +1; ret`, then `addsd xmm0, xmm1; ret`.
    let mut bytes = Vec::new();
    for _ in 0..CHAIN {
        bytes.extend([0x75, 0x01, RET]);
    }
    bytes.extend(ADDSD);
    bytes.push(RET);
    let p = blob(&bytes);
    let ir = fir_of(&p, BASE);
    assert!(ir.body.blocks.len() > 2 * CHAIN, "{}", ir.body.blocks.len());
    let start = Instant::now();
    let got = ret::recover(&ir);
    let took = start.elapsed();
    assert_eq!(got, Some(FloatRet::Double));
    assert!(took < Duration::from_secs(1), "the walk took {took:?}");
}

/// A `ret` that returns the entry value of `rax` gives no value. A read of `rax` is no write.
/// A write of `rax` or a call before the `ret` gives an integer value. A floating return gives
/// a floating value. A `void` signature gives no value, and an integer signature an integer
/// value.
#[test]
fn return_value_is_recovered() {
    let value = |bytes: &[u8]| ret::recover_value(&fir_of(&blob(bytes), BASE));
    // ret
    assert_eq!(value(&[RET]), RetValue::Void);
    // mov [rdi], esi; ret
    assert_eq!(value(&[0x89, 0x37, RET]), RetValue::Void);
    // test eax, eax; ret
    assert_eq!(value(&[0x85, 0xc0, RET]), RetValue::Void);
    // mov eax, 1; ret
    assert_eq!(value(&[0xb8, 1, 0, 0, 0, RET]), RetValue::Int);
    // call +0; ret
    assert_eq!(value(&[0xe8, 0, 0, 0, 0, RET]), RetValue::Int);
    // addsd xmm0, xmm1; ret
    let mut float_body = ADDSD.to_vec();
    float_body.push(RET);
    assert_eq!(value(&float_body), RetValue::Float(FloatRet::Double));
    let sig = |text: &'static str| move |tx: &mut ghidorah_db::Tx<'_>| sig_edit(tx, text);
    let p = with_sig_program(&[0xb8, 1, 0, 0, 0, RET], sig("void f(int x)"));
    assert_eq!(
        ret::ret_value(&p, fid(BASE), &fir_of(&p, BASE)),
        RetValue::Void
    );
    let p = with_sig_program(&[RET], sig("long f(void)"));
    assert_eq!(
        ret::ret_value(&p, fid(BASE), &fir_of(&p, BASE)),
        RetValue::Int
    );
}

/// Gives the analyzed blob `bytes` after one edit of its function.
fn with_sig_program(bytes: &[u8], make: impl FnOnce(&mut ghidorah_db::Tx<'_>) -> Edit) -> Program {
    let mut p = blob(bytes);
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("edit", Source::User, label).expect("a transaction");
    let edit = make(&mut tx);
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
    p
}

/// `ret_value_in` gives the return value of a callee: the Tier-0 prototype of an import
/// stub, else the recovery over the solve memo. Another address gives `None`.
#[test]
fn callee_return_values() {
    let p = cached("fixtures/bin/hello.gcc-O2");
    let mut memo = Memo::default();
    let mut fuel = Fuel::new(10_000_000);
    let mut at = |name: &str| {
        let entry = named(p, name);
        ret::ret_value_in(p, entry, &mut memo, &mut fuel)
    };
    assert_eq!(at("__cxa_finalize@plt"), Some(RetValue::Void));
    assert_eq!(at("puts@plt"), Some(RetValue::Int));
    assert_eq!(at("greet"), Some(RetValue::Int));
    assert_eq!(ret::ret_value_in(p, 0x3, &mut memo, &mut fuel), None);
    let slot = p
        .imports()
        .values()
        .find(|r| r.id.name() == Some("puts"))
        .and_then(|r| r.slot)
        .expect("the slot of puts");
    assert_eq!(
        ret::ret_value_in(p, slot.off, &mut memo, &mut fuel),
        Some(RetValue::Int)
    );
}

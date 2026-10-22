//! The floating return of a function (design Section 7.10): the facts and the recovery.

use std::time::{Duration, Instant};

use ghidorah_analysis::fir::callsite::Memo;
use ghidorah_analysis::fir::l1;
use ghidorah_analysis::fir::ret::{self, FloatRet, RetValue};
use ghidorah_base::{Address, Fuel};
use ghidorah_db::{Edit, Program, SessionLabel, Source, SymKind};
use ghidorah_ir::Loc;
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::elf::{ElfBuilder, FixupKind, ImportKind, Loc as ElfLoc, Section, Symbol};
use ghidorah_types::Prim;
use ghidorah_types::cc::{MS_X64, SYSV_X86_64};

use crate::blob::{BASE, load};
use crate::support::{analyze, cached, fid, fir_of, named, program_of};

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

/// A direct call whose callee returns a floating value is a floating write of its kind. `g`
/// calls `f` and returns, and `f` converts `edi` to a `double` in `xmm0`. The L0 body of `g`
/// alone gives no floating return. An indirect call is no evidence.
#[test]
fn float_return_follows_float_callee() {
    // 0x00 g: sub rsp, 8; call f; add rsp, 8; ret. 0x10 f: cvtsi2sd xmm0, edi; ret.
    let mut bytes = vec![0xcc; 0x15];
    bytes[..0x0e].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x08, 0xe8, 0x07, 0, 0, 0, 0x48, 0x83, 0xc4, 0x08, RET,
    ]);
    bytes[0x10..0x15].copy_from_slice(&[0xf2, 0x0f, 0x2a, 0xc7, RET]);
    let p = blob(&bytes);
    let g = fir_of(&p, BASE);
    assert_eq!(ret::recover(&g), None);
    assert_eq!(ret::float_ret(&p, fid(BASE), &g), Some(FloatRet::Double));
    assert_eq!(
        ret::ret_value(&p, fid(BASE + 0x10), &fir_of(&p, BASE + 0x10)),
        RetValue::Float(FloatRet::Double)
    );
    // sub rsp, 8; call rax; add rsp, 8; ret
    let ind = blob(&[
        0x48, 0x83, 0xec, 0x08, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x08, RET,
    ]);
    assert_eq!(ret::float_ret(&ind, fid(BASE), &fir_of(&ind, BASE)), None);
}

/// Gives the blob of `f` at `BASE`, `g` at `BASE + 0x10` and `h` at `BASE + 0x20`. `f` calls
/// `g` and then runs `after`. `g` calls `h` and returns its `rax`. `h` returns 7.
fn caller_blob(after: &[u8]) -> Program {
    let mut bytes = vec![0xe8, 0x0b, 0, 0, 0];
    bytes.extend_from_slice(after);
    bytes.resize(0x10, 0x90);
    bytes.extend_from_slice(&[0xe8, 0x0b, 0, 0, 0, 0xc3]);
    bytes.resize(0x20, 0x90);
    bytes.extend_from_slice(&[0xb8, 0x07, 0, 0, 0, 0xc3]);
    blob(&bytes)
}

/// A function whose value comes only from a call has no value when no caller reads `rax`.
/// A read, a return or a branch after a call site keeps the integer value.
#[test]
fn regress_ret_value_from_callers() {
    let value = |p: &Program, at: u64| ret::ret_value(p, fid(at), &fir_of(p, at));
    // call h; ret: the second call writes rax and xmm0 before any read.
    let p = caller_blob(&[0xe8, 0x16, 0, 0, 0, 0xc3]);
    assert_eq!(value(&p, BASE + 0x10), RetValue::Void);
    assert_eq!(value(&p, BASE + 0x20), RetValue::Int, "h writes rax");
    // mov eax, 1; ret: xmm0 can still pass on to the return.
    let p = caller_blob(&[0xb8, 0x01, 0, 0, 0, 0xc3]);
    assert_eq!(value(&p, BASE + 0x10), RetValue::Int);
    // add rax, 1; ret: the caller reads rax.
    let p = caller_blob(&[0x48, 0x83, 0xc0, 0x01, 0xc3]);
    assert_eq!(value(&p, BASE + 0x10), RetValue::Int);
    // ret: the caller passes rax on.
    let p = caller_blob(&[0xc3]);
    assert_eq!(value(&p, BASE + 0x10), RetValue::Int);
    // The body rule alone gives no caller evidence.
    let p = caller_blob(&[0xe8, 0x16, 0, 0, 0, 0xc3]);
    assert_eq!(ret::recover_value(&fir_of(&p, BASE + 0x10)), RetValue::Int);
}

/// `run_command` of `switch` only tail calls `puts`, and `main` ignores its value.
#[test]
fn regress_ret_value_of_tail_caller() {
    let p = cached("fixtures/bin/switch.gcc-O2");
    let value = |name: &str| {
        let at = named(p, name);
        ret::ret_value(p, fid(at), &fir_of(p, at))
    };
    assert_eq!(value("run_command"), RetValue::Void);
    assert_eq!(value("sparse_code"), RetValue::Int);
    assert_eq!(value("apply_op"), RetValue::Int);
    let mut memo = Memo::default();
    let mut fuel = Fuel::new(1_000_000);
    let at = named(p, "run_command");
    assert_eq!(
        ret::ret_value_in(p, at, &mut memo, &mut fuel),
        Some(RetValue::Void)
    );
}

/// Gives the blob of `entry` at `BASE`, which calls each function of `funcs` and returns, and
/// the functions of `funcs` at `BASE + 0x10`, `BASE + 0x20` and so on. Each function is at
/// most 16 bytes, and its `rel32` fields are relative to its own start.
fn funcs_blob(funcs: &[&[u8]]) -> Program {
    let mut bytes = Vec::new();
    for k in 0..funcs.len() {
        let at = i32::try_from(bytes.len() + 5).expect("a small offset");
        let to = i32::try_from(0x10 * (k + 1)).expect("a small offset");
        bytes.push(0xe8);
        bytes.extend_from_slice(&(to - at).to_le_bytes());
    }
    bytes.push(RET);
    assert!(bytes.len() <= 0x10, "the entry fits in 16 bytes");
    for f in funcs {
        bytes.resize(bytes.len().next_multiple_of(0x10), 0xcc);
        bytes.extend_from_slice(f);
    }
    blob(&bytes)
}

/// Gives `jmp rel32` from offset 0 of a function at `from` to `to`.
fn jmp(from: u64, to: u64) -> Vec<u8> {
    let rel =
        i32::try_from(i64::try_from(to).expect("small") - i64::try_from(from + 5).expect("small"))
            .expect("a near jump");
    let mut out = vec![0xe9];
    out.extend_from_slice(&rel.to_le_bytes());
    out
}

/// Gives `call rel32; ret` from offset 0 of a function at `from` to `to`.
fn call_ret(from: u64, to: u64) -> Vec<u8> {
    let mut out = jmp(from, to);
    out[0] = 0xe8;
    out.push(RET);
    out
}

/// `cvtsi2sd xmm0, edi; ret`.
const TO_DOUBLE: [u8; 5] = [0xf2, 0x0f, 0x2a, 0xc7, RET];

/// A tail jump passes the floating return of its target on. `f` tail jumps to `g`, `g` tail
/// jumps to `h`, and `h` returns a `double`. So all three return a `double`.
#[test]
fn regress_float_return_follows_tail_chain() {
    let (f, g) = (0x10, 0x20);
    let p = funcs_blob(&[&jmp(f, g), &jmp(g, 0x30), &TO_DOUBLE]);
    for at in [BASE + f, BASE + g, BASE + 0x30] {
        let l0 = fir_of(&p, at);
        assert_eq!(
            ret::float_ret(&p, fid(at), &l0),
            Some(FloatRet::Double),
            "{at:#x}"
        );
        assert_eq!(
            ret::ret_value(&p, fid(at), &l0),
            RetValue::Float(FloatRet::Double),
            "{at:#x}"
        );
        let mut memo = Memo::default();
        let mut fuel = Fuel::new(1_000_000);
        assert_eq!(
            ret::ret_value_in(&p, at, &mut memo, &mut fuel),
            Some(RetValue::Float(FloatRet::Double)),
            "{at:#x}"
        );
    }
    // A chain of calls gives the same kind.
    let p = funcs_blob(&[&call_ret(f, g), &call_ret(g, 0x30), &TO_DOUBLE]);
    assert_eq!(
        ret::float_ret(&p, fid(BASE + f), &fir_of(&p, BASE + f)),
        Some(FloatRet::Double)
    );
}

/// Two functions that call each other, or tail jump to each other, give a result. The walk
/// does not recurse without end.
#[test]
fn regress_mutual_calls_end() {
    let (f, g) = (0x10, 0x20);
    for funcs in [[call_ret(f, g), call_ret(g, f)], [jmp(f, g), jmp(g, f)]] {
        let p = funcs_blob(&[&funcs[0], &funcs[1]]);
        for at in [BASE + f, BASE + g] {
            let l0 = fir_of(&p, at);
            assert_eq!(ret::float_ret(&p, fid(at), &l0), None, "{at:#x}");
            assert_eq!(ret::ret_value(&p, fid(at), &l0), RetValue::Int, "{at:#x}");
            let mut memo = Memo::default();
            let mut fuel = Fuel::new(1_000_000);
            assert_eq!(
                ret::ret_value_in(&p, at, &mut memo, &mut fuel),
                Some(RetValue::Int),
                "{at:#x}"
            );
        }
    }
}

/// Gives the blob of a chain: the entry calls each function, function `k` at `0x80 * k` tail
/// jumps to function `k + 1` from each of `fan` exits, and the last function returns a
/// `double`. The chain has `depth` functions before the last one.
fn chain_blob(depth: u64, fan: u8) -> Program {
    let at = |k: u64| 0x80 * k;
    let mut bytes = Vec::new();
    for k in 1..=depth + 1 {
        let next =
            i32::try_from(at(k)).expect("small") - i32::try_from(bytes.len() + 5).expect("small");
        bytes.push(0xe8);
        bytes.extend_from_slice(&next.to_le_bytes());
    }
    bytes.push(RET);
    for k in 1..=depth {
        bytes.resize(usize::try_from(at(k)).expect("small"), 0xcc);
        // `fan - 1` times `cmp edi, j; jne +5; jmp next`, then `jmp next`.
        for j in 1..fan {
            bytes.extend_from_slice(&[0x83, 0xff, j, 0x75, 0x05]);
            let from = u64::try_from(bytes.len()).expect("small");
            bytes.extend_from_slice(&jmp(from, at(k + 1)));
        }
        let from = u64::try_from(bytes.len()).expect("small");
        bytes.extend_from_slice(&jmp(from, at(k + 1)));
    }
    bytes.resize(usize::try_from(at(depth + 1)).expect("small"), 0xcc);
    bytes.extend_from_slice(&TO_DOUBLE);
    blob(&bytes)
}

/// The walk of the callee return values stops after `RET_DEPTH` functions. A chain that fits
/// gives the floating return of its last function. A longer chain gives none.
#[test]
fn regress_ret_walk_depth_is_bounded() {
    for (depth, want) in [
        (ret::RET_DEPTH as u64, Some(FloatRet::Double)),
        (ret::RET_DEPTH as u64 + 1, None),
    ] {
        let p = chain_blob(depth, 1);
        let at = BASE + 0x80;
        assert_eq!(
            ret::float_ret(&p, fid(at), &fir_of(&p, at)),
            want,
            "{depth}"
        );
    }
}

/// The walk did not keep the result of a callee. A chain with 4 tail jumps from each function
/// to the next took 4^d visits: 21 s at a depth of 12. Now each callee takes one visit.
#[test]
fn regress_ret_walk_fan_out_is_linear() {
    let p = chain_blob(12, 4);
    let at = BASE + 0x80;
    let start = Instant::now();
    let mut memo = Memo::default();
    let mut fuel = Fuel::new(1_000_000);
    let got = ret::ret_value_in(&p, at, &mut memo, &mut fuel);
    let took = start.elapsed();
    assert_eq!(got, Some(RetValue::Float(FloatRet::Double)));
    assert!(took < Duration::from_secs(2), "the walk took {took:?}");
}

/// A call or a tail jump through the GOT slot of an import is a call of the import. `f` calls
/// `atof` through its slot and returns. `g` tail jumps through the slot. The Tier-0 prototype
/// of `atof` returns a `double`, so both functions return a `double`.
#[test]
fn regress_float_return_through_import_slot() {
    // f: call [rip + atof@got]; ret. g at 0x10: jmp [rip + atof@got].
    let mut text = vec![0xff, 0x15, 0, 0, 0, 0, RET];
    text.resize(0x10, 0xcc);
    text.extend_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
    let got = || ElfLoc::Got("atof".to_owned());
    let (bytes, layout) = ElfBuilder::exec()
        .import("atof", ImportKind::Got)
        .section(
            Section::code(".text", &text)
                .fixup(2, FixupKind::Rel32, got())
                .fixup(0x12, FixupKind::Rel32, got()),
        )
        .symbol(Symbol::func("f", ElfLoc::section(".text", 0), 7))
        .symbol(Symbol::func("g", ElfLoc::section(".text", 0x10), 6))
        .build_with_layout();
    let mut p = program_of(&bytes, &LoadOpts::AUTO);
    let _ = analyze(&mut p);
    let base = layout.section(".text").expect("the code section").addr;
    for at in [base, base + 0x10] {
        let l0 = fir_of(&p, at);
        assert_eq!(
            ret::float_ret(&p, fid(at), &l0),
            Some(FloatRet::Double),
            "{at:#x}"
        );
    }
}

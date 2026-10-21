//! Regression tests of the floating results of calls (k3-03).
//!
//! A callee returns a `float` or a `double` in `xmm0`. The printer took only the `rax` def of
//! a call as its result. So a caller that read the `xmm0` def of a call printed a variable
//! with no def in place of the call result.

use std::collections::BTreeSet;

use ghidorah_base::{Fuel, VarId};
use ghidorah_db::Types;
use ghidorah_decomp::lattice::{Store, Ty};
use ghidorah_decomp::print::{self, PrintEnv, Signature};
use ghidorah_decomp::{Call, Callee, Exit, Expr, NoEnv, Opts, Stmt, Tree, VarIdx, View};
use ghidorah_ir::{Loc, LocSet, NoNames};

use crate::fixtures::{fid, program};
use crate::out_print::{ENTRY, Spec, decomp, k, op, temp, v};
use crate::regress::undefined_reads;
use crate::shapes::node;

/// The fixtures with floating values: the PE fixtures and the varargs builds.
const FIXTURES: [&str; 10] = [
    "pe/pe_cc.exe",
    "pe/pe_dll.dll",
    "pe/pe_flags.exe",
    "pe/pe_main.exe",
    "varargs.clang-O2",
    "varargs.clang-O2.stripped",
    "varargs.gcc-O0",
    "varargs.gcc-O0.stripped",
    "varargs.gcc-O2",
    "varargs.gcc-O2.stripped",
];

/// The entry of `cc_start`, the main function of `pe_cc.exe`.
const PE_CC_MAIN: u64 = 0x1_4000_11e0;

/// The floating callees of `cc_start`: `f1`, `f2`, `m3`, `m4`, `m5`, `m6` and `g2`.
const PE_CC_FLOATS: [u64; 7] = [
    0x1_4000_1100,
    0x1_4000_1120,
    0x1_4000_1130,
    0x1_4000_1150,
    0x1_4000_1170,
    0x1_4000_11a0,
    0x1_4000_11c0,
];

/// The address of the callee of the hand-made calls.
const CALLEE: u64 = 0x2000;

/// Gives the register `xmm0`.
fn xmm0() -> Loc {
    Loc::xmm(0).expect("the register xmm0")
}

/// Gives the calls of a statement: the call statement and the calls in its expressions.
fn calls_of(s: &Stmt) -> Vec<&Call> {
    let mut out: Vec<&Call> = s
        .exprs()
        .into_iter()
        .flat_map(Expr::preorder)
        .filter_map(|x| match x {
            Expr::Call(c) => Some(c.as_ref()),
            _ => None,
        })
        .collect();
    if let Stmt::Call(c) = s {
        out.push(c);
    }
    out
}

/// Gives the identity of each variable of `view` that holds the `xmm0` def of a call.
fn xmm0_defs(view: &View) -> BTreeSet<VarId> {
    view.nodes
        .iter()
        .flat_map(|n| &n.stmts)
        .flat_map(calls_of)
        .filter(|c| !matches!(c.callee, Callee::Intrinsic(_)))
        .flat_map(|c| &c.rets)
        .filter(|(l, _)| *l == xmm0())
        .filter_map(|(_, x)| view.var(*x).map(|var| var.id.clone()))
        .collect()
}

/// The text of a function with the names of two kinds of its variables.
struct Rendered {
    /// The text.
    text: String,
    /// The variables that hold the `xmm0` def of a call.
    results: BTreeSet<String>,
    /// The variables that hold the entry value of a register.
    inputs: BTreeSet<String>,
}

/// Gives the text of the function at `entry` of `fixture` with the names of its result and
/// entry-value variables.
fn text_of(fixture: &str, entry: u64) -> Rendered {
    let p = program(fixture);
    let id = fid(entry);
    let d = ghidorah_decomp::decompile(p, id, &Opts::default(), &mut Fuel::new(50_000_000))
        .unwrap_or_else(|e| panic!("{fixture} {entry:#x}: {e}"));
    let defs = xmm0_defs(&d.view);
    let inputs: BTreeSet<VarId> = d
        .view
        .vars
        .iter()
        .filter(|v| v.input.is_some())
        .map(|v| v.id.clone())
        .collect();
    let env = ghidorah_decomp::ProgramEnv(p);
    let body = print::body_units(p, id);
    let out = ghidorah_decomp::finish(d, &env, &NoNames, "f", &body);
    let names = |ids: &BTreeSet<VarId>| {
        out.vars
            .iter()
            .filter(|r| ids.contains(&r.id))
            .map(|r| r.name.clone())
            .collect()
    };
    Rendered {
        results: names(&defs),
        inputs: names(&inputs),
        text: out.text(),
    }
}

/// Gives the text of the function at `entry` of `fixture`, with the names of the variables
/// that hold the `xmm0` def of a call.
fn text_and_results(fixture: &str, entry: u64) -> (String, BTreeSet<String>) {
    let t = text_of(fixture, entry);
    (t.text, t.results)
}

/// Asserts that `text` binds the result of each callee of `callees` and reads it.
fn assert_summed(text: &str, callees: &[u64]) {
    for callee in callees {
        let call = format!("FUN_{callee:08x}(");
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| l.contains(&call))
            .unwrap_or_else(|| panic!("no call of {call}:\n{text}"));
        let (var, _) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("the call binds no result: {line}\n{text}"));
        assert!(word_count(text, var) >= 2, "no read of {var}:\n{text}");
    }
}

/// Gives the count of the words `word` in `text`.
fn word_count(text: &str, word: &str) -> usize {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| *w == word)
        .count()
}

/// No function text of the PE fixtures or the varargs builds reads a variable with no def
/// that holds the `xmm0` def of a call. `cc_start` of `pe_cc.exe` binds each floating result,
/// and the sum reads it.
#[test]
fn regress_float_call_result_is_bound() {
    let mut bad = Vec::new();
    for fixture in FIXTURES {
        for f in program(fixture)
            .funcs()
            .iter()
            .filter(|f| !f.func.flags.thunk)
        {
            let entry = f.id().0.off;
            let (text, results) = text_and_results(fixture, entry);
            let lost: Vec<String> = undefined_reads(&text)
                .intersection(&results)
                .cloned()
                .collect();
            if !lost.is_empty() {
                bad.push(format!("{fixture} {entry:#x} reads {lost:?}:\n{text}"));
            }
        }
    }
    assert!(bad.is_empty(), "{} texts:\n{}", bad.len(), bad.join("\n"));
    let (text, _) = text_and_results("pe/pe_cc.exe", PE_CC_MAIN);
    assert_summed(&text, &PE_CC_FLOATS);
    assert!(text.lines().any(|l| l.trim() == "return;"), "{text}");
    assert!(text.starts_with("void f(void)\n"), "{text}");
}

/// MS x64 keeps `xmm6` .. `xmm15` across a call. L1 took each XMM register as a call def. So
/// in `cc_start`, the next call killed the results of `f1` and `m5` in `xmm8` and `xmm11`.
/// The constants in `xmm6`, `xmm7` and `xmm9` had no def after a call. Now the sum reads each
/// floating result, and each value with no def is an entry value.
#[test]
fn regress_ms_x64_xmm_kept_across_calls() {
    let t = text_of("pe/pe_cc.exe", PE_CC_MAIN);
    assert_summed(&t.text, &PE_CC_FLOATS);
    let undefined = undefined_reads(&t.text);
    let lost: Vec<&String> = undefined
        .iter()
        .filter(|n| !t.inputs.contains(*n))
        .collect();
    assert!(lost.is_empty(), "{lost:?} have no def:\n{}", t.text);
}

/// An environment with one name and one signature for [`CALLEE`].
struct SigEnv(&'static str, Signature);

impl ghidorah_decomp::Env for SigEnv {
    fn callee_name(&self, addr: u64) -> Option<String> {
        (addr == CALLEE).then(|| self.0.to_owned())
    }
    fn is_noreturn(&self, _addr: u64) -> bool {
        false
    }
    fn is_string(&self, _addr: u64) -> bool {
        false
    }
}

impl PrintEnv for SigEnv {
    fn signature(&self, addr: u64) -> Option<Signature> {
        (addr == CALLEE).then(|| self.1.clone())
    }
}

/// Gives an environment with the callee `proto`: no parameter and the Tier-0 return type of
/// `proto`.
fn returns_like(proto: &'static str) -> SigEnv {
    let p = Types::prototype(proto).unwrap_or_else(|| panic!("the Tier-0 prototype {proto}"));
    let sig = Signature {
        params: Vec::new(),
        names: Vec::new(),
        ret: Some(Ty {
            store: Store::Tier0,
            id: p.sig.ret,
        }),
        variadic: false,
    };
    SigEnv(proto, sig)
}

/// Gives the text lines and the variable rows of `rax = v0, xmm0 = v1` after a call of
/// [`CALLEE`]. A store reads each def in `stored`. The return reads `v0`.
fn call_then_store(env: &dyn PrintEnv, stored: &[u32]) -> (Vec<String>, Vec<(String, String)>) {
    let call = Call {
        callee: Callee::Direct(CALLEE),
        args: Vec::new(),
        set: LocSet::EMPTY,
        push: None,
        imm: Vec::new(),
        mem: None,
        rets: vec![(Loc::RAX, VarIdx(0)), (xmm0(), VarIdx(1))],
        ret: None,
        noreturn: false,
        tail: false,
        at: op(0, 0, 0),
    };
    let mut stmts = vec![Stmt::Call(call)];
    for (i, &x) in stored.iter().enumerate() {
        let w = if x == 0 { 64 } else { 128 };
        stmts.push(Stmt::Store {
            w,
            addr: k(0x3000 + 0x10 * u64::from(x), 64),
            value: v(x, w),
            at: op(0, 1 + u64::try_from(i).expect("small"), 0),
        });
    }
    stmts.push(Stmt::Return {
        uses: vec![(Loc::RAX, v(0, 64))],
        at: op(0, 3, 0),
    });
    let d = decomp(
        vec![Spec::new(Exit::Stop, stmts)],
        vec![temp("rax", ENTRY, 64), temp("xmm0", ENTRY, 128)],
        Tree::Block(node(0)),
    );
    let out = print::print(&d, env, &NoNames, "f");
    let rows = out.vars.into_iter().map(|r| (r.name, r.ty)).collect();
    (out.lines.into_iter().map(|l| l.text).collect(), rows)
}

/// A callee whose signature returns a `double` gives its result in `xmm0`. The result gets
/// the return type, and the `rax` def is no result: the return gives no value.
#[test]
fn regress_float_signature_binds_xmm0() {
    let (lines, rows) = call_then_store(&returns_like("atof"), &[1]);
    assert_eq!(
        lines,
        [
            "void f(void)",
            "{",
            "    v2 = atof();",
            "    *(uint128_t *)0x3010 = v2;",
            "    return;",
            "}",
        ],
    );
    assert_eq!(rows, [("v2".to_owned(), "double".to_owned())]);
}

/// A callee whose signature returns an integer gives its result in `rax`, also when the
/// caller reads the `xmm0` def.
#[test]
fn regress_int_signature_binds_rax() {
    let (lines, _) = call_then_store(&returns_like("strlen"), &[1]);
    assert_eq!(lines[2], "    v1 = strlen();", "{lines:?}");
    assert_eq!(lines[4], "    return v1;", "{lines:?}");
}

/// A call has no signature. The caller reads its `xmm0` def, and a return is the only read of
/// its `rax` def. Then the `xmm0` def is the result.
#[test]
fn regress_float_caller_reads_bind_xmm0() {
    let (lines, _) = call_then_store(&NoEnv, &[1]);
    assert_eq!(lines[0], "void f(void)", "{lines:?}");
    assert_eq!(lines[2], "    v2 = FUN_00002000();", "{lines:?}");
    assert_eq!(lines[4], "    return;", "{lines:?}");
}

/// A call has no signature. A statement other than a return reads its `rax` def. Then the
/// `rax` def is the result.
#[test]
fn regress_rax_read_keeps_rax_result() {
    let (lines, _) = call_then_store(&NoEnv, &[0, 1]);
    assert_eq!(lines[2], "    v1 = FUN_00002000();", "{lines:?}");
    assert_eq!(lines[5], "    return v1;", "{lines:?}");
}

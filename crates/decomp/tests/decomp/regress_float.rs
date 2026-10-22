//! Regression tests of the floating values of calls and returns (k3-03, L1 to L4).
//!
//! A callee returns a `float` or a `double` in `xmm0`. The printer took only the `rax` def of
//! a call as its result. So a caller that read the `xmm0` def of a call printed a variable
//! with no def in place of the call result.
//!
//! The later tests cover four more cases. MS x64 keeps `xmm6` .. `xmm15` across a call. A
//! function can return a floating value. A `SysV` varargs call has XMM arguments. A `void`
//! callee leaves no value in `rax`.

use std::collections::BTreeSet;

use ghidorah_analysis::fir::ret::FloatRet;
use ghidorah_base::{Fuel, VarId};
use ghidorah_db::{Edit, SessionLabel, Source, Types};
use ghidorah_decomp::lattice::{Store, Ty};
use ghidorah_decomp::print::{self, PrintEnv, Signature};
use ghidorah_decomp::{Call, Callee, Exit, Expr, NoEnv, Opts, Stmt, Tree, Var, VarIdx, View};
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
pub const CALLEE: u64 = 0x2000;

/// Gives the register `xmm0`.
pub fn xmm0() -> Loc {
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
pub fn word_count(text: &str, word: &str) -> usize {
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
pub struct SigEnv(pub &'static str, pub Signature);

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
pub fn call_then_store(env: &dyn PrintEnv, stored: &[u32]) -> (Vec<String>, Vec<(String, String)>) {
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
    (
        out.lines
            .into_iter()
            .filter(|l| l.kind != print::LineKind::Decl)
            .map(|l| l.text)
            .collect(),
        rows,
    )
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

/// Gives the output of the function at `entry` of `fixture`, or of the function `name` when
/// `entry` is 0.
pub fn render_of(fixture: &str, entry: u64, name: &str) -> ghidorah_decomp::Output {
    let p = program(fixture);
    let at = if entry == 0 {
        crate::fixtures::entry_of(p, name)
    } else {
        entry
    };
    ghidorah_decomp::render(
        p,
        fid(at),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{fixture} {at:#x}: {e}"))
}

/// A function that returns a `double` or a `float` gives its value in `xmm0`. The L1 return
/// read only `rax`. So `f1` of `pe_cc.exe` printed as `void FUN_140001100(uint128_t)`, and
/// the text lost the result of its `addsd`. Now the head gives the floating type, and the
/// return reads the result. The variable of the result has the floating type too.
#[test]
fn regress_float_return_is_printed() {
    let cases = [
        ("pe/pe_cc.exe", 0x1_4000_1100, "double"),
        ("pe/pe_cc.exe", 0x1_4000_1170, "double"),
        ("pe/pe_cc.exe", 0x1_4000_11c0, "float"),
        ("varargs.gcc-O2", 0, "double"),
        ("varargs.gcc-O0", 0, "double"),
        ("varargs.clang-O2", 0, "double"),
    ];
    for (fixture, entry, ty) in cases {
        let out = render_of(fixture, entry, "scale");
        let text = out.text();
        assert!(text.starts_with(&format!("{ty} ")), "{fixture}:\n{text}");
        let ret = text
            .lines()
            .map(str::trim)
            .rfind(|l| l.starts_with("return "))
            .unwrap_or_else(|| panic!("{fixture}: no return value:\n{text}"));
        let var = ret
            .strip_prefix("return ")
            .and_then(|r| r.strip_suffix(';'))
            .unwrap_or_default();
        assert!(
            text.lines()
                .any(|l| l.trim().starts_with(&format!("{var} = "))),
            "{fixture}: {var} has no def:\n{text}"
        );
        let row = out.vars.iter().find(|r| r.name == var);
        assert_eq!(row.map(|r| r.ty.as_str()), Some(ty), "{fixture}:\n{text}");
    }
}

/// Gives the text lines of a function with a floating return of the kind `kind`. Its body
/// holds `stmts` over the variables `vars`.
fn float_fn(
    kind: Option<FloatRet>,
    stmts: Vec<Stmt>,
    vars: Vec<Var>,
    env: &dyn PrintEnv,
) -> Vec<String> {
    let mut d = decomp(
        vec![Spec::new(Exit::Stop, stmts)],
        vars,
        Tree::Block(node(0)),
    );
    d.view.float_ret = kind;
    let out = print::print(&d, env, &NoNames, "f");
    out.lines
        .into_iter()
        .filter(|l| l.kind != print::LineKind::Decl)
        .map(|l| l.text)
        .collect()
}

/// A floating return reads `xmm0`. The result of a call in `xmm0` and the entry value of
/// `xmm0`, a floating parameter, are return values. A value that a call leaves in `xmm0` is
/// not one.
#[test]
fn float_return_reads_xmm0() {
    let call = |rets: Vec<(Loc, VarIdx)>| {
        Stmt::Call(Call {
            callee: Callee::Direct(CALLEE),
            args: Vec::new(),
            set: LocSet::EMPTY,
            push: None,
            imm: Vec::new(),
            mem: None,
            rets,
            ret: None,
            noreturn: false,
            tail: false,
            at: op(0, 0, 0),
        })
    };
    let ret = |x: u32| Stmt::Return {
        uses: vec![(xmm0(), v(x, 128))],
        at: op(0, 1, 0),
    };
    let vars = || vec![temp("rax", ENTRY, 64), temp("xmm0", ENTRY, 128)];
    let result = vec![
        call(vec![(Loc::RAX, VarIdx(0)), (xmm0(), VarIdx(1))]),
        ret(1),
    ];
    let lines = float_fn(Some(FloatRet::Float), result.clone(), vars(), &NoEnv);
    assert_eq!(lines[0], "float f(void)", "{lines:?}");
    assert_eq!(lines[2], "    v2 = FUN_00002000();", "{lines:?}");
    assert_eq!(lines[3], "    return v2;", "{lines:?}");
    let atof = returns_like("atof");
    let lines = float_fn(Some(FloatRet::Double), result, vars(), &atof);
    assert_eq!(lines[3], "    return v2;", "{lines:?}");
    let mut entry = vars();
    if let Some(x) = entry.get_mut(1) {
        x.input = Some(xmm0());
    }
    let lines = float_fn(Some(FloatRet::Double), vec![ret(1)], entry, &NoEnv);
    assert_eq!(lines[0], "double f(void)", "{lines:?}");
    assert_eq!(lines[2], "    return v2;", "{lines:?}");
    let left = vec![call(vec![(xmm0(), VarIdx(1))]), ret(1)];
    let lines = float_fn(
        Some(FloatRet::Double),
        left,
        vars(),
        &returns_like("strlen"),
    );
    assert_eq!(lines[0], "void f(void)", "{lines:?}");
    assert_eq!(lines[3], "    return;", "{lines:?}");
}

/// Gives the argument texts of the first call of `name` in `text`.
pub fn call_args(text: &str, name: &str) -> Vec<String> {
    let start = text
        .find(&format!("{name}("))
        .unwrap_or_else(|| panic!("no call of {name}:\n{text}"));
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    let (mut out, mut cur) = (Vec::new(), String::new());
    for ch in text[start + name.len() + 1..].chars() {
        match ch {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            _ if quoted => {}
            '(' => depth += 1,
            ')' if depth == 0 => break,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_owned());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    out
}

/// A `SysV` varargs call passes its floating arguments in `xmm0` .. `xmm7`, and `al` holds
/// their count. The printer took the named count of a varargs callee as its full count. A
/// `SysV` argument list held no XMM register too. So in `main` of `varargs`, `sum_va(3, 1, 2,
/// a)` printed as `sum_va(3)`, and `log_msg("%lld %f\n", r, scale(..))` lost `r` and the
/// `double`. Now the call keeps its integer arguments, and `al` gives the XMM arguments.
#[test]
fn regress_sysv_varargs_call_keeps_float_args() {
    for build in ["varargs.gcc-O0", "varargs.gcc-O2", "varargs.clang-O2"] {
        let text = render_of(build, 0, "main").text();
        let sum = call_args(&text, "sum_va");
        assert_eq!(sum.len(), 4, "{build}: {sum:?}\n{text}");
        assert_eq!(sum[..3], ["3", "1", "2"], "{build}:\n{text}");
        let log = call_args(&text, "log_msg");
        assert_eq!(log.len(), 3, "{build}: {log:?}\n{text}");
        assert_eq!(log[0], "\"%lld %f\\n\"", "{build}:\n{text}");
        let scale = text
            .lines()
            .map(str::trim)
            .find(|l| l.contains("scale("))
            .unwrap_or_else(|| panic!("{build}: no call of scale:\n{text}"));
        let (var, _) = scale
            .split_once(" = ")
            .unwrap_or_else(|| panic!("{build}: the call binds no result: {scale}\n{text}"));
        assert_eq!(word_count(&log[2], var), 1, "{build}: {log:?}\n{text}");
        assert!(undefined_reads(&text).is_empty(), "{build}:\n{text}");
    }
}

/// Gives an environment with the variadic callee `printf` at [`CALLEE`].
fn printf_env() -> SigEnv {
    let p = Types::prototype("printf").expect("the Tier-0 prototype printf");
    let ty = |id| Ty {
        store: Store::Tier0,
        id,
    };
    let sig = Signature {
        params: p.sig.params.iter().map(|x| ty(x.ty)).collect(),
        names: p.sig.params.iter().map(|x| x.name.clone()).collect(),
        ret: Some(ty(p.sig.ret)),
        variadic: true,
    };
    SigEnv("printf", sig)
}

/// Gives the call line of a call of `printf` with the `rax` value `al`. The caller sets the
/// registers of `set`, and the call reads `rdi`, `xmm0` and `xmm1`.
fn printf_line(al: Expr, set: &[Loc]) -> String {
    let xmm1 = Loc::xmm(1).expect("the register xmm1");
    let call = Call {
        callee: Callee::Direct(CALLEE),
        args: vec![
            (Loc::RDI, k(0x3000, 64)),
            (xmm0(), v(0, 128)),
            (xmm1, v(1, 128)),
            (Loc::RAX, al),
        ],
        set: set.iter().copied().collect(),
        push: None,
        imm: Vec::new(),
        mem: None,
        rets: Vec::new(),
        ret: None,
        noreturn: false,
        tail: false,
        at: op(0, 0, 0),
    };
    let ret = Stmt::Return {
        uses: Vec::new(),
        at: op(0, 1, 0),
    };
    let vars = vec![
        temp("xmm0", ENTRY, 128),
        temp("xmm1", ENTRY, 128),
        temp("rax", ENTRY, 64),
    ];
    let d = decomp(
        vec![Spec::new(Exit::Stop, vec![Stmt::Call(call), ret])],
        vars,
        Tree::Block(node(0)),
    );
    let out = print::print(&d, &printf_env(), &NoNames, "f");
    out.lines
        .iter()
        .filter(|l| l.kind != print::LineKind::Decl)
        .nth(2)
        .map(|l| l.text.trim().to_owned())
        .unwrap_or_default()
}

/// The XMM arguments of a `SysV` varargs call follow its integer arguments. A constant `al`,
/// or the low byte of a `mov al, k`, gives their count. With no constant, the count is the
/// XMM registers that the caller sets.
#[test]
fn varargs_float_args_follow_al() {
    let xmm1 = Loc::xmm(1).expect("the register xmm1");
    let rdi = [Loc::RDI];
    assert_eq!(printf_line(k(0, 64), &rdi), "printf(0x3000);");
    assert_eq!(printf_line(k(1, 64), &rdi), "printf(0x3000, v1);");
    assert_eq!(printf_line(k(0x102, 64), &rdi), "printf(0x3000, v1, v2);");
    let mov_al = Expr::Ite {
        op: ghidorah_ir::Opc::Insert,
        w: 64,
        sub: 8,
        a: Box::new(v(2, 64)),
        b: Box::new(k(1, 8)),
        c: Box::new(k(0, 8)),
        at: op(0, 0, 1),
    };
    assert_eq!(printf_line(mov_al, &rdi), "printf(0x3000, v1);");
    let set = [Loc::RDI, xmm0(), xmm1];
    assert_eq!(printf_line(v(2, 64), &set), "printf(0x3000, v1, v2);");
    assert_eq!(printf_line(v(2, 64), &rdi), "printf(0x3000);");
}

/// Gives the text of the function `name` of `p`.
fn text_named(p: &ghidorah_db::Program, name: &str) -> String {
    let entry = crate::fixtures::entry_of(p, name);
    ghidorah_decomp::render(
        p,
        fid(entry),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{name}: {e}"))
    .text()
}

/// A callee with a `void` signature leaves no value in `rax`. A return of its `rax` def
/// printed `return vN;` with no def of `vN`, and the caller got a return type from it. Now
/// that path prints `return;`, and the caller stays `void`.
#[test]
fn regress_void_callee_result_is_not_returned() {
    let void = Signature {
        params: Vec::new(),
        names: Vec::new(),
        ret: None,
        variadic: false,
    };
    let (lines, _) = call_then_store(&SigEnv("finish", void), &[]);
    assert_eq!(
        lines,
        ["void f(void)", "{", "    finish();", "    return;", "}"]
    );
    let mut p = program("hello.gcc-O0").clone();
    let finish = crate::fixtures::entry_of(&p, "finish");
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("edit", Source::User, label).expect("a transaction");
    let parsed = tx
        .parse_sig("void finish(int code)")
        .expect("the signature");
    let edit = Edit::SetSignature {
        id: fid(finish),
        sig: Some(tx.fact(parsed.ty)),
    };
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
    let run = text_named(&p, "run");
    assert!(run.starts_with("void run("), "{run}");
    assert!(run.lines().any(|l| l.trim() == "return;"), "{run}");
    assert!(undefined_reads(&run).is_empty(), "{run}");
    let before = text_named(program("hello.gcc-O0"), "run");
    assert!(before.starts_with("uint64_t run("), "{before}");
}

/// The address of the format string of [`FmtEnv`].
const FORMAT: u64 = 0x3000;

/// An environment with the variadic callee `printf` at [`CALLEE`] and the format string
/// `.1` at [`FORMAT`].
struct FmtEnv(SigEnv, &'static [u8]);

impl ghidorah_decomp::Env for FmtEnv {
    fn callee_name(&self, addr: u64) -> Option<String> {
        self.0.callee_name(addr)
    }
    fn is_noreturn(&self, _addr: u64) -> bool {
        false
    }
    fn is_string(&self, addr: u64) -> bool {
        addr == FORMAT
    }
}

impl PrintEnv for FmtEnv {
    fn signature(&self, addr: u64) -> Option<Signature> {
        self.0.signature(addr)
    }
    fn string_bytes(&self, addr: u64) -> Option<Vec<u8>> {
        (addr == FORMAT).then(|| self.1.to_vec())
    }
    fn printf_format(&self, addr: u64) -> Option<usize> {
        (addr == CALLEE).then_some(0)
    }
}

/// Gives the call line of `printf(fmt, ..)` with `al = 2`. The call reads `rdi`, `rsi`, `rdx`,
/// `xmm0` and `xmm1`, and the caller sets them.
fn format_line(fmt: &'static [u8]) -> String {
    let xmm1 = Loc::xmm(1).expect("the register xmm1");
    let call = Call {
        callee: Callee::Direct(CALLEE),
        args: vec![
            (Loc::RDI, Expr::Str { addr: FORMAT }),
            (Loc::RSI, v(2, 64)),
            (Loc::RDX, v(3, 64)),
            (xmm0(), v(0, 128)),
            (xmm1, v(1, 128)),
            (Loc::RAX, k(2, 64)),
        ],
        set: [Loc::RDI, Loc::RSI, Loc::RDX, xmm0(), xmm1]
            .into_iter()
            .collect(),
        push: None,
        imm: Vec::new(),
        mem: None,
        rets: Vec::new(),
        ret: None,
        noreturn: false,
        tail: false,
        at: op(0, 0, 0),
    };
    let ret = Stmt::Return {
        uses: Vec::new(),
        at: op(0, 1, 0),
    };
    let vars = vec![
        temp("xmm0", ENTRY, 128),
        temp("xmm1", ENTRY, 128),
        temp("rsi", ENTRY, 64),
        temp("rdx", ENTRY, 64),
    ];
    let d = decomp(
        vec![Spec::new(Exit::Stop, vec![Stmt::Call(call), ret])],
        vars,
        Tree::Block(node(0)),
    );
    let out = print::print(&d, &FmtEnv(printf_env(), fmt), &NoNames, "f");
    out.lines
        .iter()
        .find(|l| l.text.contains("printf("))
        .map(|l| l.text.trim().to_owned())
        .unwrap_or_default()
}

/// A `SysV` varargs call printed its integer arguments before its XMM arguments. Now the
/// `printf` format string of a Tier-0 callee gives the C order of the two classes. A format
/// with another count, or a form with no order, keeps the old order.
#[test]
fn regress_varargs_order_follows_format() {
    assert_eq!(
        format_line(b"%f %d %f %s\n"),
        r#"printf("%f %d %f %s\n", v1, v3, v2, v4);"#
    );
    assert_eq!(
        format_line(b"%d %f %s %f"),
        r#"printf("%d %f %s %f", v3, v1, v4, v2);"#
    );
    for fmt in [
        &b"%d %d %f"[..],
        b"%f %f %f %d %d",
        b"%1$f %2$d %3$f %4$s",
        b"%Lf %d %f %s",
    ] {
        let text = String::from_utf8_lossy(fmt).replace('\n', "\\n");
        assert_eq!(
            format_line(fmt),
            format!(r#"printf("{text}", v3, v4, v1, v2);"#),
            "{text}"
        );
    }
}

/// The program environment gives the `printf` format index of a Tier-0 callee from its
/// `fmt(printf, n)` attribute. A `scanf` format and a callee with no format give none.
#[test]
fn printf_format_of_program_callees() {
    let cases: [(&str, &str, Option<usize>); 5] = [
        ("hello.gcc-O0", "printf", Some(0)),
        ("hello.gcc-O0", "puts", None),
        ("hello.gcc-O2", "__printf_chk", Some(1)),
        ("cold_split.gcc-O0", "fprintf", Some(1)),
        ("cold_split.gcc-O2", "__fprintf_chk", Some(2)),
    ];
    for (fixture, name, want) in cases {
        let p = program(fixture);
        let stub = p
            .imports()
            .values()
            .find(|r| r.id.name() == Some(name))
            .and_then(|r| r.stub)
            .unwrap_or_else(|| panic!("{fixture}: the stub of {name}"));
        let env = ghidorah_decomp::ProgramEnv(p);
        assert_eq!(env.printf_format(stub.off), want, "{fixture} {name}");
    }
    let scanf = Types::prototype("scanf").expect("the Tier-0 prototype scanf");
    assert!(scanf.attrs.fmt.is_some(), "scanf has a format");
}

//! Regression tests of the `SysV` floating parameters and arguments, of tail calls with no
//! return value and of the floating result of a call (batch D, D1 to D4).
//!
//! The blob tests load raw x86-64 bytes at [`BASE`] with the entry at the first byte.
//!
//! `SysV` numbers its integer and floating parameter slots apart. The recovery gave the
//! floating slots, but the namer gave them no parameter, and a call dropped their arguments.

use ghidorah_analysis::fir::ret::{FloatRet, RetValue};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Fuel, Limits, Storage};
use ghidorah_db::{Edit, Program, SessionLabel, Source};
use ghidorah_decomp::lattice::{Store, Ty};
use ghidorah_decomp::print::{self, Signature};
use ghidorah_decomp::{Call, Callee, Exit, Opts, ProgramEnv, Stmt, Tree};
use ghidorah_ir::{Loc, LocSet, NoNames};
use ghidorah_loader::LoadOpts;
use ghidorah_types::Prim;

use crate::fixtures::{entry_of, fid, program};
use crate::out_print::{ENTRY, Spec, decomp, k, op, temp, v};
use crate::regress::undefined_reads;
use crate::regress_float::{CALLEE, SigEnv, call_args, call_then_store, render_of, xmm0};
use crate::shapes::node;

/// The builds of the varargs fixture with a symbol table.
const VARARGS: [&str; 3] = ["varargs.gcc-O0", "varargs.gcc-O2", "varargs.clang-O2"];

/// The text of a function, with the names of the variables that hold the entry value of an
/// XMM register.
struct Named {
    /// The text.
    text: String,
    /// The variable rows: the name and the type.
    rows: Vec<(Storage, String, String)>,
    /// The names of the variables that hold the entry value of an XMM register.
    xmm_inputs: Vec<String>,
}

/// Gives the text of the function `name` of `fixture` with its XMM entry variables.
fn named(fixture: &str, name: &str) -> Named {
    named_in(program(fixture), name)
}

/// Gives the text of the function `name` of `p` with its XMM entry variables.
fn named_in(p: &Program, name: &str) -> Named {
    let id = fid(entry_of(p, name));
    let d = ghidorah_decomp::decompile(p, id, &Opts::default(), &mut Fuel::new(50_000_000))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let inputs: Vec<_> = d
        .view
        .vars
        .iter()
        .filter(|v| v.input.is_some_and(Loc::is_xmm))
        .map(|v| v.id.clone())
        .collect();
    let out = ghidorah_decomp::finish(d, &ProgramEnv(p), &NoNames, name, &print::body_units(p, id));
    let xmm_inputs = out
        .vars
        .iter()
        .filter(|r| inputs.contains(&r.id))
        .map(|r| r.name.clone())
        .collect();
    Named {
        text: out.text(),
        rows: out
            .vars
            .iter()
            .map(|r| (r.id.storage.clone(), r.name.clone(), r.ty.clone()))
            .collect(),
        xmm_inputs,
    }
}

/// `scale(double x, int32_t k)` of the varargs builds reads `x` in `xmm0`. The recovery
/// counted the floating slot, but the namer gave a `SysV` floating register no slot. So the
/// head was `double scale(uint64_t param_1)`, and the text read `x` as a register value with
/// no def. Now the floating slot follows the integer slot: `param_2` of the type `double`.
#[test]
fn regress_sysv_float_params_are_named() {
    for build in VARARGS {
        let n = named(build, "scale");
        let head = n.text.lines().next().unwrap_or_default();
        assert_eq!(
            head, "double scale(uint64_t param_1, double param_2)",
            "{build}:\n{}",
            n.text
        );
        assert_eq!(n.xmm_inputs, ["param_2"], "{build}:\n{}", n.text);
        let row = n.rows.iter().find(|r| r.0 == Storage::Param(1));
        assert_eq!(
            row.map(|r| (r.1.as_str(), r.2.as_str())),
            Some(("param_2", "double")),
            "{build}: {:?}",
            n.rows
        );
        let lost: Vec<String> = undefined_reads(&n.text)
            .into_iter()
            .filter(|x| n.xmm_inputs.contains(x))
            .collect();
        assert!(lost.is_empty(), "{build}: {lost:?}\n{}", n.text);
    }
}

/// Gives `program` with the signature `sig` on the function `name`.
pub fn with_signature(program: &Program, name: &str, sig: &str) -> Program {
    let mut p = program.clone();
    let entry = entry_of(&p, name);
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("edit", Source::User, label).expect("a transaction");
    let parsed = tx.parse_sig(sig).expect("the signature parses");
    let edit = Edit::SetSignature {
        id: fid(entry),
        sig: Some(tx.fact(parsed.ty)),
    };
    tx.apply(edit).expect("the edit applies");
    tx.commit().expect("the commit");
    p
}

/// A `SysV` signature gives each parameter the next register of its class. With the
/// signature `double scale(double x, int k)`, `x` in `xmm0` is `param_1` and `k` in `edi` is
/// `param_2`. The namer gave `rdi` the slot 0 and no slot to `xmm0`.
#[test]
fn sysv_signature_names_params_by_class() {
    let p = with_signature(
        program("varargs.gcc-O2"),
        "scale",
        "double scale(double x, int k)",
    );
    let n = named_in(&p, "scale");
    let head = n.text.lines().next().unwrap_or_default();
    assert_eq!(
        head, "double scale(double param_1, int param_2)",
        "{}",
        n.text
    );
    assert_eq!(n.xmm_inputs, ["param_1"], "{}", n.text);
    assert!(n.text.contains("(0, param_2);"), "{}", n.text);
}

/// `main` of the varargs builds calls `scale(1.5, (int32_t)a)`. A `SysV` call that is not
/// variadic kept only its integer arguments, so the text was `scale(a)`. Now the call takes
/// its XMM arguments from the floating slots of the callee, after its integer slots.
#[test]
fn regress_sysv_call_keeps_float_args() {
    for build in VARARGS {
        let text = render_of(build, 0, "main").text();
        let args = call_args(&text, "scale");
        assert_eq!(args.len(), 2, "{build}: {args:?}\n{text}");
        assert!(args[0].contains("(uint32_t)"), "{build}: {args:?}\n{text}");
        assert_ne!(args[1], "0", "{build}: {args:?}\n{text}");
        assert!(undefined_reads(&text).is_empty(), "{build}:\n{text}");
    }
}

/// Gives the Tier-0 type of the primitive `p`.
fn prim(p: Prim) -> Ty {
    let tier0 = ghidorah_types::proto::builtin().expect("the Tier-0 store");
    Ty {
        store: Store::Tier0,
        id: tier0.store().prim(p),
    }
}

/// Gives the call line of a call of [`CALLEE`] with the signature `f(double x, int k)`. The
/// caller sets `rdi` to 1 and `xmm0` to `v1`.
fn signature_call_line() -> String {
    let sig = Signature {
        params: vec![prim(Prim::Double), prim(Prim::Int)],
        names: vec![Some("x".to_owned()), Some("k".to_owned())],
        ret: None,
        variadic: false,
    };
    let call = Call {
        callee: Callee::Direct(CALLEE),
        args: vec![(Loc::RDI, k(1, 64)), (xmm0(), v(0, 128))],
        set: [Loc::RDI, xmm0()].into_iter().collect::<LocSet>(),
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
    let d = decomp(
        vec![Spec::new(Exit::Stop, vec![Stmt::Call(call), ret])],
        vec![temp("xmm0", ENTRY, 128)],
        Tree::Block(node(0)),
    );
    let out = print::print(&d, &SigEnv("f", sig), &NoNames, "g");
    out.lines
        .get(2)
        .map(|l| l.text.trim().to_owned())
        .unwrap_or_default()
}

/// A `SysV` signature gives each parameter the next register of its class: `x` of
/// `f(double x, int k)` is in `xmm0`, and `k` is in `rdi`. The call took the first two
/// integer registers, so it printed `f(1, 0)`.
#[test]
fn sysv_signature_args_follow_param_classes() {
    assert_eq!(signature_call_line(), "f(v1, 1);");
}

/// The load address of the blobs.
const BASE: u64 = 0x40_0000;

/// Gives the analyzed program of the raw x86-64 bytes `bytes` at [`BASE`].
fn blob(bytes: &[u8]) -> Program {
    let opts = LoadOpts::raw(BASE, Some(BASE));
    let (binary, mem) =
        ghidorah_loader::load(bytes, &opts, &Limits::DEFAULT).expect("the blob loads");
    let mut p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary");
    let out = Scheduler::new()
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "an unlimited run completes");
    p
}

/// Gives the text lines of the function at `entry` of `p`.
fn lines_at(p: &Program, entry: u64) -> Vec<String> {
    ghidorah_decomp::render(
        p,
        fid(entry),
        &Opts::default(),
        &NoNames,
        &mut Fuel::new(50_000_000),
    )
    .unwrap_or_else(|e| panic!("{entry:#x}: {e}"))
    .lines
    .into_iter()
    .map(|l| l.text)
    .collect()
}

/// Gives the text lines of the function `name` of `fixture`.
fn lines_of(fixture: &str, name: &str) -> Vec<String> {
    let p = program(fixture);
    lines_at(p, entry_of(p, name))
}

/// A tail call of a callee that returns no value printed `return f(..);`. The callee
/// `__cxa_finalize` has a `void` Tier-0 prototype, so its thunk now prints the call, then
/// `return;`. The callee `__stack_chk_fail` does not return, so its thunk prints the call
/// only. A recovered callee that returns the entry value of `rax` returns no value too. So
/// `g` of the blob tail calls `f`, which stores `esi` at `rdi` and returns. A call of `f` has
/// no result too.
#[test]
fn regress_void_tail_call_is_no_return_value() {
    assert_eq!(
        lines_of("hello.gcc-O2", "__cxa_finalize@plt"),
        [
            "void __cxa_finalize(void *param_1)",
            "{",
            "    __cxa_finalize(param_1);",
            "    return;",
            "}",
        ]
    );
    assert_eq!(
        lines_of("canary.gcc-O2", "__stack_chk_fail@plt"),
        [
            "void __stack_chk_fail(void)",
            "{",
            "    __stack_chk_fail();",
            "}",
        ]
    );
    // 0x00 h: call g; mov edi, 1; mov esi, 2; call f; ret. 0x20 g: jmp f.
    // 0x30 f: mov [rdi], esi; ret.
    let mut bytes = vec![0xcc; 0x33];
    bytes[..0x15].copy_from_slice(&[
        0xe8, 0x1b, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 2, 0, 0, 0, 0xe8, 0x1c, 0, 0, 0, 0xc3,
    ]);
    bytes[0x20..0x25].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]);
    bytes[0x30..0x33].copy_from_slice(&[0x89, 0x37, 0xc3]);
    let p = blob(&bytes);
    assert_eq!(
        lines_at(&p, BASE + 0x20),
        [
            "void FUN_00400020(uint64_t param_1, uint64_t param_2)",
            "{",
            "    FUN_00400030(param_1, param_2);",
            "    return;",
            "}",
        ]
    );
    // A call of such a callee has no result, so `h` returns no value.
    assert_eq!(
        lines_at(&p, BASE),
        [
            "void FUN_00400000(uint64_t param_1, uint64_t param_2)",
            "{",
            "    FUN_00400020(param_1, param_2);",
            "    FUN_00400030(1, 2);",
            "    return;",
            "}",
        ]
    );
}

/// An environment that knows only the return value of [`CALLEE`].
struct RetEnv(RetValue);

impl ghidorah_decomp::Env for RetEnv {
    fn callee_name(&self, _addr: u64) -> Option<String> {
        None
    }
    fn is_noreturn(&self, _addr: u64) -> bool {
        false
    }
    fn is_string(&self, _addr: u64) -> bool {
        false
    }
}

impl print::PrintEnv for RetEnv {
    fn ret_value(&self, addr: u64) -> Option<RetValue> {
        (addr == CALLEE).then_some(self.0)
    }
}

/// A caller bound the floating result of a callee with no signature only from its own reads.
/// So a caller that reads the `rax` def of the call, or that only returns the result, lost
/// the `double` of the callee.
///
/// Now the recovered floating return of the callee gives the result in `xmm0`. In the blob,
/// `g` calls `f` and returns its result, and `h` tail calls `f`. The function `f` converts
/// `edi` to a `double` in `xmm0`. So `g` and `h` return a `double` too.
#[test]
fn regress_float_result_from_recovered_return() {
    let (lines, rows) = call_then_store(&RetEnv(RetValue::Float(FloatRet::Double)), &[0, 1]);
    assert_eq!(lines[2], "    v2 = FUN_00002000();", "{lines:?}");
    assert!(
        rows.contains(&("v2".to_owned(), "double".to_owned())),
        "{rows:?}"
    );
    let (lines, _) = call_then_store(&RetEnv(RetValue::Int), &[0, 1]);
    assert_eq!(lines[2], "    v1 = FUN_00002000();", "{lines:?}");
    // 0x00 e: call g; call h; ret. 0x10 g: sub rsp, 8; call f; add rsp, 8; ret.
    // 0x20 h: jmp f. 0x30 f: cvtsi2sd xmm0, edi; ret.
    let mut bytes = vec![0xcc; 0x35];
    bytes[..0x0b].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0, 0xe8, 0x16, 0, 0, 0, 0xc3]);
    bytes[0x10..0x1e].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x08, 0xe8, 0x17, 0, 0, 0, 0x48, 0x83, 0xc4, 0x08, 0xc3,
    ]);
    bytes[0x20..0x25].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]);
    bytes[0x30..0x35].copy_from_slice(&[0xf2, 0x0f, 0x2a, 0xc7, 0xc3]);
    let p = blob(&bytes);
    let g = lines_at(&p, BASE + 0x10);
    assert_eq!(g[0], "double FUN_00400010(uint64_t param_1)", "{g:?}");
    let call = g
        .iter()
        .find(|l| l.contains("FUN_00400030(param_1)"))
        .unwrap_or_else(|| panic!("no call of f: {g:?}"));
    let (var, _) = call
        .trim()
        .split_once(" = ")
        .unwrap_or_else(|| panic!("the call binds no result: {g:?}"));
    assert!(g.contains(&format!("    return {var};")), "{g:?}");
    let h = lines_at(&p, BASE + 0x20);
    assert_eq!(
        h,
        [
            "double FUN_00400020(uint64_t param_1)",
            "{",
            "    return FUN_00400030(param_1);",
            "}",
        ]
    );
}

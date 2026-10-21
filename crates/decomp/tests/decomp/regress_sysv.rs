//! Regression tests of the `SysV` floating parameters and arguments, of tail calls with no
//! return value and of the floating result of a call (batch D, D1 to D4).
//!
//! `SysV` numbers its integer and floating parameter slots apart. The recovery gave the
//! floating slots, but the namer gave them no parameter, and a call dropped their arguments.

use ghidorah_base::{Fuel, Storage};
use ghidorah_db::{Edit, Program, SessionLabel, Source};
use ghidorah_decomp::lattice::{Store, Ty};
use ghidorah_decomp::print::{self, Signature};
use ghidorah_decomp::{Call, Callee, Exit, Opts, ProgramEnv, Stmt, Tree};
use ghidorah_ir::{Loc, LocSet, NoNames};
use ghidorah_types::Prim;

use crate::fixtures::{entry_of, fid, program};
use crate::out_print::{ENTRY, Spec, decomp, k, op, temp, v};
use crate::regress::undefined_reads;
use crate::regress_float::{CALLEE, SigEnv, call_args, render_of, xmm0};
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

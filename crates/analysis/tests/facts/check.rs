//! The checker on analyzed fixtures: edges, gaps, values, syscalls and the fuel stop.

use ghidorah_analysis::facts::{Atom, Checker, Endpoint, Evidence, Gap, RefClass, Verdict};
use ghidorah_base::{Fuel, FuncId, Glob};
use ghidorah_db::{RefKey, RefType};

use crate::support::{analyzed, func, import, ram};

/// Checks `atom` with plenty of fuel.
fn check(c: &mut Checker<'_>, atom: &Atom) -> ghidorah_analysis::facts::Outcome {
    c.check(atom, &mut Fuel::new(100_000_000))
}

#[test]
fn calls_edges_and_gaps() {
    let p = analyzed("func_ptrs.gcc-O0");
    let mut c = Checker::new(&p);
    let main = func(&p, "main");
    let fire = func(&p, "fire");
    let op_mod = Endpoint::Func(func(&p, "op_mod"));
    let hit = check(
        &mut c,
        &Atom::Calls {
            f: main,
            g: op_mod.clone(),
        },
    );
    assert_eq!(hit.verdict, Verdict::Supported);
    let key = RefKey {
        from: ram(0x1411),
        op_index: 0,
        to: ram(0x1225),
        kind: RefType::UnconditionalCall,
    };
    assert_eq!(hit.evidence, [Evidence::Ref(key)]);
    let open = check(&mut c, &Atom::Calls { f: fire, g: op_mod });
    assert_eq!(open.verdict, Verdict::Unknown);
    assert_eq!(open.gaps, [Gap::Site(ram(0x1302))]);
    let printf = Endpoint::Import(import("printf"));
    let no = check(
        &mut c,
        &Atom::Calls {
            f: func(&p, "op_add"),
            g: printf.clone(),
        },
    );
    assert_eq!(no.verdict, Verdict::Refuted);
    assert!(no.complete());
    let stub = Endpoint::Func(func(&p, "printf@plt"));
    let via_stub = check(
        &mut c,
        &Atom::Calls {
            f: func(&p, "log_event"),
            g: stub,
        },
    );
    assert_eq!(
        via_stub.verdict,
        Verdict::Supported,
        "a stub names its import"
    );
    let direct = check(
        &mut c,
        &Atom::Reaches {
            f: main,
            g: printf,
            depth: 1,
        },
    );
    assert_eq!(direct.verdict, Verdict::Supported, "main calls printf");
    let path = check(
        &mut c,
        &Atom::Reaches {
            f: main,
            g: Endpoint::Import(import("__cxa_finalize")),
            depth: 3,
        },
    );
    assert_eq!(
        path.verdict,
        Verdict::Unknown,
        "fire is in the slice: {path:?}"
    );
    assert_eq!(path.gaps, [Gap::Site(ram(0x1292)), Gap::Site(ram(0x1302))]);
}

#[test]
fn reference_relations() {
    let p = analyzed("crackme.gcc-O2");
    let mut c = Checker::new(&p);
    let main = func(&p, "main");
    let check_password = func(&p, "check_password");
    let glob = |t: &str| Glob::new(t).expect("a glob");
    let hit = check(
        &mut c,
        &Atom::RefsString {
            f: main,
            glob: glob("Access granted"),
        },
    );
    assert_eq!(hit.verdict, Verdict::Supported);
    let miss = check(
        &mut c,
        &Atom::RefsString {
            f: check_password,
            glob: glob("Access*"),
        },
    );
    assert_eq!(miss.verdict, Verdict::Refuted);
    let addr = check(
        &mut c,
        &Atom::RefsAddr {
            f: main,
            addr: ram(0x2004),
        },
    );
    assert_eq!(addr.verdict, Verdict::Supported);
    let uses = check(
        &mut c,
        &Atom::UsesImport {
            f: check_password,
            import: import("strlen"),
        },
    );
    assert_eq!(uses.verdict, Verdict::Supported);
    let x = check(
        &mut c,
        &Atom::Xref {
            from: ram(0x1091),
            to: ram(0x11e0),
            kind: Some(RefClass::Call),
        },
    );
    assert_eq!(x.verdict, Verdict::Supported);
    let wrong = check(
        &mut c,
        &Atom::Xref {
            from: ram(0x1091),
            to: ram(0x11e0),
            kind: Some(RefClass::Type(RefType::Data)),
        },
    );
    assert_eq!(wrong.verdict, Verdict::Refuted);
    let inside = check(
        &mut c,
        &Atom::InFunc {
            addr: ram(0x1091),
            f: main,
        },
    );
    assert_eq!(inside.verdict, Verdict::Supported);
    assert_eq!(inside.evidence, [Evidence::Func(main)]);
    let ret = check(&mut c, &Atom::Noreturn { f: main });
    assert_eq!(ret.verdict, Verdict::Refuted);
    let missing = check(
        &mut c,
        &Atom::Noreturn {
            f: FuncId(ram(0x11d0)),
        },
    );
    assert_eq!(missing.verdict, Verdict::Unknown);
    assert_eq!(missing.gaps, [Gap::Func(FuncId(ram(0x11d0)))]);
}

#[test]
fn syscall_relations() {
    let p = analyzed("syscall_only.gcc-O2");
    let mut c = Checker::new(&p);
    let banner = func(&p, "emit_banner");
    let has = check(
        &mut c,
        &Atom::HasSyscall {
            f: banner,
            number: 1,
        },
    );
    assert_eq!(has.verdict, Verdict::Supported);
    assert_eq!(has.evidence, [Evidence::Site(ram(0x0040_1018))]);
    let not = check(
        &mut c,
        &Atom::HasSyscall {
            f: banner,
            number: 39,
        },
    );
    assert_eq!(not.verdict, Verdict::Refuted);
    let write = Endpoint::Syscall(1);
    let arg = check(
        &mut c,
        &Atom::ConstArg {
            callee: write.clone(),
            index: 2,
            value: 11,
        },
    );
    assert_eq!(
        arg.verdict,
        Verdict::Supported,
        "emit_status writes 11 bytes"
    );
    let none = check(
        &mut c,
        &Atom::ConstArg {
            callee: write,
            index: 0,
            value: 3,
        },
    );
    assert_eq!(none.verdict, Verdict::Refuted);
    assert!(none.complete());
}

#[test]
fn checks_stop_on_fuel() {
    let p = analyzed("crackme.gcc-O2");
    let mut c = Checker::new(&p);
    let atom = Atom::Calls {
        f: func(&p, "main"),
        g: Endpoint::Import(import("puts")),
    };
    let stopped = c.check(&atom, &mut Fuel::new(1));
    assert_eq!(stopped.verdict, Verdict::Unknown);
    assert!(stopped.stopped, "{stopped:?}");
    let full = check(&mut c, &atom);
    assert_eq!(full.verdict, Verdict::Supported);
    assert!(!full.stopped);
}

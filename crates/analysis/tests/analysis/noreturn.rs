//! Noreturn flags and the CFG after noreturn calls (AC-080a, AC-080b). The caveat
//! `W_NORETURN_SUSPECT` on a call with an unsafe fall-through to a callee that returns.

use ghidorah_analysis::cfg::{self, EdgeKind};
use ghidorah_analysis::code::decode_at;
use ghidorah_analysis::ctx::UNIT_NORETURN_CALL;
use ghidorah_base::{Address, FuncId, Id, WarningCode};
use ghidorah_db::{CodeUnit, FlowKind, Program};
use ghidorah_loader::LoadOpts;
use ghidorah_testkit::elf::{ElfBuilder, Loc, Section, Symbol};
use ghidorah_x86::Flow;

use crate::support::{
    all_t1, analyze, analyzed, fid, name_of, named, program_of, truth, truth_addr,
};

/// Gives the analyzed program of the `.text` bytes `code` with the function symbols `funcs`:
/// a name, an offset and a size each. The first function is the entry.
fn built(code: &[u8], funcs: &[(&str, u64, u64)]) -> Program {
    let mut b = ElfBuilder::exec().section(Section::code(".text", code));
    for (name, off, size) in funcs {
        b = b.symbol(Symbol::func(name, Loc::section(".text", *off), *size));
    }
    let b = b.entry(Loc::symbol(funcs[0].0));
    let mut p = program_of(&b.build(), &LoadOpts::AUTO);
    let _ = analyze(&mut p);
    p
}

/// Gives the `W_NORETURN_SUSPECT` caveats of the function `name`: the site and the remedy.
fn suspects(p: &Program, name: &str) -> Vec<(u64, String)> {
    let view = p.func(fid(named(p, name))).expect("the function");
    view.func
        .caveats
        .iter()
        .filter(|c| c.code == WarningCode::NoreturnSuspect)
        .map(|c| {
            let at = c.at.map_or(0, |a| a.off);
            (at, c.remedy.clone().unwrap_or_default())
        })
        .collect()
}

/// Gives the remedy of a suspect call to the function at `callee`.
fn remedy_of(callee: u64) -> String {
    format!("func_edit {{ action: \"set_noreturn\", target: \"fn:{callee:#x}\", noreturn: true }}")
}

#[test]
fn call_into_padding_is_suspect() {
    // call helper; int3 x3 | helper: xor eax, eax; ret
    let int3 = built(
        &[0xe8, 0x03, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0x31, 0xc0, 0xc3],
        &[("main", 0, 8), ("helper", 8, 3)],
    );
    // call helper; a 2-byte nop into the entry of helper | helper: xor eax, eax; ret
    let nop = built(
        &[0xe8, 0x02, 0, 0, 0, 0x66, 0x90, 0x31, 0xc0, 0xc3],
        &[("main", 0, 7), ("helper", 7, 3)],
    );
    // helper: xor eax, eax; ret; nop | call helper; then 0 bytes
    let zero = built(
        &[0x31, 0xc0, 0xc3, 0x90, 0xe8, 0xf7, 0xff, 0xff, 0xff, 0, 0],
        &[("main", 4, 7), ("helper", 0, 3)],
    );
    // helper: xor eax, eax; ret | call helper at the end of the code
    let end = built(
        &[0x31, 0xc0, 0xc3, 0xe8, 0xf8, 0xff, 0xff, 0xff],
        &[("main", 3, 5), ("helper", 0, 3)],
    );
    for p in [&int3, &nop, &zero, &end] {
        let main = named(p, "main");
        let helper = named(p, "helper");
        assert_eq!(
            suspects(p, "main"),
            vec![(main, remedy_of(helper))],
            "the call falls into padding"
        );
        let callee = p.func(fid(helper)).expect("helper");
        assert!(callee.noreturn.is_none(), "helper returns");
        assert!(suspects(p, "helper").is_empty());
    }
    // call helper; ret | helper: xor eax, eax; ret
    let safe = built(
        &[0xe8, 0x01, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3],
        &[("main", 0, 6), ("helper", 6, 3)],
    );
    assert!(
        suspects(&safe, "main").is_empty(),
        "the call returns into code"
    );
}

#[test]
fn noreturn_call_has_no_suspect_caveat() {
    // call fatal; int3 x3 | fatal: ud2
    let p = built(
        &[0xe8, 0x03, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0x0f, 0x0b],
        &[("main", 0, 8), ("fatal", 8, 2)],
    );
    let fatal = p.func(fid(named(&p, "fatal"))).expect("fatal");
    assert_eq!(fatal.noreturn.map(|n| n.value), Some(true));
    assert!(suspects(&p, "main").is_empty());
    let mut seen = 0usize;
    for (path, p) in all_t1() {
        for view in p.funcs() {
            for c in &view.func.caveats {
                if c.code != WarningCode::NoreturnSuspect {
                    continue;
                }
                seen += 1;
                let remedy = c.remedy.clone().unwrap_or_default();
                let target = remedy
                    .split('"')
                    .find_map(|part| match Id::parse(part) {
                        Ok(Id::Func(f)) => Some(f),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("{path}: a remedy names a function: {remedy}"));
                let callee = p.func(target).and_then(|f| f.noreturn);
                assert!(
                    callee.is_none_or(|n| !n.value),
                    "{path}: the suspect callee {target} is noreturn"
                );
            }
        }
    }
    assert!(seen < 50, "{seen} suspect calls in the T1 fixtures");
}

/// Tells if the call unit at `at` calls a noreturn function, by its flag or its callee.
fn noreturn_call(p: &Program, at: u64, flags: u8) -> bool {
    if flags & UNIT_NORETURN_CALL != 0 {
        return true;
    }
    let Some(insn) = decode_at(p, at) else {
        return false;
    };
    if insn.flow() != Flow::Call {
        return false;
    }
    insn.target()
        .and_then(|t| p.func(FuncId(Address::ram(t))))
        .and_then(|f| f.noreturn)
        .is_some_and(|n| n.value)
}

#[test]
fn ac_080a_no_fallthrough_after_noreturn() {
    let mut sites = 0usize;
    for (path, p) in all_t1() {
        for view in p.funcs() {
            let g = cfg::build(p, view.id()).expect("a CFG");
            for block in &g.blocks {
                let Some((at, _)) = block.insns.last() else {
                    continue;
                };
                let Some(CodeUnit::Insn { flow, flags, .. }) = p.code_unit(*at) else {
                    continue;
                };
                if !matches!(flow, FlowKind::Call | FlowKind::ICall)
                    || !noreturn_call(p, *at, *flags)
                {
                    continue;
                }
                sites += 1;
                let bad: Vec<_> = g
                    .edges
                    .iter()
                    .filter(|e| e.from == block.start)
                    .filter(|e| matches!(e.kind, EdgeKind::CallReturn | EdgeKind::Fallthrough))
                    .collect();
                assert!(
                    bad.is_empty(),
                    "{path}: the noreturn call at {at:#x} falls through: {bad:?}"
                );
                let next = at + u64::from(p.code_unit(*at).map_or(0, CodeUnit::len));
                let reached = g.edges.iter().any(|e| e.to == Some(Address::ram(next)));
                let in_body = view.func.body.contains(next);
                assert!(
                    !in_body || reached || next == view.func.entry.off,
                    "{path}: the unit after {at:#x} has no other edge"
                );
            }
        }
    }
    assert!(sites > 50, "the fixtures hold noreturn calls: {sites}");
}

#[test]
fn ac_080b_noreturn_wrappers() {
    let variants = [
        "noreturn_wrappers.gcc-O0",
        "noreturn_wrappers.gcc-O0.stripped",
        "noreturn_wrappers.gcc-O2",
        "noreturn_wrappers.gcc-O2.stripped",
        "noreturn_wrappers.clang-O2",
        "noreturn_wrappers.clang-O2.stripped",
    ];
    for name in variants {
        let p = analyzed(&format!("fixtures/bin/{name}"));
        let t = truth(name);
        let list = t
            .pointer("/facts/noreturn")
            .and_then(|v| v.as_array())
            .expect("the truth lists the noreturn wrappers");
        assert_eq!(list.len(), 4);
        for wrapper in list.iter().filter_map(|v| v.as_str()) {
            let at = truth_addr(&t, wrapper);
            let f = p
                .func(fid(at))
                .unwrap_or_else(|| panic!("{name}: no function {wrapper} at {at:#x}"));
            assert_eq!(
                f.noreturn.map(|n| n.value),
                Some(true),
                "{name}: {wrapper} is noreturn"
            );
        }
        for returns in ["check_args", "main"] {
            let at = truth_addr(&t, returns);
            let f = p.func(fid(at)).expect("the function");
            assert!(f.noreturn.is_none(), "{name}: {returns} returns");
        }
    }
}

#[test]
fn known_list_flags_stubs_and_slots() {
    let p = analyzed("fixtures/bin/noreturn_wrappers.gcc-O2");
    for stub in ["exit@plt", "abort@plt", "_exit@plt"] {
        let at = named(&p, stub);
        let f = p.func(fid(at)).expect("a stub function");
        assert!(f.func.flags.thunk, "{stub} is a thunk");
        assert_eq!(f.noreturn.map(|n| n.value), Some(true), "{stub}");
    }
    let puts = p.func(fid(named(&p, "puts@plt"))).expect("puts");
    assert!(puts.noreturn.is_none());

    // -fno-plt: `call [rip+slot]` of a listed import does not fall through.
    let q = analyzed("fixtures/bin/socket_client.gcc-O2-noplt");
    let mut flagged = 0;
    for view in q.funcs() {
        for r in view.func.body.ranges() {
            for (at, unit) in q.analysis().units_in(*r) {
                let CodeUnit::Insn { flow, flags, .. } = unit;
                if *flow == FlowKind::ICall && flags & UNIT_NORETURN_CALL != 0 {
                    flagged += 1;
                    assert!(decode_at(&q, at).is_some());
                }
            }
        }
    }
    assert!(
        flagged > 0,
        "{}: a slot call is noreturn",
        name_of("socket_client")
    );
}

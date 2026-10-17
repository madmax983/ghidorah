//! Noreturn flags and the CFG after noreturn calls (AC-080a, AC-080b).

use ghidorah_analysis::cfg::{self, EdgeKind};
use ghidorah_analysis::code::decode_at;
use ghidorah_analysis::ctx::UNIT_NORETURN_CALL;
use ghidorah_base::{Address, FuncId};
use ghidorah_db::{CodeUnit, FlowKind, Program};
use ghidorah_x86::Flow;

use crate::support::{all_t1, analyzed, fid, name_of, named, truth, truth_addr};

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
    assert!(sites > 100, "the fixtures hold noreturn calls: {sites}");
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
            for (at, unit) in q.analysis().listing().units_in(*r) {
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

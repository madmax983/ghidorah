//! The seed analyzers: entry points, symbols, PLT stubs, FDEs, call targets and flow refs.

use ghidorah_base::Address;
use ghidorah_db::{Program, RefType, StartReason};

use crate::support::{analyzed, fid, named, truth, truth_addr};

fn reason(p: &Program, at: u64) -> Option<StartReason> {
    p.func(fid(at)).map(|f| f.func.start_reason)
}

/// Tells if a call reference from the body of `caller` goes to `to`.
fn calls(p: &Program, caller: u64, to: Address) -> bool {
    p.analysis().refs().iter().any(|r| {
        r.value.key.kind == RefType::UnconditionalCall
            && r.value.key.to == to
            && p.owner_of(r.value.key.from) == Some(fid(caller))
    })
}

#[test]
fn seeds_of_an_unstripped_file() {
    let p = analyzed("fixtures/bin/hello.gcc-O2");
    let entry = p.binary().entry_points.first().expect("an entry").addr;
    assert_eq!(reason(&p, entry), Some(StartReason::Entry));
    let main = named(&p, "main");
    assert_eq!(reason(&p, main), Some(StartReason::Symbol));
    let main_f = p.func(fid(main)).expect("main");
    assert_eq!(main_f.func.confidence, 100);
    assert!(main_f.func.size() > 2);
    let puts = named(&p, "puts@plt");
    let stub = p.func(fid(puts)).expect("the stub");
    assert_eq!(stub.func.start_reason, StartReason::PltStub);
    assert_eq!(stub.func.confidence, 100);
    assert!(stub.func.flags.thunk);
    let finish = named(&p, "finish");
    assert!(
        calls(&p, finish, Address::ram(puts)),
        "finish calls puts@plt"
    );
    let libc = p
        .imports()
        .values()
        .find(|i| i.id.name() == Some("__libc_start_main"))
        .expect("the import");
    assert!(
        calls(&p, entry, libc.ext),
        "_start calls the import through its slot"
    );
}

#[test]
fn seeds_of_a_stripped_file() {
    let name = "noreturn_wrappers.gcc-O2.stripped";
    let p = analyzed(&format!("fixtures/bin/{name}"));
    let t = truth(name);
    let die = truth_addr(&t, "die");
    assert_eq!(
        reason(&p, die),
        Some(StartReason::Call),
        "a call beats an FDE"
    );
    let main = truth_addr(&t, "main");
    assert_eq!(reason(&p, main), Some(StartReason::Fde));
    assert_eq!(p.func(fid(main)).map(|f| f.func.confidence), Some(90));
    let check = truth_addr(&t, "check_args");
    assert_eq!(p.func(fid(check)).map(|f| f.func.confidence), Some(95));
}

#[test]
fn every_truth_function_is_found() {
    for name in [
        "two_helpers.gcc-O2",
        "loops.gcc-O0",
        "switch.clang-O2",
        "canary.gcc-O2",
        "noreturn_wrappers.clang-O2.stripped",
    ] {
        let p = analyzed(&format!("fixtures/bin/{name}"));
        let t = truth(name);
        let funcs = t
            .get("functions")
            .and_then(|f| f.as_array())
            .expect("functions");
        // A tail-call target with no size waits for the FETCH rule of WP-19.
        let tail_targets: Vec<&str> = t
            .get("tail_calls")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|e| e.as_array()?.get(1)?.as_str())
            .collect();
        for f in funcs {
            let at = f
                .get("addr")
                .and_then(|a| a.as_str())
                .and_then(ghidorah_base::hex::parse_u64)
                .expect("an address");
            let fname = f.get("name").and_then(|n| n.as_str()).unwrap_or_default();
            let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or_default();
            if size == 0 && tail_targets.contains(&fname) {
                continue;
            }
            assert!(
                p.func(fid(at)).is_some(),
                "{name}: {fname} at {at:#x} is a function"
            );
        }
    }
}

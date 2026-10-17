//! The call graph against the call edges of the truth files.

use std::collections::BTreeSet;

use ghidorah_analysis::{CallGraph, Callee};
use ghidorah_base::Address;
use ghidorah_db::Program;
use ghidorah_json::Value;

use crate::blobs::{BASE, Blob};
use crate::support::{analyze, analyzed, fid, truth};

/// Gives the name of a callee: the import name or the function name.
fn callee_name(p: &Program, c: &Callee) -> String {
    match c {
        Callee::Import(id) => id.name().unwrap_or_default().to_owned(),
        Callee::Func(f) => p.name(f.0).map(|n| n.text).unwrap_or_default(),
    }
}

#[test]
fn call_edges_match_the_truth() {
    for name in [
        "noreturn_wrappers.gcc-O2",
        "noreturn_wrappers.gcc-O0",
        "hello.gcc-O2",
        "hello.gcc-O2-noplt",
    ] {
        let p = analyzed(&format!("fixtures/bin/{name}"));
        let g = CallGraph::build(&p);
        let ours: BTreeSet<(String, String)> = g
            .edges()
            .into_iter()
            .map(|(f, c)| {
                let caller = p.name(f.0).map(|n| n.text).unwrap_or_default();
                (caller, callee_name(&p, c))
            })
            .collect();
        let t = truth(name);
        let tails: BTreeSet<(String, String)> = pairs(t.get("tail_calls"));
        for edge in pairs(t.get("call_edges")) {
            if tails.contains(&edge) {
                continue;
            }
            assert!(ours.contains(&edge), "{name}: no edge {edge:?} in {ours:?}");
        }
    }
}

fn pairs(v: Option<&Value>) -> BTreeSet<(String, String)> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let e = e.as_array()?;
            Some((
                e.first()?.as_str()?.to_owned(),
                e.get(1)?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

#[test]
fn callers_and_sites() {
    // 0x0: call 0x10; call 0x10; ret.  0x10: ret.
    let mut p = Blob::new()
        .call(0x10)
        .call(0x10)
        .ret()
        .at(0x10)
        .ret()
        .load(Some(0));
    let _ = analyze(&mut p);
    let g = CallGraph::build(&p);
    let main = fid(BASE);
    let callee = Callee::Func(fid(BASE + 0x10));
    assert_eq!(g.callees(main), [&callee]);
    assert_eq!(g.callers(&callee), [main]);
    assert_eq!(
        g.sites(main, &callee),
        [Address::ram(BASE), Address::ram(BASE + 5)]
    );
    assert_eq!(g.len(), 1);
    assert!(!g.is_empty());
    assert!(g.callees(callee_id()).is_empty());
    assert!(CallGraph::default().is_empty());
}

const fn callee_id() -> ghidorah_base::FuncId {
    fid(BASE + 0x10)
}

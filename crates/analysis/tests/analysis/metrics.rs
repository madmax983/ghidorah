//! Metrics, coverage, the worklist and the frozen priority.

use std::collections::BTreeMap;

use ghidorah_analysis::analyzers::metrics::{
    self, Coverage, FuncMetrics, ItemKind, Ranked, Remedy, WorkItem,
};
use ghidorah_analysis::{CallGraph, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, WarningCode};
use ghidorah_db::meta::{MetaLine, apply};
use ghidorah_db::{
    Caveat, CommentKind, Edit, FuncProgress, FuncRecord, Function, Program, SessionLabel, Source,
    StartReason, SymKind,
};
use ghidorah_types::Category;

use crate::blobs::{BASE, Blob};
use crate::support::{analyze, fid, named, program, t1};

/// The blob of the exact metrics test: `f` calls `g` and branches to one of two returns.
fn two_funcs() -> Program {
    let blob = Blob::new()
        .call(0x20) // 0x00
        .je(0x0c) // 0x05
        .ret() // 0x0b
        .ret() // 0x0c
        .at(0x20)
        .ret(); // 0x20: g
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    p
}

#[test]
fn exact_metrics_of_a_blob() {
    let p = two_funcs();
    let graph = CallGraph::build(&p);
    let f = metrics::func_metrics(&p, &graph, fid(BASE)).expect("f");
    assert_eq!(
        f,
        FuncMetrics {
            func: fid(BASE),
            size: 13,
            blocks: 4,
            insns: 4,
            edges: 3,
            cyclomatic: 2,
            callers: 0,
            callees: 1,
            string_refs: 0,
            import_calls: BTreeMap::new(),
        }
    );
    let g = metrics::func_metrics(&p, &graph, fid(BASE + 0x20)).expect("g");
    assert_eq!(
        (g.blocks, g.insns, g.cyclomatic, g.callers, g.callees),
        (1, 1, 1, 1, 0)
    );
    assert_eq!(metrics::func_metrics(&p, &graph, fid(BASE + 1)), None);
    let all = metrics::all(&p);
    assert_eq!(all, [f, g], "every function in entry order");
}

#[test]
fn import_calls_and_string_refs() {
    let p = t1("socket_client.gcc-O0");
    let graph = CallGraph::build(p);
    let connect =
        metrics::func_metrics(p, &graph, fid(named(p, "connect_to"))).expect("a function");
    assert!(
        connect
            .import_calls
            .get(&Category::Network)
            .copied()
            .unwrap_or(0)
            >= 3,
        "socket, inet_pton and connect: {connect:?}"
    );
    let main = metrics::func_metrics(p, &graph, fid(named(p, "main"))).expect("main");
    assert!(main.string_refs >= 2, "two strings: {main:?}");
    assert!(
        main.callees >= 3,
        "connect_to, send_hello, puts and close: {main:?}"
    );
    let rank = metrics::priority(p);
    assert_eq!(
        rank.first().map(|r| r.func),
        Some(fid(named(p, "connect_to"))),
        "network calls rank first: {rank:?}"
    );
}

#[test]
fn metrics_deterministic() {
    for name in [
        "crackme.gcc-O2",
        "func_ptrs.clang-O2.stripped",
        "switch.gcc-O2",
    ] {
        let path = format!("fixtures/bin/{name}");
        let mut a = program(&path);
        let _ = analyze(&mut a);
        let mut b = program(&path);
        let mut s = Scheduler::new();
        while s
            .run(&mut b, Until::Full, &mut Fuel::new(7))
            .expect("a slice")
            .resume
        {}
        let shared = t1(name);
        for p in [&a, &b] {
            assert_eq!(metrics::all(p), metrics::all(shared), "{name}: metrics");
            assert_eq!(
                metrics::coverage(p),
                metrics::coverage(shared),
                "{name}: coverage"
            );
            assert_eq!(
                metrics::worklist(p),
                metrics::worklist(shared),
                "{name}: worklist"
            );
            assert_eq!(
                metrics::priority(p),
                metrics::priority(shared),
                "{name}: priority"
            );
        }
        let all = metrics::all(shared);
        assert!(!all.is_empty(), "{name}: functions");
        for m in &all {
            assert!(m.cyclomatic >= 1 && m.insns >= m.blocks, "{name}: {m:?}");
        }
    }
}

/// Renames the function at `at` and marks it visited and commented.
fn touch_names(p: &mut Program, at: u64) {
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("rename", Source::Agent, label)
        .expect("a transaction");
    let name = tx.fact("renamed_fn".to_owned());
    tx.apply(Edit::SetName {
        addr: Address::ram(at),
        key: None,
        kind: SymKind::Function,
        primary: true,
        name: Some(name),
        evidence: Vec::new(),
    })
    .expect("a rename");
    let text = tx.fact("a note".to_owned());
    tx.apply(Edit::SetComment {
        addr: Address::ram(at),
        kind: CommentKind::Plate,
        text: Some(text),
    })
    .expect("a comment");
    tx.commit().expect("a commit");
    let row = FuncProgress {
        visited: true,
        ..FuncProgress::default()
    };
    apply(p, &MetaLine::Progress { func: fid(at), row });
}

#[test]
fn priority_frozen_per_run() {
    let mut p = program("fixtures/bin/socket_client.gcc-O2.stripped");
    let (mut sched, _) = analyze(&mut p);
    let first = metrics::priority(&p);
    assert!(first.len() > 5, "the functions have a priority");
    for pair in first.windows(2) {
        let (a, b): (&Ranked, &Ranked) = (&pair[0], &pair[1]);
        assert!(
            a.score > b.score || (a.score == b.score && a.func < b.func),
            "score from high to low, then the entry: {pair:?}"
        );
    }
    let before = metrics::coverage(&p);
    let low = first
        .iter()
        .rev()
        .find(|r| p.name(r.func.0).is_some_and(|n| n.is_default()))
        .expect("a function with a default name")
        .func
        .0
        .off;
    touch_names(&mut p, low);
    assert_eq!(
        metrics::priority(&p),
        first,
        "names, comments and visited do not change it"
    );
    let after = metrics::coverage(&p);
    assert_eq!(after.visited, before.visited + 1);
    assert_eq!(after.commented, before.commented + 1);
    assert!(after.named > before.named);
    let again = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a second run");
    assert!(again.commit.is_none_or(|c| c.noop));
    assert_eq!(
        metrics::priority(&p),
        first,
        "a run with no change keeps it"
    );
}

#[test]
fn coverage_counts() {
    let p = t1("hello.gcc-O2");
    let funcs = u64::try_from(p.funcs().len()).expect("small");
    let c = metrics::coverage(p);
    assert_eq!(
        c,
        Coverage {
            functions: funcs,
            analyzed: funcs,
            visited: 0,
            named: funcs,
            typed: c.typed,
            commented: 0,
        },
        "an unstripped file names each function"
    );
    let s = metrics::coverage(t1("hello.gcc-O2.stripped"));
    assert!(
        s.named < s.functions,
        "a stripped file has default names: {s:?}"
    );
}

#[test]
fn worklist_items() {
    let p = t1("crackme.gcc-O2.stripped");
    let list = metrics::worklist(p);
    let gaps: Vec<&WorkItem> = list.iter().filter(|i| i.kind == ItemKind::Gap).collect();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].remedy, Some(Remedy::Create(0x11d0)));
    assert_eq!(gaps[0].at, Address::ram(0x11d0));
    let blob = Blob::new()
        .raw(&[0xff, 0xd0]) // 0x00: call rax
        .jmp_rax() // 0x02: jmp rax
        .at(0x10);
    let mut p = blob.load(Some(0));
    let _ = analyze(&mut p);
    let items: Vec<(ItemKind, u64, Option<FuncId>, Option<Remedy>)> = metrics::worklist(&p)
        .iter()
        .map(|i| (i.kind, i.at.off - BASE, i.func, i.remedy))
        .collect();
    assert_eq!(
        items,
        [
            (
                ItemKind::UnresolvedCall,
                0,
                Some(fid(BASE)),
                Some(Remedy::SetCallTargets(BASE))
            ),
            (
                ItemKind::UnresolvedJump,
                2,
                Some(fid(BASE)),
                Some(Remedy::SetJumpTable(BASE + 2))
            ),
        ]
    );
    let names: Vec<&str> = [
        ItemKind::UnresolvedJump,
        ItemKind::UnresolvedCall,
        ItemKind::OverrideConflict,
        ItemKind::Gap,
    ]
    .map(ItemKind::name)
    .to_vec();
    assert_eq!(
        names,
        [
            "unresolved_jump",
            "unresolved_call",
            "override_conflict",
            "gap"
        ]
    );
}

#[test]
fn override_conflicts_join_the_worklist() {
    let mut p = two_funcs();
    let g = BASE + 0x20;
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("create", Source::Agent, label)
        .expect("a transaction");
    let mut func = Function::new(Address::ram(g), StartReason::Agent, 100, Source::Agent);
    func.caveats.push(Caveat {
        code: WarningCode::AgentOverrideConflict,
        at: None,
        remedy: None,
    });
    let record = FuncRecord {
        func,
        vars: Vec::new(),
        plate: None,
    };
    tx.apply(Edit::CreateFunction(Box::new(record)))
        .expect("an agent function");
    tx.commit().expect("a commit");
    let items: Vec<(ItemKind, Address, Option<FuncId>, Option<Remedy>)> = metrics::worklist(&p)
        .into_iter()
        .map(|i| (i.kind, i.at, i.func, i.remedy))
        .collect();
    assert_eq!(
        items,
        [(
            ItemKind::OverrideConflict,
            Address::ram(g),
            Some(fid(g)),
            None
        )]
    );
}

#[test]
fn remedy_args() {
    let cases = [
        (
            Remedy::Create(0x10),
            r#"{"action":"create","target":"0x10"}"#,
        ),
        (
            Remedy::SetCallTargets(0x20),
            r#"{"action":"set_call_targets","at":"0x20"}"#,
        ),
        (
            Remedy::SetJumpTable(0x30),
            r#"{"action":"set_jumptable","at":"0x30"}"#,
        ),
        (
            Remedy::SetNoreturn(0x40),
            r#"{"action":"set_noreturn","target":"0x40"}"#,
        ),
    ];
    for (remedy, text) in cases {
        assert_eq!(ghidorah_json::write(&remedy.args()), text);
    }
}

//! AC-074 and AC-075a: dominators against a naive model, and deep graphs in a small stack.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

use std::collections::BTreeSet;

use ghidorah_ir::{Cfg, GraphError, Loop, Node, dominators, irreducible, loops, rpo, sccs};
use ghidorah_testkit::rng::{Xoshiro256ss, below};

/// Makes a graph from an edge list.
fn graph(count: usize, edges: &[(u32, u32)]) -> Cfg {
    let mut cfg = Cfg::new(count, Node(0)).expect("a valid entry");
    for &(a, b) in edges {
        cfg.add_edge(Node(a), Node(b)).expect("valid nodes");
    }
    cfg
}

fn nodes(list: &[u32]) -> Vec<Node> {
    list.iter().copied().map(Node).collect()
}

/// The nodes that the entry reaches when the walk skips `removed`.
fn reach(cfg: &Cfg, removed: Option<Node>) -> BTreeSet<Node> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![cfg.entry()];
    while let Some(n) = stack.pop() {
        if Some(n) == removed || !seen.insert(n) {
            continue;
        }
        stack.extend(cfg.succs(n).iter().copied());
    }
    seen
}

/// The naive model: `dom[v]` holds each `d` such that removing `d` cuts `v` from the entry.
fn naive_dominators(cfg: &Cfg) -> Vec<Option<BTreeSet<Node>>> {
    let all = reach(cfg, None);
    let count = u32::try_from(cfg.len()).expect("small graph");
    let mut dom: Vec<Option<BTreeSet<Node>>> = (0..count)
        .map(|v| all.contains(&Node(v)).then(|| BTreeSet::from([Node(v)])))
        .collect();
    for d in all.iter().copied() {
        let without = reach(cfg, Some(d));
        for v in all.iter().filter(|v| !without.contains(v)) {
            if let Some(set) = dom.get_mut(v.index()).and_then(Option::as_mut) {
                set.insert(d);
            }
        }
    }
    dom
}

/// The naive immediate dominator: the strict dominator with the most dominators.
fn naive_idom(dom: &[Option<BTreeSet<Node>>], v: Node) -> Option<Node> {
    let set = dom.get(v.index())?.as_ref()?;
    set.iter().copied().filter(|&d| d != v).max_by_key(|d| {
        dom.get(d.index())
            .and_then(Option::as_ref)
            .map_or(0, BTreeSet::len)
    })
}

/// Makes a random graph. `knot` adds the two-entry cycle `0 -> x, 0 -> y, x <-> y`.
fn random_graph(rng: &mut Xoshiro256ss, knot: bool) -> (Cfg, Option<(Node, Node)>) {
    let count = usize::try_from(1 + below(rng, 20)).expect("small");
    let extra = if knot { 2 } else { 0 };
    let mut cfg = Cfg::new(count + extra, Node(0)).expect("a valid entry");
    let n = u64::try_from(count).expect("small");
    for v in 0..n {
        for _ in 0..below(rng, 4) {
            let to = below(rng, n);
            cfg.add_edge(node(v), node(to)).expect("valid nodes");
        }
    }
    if !knot {
        return (cfg, None);
    }
    let (x, y) = (node(n), node(n + 1));
    for (a, b) in [(Node(0), x), (Node(0), y), (x, y), (y, x)] {
        cfg.add_edge(a, b).expect("valid nodes");
    }
    if count > 1 {
        cfg.add_edge(y, node(below(rng, n))).expect("valid nodes");
    }
    (cfg, Some((x, y)))
}

fn node(v: u64) -> Node {
    Node(u32::try_from(v).expect("small"))
}

#[test]
fn ac_074_dominators_model() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x074);
    let mut knots = 0;
    for case in 0..10_000 {
        let (cfg, knot) = random_graph(&mut rng, case % 4 == 0);
        let dom = dominators(&cfg);
        let model = naive_dominators(&cfg);
        let count = u32::try_from(cfg.len()).expect("small");
        for v in (0..count).map(Node) {
            let reachable = model.get(v.index()).is_some_and(Option::is_some);
            assert_eq!(dom.is_reachable(v), reachable, "case {case} node {v:?}");
            assert_eq!(
                dom.idom(v),
                naive_idom(&model, v),
                "case {case} idom of {v:?}"
            );
            for d in (0..count).map(Node) {
                let want = model
                    .get(v.index())
                    .and_then(Option::as_ref)
                    .is_some_and(|set| set.contains(&d));
                assert_eq!(dom.dominates(d, v), want, "case {case}: {d:?} dom {v:?}");
            }
        }
        if let Some((x, y)) = knot {
            let regions = irreducible(&cfg, &dom);
            assert!(
                regions.iter().any(|r| r.contains(&x) && r.contains(&y)),
                "case {case}: the knot is an irreducible region"
            );
            knots += 1;
        }
    }
    assert_eq!(knots, 2_500, "the cases include irreducible graphs");
}

#[test]
fn rpo_and_tree_rows() {
    // 0 -> 1 -> 3, 0 -> 2 -> 3, 3 -> 1 (a loop 1 -> 3 -> 1), 4 unreachable.
    let cfg = graph(5, &[(0, 1), (0, 2), (1, 3), (2, 3), (3, 1)]);
    assert_eq!(rpo(&cfg), nodes(&[0, 2, 1, 3]));
    let dom = dominators(&cfg);
    assert_eq!(dom.idom(Node(0)), None);
    assert_eq!(dom.idom(Node(1)), Some(Node(0)));
    assert_eq!(dom.idom(Node(3)), Some(Node(0)));
    assert_eq!(dom.idom(Node(4)), None);
    assert!(!dom.is_reachable(Node(4)));
    assert_eq!(dom.rpo_index(Node(2)), Some(1));
    assert_eq!(dom.rpo_index(Node(4)), None);
    assert!(dom.dominates(Node(0), Node(3)));
    assert!(!dom.dominates(Node(1), Node(3)));
    assert!(!dom.dominates(Node(4), Node(4)));
    assert_eq!(
        dom.children(),
        vec![nodes(&[1, 2, 3]), vec![], vec![], vec![], vec![]]
    );
    // The loop 1 -> 3 -> 1 has two entries (from 0 and from 2): it is irreducible.
    assert_eq!(loops(&cfg, &dom), Vec::<Loop>::new());
    assert_eq!(irreducible(&cfg, &dom), vec![nodes(&[1, 3])]);
    assert_eq!(cfg.preds()[3], nodes(&[1, 2]));
}

#[test]
fn loops_and_components() {
    // 0 -> 1 -> 2 -> 1 (inner), 2 -> 3 -> 0 (outer), 3 -> 4, 4 -> 4 (self loop).
    let cfg = graph(5, &[(0, 1), (1, 2), (2, 1), (2, 3), (3, 0), (3, 4), (4, 4)]);
    let dom = dominators(&cfg);
    assert_eq!(
        loops(&cfg, &dom),
        vec![
            Loop {
                header: Node(0),
                body: nodes(&[0, 1, 2, 3]),
                latches: nodes(&[3]),
            },
            Loop {
                header: Node(1),
                body: nodes(&[1, 2]),
                latches: nodes(&[2]),
            },
            Loop {
                header: Node(4),
                body: nodes(&[4]),
                latches: nodes(&[4]),
            },
        ]
    );
    assert_eq!(sccs(&cfg), vec![nodes(&[4]), nodes(&[0, 1, 2, 3])]);
    assert!(irreducible(&cfg, &dom).is_empty());
    // A node with no cycle is one component.
    let line = graph(3, &[(0, 1), (1, 2)]);
    assert_eq!(sccs(&line), vec![nodes(&[2]), nodes(&[1]), nodes(&[0])]);
}

#[test]
fn graph_errors() {
    assert_eq!(
        Cfg::new(0, Node(0)).err(),
        Some(GraphError::NoNode(Node(0)))
    );
    let mut cfg = graph(2, &[]);
    assert_eq!(
        cfg.add_edge(Node(0), Node(2)),
        Err(GraphError::NoNode(Node(2)))
    );
    assert_eq!(
        cfg.add_edge(Node(5), Node(1)),
        Err(GraphError::NoNode(Node(5)))
    );
    assert!(cfg.succs(Node(9)).is_empty());
    assert_eq!(cfg.len(), 2);
    assert!(!cfg.is_empty());
    assert!(GraphError::TooLarge.to_string().contains("too many"));
}

/// The node count of the deep chain of AC-075a.
const CHAIN: u32 = 200_000;

#[test]
fn ac_075a_deep_cfg_small_stack() {
    let worker = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let count = usize::try_from(CHAIN).expect("fits");
            let mut cfg = Cfg::new(count, Node(0)).expect("a valid entry");
            for v in 1..CHAIN {
                cfg.add_edge(Node(v - 1), Node(v)).expect("valid nodes");
            }
            // One back edge makes the chain one long loop.
            cfg.add_edge(Node(CHAIN - 1), Node(0)).expect("valid nodes");
            let order = rpo(&cfg);
            assert_eq!(order.len(), count);
            assert!(order.iter().zip(0..).all(|(n, v)| n.0 == v));
            let dom = dominators(&cfg);
            assert!((1..CHAIN).all(|v| dom.idom(Node(v)) == Some(Node(v - 1))));
            assert!(dom.dominates(Node(0), Node(CHAIN - 1)));
            let found = loops(&cfg, &dom);
            assert_eq!(found.len(), 1);
            assert_eq!(found.first().map(|l| l.body.len()), Some(count));
            assert_eq!(sccs(&cfg).len(), 1);
            assert!(irreducible(&cfg, &dom).is_empty());
        })
        .expect("the thread starts");
    worker
        .join()
        .expect("the deep graph walks finish in a 256 KiB stack");
}

#[test]
fn irreducible_inside_a_loop() {
    // 0 -> 1 (the loop header), 1 -> 2, 1 -> 3, 2 <-> 3 (two entries), 2 -> 4, 4 -> 1, 4 -> 5.
    let cfg = graph(
        6,
        &[
            (0, 1),
            (1, 2),
            (1, 3),
            (2, 3),
            (3, 2),
            (2, 4),
            (4, 1),
            (4, 5),
        ],
    );
    let dom = dominators(&cfg);
    let found = loops(&cfg, &dom);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].header, Node(1));
    assert_eq!(found[0].body, nodes(&[1, 2, 3, 4]));
    assert_eq!(found[0].latches, nodes(&[4]));
    assert_eq!(irreducible(&cfg, &dom), vec![nodes(&[2, 3])]);
    assert!(!dom.dominates(Node(2), Node(3)) && !dom.dominates(Node(3), Node(2)));
    assert_eq!(dom.idom(Node(4)), Some(Node(2)));
    assert_eq!(dom.idom(Node(5)), Some(Node(4)));
}

//! The structurer on random shapes: trace equivalence, the FLAT rate, labels and the deep chain.

use std::collections::BTreeSet;

use ghidorah_base::Fuel;
use ghidorah_decomp::interp_ast::{End, Seeded, cfg_trace, tree_trace};
use ghidorah_decomp::structure::{self, Opts};
use ghidorah_decomp::{FlatReason, Mode, Shape, Tree, flat};
use ghidorah_testkit::rng::Xoshiro256ss;

use crate::shapes::{chain, irreducible_of, random, reducible, seeds};

/// The block limit of each trace.
const LIMIT: usize = 300;

/// The options with no node budget.
const UNBOUNDED: Opts = Opts {
    max_nodes: usize::MAX,
};

/// Checks that the CFG walker and the AST interpreter give equal traces for each seed.
fn assert_equivalent(shape: &Shape, tree: &Tree, seeds: &[u64], what: &str) {
    for &seed in seeds {
        let oracle = Seeded(seed);
        let want = cfg_trace(shape, &oracle, LIMIT);
        let got = tree_trace(tree, shape, &oracle, LIMIT);
        assert_ne!(want.end, End::Stuck, "{what}: the CFG walk is stuck");
        assert_eq!(got, want, "{what} seed {seed:#x}:\n{shape:#?}\n{tree:#?}");
    }
}

#[test]
fn ac_098a_trace_equivalence() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x098a);
    let mut irreducible = 0;
    let mut gotos = 0;
    for i in 0..10_000 {
        let shape = random(&mut rng, 64);
        if !irreducible_of(&shape).is_empty() {
            irreducible += 1;
        }
        let out = structure::run(&shape, &UNBOUNDED, &mut Fuel::unlimited());
        if !out.tree.gotos().is_empty() {
            gotos += 1;
        }
        let s = seeds(&mut rng, 3);
        assert_equivalent(&shape, &out.tree, &s, &format!("shape {i}"));
        assert_equivalent(&shape, &flat::tree(&shape), &s[..1], &format!("FLAT {i}"));
    }
    assert!(irreducible > 1_000, "only {irreducible} irreducible shapes");
    assert!(gotos > 100, "only {gotos} trees with a goto");
}

#[test]
fn ac_098b_flat_rate() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x098b);
    let total = 2_000;
    let mut flat = 0;
    for i in 0..total {
        let shape = reducible(&mut rng, 64);
        assert!(irreducible_of(&shape).is_empty(), "shape {i} is reducible");
        let out = structure::run(
            &shape,
            &Opts {
                max_nodes: ghidorah_decomp::DEFAULT_MAX_NODES,
            },
            &mut Fuel::new(1_000_000),
        );
        if matches!(out.mode, Mode::Flat(_)) {
            flat += 1;
        }
        assert_equivalent(
            &shape,
            &out.tree,
            &seeds(&mut rng, 2),
            &format!("shape {i}"),
        );
    }
    assert!(
        flat * 100 <= total,
        "{flat} of {total} shapes fall back to FLAT"
    );
}

#[test]
fn ac_098c_labels_once() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x098c);
    let mut labels = 0;
    for i in 0..3_000 {
        let shape = random(&mut rng, 40);
        for tree in [
            structure::run(&shape, &UNBOUNDED, &mut Fuel::unlimited()).tree,
            flat::tree(&shape),
        ] {
            let list = tree.labels();
            let unique: BTreeSet<_> = list.iter().copied().collect();
            assert_eq!(
                unique.len(),
                list.len(),
                "shape {i}: a label twice:\n{tree:#?}"
            );
            for g in tree.gotos() {
                assert!(unique.contains(&g), "shape {i}: goto {g:?} has no label");
            }
            labels += list.len();
        }
    }
    assert!(labels > 1_000, "only {labels} labels");
}

#[test]
fn ac_075c_structurer_deep_chain() {
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let shape = chain(200_000);
            let out = structure::run(
                &shape,
                &Opts {
                    max_nodes: ghidorah_decomp::DEFAULT_MAX_NODES,
                },
                &mut Fuel::new(10_000_000),
            );
            assert_eq!(out.mode, Mode::Flat(FlatReason::MaxNodes));
            assert_eq!(out.tree.nodes().len(), 200_000);
            let trace = tree_trace(&out.tree, &shape, &Seeded(1), 1_000);
            assert_eq!(trace, cfg_trace(&shape, &Seeded(1), 1_000));
            let big = structure::run(&shape, &UNBOUNDED, &mut Fuel::new(5_000_000));
            match big.mode {
                Mode::Structured => assert_eq!(big.tree.nodes().len(), 200_000),
                Mode::Flat(reason) => assert!(reason.is_budget(), "{reason:?}"),
            }
        })
        .expect("the thread starts");
    handle
        .join()
        .expect("the structurer completes in a 256 KiB stack");
}

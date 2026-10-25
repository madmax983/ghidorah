//! The CFG invariants of design Section 7.4 on every fixture function (AC-083): the T1 and T2
//! ELF fixtures and the PE32+ fixtures.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::cfg;
use ghidorah_db::Program;

use crate::support::{cached, fixtures, pe_paths};

/// Checks the CFG of each function of `p`. Gives the count of functions.
fn check_cfgs(path: &str, p: &Program) -> usize {
    let mut funcs = 0usize;
    for view in p.funcs() {
        funcs += 1;
        let g = cfg::build(p, view.id()).expect("a CFG");
        let found = cfg::check(&g);
        assert!(found.is_empty(), "{path}: {}: {found:?}", view.id());
        let mut seen = BTreeSet::new();
        for block in &g.blocks {
            for (at, _) in &block.insns {
                assert!(seen.insert(*at), "{path}: {at:#x} is in two blocks");
                assert!(view.func.body.contains(*at));
            }
        }
        let units: usize = view
            .func
            .body
            .ranges()
            .iter()
            .map(|r| p.analysis().units_in(*r).count())
            .sum();
        assert_eq!(
            units,
            seen.len(),
            "{path}: {}: each unit is in a block",
            view.id()
        );
    }
    funcs
}

#[test]
fn ac_083_cfg_invariants() {
    let mut paths: Vec<(String, String)> =
        fixtures().into_iter().map(|f| (f.tier, f.path)).collect();
    paths.extend(pe_paths().into_iter().map(|p| ("PE".to_owned(), p)));
    let mut funcs: BTreeMap<&str, usize> = BTreeMap::new();
    for (tier, path) in &paths {
        let n = check_cfgs(path, cached(path));
        *funcs.entry(tier.as_str()).or_default() += n;
    }
    let count = |tier: &str| funcs.get(tier).copied().unwrap_or(0);
    assert!(count("T1") > 1_500, "the T1 functions: {funcs:?}");
    assert!(count("T2") > 3_000, "the T2 functions: {funcs:?}");
    assert!(count("PE") > 40, "the PE functions: {funcs:?}");
}

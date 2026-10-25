//! The pages of the work state (ADR-0031 stage 3): a scheduler with a page store gives the
//! facts of a scheduler without one.

use ghidorah_analysis::pages::{MemStore, PageLimits};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::Fuel;
use ghidorah_db::Program;

use crate::support::{analyze, program};

/// Pages of 256 offsets with room for one loaded page: nearly each read loads a page.
const TINY: PageLimits = PageLimits {
    loaded: 1,
    bits: PageLimits::MIN_BITS,
};

fn hash(program: &Program) -> String {
    program.state_hash().expect("the state hash").to_string()
}

/// Runs `program` with slices of `k` fuel units and a page store. Gives the store writes.
fn paged(program: &mut Program, k: u64) -> u64 {
    let store = MemStore::new();
    let count = store.clone();
    let mut sched = Scheduler::new();
    sched.set_pages(Box::new(store), TINY);
    for _ in 0..1_000_000 {
        let out = sched
            .run(program, Until::Full, &mut Fuel::new(k))
            .expect("a paged slice runs");
        if out.state == RunState::Complete {
            return count.writes();
        }
    }
    panic!("the paged slices make no progress");
}

#[test]
fn pages_do_not_change_the_facts() {
    let fixtures = [
        "fixtures/bin/hello.gcc-O2",
        "fixtures/bin/cold_split.gcc-O2.stripped",
        "fixtures/bin/func_ptrs.clang-O2",
        "fixtures/bin/switch.clang-O2",
        "fixtures/bin/large.gcc-O2",
        "fixtures/bin/noreturn_wrappers.gcc-O0",
    ];
    for path in fixtures {
        let mut whole = program(path);
        let _ = analyze(&mut whole);
        let expect = hash(&whole);
        for k in [u64::MAX, 50] {
            let mut p = program(path);
            let writes = paged(&mut p, k);
            assert_eq!(hash(&p), expect, "{path}: pages and slices of {k}");
            assert!(writes > 1, "{path}: the store takes {writes} pages");
        }
    }
}

#[test]
fn a_restart_keeps_the_page_store() {
    let path = "fixtures/bin/two_helpers.clang-O2.stripped";
    let mut whole = program(path);
    let _ = analyze(&mut whole);
    let store = MemStore::new();
    let count = store.clone();
    let mut p = program(path);
    let mut sched = Scheduler::new();
    sched.set_pages(Box::new(store), TINY);
    let _ = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a paged run");
    let before = count.writes();
    sched.restart(0);
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a paged shadow run");
    assert_eq!(out.state, RunState::Complete);
    assert!(count.writes() > before, "the shadow run uses the store");
    assert_eq!(hash(&p), hash(&whole));
}

/// A rule over the call sites of a function and an owner read load no page. The fallthrough
/// rule read the code unit at each call site, and each owner read loaded the page of its
/// address. The call sites are all over the binary, so nearly each read loaded a page. With
/// pages of 1 KiB and 4 pages in memory, an analysis read about 3,200 pages. The index of the
/// call sites keeps the length of each unit, and the body ranges give the owner. Now the count
/// is near 1,000.
#[test]
fn regress_call_site_reads_load_no_page() {
    for path in ["fixtures/bin/large.gcc-O2", "fixtures/bin/large.clang-O2"] {
        let mut p = program(path);
        let store = MemStore::new();
        let count = store.clone();
        let mut sched = Scheduler::new();
        let limits = PageLimits {
            loaded: 4,
            bits: 10,
        };
        sched.set_pages(Box::new(store), limits);
        let _ = sched
            .run(&mut p, Until::Full, &mut Fuel::unlimited())
            .expect("a paged run");
        let units = u64::try_from(p.analysis().unit_count()).expect("a count");
        let reads = count.reads();
        assert!(
            reads * 7 <= units,
            "{path}: {reads} page reads for {units} code units"
        );
    }
}

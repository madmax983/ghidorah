//! The scheduler: tie breaks, fuel slices, idempotence, shadow runs and the analyzer table
//! (AC-092, AC-093).

use ghidorah_analysis::registry::{ANALYZERS, by_name, index};
use ghidorah_analysis::sched::{pick, unit};
use ghidorah_analysis::{
    AnalyzerId, AnalyzerSpec, BAND_FULL, BAND_SIGNATURES, BAND_TRIAGE, Grain, Mode, RunState,
    Scheduler, Trigger, Until,
};
use ghidorah_base::{Address, Fuel, FuncId, Range};
use ghidorah_db::{Edit, Program, SessionLabel, Source};
use ghidorah_kernel::RangeSet;
use ghidorah_testkit::rng::{SplitMix64, below};

use crate::blobs::Blob;
use crate::support::{analyze, named, program};

fn spec(name: &'static str, priority: u16, grain: Grain) -> AnalyzerSpec {
    AnalyzerSpec {
        id: AnalyzerId::Disasm,
        name,
        priority,
        triggers: &[Trigger::Functions],
        version: 1,
        grain,
        options: &[],
        doc: "A test analyzer.",
    }
}

fn set(ranges: &[(u64, u64)]) -> RangeSet {
    let mut s = RangeSet::new();
    for (a, b) in ranges {
        s.insert(Range::new(*a, *b).expect("a range"));
    }
    s
}

/// Runs `program` with slices of `k` fuel units until the run completes. Gives the runs.
fn sliced(program: &mut Program, k: u64) -> u64 {
    let mut sched = Scheduler::new();
    let mut runs = 0u64;
    loop {
        runs += 1;
        assert!(runs < 1_000_000, "the slices make progress");
        let out = sched
            .run(program, Until::Full, &mut Fuel::new(k))
            .expect("a slice runs");
        if out.state == RunState::Complete {
            assert!(!out.resume);
            return runs;
        }
        assert_eq!(out.state, RunState::BudgetStopped);
        assert!(out.resume);
        assert!(out.steps_used > 0, "each slice makes progress");
    }
}

fn hash(program: &Program) -> String {
    program.state_hash().expect("the state hash").to_string()
}

#[test]
fn sched_tie_break_order() {
    let a = spec("Alpha", 300, Grain::Range);
    let b = spec("Beta", 300, Grain::Whole);
    let low = spec("Zeta", 100, Grain::Whole);
    let specs = [&b, &a, &low];
    let mut pending = vec![
        set(&[(0x20, 0x20), (0x10, 0x10)]),
        set(&[(0x5, 0x5)]),
        RangeSet::new(),
    ];
    assert_eq!(
        pick(&specs, &pending, u16::MAX),
        Some(1),
        "the name breaks the tie"
    );
    assert_eq!(unit(&a, &pending[1]), set(&[(0x5, 0x5)]));
    assert_eq!(
        unit(&a, &pending[0]),
        set(&[(0x10, 0x10)]),
        "the address breaks the tie inside one analyzer"
    );
    assert_eq!(
        unit(&b, &pending[0]),
        pending[0],
        "a whole step takes the set"
    );
    pending[1] = RangeSet::new();
    assert_eq!(pick(&specs, &pending, u16::MAX), Some(0));
    pending[2] = set(&[(0x1, 0x1)]);
    assert_eq!(
        pick(&specs, &pending, u16::MAX),
        Some(2),
        "a lower band runs first"
    );
    assert_eq!(
        pick(&specs, &pending, 99),
        None,
        "the last band stops the pick"
    );

    // The shipped registry runs the seed bands in order, then the lowest entry first.
    let mut p = program("fixtures/bin/noreturn_wrappers.gcc-O2");
    let mut sched = Scheduler::new();
    let mut order = Vec::new();
    let mut disasm = Vec::new();
    while let Some(ran) = sched.step(&p, Until::Full) {
        order.push(ran.analyzer);
        if ran.analyzer == AnalyzerId::Disasm && disasm.len() < 5 {
            disasm.push(ran.ranges.first().expect("a range").first);
        }
        if order.len() > 20 {
            break;
        }
    }
    assert_eq!(
        order.get(..5),
        Some(
            &[
                AnalyzerId::Entry,
                AnalyzerId::Symbols,
                AnalyzerId::ImportStubs,
                AnalyzerId::FdeSeeds,
                AnalyzerId::Overrides
            ][..]
        )
    );
    assert!(
        disasm.len() >= 2 && disasm.windows(2).all(|w| w[0] < w[1]),
        "{disasm:x?}"
    );
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the run ends");
    assert_eq!(out.state, RunState::Complete);
}

#[test]
fn ac_092_fuel_slicing() {
    let fixtures = [
        "fixtures/bin/noreturn_wrappers.gcc-O0",
        "fixtures/bin/hello.gcc-O2",
        "fixtures/bin/two_helpers.clang-O2.stripped",
    ];
    for path in fixtures {
        let mut whole = program(path);
        let (sched, _) = analyze(&mut whole);
        let expect = hash(&whole);
        for k in [1, 7] {
            let mut p = program(path);
            let runs = sliced(&mut p, k);
            assert_eq!(
                hash(&p),
                expect,
                "{path}: slices of {k} give the same state"
            );
            if k == 1 {
                assert!(runs > 10, "{path}: {runs} slices");
            }
        }
        let mut rng = SplitMix64::new(0x92);
        let k = 1 + below(&mut rng, sched.steps_used().max(1));
        let mut p = program(path);
        let _ = sliced(&mut p, k);
        assert_eq!(hash(&p), expect, "{path}: slices of {k}");
    }
    let mut p = program("fixtures/bin/hello.gcc-O2");
    let mut sched = Scheduler::new();
    let first = sched
        .run(&mut p, Until::Full, &mut Fuel::new(1))
        .expect("a slice runs");
    assert_eq!(first.state, RunState::BudgetStopped);
    assert!(
        first.commit.is_some(),
        "the first analysis publishes each slice"
    );
    assert!(!p.analysis().funcs().is_empty(), "reads see a partial set");
}

#[test]
fn ac_093_idempotent() {
    for path in [
        "fixtures/bin/noreturn_wrappers.gcc-O2",
        "fixtures/bin/crackme.clang-O2.stripped",
    ] {
        let mut p = program(path);
        let (mut sched, out) = analyze(&mut p);
        assert!(
            out.commit.is_some_and(|c| !c.noop),
            "{path}: the first run commits"
        );
        let rev = p.rev();
        let events = p.events().len();
        let again = sched
            .run(&mut p, Until::Full, &mut Fuel::unlimited())
            .expect("a second run");
        assert_eq!(again.steps_used, 0);
        assert!(again.commit.is_none_or(|c| c.noop));
        let (_, fresh) = analyze(&mut p);
        assert!(
            fresh.commit.is_none_or(|c| c.noop),
            "{path}: a second full run is a no-op"
        );
        assert_eq!(p.rev(), rev, "{path}: no new revision");
        assert_eq!(p.events().len(), events, "{path}: no change event");
    }
}

#[test]
fn zero_fuel_runs_nothing() {
    let mut p = program("fixtures/bin/hello.gcc-O2");
    let mut sched = Scheduler::new();
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::new(0))
        .expect("a run");
    assert_eq!(out.steps_used, 0);
    assert_eq!(out.state, RunState::BudgetStopped);
    assert!(out.commit.is_none());
    assert_eq!(p.rev().0, 0);
    let rows = sched.rows();
    assert_eq!(rows.len(), ANALYZERS.len());
    let entry = rows.first().expect("a row");
    assert_eq!((entry.name, entry.priority, entry.runs), ("Entry", 100, 0));
    assert!(
        entry.pending > 0,
        "a fresh run gives the seed analyzers work"
    );
}

#[test]
fn rows_count_runs_and_pending() {
    let mut p = program("fixtures/bin/hello.gcc-O2");
    let (sched, out) = analyze(&mut p);
    assert_eq!(sched.steps_used(), out.steps_used);
    let rows = sched.rows();
    assert!(rows.iter().all(|r| r.pending == 0));
    let disasm = rows.iter().find(|r| r.name == "Disasm").expect("a row");
    assert!(disasm.runs > 1);
    let names: Vec<&str> = rows.iter().map(|r| r.name).collect();
    let specs: Vec<&str> = ANALYZERS.iter().map(|s| s.name).collect();
    assert_eq!(names, specs);
}

#[test]
fn triage_and_full_bands() {
    assert_eq!(Until::Triage.last_band(), BAND_TRIAGE);
    assert_eq!(Until::Full.last_band(), u16::MAX);
    let mut p = program("fixtures/bin/two_helpers.gcc-O2");
    let mut full = program("fixtures/bin/two_helpers.gcc-O2");
    let _ = analyze(&mut full);
    let mut sched = Scheduler::new();
    let out = sched
        .run(&mut p, Until::Triage, &mut Fuel::unlimited())
        .expect("a triage run");
    assert!(sched.is_done(Until::Triage));
    assert_eq!(
        out.state,
        RunState::BudgetStopped,
        "bands 800 and 810 wait for a full run"
    );
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a full run");
    assert_eq!(out.state, RunState::Complete);
    assert_eq!(hash(&p), hash(&full));
}

/// Sets an agent noreturn flag on the function at `entry`.
fn agent_noreturn(p: &mut Program, entry: u64) {
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("test", Source::Agent, label)
        .expect("a transaction");
    let flag = tx.fact(true);
    tx.apply(Edit::SetNoreturn {
        id: FuncId(Address::ram(entry)),
        noreturn: Some(flag),
    })
    .expect("the flag applies");
    tx.commit().expect("the commit works");
}

#[test]
fn shadow_publishes_once_at_completion() {
    let mut p = program("fixtures/bin/noreturn_wrappers.gcc-O2");
    let _ = analyze(&mut p);
    let check = named(&p, "check_args");
    agent_noreturn(&mut p, check);
    let committed = p.analysis().clone();
    let rev = p.rev();
    let mut shadow = Scheduler::shadow();
    assert_eq!(shadow.mode(), Mode::Shadow);
    let mut commits = 0;
    loop {
        let out = shadow
            .run(&mut p, Until::Full, &mut Fuel::new(5))
            .expect("a shadow slice");
        if out.state == RunState::Complete {
            commits += usize::from(out.commit.is_some_and(|c| !c.noop));
            break;
        }
        assert_eq!(out.state, RunState::Stale);
        assert!(out.commit.is_none());
        assert_eq!(p.analysis(), &committed, "reads see the committed set");
        assert_eq!(p.rev(), rev);
    }
    assert_eq!(commits, 1, "one ReplaceAnalysis commit swaps the shadow in");
    assert_eq!(p.rev().0, rev.0 + 1);
    assert_ne!(
        p.analysis(),
        &committed,
        "the agent flag changes the analysis"
    );
    let mut fresh = program("fixtures/bin/noreturn_wrappers.gcc-O2");
    let _ = analyze(&mut fresh);
    agent_noreturn(&mut fresh, check);
    let _ = analyze(&mut fresh);
    assert_eq!(
        p.analysis(),
        fresh.analysis(),
        "the shadow equals a fresh run"
    );
}

#[test]
fn restart_keeps_the_lower_bands() {
    let mut p = Blob::new().call(0x10).ret().at(0x10).ret().load(Some(0));
    let (mut sched, _) = analyze(&mut p);
    sched.restart(BAND_SIGNATURES);
    assert_eq!(sched.mode(), Mode::Shadow);
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a restart");
    assert_eq!(out.state, RunState::Complete);
    assert!(
        out.steps_used > 0,
        "CallingConvention and Syscalls run again from band 800"
    );
    sched.restart(BAND_FULL);
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a full restart");
    assert!(out.steps_used > 0);
    assert!(
        out.commit.is_none_or(|c| c.noop),
        "the same inputs give the same set"
    );
    assert_eq!(sched.mode(), Mode::Shadow);
}

#[test]
fn registry_follows_section_7_1() {
    let priorities: Vec<u16> = ANALYZERS.iter().map(|s| s.priority).collect();
    assert_eq!(
        priorities,
        [
            100, 110, 120, 150, 160, 300, 301, 302, 400, 410, 420, 430, 440, 450, 460, 600, 650,
            700, 800, 810
        ]
    );
    for (i, s) in ANALYZERS.iter().enumerate() {
        assert_eq!(index(s.id), Some(i));
        assert_eq!(by_name(s.name).map(|x| x.id), Some(s.id));
        assert!(!s.doc.is_empty() && s.version > 0);
        assert!(
            !s.listens(Trigger::Signatures) || s.priority >= BAND_SIGNATURES,
            "only bands 800 and above read signatures (AC-210)"
        );
        for o in s.options {
            assert_eq!(s.option(o.name), Some(o.value));
        }
    }
    assert!(by_name("Nothing").is_none());
    let names: Vec<&str> = Trigger::ALL.iter().map(|t| t.name()).collect();
    assert_eq!(
        names,
        [
            "bytes",
            "instructions",
            "functions",
            "function_modifiers",
            "signatures",
            "data"
        ]
    );
    assert_eq!(RunState::Stale.name(), "stale");
}

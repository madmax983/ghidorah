//! Allocation bounds of the scaling paths of the analysis.
//!
//! This binary installs the counting allocator of `ghidorah-oracle`. Each test counts the
//! bytes that one path allocates for an input of size `n` and of size `2 n`. The count of
//! a fixed input is the same on each run, so the tests use no clock. A linear path allocates
//! about twice the bytes for twice the input. A path that copies its state on each step
//! allocates about four times the bytes.
//!
//! The memory tests count the bytes that a result keeps, for each record or code unit.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]

use ghidorah_analysis::analyzers::gaps;
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Fuel, Limits};
use ghidorah_db::Program;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_oracle::alloc::CountingAlloc;
use ghidorah_testkit::elf::{ElfBuilder, Fde, Loc, Section, Symbol};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

/// The code of one small frame-pointer function and its padding.
const BODY: [u8; 16] = [
    0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

/// Builds an ELF with `n` small functions. Each function has an FDE. With `symbols`, each
/// function also has a function symbol over its padding.
fn functions(n: u64, symbols: bool) -> Program {
    let text: Vec<u8> = (0..n).flat_map(|_| BODY).collect();
    let mut elf = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .entry(Loc::section(".text", 0));
    for i in 0..n {
        elf = elf.fde(Fde::frame_pointer(Loc::section(".text", i * 16), 6));
        if symbols {
            let at = Loc::section(".text", i * 16 + 8);
            elf = elf.symbol(Symbol::func(&format!("f{i}"), at, 2));
        }
    }
    let (binary, mem) = load(&elf.build(), &LoadOpts::AUTO, &Limits::DEFAULT).expect("a load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("a program")
}

/// Asserts that twice the input allocates at most 2.5 times the bytes.
fn assert_linear(what: &str, small: u64, large: u64) {
    assert!(
        large * 2 <= small * 5,
        "{what}: twice the input allocates {large} bytes, not about 2 x {small}"
    );
}

/// The owned set of the gaps goes in by start. Each function symbol went in after all FDEs,
/// in the middle of the set, and copied the tail of the set.
#[test]
fn regress_gap_sets_allocate_linearly() {
    let bytes = |n: u64| {
        let program = functions(n, true);
        let (items, stats) = ALLOC.measure(|| gaps::items(&program));
        assert!(items.len() < 2, "the FDEs and symbols own the code");
        stats.allocated_bytes
    };
    assert_linear("gaps::items", bytes(10_000), bytes(20_000));
}

/// A full analysis allocates in step with its functions. Two fixes keep it so:
///
/// - A step puts its event ranges in the inbox of each listener. A union for each event
///   copied the whole pending set of the listener.
/// - A step of `Disasm` takes the first range of a mirrored pending set, so it removes the
///   last stored entry. A take from the front copied all other entries.
#[test]
fn regress_analysis_allocates_linearly() {
    let bytes = |n: u64| {
        let mut program = functions(n, false);
        let (out, stats) = ALLOC.measure(|| {
            Scheduler::new()
                .run(&mut program, Until::Full, &mut Fuel::new(u64::MAX))
                .expect("a run")
        });
        assert_eq!(out.state, RunState::Complete);
        stats.allocated_bytes
    };
    assert_linear("a full analysis", bytes(5_000), bytes(10_000));
}

/// A `ReplaceAnalysis` commit shares the new set between the program and the log of the
/// transaction. A copy of the set for the program allocated as many bytes as the set.
#[test]
fn regress_replace_analysis_shares_the_set() {
    use std::sync::Arc;

    use ghidorah_db::{Edit, SessionLabel, Source};

    let mut analyzed = functions(2_000, false);
    Scheduler::new()
        .run(&mut analyzed, Until::Full, &mut Fuel::new(u64::MAX))
        .expect("a run");
    let (set, copy) = ALLOC.measure(|| analyzed.analysis().clone());
    let mut fresh = functions(2_000, false);
    let label = SessionLabel::new(SessionLabel::ANALYSIS).expect("a label");
    let mut tx = fresh
        .begin("analysis", Source::Analysis, label)
        .expect("a transaction");
    let edit = Edit::ReplaceAnalysis(Arc::new(set));
    let (applied, swap) = ALLOC.measure(|| tx.apply(edit));
    applied.expect("the edit applies");
    assert!(
        swap.allocated_bytes * 10 < copy.allocated_bytes,
        "the swap allocates {} bytes; a copy of the set is {} bytes",
        swap.allocated_bytes,
        copy.allocated_bytes
    );
}

/// Runs a full analysis of `n` small functions. Gives the program, the bytes that the
/// published set keeps and the bytes that the work state of the scheduler keeps.
fn kept_bytes(n: u64) -> (Program, usize, usize) {
    let run = |program: &mut Program| {
        let mut sched = Scheduler::new();
        let out = sched
            .run(program, Until::Full, &mut Fuel::new(u64::MAX))
            .expect("a run");
        assert_eq!(out.state, RunState::Complete);
        sched
    };
    let mut program = functions(n, false);
    let (sched, both) = ALLOC.measure(|| run(&mut program));
    drop(sched);
    let mut again = functions(n, false);
    let ((), set) = ALLOC.measure(|| drop(run(&mut again)));
    let work = both.retained_bytes.saturating_sub(set.retained_bytes);
    (program, set.retained_bytes, work)
}

/// The work state keeps the owner of each code unit, not its why-record. The record of a
/// unit is always `R_DISASM_FLOW` with the owner function, so the publish step makes it.
/// A copy in each unit kept 459 bytes of work state for each unit; now 344.
#[test]
fn regress_work_state_keeps_no_unit_why() {
    let (program, _, work) = kept_bytes(5_000);
    let units = program.analysis().listing().unit_count();
    assert!(
        work <= units * 400,
        "the work state keeps {work} bytes for {units} code units"
    );
}

/// The why store builds its tree in one pass from rows in key order, and the records of one
/// rule share the text of its code. One insert at a time left each node about half full, and
/// each record kept its own copy of the code: 279 bytes for each record; now 162.
#[test]
fn regress_why_store_packs_its_records() {
    use ghidorah_db::codec::{SetRows, tables_from_rows};
    use ghidorah_db::{FactKey, RuleCode, Why};

    let n = 20_000u64;
    let rule = RuleCode::new("R_DISASM_FLOW").expect("a rule code");
    let (tables, stats) = ALLOC.measure(|| {
        let why = (0..n)
            .map(|i| {
                let record = Why {
                    rule: rule.clone(),
                    premises: vec![FactKey::Entry(0)],
                };
                (FactKey::CodeUnit(i * 4), i, record)
            })
            .collect();
        let rows = SetRows {
            why,
            why_next: n,
            ..SetRows::default()
        };
        tables_from_rows(rows).expect("the rows")
    });
    let records = tables.why().len();
    assert_eq!(records, 20_000);
    assert!(
        stats.retained_bytes <= records * 200,
        "the store keeps {} bytes for {records} records",
        stats.retained_bytes
    );
}

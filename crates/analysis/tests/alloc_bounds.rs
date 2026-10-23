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

/// The why store builds its tree in one pass from rows in key order. The records of one rule
/// share the text of its code. One insert at a time left each node about half full. Each
/// record also kept its own copy of the code. The store kept 279 bytes for each record; now 162.
#[test]
fn regress_why_store_packs_its_records() {
    use ghidorah_db::codec::{SetRows, tables_from_rows};
    use ghidorah_db::{FactKey, RuleCode, Why, WhyRows};

    let n = 20_000u64;
    let rule = RuleCode::new("R_DISASM_FLOW").expect("a rule code");
    let (tables, stats) = ALLOC.measure(|| {
        let why = WhyRows::from_rows((0..n).map(|i| {
            let record = Why {
                rule: rule.clone(),
                premises: vec![FactKey::Entry(0)],
            };
            (FactKey::CodeUnit(i * 4), record)
        }))
        .expect("the rows");
        let rows = SetRows {
            why,
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

/// The publish step keeps the premises of each record in the list of the record. A filtered
/// copy of each list reserved room for four keys: 446 bytes of set for each record; now 278.
#[test]
fn regress_published_set_keeps_exact_premise_lists() {
    let (program, set, _) = kept_bytes(5_000);
    let records = program.analysis().why().len();
    assert!(
        set <= records * 350,
        "the published set keeps {set} bytes for {records} records"
    );
}

/// The project writes a snapshot to its file one piece at a time. Before, the text of the
/// whole snapshot was one string, and its growth held up to two copies of the text. The
/// encoder peaks far below the length of the text.
#[test]
fn regress_snapshot_streams_its_text() {
    let (program, _, _) = kept_bytes(5_000);
    let (len, stats) = ALLOC.measure(|| {
        let mut len = 0usize;
        ghidorah_db::snapshot::encode_to(&program, 0, None, &mut |piece| len += piece.len())
            .expect("a JCS text");
        len
    });
    assert!(
        stats.peak_bytes * 10 < len,
        "the encoder peaks at {} bytes for a text of {len} bytes",
        stats.peak_bytes
    );
}

/// The why store keeps two record shapes as compact values with no premise list. One is a
/// code unit with its owner function. The other is a reference with the code unit of its
/// source. A general record with a list kept 162 bytes for each record; now 50.
#[test]
fn regress_why_store_keeps_derived_premises_compact() {
    use ghidorah_base::{Address, FuncId};
    use ghidorah_db::codec::{SetRows, tables_from_rows};
    use ghidorah_db::{FactKey, RefKey, RefType, RuleCode, Why, WhyRows};

    let n = 20_000u64;
    let flow = RuleCode::new("R_DISASM_FLOW").expect("a rule code");
    let refer = RuleCode::new("R_FLOW_REF").expect("a rule code");
    let (tables, stats) = ALLOC.measure(|| {
        let units = (0..n).map(|i| {
            let owner = FactKey::Func(FuncId(Address::ram(i / 8 * 32)));
            let record = Why {
                rule: flow.clone(),
                premises: vec![owner],
            };
            (FactKey::CodeUnit(i * 4), record)
        });
        let refs = (0..n).map(|i| {
            let key = RefKey {
                from: Address::ram(i * 4),
                op_index: -1,
                to: Address::ram(0x1000),
                kind: RefType::UnconditionalCall,
            };
            let record = Why {
                rule: refer.clone(),
                premises: vec![FactKey::CodeUnit(i * 4)],
            };
            (FactKey::Ref(key), record)
        });
        let rows = SetRows {
            why: WhyRows::from_rows(units.chain(refs)).expect("the rows"),
            ..SetRows::default()
        };
        tables_from_rows(rows).expect("the rows")
    });
    let records = tables.why().len();
    assert_eq!(records, 40_000);
    assert!(
        stats.retained_bytes <= records * 64,
        "the store keeps {} bytes for {records} records",
        stats.retained_bytes
    );
}

/// The publish step keeps the derived why-records of code units and references as compact
/// values. It packs the rows of the set as they come. Before, a map of full records and a
/// list of full rows raised the peak. A full analysis peaked at 895 bytes for each code
/// unit. The steps after that gave 811 (compact records), 762 (the collection goes before
/// the tables grow) and 736 (no creation order in a record).
#[test]
fn regress_publish_keeps_derived_whys_compact() {
    let mut program = functions(5_000, false);
    let ((), stats) = ALLOC.measure(|| {
        Scheduler::new()
            .run(&mut program, Until::Full, &mut Fuel::new(u64::MAX))
            .map(drop)
            .expect("a run");
    });
    let units = program.analysis().listing().unit_count();
    assert!(
        stats.peak_bytes <= units * 765,
        "a full analysis peaks at {} bytes for {units} code units",
        stats.peak_bytes
    );
}

/// The code of one frame-pointer function that calls the next function, and its padding.
const CALLER: [u8; 16] = [
    0x55, 0x48, 0x89, 0xe5, 0xe8, 0x07, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

/// Gives the bytes that the set and the work state keep after a full analysis of `program`.
fn kept_after_run(mut program: Program) -> (Program, usize) {
    let (sched, stats) = ALLOC.measure(|| {
        let mut sched = Scheduler::new();
        sched
            .run(&mut program, Until::Full, &mut Fuel::new(u64::MAX))
            .expect("a run");
        sched
    });
    drop(sched);
    (program, stats.retained_bytes)
}

/// The work state keeps each flow and operand reference as a key. The why-record of such a
/// reference is its rule with the code unit at its source, so the publish step makes it.
/// The bytes of one call are the bytes of `n` functions with a call each, less the bytes of
/// `n` functions with no call. A call kept 1,542 bytes with a full record; now 1,428.
#[test]
fn regress_work_state_keeps_reference_keys_only() {
    let n = 5_000u64;
    let text: Vec<u8> = (0..n).flat_map(|_| CALLER).collect();
    let mut elf = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .entry(Loc::section(".text", 0));
    for i in 0..n {
        elf = elf.fde(Fde::frame_pointer(Loc::section(".text", i * 16), 11));
    }
    let (binary, mem) = load(&elf.build(), &LoadOpts::AUTO, &Limits::DEFAULT).expect("a load");
    let callers = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("a program");
    let (callers, with_calls) = kept_after_run(callers);
    let (_, plain) = kept_after_run(functions(n, false));
    let refs = callers.analysis().refs().iter().count();
    assert!(
        refs >= 4_999,
        "each call but the last has a reference: {refs}"
    );
    let per_call = with_calls.saturating_sub(plain) / refs;
    assert!(per_call <= 1_480, "a call keeps {per_call} bytes");
}

/// The reference table and the listing of a new set take their rows in one bulk build each.
/// One insert at a time in key order left each node about half full. A unit and a reference
/// kept 328 bytes; now 177.
#[test]
fn regress_set_tables_build_full_nodes() {
    use ghidorah_base::Address;
    use ghidorah_db::codec::{SetRows, tables_from_rows};
    use ghidorah_db::listing::{CodeUnit, FlowKind};
    use ghidorah_db::{Origin, Ref, RefKey, RefType};

    let n = 20_000u64;
    let origin = Origin::analysis();
    let (tables, stats) = ALLOC.measure(|| {
        let unit = CodeUnit::Insn {
            len: 4,
            flow: FlowKind::Call,
            flags: 0,
        };
        let key = |i: u64| RefKey {
            from: Address::ram(i * 4),
            op_index: -1,
            to: Address::ram(0x10_0000),
            kind: RefType::UnconditionalCall,
        };
        let rows = SetRows {
            units: (0..n).map(|i| (i * 4, unit)).collect(),
            refs: (0..n)
                .map(|i| {
                    origin.fact(Ref {
                        key: key(i),
                        primary: true,
                    })
                })
                .collect(),
            ..SetRows::default()
        };
        tables_from_rows(rows).expect("the rows")
    });
    assert_eq!(tables.refs().len(), 20_000);
    assert!(
        stats.retained_bytes <= 20_000 * 250,
        "the tables keep {} bytes for 20,000 units and references",
        stats.retained_bytes
    );
}

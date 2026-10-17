//! Fuzz target `journal_replay` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. Each case parses the input
//! as a journal and replays its lines into a fresh program. A case gives lines, a
//! `JOURNAL_CORRUPT` error or a replay error, and never a panic. A replay error leaves the
//! program state of the lines before the bad line.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::{Address, Limits};
use ghidorah_db::journal::{self, Line, TxLine};
use ghidorah_db::meta::MetaLine;
use ghidorah_db::{Edit, FuncProgress, History, Program, SessionLabel, Source, SymKind, replay};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. Stage 1: the journal parses. Stage 2: the lines replay.
const STAGES: [&str; 3] = ["input", "parsed", "replayed"];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/journal_replay")
}

fn program() -> Program {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bin/crackme.gcc-O2");
    let bytes = std::fs::read(path).expect("the fixture");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("the program")
}

/// Gives a journal text with renames, a meta line and an undo line.
fn corpus(start: &Program) -> Vec<Vec<u8>> {
    let mut p = start.clone();
    let mut text = Vec::new();
    for (i, addr) in [0x1090, 0x1094, 0x1090].into_iter().enumerate() {
        let label = SessionLabel::new("mcp-1").expect("a label");
        let mut tx = p
            .begin("symbol_rename", Source::Agent, label)
            .expect("a tx");
        let fact = tx.fact(format!("name{i}"));
        tx.apply(Edit::SetName {
            addr: Address::ram(addr),
            key: None,
            kind: SymKind::Label,
            primary: true,
            name: Some(fact),
            evidence: vec!["fn:0x1080".to_owned()],
        })
        .expect("the edit");
        let line = TxLine::of_commit(&tx.commit().expect("the commit"));
        text.extend_from_slice(journal::encode(&Line::Tx(Box::new(line))).as_bytes());
        text.push(b'\n');
    }
    let meta = MetaLine::Progress {
        func: ghidorah_base::FuncId(Address::ram(0x1080)),
        row: FuncProgress {
            visited: true,
            ..FuncProgress::default()
        },
    };
    text.extend_from_slice(journal::encode(&Line::Meta(meta)).as_bytes());
    text.push(b'\n');
    vec![text]
}

fn target(start: &Program, input: &[u8]) -> Outcome {
    let Ok(parsed) = journal::parse(input) else {
        return Outcome::reached(0);
    };
    let mut p = start.clone();
    let mut history = History::new();
    match replay::replay(&mut p, &parsed.lines, 0, &mut history) {
        Ok(_) => {
            if p.check_invariants().is_empty() {
                Outcome::reached(2)
            } else {
                Outcome::violation(2, "a replay breaks an invariant".to_owned())
            }
        }
        Err(_) => Outcome::reached(1),
    }
}

#[test]
fn fuzz_journal_replay() {
    let start = program();
    let corpus = corpus(&start);
    let seed = journal::parse(corpus.first().expect("a corpus input")).expect("the seed parses");
    assert_eq!(seed.lines.len(), 4, "the seed journal has four lines");
    let run = |input: &[u8]| target(&start, input);
    let replay = fuzz::replay_regress(&regress_dir(), run)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);
    let mut config = Config::new("journal_replay", 600);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 16_384;
    config.stack_size = 8 * 1024 * 1024;
    let report =
        fuzz::run(&config, &corpus, run).unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 600);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(report.reached[2] > 0, "replay share: {:?}", report.reached);
}

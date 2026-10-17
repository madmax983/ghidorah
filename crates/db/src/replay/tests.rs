//! Tests of replay: exact commits, run markers, meta folds and bad lines.

use ghidorah_base::{Address, FuncId, Rev, TxId};

use super::{apply_tx, replay};
use crate::edit::Edit;
use crate::history::History;
use crate::journal::{Line, RunLine, RunState, TxLine};
use crate::meta::MetaLine;
use crate::progress::FuncProgress;
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::{seeded, session};

fn rename_line(p: &mut crate::program::Program, addr: u64) -> TxLine {
    let mut tx = p.begin("t", Source::Agent, session("mcp-1")).unwrap();
    let fact = tx.fact("x".to_string());
    tx.apply(Edit::SetName {
        addr: Address::ram(addr),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: Vec::new(),
    })
    .unwrap();
    TxLine::of_commit(&tx.commit().unwrap())
}

#[test]
fn replay_applies_lines_after_the_skip() {
    let start = seeded();
    let mut live = start.clone();
    let first = rename_line(&mut live, 0x1084);
    let second = rename_line(&mut live, 0x1088);
    let func = FuncId(Address::ram(0x1080));
    let lines = vec![
        Line::Tx(Box::new(first.clone())),
        Line::Meta(MetaLine::Progress {
            func,
            row: FuncProgress {
                visited: true,
                ..FuncProgress::default()
            },
        }),
        Line::Tx(Box::new(second)),
        Line::Run(RunLine {
            rev: Rev(3),
            tx: TxId(3),
            state: RunState::Complete,
            inputs_hash: [0; 32],
            fuel_used: 1,
            result_hash: [0; 32],
        }),
    ];
    let mut p = start.clone();
    let mut h = History::new();
    let out = replay(&mut p, &lines, 0, &mut h).unwrap();
    assert_eq!(out.applied, 4);
    assert!(out.behind);
    assert_eq!(p.rev(), Rev(3));
    assert!(p.progress().get(func).visited);
    assert_eq!(h.entries().count(), 3);
    // A skip of the first line: the snapshot covers it.
    let mut covered = start.clone();
    apply_tx(&mut covered, &first).unwrap();
    let mut h = History::new();
    let out = replay(&mut covered, &lines, 1, &mut h).unwrap();
    assert_eq!(out.applied, 3);
    assert_eq!(h.entries().count(), 3, "the history holds all lines");
    assert_eq!(covered.state_hash(), p.state_hash());
}

#[test]
fn replay_refuses_a_wrong_rev() {
    let start = seeded();
    let mut live = start.clone();
    let mut line = rename_line(&mut live, 0x1084);
    line.rev = Rev(5);
    let mut p = start.clone();
    let error = replay(&mut p, &[Line::Tx(Box::new(line))], 0, &mut History::new()).unwrap_err();
    assert_eq!(error.line, 1);
    assert_eq!(p.state_hash(), start.state_hash());
    let mut live = start.clone();
    let mut wrong = rename_line(&mut live, 0x1084);
    wrong.edits[0].inverse = wrong.edits[0].edit.clone();
    let mut p = start.clone();
    assert!(apply_tx(&mut p, &wrong).is_err(), "the inverse must match");
}

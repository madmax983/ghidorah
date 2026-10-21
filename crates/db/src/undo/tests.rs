//! Tests of undo and redo: the clone-stack model (AC-116a, AC-116b), the session stack cases
//! (AC-116c) and the selective undo conflict (AC-116d).

use std::cell::RefCell;

use ghidorah_base::{Address, ErrorCode, Rev, TxId};
use ghidorah_testkit::pbt::check;

use super::{UndoError, UndoRequest, run};
use crate::edit::{Edit, EditKind};
use crate::hash::StateHash;
use crate::history::{EntryState, History, Scope};
use crate::journal::TxLine;
use crate::program::Program;
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::ops::{Pools, analysis_edit, base_edit};
use crate::tests::{analysis_set, func_type, seeded, session};

fn hash(p: &Program) -> StateHash {
    p.state_hash().unwrap()
}

/// Commits one rename of `addr` to `name` in `session` and records it.
fn rename(p: &mut Program, h: &mut History, session_name: &str, addr: u64, name: &str) -> TxId {
    let mut tx = p
        .begin("symbol_rename", Source::Agent, session(session_name))
        .unwrap();
    let fact = tx.fact(name.to_string());
    tx.apply(Edit::SetName {
        addr: Address::ram(addr),
        key: None,
        kind: SymKind::Function,
        primary: true,
        name: Some(fact),
        evidence: Vec::new(),
    })
    .unwrap();
    let commit = tx.commit().unwrap();
    h.record(&TxLine::of_commit(&commit));
    commit.tx
}

/// Gives an undo request of `scope` for one entry.
fn request(scope: Scope, redo: bool) -> UndoRequest {
    UndoRequest {
        scope,
        tx: None,
        count: 1,
        redo,
        force: true,
        dry_run: false,
        source: Source::Agent,
        session: session("mcp-1"),
    }
}

fn of(name: &str) -> Scope {
    Scope::Session(session(name))
}

/// Runs a request and records its commit.
fn apply(p: &mut Program, h: &mut History, req: &UndoRequest) -> Result<Vec<TxId>, UndoError> {
    let out = run(p, h, req)?;
    if let Some(line) = &out.line {
        h.record(line);
    }
    Ok(out.entries)
}

/// One step of the model: the hashes before and after one original commit.
struct Step {
    before: StateHash,
    after: StateHash,
}

/// Runs the random undo and redo model of AC-116a with its fixed seed. Each sequence commits
/// random edits, undoes all of them and redoes all of them. Each step must give the state hash
/// before or after its commit. Returns the number of applied edits of each kind of
/// [`EditKind::ALL`] over all the sequences.
fn undo_redo_model() -> [usize; 15] {
    let mut start = seeded();
    let fn_type = func_type(&mut start);
    let pools = Pools::of(&start, fn_type);
    let sets = [analysis_set(&start, 0), analysis_set(&start, 1)];
    let counts = RefCell::new([0usize; 15]);
    check("ac_116a_undo_redo_model", 64, |g| {
        let mut p = start.clone();
        let mut h = History::new();
        let mut steps: Vec<Step> = Vec::new();
        let one_session = g.bool();
        let commands = 1 + g.draw(50);
        for _ in 0..commands {
            let (source, name) = match (one_session, g.draw(5)) {
                (false, 0) => (Source::User, "cli"),
                (false, 1) => (Source::Analysis, "analysis"),
                (false, 2) => (Source::Agent, "mcp-2"),
                _ => (Source::Agent, "mcp-1"),
            };
            let before = hash(&p);
            let mut tx = p.begin("model", source, session(name)).unwrap();
            for _ in 0..=g.draw(3) {
                let edit = if source == Source::Analysis {
                    analysis_edit(g, &sets)
                } else {
                    let kind = g.draw(14);
                    base_edit(g, &tx, &pools, kind)
                };
                let _ = tx.apply(edit);
            }
            let commit = tx.commit().map_err(|e| e.to_string())?;
            if commit.noop {
                continue;
            }
            for a in &commit.edits {
                let i = EditKind::ALL
                    .iter()
                    .position(|k| *k == a.edit.kind())
                    .unwrap_or(0);
                counts.borrow_mut()[i] += 1;
            }
            h.record(&TxLine::of_commit(&commit));
            steps.push(Step {
                before,
                after: hash(&p),
            });
        }
        let scope = if one_session { of("mcp-1") } else { Scope::All };
        for (i, step) in steps.iter().enumerate().rev() {
            apply(&mut p, &mut h, &request(scope.clone(), false))
                .map_err(|e| format!("undo {i}: {e}"))?;
            if hash(&p) != step.before {
                return Err(format!("undo {i} does not give the state before"));
            }
        }
        match run(&mut p, &h, &request(scope.clone(), false)) {
            Err(UndoError::NothingToUndo) => {}
            other => return Err(format!("a full undo leaves entries: {other:?}")),
        }
        for (i, step) in steps.iter().enumerate() {
            apply(&mut p, &mut h, &request(scope.clone(), true))
                .map_err(|e| format!("redo {i}: {e}"))?;
            if hash(&p) != step.after {
                return Err(format!("redo {i} does not give the state after"));
            }
        }
        match run(&mut p, &h, &request(scope, true)) {
            Err(UndoError::NothingToRedo) => Ok(()),
            other => Err(format!("a full redo leaves entries: {other:?}")),
        }
    });
    counts.into_inner()
}

/// Makes sure that each edit kind occurs at least 20 times in `counts`.
fn assert_coverage(counts: &[usize; 15]) {
    for (kind, n) in EditKind::ALL.iter().zip(counts) {
        assert!(*n >= 20, "{kind} occurs {n} times");
    }
}

#[test]
fn ac_116a_undo_redo_model() {
    let counts = undo_redo_model();
    assert_coverage(&counts);
}

#[test]
fn ac_116b_edit_coverage() {
    // The coverage is over the random undo and redo sequences of AC-116a.
    let counts = undo_redo_model();
    assert_coverage(&counts);
}

#[test]
fn ac_116c_session_stack_cases() {
    let mut p = seeded();
    let mut h = History::new();
    let start = hash(&p);
    // Undo, undo: each undo reverts the next entry of the session, in reverse order.
    let a1 = rename(&mut p, &mut h, "mcp-1", 0x1084, "alpha");
    let after_a1 = hash(&p);
    let a2 = rename(&mut p, &mut h, "mcp-1", 0x1088, "beta");
    assert_eq!(
        apply(&mut p, &mut h, &request(of("mcp-1"), false)),
        Ok(vec![a2])
    );
    assert_eq!(hash(&p), after_a1);
    assert_eq!(
        apply(&mut p, &mut h, &request(of("mcp-1"), false)),
        Ok(vec![a1])
    );
    assert_eq!(hash(&p), start);
    // Redo, undo: a redo re-applies the most recently undone entry first.
    assert_eq!(
        apply(&mut p, &mut h, &request(of("mcp-1"), true)),
        Ok(vec![a1])
    );
    assert_eq!(hash(&p), after_a1);
    assert_eq!(
        apply(&mut p, &mut h, &request(of("mcp-1"), false)),
        Ok(vec![a1])
    );
    assert_eq!(hash(&p), start);
    // Edit after undo: a new original transaction ends the redo chain of the session.
    let a3 = rename(&mut p, &mut h, "mcp-1", 0x108c, "gamma");
    assert_eq!(
        run(&mut p, &h, &request(of("mcp-1"), true)).map(|o| o.entries),
        Err(UndoError::NothingToRedo)
    );
    // Cross-session: the undo of a session never reverts an entry of another session.
    let b1 = rename(&mut p, &mut h, "mcp-2", 0x1094, "delta");
    assert_eq!(
        apply(&mut p, &mut h, &request(of("mcp-1"), false)),
        Ok(vec![a3])
    );
    assert_eq!(h.entry(b1).map(|e| e.state), Some(EntryState::Applied));
    assert_eq!(
        apply(&mut p, &mut h, &request(of("mcp-2"), false)),
        Ok(vec![b1])
    );
    assert_eq!(h.entry(a2).map(|e| e.state), Some(EntryState::Undone));
    // A session with no applied entry gives NOTHING_TO_UNDO. The wide scope sees the others.
    let none = run(&mut p, &h, &request(of("mcp-2"), false));
    assert_eq!(none.map(|o| o.entries), Err(UndoError::NothingToUndo));
    let mut count = request(Scope::All, true);
    count.count = 3;
    let redone = apply(&mut p, &mut h, &count).unwrap();
    assert_eq!(redone.len(), 2, "{redone:?}");
    // An agent undo of a user transaction needs force.
    let mut tx = p
        .begin("comment_set", Source::User, session("cli"))
        .unwrap();
    let text = tx.fact("from a human".to_string());
    tx.apply(Edit::SetComment {
        addr: Address::ram(0x1080),
        kind: crate::comments::CommentKind::Eol,
        text: Some(text),
    })
    .unwrap();
    let commit = tx.commit().unwrap();
    h.record(&TxLine::of_commit(&commit));
    let mut agent = request(of("cli"), false);
    agent.force = false;
    let refused = run(&mut p, &h, &agent).map(|o| o.entries);
    assert_eq!(refused, Err(UndoError::UserTx(commit.tx)));
    assert_eq!(
        refused.unwrap_err().code(),
        ErrorCode::BlockedByHigherPrioritySource
    );
    agent.force = true;
    assert_eq!(apply(&mut p, &mut h, &agent), Ok(vec![commit.tx]));
}

#[test]
fn ac_116d_selective_undo_conflict() {
    let mut p = seeded();
    let mut h = History::new();
    let t1 = rename(&mut p, &mut h, "mcp-1", 0x1084, "alpha");
    let t2 = rename(&mut p, &mut h, "mcp-2", 0x1084, "beta");
    let t3 = rename(&mut p, &mut h, "mcp-2", 0x108c, "gamma");
    let t4 = rename(&mut p, &mut h, "mcp-1", 0x1084, "delta");
    let before = hash(&p);
    let mut req = request(Scope::All, false);
    req.tx = Some(t1);
    let found = run(&mut p, &h, &req).map(|o| o.entries);
    assert_eq!(
        found,
        Err(UndoError::Conflict {
            tx: t1,
            later: vec![t2, t4]
        })
    );
    assert_eq!(found.unwrap_err().code(), ErrorCode::Conflict);
    assert_eq!(hash(&p), before, "a conflict changes nothing");
    // An entry with no later overlap reverts alone.
    req.tx = Some(t3);
    assert_eq!(apply(&mut p, &mut h, &req), Ok(vec![t3]));
    assert_eq!(h.entry(t3).map(|e| e.state), Some(EntryState::Undone));
    assert_eq!(h.entry(t4).map(|e| e.state), Some(EntryState::Applied));
    req.tx = Some(TxId(99));
    assert_eq!(
        run(&mut p, &h, &req).map(|o| o.entries),
        Err(UndoError::UnknownTx(TxId(99)))
    );
}

#[test]
fn undo_commit_is_a_forward_commit() {
    let mut p = seeded();
    let mut h = History::new();
    let t1 = rename(&mut p, &mut h, "mcp-1", 0x1084, "alpha");
    let rev = p.rev();
    let out = run(&mut p, &h, &request(of("mcp-1"), false)).unwrap();
    let line = out.line.unwrap();
    assert_eq!(line.rev, Rev(rev.0 + 1));
    assert_eq!(line.tx, TxId(t1.0 + 1));
    assert_eq!(line.undo_of, vec![t1]);
    assert_eq!(line.of, vec![t1; line.edits.len()]);
    assert_eq!(line.label.as_str(), super::UNDO_LABEL);
    assert_eq!(p.rev(), line.rev);
    // A dry run plans the same edits and changes nothing.
    h.record(&line);
    let before = hash(&p);
    let mut dry = request(of("mcp-1"), true);
    dry.dry_run = true;
    let plan = run(&mut p, &h, &dry).unwrap();
    assert!(plan.line.is_none());
    assert_eq!(plan.entries, vec![t1]);
    assert!(!plan.planned.is_empty());
    assert_eq!(hash(&p), before);
}

//! Tests of the history: entry states and the `history_list` rows.

use ghidorah_base::{Address, Rev, TxId};
use ghidorah_json::Value;

use super::{ChangeKind, EntryState, History, RowQuery, Scope};
use crate::comments::CommentKind;
use crate::edit::Edit;
use crate::journal::{RunLine, RunState, TxLine};
use crate::program::Program;
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::{seeded, session};

fn commit(
    p: &mut Program,
    h: &mut History,
    who: &str,
    edit: impl FnOnce(&crate::tx::Tx<'_>) -> Edit,
) {
    let mut tx = p.begin("t", Source::Agent, session(who)).unwrap();
    let e = edit(&tx);
    tx.apply(e).unwrap();
    let c = tx.commit().unwrap();
    h.record(&TxLine::of_commit(&c));
}

fn name(addr: u64, text: &str) -> impl FnOnce(&crate::tx::Tx<'_>) -> Edit {
    let text = text.to_string();
    move |tx| Edit::SetName {
        addr: Address::ram(addr),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(tx.fact(text)),
        evidence: vec!["fn:0x1080".to_string()],
    }
}

#[test]
fn rows_coalesce_by_fact() {
    let mut p = seeded();
    let mut h = History::new();
    commit(&mut p, &mut h, "mcp-1", name(0x1084, "a"));
    commit(&mut p, &mut h, "mcp-2", name(0x1084, "b"));
    commit(&mut p, &mut h, "mcp-1", |tx| Edit::SetComment {
        addr: Address::ram(0x1088),
        kind: CommentKind::Pre,
        text: Some(tx.fact("c".to_string())),
    });
    h.record_run(&RunLine {
        rev: Rev(4),
        tx: TxId(4),
        state: RunState::Complete,
        inputs_hash: [0; 32],
        fuel_used: 3,
        result_hash: [1; 32],
    });
    let coalesced = h.rows(
        &p,
        &RowQuery {
            coalesce: true,
            ..RowQuery::default()
        },
    );
    let got: Vec<(ChangeKind, u64, &str)> = coalesced
        .iter()
        .map(|r| (r.kind, r.rev.0, r.session.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (ChangeKind::Name, 2, "mcp-2"),
            (ChangeKind::Comment, 3, "mcp-1"),
            (ChangeKind::Analysis, 4, "analysis"),
        ]
    );
    let first = &coalesced[0];
    assert_eq!(first.id, "0x1084");
    assert_eq!(first.addr, Some(Address::ram(0x1084)));
    assert_eq!(first.fields.get("name").and_then(Value::as_str), Some("b"));
    assert_eq!(first.fields.get("old").and_then(Value::as_str), Some("a"));
    let raw = h.rows(&p, &RowQuery::default());
    assert_eq!(raw.len(), 4);
    assert_eq!(raw[0].tx, TxId(1));
    assert_eq!(raw[0].label, "t");
    let only = h.rows(
        &p,
        &RowQuery {
            kinds: vec![ChangeKind::Comment],
            ..RowQuery::default()
        },
    );
    assert_eq!(only.len(), 1);
    let since = h.rows(
        &p,
        &RowQuery {
            since_rev: Rev(2),
            ..RowQuery::default()
        },
    );
    assert_eq!(since.len(), 2);
}

#[test]
fn record_tracks_states_and_labels() {
    let mut p = seeded();
    let mut h = History::new();
    commit(&mut p, &mut h, "mcp-1", name(0x1084, "a"));
    commit(&mut p, &mut h, "mcp-3", name(0x1088, "b"));
    commit(&mut p, &mut h, "cli", name(0x108c, "c"));
    assert_eq!(h.mcp_labels(), 2);
    assert_eq!(h.last_original(&Scope::All), Some(TxId(3)));
    assert_eq!(
        h.last_original(&Scope::Session(session("mcp-1"))),
        Some(TxId(1))
    );
    let entry = h.entry(TxId(1)).unwrap();
    assert_eq!(entry.state, EntryState::Applied);
    assert!(
        entry
            .keys
            .iter()
            .any(|k| matches!(k, crate::why::FactKey::Symbol(a, _) if *a == Address::ram(0x1084)))
    );
    assert_eq!(
        h.last_commit().map(|(r, s)| (r, s.as_str().to_owned())),
        Some((Rev(3), "cli".to_owned()))
    );
}

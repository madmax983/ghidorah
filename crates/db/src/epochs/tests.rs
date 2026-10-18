use ghidorah_base::{FuncId, NoteId, Range, Rev, Storage, VarId};
use ghidorah_kernel::RangeSet;

use super::Table;
use crate::comments::CommentKind;
use crate::edit::{Edit, VarField};
use crate::notes::{Note, NoteKind, NoteStatus};
use crate::program::Program;
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::{analysis_set, ram, seeded, session};

/// Commits one edit that `make` builds for the Tx.
fn commit(p: &mut Program, source: Source, make: impl Fn(&crate::Tx<'_>) -> Edit) {
    let label = if source == Source::Analysis {
        "analysis"
    } else {
        "mcp-1"
    };
    let mut tx = p.begin("step", source, session(label)).unwrap();
    let e = make(&tx);
    tx.apply(e).unwrap().unwrap();
    tx.commit().unwrap();
}

fn comment(at: u64) -> impl Fn(&crate::Tx<'_>) -> Edit {
    move |tx| Edit::SetComment {
        addr: ram(at),
        kind: CommentKind::Eol,
        text: Some(tx.fact(format!("at {at:#x}"))),
    }
}

#[test]
fn table_names_and_merges() {
    for t in Table::ALL {
        assert_eq!(Table::parse(t.name()), Some(t));
        assert_eq!(t.to_string(), t.name());
    }
    assert_eq!(Table::parse("nope"), None);
    let merged: Vec<Table> = Table::ALL
        .into_iter()
        .filter(|t| t.merges_analysis())
        .collect();
    assert_eq!(
        merged,
        vec![
            Table::Listing,
            Table::Functions,
            Table::Symbols,
            Table::Refs,
            Table::Strings,
            Table::Comments,
            Table::Vars
        ]
    );
}

#[test]
fn table_epochs_follow_commits() {
    let mut p = seeded();
    commit(&mut p, Source::Agent, |tx| Edit::SetName {
        addr: ram(0x1084),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(tx.fact("alpha".to_string())),
        evidence: Vec::new(),
    });
    commit(&mut p, Source::Agent, comment(0x1084));
    assert_eq!(p.epoch(Table::Symbols), Rev(1));
    assert_eq!(p.epoch(Table::Comments), Rev(2));
    assert_eq!(p.epochs().table(Table::Symbols), Rev(1));
    let set = analysis_set(&p, 1);
    commit(&mut p, Source::Analysis, |_| {
        Edit::ReplaceAnalysis(Box::new(set.clone()))
    });
    assert_eq!(p.epoch(Table::Analysis), Rev(3));
    assert_eq!(p.epoch(Table::Symbols), Rev(3));
    assert_eq!(p.epochs().table(Table::Symbols), Rev(1));
    assert_eq!(p.epoch(Table::Notes), Rev(0));
    commit(&mut p, Source::Agent, |tx| {
        Edit::WriteNote(Box::new(Note {
            id: NoteId(1),
            kind: NoteKind::Note,
            text: "n".to_string(),
            at: None,
            func: None,
            status: NoteStatus::Open,
            tags: Vec::new(),
            evidence: Vec::new(),
            lift_ver: None,
            claims: Vec::new(),
            set: None,
            src: Source::Agent,
            session: session("mcp-1"),
            rev: tx.pending_rev(),
        }))
    });
    assert_eq!(p.epoch(Table::Notes), Rev(4));
    assert_eq!(p.epoch(Table::Memory), Rev(0));
}

#[test]
fn func_epoch_reads_body_callees_and_record() {
    let mut p = seeded();
    let [f0, f1, f2] = [0x1080, 0x10c0, 0x1100].map(|a| FuncId(ram(a)));
    assert_eq!(p.func_epoch(f0), Rev(0));
    // A comment in the body of f0.
    commit(&mut p, Source::Agent, comment(0x1090));
    assert_eq!((p.func_epoch(f0), p.func_epoch(f1)), (Rev(1), Rev(0)));
    // The noreturn flag of f1, a callee of f0.
    commit(&mut p, Source::Agent, |tx| Edit::SetNoreturn {
        id: f1,
        noreturn: Some(tx.fact(true)),
    });
    assert_eq!((p.func_epoch(f0), p.func_epoch(f1)), (Rev(2), Rev(2)));
    // The name at the entry of f2.
    commit(&mut p, Source::Agent, |tx| Edit::SetName {
        addr: ram(0x1100),
        key: None,
        kind: SymKind::Function,
        primary: true,
        name: Some(tx.fact("parse".to_string())),
        evidence: Vec::new(),
    });
    assert_eq!((p.func_epoch(f0), p.func_epoch(f2)), (Rev(2), Rev(3)));
    // A variable fact of f2.
    commit(&mut p, Source::Agent, |tx| Edit::SetVarFact {
        var: VarId {
            func: f2,
            storage: Storage::Param(1),
        },
        field: VarField::Name(Some(tx.fact("len".to_string()))),
    });
    assert_eq!(p.func_epoch(f2), Rev(4));
    // A comment outside every body.
    commit(&mut p, Source::Agent, comment(0x1000));
    assert_eq!(
        [f0, f1, f2].map(|f| p.func_epoch(f)),
        [Rev(2), Rev(2), Rev(4)]
    );
    assert_eq!(p.epochs().addr(ram(0x1000)), Rev(5));
    assert_eq!(p.epochs().func(f2), Rev(4));
    let body = RangeSet::from_ranges(&[Range {
        first: 0x1080,
        last: 0x10bf,
    }]);
    assert_eq!(p.epochs().in_ranges(&body), Rev(1));
    // A new analysis set changes every function.
    let set = analysis_set(&p, 1);
    commit(&mut p, Source::Analysis, |_| {
        Edit::ReplaceAnalysis(Box::new(set.clone()))
    });
    assert_eq!([f0, f1, f2].map(|f| p.func_epoch(f)), [Rev(6); 3]);
    assert_eq!(p.func_epoch(FuncId(ram(0x9999))), Rev(6));
}

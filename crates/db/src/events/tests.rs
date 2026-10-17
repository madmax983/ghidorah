use ghidorah_base::{Range, Rev, TxId};
use ghidorah_kernel::RangeSet;

use super::{EVENT_RING, Event};
use crate::comments::CommentKind;
use crate::edit::Edit;
use crate::epochs::Table;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::{SymKey, SymKind};
use crate::test_support::{ram, seeded, session};
use crate::why::FactKey;

#[test]
fn event_ring_wraps_at_4096() {
    let mut p = seeded();
    let commits = EVENT_RING + 1;
    for i in 0..commits {
        let mut tx = p.begin("rename", Source::Agent, session("mcp-1")).unwrap();
        let name = if i % 2 == 0 { "even" } else { "odd" };
        let e = Edit::SetName {
            addr: ram(0x1084),
            key: None,
            kind: SymKind::Function,
            primary: true,
            name: Some(tx.fact(name.to_string())),
            evidence: Vec::new(),
        };
        tx.apply(e).unwrap();
        tx.commit().unwrap();
    }
    let events = p.events();
    assert_eq!(events.len(), EVENT_RING);
    assert_eq!(events.lost(), Rev(1));
    assert_eq!(events.iter().next().map(|e| e.rev), Some(Rev(2)));
    assert!(events.since(Rev(0)).is_none());
    assert_eq!(events.since(Rev(1)).map(|v| v.len()), Some(EVENT_RING));
    let last = u64::try_from(commits).unwrap();
    assert_eq!(events.since(Rev(last - 3)).map(|v| v.len()), Some(3));
    assert_eq!(events.since(Rev(last)).map(|v| v.len()), Some(0));
    assert!(p.check_invariants().is_empty());
}

#[test]
fn one_event_per_table_in_a_commit() {
    let mut p = seeded();
    let mut tx = p.begin("batch", Source::Agent, session("mcp-1")).unwrap();
    let name = Edit::SetName {
        addr: ram(0x1084),
        key: None,
        kind: SymKind::Function,
        primary: true,
        name: Some(tx.fact("alpha".to_string())),
        evidence: Vec::new(),
    };
    tx.apply(name).unwrap();
    let comment = Edit::SetComment {
        addr: ram(0x1090),
        kind: CommentKind::Eol,
        text: Some(tx.fact("loop".to_string())),
    };
    tx.apply(comment).unwrap();
    let mut keys = Vec::new();
    for from in [0x10a0, 0x1094] {
        let key = RefKey {
            from: ram(from),
            op_index: 0,
            to: ram(0x10c0),
            kind: RefType::Data,
        };
        keys.push(key);
        let r = tx.fact(Ref { key, primary: true });
        tx.apply(Edit::AddRef { fact: r }).unwrap();
    }
    tx.commit().unwrap();
    let events: Vec<&Event> = p.events().iter().collect();
    let kinds: Vec<Table> = events.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![Table::Symbols, Table::Refs, Table::Comments]);
    assert!(events.iter().all(|e| e.rev == Rev(1) && e.tx == TxId(1)));
    let refs = events[1];
    assert_eq!(
        refs.ranges,
        RangeSet::from_ranges(&[Range::single(0x1094), Range::single(0x10a0)])
    );
    keys.sort();
    assert_eq!(
        refs.ids,
        keys.into_iter().map(FactKey::Ref).collect::<Vec<_>>()
    );
    assert_eq!(events[0].ids, vec![FactKey::Symbol(ram(0x1084), SymKey(0))]);
    assert_eq!(
        events[2].ids,
        vec![FactKey::Comment(ram(0x1090), CommentKind::Eol)]
    );
    assert_eq!(p.events().since(Rev(0)).map(|v| v.len()), Some(3));
}

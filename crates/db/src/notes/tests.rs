use ghidorah_base::{Address, NoteId, Range, Rev, SetName};
use ghidorah_kernel::RangeSet;
use ghidorah_testkit::pbt::{self, Gen};

use super::{
    Claim, MAX_ITEMS, MAX_TEXT, Note, NoteKind, NoteSet, NoteStatus, Notes, SetMembers, SetOp,
};
use crate::fact::{Invalid, SessionLabel};
use crate::source::Source;

fn note(id: u64, kind: NoteKind) -> Note {
    Note {
        id: NoteId(id),
        kind,
        text: "text".to_string(),
        at: Some(Address::ram(0x40_1000)),
        func: None,
        status: NoteStatus::Open,
        tags: vec!["parser".to_string()],
        evidence: vec!["fn:0x401000".to_string()],
        lift_ver: None,
        claims: vec![Claim {
            rel: "calls".to_string(),
            args: vec!["fn:0x401000".to_string(), "imp:puts".to_string()],
        }],
        set: None,
        src: Source::Agent,
        session: SessionLabel::new("mcp-1").unwrap(),
        rev: Rev(3),
    }
}

fn set_note(id: u64, name: &str, members: SetMembers) -> Note {
    let mut n = note(id, NoteKind::Set);
    n.set = Some(NoteSet {
        name: SetName::new(name).unwrap(),
        members,
    });
    n
}

fn addrs(ranges: &[(u64, u64)]) -> SetMembers {
    let mut set = RangeSet::new();
    for &(first, last) in ranges {
        set.insert(Range { first, last });
    }
    SetMembers::Addrs(set)
}

fn ids(items: &[&str]) -> SetMembers {
    SetMembers::ids(items.iter().map(ToString::to_string).collect())
}

#[test]
fn write_get_and_delete() {
    let mut notes = Notes::default();
    assert_eq!(notes.next_id(), NoteId(1));
    assert_eq!(notes.write(note(1, NoteKind::Hypothesis)).unwrap(), None);
    assert_eq!(notes.next_id(), NoteId(2));
    let mut changed = note(1, NoteKind::Hypothesis);
    changed.status = NoteStatus::Confirmed;
    let old = notes.write(changed).unwrap().unwrap();
    assert_eq!(old.status, NoteStatus::Open);
    assert_eq!(notes.get(NoteId(1)).unwrap().status, NoteStatus::Confirmed);
    notes.write(note(7, NoteKind::Todo)).unwrap();
    assert_eq!(notes.next_id(), NoteId(8));
    assert_eq!(notes.len(), 2);
    assert!(!notes.is_empty());
    assert_eq!(
        notes.iter().map(|n| n.id).collect::<Vec<_>>(),
        [NoteId(1), NoteId(7)]
    );
    assert_eq!(notes.delete(NoteId(7)).unwrap().kind, NoteKind::Todo);
    assert_eq!(notes.delete(NoteId(7)), None);
    assert_eq!(notes.next_id(), NoteId(8), "IDs never come back");
}

#[test]
fn write_checks_the_rules() {
    let mut notes = Notes::default();
    let mut n = note(1, NoteKind::Note);
    n.text = "é".repeat(MAX_TEXT + 1);
    assert_eq!(
        notes.write(n),
        Err(Invalid::TooLong {
            len: MAX_TEXT + 1,
            max: MAX_TEXT
        })
    );
    let mut n = note(1, NoteKind::Note);
    n.text = "é".repeat(MAX_TEXT);
    notes.write(n).unwrap();

    let mut n = note(2, NoteKind::Note);
    n.tags = vec!["t".to_string(); MAX_ITEMS + 1];
    assert!(matches!(notes.write(n), Err(Invalid::TooMany { .. })));
    let mut n = note(2, NoteKind::Note);
    n.evidence = vec!["not an id".to_string()];
    assert_eq!(
        notes.write(n),
        Err(Invalid::BadEvidence("not an id".to_string()))
    );
    let mut n = note(2, NoteKind::Note);
    n.claims = vec![
        Claim {
            rel: "noreturn".to_string(),
            args: Vec::new()
        };
        MAX_ITEMS + 1
    ];
    assert!(matches!(notes.write(n), Err(Invalid::TooMany { .. })));
    let mut n = note(2, NoteKind::Note);
    n.src = Source::Analysis;
    assert_eq!(notes.write(n), Err(Invalid::BadSource(Source::Analysis)));
    let mut n = note(2, NoteKind::Note);
    n.src = Source::User;
    notes.write(n).unwrap();

    assert_eq!(
        notes.write(note(3, NoteKind::Set)),
        Err(Invalid::SetMismatch)
    );
    let mut n = set_note(3, "s", ids(&[]));
    n.kind = NoteKind::Finding;
    assert_eq!(notes.write(n), Err(Invalid::SetMismatch));
    assert_eq!(
        notes.write(set_note(3, "s", ids(&["bad id"]))),
        Err(Invalid::BadEvidence("bad id".to_string()))
    );
    assert_eq!(notes.len(), 2, "a refused write changes nothing");
}

#[test]
fn set_names_index_and_member_order() {
    let mut notes = Notes::default();
    notes
        .write(set_note(1, "parsers", ids(&["fn:0x2", "fn:0x1", "fn:0x2"])))
        .unwrap();
    let name = SetName::new("parsers").unwrap();
    let got = notes.set(&name).unwrap();
    assert_eq!(got.id, NoteId(1));
    assert_eq!(
        got.set.as_ref().unwrap().members,
        ids(&["fn:0x1", "fn:0x2"])
    );
    assert_eq!(
        notes.write(set_note(2, "parsers", ids(&[]))),
        Err(Invalid::SetNameTaken {
            name: "parsers".to_string(),
            owner: NoteId(1)
        })
    );
    notes
        .write(set_note(1, "renamed", addrs(&[(1, 2)])))
        .unwrap();
    assert!(
        notes.set(&name).is_none(),
        "a renamed set frees its old name"
    );
    notes.write(set_note(2, "parsers", ids(&[]))).unwrap();
    let names: Vec<(String, NoteId)> = notes
        .sets()
        .map(|(n, id)| (n.as_str().to_string(), id))
        .collect();
    assert_eq!(
        names,
        [
            ("parsers".to_string(), NoteId(2)),
            ("renamed".to_string(), NoteId(1))
        ]
    );
    notes.delete(NoteId(2));
    assert!(notes.set(&name).is_none());
    let mut plain = note(1, NoteKind::Note);
    plain.set = None;
    notes.write(plain).unwrap();
    assert_eq!(
        notes.sets().count(),
        0,
        "a note that is no longer a set frees its name"
    );
}

#[test]
fn set_algebra_on_ids_matches_a_model() {
    pbt::check("set_algebra_on_ids_matches_a_model", 200, |g: &mut Gen| {
        let pool = ["fn:0x1", "fn:0x2", "imp:puts", "str:0x10"];
        let draw = |g: &mut Gen| -> Vec<String> {
            g.vec(5, |g| (*g.pick(&pool).unwrap_or(&"fn:0x1")).to_string())
        };
        let a = draw(g);
        let b = draw(g);
        let sa: std::collections::BTreeSet<String> = a.iter().cloned().collect();
        let sb: std::collections::BTreeSet<String> = b.iter().cloned().collect();
        let left = SetMembers::ids(a);
        let right = SetMembers::ids(b);
        let cases = [
            (SetOp::Replace, sb.clone()),
            (SetOp::Union, sa.union(&sb).cloned().collect()),
            (SetOp::Intersect, sa.intersection(&sb).cloned().collect()),
            (SetOp::Subtract, sa.difference(&sb).cloned().collect()),
        ];
        for (op, want) in cases {
            let got = left.apply(op, &right).map_err(|e| e.to_string())?;
            let want = SetMembers::Ids(want.into_iter().collect());
            if got != want {
                return Err(format!("{op:?}: {got:?} != {want:?}"));
            }
        }
        Ok(())
    });
}

#[test]
fn set_algebra_on_addresses() {
    let a = addrs(&[(0, 9), (20, 29)]);
    let b = addrs(&[(5, 24)]);
    assert_eq!(a.apply(SetOp::Union, &b).unwrap(), addrs(&[(0, 29)]));
    assert_eq!(
        a.apply(SetOp::Intersect, &b).unwrap(),
        addrs(&[(5, 9), (20, 24)])
    );
    assert_eq!(
        a.apply(SetOp::Subtract, &b).unwrap(),
        addrs(&[(0, 4), (25, 29)])
    );
    assert_eq!(
        a.apply(SetOp::Replace, &ids(&["fn:0x1"])).unwrap(),
        ids(&["fn:0x1"])
    );
    assert_eq!(a.apply(SetOp::Union, &ids(&[])), Err(Invalid::SetKinds));
    assert_eq!(
        ids(&["fn:0x1"]).apply(SetOp::Subtract, &a),
        Err(Invalid::SetKinds)
    );
    assert_eq!(a.count(), 20);
    assert_eq!(addrs(&[(0, u64::MAX)]).count(), 1u128 << 64);
    assert_eq!(ids(&["fn:0x1", "fn:0x1", "fn:0x2"]).count(), 2);
}

#[test]
fn kind_and_status_names() {
    for k in NoteKind::ALL {
        assert_eq!(NoteKind::parse(k.name()), Some(k));
        assert_eq!(k.to_string(), k.name());
    }
    for s in NoteStatus::ALL {
        assert_eq!(NoteStatus::parse(s.name()), Some(s));
        assert_eq!(s.to_string(), s.name());
    }
    assert_eq!(NoteKind::parse("bookmark"), None);
    assert_eq!(NoteStatus::parse("closed"), None);
    let names: Vec<&str> = NoteKind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(
        names,
        ["note", "todo", "hypothesis", "finding", "error", "set"]
    );
}

use std::collections::BTreeSet;

use ghidorah_base::{Address, TxId};
use ghidorah_testkit::pbt::{self, Gen};

use super::{Ref, RefKey, RefType, Refs};
use crate::fact::{Origin, SessionLabel, WriteError};
use crate::source::Source;

fn agent() -> Origin {
    Origin::new(
        Source::Agent,
        TxId(3),
        SessionLabel::new("cli").unwrap(),
        false,
    )
}

fn key(from: u64, op_index: i8, to: u64, kind: RefType) -> RefKey {
    RefKey {
        from: Address::ram(from),
        op_index,
        to: Address::ram(to),
        kind,
    }
}

fn draw_key(g: &mut Gen) -> RefKey {
    let kinds = [RefType::UnconditionalCall, RefType::Read, RefType::Data];
    key(
        g.range(0, 3),
        i8::try_from(g.range(0, 1)).unwrap_or(0) - 1,
        g.range(0, 3),
        *g.pick(&kinds).unwrap_or(&RefType::Data),
    )
}

#[test]
fn refs_from_to_index_agree() {
    pbt::check("refs_from_to_index_agree", 300, |g: &mut Gen| {
        let mut refs = Refs::default();
        let mut model: BTreeSet<RefKey> = BTreeSet::new();
        for _ in 0..g.range(1, 40) {
            let k = draw_key(g);
            if g.bool() {
                refs.add(
                    Ref {
                        key: k,
                        primary: g.bool(),
                    },
                    &agent(),
                )
                .map_err(|e| e.to_string())?;
                model.insert(k);
            } else {
                let old = refs.remove(&k, &agent()).map_err(|e| e.to_string())?;
                if old.is_some() != model.remove(&k) {
                    return Err(format!("remove of {k:?} disagrees with the model"));
                }
            }
            let from: BTreeSet<RefKey> = refs.iter().map(|f| f.value.key).collect();
            let to: BTreeSet<RefKey> = refs.to_index().collect();
            if from != to || from != model || refs.len() != model.len() {
                return Err(format!("from {from:?}, to {to:?}, model {model:?}"));
            }
            for a in 0..4 {
                let addr = Address::ram(a);
                let got_from: Vec<RefKey> = refs.from(addr).map(|f| f.value.key).collect();
                let want_from: Vec<RefKey> =
                    model.iter().copied().filter(|k| k.from == addr).collect();
                let got_to: Vec<RefKey> = refs.to(addr).map(|f| f.value.key).collect();
                let mut want_to: Vec<RefKey> =
                    model.iter().copied().filter(|k| k.to == addr).collect();
                want_to.sort_by_key(|k| (k.to, k.from, k.op_index, k.kind));
                if got_from != want_from || got_to != want_to {
                    return Err(format!("lists of {addr} disagree with the model"));
                }
            }
        }
        Ok(())
    });
}

#[test]
fn add_and_remove_follow_the_write_rule() {
    let mut refs = Refs::default();
    let k = key(0x10, 0, 0x20, RefType::Read);
    assert_eq!(
        refs.add(
            Ref {
                key: k,
                primary: true
            },
            &Origin::analysis()
        )
        .unwrap(),
        None
    );
    let old = refs
        .add(
            Ref {
                key: k,
                primary: false,
            },
            &agent(),
        )
        .unwrap()
        .unwrap();
    assert!(old.value.primary);
    assert_eq!(old.source, Source::Analysis);
    assert_eq!(refs.get(&k).unwrap().source, Source::Agent);

    let err = refs.remove(&k, &Origin::analysis()).unwrap_err();
    assert!(matches!(&err, WriteError::Blocked(b) if b.current.value.key == k));
    let err = refs
        .add(
            Ref {
                key: k,
                primary: true,
            },
            &Origin::analysis(),
        )
        .unwrap_err();
    assert!(matches!(err, WriteError::Blocked(_)));
    assert_eq!(refs.len(), 1);
    assert!(!refs.is_empty());

    assert_eq!(
        refs.remove(&key(1, 0, 2, RefType::Data), &agent()).unwrap(),
        None
    );
    assert!(refs.remove(&k, &agent()).unwrap().is_some());
    assert!(refs.is_empty());
    assert_eq!(refs.to_index().count(), 0);
}

#[test]
fn external_targets_and_negative_operands_sort_by_key() {
    let mut refs = Refs::default();
    let from = Address::ram(0x40_1000);
    let ext = Address::external(1);
    let keys = [
        RefKey {
            from,
            op_index: -1,
            to: ext,
            kind: RefType::UnconditionalCall,
        },
        RefKey {
            from,
            op_index: 0,
            to: Address::ram(0x40_2000),
            kind: RefType::Read,
        },
        RefKey {
            from,
            op_index: 0,
            to: ext,
            kind: RefType::Data,
        },
    ];
    for k in keys.iter().rev() {
        refs.add(
            Ref {
                key: *k,
                primary: false,
            },
            &Origin::analysis(),
        )
        .unwrap();
    }
    let got: Vec<RefKey> = refs.from(from).map(|f| f.value.key).collect();
    assert_eq!(got, keys);
    assert_eq!(refs.to(ext).count(), 2);
    assert_eq!(refs.from(Address::ram(0x40_1001)).count(), 0);
    assert_eq!(refs.to(Address::ram(u64::MAX)).count(), 0);
}

#[test]
fn ref_types_keep_the_ghidra_codes_and_names() {
    let want: [(u8, &str); 17] = [
        (0, "fall_through"),
        (1, "unconditional_jump"),
        (2, "conditional_jump"),
        (3, "unconditional_call"),
        (4, "conditional_call"),
        (5, "terminator"),
        (6, "computed_jump"),
        (7, "conditional_terminator"),
        (8, "computed_call"),
        (9, "indirection"),
        (100, "data"),
        (101, "read"),
        (102, "write"),
        (103, "read_write"),
        (107, "param"),
        (113, "external_ref"),
        (127, "thunk"),
    ];
    let got: Vec<(u8, &str)> = RefType::ALL.iter().map(|t| (t.code(), t.name())).collect();
    assert_eq!(got, want);
    for t in RefType::ALL {
        assert_eq!(RefType::from_code(t.code()), Some(t));
        assert_eq!(RefType::parse(t.name()), Some(t));
        assert_eq!(t.to_string(), t.name());
        assert_eq!(t.is_flow(), t.code() < 100);
    }
    assert_eq!(RefType::from_code(10), None);
    assert_eq!(RefType::parse("jump"), None);
    let calls: Vec<RefType> = RefType::ALL.into_iter().filter(|t| t.is_call()).collect();
    assert_eq!(
        calls,
        [
            RefType::UnconditionalCall,
            RefType::ConditionalCall,
            RefType::ComputedCall
        ]
    );
}

#[test]
fn ref_ids_use_the_type_name() {
    let k = key(0x40_1136, 1, 0x40_2010, RefType::Read);
    assert_eq!(k.id().unwrap().to_string(), "ref:0x401136>0x402010:read");
}

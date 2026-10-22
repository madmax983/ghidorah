use ghidorah_base::{Address, FuncId};

use super::{FactKey, MAX_PREMISES, MAX_RULE, RuleCode, Why, WhyStore};
use crate::fact::Invalid;

fn why(rule: &str, premises: Vec<FactKey>) -> Why {
    Why {
        rule: RuleCode::new(rule).unwrap(),
        premises,
    }
}

#[test]
fn rule_codes_obey_the_grammar() {
    for good in ["R_ENTRY", "R_FDE_START", "R_X1", "R__"] {
        assert_eq!(RuleCode::new(good).unwrap().as_str(), good);
        assert_eq!(RuleCode::new(good).unwrap().to_string(), good);
    }
    for bad in ["", "R_", "ENTRY", "R_entry", "R_A-B", "r_A"] {
        assert_eq!(RuleCode::new(bad), Err(Invalid::EmptyName), "{bad:?}");
    }
    let long = format!("R_{}", "A".repeat(MAX_RULE - 1));
    assert_eq!(
        RuleCode::new(&long),
        Err(Invalid::TooLong {
            len: MAX_RULE + 1,
            max: MAX_RULE
        })
    );
    assert!(RuleCode::new(&long[..MAX_RULE]).is_ok());
}

#[test]
fn records_get_increasing_creation_orders() {
    let mut store = WhyStore::default();
    let f = FactKey::Func(FuncId(Address::ram(0x40_1000)));
    let entry = FactKey::Entry(0x40_1000);
    assert_eq!(
        store
            .insert(entry.clone(), why("R_INPUT", Vec::new()))
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .insert(f.clone(), why("R_ENTRY", vec![entry.clone()]))
            .unwrap(),
        None
    );
    assert!(store.order(&entry) < store.order(&f));
    assert_eq!(
        store.get(&f).unwrap().premises,
        std::slice::from_ref(&entry)
    );
    let old = store
        .insert(entry.clone(), why("R_AGAIN", Vec::new()))
        .unwrap()
        .unwrap();
    assert_eq!(old.rule.as_str(), "R_INPUT");
    assert!(
        store.order(&entry) > store.order(&f),
        "a new record gets a new order"
    );
    assert_eq!(store.len(), 2);
    assert!(!store.is_empty());
    assert_eq!(store.iter().count(), 2);

    let many = vec![entry.clone(); MAX_PREMISES + 1];
    assert_eq!(
        store.insert(FactKey::Reloc(1), why("R_X", many)),
        Err(Invalid::TooMany {
            count: MAX_PREMISES + 1,
            max: MAX_PREMISES
        })
    );
    assert_eq!(store.remove(&entry).unwrap().rule.as_str(), "R_AGAIN");
    assert!(store.get(&entry).is_none());
    assert!(store.order(&entry).is_none());
}

#[test]
fn a_bulk_build_matches_one_insert_at_a_time() {
    let rows = |keys: &[u64]| -> Vec<(FactKey, u64, Why)> {
        keys.iter()
            .map(|k| {
                (
                    FactKey::CodeUnit(*k),
                    k * 2,
                    why("R_X", vec![FactKey::Entry(*k)]),
                )
            })
            .collect()
    };
    let one_by_one = |rows: Vec<(FactKey, u64, Why)>| {
        let mut store = WhyStore::default();
        for (k, o, w) in rows {
            store.insert_at(k, o, w).unwrap();
        }
        store
    };
    // Rows in key order, rows out of order, a key twice and a store that is not empty.
    for keys in [&[1, 2, 5, 9][..], &[9, 1, 5], &[1, 5, 5, 2], &[]] {
        let mut bulk = WhyStore::default();
        bulk.extend_at(rows(keys)).unwrap();
        assert_eq!(bulk, one_by_one(rows(keys)), "{keys:?}");
    }
    let mut store = one_by_one(rows(&[3]));
    store.extend_at(rows(&[1, 4])).unwrap();
    assert_eq!(store, one_by_one(rows(&[3, 1, 4])));
    assert_eq!(store.next_order(), 9);
}

#[test]
fn a_bulk_build_refuses_too_many_premises() {
    let many = vec![FactKey::Entry(0); MAX_PREMISES + 1];
    let mut store = WhyStore::default();
    let rows = vec![
        (FactKey::CodeUnit(1), 0, why("R_X", Vec::new())),
        (FactKey::CodeUnit(2), 1, why("R_X", many)),
    ];
    assert_eq!(
        store.extend_at(rows),
        Err(Invalid::TooMany {
            count: MAX_PREMISES + 1,
            max: MAX_PREMISES
        })
    );
    assert!(store.is_empty());
}

#[test]
fn clones_of_a_rule_code_share_its_text() {
    let code = RuleCode::new("R_DISASM_FLOW").unwrap();
    let copy = code.clone();
    assert!(std::ptr::eq(code.as_str(), copy.as_str()));
}

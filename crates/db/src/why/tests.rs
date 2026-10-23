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

fn call_ref(from: u64, to: u64) -> FactKey {
    FactKey::Ref(crate::refs::RefKey {
        from: Address::ram(from),
        op_index: -1,
        to: Address::ram(to),
        kind: crate::refs::RefType::UnconditionalCall,
    })
}

fn func(entry: u64) -> FactKey {
    FactKey::Func(FuncId(Address::ram(entry)))
}

/// Records of each shape: compact unit and reference records, and general records with a
/// premise that does not follow from the key.
fn mixed() -> Vec<(FactKey, u64, Why)> {
    let ext = FactKey::Func(FuncId(Address::external(0x10)));
    vec![
        (
            FactKey::CodeUnit(0x10),
            3,
            why("R_DISASM_FLOW", vec![func(0x10)]),
        ),
        (FactKey::CodeUnit(0x14), 4, why("R_DISASM_FLOW", vec![ext])),
        (
            FactKey::CodeUnit(0x18),
            5,
            why("R_OTHER", vec![func(0x10), func(0x20)]),
        ),
        (FactKey::CodeUnit(0x1c), 6, why("R_DISASM_FLOW", Vec::new())),
        (func(0x10), 0, why("R_ENTRY", vec![FactKey::Entry(0x10)])),
        (
            call_ref(0x10, 0x40),
            7,
            why("R_FLOW_REF", vec![FactKey::CodeUnit(0x10)]),
        ),
        (
            call_ref(0x14, 0x40),
            8,
            why("R_FLOW_REF", vec![FactKey::CodeUnit(0x10)]),
        ),
        (FactKey::Entry(0x10), 1, why("R_INPUT", Vec::new())),
    ]
}

#[test]
fn compact_records_read_back_as_inserted() {
    let mut rows = mixed();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut bulk = WhyStore::default();
    bulk.extend_at(rows.clone()).unwrap();
    let mut single = WhyStore::default();
    for (k, o, w) in rows.iter().rev().cloned() {
        single.insert_at(k, o, w).unwrap();
    }
    assert_eq!(bulk, single);
    assert_eq!(bulk.len(), rows.len());
    let read: Vec<(FactKey, u64, Why)> = bulk.iter().collect();
    assert_eq!(
        read, rows,
        "every record and order reads back, in key order"
    );
    for (k, o, w) in &rows {
        assert_eq!(bulk.get(k).as_ref(), Some(w), "{k:?}");
        assert_eq!(bulk.order(k), Some(*o), "{k:?}");
    }
}

#[test]
fn a_key_moves_between_the_compact_and_the_general_map() {
    let mut store = WhyStore::default();
    let unit = FactKey::CodeUnit(0x10);
    let flow = why("R_DISASM_FLOW", vec![func(0x10)]);
    let other = why("R_OTHER", vec![func(0x10), func(0x20)]);
    assert_eq!(store.insert(unit.clone(), flow.clone()).unwrap(), None);
    assert_eq!(
        store.insert(unit.clone(), other.clone()).unwrap(),
        Some(flow.clone())
    );
    assert_eq!((store.len(), store.get(&unit)), (1, Some(other.clone())));
    assert_eq!(
        store.insert(unit.clone(), flow.clone()).unwrap(),
        Some(other)
    );
    assert_eq!((store.len(), store.order(&unit)), (1, Some(2)));
    assert_eq!(store.remove(&unit), Some(flow));
    assert!(store.is_empty());
    assert_eq!(store.get(&unit), None);
}

#[test]
fn rows_out_of_key_order_set_one_at_a_time() {
    let mut rows = mixed();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    // A copy of one key after the others: the last row of a key wins.
    let late = (FactKey::CodeUnit(0x10), 9, why("R_OTHER", Vec::new()));
    let pushed = super::WhyRows::from_rows(rows.iter().cloned().chain([late.clone()])).unwrap();
    assert_eq!(pushed.len(), rows.len() + 1);
    let mut store = WhyStore::default();
    store.extend_rows(pushed).unwrap();
    let mut single = WhyStore::default();
    for (k, o, w) in rows.into_iter().chain([late.clone()]) {
        single.insert_at(k, o, w).unwrap();
    }
    assert_eq!(store, single);
    assert_eq!(store.get(&late.0), Some(late.2));
    assert_eq!(store.next_order(), 10);
}

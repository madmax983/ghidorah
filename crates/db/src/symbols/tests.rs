use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, TxId};
use ghidorah_testkit::pbt::{self, Gen};

use super::{SymKey, SymKind, Symbols};
use crate::fact::{Invalid, Origin, SessionLabel, WriteError};
use crate::source::Source;

fn agent() -> Origin {
    Origin::new(
        Source::Agent,
        TxId(1),
        SessionLabel::new("cli").unwrap(),
        false,
    )
}

/// Checks the rules of the module doc over the whole layer.
fn check_rules(s: &Symbols) -> Result<(), String> {
    let mut by_addr: BTreeMap<Address, Vec<(SymKey, bool, &str)>> = BTreeMap::new();
    for sym in s.iter() {
        by_addr
            .entry(sym.addr)
            .or_default()
            .push((sym.key, sym.primary, sym.name.value.as_str()));
    }
    for (addr, syms) in &by_addr {
        let primaries = syms.iter().filter(|(_, p, _)| *p).count();
        if primaries != 1 {
            return Err(format!("{addr} has {primaries} primary symbols: {syms:?}"));
        }
        let names: BTreeSet<&str> = syms.iter().map(|(_, _, n)| *n).collect();
        if names.len() != syms.len() {
            return Err(format!("{addr} has a name twice: {syms:?}"));
        }
        if s.primary(*addr).map(|p| p.key) != syms.iter().find(|x| x.1).map(|x| x.0) {
            return Err(format!("primary() disagrees at {addr}"));
        }
    }
    let mut index: BTreeMap<&str, Vec<Address>> = BTreeMap::new();
    for sym in s.iter() {
        index
            .entry(sym.name.value.as_str())
            .or_default()
            .push(sym.addr);
    }
    let actual: BTreeMap<&str, Vec<Address>> = s.names().map(|(n, a)| (n, a.to_vec())).collect();
    if actual != index {
        return Err(format!(
            "name index {actual:?} differs from the table {index:?}"
        ));
    }
    Ok(())
}

#[test]
fn symbols_one_primary_per_address() {
    pbt::check("symbols_one_primary_per_address", 300, |g: &mut Gen| {
        let mut s = Symbols::default();
        let names = ["a", "b", "c", "main"];
        for _ in 0..g.range(1, 40) {
            let addr = Address::ram(g.range(0, 3));
            let name = (*g.pick(&names).unwrap_or(&"a")).to_string();
            match g.draw(5) {
                0 => {
                    s.add(addr, name, SymKind::Label, &agent())
                        .map_err(|e| e.to_string())?;
                }
                1 => match s.set_name(addr, Some(name), SymKind::Function, &agent()) {
                    Ok(_) | Err(WriteError::Invalid(Invalid::DuplicateName(_))) => {}
                    Err(e) => return Err(e.to_string()),
                },
                2 => {
                    s.set_name(addr, None, SymKind::Function, &agent())
                        .map_err(|e| e.to_string())?;
                }
                3 => {
                    let key = SymKey(u16::try_from(g.range(0, 3)).unwrap_or(0));
                    s.set_primary(addr, key);
                }
                _ => {
                    let key = SymKey(u16::try_from(g.range(0, 3)).unwrap_or(0));
                    s.remove(addr, key);
                }
            }
            check_rules(&s)?;
        }
        Ok(())
    });
}

#[test]
fn add_gives_keys_in_order_and_keeps_names_unique() {
    let mut s = Symbols::default();
    let a = Address::ram(0x1000);
    let k0 = s
        .add(a, "main".to_string(), SymKind::Function, &Origin::load())
        .unwrap();
    let k1 = s
        .add(a, "entry".to_string(), SymKind::Label, &Origin::load())
        .unwrap();
    let again = s
        .add(a, "main".to_string(), SymKind::Label, &Origin::load())
        .unwrap();
    assert_eq!((k0, k1, again), (SymKey(0), SymKey(1), SymKey(0)));
    assert_eq!(s.len(), 2);
    assert!(!s.is_empty());
    assert!(s.get(a, k0).unwrap().primary);
    assert!(!s.get(a, k1).unwrap().primary);
    assert_eq!(s.get(a, k0).unwrap().kind, SymKind::Function);
    assert_eq!(
        s.at(a).map(|x| x.name.value.as_str()).collect::<Vec<_>>(),
        ["main", "entry"]
    );
    assert_eq!(s.by_name("main"), &[a]);
    assert!(s.by_name("nothing").is_empty());
    assert_eq!(s.at(Address::ram(0x1001)).count(), 0);
    assert_eq!(s.at(Address::external(0x1000)).count(), 0);

    assert_eq!(
        s.add(a, String::new(), SymKind::Label, &Origin::load()),
        Err(Invalid::EmptyName)
    );
    let long = "x".repeat(ghidorah_base::id::MAX_NAME_LEN + 1);
    assert!(matches!(
        s.add(a, long, SymKind::Label, &Origin::load()),
        Err(Invalid::TooLong { .. })
    ));
}

#[test]
fn set_name_renames_the_primary_and_follows_the_rule() {
    let mut s = Symbols::default();
    let a = Address::ram(0x2000);
    s.add(
        a,
        "puts@plt".to_string(),
        SymKind::Function,
        &Origin::load(),
    )
    .unwrap();

    let err = s
        .set_name(a, Some("my_puts".to_string()), SymKind::Function, &agent())
        .unwrap_err();
    assert!(matches!(&err, WriteError::Blocked(b) if b.current.value == "puts@plt"));
    assert_eq!(s.by_name("puts@plt"), &[a]);

    let forced = Origin::new(
        Source::Agent,
        TxId(2),
        SessionLabel::new("cli").unwrap(),
        true,
    );
    let old = s
        .set_name(a, Some("my_puts".to_string()), SymKind::Function, &forced)
        .unwrap()
        .unwrap();
    assert_eq!(old.value, "puts@plt");
    assert!(s.by_name("puts@plt").is_empty());
    assert_eq!(s.by_name("my_puts"), &[a]);
    assert_eq!(
        s.primary(a).unwrap().key,
        SymKey(0),
        "a rename keeps the key"
    );
    assert_eq!(s.primary(a).unwrap().name.source, Source::Agent);

    let b = Address::ram(0x3000);
    assert_eq!(
        s.set_name(b, Some("f".to_string()), SymKind::Function, &agent())
            .unwrap(),
        None
    );
    assert_eq!(s.primary(b).unwrap().kind, SymKind::Function);
    let old = s
        .set_name(b, None, SymKind::Function, &agent())
        .unwrap()
        .unwrap();
    assert_eq!(old.value, "f");
    assert_eq!(s.at(b).count(), 0);
    assert_eq!(
        s.set_name(b, None, SymKind::Function, &agent()).unwrap(),
        None
    );
    assert!(
        s.set_name(b, Some(String::new()), SymKind::Label, &agent())
            .is_err()
    );
}

#[test]
fn set_name_refuses_a_name_of_another_symbol_at_the_address() {
    let mut s = Symbols::default();
    let a = Address::ram(0x10);
    s.add(a, "x".to_string(), SymKind::Label, &agent()).unwrap();
    s.add(a, "y".to_string(), SymKind::Label, &agent()).unwrap();
    let err = s
        .set_name(a, Some("y".to_string()), SymKind::Label, &agent())
        .unwrap_err();
    assert_eq!(
        err,
        WriteError::Invalid(Invalid::DuplicateName("y".to_string()))
    );
    assert_eq!(s.at(a).count(), 2);
    assert_eq!(s.primary(a).unwrap().name.value, "x");
    let same = s
        .set_name(a, Some("x".to_string()), SymKind::Label, &agent())
        .unwrap();
    assert_eq!(
        same.map(|f| f.value),
        Some("x".to_string()),
        "the same name is a rewrite"
    );
    check_rules(&s).unwrap();
}

#[test]
fn remove_passes_the_primary_flag_on() {
    let mut s = Symbols::default();
    let a = Address::ram(0x4000);
    for name in ["a", "b", "c"] {
        s.add(a, name.to_string(), SymKind::Label, &agent())
            .unwrap();
    }
    assert_eq!(s.set_primary(a, SymKey(2)), Some(SymKey(0)));
    assert_eq!(s.primary(a).unwrap().name.value, "c");
    assert_eq!(s.set_primary(a, SymKey(9)), None);
    assert_eq!(s.primary(a).unwrap().name.value, "c");
    let removed = s.remove(a, SymKey(2)).unwrap();
    assert_eq!(removed.name.value, "c");
    assert_eq!(s.primary(a).unwrap().key, SymKey(0));
    assert!(s.remove(a, SymKey(2)).is_none());
    assert!(s.remove(a, SymKey(1)).is_some());
    assert!(s.remove(a, SymKey(0)).is_some());
    assert!(s.is_empty());
    assert_eq!(s.names().count(), 0);
}

#[test]
fn kind_codes_are_the_ghidra_codes() {
    let codes: Vec<(u8, &str)> = SymKind::ALL.iter().map(|k| (k.code(), k.name())).collect();
    assert_eq!(
        codes,
        [
            (0, "label"),
            (1, "library"),
            (5, "function"),
            (6, "parameter"),
            (7, "local_var"),
            (8, "global_var")
        ]
    );
    for k in SymKind::ALL {
        assert_eq!(SymKind::from_code(k.code()), Some(k));
        assert_eq!(k.to_string(), k.name());
    }
    assert_eq!(SymKind::from_code(2), None);
}

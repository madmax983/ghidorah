//! Why-records: each analysis fact has a reason, each premise exists and the premise graph
//! has no cycle (AC-094).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_analysis::{Rule, Why};
use ghidorah_base::{Address, StringId};
use ghidorah_db::{FactKey, Program, Tables};

use crate::blobs::Blob;
use crate::support::{all_t1, analyze};

/// Gives the keys of every fact of a layer.
fn fact_keys(t: &Tables) -> Vec<FactKey> {
    let all = ghidorah_base::Range {
        first: 0,
        last: u64::MAX,
    };
    let mut keys: Vec<FactKey> = t
        .listing()
        .units_in(all)
        .map(|(at, _)| FactKey::CodeUnit(at))
        .collect();
    for f in t.funcs().iter() {
        keys.push(FactKey::Func(f.id()));
        if f.flags.noreturn.is_some() {
            keys.push(FactKey::Noreturn(f.id()));
        }
        if f.sig.is_some() {
            keys.push(FactKey::Signature(f.id()));
        }
    }
    keys.extend(t.refs().iter().map(|r| FactKey::Ref(r.value.key)));
    keys.extend(t.symbols().iter().map(|s| FactKey::Symbol(s.addr, s.key)));
    keys.extend(
        t.strings()
            .iter()
            .map(|(at, _)| FactKey::Str(StringId(Address::ram(at)))),
    );
    keys
}

/// Checks the why graph of the analysis layer of `p`.
fn check(path: &str, p: &Program) -> usize {
    let found = p.check_invariants();
    assert!(found.is_empty(), "{path}: {found:?}");
    let a = p.analysis();
    let keys = fact_keys(a);
    for key in &keys {
        let why = a
            .why()
            .get(key)
            .unwrap_or_else(|| panic!("{path}: {key:?} has no why-record"));
        assert!(
            Rule::parse(why.rule.as_str()).is_some(),
            "{path}: {} is a catalog rule",
            why.rule
        );
    }
    // A premise in the analysis layer is an edge of the premise graph. Other premises are
    // base-layer facts or inputs. A graph with no cycle drains in a topological order, so a
    // walk from any fact ends.
    let held: BTreeSet<&FactKey> = keys.iter().collect();
    let mut waits: BTreeMap<&FactKey, usize> = BTreeMap::new();
    let mut users: BTreeMap<FactKey, Vec<&FactKey>> = BTreeMap::new();
    for key in &keys {
        let why = a.why().get(key).expect("a record");
        let inside: Vec<FactKey> = why
            .premises
            .into_iter()
            .filter(|q| held.contains(q))
            .collect();
        waits.insert(key, inside.len());
        for q in inside {
            users.entry(q).or_default().push(key);
        }
    }
    let mut ready: Vec<&FactKey> = waits
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(k, _)| *k)
        .collect();
    let mut drained = 0;
    while let Some(key) = ready.pop() {
        drained += 1;
        for user in users.get(key).into_iter().flatten() {
            let n = waits.get_mut(user).expect("a user");
            *n -= 1;
            if *n == 0 {
                ready.push(user);
            }
        }
    }
    assert_eq!(
        drained,
        keys.len(),
        "{path}: the premise graph has no cycle"
    );
    keys.len()
}

#[test]
fn ac_094_why_records() {
    let mut facts = 0;
    let mut rules = BTreeSet::new();
    for (path, p) in all_t1() {
        facts += check(path, p);
        for (_, why) in p.analysis().why().iter() {
            rules.insert(why.rule.as_str().to_owned());
        }
    }
    assert!(facts > 20_000, "the fixtures hold analysis facts: {facts}");
    for rule in [
        Rule::Entry,
        Rule::SymbolFunc,
        Rule::PltRelocSlot,
        Rule::FdeStart,
        Rule::CallTarget,
        Rule::DisasmFlow,
        Rule::FlowRef,
        Rule::NoreturnKnown,
        Rule::NoreturnBody,
    ] {
        assert!(rules.contains(rule.code()), "the fixtures use {rule}");
    }
    let mut p = Blob::new().call(0x10).ret().at(0x10).ret().load(Some(0));
    let _ = analyze(&mut p);
    assert!(check("blob", &p) >= 4);
}

#[test]
fn rule_catalog() {
    for rule in Rule::ALL {
        assert_eq!(Rule::parse(rule.code()), Some(rule));
        assert!(rule.code().starts_with("R_"));
        assert!(rule.rule_code().is_ok());
        assert!(rule.doc().ends_with('.'));
        assert_eq!(rule.to_string(), rule.code());
    }
    assert_eq!(Rule::parse("R_NOTHING"), None);
    let key = FactKey::Entry(0x10);
    let why = Why::new(Rule::Entry, vec![key.clone(), key.clone()]);
    assert_eq!(why.premises, [key]);
    let many: Vec<FactKey> = (0..100).map(FactKey::CodeUnit).collect();
    assert_eq!(Why::new(Rule::NoreturnBody, many).premises.len(), 64);
    assert!(Why::bare(Rule::EndbrHead).premises.is_empty());
}

//! The store of the why-records of one layer.
//!
//! Most records of an analysis layer have one premise that follows from the key. The store
//! keeps these records in compact maps with no premise list:
//!
//! | Key | Premise | Compact value |
//! |---|---|---|
//! | `CodeUnit(at)` | `Func` at a RAM entry | the entry and the rule |
//! | `Ref(k)` | `CodeUnit` at the RAM `from` of `k` | the rule |
//!
//! Each other record goes in the general map. A key is in one map only. A read makes the
//! record of a compact value again, so the readers see the same records in the same order.

use std::collections::BTreeMap;
use std::iter::Peekable;

use ghidorah_base::{Address, FuncId, SpaceId};

use super::{FactKey, MAX_PREMISES, RuleCode, Why, WhyRows};
use crate::fact::Invalid;
use crate::refs::RefKey;

/// A record whose one premise follows from its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Slim {
    /// The entry of the premise function of a code unit. A reference keeps 0.
    pub(super) entry: u64,
    /// The index of the rule in the rule list of the store.
    pub(super) rule: u16,
}

/// The why-records of one layer.
#[derive(Debug, Clone, Default)]
pub struct WhyStore {
    /// The records that have no compact form.
    map: BTreeMap<FactKey, Why>,
    /// The records of code units with one premise function.
    units: BTreeMap<u64, Slim>,
    /// The records of references with the code unit of their source as the premise.
    refs: BTreeMap<RefKey, Slim>,
    /// The rule codes of the compact records. A record keeps the index of its rule.
    rules: Vec<RuleCode>,
}

/// The compact form of a record.
pub(super) enum Compact {
    /// A code unit at a RAM offset and the entry of its premise function.
    Unit(u64, u64),
    /// A reference.
    Ref(RefKey),
}

/// Gives the compact form of the record `why` of `key`, or `None` for a general record.
pub(super) fn compact(key: &FactKey, why: &Why) -> Option<Compact> {
    match (key, why.premises.as_slice()) {
        (FactKey::CodeUnit(at), [FactKey::Func(FuncId(a))]) if a.space == SpaceId::RAM => {
            Some(Compact::Unit(*at, a.off))
        }
        (FactKey::Ref(k), [FactKey::CodeUnit(off)])
            if k.from.space == SpaceId::RAM && k.from.off == *off =>
        {
            Some(Compact::Ref(*k))
        }
        _ => None,
    }
}

/// Checks the number of premises of a record.
pub(super) fn check(why: &Why) -> Result<(), Invalid> {
    if why.premises.len() > MAX_PREMISES {
        return Err(Invalid::TooMany {
            count: why.premises.len(),
            max: MAX_PREMISES,
        });
    }
    Ok(())
}

/// Makes the record of the compact value `s` of `key` again, with the rule list `rules`.
pub(super) fn expand(rules: &[RuleCode], key: &FactKey, s: Slim) -> Option<Why> {
    let rule = rules.get(usize::from(s.rule))?.clone();
    let premise = match key {
        FactKey::CodeUnit(_) => FactKey::Func(FuncId(Address::ram(s.entry))),
        FactKey::Ref(k) => FactKey::CodeUnit(k.from.off),
        _ => return None,
    };
    Some(Why {
        rule,
        premises: vec![premise],
    })
}

/// Gives the index of `rule` in `rules`. A new rule goes at the end. Gives `None` when the
/// list is full.
pub(super) fn intern(rules: &mut Vec<RuleCode>, rule: &RuleCode) -> Option<u16> {
    if let Some(i) = rules.iter().position(|r| r == rule) {
        return u16::try_from(i).ok();
    }
    let i = u16::try_from(rules.len()).ok()?;
    rules.push(rule.clone());
    Some(i)
}

impl PartialEq for WhyStore {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for WhyStore {}

impl WhyStore {
    /// Gives the number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map
            .len()
            .saturating_add(self.units.len())
            .saturating_add(self.refs.len())
    }

    /// Tells if the layer has no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gives the record of a fact.
    #[must_use]
    pub fn get(&self, key: &FactKey) -> Option<Why> {
        self.slim(key)
            .and_then(|s| self.expand(key, s))
            .or_else(|| self.map.get(key).cloned())
    }

    /// Tells if the layer has a record of `key`.
    #[must_use]
    pub fn contains(&self, key: &FactKey) -> bool {
        self.slim(key).is_some() || self.map.contains_key(key)
    }

    /// Gives all records in key order.
    pub fn iter(&self) -> impl Iterator<Item = (FactKey, Why)> + '_ {
        let units = self
            .units
            .iter()
            .map(|(at, s)| (FactKey::CodeUnit(*at), *s));
        let refs = self.refs.iter().map(|(k, s)| (FactKey::Ref(*k), *s));
        let slims = units.chain(refs).filter_map(|(key, s)| {
            let why = self.expand(&key, s)?;
            Some((key, why))
        });
        let general = self.map.iter().map(|(k, w)| (k.clone(), w.clone()));
        Merge {
            a: general.peekable(),
            b: slims.peekable(),
        }
    }

    /// Gives the compact value of `key`.
    fn slim(&self, key: &FactKey) -> Option<Slim> {
        match key {
            FactKey::CodeUnit(at) => self.units.get(at).copied(),
            FactKey::Ref(k) => self.refs.get(k).copied(),
            _ => None,
        }
    }

    /// Makes the record of the compact value `s` of `key` again.
    fn expand(&self, key: &FactKey, s: Slim) -> Option<Why> {
        expand(&self.rules, key, s)
    }

    /// Gives the index of `rule` in the rule list, or `None` when the list is full.
    fn rule_index(&mut self, rule: &RuleCode) -> Option<u16> {
        intern(&mut self.rules, rule)
    }

    /// Puts the record of `key` in its map. Gives the old record.
    fn put(&mut self, key: FactKey, why: Why) -> Option<Why> {
        let old = self.remove(&key);
        let slim = |store: &mut Self, entry: u64| {
            store.rule_index(&why.rule).map(|rule| Slim { entry, rule })
        };
        match compact(&key, &why) {
            Some(Compact::Unit(at, entry)) => {
                if let Some(s) = slim(self, entry) {
                    self.units.insert(at, s);
                    return old;
                }
            }
            Some(Compact::Ref(k)) => {
                if let Some(s) = slim(self, 0) {
                    self.refs.insert(k, s);
                    return old;
                }
            }
            None => {}
        }
        self.map.insert(key, why);
        old
    }

    /// Sets the record of a fact. Gives the old record.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises.
    pub(crate) fn insert(&mut self, key: FactKey, why: Why) -> Result<Option<Why>, Invalid> {
        check(&why)?;
        Ok(self.put(key, why))
    }

    /// Removes the record of a fact and gives it.
    pub(crate) fn remove(&mut self, key: &FactKey) -> Option<Why> {
        let slim = match key {
            FactKey::CodeUnit(at) => self.units.remove(at),
            FactKey::Ref(k) => self.refs.remove(k),
            _ => None,
        };
        match slim {
            Some(s) => self.expand(key, s),
            None => self.map.remove(key),
        }
    }

    /// Sets the records of `rows` in their order, as [`Self::insert`] does one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises. Then the store does not
    /// change.
    pub(crate) fn extend(&mut self, rows: Vec<(FactKey, Why)>) -> Result<(), Invalid> {
        self.extend_rows(WhyRows::from_rows(rows)?)
    }

    /// Sets the records of `rows`, as [`Self::insert`] does one at a time in push order.
    ///
    /// An empty store takes the packed maps of `rows` in one bulk build each, so each map has
    /// full nodes. One insert at a time in key order leaves each node about half full.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises. Each row of [`WhyRows`]
    /// passes this check on its push, so the error does not occur.
    pub(crate) fn extend_rows(&mut self, rows: WhyRows) -> Result<(), Invalid> {
        let WhyRows {
            map,
            units,
            refs,
            rules,
            loose,
            ..
        } = rows;
        if self.is_empty() {
            self.map = map.into_iter().collect();
            self.units = units.into_iter().collect();
            self.refs = refs.into_iter().collect();
            self.rules = rules;
        } else {
            for (key, why) in map {
                self.insert(key, why)?;
            }
            let units = units.into_iter().map(|(at, s)| (FactKey::CodeUnit(at), s));
            let refs = refs.into_iter().map(|(k, s)| (FactKey::Ref(k), s));
            for (key, s) in units.chain(refs) {
                if let Some(why) = expand(&rules, &key, s) {
                    self.insert(key, why)?;
                }
            }
        }
        for (key, why) in loose {
            self.insert(key, why)?;
        }
        Ok(())
    }
}

/// The merge of two record streams in key order. No key is in both streams.
struct Merge<A: Iterator, B: Iterator> {
    a: Peekable<A>,
    b: Peekable<B>,
}

impl<A, B> Iterator for Merge<A, B>
where
    A: Iterator<Item = (FactKey, Why)>,
    B: Iterator<Item = (FactKey, Why)>,
{
    type Item = (FactKey, Why);

    fn next(&mut self) -> Option<Self::Item> {
        let a_first = match (self.a.peek(), self.b.peek()) {
            (Some(x), Some(y)) => x.0 < y.0,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if a_first {
            self.a.next()
        } else {
            self.b.next()
        }
    }
}

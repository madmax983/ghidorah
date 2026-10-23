//! The store of the why-records of one layer.
//!
//! Most records of an analysis layer have one premise that follows from the key. The store
//! keeps these records in compact maps with no premise list:
//!
//! | Key | Premise | Compact value |
//! |---|---|---|
//! | `CodeUnit(at)` | `Func` at a RAM entry | the order, the entry and the rule |
//! | `Ref(k)` | `CodeUnit` at the RAM `from` of `k` | the order and the rule |
//!
//! Each other record goes in the general map. A key is in one map only. A read makes the
//! record of a compact value again, so the readers see the same records in the same order.

use std::collections::BTreeMap;
use std::iter::Peekable;

use ghidorah_base::{Address, FuncId, SpaceId};

use super::{FactKey, MAX_PREMISES, RuleCode, Why};
use crate::fact::Invalid;
use crate::refs::RefKey;

/// A record whose one premise follows from its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slim {
    /// The creation order.
    order: u64,
    /// The entry of the premise function of a code unit. A reference keeps 0.
    entry: u64,
    /// The index of the rule in [`WhyStore::rules`].
    rule: u16,
}

/// The why-records of one layer.
#[derive(Debug, Clone, Default)]
pub struct WhyStore {
    /// The records that have no compact form.
    map: BTreeMap<FactKey, (u64, Why)>,
    /// The records of code units with one premise function.
    units: BTreeMap<u64, Slim>,
    /// The records of references with the code unit of their source as the premise.
    refs: BTreeMap<RefKey, Slim>,
    /// The rule codes of the compact records. A record keeps the index of its rule.
    rules: Vec<RuleCode>,
    /// The creation order of the next new record.
    next: u64,
}

/// The compact form of a record.
enum Compact {
    /// A code unit at a RAM offset and the entry of its premise function.
    Unit(u64, u64),
    /// A reference.
    Ref(RefKey),
}

/// Gives the compact form of the record `why` of `key`, or `None` for a general record.
fn compact(key: &FactKey, why: &Why) -> Option<Compact> {
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
fn check(why: &Why) -> Result<(), Invalid> {
    if why.premises.len() > MAX_PREMISES {
        return Err(Invalid::TooMany {
            count: why.premises.len(),
            max: MAX_PREMISES,
        });
    }
    Ok(())
}

impl PartialEq for WhyStore {
    fn eq(&self, other: &Self) -> bool {
        self.next == other.next && self.len() == other.len() && self.iter().eq(other.iter())
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
            .or_else(|| self.map.get(key).map(|(_, w)| w.clone()))
    }

    /// Gives the creation order of the record of a fact.
    #[must_use]
    pub fn order(&self, key: &FactKey) -> Option<u64> {
        self.slim(key)
            .map(|s| s.order)
            .or_else(|| self.map.get(key).map(|(o, _)| *o))
    }

    /// Gives all records in key order with their creation order.
    pub fn iter(&self) -> impl Iterator<Item = (FactKey, u64, Why)> + '_ {
        let units = self
            .units
            .iter()
            .map(|(at, s)| (FactKey::CodeUnit(*at), *s));
        let refs = self.refs.iter().map(|(k, s)| (FactKey::Ref(*k), *s));
        let slims = units.chain(refs).filter_map(|(key, s)| {
            let why = self.expand(&key, s)?;
            Some((key, s.order, why))
        });
        let general = self
            .map
            .iter()
            .map(|(k, (o, w))| (k.clone(), *o, w.clone()));
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
        let rule = self.rules.get(usize::from(s.rule))?.clone();
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

    /// Gives the index of `rule` in the rule list, or `None` when the list is full.
    fn rule_index(&mut self, rule: &RuleCode) -> Option<u16> {
        if let Some(i) = self.rules.iter().position(|r| r == rule) {
            return u16::try_from(i).ok();
        }
        let i = u16::try_from(self.rules.len()).ok()?;
        self.rules.push(rule.clone());
        Some(i)
    }

    /// Puts the record of `key` with its order in its map. Gives the old record.
    fn put(&mut self, key: FactKey, order: u64, why: Why) -> Option<Why> {
        let old = self.remove(&key);
        let slim = |store: &mut Self, entry: u64| {
            store
                .rule_index(&why.rule)
                .map(|rule| Slim { order, entry, rule })
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
        self.map.insert(key, (order, why));
        old
    }

    /// Sets the record of a fact. The record gets the next creation order. Gives the old record.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises.
    pub(crate) fn insert(&mut self, key: FactKey, why: Why) -> Result<Option<Why>, Invalid> {
        check(&why)?;
        let order = self.next;
        self.next = self.next.saturating_add(1);
        Ok(self.put(key, order, why))
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
            None => self.map.remove(key).map(|(_, w)| w),
        }
    }

    /// Gives the creation order of the next new record.
    #[must_use]
    pub const fn next_order(&self) -> u64 {
        self.next
    }

    /// Sets the record of a fact with its creation order. Gives the old record.
    ///
    /// The next order stays above `order`. The JSON codec uses this function for an exact copy.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises.
    pub(crate) fn insert_at(
        &mut self,
        key: FactKey,
        order: u64,
        why: Why,
    ) -> Result<Option<Why>, Invalid> {
        check(&why)?;
        self.next = self.next.max(order.saturating_add(1));
        Ok(self.put(key, order, why))
    }

    /// Sets the records of `rows`, each with its creation order, as [`Self::insert_at`] does
    /// one at a time.
    ///
    /// When the store is empty and each key is above the key before it, one bulk build makes
    /// each map with full nodes. One insert at a time in key order leaves each node about
    /// half full.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises.
    pub(crate) fn extend_at(&mut self, rows: Vec<(FactKey, u64, Why)>) -> Result<(), Invalid> {
        let sorted = rows.windows(2).all(|w| matches!(w, [a, b] if a.0 < b.0));
        if !self.is_empty() || !sorted {
            for (key, order, why) in rows {
                self.insert_at(key, order, why)?;
            }
            return Ok(());
        }
        rows.iter().try_for_each(|r| check(&r.2))?;
        if let Some(top) = rows.iter().map(|r| r.1).max() {
            self.next = self.next.max(top.saturating_add(1));
        }
        let (mut map, mut units, mut refs) = (Vec::new(), Vec::new(), Vec::new());
        for (key, order, why) in rows {
            let shape = compact(&key, &why);
            let rule = shape.as_ref().and_then(|_| self.rule_index(&why.rule));
            match (shape, rule) {
                (Some(Compact::Unit(at, entry)), Some(rule)) => {
                    units.push((at, Slim { order, entry, rule }));
                }
                (Some(Compact::Ref(k)), Some(rule)) => {
                    refs.push((
                        k,
                        Slim {
                            order,
                            entry: 0,
                            rule,
                        },
                    ));
                }
                _ => map.push((key, (order, why))),
            }
        }
        self.map = map.into_iter().collect();
        self.units = units.into_iter().collect();
        self.refs = refs.into_iter().collect();
        Ok(())
    }

    /// Sets the creation order of the next new record. The order never goes below a stored order.
    pub(crate) fn set_next(&mut self, next: u64) {
        self.next = self.next.max(next);
    }
}

/// The merge of two record streams in key order. No key is in both streams.
struct Merge<A: Iterator, B: Iterator> {
    a: Peekable<A>,
    b: Peekable<B>,
}

impl<A, B> Iterator for Merge<A, B>
where
    A: Iterator<Item = (FactKey, u64, Why)>,
    B: Iterator<Item = (FactKey, u64, Why)>,
{
    type Item = (FactKey, u64, Why);

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

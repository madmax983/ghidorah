//! The why-records of a set before the order step.
//!
//! Most records have one premise that follows from the key. A code unit has its owner
//! function, and a flow or operand reference has the code unit of its source. The collection
//! keeps these records as compact values. [`Whys::records`] gives all records in key order,
//! and [`Rec::premise`] makes each premise when the walk reads it.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use ghidorah_base::{Address, FuncId, SpaceId};
use ghidorah_db::{FactKey, RefKey};

use crate::why::{Rule, Why};

/// The why-records of a set by key. A key is in one map only.
#[derive(Debug, Default)]
pub(crate) struct Whys {
    /// The records that have no compact form.
    general: BTreeMap<FactKey, Why>,
    /// The code unit records in key order: RAM offset, owner entry and rule.
    units: Vec<(u64, u64, Rule)>,
    /// The reference records with the code unit of their source as the premise.
    refs: BTreeMap<RefKey, Rule>,
}

impl Whys {
    /// Sets the record of `key`. A record of the key goes.
    pub(crate) fn insert(&mut self, key: FactKey, why: Why) {
        self.remove(&key);
        match (&key, why.premises.as_slice()) {
            (FactKey::CodeUnit(at), [FactKey::Func(FuncId(a))]) if a.space == SpaceId::RAM => {
                self.put_unit(*at, a.off, why.rule);
            }
            (FactKey::Ref(k), [FactKey::CodeUnit(off)])
                if k.from.space == SpaceId::RAM && k.from.off == *off =>
            {
                self.refs.insert(*k, why.rule);
            }
            _ => {
                self.general.insert(key, why);
            }
        }
    }

    /// Sets the record of the code unit at `at`: [`crate::why::unit_why`] of `owner`.
    pub(crate) fn insert_unit(&mut self, at: u64, owner: u64) {
        self.remove(&FactKey::CodeUnit(at));
        self.put_unit(at, owner, Rule::DisasmFlow);
    }

    /// Sets the record of the reference `key`: `rule` with the code unit at its RAM source.
    pub(crate) fn insert_ref(&mut self, key: RefKey, rule: Rule) {
        let premise = FactKey::CodeUnit(key.from.off);
        if key.from.space != SpaceId::RAM {
            self.insert(FactKey::Ref(key), Why::new(rule, vec![premise]));
            return;
        }
        self.remove(&FactKey::Ref(key));
        self.refs.insert(key, rule);
    }

    /// Removes the record of `key`.
    fn remove(&mut self, key: &FactKey) {
        match key {
            FactKey::CodeUnit(at) => {
                if let Ok(i) = self.units.binary_search_by_key(at, |u| u.0) {
                    self.units.remove(i);
                }
            }
            FactKey::Ref(k) => {
                self.refs.remove(k);
            }
            _ => {}
        }
        self.general.remove(key);
    }

    /// Puts a code unit record. The units come in address order, so the record goes at the
    /// end. Another record goes in its place by a search.
    fn put_unit(&mut self, at: u64, owner: u64, rule: Rule) {
        if self.units.last().is_none_or(|u| u.0 < at) {
            self.units.push((at, owner, rule));
            return;
        }
        match self.units.binary_search_by_key(&at, |u| u.0) {
            Ok(i) | Err(i) => self.units.insert(i, (at, owner, rule)),
        }
    }

    /// Gives every record in key order.
    pub(super) fn records(&self) -> Vec<Rec<'_>> {
        let units = self
            .units
            .iter()
            .map(|&(at, owner, rule)| Rec::Unit { at, owner, rule });
        let refs = self.refs.iter().map(|(k, r)| Rec::Ref(k, *r));
        let mut compact = units.chain(refs).peekable();
        let mut general = self
            .general
            .iter()
            .map(|(k, w)| Rec::General(k, w))
            .peekable();
        let mut out = Vec::with_capacity(
            self.general
                .len()
                .saturating_add(self.units.len())
                .saturating_add(self.refs.len()),
        );
        loop {
            let take_general = match (general.peek(), compact.peek()) {
                (Some(g), Some(c)) => c.cmp_key(&g.key()) == Ordering::Greater,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let next = if take_general {
                general.next()
            } else {
                compact.next()
            };
            out.extend(next);
        }
        out
    }
}

/// One why-record of [`Whys`].
#[derive(Debug, Clone, Copy)]
pub(super) enum Rec<'a> {
    /// A record with a premise list.
    General(&'a FactKey, &'a Why),
    /// A code unit with its owner function as the premise.
    Unit {
        /// The RAM offset of the unit.
        at: u64,
        /// The entry of the owner function.
        owner: u64,
        /// The rule.
        rule: Rule,
    },
    /// A reference with the code unit of its source as the premise.
    Ref(&'a RefKey, Rule),
}

impl Rec<'_> {
    /// Gives the key of the record.
    pub(super) fn key(&self) -> FactKey {
        match self {
            Self::General(k, _) => (*k).clone(),
            Self::Unit { at, .. } => FactKey::CodeUnit(*at),
            Self::Ref(k, _) => FactKey::Ref(**k),
        }
    }

    /// Compares the key of the record with `key`.
    pub(super) fn cmp_key(&self, key: &FactKey) -> Ordering {
        match self {
            Self::General(k, _) => (*k).cmp(key),
            _ => self.key().cmp(key),
        }
    }

    /// Gives the rule of the record.
    pub(super) const fn rule(&self) -> Rule {
        match self {
            Self::General(_, w) => w.rule,
            Self::Unit { rule, .. } | Self::Ref(_, rule) => *rule,
        }
    }

    /// Gives the number of premises.
    pub(super) const fn premise_count(&self) -> usize {
        match self {
            Self::General(_, w) => w.premises.len(),
            Self::Unit { .. } | Self::Ref(..) => 1,
        }
    }

    /// Gives premise `j`, or `None` past the last premise.
    pub(super) fn premise(&self, j: usize) -> Option<FactKey> {
        match (self, j) {
            (Self::General(_, w), _) => w.premises.get(j).cloned(),
            (Self::Unit { owner, .. }, 0) => Some(FactKey::Func(FuncId(Address::ram(*owner)))),
            (Self::Ref(k, _), 0) => Some(FactKey::CodeUnit(k.from.off)),
            _ => None,
        }
    }
}

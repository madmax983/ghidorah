//! The why-records of a new layer, packed as they come.
//!
//! A producer pushes the rows of a layer in key order: the publish step of the analysis and
//! the JSON decoder. Each push packs a record of a compact shape at once, so no list of all
//! full records exists. [`super::WhyStore`] takes the packed maps in one bulk build each.

use super::store::{Compact, Slim, check, compact, intern};
use super::{FactKey, RuleCode, Why};
use crate::fact::Invalid;
use crate::refs::RefKey;

/// The why-records of a new layer: key and record.
///
/// A row with a key above the key of the row before it goes into the packed maps. After the first row out of key order,
/// each row stays as it is. The store then sets these rows one at a time in push order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WhyRows {
    /// The general records in key order.
    pub(super) map: Vec<(FactKey, Why)>,
    /// The compact records of code units in key order.
    pub(super) units: Vec<(u64, Slim)>,
    /// The compact records of references in key order.
    pub(super) refs: Vec<(RefKey, Slim)>,
    /// The rule codes of the compact records.
    pub(super) rules: Vec<RuleCode>,
    /// The rows from the first row out of key order, in push order.
    pub(super) loose: Vec<(FactKey, Why)>,
    /// The key of the last packed row.
    pub(super) last: Option<FactKey>,
}

impl WhyRows {
    /// Makes an empty row list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes a row list from `rows` in their order.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`crate::why::MAX_PREMISES`] premises.
    pub fn from_rows(rows: impl IntoIterator<Item = (FactKey, Why)>) -> Result<Self, Invalid> {
        let mut out = Self::new();
        for (key, why) in rows {
            out.push(key, why)?;
        }
        Ok(out)
    }

    /// Gives the number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map
            .len()
            .saturating_add(self.units.len())
            .saturating_add(self.refs.len())
            .saturating_add(self.loose.len())
    }

    /// Tells if the list has no row.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds the record `why` of `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`crate::why::MAX_PREMISES`] premises. Then the
    /// list does not change.
    pub fn push(&mut self, key: FactKey, why: Why) -> Result<(), Invalid> {
        check(&why)?;
        let in_order = self.loose.is_empty() && self.last.as_ref().is_none_or(|l| *l < key);
        if !in_order {
            self.loose.push((key, why));
            return Ok(());
        }
        self.last = Some(key.clone());
        let shape = compact(&key, &why);
        let rule = shape
            .as_ref()
            .and_then(|_| intern(&mut self.rules, &why.rule));
        match (shape, rule) {
            (Some(Compact::Unit(at, entry)), Some(rule)) => {
                self.units.push((at, Slim { entry, rule }));
            }
            (Some(Compact::Ref(k)), Some(rule)) => {
                self.refs.push((k, Slim { entry: 0, rule }));
            }
            _ => self.map.push((key, why)),
        }
        Ok(())
    }
}

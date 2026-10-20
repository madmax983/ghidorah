//! The split of the budget of one function over its sections (design Section 10.9).
//!
//! The sections share the budget by weight in include order (`budget::section_weight`). A
//! section that needs less than its share gives the rest to the later sections. A section
//! with a share below the minimum, or a section that does not fit its share, goes to
//! `omitted`. Then its share comes back: the split runs again over the sections that stay,
//! so an earlier section can use the budget too. Each run drops at least one more section,
//! so the split ends after at most one run for each section.

use std::collections::BTreeMap;

use ghidorah_json::Value;

use crate::budget::section_weight;

/// The `why` of the call that reads an omitted `decomp` section alone.
pub const WHY_DECOMP: &str = "Read the C text of the function in a window of lines.";

/// The result of one section: its share, its need, its use and its value or its omitted
/// entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section name.
    pub name: &'static str,
    /// The characters of the share of the section.
    pub share: u64,
    /// The characters of the full section, or 0 for a share below the minimum.
    pub need: u64,
    /// The characters of the result that the section uses.
    pub used: u64,
    /// The value of the section, or its `omitted` entry.
    pub value: Result<Value, Value>,
}

/// Renders one section within a share. It gives the value or the omitted entry, the need and
/// the use.
pub type Renderer<'a> = dyn FnMut(&'static str, u64) -> (Result<Value, Value>, u64, u64) + 'a;

/// Splits `total` characters over the sections of `include` in include order. A share below
/// `min_share` gives the omitted entry `null` with no render.
pub fn split(
    total: u64,
    include: &[&'static str],
    min_share: u64,
    render: &mut Renderer<'_>,
) -> Vec<Section> {
    let mut out: BTreeMap<&'static str, Section> = BTreeMap::new();
    for _ in 0..=include.len() {
        let active: Vec<&'static str> = include
            .iter()
            .filter(|s| !out.contains_key(*s))
            .copied()
            .collect();
        let mut free = u128::from(total);
        let mut left: u128 = active.iter().map(|s| u128::from(section_weight(s))).sum();
        let mut kept = Vec::new();
        let mut dropped = false;
        for name in active {
            let weight = u128::from(section_weight(name));
            let share =
                u64::try_from(free.saturating_mul(weight) / left.max(1)).unwrap_or(u64::MAX);
            left = left.saturating_sub(weight);
            let (value, need, used) = if share < min_share {
                (Err(Value::Null), 0, 0)
            } else {
                render(name, share)
            };
            free = free.saturating_sub(u128::from(used));
            let section = Section {
                name,
                share,
                need,
                used,
                value,
            };
            if section.value.is_err() {
                dropped = true;
                out.insert(name, section);
            } else {
                kept.push(section);
            }
        }
        if !dropped {
            out.extend(kept.into_iter().map(|s| (s.name, s)));
            break;
        }
    }
    include.iter().filter_map(|s| out.remove(s)).collect()
}

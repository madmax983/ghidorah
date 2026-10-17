//! Did-you-mean candidates (design Section 10.5).
//!
//! The distance is the optimal string alignment form of the Damerau-Levenshtein distance
//! over characters. An adjacent transposition costs 1. The comparison ignores ASCII
//! letter case. The result holds at most [`MAX_SUGGESTIONS`] names, sorted by distance,
//! then by name.

use std::collections::BTreeSet;

use crate::fuel::Fuel;

/// The largest number of suggestions.
pub const MAX_SUGGESTIONS: usize = 5;

/// The longest query in characters. A longer query gives no suggestion.
pub const MAX_QUERY_CHARS: usize = 256;

/// One suggestion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Suggestion {
    /// The distance from the query.
    pub distance: usize,
    /// The suggested name.
    pub name: String,
}

/// Gives the largest distance of a suggestion for a query of `query_chars` characters.
///
/// The value is a third of the length, at least 1 and at most 4.
#[must_use]
pub const fn max_distance(query_chars: usize) -> usize {
    let third = query_chars / 3;
    if third < 1 {
        1
    } else if third > 4 {
        4
    } else {
        third
    }
}

/// Gives the characters of `text` with ASCII letters in lower case.
fn folded(text: &str) -> Vec<char> {
    text.chars().map(|c| c.to_ascii_lowercase()).collect()
}

/// Gives the optimal string alignment distance of two character slices.
fn osa(a: &[char], b: &[char]) -> usize {
    let mut before: Vec<usize> = vec![0; b.len() + 1];
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur: Vec<usize> = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            let mut best = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
            let swapped = i > 0 && j > 0 && ca == b[j - 1] && a[i - 1] == cb;
            if swapped {
                best = best.min(before[j - 1] + 1);
            }
            cur[j + 1] = best;
        }
        std::mem::swap(&mut before, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Gives the optimal string alignment distance of `a` and `b`, with ASCII case ignored.
#[must_use]
pub fn distance(a: &str, b: &str) -> usize {
    osa(&folded(a), &folded(b))
}

/// Gives the names nearest to `query`.
///
/// The result holds names within [`max_distance`] of the query, at most
/// [`MAX_SUGGESTIONS`], sorted by distance and then by name. Duplicate names count once.
/// Each comparison takes fuel. When the fuel runs out, the scan stops and the function
/// gives the best names so far. So give `names` in a fixed order.
pub fn did_you_mean<'a, I>(query: &str, names: I, fuel: &mut Fuel) -> Vec<Suggestion>
where
    I: IntoIterator<Item = &'a str>,
{
    let q = folded(query);
    if q.len() > MAX_QUERY_CHARS {
        return Vec::new();
    }
    let limit = max_distance(q.len());
    let longest = q.len() + limit;
    let mut best = BTreeSet::new();
    for name in names {
        if fuel.tick().is_err() {
            break;
        }
        let chars = name.chars().take(longest + 1).count();
        if chars.abs_diff(q.len()) > limit {
            continue;
        }
        let cost = u64::try_from((q.len() + 1) * (chars + 1)).unwrap_or(u64::MAX);
        if fuel.take(cost).is_err() {
            break;
        }
        let d = osa(&q, &folded(name));
        if d <= limit {
            best.insert(Suggestion {
                distance: d,
                name: name.to_string(),
            });
            if best.len() > MAX_SUGGESTIONS {
                best.pop_last();
            }
        }
    }
    best.into_iter().collect()
}

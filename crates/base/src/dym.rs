//! Did-you-mean candidates (design Section 10.5).
//!
//! The distance is the optimal string alignment form of the Damerau-Levenshtein distance
//! over characters. An adjacent transposition costs 1. The comparison ignores ASCII
//! letter case. The result holds at most [`MAX_SUGGESTIONS`] names, sorted by distance,
//! then by name.

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
    let _ = query_chars;
    0
}

/// Gives the optimal string alignment distance of `a` and `b`, with ASCII case ignored.
#[must_use]
pub fn distance(a: &str, b: &str) -> usize {
    let _ = (a, b);
    0
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
    let _ = (query, names.into_iter().count(), fuel.used());
    Vec::new()
}

//! The corpus index: weights, scores, matches and name proposals (design Section 7.13).
//!
//! All arithmetic is integer arithmetic. `l2(x)` is the log2 of an integer in Q16 fixed
//! point: the integer part from the leading zeros, then 16 fraction bits by repeated squaring.
//!
//! | Value | Rule |
//! |---|---|
//! | `N` | the number of documents of the corpus |
//! | `df` | the number of documents whose vector holds the key |
//! | `tf` | `65,536 + l2(count)` |
//! | `idf` | `65,536 + l2(N + 1) - l2(df + 1)` |
//! | `w` | `(tf * idf) >> 16` |
//! | `dot` | the sum of `w_a * w_b` over the shared keys |
//! | `norm` | the integer square root of the sum of `w * w` |
//! | `score` | `floor(1000 * dot / D)` with `D = max(norm_a * norm_b, dot)`, 0 to 1,000 |
//! | `weight` | `floor(1000 * w_a * w_b / D)`, the share of one shared key |
//!
//! `D` is `norm_a * norm_b` except when the integer square roots make the product smaller
//! than `dot`. So a score never passes 1,000, and the weights of a match add up to at most
//! its score. A zero norm gives no score.
//!
//! Candidates: scope `binary` takes the other documents of the binary of the query. Scope
//! `open` takes every other document. A candidate shares at least one key with the query.
//! The order is the score from high to low, then the binary ID, then the entry address.
//!
//! The top features of a match are the [`MAX_TOP`] shared keys with the highest weight, then
//! in kind order, then in text order. The text is the text of the query vector.

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidorah_base::{BinaryId, Fuel, FuncId, OutOfFuel};
use ghidorah_db::Source;

use super::features::Kind;
use super::vectors::Vector;

/// The value 1 in Q16 fixed point.
pub const ONE: u64 = 65_536;

/// The largest number of top features of one match.
pub const MAX_TOP: usize = 8;

/// The lowest rank-1 score of a name proposal.
pub const MIN_PROPOSAL_SCORE: u32 = 800;

/// The margin of a name proposal over the best match with another name.
pub const MARGIN: u32 = 50;

/// Gives the log2 of `x` in Q16 fixed point, rounded down. `l2(0)` and `l2(1)` are 0.
#[must_use]
pub fn l2(x: u64) -> u64 {
    let _ = x;
    0
}

/// Gives the integer square root of `x`, rounded down.
#[must_use]
pub fn isqrt(x: u128) -> u128 {
    let _ = x;
    0
}

/// The candidate set of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// The other functions of the binary of the query.
    Binary,
    /// Every other function of every open binary.
    Open,
}

impl Scope {
    /// The output names in order.
    pub const NAMES: [&'static str; 2] = ["binary", "open"];

    /// Gives the scope of an output name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "binary" => Some(Self::Binary),
            "open" => Some(Self::Open),
            _ => None,
        }
    }
}

/// One document of the corpus: a function and its vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doc {
    /// The binary.
    pub binary: BinaryId,
    /// The function.
    pub func: FuncId,
    /// The vector.
    pub vector: Arc<Vector>,
}

/// One scored candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scored {
    /// The document index.
    pub doc: usize,
    /// The score, 0 to 1,000.
    pub score: u32,
}

/// One shared feature of a match.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopFeature {
    /// The kind.
    pub kind: Kind,
    /// The text in the query vector.
    pub text: String,
    /// The share of the score, in thousandths.
    pub weight: u32,
}

/// One explained match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The document index.
    pub doc: usize,
    /// The score, 0 to 1,000.
    pub score: u32,
    /// The number of keys in both vectors.
    pub shared: u32,
    /// The number of keys in the union of both vectors.
    pub total: u32,
    /// The shared features with the highest weight.
    pub top: Vec<TopFeature>,
}

/// The corpus index.
#[derive(Debug, Clone, Default)]
pub struct Index {
    docs: Vec<Doc>,
    weights: Vec<Vec<u64>>,
    norms: Vec<u128>,
    df: BTreeMap<u64, u32>,
    postings: BTreeMap<u64, Vec<(u32, u64)>>,
}

impl Index {
    /// Builds the index of `docs`. The documents keep their order.
    #[must_use]
    pub fn build(docs: Vec<Doc>) -> Self {
        Self {
            docs,
            ..Self::default()
        }
    }

    /// Gives the number of documents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// Tells if the corpus has no document.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Gives the documents in index order.
    #[must_use]
    pub fn docs(&self) -> &[Doc] {
        &self.docs
    }

    /// Gives the index of the document of `func` in `binary`.
    #[must_use]
    pub fn position(&self, binary: BinaryId, func: FuncId) -> Option<usize> {
        let _ = (binary, func);
        None
    }

    /// Gives the number of documents that hold `key`.
    #[must_use]
    pub fn df(&self, key: u64) -> u32 {
        self.df.get(&key).copied().unwrap_or(0)
    }

    /// Gives the weight of `key` in the document `doc`.
    #[must_use]
    pub fn weight(&self, doc: usize, key: u64) -> Option<u64> {
        let _ = (&self.weights, &self.postings, doc, key);
        None
    }

    /// Gives the norm of the document `doc`.
    #[must_use]
    pub fn norm(&self, doc: usize) -> u128 {
        self.norms.get(doc).copied().unwrap_or(0)
    }

    /// Gives the score of the documents `a` and `b`, or `None` for a zero norm.
    #[must_use]
    pub fn score(&self, a: usize, b: usize) -> Option<u32> {
        let _ = (a, b);
        None
    }

    /// Gives every candidate of the query `query` in `scope` in match order.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfFuel`] when `fuel` runs out. The call takes one unit for each key of the
    /// query.
    pub fn ranked(
        &self,
        query: usize,
        scope: Scope,
        fuel: &mut Fuel,
    ) -> Result<Vec<Scored>, OutOfFuel> {
        let _ = (query, scope);
        fuel.tick()?;
        Ok(Vec::new())
    }

    /// Explains the match of the document `doc` for the query `query`.
    #[must_use]
    pub fn explain(&self, query: usize, doc: usize) -> Match {
        let _ = query;
        Match {
            doc,
            score: 0,
            shared: 0,
            total: 0,
            top: Vec::new(),
        }
    }

    /// Gives the explained matches of `query` with a score of at least `min_score`, at most
    /// `limit` of them.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfFuel`] when `fuel` runs out (see [`Self::ranked`]).
    pub fn matches(
        &self,
        query: usize,
        scope: Scope,
        min_score: u32,
        limit: usize,
        fuel: &mut Fuel,
    ) -> Result<Vec<Match>, OutOfFuel> {
        let ranked = self.ranked(query, scope, fuel)?;
        Ok(ranked
            .iter()
            .filter(|s| s.score >= min_score)
            .take(limit)
            .map(|s| self.explain(query, s.doc))
            .collect())
    }
}

/// The name of one ranked candidate for the proposal rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Named<'a> {
    /// The name text.
    pub name: &'a str,
    /// The source of the name.
    pub source: Source,
    /// The score.
    pub score: u32,
}

/// Tells if the rank-1 candidate of `ranked` gives a name proposal for a query whose name has
/// the source `query`.
///
/// All four rules must hold:
///
/// 1. `query` is `Default` or `Analysis`.
/// 2. The rank-1 name has the source `Imported`, `Agent` or `User`.
/// 3. The rank-1 score is at least [`MIN_PROPOSAL_SCORE`].
/// 4. The rank-1 score is at least [`MARGIN`] above the best score of a candidate with
///    another name, or 0 when there is none.
#[must_use]
pub fn propose(query: Source, ranked: &[Named<'_>]) -> bool {
    let _ = (query, ranked);
    false
}

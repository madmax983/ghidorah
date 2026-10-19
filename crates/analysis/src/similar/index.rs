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
    if x < 2 {
        return 0;
    }
    let n = x.ilog2();
    // The mantissa in [1, 2) with 63 fraction bits. The square of a value below 2^64 fits.
    let mut m = u128::from(x << (63 - n));
    let mut frac = 0u64;
    for _ in 0..16 {
        m = (m * m) >> 63;
        frac <<= 1;
        if m >> 64 != 0 {
            m >>= 1;
            frac |= 1;
        }
    }
    (u64::from(n) << 16) | frac
}

/// Gives the integer square root of `x`, rounded down.
#[must_use]
pub fn isqrt(x: u128) -> u128 {
    if x < 2 {
        return x;
    }
    let bits = 128 - x.leading_zeros();
    // A first value at or above the root. Newton steps from above go down to the floor.
    let mut r: u128 = 1 << bits.div_ceil(2);
    loop {
        let next = u128::midpoint(r, x / r);
        if next >= r {
            return r;
        }
        r = next;
    }
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
        let mut df: BTreeMap<u64, u32> = BTreeMap::new();
        for d in &docs {
            for e in d.vector.entries() {
                let n = df.entry(e.key).or_default();
                *n = n.saturating_add(1);
            }
        }
        let n = u64::try_from(docs.len()).unwrap_or(u64::MAX);
        let l2n = l2(n.saturating_add(1));
        let mut weights = Vec::with_capacity(docs.len());
        let mut norms = Vec::with_capacity(docs.len());
        let mut postings: BTreeMap<u64, Vec<(u32, u64)>> = BTreeMap::new();
        for (i, d) in docs.iter().enumerate() {
            let doc = u32::try_from(i).unwrap_or(u32::MAX);
            let mut list = Vec::with_capacity(d.vector.len());
            let mut sum: u128 = 0;
            for e in d.vector.entries() {
                let count = df.get(&e.key).copied().unwrap_or(1);
                let tf = ONE + l2(u64::from(e.count));
                let idf = (ONE + l2n).saturating_sub(l2(u64::from(count).saturating_add(1)));
                let w = u64::try_from((u128::from(tf) * u128::from(idf)) >> 16).unwrap_or(u64::MAX);
                sum = sum.saturating_add(u128::from(w) * u128::from(w));
                postings.entry(e.key).or_default().push((doc, w));
                list.push(w);
            }
            weights.push(list);
            norms.push(isqrt(sum));
        }
        Self {
            docs,
            weights,
            norms,
            df,
            postings,
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
        self.docs
            .iter()
            .position(|d| d.binary == binary && d.func == func)
    }

    /// Gives the number of documents that hold `key`.
    #[must_use]
    pub fn df(&self, key: u64) -> u32 {
        self.df.get(&key).copied().unwrap_or(0)
    }

    /// Gives the weight of `key` in the document `doc`.
    #[must_use]
    pub fn weight(&self, doc: usize, key: u64) -> Option<u64> {
        let entries = self.docs.get(doc)?.vector.entries();
        let i = entries.binary_search_by_key(&key, |e| e.key).ok()?;
        self.weights.get(doc)?.get(i).copied()
    }

    /// Gives the shared keys of `query` and `doc`: the entry index in `query` and the product
    /// of the two weights.
    fn shared(&self, query: usize, doc: usize) -> Vec<(usize, u128)> {
        let (Some(left), Some(right)) = (self.docs.get(query), self.docs.get(doc)) else {
            return Vec::new();
        };
        let weight = |d: usize, at: usize| {
            u128::from(
                self.weights
                    .get(d)
                    .and_then(|w| w.get(at))
                    .copied()
                    .unwrap_or(0),
            )
        };
        let (lhs, rhs) = (left.vector.entries(), right.vector.entries());
        let mut out = Vec::new();
        let (mut at_l, mut at_r) = (0, 0);
        while let (Some(l), Some(r)) = (lhs.get(at_l), rhs.get(at_r)) {
            match l.key.cmp(&r.key) {
                std::cmp::Ordering::Less => at_l += 1,
                std::cmp::Ordering::Greater => at_r += 1,
                std::cmp::Ordering::Equal => {
                    out.push((at_l, weight(query, at_l) * weight(doc, at_r)));
                    at_l += 1;
                    at_r += 1;
                }
            }
        }
        out
    }

    /// Gives the denominator `D = max(norm_a * norm_b, dot)`, or `None` for a zero norm.
    fn denominator(&self, a: usize, b: usize, dot: u128) -> Option<u128> {
        let product = self.norm(a).saturating_mul(self.norm(b));
        (product != 0).then(|| product.max(dot))
    }

    /// Gives the norm of the document `doc`.
    #[must_use]
    pub fn norm(&self, doc: usize) -> u128 {
        self.norms.get(doc).copied().unwrap_or(0)
    }

    /// Gives the score of the documents `a` and `b`, or `None` for a zero norm.
    #[must_use]
    pub fn score(&self, a: usize, b: usize) -> Option<u32> {
        let dot: u128 = self.shared(a, b).iter().map(|(_, p)| *p).sum();
        let d = self.denominator(a, b, dot)?;
        Some(per_mille(dot, d))
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
        let Some(q) = self.docs.get(query) else {
            return Ok(Vec::new());
        };
        if self.norm(query) == 0 {
            return Ok(Vec::new());
        }
        let mut dots: Vec<u128> = vec![0; self.docs.len()];
        let mut touched: Vec<usize> = Vec::new();
        let weights = self
            .weights
            .get(query)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for (e, wq) in q.vector.entries().iter().zip(weights) {
            fuel.tick()?;
            for (doc, w) in self
                .postings
                .get(&e.key)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let doc = usize::try_from(*doc).unwrap_or(usize::MAX);
                if let Some(slot) = dots.get_mut(doc) {
                    if *slot == 0 {
                        touched.push(doc);
                    }
                    *slot = slot.saturating_add(u128::from(*wq) * u128::from(*w));
                }
            }
        }
        let mut out: Vec<Scored> = touched
            .into_iter()
            .filter(|d| *d != query)
            .filter_map(|d| {
                let doc = self.docs.get(d)?;
                if scope == Scope::Binary && doc.binary != q.binary {
                    return None;
                }
                let dot = dots.get(d).copied().unwrap_or(0);
                let den = self.denominator(query, d, dot)?;
                Some(Scored {
                    doc: d,
                    score: per_mille(dot, den),
                })
            })
            .collect();
        out.sort_by_key(|s| {
            let d = self.docs.get(s.doc);
            (
                std::cmp::Reverse(s.score),
                d.map(|d| d.binary),
                d.map(|d| d.func),
            )
        });
        Ok(out)
    }

    /// Explains the match of the document `doc` for the query `query`.
    #[must_use]
    pub fn explain(&self, query: usize, doc: usize) -> Match {
        let shared = self.shared(query, doc);
        let dot: u128 = shared.iter().map(|(_, p)| *p).sum();
        let len = |d: usize| self.docs.get(d).map_or(0, |x| x.vector.len());
        let total = (len(query) + len(doc)).saturating_sub(shared.len());
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let Some(den) = self.denominator(query, doc, dot) else {
            return Match {
                doc,
                score: 0,
                shared: count(shared.len()),
                total: count(total),
                top: Vec::new(),
            };
        };
        let entries = self
            .docs
            .get(query)
            .map(|d| d.vector.entries())
            .unwrap_or_default();
        let mut top: Vec<TopFeature> = shared
            .iter()
            .filter_map(|(i, p)| {
                let e = entries.get(*i)?;
                Some(TopFeature {
                    kind: e.kind,
                    text: e.text.clone(),
                    weight: per_mille(*p, den),
                })
            })
            .collect();
        top.sort_by(|a, b| {
            b.weight
                .cmp(&a.weight)
                .then(a.kind.cmp(&b.kind))
                .then_with(|| a.text.cmp(&b.text))
        });
        top.truncate(MAX_TOP);
        Match {
            doc,
            score: per_mille(dot, den),
            shared: count(shared.len()),
            total: count(total),
            top,
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
    let Some(first) = ranked.first() else {
        return false;
    };
    let other = ranked
        .iter()
        .filter(|n| n.name != first.name)
        .map(|n| n.score)
        .max()
        .unwrap_or(0);
    matches!(query, Source::Default | Source::Analysis)
        && matches!(
            first.source,
            Source::Imported | Source::Agent | Source::User
        )
        && first.score >= MIN_PROPOSAL_SCORE
        && first.score >= other.saturating_add(MARGIN)
}

/// Gives `floor(1000 * x / d)` for `x <= d`, at most 1,000. A zero `d` gives 0.
fn per_mille(x: u128, d: u128) -> u32 {
    if d == 0 {
        return 0;
    }
    let v = x.saturating_mul(1_000) / d;
    u32::try_from(v.min(1_000)).unwrap_or(1_000)
}

//! Function similarity (design Section 7.13, ADR-0028).
//!
//! `func_similar` finds the functions of the open binaries that look like a query function.
//! Every step is deterministic and uses integer arithmetic. No output path uses a float or a
//! hash map.
//!
//! | Module | Content |
//! |---|---|
//! | [`features`] | The feature stream of one function: kinds, texts and keys |
//! | [`vectors`] | Sparse count vectors and the vector cache by `(FuncId, func_epoch)` |
//! | [`index`] | The corpus index: Q16 TF-IDF weights, cosine scores, matches and name proposals |
//!
//! The corpus is every function of every open binary. [`docs`] gives the vectors in binary ID
//! order, then in entry order, and [`corpus`] builds the index of these documents. Each new
//! vector goes into the cache at once, so a call that runs out of fuel keeps the vectors that
//! it built.

pub mod features;
pub mod index;
pub mod vectors;

use ghidorah_base::{Fuel, OutOfFuel};
use ghidorah_db::Program;

pub use features::{Context, Feature, Kind, MIN_CONST, bucket, feature_key, token};
pub use index::{
    Doc, Index, MARGIN, MAX_TOP, MIN_PROPOSAL_SCORE, Match, Named, ONE, Scope, Scored, TopFeature,
    isqrt, l2, propose,
};
pub use vectors::{
    CACHE_CAPACITY, CacheKey, Entry, MAX_COUNT, Stats, Vector, VectorCache, inputs_hash, key_of,
};

/// Builds the corpus index of `programs`: one document for each function of each program.
///
/// The documents are in binary ID order, then in entry order. A vector of `cache` with the
/// same [`CacheKey`] costs no fuel. Each vector that the call builds goes into `cache`.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out. The vectors built before the stop stay in
/// `cache`, so a second call with the same cache continues.
pub fn corpus(
    programs: &[&Program],
    cache: &mut VectorCache,
    fuel: &mut Fuel,
) -> Result<Index, OutOfFuel> {
    Ok(Index::build(docs(programs, cache, fuel)?))
}

/// Gives the documents of the corpus of `programs` in the order of [`corpus`].
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out (see [`corpus`]).
pub fn docs(
    programs: &[&Program],
    cache: &mut VectorCache,
    fuel: &mut Fuel,
) -> Result<Vec<Doc>, OutOfFuel> {
    let mut sorted: Vec<&Program> = programs.to_vec();
    sorted.sort_by_key(|p| p.meta().binary_id);
    let mut out = Vec::new();
    for program in sorted {
        let ctx = Context::new(program);
        let binary = program.meta().binary_id;
        for f in program.funcs() {
            let func = f.id();
            let vector = cache.vector(&ctx, func, fuel)?;
            out.push(Doc {
                binary,
                func,
                vector,
            });
        }
    }
    Ok(out)
}

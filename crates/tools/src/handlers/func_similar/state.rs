//! The vectors and the last corpus index of the worker thread.
//!
//! The MCP server runs every call on one worker thread. So the cache of the thread keeps the
//! vectors between calls, and a call after a fuel stop continues with them. The last index
//! stays while each document of the corpus has the same function and the same vector.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use ghidorah_analysis::similar::{self, Doc, Index, VectorCache};
use ghidorah_base::{Fuel, OutOfFuel};
use ghidorah_db::Program;

/// The cache of one thread.
#[derive(Debug, Default)]
struct State {
    vectors: VectorCache,
    last: Option<Rc<Index>>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Tells if `docs` are the documents of `index`: the same functions with the same vectors.
fn same(index: &Index, docs: &[Doc]) -> bool {
    index.docs().len() == docs.len()
        && index.docs().iter().zip(docs).all(|(a, b)| {
            a.binary == b.binary && a.func == b.func && Arc::ptr_eq(&a.vector, &b.vector)
        })
}

/// Gives the corpus index of `programs`.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when the vectors that the cache does not hold need more fuel than
/// `fuel` gives. The vectors that the call builds stay in the cache.
pub fn index(programs: &[&Program], fuel: &mut Fuel) -> Result<Rc<Index>, OutOfFuel> {
    STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        let docs = similar::docs(programs, &mut state.vectors, fuel)?;
        if let Some(last) = &state.last
            && same(last, &docs)
        {
            return Ok(Rc::clone(last));
        }
        let index = Rc::new(Index::build(docs));
        state.last = Some(Rc::clone(&index));
        Ok(index)
    })
}

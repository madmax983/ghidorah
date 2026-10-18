//! Claims over the facts of a program and why trees (design Section 11.8, ADR-0023).
//!
//! `fact_check`, the `claim` guards of `batch_run`, hypothesis notes and the eval answer
//! checkers use the same atoms. Each verdict is `supported`, `refuted` or `unknown`:
//!
//! | Relation | Supported when | Refuted only when |
//! |---|---|---|
//! | `calls(f, g)` | an edge f -> g: a call, a tail-call jump, an override target or a syscall site | f has no gap and no edge to g |
//! | `reaches(f, g, d)` | a path of at most d edges | no function of the slice has a gap |
//! | `uses_import(f, i)` | f calls i or refers to its stub, slot or EXTERNAL address | f has no gap and no such reference |
//! | `refs_string(f, glob)` | f refers to a string that matches | f has no gap and no reference to a pointer slot |
//! | `refs_addr(f, a)` | f refers to a | f has no gap and no reference to a pointer slot |
//! | `xref(from, to, kind)` | the reference exists | from is an analyzed instruction that is not a gap |
//! | `const_arg(callee, index, value)` | a call site passes the value | each call site has a known value, and the callee has no unresolved caller |
//! | `has_syscall(f, name)` | f has the syscall site | each syscall site of f has a number, and f has no unresolved jump |
//! | `noreturn(f)` | the noreturn flag is set | f has a return instruction |
//! | `in_func(a, f)` | the body of f holds a | another function owns a |
//!
//! A gap is an indirect call or jump with no target: no call or jump reference, no resolved
//! jump table and no `IndirectTargets` override. A site with an override counts as resolved.
//! `basis.gaps` lists the gaps that block a negative verdict. A `refuted` verdict is sound.

pub mod check;
pub mod explain;
pub mod relations;

pub use check::Checker;
pub use explain::{ExplainError, Node, explain, fact_name, key_of};
pub use relations::{
    Atom, CATALOG, ColKind, Column, Endpoint, Evidence, Gap, NAMES, Outcome, RefClass, RelSpec,
    Relation, Verdict,
};

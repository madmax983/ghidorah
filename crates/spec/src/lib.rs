//! Std-only stub of the Verus attributes and the `proof!` macro (ADR-0011).
//!
//! Plain `cargo` builds of `ghidorah-kernel` use this crate. Verus builds use `vstd` in its place.
//! So the verified code is the shipped code.
//!
//! | Item | Plain build |
//! |---|---|
//! | `#[verus_spec(..)]` | Gives the item without a change. |
//! | `#[verus_verify]` | Gives the item without a change. |
//! | `proof! { .. }` | Expands to nothing. |
//!
//! Stable rustc rejects an attribute macro on a loop statement (E0658).
//! So a loop uses `#[cfg_attr(verus_only, verus_spec(..))]` and never this stub.

use proc_macro::TokenStream;

/// Gives the item without a change.
///
/// Verus reads the `requires`, `ensures` and `invariant` clauses of the argument.
/// A plain build drops the argument.
#[proc_macro_attribute]
pub fn verus_spec(spec: TokenStream, item: TokenStream) -> TokenStream {
    drop(spec);
    item
}

/// Gives the item without a change.
///
/// Verus verifies a struct, an enum, an impl or a const that has this attribute.
#[proc_macro_attribute]
pub fn verus_verify(args: TokenStream, item: TokenStream) -> TokenStream {
    drop(args);
    item
}

/// Expands to nothing.
///
/// Verus reads the ghost code of the body. A plain build drops the body.
#[proc_macro]
pub fn proof(body: TokenStream) -> TokenStream {
    drop(body);
    TokenStream::new()
}

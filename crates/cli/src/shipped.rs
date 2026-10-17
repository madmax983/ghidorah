//! The backend of the `ghidorah` binary.
//!
//! [`Shipped`] names the one backend type of the binary. Tests that run the shipped registry
//! use this name, so they follow the binary.

/// The backend of the `ghidorah` binary.
pub type Shipped = crate::bare::Bare;

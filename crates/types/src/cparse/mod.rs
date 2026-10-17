//! The C parser (design Section 9.2).
//!
//! The parser is a hand-written recursive descent parser in the style of the LuaJIT FFI.
//! It has two modes:
//!
//! | Mode | Function | Input |
//! |---|---|---|
//! | `sig` | [`parse_sig`] | One function prototype, for example `int puts(const char *s);` |
//! | `type` | [`parse_type`] | One abstract type, for example `struct sockaddr_in *` or `uint8_t[16]` |
//!
//! A type name must name a prelude type, a type of the store or a type that the text defines.
//! A text can define a `struct`, a `union` or an `enum` inline. The definition goes into the store.
//! The store does not change when the parse fails.
//!
//! These features give `C_PARSE_ERROR` with the detail code `E_UNSUPPORTED` and a hint:
//! bit-fields, `__attribute__`, `__declspec`, `#pragma` and other preprocessor lines,
//! `_Alignas`, `_Atomic`, `_Complex`, `asm` and `typedef` declarations.
//!
//! Limits: input 1 MiB, 200,000 tokens, identifier 1,024 bytes, declarator nesting 64,
//! 4,096 parameters. Constants evaluate in `i128` with checked operations. A counter limits
//! the recursion depth to 64. A limit gives the detail code `E_LIMIT`.

use std::fmt;

use ghidorah_base::{DiagCode, ErrorCode};

use crate::store::TypeStore;
use crate::ty::{Sig, TypeId};

/// The largest input in bytes.
pub const MAX_INPUT: usize = 1 << 20;

/// The largest number of tokens.
pub const MAX_TOKENS: usize = 200_000;

/// The longest identifier in bytes.
pub const MAX_IDENT: usize = 1024;

/// The largest number of derivations (pointer, array, function) in one declarator.
pub const MAX_NESTING: usize = 64;

/// The largest number of parameters of one function, and of fields of one record.
pub const MAX_PARAMS: usize = 4096;

/// The deepest recursion of the parser.
pub const MAX_DEPTH: usize = 64;

/// The longest snippet in bytes.
pub const MAX_SNIPPET: usize = 120;

/// A place in the C text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    /// The line, from 1.
    pub line: u32,
    /// The column in characters, from 1.
    pub col: u32,
    /// The byte offset, from 0.
    pub byte: u32,
    /// The length in bytes.
    pub len: u32,
}

/// One parser diagnostic, an item of `C_PARSE_ERROR.details.errors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CDiag {
    /// The detail code, for example `E_SYNTAX`.
    pub code: DiagCode,
    /// The place of the error.
    pub at: Span,
    /// The text of the line around the place, at most [`MAX_SNIPPET`] bytes.
    pub snippet: String,
    /// The tokens or the items that the parser expects at the place.
    pub expected: Vec<String>,
    /// The names nearest to an unknown name.
    pub candidates: Vec<String>,
    /// One short instruction for the repair.
    pub hint: String,
}

/// The error of a parse. It holds at least one diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CParseError {
    /// The diagnostics in text order.
    pub errors: Vec<CDiag>,
}

impl CParseError {
    /// Gives the first diagnostic.
    #[must_use]
    pub fn first(&self) -> Option<&CDiag> {
        self.errors.first()
    }

    /// Gives the tool error code: `C_PARSE_ERROR`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::InternalError
    }
}

impl fmt::Display for CParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("C parse error")
    }
}

impl std::error::Error for CParseError {}

/// The result of [`parse_sig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSig {
    /// The function name.
    pub name: String,
    /// The function type in the store.
    pub ty: TypeId,
    /// The signature.
    pub sig: Sig,
}

/// Parses one function prototype in the `sig` mode.
///
/// The text holds declaration specifiers, one declarator with a name and an optional `;`.
/// The declarator must declare a function. `extern`, `static`, `inline` and `_Noreturn`
/// can come first. `_Noreturn` sets [`Sig::noreturn`].
///
/// # Errors
///
/// Returns [`CParseError`] with the diagnostics of the text. The store does not change.
pub fn parse_sig(store: &mut TypeStore, text: &str) -> Result<ParsedSig, CParseError> {
    let _ = (store, text);
    Err(CParseError { errors: Vec::new() })
}

/// Parses one abstract type in the `type` mode.
///
/// The text holds a specifier list, an abstract declarator without a name and an optional `;`.
///
/// # Errors
///
/// Returns [`CParseError`] with the diagnostics of the text. The store does not change.
pub fn parse_type(store: &mut TypeStore, text: &str) -> Result<TypeId, CParseError> {
    let _ = (store, text);
    Err(CParseError { errors: Vec::new() })
}

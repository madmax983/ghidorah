//! Shared helpers of the type tests.

use std::path::PathBuf;

use ghidorah_base::DiagCode;
use ghidorah_types::{CDiag, CParseError, TypeId, TypeStore, parse_type};

/// The stack size of the bomb tests (design Section 9.2).
pub const SMALL_STACK: usize = 256 * 1024;

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Makes a store with the prelude.
pub fn store() -> TypeStore {
    TypeStore::with_prelude().expect("the prelude installs")
}

/// Parses a type that must parse.
pub fn ty(store: &mut TypeStore, text: &str) -> TypeId {
    parse_type(store, text).unwrap_or_else(|e| panic!("`{text}` must parse: {e}"))
}

/// Gives the first diagnostic of a parse error.
pub fn first(err: &CParseError) -> &CDiag {
    err.first().expect("a parse error holds a diagnostic")
}

/// Gives the 1-based line and column of the byte offset `at` in an ASCII `text`.
pub fn line_col(text: &str, at: usize) -> (u32, u32) {
    let before = &text[..at];
    let line = before.matches('\n').count() + 1;
    let col = at - before.rfind('\n').map_or(0, |i| i + 1) + 1;
    (
        u32::try_from(line).expect("small"),
        u32::try_from(col).expect("small"),
    )
}

/// Gives the byte offset of the first `needle` in `text`.
pub fn offset(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is not in `{text}`"))
}

/// Checks the code and the place of the first diagnostic. `at` is the byte offset.
pub fn assert_diag(text: &str, err: &CParseError, code: DiagCode, at: usize) {
    let d = first(err);
    assert_eq!(d.code, code, "code of `{text}`: {d:?}");
    let (line, col) = line_col(text, at);
    assert_eq!(
        (d.at.line, d.at.col, d.at.byte as usize),
        (line, col, at),
        "place of `{text}`: {d:?}"
    );
}

/// Runs `body` in a thread with a stack of [`SMALL_STACK`] bytes.
pub fn in_small_stack<T: Send>(body: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("small-stack".to_string())
            .stack_size(SMALL_STACK)
            .spawn_scoped(scope, body)
            .expect("the thread starts")
            .join()
            .expect("the thread does not panic")
    })
}

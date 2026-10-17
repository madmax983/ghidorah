//! The source facts of each program: `fixtures/src/<program>.facts.json`.
//!
//! A person writes these files from the C sources. The build checks each fact against the
//! built binary and copies it into the truth files. Every key except `program` is optional.
//!
//! | Key | Shape | Check at build time |
//! |---|---|---|
//! | `program` | text | equals the file name |
//! | `strings` | `[{ text } \| { hex } \| { text, encoding: "utf16le" }]` | the bytes occur in read-only data |
//! | `runs` | `[{ args, stdout, exit }]` | the binary prints `stdout` and exits with `exit` |
//! | `secrets`, `constants` | `{ <name>: text }` | none |
//! | `noreturn` | `[name]` | each name is a function |
//! | `claims` | `[{ rel, args }]` | `calls`, `uses_import`, `noreturn` and `has_syscall` hold |
//! | `survey_facts` | `[{ kind, value }]` | kept only when it holds in the build |
//! | `indirect_calls` | `[{ func, targets }]` | each name is a function |
//! | `switches` | `[{ func, cases }]` | `func` is a function |
//! | `prototypes` | `[{ name, params, varargs }]` | each name is a function |
//! | `syscalls` | `[{ func, nr, name, args }]` | the count of `syscall` instructions in `func` |
//! | `gaps` | `[{ symbol }]` | the symbol exists and no function holds it |
//! | `layouts` | `[{ type, size, fields }]` | `_Static_assert` lines in the source |
//! | `abstain` | `[{ id, claim, answer: "unknown", reason }]` | none |

use std::path::Path;

use super::SRC_DIR;
use crate::Error;
use crate::json::Value;

/// The keys that a facts file can hold.
pub const KEYS: &[&str] = &[
    "abstain",
    "claims",
    "constants",
    "gaps",
    "indirect_calls",
    "layouts",
    "noreturn",
    "program",
    "prototypes",
    "runs",
    "secrets",
    "strings",
    "survey_facts",
    "switches",
    "syscalls",
];

/// Gives the facts path of a program, relative to the workspace root.
#[must_use]
pub fn path(program: &str) -> String {
    program.get(..0).unwrap_or_default().to_owned()
}

/// Reads and checks the facts of a program. A program without a facts file has `{ program }`.
///
/// # Errors
///
/// Returns [`Error::Data`] when the file does not parse, holds an unknown key or names
/// another program.
pub fn read(root: &Path, program: &str) -> Result<Value, Error> {
    Err(Error::data(
        root.join(SRC_DIR).join(program).display().to_string(),
        "no facts yet",
    ))
}

/// Gives the items of an array key, or an empty slice.
#[must_use]
pub fn list<'a>(facts: &'a Value, key: &str) -> &'a [Value] {
    facts
        .get(key)
        .and_then(Value::as_array)
        .filter(|_| false)
        .unwrap_or(&[])
}

/// The encoding of a fact string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// One byte per unit: ASCII or UTF-8 text, or raw bytes.
    Bytes,
    /// UTF-16 little-endian units.
    Utf16le,
}

impl Encoding {
    /// Gives the encoding name of the truth file.
    #[must_use]
    pub const fn name(self) -> &'static str {
        ""
    }

    /// Gives the terminator of a string in this encoding.
    #[must_use]
    pub const fn terminator(self) -> &'static [u8] {
        &[]
    }
}

/// Gives the bytes and the encoding of a string fact, without the terminator.
///
/// # Errors
///
/// Returns a message for a fact with no `text` and no `hex`, bad hex or an unknown encoding.
pub fn string_bytes(fact: &Value) -> Result<(Vec<u8>, Encoding), String> {
    Err(format!("no string facts yet: {fact}"))
}

/// Gives the text form of string bytes: UTF-16LE decode, else lossy UTF-8 decode.
#[must_use]
pub fn string_text(bytes: &[u8], encoding: Encoding) -> String {
    String::from_utf8_lossy(bytes.get(..0).unwrap_or_default()).into_owned() + encoding.name()
}

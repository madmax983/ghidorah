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
use crate::json::{self, Value};

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
    format!("{SRC_DIR}/{program}.facts.json")
}

/// Reads and checks the facts of a program. A program without a facts file has `{ program }`.
///
/// # Errors
///
/// Returns [`Error::Data`] when the file does not parse, holds an unknown key or names
/// another program.
pub fn read(root: &Path, program: &str) -> Result<Value, Error> {
    let rel = path(program);
    let full = root.join(&rel);
    if !full.exists() {
        return Ok(Value::object([("program", Value::from(program))]));
    }
    let text = std::fs::read_to_string(&full).map_err(|e| Error::io(&full, e))?;
    let value = json::parse(&text).map_err(|e| Error::data(&rel, e.to_string()))?;
    let members = value
        .as_object()
        .ok_or_else(|| Error::data(&rel, "the facts are not an object"))?;
    if let Some(key) = members.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(Error::data(&rel, format!("unknown key `{key}`")));
    }
    if value.get("program").and_then(Value::as_str) != Some(program) {
        return Err(Error::data(&rel, "`program` differs from the file name"));
    }
    Ok(value)
}

/// Gives the items of an array key, or an empty slice.
#[must_use]
pub fn list<'a>(facts: &'a Value, key: &str) -> &'a [Value] {
    facts.get(key).and_then(Value::as_array).unwrap_or(&[])
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
        match self {
            Self::Bytes => "bytes",
            Self::Utf16le => "utf16le",
        }
    }

    /// Gives the terminator of a string in this encoding.
    #[must_use]
    pub const fn terminator(self) -> &'static [u8] {
        match self {
            Self::Bytes => &[0],
            Self::Utf16le => &[0, 0],
        }
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

/// Gives the bytes and the encoding of a string fact, without the terminator.
///
/// # Errors
///
/// Returns a message for a fact with no `text` and no `hex`, bad hex or an unknown encoding.
pub fn string_bytes(fact: &Value) -> Result<(Vec<u8>, Encoding), String> {
    let encoding = match fact.get("encoding").and_then(Value::as_str) {
        None => Encoding::Bytes,
        Some("utf16le") => Encoding::Utf16le,
        Some(other) => return Err(format!("unknown encoding `{other}`")),
    };
    if let Some(h) = fact.get("hex").and_then(Value::as_str) {
        return unhex(h)
            .map(|b| (b, encoding))
            .ok_or_else(|| format!("bad hex `{h}`"));
    }
    let text = fact
        .get("text")
        .and_then(Value::as_str)
        .ok_or("a string fact needs `text` or `hex`")?;
    let bytes = match encoding {
        Encoding::Bytes => text.as_bytes().to_vec(),
        Encoding::Utf16le => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    };
    Ok((bytes, encoding))
}

/// Gives the text form of string bytes: UTF-16LE decode, else lossy UTF-8 decode.
#[must_use]
pub fn string_text(bytes: &[u8], encoding: Encoding) -> String {
    match encoding {
        Encoding::Bytes => String::from_utf8_lossy(bytes).into_owned(),
        Encoding::Utf16le => {
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|c| {
                    u16::from_le_bytes([
                        c.first().copied().unwrap_or(0),
                        c.get(1).copied().unwrap_or(0),
                    ])
                })
                .collect();
            String::from_utf16_lossy(&units)
        }
    }
}

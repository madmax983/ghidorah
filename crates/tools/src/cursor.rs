//! Keyset cursors (design Section 10.9, ADR-0021).
//!
//! A cursor is the lower case hex text of these bytes:
//!
//! | Bytes | Field |
//! |---|---|
//! | 1 | The format version [`VERSION`] |
//! | 2 | The tool index in the registry, little-endian |
//! | 8 | The args hash: SHA-256 of the JCS of the query, see [`args_hash`] |
//! | 1 | The section: 0 for a list page, else a `func_get` section |
//! | 1 + 8 | A flag and the analysis rev of an analysis-derived sort key |
//! | 1 + parts | The part count and the parts of the sort key of the last returned item |
//! | 4 | The check: the high 4 bytes of FNV-1a 64 over the bytes before it |
//!
//! A key part is `0` and a `u64`, or `1`, a `u32` length and UTF-8 bytes. Numbers are
//! little-endian. A cursor above [`MAX_CURSOR_CHARS`] characters keeps its key in the [`Spill`]
//! store of the session instead: the part count is [`SPILLED`], and the FNV-1a 64 hash of the
//! key bytes follows it.
//!
//! Decode errors:
//!
//! | Cause | Code |
//! |---|---|
//! | The text is not hex, the check fails, the version, tool, section or args hash differ | `CURSOR_INVALID` |
//! | A spilled key that the store does not hold | `CURSOR_INVALID` |
//! | An analysis-derived sort key, and the analysis rev changed | `CURSOR_STALE` |
//!
//! Edits never make a cursor stale. The tools with a name sort check the boundary item.

use std::collections::{BTreeMap, VecDeque};

use ghidorah_base::{ErrorCode, fnv1a64, hex, sha256};
use ghidorah_json::{Object, Value};

use crate::args::Args;
use crate::dispatch::{CursorCall, KeyPart, SortKey};
use crate::envelope::Frame;
use crate::errors::ToolError;

/// The format version of a cursor.
pub const VERSION: u8 = 1;

/// The longest cursor text. It equals the cap of the `cursor` argument.
pub const MAX_CURSOR_CHARS: usize = 1_024;

/// The values of the `sort` argument that give analysis-derived sort keys.
pub const ANALYSIS_SORTS: [&str; 3] = ["size", "priority", "in_degree"];

/// The arguments that the args hash leaves out: paging, budget, form and attribution.
pub const PAGING_ARGS: [&str; 8] = [
    "cursor",
    "limit",
    "count_only",
    "shape",
    "fields",
    "format",
    "max_chars",
    "session",
];

/// The largest number of keys in a [`Spill`] store.
pub const SPILL_CAP: usize = 1_024;

/// The largest number of parts in a sort key in the cursor bytes.
pub const MAX_PARTS: usize = 8;

/// The part count of a key in the spill store.
pub const SPILLED: u8 = 0xff;

/// The bytes before the key: version, tool, args hash, section, flag and analysis rev.
const HEAD: usize = 21;

/// The bytes of the check.
const CHECK: usize = 4;

/// The fields of one cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// The tool index in the registry.
    pub tool_index: u16,
    /// The args hash of the query.
    pub args_hash: [u8; 8],
    /// The section: 0 for a list page.
    pub section: u8,
    /// The analysis rev of an analysis-derived sort key.
    pub analysis_rev: Option<u64>,
    /// The sort key of the last returned item.
    pub key: SortKey,
}

/// The store of long sort keys, keyed by the FNV-1a 64 hash of the key bytes.
///
/// The store keeps at most [`SPILL_CAP`] keys. The oldest key goes first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spill {
    keys: BTreeMap<u64, SortKey>,
    order: VecDeque<u64>,
}

impl Spill {
    /// Makes an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Tells if the store holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Puts `key` in the store and gives its hash.
    pub fn put(&mut self, key: &SortKey) -> u64 {
        let hash = fnv1a64(&key_bytes(key));
        if self.keys.insert(hash, key.clone()).is_none() {
            self.order.push_back(hash);
        }
        while self.keys.len() > SPILL_CAP {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            self.keys.remove(&old);
        }
        hash
    }

    /// Gives the key with the hash `hash`, or `None`.
    #[must_use]
    pub fn get(&self, hash: u64) -> Option<&SortKey> {
        self.keys.get(&hash)
    }
}

/// Gives the args hash of a query: the first 8 bytes of the SHA-256 of the JCS of an object.
///
/// The object holds the tool arguments with their defaults, the `in` set and the bound binary.
/// The arguments of [`PAGING_ARGS`] are not in it.
#[must_use]
pub fn args_hash(args: &Args, frame: &Frame) -> [u8; 8] {
    let mut object = Object::new();
    for (name, value) in args.values() {
        if !PAGING_ARGS.contains(&name) {
            object.push(name, value.clone());
        }
    }
    if let Some(set) = &args.globals().in_set {
        object.push("$in", Value::from(set.as_str()));
    }
    if let Some(id) = &frame.binary_id {
        object.push("$binary", Value::from(id.as_str()));
    }
    let value = Value::Object(object);
    let text = ghidorah_json::write_jcs(&value).unwrap_or_else(|_| ghidorah_json::write(&value));
    let digest = sha256(text.as_bytes());
    let mut out = [0u8; 8];
    for (dst, src) in out.iter_mut().zip(digest) {
        *dst = src;
    }
    out
}

/// Tells if the query sorts by an analysis-derived key: its `sort` is in [`ANALYSIS_SORTS`].
#[must_use]
pub fn analysis_derived(args: &Args) -> bool {
    args.str("sort")
        .is_some_and(|sort| ANALYSIS_SORTS.contains(&sort))
}

/// Gives the bytes of the parts of `key`.
fn key_bytes(key: &SortKey) -> Vec<u8> {
    let mut out = Vec::new();
    for part in &key.0 {
        match part {
            KeyPart::Int(v) => {
                out.push(0);
                out.extend_from_slice(&v.to_le_bytes());
            }
            KeyPart::Text(text) => {
                out.push(1);
                let len = u32::try_from(text.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(text.as_bytes());
            }
        }
    }
    out
}

/// Gives the check of `bytes`: the high 4 bytes of their FNV-1a 64 hash.
fn check(bytes: &[u8]) -> [u8; CHECK] {
    let [a, b, c, d, ..] = fnv1a64(bytes).to_be_bytes();
    [a, b, c, d]
}

/// Gives the `CURSOR_INVALID` error.
fn invalid() -> ToolError {
    ToolError::new(ErrorCode::CursorInvalid)
}

/// A reader of cursor bytes. Each read checks the length first.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ToolError> {
        if n > self.bytes.len() {
            return Err(invalid());
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ToolError> {
        self.take(1)?.first().copied().ok_or_else(invalid)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ToolError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| invalid())
    }

    fn u64(&mut self) -> Result<u64, ToolError> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    fn part(&mut self) -> Result<KeyPart, ToolError> {
        match self.u8()? {
            0 => self.u64().map(KeyPart::Int),
            1 => {
                let len = usize::try_from(u32::from_le_bytes(self.array::<4>()?))
                    .map_err(|_| invalid())?;
                let text = std::str::from_utf8(self.take(len)?).map_err(|_| invalid())?;
                Ok(KeyPart::Text(text.to_owned()))
            }
            _ => Err(invalid()),
        }
    }
}

impl Cursor {
    /// Makes the cursor of `call` after the item with `key` in `section`.
    ///
    /// The cursor keeps the analysis rev of the frame when the sort key is analysis-derived.
    #[must_use]
    pub fn of_call(call: &CursorCall<'_>, key: &SortKey, section: u8) -> Self {
        let analysis_rev = if analysis_derived(call.args) {
            call.frame.analysis.map(|a| a.rev)
        } else {
            None
        };
        Self {
            tool_index: u16::try_from(call.tool_index).unwrap_or(u16::MAX),
            args_hash: args_hash(call.args, call.frame),
            section,
            analysis_rev,
            key: key.clone(),
        }
    }

    /// Gives the bytes before the key.
    fn head(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD);
        out.push(VERSION);
        out.extend_from_slice(&self.tool_index.to_le_bytes());
        out.extend_from_slice(&self.args_hash);
        out.push(self.section);
        out.push(u8::from(self.analysis_rev.is_some()));
        out.extend_from_slice(&self.analysis_rev.unwrap_or(0).to_le_bytes());
        out
    }

    /// Gives the cursor bytes. A long key goes into `spill`.
    #[must_use]
    pub fn to_bytes(&self, spill: &mut Spill) -> Vec<u8> {
        let mut out = self.head();
        let parts = u8::try_from(self.key.0.len())
            .ok()
            .filter(|n| usize::from(*n) <= MAX_PARTS);
        let inline = key_bytes(&self.key);
        let fits = HEAD + 1 + inline.len() + CHECK <= MAX_CURSOR_CHARS / 2;
        match parts {
            Some(n) if fits => {
                out.push(n);
                out.extend_from_slice(&inline);
            }
            _ => {
                out.push(SPILLED);
                out.extend_from_slice(&spill.put(&self.key).to_le_bytes());
            }
        }
        let sum = check(&out);
        out.extend_from_slice(&sum);
        out
    }

    /// Reads the cursor bytes. A spilled key comes from `spill`.
    ///
    /// # Errors
    ///
    /// Returns `CURSOR_INVALID` for bytes that are cut, have extra bytes, fail the check or
    /// name a key that `spill` does not hold.
    pub fn from_bytes(bytes: &[u8], spill: &Spill) -> Result<Self, ToolError> {
        let body_len = bytes.len().checked_sub(CHECK).ok_or_else(invalid)?;
        let (body, sum) = bytes.split_at(body_len);
        if check(body) != sum {
            return Err(invalid());
        }
        let mut r = Reader { bytes: body };
        if r.u8()? != VERSION {
            return Err(invalid());
        }
        let tool_index = u16::from_le_bytes(r.array::<2>()?);
        let args_hash = r.array::<8>()?;
        let section = r.u8()?;
        let flag = r.u8()?;
        let rev = r.u64()?;
        let analysis_rev = match flag {
            0 if rev == 0 => None,
            1 => Some(rev),
            _ => return Err(invalid()),
        };
        let count = r.u8()?;
        let key = if count == SPILLED {
            spill.get(r.u64()?).cloned().ok_or_else(invalid)?
        } else if usize::from(count) <= MAX_PARTS {
            let mut parts = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                parts.push(r.part()?);
            }
            SortKey(parts)
        } else {
            return Err(invalid());
        };
        if !r.bytes.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            tool_index,
            args_hash,
            section,
            analysis_rev,
            key,
        })
    }
}

/// Gives the cursor text of `call` after the item with `key` in `section`.
#[must_use]
pub fn encode(call: &CursorCall<'_>, key: &SortKey, section: u8, spill: &mut Spill) -> String {
    hex::encode(&Cursor::of_call(call, key, section).to_bytes(spill))
}

/// Gives the sort key of the cursor `text` of `call` in `section`.
///
/// # Errors
///
/// Returns `CURSOR_INVALID` or `CURSOR_STALE` as the module docs say.
pub fn decode(
    call: &CursorCall<'_>,
    text: &str,
    section: u8,
    spill: &Spill,
) -> Result<SortKey, ToolError> {
    let lower = text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if text.is_empty() || text.len() > MAX_CURSOR_CHARS || !lower {
        return Err(invalid());
    }
    let bytes = hex::decode(text).map_err(|_| invalid())?;
    let cursor = Cursor::from_bytes(&bytes, spill)?;
    let want = Cursor::of_call(call, &cursor.key, section);
    if cursor.tool_index != want.tool_index
        || cursor.args_hash != want.args_hash
        || cursor.section != want.section
    {
        return Err(invalid());
    }
    if cursor.analysis_rev != want.analysis_rev {
        return Err(ToolError::new(ErrorCode::CursorStale));
    }
    Ok(cursor.key)
}

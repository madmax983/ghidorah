//! Provenance facts, session labels and write errors (design Section 3.6).
//!
//! A [`Fact`] is a value with its [`Origin`]: the source, the transaction, the session label
//! and the force flag. Each manager write goes through the crate functions `put` or
//! `put_slot`. These functions apply the write rule of [`write_rule`].
//! A refused write gives [`Blocked`] with the current fact, so the caller can report it.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ghidorah_base::{Address, ErrorCode, FuncId, NoteId, Range, TxId};

use crate::source::{Source, write_rule};

/// The longest session label in bytes.
pub const MAX_LABEL: usize = 64;

/// A session label: 1 to [`MAX_LABEL`] bytes of `[A-Za-z0-9._-]`.
///
/// A label is for attribution, filters and the undo scope. It never changes a rank.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionLabel(Arc<str>);

impl SessionLabel {
    /// The label of the facts that [`Program::from_binary`](crate::Program::from_binary) writes.
    pub const LOAD: &'static str = "load";

    /// The label of the facts that the analysis engine writes.
    pub const ANALYSIS: &'static str = "analysis";

    /// Makes a label.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::BadLabel`] for an empty label, a label above [`MAX_LABEL`] bytes or
    /// a byte outside `[A-Za-z0-9._-]`.
    pub fn new(text: &str) -> Result<Self, Invalid> {
        let byte_ok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        if text.is_empty() || text.len() > MAX_LABEL || !text.bytes().all(byte_ok) {
            return Err(Invalid::BadLabel);
        }
        Ok(Self(Arc::from(text)))
    }

    /// Gives the label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Makes a label from a constant that obeys the grammar.
    fn constant(text: &'static str) -> Self {
        Self(Arc::from(text))
    }
}

impl fmt::Display for SessionLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who writes a fact: the source, the transaction, the session and the force flag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    /// The source rank of the write.
    pub source: Source,
    /// The transaction of the write.
    pub tx: TxId,
    /// The session label.
    pub session: SessionLabel,
    /// The write uses `force: true`.
    pub force: bool,
}

impl Origin {
    /// Makes an origin.
    #[must_use]
    pub const fn new(source: Source, tx: TxId, session: SessionLabel, force: bool) -> Self {
        Self {
            source,
            tx,
            session,
            force,
        }
    }

    /// The origin of the facts of the binary: `Imported`, transaction 0, session `load`.
    #[must_use]
    pub fn load() -> Self {
        Self::new(
            Source::Imported,
            TxId(0),
            SessionLabel::constant(SessionLabel::LOAD),
            false,
        )
    }

    /// The origin of analysis facts: `Analysis`, transaction 0, session `analysis`.
    #[must_use]
    pub fn analysis() -> Self {
        Self::new(
            Source::Analysis,
            TxId(0),
            SessionLabel::constant(SessionLabel::ANALYSIS),
            false,
        )
    }

    /// Makes a fact with this origin.
    #[must_use]
    pub fn fact<T>(&self, value: T) -> Fact<T> {
        Fact {
            value,
            source: self.source,
            tx: self.tx,
            session: self.session.clone(),
            force: self.force,
        }
    }
}

/// A value with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fact<T> {
    /// The value.
    pub value: T,
    /// The source rank.
    pub source: Source,
    /// The transaction that wrote the fact.
    pub tx: TxId,
    /// The session that wrote the fact.
    pub session: SessionLabel,
    /// The write used `force: true`.
    pub force: bool,
}

impl<T> Fact<T> {
    /// Gives the origin of the fact.
    #[must_use]
    pub fn origin(&self) -> Origin {
        Origin::new(self.source, self.tx, self.session.clone(), self.force)
    }
}

/// A write that the rule refuses: `BLOCKED_BY_HIGHER_PRIORITY_SOURCE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked<T> {
    /// The current fact. Error details show its value and its source.
    pub current: Fact<T>,
    /// The source of the refused write.
    pub attempted: Source,
    /// The refused write used `force: true`.
    pub force: bool,
}

impl<T> Blocked<T> {
    /// Tells if the same write with `force: true` succeeds. Then `next[0]` repeats it so.
    #[must_use]
    pub fn force_applies(&self) -> bool {
        write_rule(self.current.source, self.attempted, true).is_allowed()
    }

    /// Gives the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::BlockedByHigherPrioritySource
    }
}

impl<T> fmt::Display for Blocked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "A fact with the source {} (rank {}) blocks the write with the source {} (rank {}).",
            self.current.source,
            self.current.source.rank(),
            self.attempted,
            self.attempted.rank()
        )
    }
}

/// A write that breaks a rule of its table. The table does not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// The write has the source `Default`. The DB never stores a default.
    DefaultSource,
    /// The session label does not obey its grammar.
    BadLabel,
    /// The name is empty.
    EmptyName,
    /// Another symbol at the address has the name.
    DuplicateName(String),
    /// The text is longer than its cap.
    TooLong {
        /// The length in bytes or characters.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// The list holds more items than its cap.
    TooMany {
        /// The item count.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// The address is not in the RAM space.
    NotRam(Address),
    /// The length is 0, or the end goes past `u64::MAX`.
    BadLength(u64),
    /// The new range overlaps a range of the table.
    Overlap {
        /// The new range.
        new: Range,
        /// The range of the table.
        existing: Range,
    },
    /// A function body does not hold the entry.
    EntryOutsideBody(Address),
    /// The function already exists.
    FuncExists(FuncId),
    /// The function does not exist.
    NoFunc(FuncId),
    /// Another note owns the set name.
    SetNameTaken {
        /// The set name.
        name: String,
        /// The note that owns it.
        owner: NoteId,
    },
    /// A note of kind `set` needs a set, and a note of another kind has none.
    SetMismatch,
    /// Address members and ID members do not mix.
    SetKinds,
    /// An evidence entry does not parse as an ID.
    BadEvidence(String),
    /// The source cannot write this table.
    BadSource(Source),
}

impl Invalid {
    /// Gives the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::TooLong { .. } | Self::TooMany { .. } => ErrorCode::LimitExceeded,
            Self::Overlap { .. } | Self::FuncExists(_) => ErrorCode::BodyOverlap,
            Self::NoFunc(_) => ErrorCode::NotFound,
            Self::SetNameTaken { .. } | Self::DuplicateName(_) => ErrorCode::Conflict,
            _ => ErrorCode::InvalidArgument,
        }
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultSource => f.write_str("A write cannot have the source default."),
            Self::BadLabel => f.write_str("A session label has 1 to 64 bytes of [A-Za-z0-9._-]."),
            Self::EmptyName => f.write_str("The name is empty."),
            Self::DuplicateName(name) => {
                write!(f, "Another symbol at the address has the name {name:?}.")
            }
            Self::TooLong { len, max } => write!(f, "The text has {len} units. The cap is {max}."),
            Self::TooMany { count, max } => {
                write!(f, "The list has {count} items. The cap is {max}.")
            }
            Self::NotRam(a) => write!(f, "The address {a} is not in the RAM space."),
            Self::BadLength(len) => write!(f, "The length {len:#x} is not valid here."),
            Self::Overlap { new, existing } => write!(
                f,
                "The range [{:#x}, {:#x}] overlaps the range [{:#x}, {:#x}].",
                new.first, new.last, existing.first, existing.last
            ),
            Self::EntryOutsideBody(a) => write!(f, "The body does not hold the entry {a}."),
            Self::FuncExists(id) => write!(f, "The function {id} exists."),
            Self::NoFunc(id) => write!(f, "The function {id} does not exist."),
            Self::SetNameTaken { name, owner } => {
                write!(f, "The note {owner} owns the set name {name}.")
            }
            Self::SetMismatch => f.write_str("Only a note of kind set has a set."),
            Self::SetKinds => f.write_str("A set holds addresses or IDs, not both."),
            Self::BadEvidence(text) => write!(f, "The evidence {text:?} is not an ID."),
            Self::BadSource(s) => write!(f, "The source {s} cannot write this table."),
        }
    }
}

impl std::error::Error for Invalid {}

/// The error of a manager write. The table does not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError<T> {
    /// A fact of a higher rank blocks the write.
    Blocked(Box<Blocked<T>>),
    /// The write breaks a rule of the table.
    Invalid(Invalid),
}

impl<T> WriteError<T> {
    /// Gives the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Blocked(b) => b.code(),
            Self::Invalid(i) => i.code(),
        }
    }
}

impl<T> From<Invalid> for WriteError<T> {
    fn from(value: Invalid) -> Self {
        Self::Invalid(value)
    }
}

impl<T> fmt::Display for WriteError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked(b) => b.fmt(f),
            Self::Invalid(i) => i.fmt(f),
        }
    }
}

impl<T: fmt::Debug> std::error::Error for WriteError<T> {}

/// Checks a write with `origin` over the fact `current`.
///
/// # Errors
///
/// Returns [`Invalid::DefaultSource`] for a write with the source `Default`, and
/// [`WriteError::Blocked`] when the write rule refuses the write.
pub(crate) fn check<T: Clone>(
    current: Option<&Fact<T>>,
    origin: &Origin,
) -> Result<(), WriteError<T>> {
    if origin.source == Source::Default {
        return Err(Invalid::DefaultSource.into());
    }
    match current {
        Some(cur) if !write_rule(cur.source, origin.source, origin.force).is_allowed() => {
            Err(WriteError::Blocked(Box::new(Blocked {
                current: cur.clone(),
                attempted: origin.source,
                force: origin.force,
            })))
        }
        _ => Ok(()),
    }
}

/// Writes `value` into `slot` by the write rule. `None` removes the fact. Gives the old fact.
///
/// # Errors
///
/// Returns the error of [`check`]. Then `slot` does not change.
pub(crate) fn put_slot<T: Clone>(
    slot: &mut Option<Fact<T>>,
    value: Option<T>,
    origin: &Origin,
) -> Result<Option<Fact<T>>, WriteError<T>> {
    check(slot.as_ref(), origin)?;
    Ok(std::mem::replace(slot, value.map(|v| origin.fact(v))))
}

/// Writes `value` at `key` of `map` by the write rule. `None` removes the fact.
/// Gives the old fact.
///
/// # Errors
///
/// Returns the error of [`check`]. Then `map` does not change.
pub(crate) fn put<K: Ord, T: Clone>(
    map: &mut BTreeMap<K, Fact<T>>,
    key: K,
    value: Option<T>,
    origin: &Origin,
) -> Result<Option<Fact<T>>, WriteError<T>> {
    check(map.get(&key), origin)?;
    Ok(match value {
        Some(v) => map.insert(key, origin.fact(v)),
        None => map.remove(&key),
    })
}

/// Gives the fact of the higher rank. A tie gives `a`.
#[must_use]
pub fn higher<'a, T>(a: Option<&'a Fact<T>>, b: Option<&'a Fact<T>>) -> Option<&'a Fact<T>> {
    match (a, b) {
        (Some(x), Some(y)) if y.source > x.source => Some(y),
        (Some(x), _) => Some(x),
        (None, y) => y,
    }
}

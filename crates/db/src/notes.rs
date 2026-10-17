//! The note store and the named sets (design Section 10.7, ADR-0023).
//!
//! Notes, bookmarks, hypotheses, findings, todos and named sets are one store. A note of kind
//! `set` owns one set name, and `set:<name>` finds it. Address sets use the kernel
//! [`RangeSet`]. ID sets are sorted vectors without duplicates.
//!
//! | Op | Address set | ID set |
//! |---|---|---|
//! | `replace` | the new members | the new members |
//! | `union` | [`RangeSet::union`] | sorted merge |
//! | `intersect` | [`RangeSet::intersect`] | the IDs in both |
//! | `subtract` | [`RangeSet::subtract`] | the IDs of the first set only |

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, FuncId, Id, NoteId, Range, Rev, SetName};
use ghidorah_kernel::RangeSet;

use crate::fact::{Invalid, SessionLabel};
use crate::source::Source;

/// The longest note text in characters.
pub const MAX_TEXT: usize = 4000;

/// The largest number of tags, evidence IDs or claims of one note.
pub const MAX_ITEMS: usize = 64;

/// The largest number of ID members of one set.
pub const MAX_MEMBERS: usize = 65_536;

/// The kind of a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoteKind {
    /// A plain note or bookmark.
    Note,
    /// A task.
    Todo,
    /// A hypothesis with claims.
    Hypothesis,
    /// A finding.
    Finding,
    /// An error report.
    Error,
    /// A named set.
    Set,
}

impl NoteKind {
    /// All kinds.
    pub const ALL: [Self; 6] = [
        Self::Note,
        Self::Todo,
        Self::Hypothesis,
        Self::Finding,
        Self::Error,
        Self::Set,
    ];

    /// Gives the output name, for example `hypothesis`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Todo => "todo",
            Self::Hypothesis => "hypothesis",
            Self::Finding => "finding",
            Self::Error => "error",
            Self::Set => "set",
        }
    }

    /// Gives the kind of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl fmt::Display for NoteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The status of a note. The agent sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoteStatus {
    /// Open.
    Open,
    /// Confirmed.
    Confirmed,
    /// Refuted.
    Refuted,
    /// Done.
    Done,
}

impl NoteStatus {
    /// All statuses.
    pub const ALL: [Self; 4] = [Self::Open, Self::Confirmed, Self::Refuted, Self::Done];

    /// Gives the output name, for example `open`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Confirmed => "confirmed",
            Self::Refuted => "refuted",
            Self::Done => "done",
        }
    }

    /// Gives the status of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }
}

impl fmt::Display for NoteStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One claim: a relation name and its ID arguments (design Section 11.8).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Claim {
    /// The relation name, for example `calls`.
    pub rel: String,
    /// The arguments in relation order.
    pub args: Vec<String>,
}

/// The members of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetMembers {
    /// RAM addresses.
    Addrs(RangeSet),
    /// ID texts in sorted order without duplicates.
    Ids(Vec<String>),
}

/// An operation of set algebra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SetOp {
    /// The new members replace the old members.
    Replace,
    /// The members of both sets.
    Union,
    /// The members in both sets.
    Intersect,
    /// The old members that are not new members.
    Subtract,
}

impl SetMembers {
    /// Makes an ID set: sorted, without duplicates.
    #[must_use]
    pub fn ids(mut ids: Vec<String>) -> Self {
        ids.sort_unstable();
        ids.dedup();
        Self::Ids(ids)
    }

    /// Gives the number of members: addresses or IDs. An address set can hold 2^64 values.
    #[must_use]
    pub fn count(&self) -> u128 {
        match self {
            Self::Addrs(set) => set.ranges().iter().map(Range::len).sum(),
            Self::Ids(ids) => u128::try_from(ids.len()).unwrap_or(u128::MAX),
        }
    }

    /// Applies `op` with the members `other`. Gives the new members.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::SetKinds`] when one set holds addresses and the other holds IDs,
    /// unless `op` is `Replace`.
    pub fn apply(&self, op: SetOp, other: &Self) -> Result<Self, Invalid> {
        match (self, other) {
            (Self::Addrs(a), Self::Addrs(b)) => Ok(Self::Addrs(match op {
                SetOp::Replace => b.clone(),
                SetOp::Union => a.union(b),
                SetOp::Intersect => a.intersect(b),
                SetOp::Subtract => a.subtract(b),
            })),
            (Self::Ids(a), Self::Ids(b)) => {
                let in_b: BTreeSet<&String> = b.iter().collect();
                let out: Vec<String> = match op {
                    SetOp::Replace => b.clone(),
                    SetOp::Union => a.iter().chain(b).cloned().collect(),
                    SetOp::Intersect => a.iter().filter(|x| in_b.contains(x)).cloned().collect(),
                    SetOp::Subtract => a.iter().filter(|x| !in_b.contains(x)).cloned().collect(),
                };
                Ok(Self::ids(out))
            }
            _ if op == SetOp::Replace => Ok(other.clone()),
            _ => Err(Invalid::SetKinds),
        }
    }
}

/// A named set of a note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSet {
    /// The set name. `set:<name>` finds the note.
    pub name: SetName,
    /// The members.
    pub members: SetMembers,
}

/// One note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The ID.
    pub id: NoteId,
    /// The kind.
    pub kind: NoteKind,
    /// The text, at most [`MAX_TEXT`] characters.
    pub text: String,
    /// The address that the note is about.
    pub at: Option<Address>,
    /// The function that the note is about.
    pub func: Option<FuncId>,
    /// The status.
    pub status: NoteStatus,
    /// The tags.
    pub tags: Vec<String>,
    /// The evidence: ID texts that parse.
    pub evidence: Vec<String>,
    /// The claims.
    pub claims: Vec<Claim>,
    /// The set of a note of kind `set`.
    pub set: Option<NoteSet>,
    /// `Agent` or `User`.
    pub src: Source,
    /// The session that wrote the note.
    pub session: SessionLabel,
    /// The revision of the last write.
    pub rev: Rev,
}

/// The note store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes {
    map: BTreeMap<NoteId, Note>,
    sets: BTreeMap<SetName, NoteId>,
    next: u64,
}

impl Notes {
    /// Gives the number of notes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the store has no note.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives a note.
    #[must_use]
    pub fn get(&self, id: NoteId) -> Option<&Note> {
        self.map.get(&id)
    }

    /// Gives all notes in ID order.
    pub fn iter(&self) -> impl Iterator<Item = &Note> {
        self.map.values()
    }

    /// Gives the note that owns the set `name`.
    #[must_use]
    pub fn set(&self, name: &SetName) -> Option<&Note> {
        self.sets.get(name).and_then(|id| self.map.get(id))
    }

    /// Gives the set names in name order with their notes.
    pub fn sets(&self) -> impl Iterator<Item = (&SetName, NoteId)> {
        self.sets.iter().map(|(n, id)| (n, *id))
    }

    /// Gives the ID of the next new note. IDs start at 1 and never come back.
    #[must_use]
    pub fn next_id(&self) -> NoteId {
        NoteId(self.next.max(1))
    }

    /// Checks the rules of the module doc for `note`.
    fn check(&self, note: &Note) -> Result<(), Invalid> {
        if !matches!(note.src, Source::Agent | Source::User) {
            return Err(Invalid::BadSource(note.src));
        }
        let len = note.text.chars().count();
        if len > MAX_TEXT {
            return Err(Invalid::TooLong { len, max: MAX_TEXT });
        }
        for count in [note.tags.len(), note.evidence.len(), note.claims.len()] {
            if count > MAX_ITEMS {
                return Err(Invalid::TooMany {
                    count,
                    max: MAX_ITEMS,
                });
            }
        }
        check_ids(&note.evidence)?;
        if note.set.is_some() != (note.kind == NoteKind::Set) {
            return Err(Invalid::SetMismatch);
        }
        if let Some(set) = &note.set {
            if let SetMembers::Ids(ids) = &set.members {
                if ids.len() > MAX_MEMBERS {
                    return Err(Invalid::TooMany {
                        count: ids.len(),
                        max: MAX_MEMBERS,
                    });
                }
                check_ids(ids)?;
            }
            if let Some(owner) = self.sets.get(&set.name)
                && *owner != note.id
            {
                return Err(Invalid::SetNameTaken {
                    name: set.name.as_str().to_string(),
                    owner: *owner,
                });
            }
        }
        Ok(())
    }

    /// Removes the set name of `note` from the index.
    fn unlink(&mut self, note: &Note) {
        if let Some(set) = &note.set {
            self.sets.remove(&set.name);
        }
    }

    /// Writes a note: a new note or a change of the note with its ID. Gives the old note.
    ///
    /// The ID members of a set change to sorted order without duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid`] when the note breaks a rule: the text cap, the item caps, the
    /// set rules, an evidence entry that does not parse or a source other than `Agent` and
    /// `User`. Then the store does not change.
    pub(crate) fn write(&mut self, mut note: Note) -> Result<Option<Note>, Invalid> {
        self.check(&note)?;
        if let Some(NoteSet {
            members: SetMembers::Ids(ids),
            ..
        }) = &mut note.set
        {
            ids.sort_unstable();
            ids.dedup();
        }
        let id = note.id;
        let name = note.set.as_ref().map(|s| s.name.clone());
        let old = self.map.insert(id, note);
        if let Some(old) = &old {
            self.unlink(old);
        }
        if let Some(name) = name {
            self.sets.insert(name, id);
        }
        self.next = self.next.max(id.0.saturating_add(1));
        Ok(old)
    }

    /// Removes a note and its set name. Gives the note.
    pub(crate) fn delete(&mut self, id: NoteId) -> Option<Note> {
        let note = self.map.remove(&id)?;
        self.unlink(&note);
        Some(note)
    }
}

/// Checks that each text parses as an ID.
fn check_ids(items: &[String]) -> Result<(), Invalid> {
    match items.iter().find(|t| Id::parse(t).is_err()) {
        Some(bad) => Err(Invalid::BadEvidence(bad.clone())),
        None => Ok(()),
    }
}

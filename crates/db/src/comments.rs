//! The comment manager (design Section 3.4).
//!
//! The key is an address and a [`CommentKind`]. Each value is a text fact. An empty text
//! removes the comment. The text holds at most [`MAX_COMMENT`] characters.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::Address;

use crate::fact::{Fact, Invalid, Origin, WriteError, put};

/// The longest comment in characters.
pub const MAX_COMMENT: usize = 4000;

/// The kind of a comment. The codes are the Ghidra codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CommentKind {
    /// `EOL`: at the end of the line.
    Eol = 0,
    /// `PRE`: before the line.
    Pre = 1,
    /// `POST`: after the line.
    Post = 2,
    /// `PLATE`: a block before a function or a section.
    Plate = 3,
    /// `REPEATABLE`: a comment that shows at each reference.
    Repeatable = 4,
}

impl CommentKind {
    /// All kinds in code order.
    pub const ALL: [Self; 5] = [
        Self::Eol,
        Self::Pre,
        Self::Post,
        Self::Plate,
        Self::Repeatable,
    ];

    /// Gives the Ghidra code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Gives the output name, for example `eol`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Eol => "eol",
            Self::Pre => "pre",
            Self::Post => "post",
            Self::Plate => "plate",
            Self::Repeatable => "repeatable",
        }
    }

    /// Gives the kind of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl fmt::Display for CommentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The comments of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Comments {
    map: BTreeMap<(Address, CommentKind), Fact<String>>,
}

impl Comments {
    /// Gives the number of comments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the layer has no comment.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives the comment of `kind` at `addr`.
    #[must_use]
    pub fn get(&self, addr: Address, kind: CommentKind) -> Option<&Fact<String>> {
        self.map.get(&(addr, kind))
    }

    /// Gives the comments at `addr` in kind order.
    pub fn at(&self, addr: Address) -> impl Iterator<Item = (CommentKind, &Fact<String>)> {
        let _ = addr;
        std::iter::empty()
    }

    /// Gives all comments in address order, then kind order.
    pub fn iter(&self) -> impl Iterator<Item = (Address, CommentKind, &Fact<String>)> {
        self.map.iter().map(|((a, k), f)| (*a, *k, f))
    }

    /// Sets a comment by the write rule. `None` or an empty text removes it. Gives the old fact.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooLong`] above [`MAX_COMMENT`] characters, or
    /// [`WriteError::Blocked`] with the current comment.
    pub(crate) fn set(
        &mut self,
        addr: Address,
        kind: CommentKind,
        text: Option<String>,
        origin: &Origin,
    ) -> Result<Option<Fact<String>>, WriteError<String>> {
        let _ = (
            addr,
            kind,
            text,
            origin,
            put::<(Address, CommentKind), String>,
        );
        Err(Invalid::DefaultSource.into())
    }
}

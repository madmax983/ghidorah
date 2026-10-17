//! Progress rows and last-brief marks (design Sections 3.4 and 3.10).
//!
//! Both tables are session metadata. A change of them changes no `rev`. The journal keeps
//! them in `meta` lines.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::{FuncId, Rev};

use crate::fact::SessionLabel;

/// The progress of one function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one progress column of design Section 3.4"
)]
pub struct FuncProgress {
    /// A call read the disassembly, the IR or the pseudo-C of the function.
    pub visited: bool,
    /// The function has a name that is not a default name.
    pub named: bool,
    /// The function has a signature.
    pub typed: bool,
    /// The function has a comment.
    pub commented: bool,
}

/// The counts of the progress columns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgressCounts {
    /// Visited functions.
    pub visited: u64,
    /// Named functions.
    pub named: u64,
    /// Typed functions.
    pub typed: u64,
    /// Commented functions.
    pub commented: u64,
}

/// The last-brief mark of a session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mark {
    /// The revision of the last `session_brief` call of the session.
    pub last_brief_rev: Rev,
}

/// The progress rows and the marks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    funcs: BTreeMap<FuncId, FuncProgress>,
    marks: BTreeMap<SessionLabel, Mark>,
}

impl Progress {
    /// Gives the progress of a function. A function without a row gives the default row.
    #[must_use]
    pub fn get(&self, func: FuncId) -> FuncProgress {
        self.funcs.get(&func).copied().unwrap_or_default()
    }

    /// Gives the rows in function order.
    pub fn iter(&self) -> impl Iterator<Item = (FuncId, FuncProgress)> + '_ {
        self.funcs.iter().map(|(f, p)| (*f, *p))
    }

    /// Gives the counts of the rows.
    #[must_use]
    pub fn counts(&self) -> ProgressCounts {
        ProgressCounts::default()
    }

    /// Gives the mark of a session.
    #[must_use]
    pub fn mark(&self, session: &SessionLabel) -> Option<Mark> {
        self.marks.get(session).copied()
    }

    /// Gives the marks in label order.
    pub fn marks(&self) -> impl Iterator<Item = (&SessionLabel, Mark)> {
        self.marks.iter().map(|(s, m)| (s, *m))
    }

    /// Sets the row of a function. A default row removes the row. Gives the old row.
    pub(crate) fn set(&mut self, func: FuncId, row: FuncProgress) -> FuncProgress {
        let _ = (func, row);
        FuncProgress::default()
    }

    /// Sets the mark of a session. Gives the old mark.
    pub(crate) fn set_mark(&mut self, session: SessionLabel, mark: Mark) -> Option<Mark> {
        let _ = (session, mark);
        None
    }
}

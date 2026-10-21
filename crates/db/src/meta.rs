//! Meta lines: session metadata in the journal (design Sections 3.7 and 3.10).
//!
//! A meta line changes no `rev`. Replay folds it into the progress rows and the marks.
//!
//! | Line | JSON |
//! |---|---|
//! | progress | `{"v":1,"meta":"progress","func":"0x401130","visited":true,"named":false,"typed":false,"commented":false}` |
//! | brief | `{"v":1,"meta":"brief","session":"mcp-1","rev":57}` |
//!
//! A progress line sets the whole row of the function. A brief line keeps the higher of the
//! old and the new rev, so a second fold of a line changes nothing.

#[cfg(test)]
mod tests;

use ghidorah_base::{FuncId, Rev};
use ghidorah_json::Value;

use crate::codec::{CodecError, Json, Obj};
use crate::fact::SessionLabel;
use crate::program::Program;
use crate::progress::{FuncProgress, Mark};

/// The member that marks a meta line.
pub const META_KEY: &str = "meta";

/// One meta line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaLine {
    /// The progress row of a function.
    Progress {
        /// The function.
        func: FuncId,
        /// The new row.
        row: FuncProgress,
    },
    /// The last-brief mark of a session.
    Brief {
        /// The session.
        session: SessionLabel,
        /// The rev of the `session_brief` call.
        rev: Rev,
    },
}

impl MetaLine {
    /// Gives the members of the line after `v`, without the checksum.
    #[must_use]
    pub fn members(&self) -> Vec<(&'static str, Value)> {
        match self {
            Self::Progress { func, row } => vec![
                (META_KEY, Value::from("progress")),
                ("func", func.enc()),
                ("visited", row.visited.enc()),
                ("named", row.named.enc()),
                ("typed", row.typed.enc()),
                ("commented", row.commented.enc()),
            ],
            Self::Brief { session, rev } => vec![
                (META_KEY, Value::from("brief")),
                ("session", session.enc()),
                ("rev", rev.enc()),
            ],
        }
    }

    /// Reads a meta line object. The object has `v` and `crc` too.
    ///
    /// # Errors
    ///
    /// Returns a [`CodecError`] for an unknown kind, a missing member or a bad value.
    pub fn from_json(value: &Value) -> Result<Self, CodecError> {
        let kind = value.get(META_KEY).and_then(Value::as_str).unwrap_or("");
        match kind {
            "progress" => {
                let o = Obj::new(
                    value,
                    &[
                        "v",
                        META_KEY,
                        "func",
                        "visited",
                        "named",
                        "typed",
                        "commented",
                        "crc",
                    ],
                )?;
                Ok(Self::Progress {
                    func: o.get("func")?,
                    row: FuncProgress {
                        visited: o.get("visited")?,
                        named: o.get("named")?,
                        typed: o.get("typed")?,
                        commented: o.get("commented")?,
                    },
                })
            }
            "brief" => {
                let o = Obj::new(value, &["v", META_KEY, "session", "rev", "crc"])?;
                Ok(Self::Brief {
                    session: o.get("session")?,
                    rev: o.get("rev")?,
                })
            }
            _ => Err(CodecError::text("meta line kind").at(META_KEY)),
        }
    }
}

/// Folds a meta line into the progress rows and the marks of `program`.
///
/// The fold changes no `rev` and no fact.
pub fn apply(program: &mut Program, line: &MetaLine) {
    match line {
        MetaLine::Progress { func, row } => {
            program.progress_mut().set(*func, *row);
        }
        MetaLine::Brief { session, rev } => {
            let old = program
                .progress()
                .mark(session)
                .map_or(Rev(0), |m| m.last_brief_rev);
            let mark = Mark {
                last_brief_rev: Rev(old.0.max(rev.0)),
            };
            program.progress_mut().set_mark(session.clone(), mark);
        }
    }
}

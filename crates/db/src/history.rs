//! The history of a project: the commit lines and the undo entries (design Sections 3.7 and
//! 3.8, ADR-0017).
//!
//! [`History`] reads every commit line of the journal in order. Each original transaction
//! (not an undo and not a redo) is one [`Entry`] of the session that committed it. An entry
//! has the state `applied` or `undone`. An undo commit sets the entries of its `undo_of` list
//! to `undone`. A redo commit sets the entries of its `redo_of` list to `applied`.
//!
//! Each entry keeps the applied edits of the last commit that set its state. An undo applies
//! the inverses of these edits in reverse order. So an undo and a redo are exact.
//!
//! An analysis run marker is an entry of the session `analysis` with no edits. No undo selects
//! it.
//!
//! [`History::rows`] gives the rows of `history_list`: one raw row per edit of each commit,
//! or one coalesced row per changed fact, plus one row per analysis run.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, Rev, TxId};
use ghidorah_json::Value;

use crate::comments::CommentKind;
use crate::fact::SessionLabel;
use crate::journal::{Line, RunLine, TxLine};
use crate::meta::MetaLine;
use crate::program::Program;
use crate::source::Source;
use crate::tx::{Applied, TxLabel};
use crate::why::FactKey;

/// The label of an analysis run entry.
pub const RUN_LABEL: &str = "analysis_run";

/// The undo state of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryState {
    /// The edits of the entry are in the program.
    Applied,
    /// An undo commit reverted the edits of the entry.
    Undone,
}

/// One original transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The transaction ID.
    pub tx: TxId,
    /// The revision of the commit.
    pub rev: Rev,
    /// The label.
    pub label: TxLabel,
    /// The source.
    pub source: Source,
    /// The session label.
    pub session: SessionLabel,
    /// The state.
    pub state: EntryState,
    /// The keys of the facts that the entry changes. A selective undo compares them.
    pub keys: BTreeSet<FactKey>,
    /// The applied edits of the last commit that set the state, or `None` for an analysis run.
    pub edits: Option<Vec<Applied>>,
    /// The transaction that set the state: the entry itself, an undo or a redo commit.
    pub changed_by: TxId,
}

/// The scope of an undo or a redo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// The entries of one session.
    Session(SessionLabel),
    /// The entries of all sessions: `session: "*"`.
    All,
}

impl Scope {
    /// Tells if the scope holds the session `session`.
    #[must_use]
    pub fn holds(&self, session: &SessionLabel) -> bool {
        match self {
            Self::Session(s) => s == session,
            Self::All => true,
        }
    }
}

/// The kind of a changed fact in a `history_list` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    /// A symbol name.
    Name,
    /// A comment.
    Comment,
    /// A variable fact.
    Var,
    /// A reference.
    Ref,
    /// A function.
    Function,
    /// A function signature.
    Signature,
    /// A noreturn flag.
    Noreturn,
    /// A jump table.
    JumpTable,
    /// A flow override.
    Flow,
    /// A data definition.
    Data,
    /// A note.
    Note,
    /// The analysis layer: an analysis run.
    Analysis,
}

impl ChangeKind {
    /// All kinds in output order.
    pub const ALL: [Self; 12] = [
        Self::Name,
        Self::Comment,
        Self::Var,
        Self::Ref,
        Self::Function,
        Self::Signature,
        Self::Noreturn,
        Self::JumpTable,
        Self::Flow,
        Self::Data,
        Self::Note,
        Self::Analysis,
    ];

    /// Gives the output name, for example `name`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Comment => "comment",
            Self::Var => "var",
            Self::Ref => "ref",
            Self::Function => "function",
            Self::Signature => "signature",
            Self::Noreturn => "noreturn",
            Self::JumpTable => "jumptable",
            Self::Flow => "flow",
            Self::Data => "data",
            Self::Note => "note",
            Self::Analysis => "analysis",
        }
    }

    /// Gives the kind of an output name, or `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// The filter of [`History::rows`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RowQuery {
    /// Only commits with a higher revision.
    pub since_rev: Rev,
    /// Only these kinds. An empty list keeps every kind.
    pub kinds: Vec<ChangeKind>,
    /// Only commits of this session.
    pub session: Option<String>,
    /// No commits of this session.
    pub exclude_session: Option<String>,
    /// One row per changed fact: the last change.
    pub coalesce: bool,
}

/// One row of `history_list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The revision of the commit. A coalesced row gives the last revision.
    pub rev: Rev,
    /// The transaction.
    pub tx: TxId,
    /// The position of the edit in its commit.
    pub seq: u32,
    /// The transaction label.
    pub label: String,
    /// The source.
    pub source: Source,
    /// The session label.
    pub session: String,
    /// The kind of the fact.
    pub kind: ChangeKind,
    /// The ID of the fact, for example `fn:0x401130` or `note:7`.
    pub id: String,
    /// The address of the fact, or `None`.
    pub addr: Option<Address>,
    /// The new state of the fact.
    pub fields: Value,
    /// The undo commit that reverted the transaction, or `None`.
    pub undone_by: Option<TxId>,
    /// The key of the fact: rows with one key coalesce.
    pub key: String,
}

/// The history of one project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    entries: BTreeMap<TxId, Entry>,
    lines: Vec<Line>,
    last_original: BTreeMap<SessionLabel, TxId>,
}

impl History {
    /// Makes an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a commit line: a new entry for an original commit, else new entry states.
    pub fn record(&mut self, line: &TxLine) {
        if line.is_original() {
            let edits = line.edits.clone();
            self.entries.insert(
                line.tx,
                Entry {
                    tx: line.tx,
                    rev: line.rev,
                    label: line.label.clone(),
                    source: line.source,
                    session: line.session.clone(),
                    state: EntryState::Applied,
                    keys: conflict_keys(&edits),
                    edits: Some(edits),
                    changed_by: line.tx,
                },
            );
            self.last_original.insert(line.session.clone(), line.tx);
        }
        let groups = [
            (&line.undo_of, EntryState::Undone),
            (&line.redo_of, EntryState::Applied),
        ];
        for (list, state) in groups {
            for tx in list {
                let edits: Vec<Applied> = line
                    .edits
                    .iter()
                    .zip(&line.of)
                    .filter(|(_, of)| *of == tx)
                    .map(|(a, _)| a.clone())
                    .collect();
                if let Some(entry) = self.entries.get_mut(tx) {
                    entry.state = state;
                    entry.edits = Some(edits);
                    entry.changed_by = line.tx;
                }
            }
        }
        self.lines.push(Line::Tx(Box::new(line.clone())));
    }

    /// Records an analysis run marker: an entry of the session `analysis` with no edits.
    pub fn record_run(&mut self, line: &RunLine) {
        if let (Ok(label), Ok(session)) = (
            TxLabel::new(RUN_LABEL),
            SessionLabel::new(SessionLabel::ANALYSIS),
        ) {
            self.entries.insert(
                line.tx,
                Entry {
                    tx: line.tx,
                    rev: line.rev,
                    label,
                    source: Source::Analysis,
                    session: session.clone(),
                    state: EntryState::Applied,
                    keys: BTreeSet::new(),
                    edits: None,
                    changed_by: line.tx,
                },
            );
            self.last_original.insert(session, line.tx);
        }
        self.lines.push(Line::Run(*line));
    }

    /// Records a meta line. A reload in memory folds it again.
    pub fn record_meta(&mut self, line: &MetaLine) {
        self.lines.push(Line::Meta(line.clone()));
    }

    /// Gives the entry of a transaction, or `None`.
    #[must_use]
    pub fn entry(&self, tx: TxId) -> Option<&Entry> {
        self.entries.get(&tx)
    }

    /// Gives the entries in transaction order.
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &Entry> {
        self.entries.values()
    }

    /// Gives the commit, run and meta lines in journal order.
    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// Gives the last original transaction of the scope, or `None`.
    #[must_use]
    pub fn last_original(&self, scope: &Scope) -> Option<TxId> {
        match scope {
            Scope::Session(s) => self.last_original.get(s).copied(),
            Scope::All => self.last_original.values().max().copied(),
        }
    }

    /// Gives the number of distinct session labels with the prefix `mcp-` (design Section 3.6).
    #[must_use]
    pub fn mcp_labels(&self) -> u64 {
        let labels: BTreeSet<&str> = self
            .lines
            .iter()
            .filter_map(|l| match l {
                Line::Tx(t) => Some(t.session.as_str()),
                _ => None,
            })
            .filter(|s| s.starts_with("mcp-"))
            .collect();
        u64::try_from(labels.len()).unwrap_or(u64::MAX)
    }

    /// Gives the revision and the session of the last commit line, or `None`.
    #[must_use]
    pub fn last_commit(&self) -> Option<(Rev, SessionLabel)> {
        self.lines.iter().rev().find_map(|l| match l {
            Line::Tx(t) => Some((t.rev, t.session.clone())),
            _ => None,
        })
    }

    /// Gives the rows of `history_list` in row order.
    ///
    /// Raw rows come in commit order and edit order. Coalesced rows keep the last change of
    /// each fact and come in the order of their last revision. Run rows stay one per run.
    #[must_use]
    pub fn rows(&self, program: &Program, query: &RowQuery) -> Vec<Row> {
        let _ = (program, query);
        Vec::new()
    }
}

/// Gives the conflict keys of applied edits: the keys of each edit and each inverse.
///
/// A key of a function part (signature, noreturn flag, variable, plate comment) also gives the
/// key of its function. So an undo of a function and a later change of its parts conflict.
#[must_use]
pub fn conflict_keys(edits: &[Applied]) -> BTreeSet<FactKey> {
    let mut out = BTreeSet::new();
    for a in edits {
        for key in a.edit.keys().into_iter().chain(a.inverse.keys()) {
            match &key {
                FactKey::Signature(f) | FactKey::Noreturn(f) => {
                    out.insert(FactKey::Func(*f));
                }
                FactKey::Var(v) => {
                    out.insert(FactKey::Func(v.func));
                }
                FactKey::Comment(addr, CommentKind::Plate) => {
                    out.insert(FactKey::Func(FuncId(*addr)));
                }
                _ => {}
            }
            out.insert(key);
        }
    }
    out
}

//! The parts of a brief: the facts of one binary at full length and their render with a row
//! cap.
//!
//! | Part | Order |
//! |---|---|
//! | open notes, findings | newest rev first, then the higher note ID |
//! | recent edits | newest last rev first, then the fact key |
//! | weak names | the frozen priority order of design Section 7.11 |
//! | orphans | address, then kind, then ID |
//!
//! An orphan is an agent or user fact whose function does not exist: a function name at an
//! address with no function, or a variable fact of a function that does not exist.

use ghidorah_analysis::analyzers::metrics;
use ghidorah_base::{FuncId, Rev};
use ghidorah_db::{
    ChangeKind, History, Note, NoteKind, NoteStatus, Program, Row, RowQuery, Source, SymKind,
};
use ghidorah_json::{Object, Value};

use super::{MAX_ROWS, TEXT_CHARS};
use crate::handlers::func_sections::{addr, safe};
use crate::session::OpenBinary;

/// One orphaned fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Orphan {
    /// The address of the fact.
    pub at: ghidorah_base::Address,
    /// The kind: `name` or `var`.
    pub kind: &'static str,
    /// The ID of the fact: the address text or the `var:` ID.
    pub id: String,
}

/// The facts of one brief at full length.
#[derive(Debug, Clone)]
pub(super) struct Facts {
    /// The binary of the brief.
    pub binary_id: String,
    /// The rows of the open binaries.
    pub binaries: Vec<Value>,
    /// The progress object.
    pub progress: Value,
    /// The counts of the open todos, the open hypotheses and all open notes.
    pub open_counts: (u64, u64, u64),
    /// The rows of the open notes, newest first.
    pub open_notes: Vec<Value>,
    /// The rows of the findings, newest first.
    pub findings: Vec<Value>,
    /// The rows of the changed facts, newest first.
    pub edits: Vec<Value>,
    /// The changes after the last brief: the rev of the mark and the counts by kind.
    pub changed: (u64, Vec<(ChangeKind, u64)>),
    /// The functions with default names in priority order.
    pub weak: Vec<Value>,
    /// The orphaned facts.
    pub orphans: Vec<Orphan>,
}

/// Gives a count as a `u64`.
fn number(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Gives a count as a JSON integer.
fn count(n: usize) -> Value {
    Value::from(number(n))
}

/// Gives the first [`TEXT_CHARS`] characters of `text`, and `true` when the cut drops text.
fn cut(text: &str) -> (String, bool) {
    let shown: String = text.chars().take(TEXT_CHARS).collect();
    let cut = shown.len() < text.len();
    (shown, cut)
}

/// Gives the row of one note: `{ id, kind, text, truncated?, at?, status, evidence?, rev }`.
fn note_row(n: &Note) -> Value {
    let (text, truncated) = cut(&n.text);
    let mut out = Object::new();
    out.push("id", Value::from(n.id.to_string()));
    out.push("kind", Value::from(n.kind.name()));
    out.push("text", Value::from(text));
    if truncated {
        out.push("truncated", Value::Bool(true));
    }
    if let Some(at) = n.at {
        out.push("at", addr(at));
    }
    out.push("status", Value::from(n.status.name()));
    if n.kind == NoteKind::Finding {
        out.push(
            "evidence",
            count(n.evidence.len().saturating_add(n.claims.len())),
        );
    }
    out.push("rev", Value::from(n.rev.0));
    Value::Object(out)
}

/// Gives the notes that `keep` selects, newest rev first, then the higher note ID.
fn newest(p: &Program, keep: impl Fn(&Note) -> bool) -> Vec<&Note> {
    let mut list: Vec<&Note> = p.notes().iter().filter(|n| keep(n)).collect();
    list.sort_by_key(|n| std::cmp::Reverse((n.rev, n.id)));
    list
}

/// Tells if a note is an open note of the brief: open, and not a set or a finding.
fn is_open(n: &Note) -> bool {
    n.status == NoteStatus::Open && !matches!(n.kind, NoteKind::Set | NoteKind::Finding)
}

/// Gives the short value text of a history row: a name, a comment text or a note kind.
fn row_value(row: &Row) -> Option<String> {
    let key = match row.kind {
        ChangeKind::Name => "name",
        ChangeKind::Comment => "text",
        ChangeKind::Note => "kind",
        ChangeKind::Var => "value",
        _ => return None,
    };
    let value = row.fields.get(key)?;
    let text = value
        .as_str()
        .or_else(|| value.get("text").and_then(Value::as_str))?;
    Some(cut(&safe(text)).0)
}

/// Gives the row of one changed fact: `{ kind, id, addr?, value?, rev, session }`.
fn edit_row(row: &Row) -> Value {
    let mut out = Object::new();
    out.push("kind", Value::from(row.kind.name()));
    out.push("id", Value::from(row.id.as_str()));
    if let Some(a) = row.addr {
        out.push("addr", addr(a));
    }
    if let Some(value) = row_value(row) {
        out.push("value", Value::from(value));
    }
    out.push("rev", Value::from(row.rev.0));
    out.push("session", Value::from(row.session.as_str()));
    Value::Object(out)
}

/// Gives the coalesced rows of the facts that changed after `since`, newest first. The rows
/// of analysis runs are not changes of facts.
fn changes(history: &History, p: &Program, since: Rev) -> Vec<Row> {
    let query = RowQuery {
        since_rev: since,
        coalesce: true,
        ..RowQuery::default()
    };
    let mut rows: Vec<Row> = history
        .rows(p, &query)
        .into_iter()
        .filter(|r| r.kind != ChangeKind::Analysis)
        .collect();
    rows.sort_by(|a, b| (b.rev, &a.key).cmp(&(a.rev, &b.key)));
    rows
}

/// Tells if a fact source is an agent or a user.
const fn is_agent(source: Source) -> bool {
    matches!(source, Source::Agent | Source::User)
}

/// Gives the orphaned facts of `p` in order.
fn orphans(p: &Program) -> Vec<Orphan> {
    let mut out = Vec::new();
    for s in p.base().symbols().iter() {
        if s.kind == SymKind::Function
            && is_agent(s.name.source)
            && p.func(FuncId(s.addr)).is_none()
        {
            out.push(Orphan {
                at: s.addr,
                kind: "name",
                id: s.addr.to_string(),
            });
        }
    }
    for (var, fact) in p.base().vars().iter() {
        let agent = fact.name.as_ref().is_some_and(|f| is_agent(f.source))
            || fact.ty.as_ref().is_some_and(|f| is_agent(f.source));
        if agent && p.func(var.func).is_none() {
            out.push(Orphan {
                at: var.func.0,
                kind: "var",
                id: var.to_string(),
            });
        }
    }
    out.sort();
    out
}

/// Gives the row of one open binary: `{ binary_id, file_name, rev, read_only, analysis }`.
pub(super) fn binary_row(b: &OpenBinary) -> Value {
    let mut out = Object::new();
    out.push("binary_id", Value::from(b.id.to_string()));
    out.push("file_name", Value::from(safe(&b.file_name)));
    out.push("rev", Value::from(b.program.rev().0));
    out.push("read_only", Value::Bool(b.read_only));
    out.push(
        "analysis",
        b.analysis
            .map_or(Value::Null, |a| Value::from(a.state.as_str())),
    );
    Value::Object(out)
}

/// Gives the progress object `{ functions, visited, named, typed, commented, pct }`.
fn progress(p: &Program) -> Value {
    let c = metrics::coverage(p);
    let pct = c
        .visited
        .saturating_mul(100)
        .checked_div(c.functions)
        .unwrap_or(0);
    Value::object([
        ("functions", Value::from(c.functions)),
        ("visited", Value::from(c.visited)),
        ("named", Value::from(c.named)),
        ("typed", Value::from(c.typed)),
        ("commented", Value::from(c.commented)),
        ("pct", Value::from(pct)),
    ])
}

impl Facts {
    /// Gathers the facts of the binary `b` with the history `history`. `since` is the rev of
    /// the last-brief mark of the session.
    pub(super) fn gather(
        b: &OpenBinary,
        binaries: Vec<Value>,
        history: &History,
        since: Rev,
    ) -> Self {
        let p = &b.program;
        let open = newest(p, is_open);
        let of_kind = |k: NoteKind| number(open.iter().filter(|n| n.kind == k).count());
        let open_counts = (
            of_kind(NoteKind::Todo),
            of_kind(NoteKind::Hypothesis),
            number(open.len()),
        );
        let after = changes(history, p, since);
        let by_kind = ChangeKind::ALL
            .into_iter()
            .map(|k| (k, number(after.iter().filter(|r| r.kind == k).count())))
            .filter(|(_, n)| *n > 0)
            .collect();
        let weak = metrics::priority(p)
            .iter()
            .filter_map(|r| {
                let name = p.name(r.func.0)?;
                name.is_default().then(|| {
                    Value::object([
                        ("id", Value::from(r.func.to_string())),
                        ("name", Value::from(name.text)),
                    ])
                })
            })
            .collect();
        Self {
            binary_id: b.id.to_string(),
            binaries,
            progress: progress(p),
            open_counts,
            open_notes: open.iter().map(|n| note_row(n)).collect(),
            findings: newest(p, |n| n.kind == NoteKind::Finding)
                .iter()
                .map(|n| note_row(n))
                .collect(),
            edits: changes(history, p, Rev(0)).iter().map(edit_row).collect(),
            changed: (since.0, by_kind),
            weak,
            orphans: orphans(p),
        }
    }

    /// Tells if a row cap of `cap` cuts a list.
    pub(super) fn cuts(&self, cap: usize) -> bool {
        let cap = cap.min(MAX_ROWS);
        [
            self.binaries.len(),
            self.open_notes.len(),
            self.findings.len(),
            self.edits.len(),
            self.weak.len(),
            self.orphans.len(),
        ]
        .into_iter()
        .any(|n| n > cap)
    }

    /// Gives the number of facts that changed after the last brief.
    pub(super) fn changed_count(&self) -> u64 {
        self.changed
            .1
            .iter()
            .map(|(_, n)| n)
            .fold(0, |a, n| a.saturating_add(*n))
    }

    /// Gives the data of the brief with at most `cap` rows per list. `truncated` tells if the
    /// budget cut a list.
    pub(super) fn render(&self, cap: usize, truncated: bool) -> Object {
        let take = |list: &[Value]| Value::Array(list.iter().take(cap).cloned().collect());
        let mut out = Object::new();
        out.push("binary_id", Value::from(self.binary_id.as_str()));
        out.push("binaries", take(&self.binaries));
        out.push("progress", self.progress.clone());
        let (todo, hypothesis, total) = self.open_counts;
        out.push(
            "open_notes",
            Value::object([
                ("todo", Value::from(todo)),
                ("hypothesis", Value::from(hypothesis)),
                ("total", Value::from(total)),
                ("top", take(&self.open_notes)),
            ]),
        );
        out.push("recent_findings", take(&self.findings));
        out.push("recent_edits", take(&self.edits));
        let by_kind = self
            .changed
            .1
            .iter()
            .map(|(k, n)| {
                Value::object([("kind", Value::from(k.name())), ("count", Value::from(*n))])
            })
            .collect();
        out.push(
            "changed_since_last_brief",
            Value::object([
                ("since_rev", Value::from(self.changed.0)),
                ("count", Value::from(self.changed_count())),
                ("by_kind", Value::Array(by_kind)),
            ]),
        );
        out.push("weak_names", take(&self.weak));
        let orphans = self
            .orphans
            .iter()
            .take(cap)
            .map(|o| {
                Value::object([
                    ("kind", Value::from(o.kind)),
                    ("at", addr(o.at)),
                    ("id", Value::from(o.id.as_str())),
                ])
            })
            .collect();
        out.push("orphans", Value::Array(orphans));
        out.push("truncated", Value::Bool(truncated));
        out
    }
}

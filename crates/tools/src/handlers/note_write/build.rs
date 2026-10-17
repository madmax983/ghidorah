//! The note of one `note_write` call: a new note, or the target note with the given fields.
//!
//! | Argument | Effect |
//! |---|---|
//! | `target` | the note to change. Without it, the call makes a new note. A set call without `target` changes the set note with the same name when it exists. |
//! | `kind` | the kind. A set note stays a set note, and a note of another kind never becomes one. |
//! | `text`, `status`, `tags`, `evidence`, `claims` | the new value of the field |
//! | `at` | the address, and the function that owns it |
//! | `set` | the set name and the result of the set operation (the `members` module) |
//!
//! Each write takes the source, the session and the pending rev of the transaction.

use ghidorah_base::{ErrorCode, Id, NoteId, SetName};
use ghidorah_db::{
    Claim, Edit, Note, NoteKind, NoteSet, NoteStatus, Program, SetMembers, SetOp, Tx,
};
use ghidorah_json::{Object, Value};

use super::members;
use crate::args::Args;
use crate::errors::ToolError;
use crate::handlers::symbol_rename::edits::{address_at, edit_error, invalid, missing, texts};

/// The arguments that a delete call does not take.
const NOT_WITH_DELETE: [&str; 8] = [
    "kind", "text", "at", "status", "tags", "evidence", "claims", "set",
];

/// Gives the `NOT_FOUND` error of a missing entity of `kind` at `path`.
fn not_found(kind: &str, path: &str) -> ToolError {
    ToolError::new(ErrorCode::NotFound)
        .var("kind", kind)
        .path(path)
        .detail("kind", Value::from(kind))
}

/// Gives the note ID of `target`, or `None` for a call with no target.
fn target_id(args: &Args) -> Result<Option<NoteId>, ToolError> {
    match args.str("target").map(Id::parse) {
        None => Ok(None),
        Some(Ok(Id::Note(id))) => Ok(Some(id)),
        Some(_) => Err(invalid("/target", "a note ID such as note:7")),
    }
}

/// Gives the set name of the `set` argument, or `None` for a call with no set.
fn set_name(args: &Args) -> Result<Option<SetName>, ToolError> {
    let Some(set) = args.get("set") else {
        return Ok(None);
    };
    let text = set.get("name").and_then(Value::as_str).unwrap_or_default();
    SetName::new(text).map(Some).map_err(|_| {
        invalid(
            "/set/name",
            "a set name of 1 to 64 letters, digits, dots, dashes and underscores",
        )
    })
}

/// Gives the set operation of `op`. The default is `replace`.
fn set_op(op: Option<&Value>) -> SetOp {
    match op.and_then(Value::as_str) {
        Some("union") => SetOp::Union,
        Some("intersect") => SetOp::Intersect,
        Some("subtract") => SetOp::Subtract,
        _ => SetOp::Replace,
    }
}

/// Gives the members of the set `from` for the operand of a set operation.
fn from_members(p: &Program, from: &Value) -> Result<SetMembers, ToolError> {
    from.as_str()
        .and_then(|t| t.strip_prefix("set:"))
        .and_then(|n| SetName::new(n).ok())
        .and_then(|n| p.notes().set(&n))
        .and_then(|n| n.set.as_ref())
        .map(|s| s.members.clone())
        .ok_or_else(|| not_found("set", "/set/from_set"))
}

/// Applies the `set` argument to `note`.
fn apply_set(p: &Program, note: &mut Note, set: &Value, name: SetName) -> Result<(), ToolError> {
    let operand = match (set.get("members"), set.get("from_set")) {
        (Some(_), Some(_)) => {
            return Err(invalid("/set/from_set", "members or from_set, not both"));
        }
        (None, Some(from)) => from_members(p, from)?,
        (Some(list), None) => members::parse(list.as_array().unwrap_or_default(), "/set/members")?,
        (None, None) => SetMembers::ids(Vec::new()),
    };
    let old = note.set.as_ref().map(|s| &s.members);
    let members = members::combine(old, set_op(set.get("op")), operand, "/set/members")?;
    note.set = Some(NoteSet { name, members });
    Ok(())
}

/// Gives the note to write: the old note, or a new note.
fn start(tx: &Tx<'_>, args: &Args, name: Option<&SetName>) -> Result<(Note, bool), ToolError> {
    let p = tx.program();
    let kind = args.str("kind").and_then(NoteKind::parse);
    if let Some(id) = target_id(args)? {
        let note = p.notes().get(id).cloned();
        return note
            .map(|n| (n, true))
            .ok_or_else(|| not_found("note", "/target"));
    }
    let same_set = name
        .filter(|_| kind == Some(NoteKind::Set))
        .and_then(|n| p.notes().set(n));
    if let Some(found) = same_set {
        return Ok((found.clone(), true));
    }
    let origin = tx.origin();
    let note = Note {
        id: p.notes().next_id(),
        kind: kind.unwrap_or(NoteKind::Note),
        text: String::new(),
        at: None,
        func: None,
        status: NoteStatus::Open,
        tags: Vec::new(),
        evidence: Vec::new(),
        claims: Vec::new(),
        set: None,
        src: origin.source,
        session: origin.session.clone(),
        rev: tx.pending_rev(),
    };
    Ok((note, false))
}

/// Gives the note of the call: the new note, or the target note with the given fields.
///
/// # Errors
///
/// Returns `NOT_FOUND` for a target or a `from_set` that does not exist. Returns
/// `MISSING_ARGUMENT` for a new note with no text, and `INVALID_ARGUMENT` for a bad value.
pub(super) fn build(tx: &Tx<'_>, args: &Args) -> Result<Note, ToolError> {
    let name = set_name(args)?;
    let (mut note, existing) = start(tx, args, name.as_ref())?;
    let p = tx.program();
    if let Some(kind) = args.str("kind").and_then(NoteKind::parse) {
        if existing && (kind == NoteKind::Set) != (note.kind == NoteKind::Set) {
            return Err(invalid(
                "/kind",
                "the kind of the note: a set note stays a set note",
            ));
        }
        note.kind = kind;
    }
    if !existing && note.kind != NoteKind::Set && !args.given("text") {
        return Err(missing("text"));
    }
    if let Some(text) = args.str("text") {
        text.clone_into(&mut note.text);
    }
    if let Some(at) = args.get("at") {
        let addr = address_at(tx, at, "/at")?;
        note.at = Some(addr);
        note.func = p.owner_of(addr);
    }
    if let Some(status) = args.str("status").and_then(NoteStatus::parse) {
        note.status = status;
    }
    if args.given("tags") {
        note.tags = texts(args.get("tags"));
    }
    if args.given("evidence") {
        let evidence = texts(args.get("evidence"));
        if let Some(i) = evidence.iter().position(|e| Id::parse(e).is_err()) {
            return Err(invalid(
                &format!("/evidence/{i}"),
                "an ID such as fn:0x401130",
            ));
        }
        note.evidence = evidence;
    }
    if let Some(claims) = args.list("claims") {
        note.claims = claims
            .iter()
            .map(|c| Claim {
                rel: c
                    .get("rel")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                args: texts(c.get("args")),
            })
            .collect();
    }
    match (args.get("set"), name) {
        (Some(set), Some(name)) => apply_set(p, &mut note, set, name)?,
        _ if note.kind == NoteKind::Set && note.set.is_none() => return Err(missing("set")),
        _ => {}
    }
    let origin = tx.origin();
    note.src = origin.source;
    note.session = origin.session.clone();
    note.rev = tx.pending_rev();
    Ok(note)
}

/// Gives the result object of a note: `{ note, kind, status, set?, members?, ranges? }`.
pub(super) fn summary(note: &Note) -> Object {
    let mut out = Object::new();
    out.push("note", Value::from(note.id.to_string()));
    out.push("kind", Value::from(note.kind.name()));
    out.push("status", Value::from(note.status.name()));
    if let Some(set) = &note.set {
        out.push("set", Value::from(format!("set:{}", set.name.as_str())));
        match &set.members {
            SetMembers::Ids(ids) => out.push("members", Value::from(ids.len())),
            SetMembers::Addrs(ranges) => out.push("ranges", Value::from(ranges.ranges().len())),
        }
    }
    out
}

/// Gives the JSON pointer of the argument that an edit error of a note names.
fn error_path(e: &ghidorah_db::EditError) -> &'static str {
    use ghidorah_db::{EditError, Invalid};
    match e {
        EditError::Invalid(Invalid::SetNameTaken { .. } | Invalid::SetKinds) => "/set/name",
        EditError::Invalid(Invalid::TooMany { .. }) => "/set/members",
        EditError::Invalid(Invalid::BadEvidence(_)) => "/evidence",
        _ => "/text",
    }
}

/// Writes `note` in the transaction. Gives `true` for a no-op.
///
/// # Errors
///
/// Returns the tool error of the refused edit.
pub(super) fn write(tx: &mut Tx<'_>, note: Note) -> Result<bool, ToolError> {
    tx.apply(Edit::WriteNote(Box::new(note)))
        .map(|a| a.is_none())
        .map_err(|e| edit_error(&e, error_path(&e), None))
}

/// Deletes the target note. Gives the result object with `deleted: true`.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a call with no target or with other fields, and
/// `NOT_FOUND` for a note that does not exist.
pub(super) fn delete(tx: &mut Tx<'_>, args: &Args) -> Result<Object, ToolError> {
    if let Some(field) = NOT_WITH_DELETE.iter().find(|f| args.given(f)) {
        return Err(invalid(
            &format!("/{field}"),
            "no value: a delete takes only target",
        ));
    }
    let id = target_id(args)?.ok_or_else(|| invalid("/delete", "a delete with target"))?;
    let note = tx
        .program()
        .notes()
        .get(id)
        .cloned()
        .ok_or_else(|| not_found("note", "/target"))?;
    tx.apply(Edit::DeleteNote { id })
        .map_err(|e| edit_error(&e, "/target", None))?;
    let mut out = summary(&note);
    out.push("deleted", Value::Bool(true));
    Ok(out)
}

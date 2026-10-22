//! The migration of a version 1 project (design Section 3.10).

use std::fmt::Write as _;
use std::path::Path;

use ghidorah_json::{Limits, Value, parse, write, write_jcs};

use super::{ROOT, input, opts, reopen, sim, write as write_opts};
use crate::edit::Edit;
use crate::fs::Fs;
use crate::history::History;
use crate::journal::{self, JOURNAL_FILE, Line, TxLine};
use crate::migrate::ExtMap;
use crate::notes::{Note, NoteKind, NoteStatus};
use crate::project::{Access, LoadSpec, PROJECT_FILE, Project, ProjectMeta};
use crate::snapshot::{FORMAT_VERSION, SNAPSHOT_FILE};
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::session;

/// Gives the JSON value of the file at `path` of `fs`.
fn json_of(fs: &mut dyn Fs, path: &Path) -> Value {
    let bytes = fs.read(path).unwrap();
    parse(std::str::from_utf8(&bytes).unwrap(), &Limits::DEFAULT).unwrap()
}

/// Gives `value` with the member `key` set to `to`.
fn with(mut value: Value, key: &str, to: Value) -> Value {
    if let Value::Object(o) = &mut value {
        o.insert(key, to);
    }
    value
}

/// Writes the project in `dir` again in format version 1. The version members change. The
/// journal edits and the snapshot facts get the old `ext:` addresses. `back` maps each new
/// address to its old address.
fn downgrade(fs: &mut dyn Fs, dir: &Path, back: &ExtMap) {
    let meta = with(
        json_of(fs, &dir.join(PROJECT_FILE)),
        "format_version",
        Value::from(1u64),
    );
    fs.write_all(&dir.join(PROJECT_FILE), write(&meta).as_bytes())
        .unwrap();
    let text = String::from_utf8(fs.read(&dir.join(JOURNAL_FILE)).unwrap()).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let mut value = parse(line, &Limits::DEFAULT).unwrap();
        if let Value::Object(o) = &mut value {
            o.remove("crc");
            o.insert("v", Value::from(1u64));
            if let Some(edits) = o.remove("edits") {
                o.insert("edits", back.remap(edits));
            }
        }
        let body = write(&value);
        let open = body.strip_suffix('}').unwrap();
        let sum = journal::crc(&body);
        writeln!(out, "{open},\"crc\":\"{sum}\"}}").unwrap();
    }
    fs.write_all(&dir.join(JOURNAL_FILE), out.as_bytes())
        .unwrap();
    let mut snap = with(
        json_of(fs, &dir.join(SNAPSHOT_FILE)),
        "format_version",
        Value::from(1u64),
    );
    if let Value::Object(top) = &mut snap
        && let Some(Value::Object(facts)) = top.get_mut("facts")
    {
        for key in ["analysis", "base", "notes"] {
            let old = facts.remove(key).unwrap();
            facts.insert(key, back.remap(old));
        }
    }
    fs.write_all(
        &dir.join(SNAPSHOT_FILE),
        write_jcs(&snap).unwrap().as_bytes(),
    )
    .unwrap();
}

/// Gives the primary name of the base layer at the `ext:` address of the import `name`.
fn import_label(p: &crate::program::Program, name: &str) -> Option<String> {
    let row = p.imports().values().find(|r| r.id.name() == Some(name))?;
    p.base()
        .symbols()
        .primary(row.ext)
        .map(|s| s.name.value.clone())
}

/// Commits a rename of the `ext:` label of the import `name` to `to`. With `note`, the commit
/// also writes a note at the `ext:` address.
fn rename_import(
    p: &mut crate::program::Program,
    name: &str,
    to: &str,
    note: bool,
) -> crate::tx::Commit {
    let at = p
        .imports()
        .values()
        .find(|r| r.id.name() == Some(name))
        .map(|r| r.ext)
        .unwrap();
    let mut tx = p
        .begin("symbol_rename", Source::User, session("mcp-1"))
        .unwrap();
    let fact = tx.fact(to.to_string());
    tx.apply(Edit::SetName {
        addr: at,
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: vec![at.to_string()],
    })
    .unwrap();
    if note {
        let note = Note {
            id: tx.program().notes().next_id(),
            kind: NoteKind::Finding,
            text: format!("{name} prints the result."),
            at: Some(at),
            func: None,
            status: NoteStatus::Open,
            tags: Vec::new(),
            evidence: vec![at.to_string()],
            lift_ver: None,
            claims: Vec::new(),
            set: None,
            src: Source::User,
            session: session("mcp-1"),
            rev: tx.pending_rev(),
        };
        tx.apply(Edit::WriteNote(Box::new(note))).unwrap();
    }
    tx.commit().unwrap()
}

/// A version 1 project keeps its `ext:` facts: the snapshot and the journal lines map each
/// old address to the address of its import ID. A write open makes the project version 2.
#[test]
fn regress_v1_project_migrates() {
    let fs = sim(&[100, 200]);
    let (bytes, mut p) = input("crackme.gcc-O2");
    let meta = ProjectMeta::new(&p, "crackme.gcc-O2", LoadSpec::Auto);
    let dir = Project::dir_of(Path::new(ROOT), meta.binary_id);
    let mut project = Project::create(
        fs.boxed(),
        Path::new(ROOT),
        meta,
        &bytes,
        &p,
        &write_opts(100),
    )
    .unwrap();
    let back = ExtMap::from_pairs(p.v1_ext_map().into_iter().map(|(old, new)| (new, old)));
    assert!(!back.is_empty(), "crackme has imports in another order");
    let mut h = History::new();
    for (name, to) in [("puts", "my_puts"), ("strlen", "my_strlen")] {
        let commit = rename_import(&mut p, name, to, name == "puts");
        let line = TxLine::of_commit(&commit);
        project
            .append(&Line::Tx(Box::new(line.clone())), &p)
            .unwrap();
        h.record(&line);
        if name == "puts" {
            project.snapshot(&p).unwrap();
        }
    }
    drop(project);
    let mut raw = fs.boxed();
    downgrade(raw.as_mut(), &dir, &back);
    // A read-only open migrates in memory and writes nothing.
    let read = reopen(&fs, &dir, &opts(Access::ReadOnly, 200)).unwrap();
    assert_eq!(read.project.meta().format_version, 1);
    for opened in [read, reopen(&fs, &dir, &write_opts(200)).unwrap()] {
        let q = &opened.program;
        assert_eq!(q.rev(), p.rev());
        assert_eq!(import_label(q, "puts").as_deref(), Some("my_puts"));
        assert_eq!(import_label(q, "strlen").as_deref(), Some("my_strlen"));
        let puts = q
            .imports()
            .values()
            .find(|r| r.id.name() == Some("puts"))
            .map(|r| r.ext);
        let note = q.notes().iter().next().unwrap();
        assert_eq!(note.at, puts, "the note moves too");
        assert_eq!(note.evidence, [puts.unwrap().to_string()]);
        for row in q.imports().values() {
            let name = row.id.name().unwrap();
            if !["puts", "strlen"].contains(&name) {
                assert_eq!(import_label(q, name).as_deref(), Some(name), "{}", row.id);
            }
        }
        assert_eq!(q.state_hash(), p.state_hash());
    }
    let meta = json_of(raw.as_mut(), &dir.join(PROJECT_FILE));
    assert_eq!(
        meta.get("format_version").and_then(Value::as_u64),
        Some(FORMAT_VERSION),
        "a write open makes the project version 2"
    );
    let again = reopen(&fs, &dir, &write_opts(200)).unwrap();
    assert_eq!(again.program.state_hash(), p.state_hash());
}

//! AC-118: after SIGKILL of `ghidorah mcp` and a restart, renames, notes and `rev` survive.
//!
//! The test copies the golden v1 project (a rename, a note, an undone comment) into a new
//! projects root. A server opens it and gets a SIGKILL. When the shipped registry has
//! `history_undo`, the killed server first commits an undo and a redo. Then it commits a new
//! rename and a new note. The test checks replay, not sync: the lines are in the journal
//! before the kill.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;

#[path = "common/child.rs"]
mod child;

use std::path::PathBuf;

use ghidorah_base::{Address, BinaryId};
use ghidorah_json::Value;
use ghidorah_tools::session::ProjectsConfig;
use ghidorah_tools::{Roots, Session, SessionConfig};

use crate::child::{DEMO_ID, Server, copy_golden, demo_args};
use crate::common::tmp;

/// The address of the rename that the killed server commits.
const NEW_RENAME_AT: &str = "0x11e4";

/// The name of the rename that the killed server commits.
const NEW_NAME: &str = "loop_head";

/// The text of the note that the killed server commits.
const NEW_NOTE: &str = "The killed server wrote this note.";

fn rev_of(envelope: &Value) -> Option<u64> {
    envelope.get("rev").and_then(Value::as_u64)
}

#[test]
fn ac_118_restart_persistence() {
    let projects = tmp("ac_118");
    let dir = copy_golden(&projects);
    let root_arg = projects.to_string_lossy().into_owned();
    let args = ["--project-root", root_arg.as_str()];

    // The golden project has no analysis run. So the reopen runs the analysis, and its publish
    // commit comes after the four edit revisions.
    let mut first = Server::spawn(&args);
    let opened = first.call("binary_load", demo_args());
    assert_eq!(rev_of(&opened), Some(5), "{opened}");
    assert_eq!(
        opened.pointer("/analysis/state").and_then(Value::as_str),
        Some("complete"),
        "{opened}"
    );
    let expected = if first.tools().iter().any(|t| t == "history_undo") {
        let all = Value::object([("session", Value::from("*"))]);
        let undo = first.call("history_undo", all);
        assert_eq!(rev_of(&undo), Some(6), "{undo}");
        let redo = Value::object([("session", Value::from("*")), ("redo", Value::Bool(true))]);
        let redone = first.call("history_undo", redo);
        assert_eq!(rev_of(&redone), Some(7), "{redone}");
        7
    } else {
        5
    };
    let expected = commit_new_facts(&mut first, expected);
    first.kill();
    assert!(
        dir.join("project.lock").exists(),
        "a SIGKILL leaves the lock"
    );

    // The lock of the killed server is stale: only --break-lock replaces it.
    let mut second = Server::spawn(&args);
    let locked = second.call("binary_load", demo_args());
    assert_eq!(
        locked.pointer("/error/code").and_then(Value::as_str),
        Some("PROJECT_LOCKED"),
        "{locked}"
    );
    assert_eq!(
        locked.pointer("/error/details/stale"),
        Some(&Value::Bool(true))
    );
    second.close();

    let mut third = Server::spawn(&["--project-root", root_arg.as_str(), "--break-lock"]);
    let again = third.call("binary_load", demo_args());
    assert_eq!(rev_of(&again), Some(expected), "{again}");
    assert_eq!(
        again.pointer("/data/analysis/steps_used"),
        Some(&Value::from(0u64)),
        "the analysis of the project is current, so no run: {again}"
    );
    third.close();

    check_facts(projects, expected);
}

/// Commits a new rename and a new note through `server` at the revision `rev`. Gives the
/// revision after the two commits.
fn commit_new_facts(server: &mut Server, rev: u64) -> u64 {
    let rename = Value::object([
        ("target", Value::from(NEW_RENAME_AT)),
        ("name", Value::from(NEW_NAME)),
    ]);
    let renamed = server.call("symbol_rename", rename);
    assert_eq!(rev_of(&renamed), Some(rev + 1), "{renamed}");
    let note = Value::object([
        ("kind", Value::from("note")),
        ("text", Value::from(NEW_NOTE)),
    ]);
    let noted = server.call("note_write", note);
    assert_eq!(rev_of(&noted), Some(rev + 2), "{noted}");
    rev + 2
}

/// Checks the facts of the project under `projects`: a session in this process reads the
/// project again.
fn check_facts(projects: PathBuf, expected: u64) {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = SessionConfig::new(
        Roots::new(&workspace, &[PathBuf::from(".")]).expect("the root is valid"),
    );
    config.projects = Some(ProjectsConfig {
        root: projects,
        named: true,
        break_lock: false,
    });
    config.read_only = true;
    let mut session = Session::new(config, Box::new(ghidorah_base::FixedClock::new(0)));
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    assert!(session.open_project(id).expect("the project opens"));
    let program = &session.binary(id).expect("the binary is open").program;
    assert_eq!(program.rev().0, expected);
    let name = program
        .base()
        .symbols()
        .primary(Address::ram(0x1090))
        .map(|s| s.name.value.clone());
    assert_eq!(
        name.as_deref(),
        Some("read_input"),
        "the golden rename survives"
    );
    let at = ghidorah_base::hex::parse_u64(NEW_RENAME_AT).expect("the address parses");
    let name = program
        .base()
        .symbols()
        .primary(Address::ram(at))
        .map(|s| s.name.value.clone());
    assert_eq!(
        name.as_deref(),
        Some(NEW_NAME),
        "the rename of the killed server survives"
    );
    let texts: Vec<&str> = program.notes().iter().map(|n| n.text.as_str()).collect();
    assert_eq!(
        texts.len(),
        2,
        "the golden note and the new note: {texts:?}"
    );
    assert!(
        texts.contains(&NEW_NOTE),
        "the note of the killed server survives: {texts:?}"
    );
}

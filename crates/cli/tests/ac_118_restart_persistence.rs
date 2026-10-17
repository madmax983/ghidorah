//! AC-118: after SIGKILL of `ghidorah mcp` and a restart, renames, notes and `rev` survive.
//!
//! The test copies the golden v1 project (a rename, a note, an undone comment) into a new
//! projects root. A server opens it and gets a SIGKILL. When the shipped registry has
//! `history_undo`, the killed server first commits an undo and a redo. The test checks replay,
//! not sync: the lines are in the journal before the kill.

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

fn rev_of(envelope: &Value) -> Option<u64> {
    envelope.get("rev").and_then(Value::as_u64)
}

#[test]
fn ac_118_restart_persistence() {
    let projects = tmp("ac_118");
    let dir = copy_golden(&projects);
    let root_arg = projects.to_string_lossy().into_owned();
    let args = ["--project-root", root_arg.as_str()];

    let mut first = Server::spawn(&args);
    let opened = first.call("binary_load", demo_args());
    assert_eq!(rev_of(&opened), Some(4), "{opened}");
    let mut expected = 4;
    if first.tools().iter().any(|t| t == "history_undo") {
        let all = Value::object([("session", Value::from("*"))]);
        let undo = first.call("history_undo", all);
        assert_eq!(rev_of(&undo), Some(5), "{undo}");
        let redo = Value::object([("session", Value::from("*")), ("redo", Value::Bool(true))]);
        let redone = first.call("history_undo", redo);
        assert_eq!(rev_of(&redone), Some(6), "{redone}");
        expected = 6;
    }
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
    third.close();

    // The facts survive: a session in this process reads the project again.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = SessionConfig::new(
        Roots::new(&workspace, &[PathBuf::from(".")]).expect("the root is valid"),
    );
    config.projects = Some(ProjectsConfig {
        root: projects.clone(),
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
    assert_eq!(name.as_deref(), Some("read_input"), "the rename survives");
    assert_eq!(program.notes().iter().count(), 1, "the note survives");
}

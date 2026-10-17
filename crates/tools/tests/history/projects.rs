//! Projects in a session: reopen by `binary_id`, the lock, read-only mode, the torn tail
//! warning, the reopen hint and the root rule of ADR-0022.

use std::path::PathBuf;

use ghidorah_base::BinaryId;
use ghidorah_json::Value;
use ghidorah_tools::session::ProjectsConfig;

use crate::support::{
    DEMO_ID, call, code, config, config_in, data, load_demo, rename, session_with, state, tmp,
};

fn demo_args() -> String {
    format!(r#"{{"binary_id":"{DEMO_ID}"}}"#)
}

#[test]
fn reopen_by_binary_id_restores_the_state() {
    let dir = tmp("reopen");
    let before = {
        let mut s = session_with(config_in(&dir));
        let id = load_demo(&mut s);
        rename(&mut s, id, "mcp-1", 0x1090, "read_input");
        state(&s, id)
    };
    let project = dir.join(DEMO_ID);
    assert!(project.join("project.json").is_file());
    assert!(
        project.join("snapshot.json").is_file(),
        "a clean close writes a snapshot"
    );
    assert!(
        !project.join("project.lock").exists(),
        "a clean close releases the lock"
    );
    let mut s = session_with(config_in(&dir));
    let envelope = call(&mut s, "binary_load", &demo_args());
    let loaded = data(&envelope);
    assert_eq!(loaded.get("already_loaded"), Some(&Value::Bool(false)));
    assert_eq!(
        loaded.get("file_name").and_then(Value::as_str),
        Some("demo.elf")
    );
    assert_eq!(
        envelope.get("session").and_then(Value::as_str),
        Some("mcp-2")
    );
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    assert_eq!(state(&s, id), before);
    drop(s);
    // A load by path of the same bytes opens the same project.
    let mut by_path = session_with(config_in(&dir));
    let args = r#"{"path":"fixtures/bin/crackme.gcc-O2","analysis":"none"}"#;
    let envelope = call(&mut by_path, "binary_load", args);
    assert_eq!(
        envelope.get("rev").and_then(Value::as_u64),
        Some(1),
        "{envelope}"
    );
    assert_eq!(state(&by_path, id), before);
    // An empty root has no project of the binary.
    let mut empty = session_with(config_in(&tmp("reopen_empty")));
    assert_eq!(
        code(&call(&mut empty, "binary_load", &demo_args())),
        "UNKNOWN_BINARY"
    );
}

#[test]
fn second_writer_and_read_only() {
    let dir = tmp("locked");
    let mut first = session_with(config_in(&dir));
    load_demo(&mut first);
    let mut second = session_with(config_in(&dir));
    let locked = call(&mut second, "binary_load", &demo_args());
    assert_eq!(code(&locked), "PROJECT_LOCKED", "{locked}");
    assert_eq!(
        locked.pointer("/error/details/stale"),
        Some(&Value::Bool(false))
    );
    assert!(locked.pointer("/error/details/owner/pid").is_some());
    let mut read_config = config_in(&dir);
    read_config.read_only = true;
    let mut reader = session_with(read_config);
    let opened = call(&mut reader, "binary_load", &demo_args());
    assert_eq!(data(&opened).get("read_only"), Some(&Value::Bool(true)));
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    let refused = reader.transact(id, "symbol_rename", "mcp-1", |_| Ok(()));
    assert_eq!(
        refused.map(|_| ()).map_err(|e| e.code.name()),
        Err("READ_ONLY_PROJECT")
    );
    // A read-only load by path opens the project on disk too.
    let mut path_config = config_in(&dir);
    path_config.read_only = true;
    let mut by_path = session_with(path_config);
    let args = r#"{"path":"fixtures/bin/crackme.gcc-O2","analysis":"none"}"#;
    let envelope = call(&mut by_path, "binary_load", args);
    assert_eq!(data(&envelope).get("read_only"), Some(&Value::Bool(true)));
    assert!(by_path.store(id).and_then(|s| s.project()).is_some());
    // A read-only load of a binary with no project makes none.
    let mut fresh_config = config_in(&tmp("locked_fresh"));
    fresh_config.read_only = true;
    let mut fresh = session_with(fresh_config);
    data(&call(&mut fresh, "binary_load", args));
    assert!(fresh.store(id).and_then(|s| s.project()).is_none());
}

#[test]
fn torn_tail_gives_a_warning() {
    let dir = tmp("torn");
    {
        let mut s = session_with(config_in(&dir));
        let id = load_demo(&mut s);
        rename(&mut s, id, "mcp-1", 0x1090, "first");
        rename(&mut s, id, "mcp-1", 0x1094, "second");
    }
    let project = dir.join(DEMO_ID);
    std::fs::remove_file(project.join("snapshot.json")).expect("the snapshot exists");
    let journal = project.join("journal.jsonl");
    let text = std::fs::read(&journal).expect("the journal");
    let cut = text.len() - 7;
    std::fs::write(&journal, &text[..cut]).expect("the cut journal");
    let mut s = session_with(config_in(&dir));
    let envelope = call(&mut s, "binary_load", &demo_args());
    assert_eq!(
        envelope.get("rev").and_then(Value::as_u64),
        Some(1),
        "{envelope}"
    );
    assert_eq!(
        envelope.pointer("/warnings/0/code").and_then(Value::as_str),
        Some("W_JOURNAL_TAIL_DISCARDED")
    );
}

#[test]
fn unknown_binary_names_the_project() {
    let dir = tmp("hint");
    {
        let mut s = session_with(config_in(&dir));
        load_demo(&mut s);
    }
    let mut s = session_with(config_in(&dir));
    let envelope = call(&mut s, "history_list", &demo_args());
    assert_eq!(code(&envelope), "UNKNOWN_BINARY", "{envelope}");
    assert_eq!(
        envelope.pointer("/next/0/tool").and_then(Value::as_str),
        Some("binary_load")
    );
    assert!(
        s.open_project(BinaryId::parse(DEMO_ID).expect("the ID"))
            .expect("the open")
    );
    data(&call(&mut s, "history_list", &demo_args()));
    assert!(
        !s.open_project(BinaryId::parse("0123456789abcdef").expect("the ID"))
            .expect("no error")
    );
}

#[test]
fn default_root_in_a_git_tree_keeps_no_project() {
    let dir = tmp("git_tree");
    std::fs::create_dir_all(dir.join(".git")).expect("a git directory");
    let root: PathBuf = dir.join("projects");
    let mut cfg = config();
    cfg.projects = Some(ProjectsConfig {
        root: root.clone(),
        named: false,
        break_lock: false,
    });
    let mut s = session_with(cfg);
    load_demo(&mut s);
    assert!(!root.join(DEMO_ID).exists(), "no project inside a git tree");
    let mut named = config_in(&root);
    named.labels = ghidorah_tools::session::LabelRule::Fixed("cli".to_owned());
    let mut s = session_with(named);
    load_demo(&mut s);
    assert!(root.join(DEMO_ID).join("project.json").is_file());
}

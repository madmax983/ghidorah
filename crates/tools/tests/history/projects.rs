//! Projects in a session: reopen by `binary_id`, the lock, read-only mode, the torn tail
//! warning, the reopen hint and the root rule of ADR-0022.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ghidorah_base::BinaryId;
use ghidorah_db::fs::EntryKind;
use ghidorah_db::{Fs, FsError, RealFs};
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

#[test]
fn regress_git_tree_root_reports_not_persisted() {
    use ghidorah_base::FixedClock;
    use ghidorah_tools::{Host, Session};

    let dir = tmp("git_tree_reason");
    std::fs::create_dir_all(dir.join(".git")).expect("a git directory");
    let root: PathBuf = dir.join("projects");
    let mut cfg = config();
    cfg.projects = Some(ProjectsConfig {
        root: root.clone(),
        named: false,
        break_lock: false,
    });
    let mut s = Session::with_registry(
        <Session as Host>::registry(),
        cfg,
        Box::new(FixedClock::new(0)),
    );
    // With no open binary, the brief tells why no project persists.
    let empty = call(&mut s, "session_brief", "{}");
    assert_eq!(
        data(&empty).get("persisted"),
        Some(&Value::Bool(false)),
        "{empty}"
    );
    let reason = data(&empty)
        .get("persist_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    assert!(reason.contains("git working tree"), "{empty}");
    let load = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    let got = data(&load);
    assert_eq!(got.get("persisted"), Some(&Value::Bool(false)), "{load}");
    assert_eq!(
        got.get("persist_reason").and_then(Value::as_str),
        Some(reason.as_str()),
        "{load}"
    );
    assert!(!root.join(DEMO_ID).exists(), "no project inside a git tree");
    let brief = call(&mut s, "session_brief", "{}");
    let row = data(&brief)
        .pointer("/binaries/0")
        .cloned()
        .unwrap_or_default();
    assert_eq!(row.get("persisted"), Some(&Value::Bool(false)), "{brief}");
    assert_eq!(
        row.get("persist_reason").and_then(Value::as_str),
        Some(reason.as_str()),
        "{brief}"
    );
    // A root that keeps projects gives no persisted member.
    let mut named = session_with(config_in(&root));
    let load = call(
        &mut named,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    assert!(data(&load).get("persisted").is_none(), "{load}");
    // A bad project file gives its reason in the error details.
    drop(named);
    std::fs::write(root.join(DEMO_ID).join("project.json"), "{}").expect("a bad project file");
    let mut bad = session_with(config_in(&root));
    let error = call(&mut bad, "binary_load", &demo_args());
    assert_eq!(code(&error), "INTERNAL_ERROR", "{error}");
    assert!(
        error
            .pointer("/error/details/reason")
            .and_then(Value::as_str)
            .is_some_and(|r| r.starts_with("The project file is bad")),
        "{error}"
    );
}

/// Makes sure that `text` holds no absolute path and no part of the test directory `dir`
/// (design Section 10.11 rule 10).
fn assert_path_free(text: &str, dir: &Path, envelope: &Value) {
    assert!(!text.is_empty(), "{envelope}");
    assert!(!text.contains('/'), "an absolute path: {envelope}");
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("?");
    assert!(!text.contains(name), "a part of the root path: {envelope}");
}

#[test]
fn regress_persist_reason_has_no_absolute_path() {
    use ghidorah_base::FixedClock;
    use ghidorah_tools::{Host, Session, SessionConfig};

    let shipped = |cfg: SessionConfig| {
        Session::with_registry(
            <Session as Host>::registry(),
            cfg,
            Box::new(FixedClock::new(0)),
        )
    };
    let dir = tmp("git_tree_path_free");
    std::fs::create_dir_all(dir.join(".git")).expect("a git directory");
    let mut cfg = config();
    cfg.projects = Some(ProjectsConfig {
        root: dir.join("projects"),
        named: false,
        break_lock: false,
    });
    let mut s = shipped(cfg);
    let brief = call(&mut s, "session_brief", "{}");
    let load = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    for envelope in [&brief, &load] {
        let reason = data(envelope)
            .get("persist_reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(reason.contains("git working tree"), "{envelope}");
        assert_path_free(reason, &dir, envelope);
    }
    // A failed journal write names the file relative to the project directory.
    let full = Arc::new(AtomicBool::new(false));
    let mut s = shipped(config_in(&dir.join("named")));
    s.set_fs(Box::new(HookFs {
        full: Arc::clone(&full),
        ..HookFs::default()
    }));
    let load = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    assert!(data(&load).get("persisted").is_none(), "{load}");
    full.store(true, Ordering::SeqCst);
    let error = call(
        &mut s,
        "comment_set",
        r#"{"target":"0x1080","kind":"eol","text":"full disk"}"#,
    );
    assert_eq!(code(&error), "INTERNAL_ERROR", "{error}");
    let reason = error
        .pointer("/error/details/reason")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(reason.contains("journal.jsonl"), "{error}");
    assert!(reason.contains("append"), "{error}");
    assert_path_free(reason, &dir, &error);
}

/// The real file system with two hooks. The first `hidden` checks of a project file give
/// `false`, so the test sees the race with a second process that makes the project. While
/// `full` holds `true`, each append to a journal fails like a full disk.
#[derive(Clone, Default)]
struct HookFs {
    hidden: Arc<AtomicUsize>,
    full: Arc<AtomicBool>,
}

impl Fs for HookFs {
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        RealFs.create_dir_all(path)
    }
    fn create_new(&mut self, path: &Path) -> Result<(), FsError> {
        RealFs.create_new(path)
    }
    fn append(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if self.full.load(Ordering::SeqCst) && path.ends_with("journal.jsonl") {
            return Err(FsError::Io {
                op: "append",
                path: path.to_path_buf(),
                message: "No space left on device (os error 28)".to_owned(),
            });
        }
        RealFs.append(path, bytes)
    }
    fn write_all(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        RealFs.write_all(path, bytes)
    }
    fn truncate(&mut self, path: &Path, len: u64) -> Result<(), FsError> {
        RealFs.truncate(path, len)
    }
    fn sync_file(&mut self, path: &Path) -> Result<(), FsError> {
        RealFs.sync_file(path)
    }
    fn rename(&mut self, from: &Path, to: &Path) -> Result<(), FsError> {
        RealFs.rename(from, to)
    }
    fn link_new(&mut self, src: &Path, dst: &Path) -> Result<(), FsError> {
        RealFs.link_new(src, dst)
    }
    fn sync_dir(&mut self, path: &Path) -> Result<(), FsError> {
        RealFs.sync_dir(path)
    }
    fn remove(&mut self, path: &Path) -> Result<(), FsError> {
        RealFs.remove(path)
    }
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, FsError> {
        RealFs.read(path)
    }
    fn set_read_only(&mut self, path: &Path) -> Result<(), FsError> {
        RealFs.set_read_only(path)
    }
    fn list(&mut self, dir: &Path) -> Result<Vec<String>, FsError> {
        RealFs.list(dir)
    }
    fn exists(&mut self, path: &Path) -> bool {
        let hide = path.ends_with("project.json")
            && self
                .hidden
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
        !hide && RealFs.exists(path)
    }
    fn kind(&mut self, path: &Path) -> Option<EntryKind> {
        RealFs.kind(path)
    }
    fn modified(&mut self, path: &Path) -> Option<std::time::SystemTime> {
        RealFs.modified(path)
    }
    fn boxed(&self) -> Box<dyn Fs> {
        Box::new(self.clone())
    }
}

#[test]
fn regress_admit_reopens_a_project_made_meanwhile() {
    let dir = tmp("late_project");
    {
        let mut first = session_with(config_in(&dir));
        load_demo(&mut first);
    }
    let mut s = session_with(config_in(&dir));
    s.set_fs(Box::new(HookFs {
        hidden: Arc::new(AtomicUsize::new(1)),
        ..HookFs::default()
    }));
    // The check of admit misses the project, so the create finds the project file.
    let envelope = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    let got = data(&envelope);
    assert_eq!(got.get("already_loaded"), Some(&Value::Bool(false)));
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    assert!(
        s.store(id).and_then(|st| st.project()).is_some(),
        "the session opens the project on disk"
    );
}

//! The envelope frame, `partial` and the repair hints of failures (design Sections 10.6
//! and 10.8).

use std::path::{Path, PathBuf};

use ghidorah_json::Value;
use ghidorah_tools::handlers::analysis_run;
use ghidorah_tools::session::ProjectsConfig;
use ghidorah_tools::{Host, Profile, ProfileSet, Session};

use crate::support::{call, code, config, data, fixture, load, session_with, text_at};

/// A binary with no analysis run gives partial results, an `analysis` member with the
/// state `none` and the `analysis_run` hint.
#[test]
fn regress_no_analysis_is_partial() {
    let (mut s, _) = fixture("hello.gcc-O0");
    let list = call(&mut s, "func_list", "{}");
    assert_eq!(list.get("ok"), Some(&Value::Bool(true)), "{list}");
    assert_eq!(list.get("partial"), Some(&Value::Bool(true)), "{list}");
    assert_eq!(text_at(&list, "/analysis/state"), "none", "{list}");
    assert_eq!(text_at(&list, "/next/0/tool"), "analysis_run", "{list}");
}

/// Gives a new empty directory for one test.
fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("session")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Makes a session with `profile` and the projects root `projects`, or no projects root.
fn session_in(profile: ProfileSet, projects: Option<&Path>) -> Session {
    let mut c = config();
    c.profile = profile;
    c.projects = projects.map(|root| ProjectsConfig {
        root: root.to_path_buf(),
        named: true,
        break_lock: false,
    });
    session_with(c)
}

/// Makes sure that the hint of a failure names `next[0]` and the candidates only when the
/// envelope holds them.
fn assert_hint_matches(envelope: &Value) {
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(false)), "{envelope}");
    let hint = text_at(envelope, "/error/hint");
    assert!(!hint.is_empty(), "{envelope}");
    if envelope.get("next").is_none() {
        assert!(!hint.contains("next[0]"), "{envelope}");
    }
    if envelope.pointer("/error/candidates").is_none() {
        assert!(!hint.contains("candidate"), "{envelope}");
    }
}

/// The hint of a failure never names `next[0]`, the candidates or the scope `*` when the
/// envelope does not hold them.
#[test]
fn regress_hint_matches_payload() {
    let mini = || ProfileSet::new(Profile::Mini, None);
    let mut s = session_in(mini(), None);
    let open = call(&mut s, "func_list", "{}");
    assert_eq!(code(&open), "NO_BINARY_OPEN", "{open}");
    assert_hint_matches(&open);
    let tools = ["func_list", "func_get", "xref_list"].map(str::to_owned);
    let mut s = session_in(ProfileSet::new(Profile::Full, Some(tools.to_vec())), None);
    let _ = load(&mut s, "fixtures/bin/hello.gcc-O0");
    let missing = call(&mut s, "func_get", "{}");
    assert_eq!(code(&missing), "MISSING_ARGUMENT", "{missing}");
    assert_hint_matches(&missing);
    let (mut s, _) = fixture("hello.gcc-O0");
    let found = call(&mut s, "func_get", r#"{"target":"nosuchname"}"#);
    assert_eq!(code(&found), "NOT_FOUND", "{found}");
    assert!(found.pointer("/error/candidates").is_none(), "{found}");
    assert_hint_matches(&found);
    let undo = call(&mut s, "history_undo", r#"{"session":"*"}"#);
    assert_eq!(code(&undo), "NOTHING_TO_UNDO", "{undo}");
    assert_hint_matches(&undo);
    for part in ["/error/hint", "/error/message"] {
        assert!(!text_at(&undo, part).contains('*'), "{undo}");
    }
    // In mini, the repair of NO_BINARY_OPEN opens the newest project.
    let dir = tmp("hint_mini_project");
    let mut full = session_in(ProfileSet::default(), Some(&dir));
    let id = load(&mut full, "fixtures/bin/hello.gcc-O0");
    drop(full);
    let mut s = session_in(mini(), Some(&dir));
    let open = call(&mut s, "func_list", "{}");
    assert_eq!(code(&open), "NO_BINARY_OPEN", "{open}");
    assert_eq!(text_at(&open, "/next/0/tool"), "binary_load", "{open}");
    assert_eq!(text_at(&open, "/next/0/args/binary_id"), id, "{open}");
    assert_hint_matches(&open);
}

/// A failed call reports the real frame: the rev, the binary and the session label.
#[test]
fn regress_failed_call_frame_is_real() {
    let mut s = session_in(ProfileSet::new(Profile::Mini, None), None);
    let id = load(&mut s, "fixtures/bin/hello.gcc-O0");
    let note = call(&mut s, "note_write", r#"{"kind":"note","text":"x"}"#);
    assert_eq!(note.get("ok"), Some(&Value::Bool(true)), "{note}");
    let rev = note.get("rev").and_then(Value::as_u64);
    let args = r#"{"target":"main","kind":"eol","text":"x"}"#;
    let outside = call(&mut s, "comment_set", args);
    assert_eq!(code(&outside), "TOOL_NOT_IN_PROFILE", "{outside}");
    assert_eq!(outside.get("rev").and_then(Value::as_u64), rev, "{outside}");
    assert_eq!(text_at(&outside, "/binary_id"), id, "{outside}");
    assert_eq!(text_at(&outside, "/session"), "cli", "{outside}");
    let hint = text_at(&outside, "/error/hint");
    assert!(
        hint.contains("mini") && hint.contains("--profile full"),
        "{outside}"
    );
    assert!(!hint.contains("destructive"), "{outside}");
    assert_eq!(
        text_at(&outside, "/next/0/tool"),
        "tool_search",
        "{outside}"
    );
    assert_eq!(text_at(&outside, "/next/0/args/query"), "comment_set");
    let closest = call(&mut s, "func_edit", "{}");
    assert_eq!(code(&closest), "TOOL_NOT_IN_PROFILE", "{closest}");
    let values: Vec<String> = closest
        .pointer("/error/candidates")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|c| text_at(c, "/value"))
        .collect();
    assert!(values.iter().any(|v| v == "func_get"), "{closest}");
    assert!(values.iter().all(|v| s.in_profile(v)), "{closest}");
    let mut empty = session_in(ProfileSet::default(), None);
    let open = call(&mut empty, "func_list", r#"{"session":"agent-7"}"#);
    assert_eq!(code(&open), "NO_BINARY_OPEN", "{open}");
    assert_eq!(text_at(&open, "/session"), "agent-7", "{open}");
    let (mut s, _) = fixture("hello.gcc-O0");
    let note = call(
        &mut s,
        "note_write",
        r#"{"kind":"note","text":"x","session":"agent-7"}"#,
    );
    assert_eq!(text_at(&note, "/session"), "agent-7", "{note}");
    let undo = call(&mut s, "history_undo", r#"{"session":"*"}"#);
    assert_eq!(undo.get("ok"), Some(&Value::Bool(true)), "{undo}");
    assert_eq!(text_at(&undo, "/session"), "cli", "{undo}");
    assert_eq!(
        text_at(&undo, "/data/undone/0/session"),
        "agent-7",
        "{undo}"
    );
}

/// Gives the items of a list envelope.
fn items(envelope: &Value) -> Vec<Value> {
    data(envelope)
        .get("items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .to_vec()
}

/// The `in` filter keeps the cross-references whose source function or source address is in
/// the set.
#[test]
fn regress_in_filter_matches_xref_items() {
    let mut s = session_in(ProfileSet::default(), None);
    analysis_run::install(&mut s);
    let load = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(
        text_at(data(&load), "/analysis/state"),
        "complete",
        "{load}"
    );
    let ids = r#"{"kind":"set","set":{"name":"m","members":["fn:0x1080"]}}"#;
    let _ = data(&call(&mut s, "note_write", ids));
    let range =
        r#"{"kind":"set","set":{"name":"r","members":[{"start":"0x1000","end":"0x2000"}]}}"#;
    let _ = data(&call(&mut s, "note_write", range));
    let from = r#""targets":["fn:0x1080"],"direction":"from""#;
    let all = items(&call(&mut s, "xref_list", &format!("{{{from}}}")));
    assert!(!all.is_empty(), "main has references");
    for set in ["set:m", "set:r"] {
        let args = format!(r#"{{{from},"in":"{set}"}}"#);
        let kept = items(&call(&mut s, "xref_list", &args));
        assert_eq!(kept.len(), all.len(), "{set}: {kept:?}");
        for item in &kept {
            assert_eq!(text_at(item, "/from_func/id"), "fn:0x1080", "{item}");
        }
    }
    let other = r#"{"kind":"set","set":{"name":"o","members":["fn:0x11e0"]}}"#;
    let _ = data(&call(&mut s, "note_write", other));
    let args = format!(r#"{{{from},"in":"set:o"}}"#);
    assert!(items(&call(&mut s, "xref_list", &args)).is_empty());
}

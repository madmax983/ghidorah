//! `session_brief`: the brief of an open binary (AC-155), the last-brief marks and the project
//! list with zero open binaries (AC-212).

use ghidorah_base::{Address, FuncId, VarId};
use ghidorah_db::{Edit, SessionLabel, SymKind, VarField};
use ghidorah_json::Value;
use ghidorah_tools::content::result_chars;
use ghidorah_tools::{ContentMode, Request, Session, ToolError, dispatch_with};

use crate::support::{
    STRIPPED, call, call_value, chars, code, config, config_in, data, fixture, int_at, next0,
    program, session_with, str_of, text_at, tmp,
};

/// Gives the list at `key` of the data of an envelope.
fn list(envelope: &Value, key: &str) -> Vec<Value> {
    data(envelope)
        .get(key)
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
}

/// Commits agent facts whose function does not exist: a function name and a variable name at
/// the address 0x1088 inside `main`.
fn orphans(session: &mut Session, id: ghidorah_base::BinaryId) {
    let var = VarId {
        func: FuncId(Address::ram(0x1088)),
        storage: ghidorah_base::Storage::Stack(-8),
    };
    session
        .transact(id, "symbol_rename", "cli", |tx| {
            let name = tx.fact("lost_function".to_owned());
            tx.apply(Edit::SetName {
                addr: Address::ram(0x1088),
                key: None,
                kind: SymKind::Function,
                primary: true,
                name: Some(name),
                evidence: Vec::new(),
            })
            .map_err(|e| ToolError::new(e.code()))?;
            let var_name = tx.fact("lost_var".to_owned());
            tx.apply(Edit::SetVarFact {
                var: var.clone(),
                field: VarField::Name(Some(var_name)),
            })
            .map(drop)
            .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the orphans commit");
}

/// Writes the notes, the renames and the comments of a busy session.
fn busy(session: &mut Session, long_notes: usize) {
    let long = "x".repeat(400);
    let calls = [
        (
            "note_write",
            r#"{"kind":"todo","text":"Read the password check.","at":"0x11e0"}"#.to_owned(),
        ),
        (
            "note_write",
            r#"{"kind":"hypothesis","text":"main calls strlen.","claims":[{"rel":"calls","args":["fn:0x1080","imp:strlen"]}]}"#.to_owned(),
        ),
        (
            "note_write",
            r#"{"kind":"finding","text":"The check compares a length.","evidence":["fn:0x11e0"]}"#.to_owned(),
        ),
        (
            "note_write",
            r#"{"kind":"todo","text":"Old task.","status":"done"}"#.to_owned(),
        ),
        (
            "symbol_rename",
            r#"{"target":"fn:0x11e0","name":"check_password"}"#.to_owned(),
        ),
        (
            "comment_set",
            r#"{"target":"0x1084","kind":"eol","text":"Align the stack."}"#.to_owned(),
        ),
    ];
    for (tool, args) in calls {
        let envelope = call(session, tool, &args);
        assert_eq!(code(&envelope), "", "{tool} {args}: {envelope}");
    }
    for i in 0..long_notes {
        let kind = if i % 2 == 0 { "todo" } else { "finding" };
        let args = Value::object([
            ("kind", Value::from(kind)),
            ("text", Value::from(format!("Note {i}. {long}"))),
            ("evidence", Value::Array(vec![Value::from("fn:0x1080")])),
        ]);
        let envelope = call_value(session, "note_write", args);
        assert_eq!(code(&envelope), "", "{envelope}");
    }
}

#[test]
fn ac_155_session_brief() {
    for long_notes in [0, 40] {
        let (mut session, id) = fixture(STRIPPED);
        busy(&mut session, long_notes);
        orphans(&mut session, id);
        let rev = program(&session, id).rev().0;
        let brief = call(&mut session, "session_brief", "{}");
        assert!(chars(&brief) <= 8_000, "{} chars", chars(&brief));
        assert_eq!(int_at(&brief, "/rev"), rev, "a brief changes no rev");
        assert_eq!(text_at(&brief, "/data/binary_id"), id.to_string());
        let d = data(&brief);
        assert!(int_at(d, "/open_notes/todo") >= 1, "{brief}");
        assert_eq!(int_at(d, "/open_notes/hypothesis"), 1);
        let top = d
            .pointer("/open_notes/top")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        assert!(!top.is_empty(), "{brief}");
        assert!(top.iter().all(|n| str_of(n, "status") == "open"), "{brief}");
        assert!(top.iter().all(|n| str_of(n, "text").chars().count() <= 160));
        assert!(!list(&brief, "recent_findings").is_empty(), "{brief}");
        let edits = list(&brief, "recent_edits");
        assert!(!edits.is_empty(), "{brief}");
        let found = list(&brief, "orphans");
        let kinds: Vec<(String, String)> = found
            .iter()
            .map(|o| (str_of(o, "kind"), str_of(o, "at")))
            .collect();
        assert!(
            kinds.contains(&("name".to_owned(), "0x1088".to_owned())),
            "{brief}"
        );
        assert!(
            kinds.contains(&("var".to_owned(), "0x1088".to_owned())),
            "{brief}"
        );
        let weak = list(&brief, "weak_names");
        assert!(!weak.is_empty(), "{brief}");
        assert!(weak.iter().all(|w| str_of(w, "name").starts_with("FUN_")));
        assert!(
            weak.iter().all(|w| str_of(w, "id") != "fn:0x11e0"),
            "a renamed function is not weak"
        );
        assert_eq!(int_at(d, "/progress/functions"), 12);
        assert_eq!(
            d.get("truncated"),
            Some(&Value::Bool(long_notes > 0)),
            "{} chars",
            chars(&brief)
        );
        if long_notes == 0 {
            assert!(
                edits.iter().any(|e| str_of(e, "value") == "check_password"),
                "{brief}"
            );
        }
        let mut request =
            Request::new("session_brief", Value::Object(ghidorah_json::Object::new()));
        request.content = ContentMode::Both;
        let registry = session.active_registry();
        let both = dispatch_with(&registry, &mut session, &request).to_json();
        assert!(
            result_chars(&both, false, ContentMode::Both) <= 8_000,
            "two copies fit"
        );
    }
}

#[test]
fn brief_marks_and_changes() {
    let (mut session, id) = fixture(STRIPPED);
    let first = call(&mut session, "session_brief", "{}");
    assert_eq!(
        int_at(&first, "/data/changed_since_last_brief/since_rev"),
        0,
        "{first}"
    );
    assert_eq!(int_at(&first, "/data/changed_since_last_brief/count"), 0);
    let label = SessionLabel::new("cli").expect("a label");
    let mark = program(&session, id)
        .progress()
        .mark(&label)
        .map(|m| m.last_brief_rev.0);
    assert_eq!(
        mark,
        Some(int_at(&first, "/rev")),
        "the brief writes its mark"
    );
    let renamed = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"fn:0x11e0","name":"check_password"}"#,
    );
    assert_eq!(code(&renamed), "", "{renamed}");
    let second = call(&mut session, "session_brief", "{}");
    let changed = second
        .pointer("/data/changed_since_last_brief")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        int_at(&changed, "/since_rev"),
        int_at(&first, "/rev"),
        "{second}"
    );
    assert_eq!(int_at(&changed, "/count"), 1);
    assert_eq!(
        changed.get("by_kind"),
        Some(
            &ghidorah_json::parse(
                r#"[{"kind":"name","count":1}]"#,
                &ghidorah_json::Limits::DEFAULT
            )
            .expect("JSON")
        )
    );
    let third = call(&mut session, "session_brief", "{}");
    assert_eq!(
        int_at(&third, "/data/changed_since_last_brief/count"),
        0,
        "{third}"
    );
    let other = call(&mut session, "session_brief", r#"{"session":"other"}"#);
    assert_eq!(
        int_at(&other, "/data/changed_since_last_brief/count"),
        1,
        "{other}"
    );
    assert_eq!(text_at(&other, "/session"), "other");
}

#[test]
fn ac_212_projects_listing() {
    let dir = tmp("ac_212");
    {
        let mut a = session_with(config_in(&dir));
        let demo = call(&mut a, "binary_load", r#"{"builtin":"demo"}"#);
        assert_eq!(code(&demo), "", "{demo}");
        let forced = call(
            &mut a,
            "symbol_rename",
            r#"{"target":"fn:0x11e0","name":"check_pw","force":true}"#,
        );
        assert_eq!(code(&forced), "", "{forced}");
        let stripped = call(
            &mut a,
            "binary_load",
            r#"{"path":"fixtures/bin/crackme.gcc-O2.stripped"}"#,
        );
        let stripped_id = text_at(&stripped, "/data/binary_id");
        for args in [
            r#"{"kind":"todo","text":"Read main."}"#,
            r#"{"kind":"finding","text":"main reads input.","evidence":["fn:0x1080"]}"#,
        ] {
            let mut object = ghidorah_json::parse(args, &ghidorah_json::Limits::DEFAULT)
                .expect("JSON")
                .as_object()
                .cloned()
                .unwrap_or_default();
            object.push("binary_id", Value::from(stripped_id.as_str()));
            let envelope = call_value(&mut a, "note_write", Value::Object(object));
            assert_eq!(code(&envelope), "", "{envelope}");
        }
    }
    let mut b = session_with(config_in(&dir));
    let brief = call(&mut b, "session_brief", "{}");
    let projects = list(&brief, "projects");
    assert_eq!(projects.len(), 2, "{brief}");
    assert_eq!(
        str_of(&projects[0], "file_name"),
        "crackme.gcc-O2.stripped",
        "newest rev first"
    );
    assert_eq!(str_of(&projects[1], "binary_id"), crate::support::DEMO_ID);
    assert!(int_at(&projects[0], "/rev") >= int_at(&projects[1], "/rev"));
    for p in &projects {
        assert_eq!(p.get("open"), Some(&Value::Bool(false)));
        assert_eq!(str_of(p, "last_session"), "mcp-1", "{p}");
    }
    let (tool, args) = next0(&brief);
    assert_eq!(tool, "binary_load");
    assert_eq!(
        str_of(&args, "binary_id"),
        str_of(&projects[0], "binary_id")
    );
    let opened = call_value(&mut b, &tool, args);
    assert_eq!(code(&opened), "", "{opened}");
    let notes = call(&mut b, "search", r#"{"ids":["note:1","note:2"]}"#);
    assert_eq!(
        text_at(&notes, "/data/items/0/text"),
        "Read main.",
        "{notes}"
    );
    let after = call(&mut b, "session_brief", "{}");
    assert!(
        data(&after).get("projects").is_none(),
        "an open binary gets a brief: {after}"
    );
    assert_eq!(int_at(&after, "/data/open_notes/todo"), 1);

    let mut none = session_with(config());
    let empty = call(&mut none, "session_brief", "{}");
    assert!(list(&empty, "projects").is_empty(), "{empty}");
    let (tool, args) = next0(&empty);
    assert_eq!(tool, "tool_search");
    assert_eq!(str_of(&args, "name"), "binary_load");
}

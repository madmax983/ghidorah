//! The read-back map of design Section 10.12 (AC-206).
//!
//! Each row writes a value and reads it back in one batch. The read step has an `expect`
//! guard on the mapped field. The two destructive edits run as direct calls, and a batch
//! reads them back.

use std::collections::BTreeSet;

use ghidorah_db::{EditKind, NoteKind};
use ghidorah_json::Value;

use crate::support::{batch, call, data, demo, steps, text_at};

/// One row of the read-back map: the edit kinds, the note kinds and the batch steps.
struct Row {
    edits: &'static [&'static str],
    notes: &'static [&'static str],
    steps: &'static str,
}

const ROWS: &[Row] = &[
    Row {
        edits: &["SetName"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"symbol_rename","args":{"target":"fn:0x11e0","name":"verify_input","evidence":["fn:0x1080"],"force":true}},
            {"id":"r1","tool":"func_list","args":{"filter":{"name":"verify_*"}},"expect":[{"ptr":"/data/items/0/name","op":"eq","value":"verify_input"}]},
            {"id":"r2","tool":"func_get","args":{"target":"fn:0x11e0"},"expect":[{"ptr":"/data/name","op":"eq","value":"verify_input"}]},
            {"id":"r3","tool":"search","args":{"kind":"name","query":"verify_input"},"expect":[{"ptr":"/data/items","op":"len_gt","value":0}]},
            {"id":"r4","tool":"addr_info","args":{"target":"0x11e0"},"expect":[{"ptr":"/data/symbol/name","op":"eq","value":"verify_input"}]}
        ]"#,
    },
    Row {
        edits: &["SetComment"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"comment_set","args":{"target":"0x1080","kind":"eol","text":"reads the input"}},
            {"id":"r1","tool":"addr_info","args":{"target":"0x1080","include":["comments"]},"expect":[{"ptr":"/data/comments/0/text","op":"eq","value":"reads the input"}]},
            {"id":"r2","tool":"search","args":{"kind":"comment","query":"reads the"},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]}
        ]"#,
    },
    Row {
        edits: &["SetVarFact"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"symbol_rename","args":{"target":"var:0x11e0/stack:-0x14","name":"length"}},
            {"id":"r","tool":"func_get","args":{"target":"fn:0x11e0","include":["vars"]},"expect":[{"ptr":"/data/vars/*/name","op":"contains","value":"length"}]}
        ]"#,
    },
    Row {
        edits: &["AddRef"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"func_edit","args":{"action":"add_ref","ref":{"from":"0x10f8","to":"0x2004","kind":"read"}}},
            {"id":"r","tool":"xref_list","args":{"targets":["0x2004"]},"expect":[{"ptr":"/data/items/*/source","op":"contains","value":"agent"}]}
        ]"#,
    },
    Row {
        edits: &["CreateFunction"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"func_edit","args":{"action":"create","target":"0x11d0"}},
            {"id":"r1","tool":"func_get","args":{"target":"fn:0x11d0"},"expect":[{"ptr":"/data/start_reason","op":"eq","value":"agent"}]},
            {"id":"r2","tool":"func_list","args":{"filter":{"start_reason":["agent"]}},"expect":[{"ptr":"/data/items/*/id","op":"contains","value":"fn:0x11d0"}]}
        ]"#,
    },
    Row {
        edits: &["SetSignature"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"type_edit","args":{"target":"fn:0x11e0","signature":"int check_password(const char *input)"}},
            {"id":"r","tool":"func_get","args":{"target":"fn:0x11e0"},"expect":[{"ptr":"/data/signature","op":"exists"}]}
        ]"#,
    },
    Row {
        edits: &["SetNoreturn"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"func_edit","args":{"action":"set_noreturn","target":"fn:0x11e0","noreturn":true}},
            {"id":"r","tool":"func_get","args":{"target":"fn:0x11e0"},"expect":[{"ptr":"/data/flags","op":"contains","value":"noreturn"}]}
        ]"#,
    },
    Row {
        edits: &["SetJumpTable"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"func_edit","args":{"action":"set_jumptable","at":"0x1170","targets":["0x1178"]}},
            {"id":"r1","tool":"func_get","args":{"target":"fn:0x1140","include":["jumptables"]},"expect":[{"ptr":"/data/jumptables","op":"len_gt","value":0}]},
            {"id":"r2","tool":"search","args":{"ids":["jt:0x1170"]},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]}
        ]"#,
    },
    Row {
        edits: &["SetFlowOverride"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"func_edit","args":{"action":"set_flow","at":"0x10c7","flow":{"kind":"call_as_jump"}}},
            {"id":"r","tool":"addr_info","args":{"target":"0x10c7"},"expect":[{"ptr":"/data/override/kind","op":"eq","value":"call_as_jump"}]}
        ]"#,
    },
    Row {
        edits: &["SetDataDef"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"type_edit","args":{"target":"0x2004","type":"char [26]"}},
            {"id":"r","tool":"addr_info","args":{"target":"0x2004"},"expect":[{"ptr":"/data/code_unit/type","op":"eq","value":"char [26]"}]}
        ]"#,
    },
    Row {
        edits: &["WriteNote"],
        notes: &["note", "todo", "hypothesis", "finding", "error"],
        steps: r#"[
            {"id":"n1","tool":"note_write","args":{"kind":"note","text":"main reads the password.","at":"0x1080"}},
            {"id":"n2","tool":"note_write","args":{"kind":"todo","text":"Read check_password.","at":"0x11e0"}},
            {"id":"n3","tool":"note_write","args":{"kind":"hypothesis","text":"main calls puts.","claims":[{"rel":"calls","args":["fn:0x1080","imp:puts"]}]}},
            {"id":"n4","tool":"note_write","args":{"kind":"finding","text":"check_password calls strlen.","evidence":["fn:0x11e0","imp:strlen"]}},
            {"id":"n5","tool":"note_write","args":{"kind":"error","text":"The input type is not known."}},
            {"id":"r1","tool":"search","args":{"kind":"note","note_filter":{"kind":"note"}},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]},
            {"id":"r2","tool":"search","args":{"kind":"note","note_filter":{"kind":"todo"}},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]},
            {"id":"r3","tool":"search","args":{"kind":"note","note_filter":{"kind":"hypothesis"}},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]},
            {"id":"r4","tool":"search","args":{"kind":"note","note_filter":{"kind":"finding"}},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]},
            {"id":"r5","tool":"search","args":{"kind":"note","note_filter":{"kind":"error"}},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]},
            {"id":"r6","tool":"search","args":{"ids":[{"$ref":"n2","ptr":"/data/note"}]},"expect":[{"ptr":"/data/items/0/text","op":"eq","value":"Read check_password."}]}
        ]"#,
    },
    Row {
        edits: &["WriteNote"],
        notes: &["set"],
        steps: r#"[
            {"id":"w","tool":"note_write","args":{"kind":"set","set":{"name":"checks","members":["fn:0x11e0","fn:0x1080"],"op":"union"}}},
            {"id":"r1","tool":"search","args":{"kind":"set"},"expect":[{"ptr":"/data/items","op":"len_eq","value":1}]},
            {"id":"r2","tool":"func_list","args":{"in":"set:checks"},"expect":[{"ptr":"/data/items","op":"len_eq","value":2}]}
        ]"#,
    },
    Row {
        edits: &["DeleteNote"],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"note_write","args":{"kind":"note","text":"A note to delete."}},
            {"id":"d","tool":"note_write","args":{"target":{"$ref":"w","ptr":"/data/note"},"delete":true}},
            {"id":"r","tool":"search","args":{"kind":"note"},"expect":[{"ptr":"/data/items","op":"len_eq","value":0}]}
        ]"#,
    },
    Row {
        edits: &[],
        notes: &[],
        steps: r#"[
            {"id":"w","tool":"func_get","args":{"target":"fn:0x11e0","include":["disasm"]}},
            {"id":"r","tool":"func_list","args":{"filter":{"visited":true}},"expect":[{"ptr":"/data/items/0/id","op":"eq","value":"fn:0x11e0"}]}
        ]"#,
    },
];

/// Runs the batch of `steps` and makes sure that each step passes.
fn run_row(steps_text: &str) {
    let mut s = demo();
    let text = format!(r#"{{"steps":{steps_text},"on_error":"continue"}}"#);
    check_all(&batch(&mut s, &text), steps_text);
}

/// Makes sure that every step entry of `envelope` passes.
fn check_all(envelope: &Value, what: &str) {
    assert_eq!(
        envelope.get("ok"),
        Some(&Value::Bool(true)),
        "{what}: {envelope}"
    );
    for entry in steps(envelope) {
        assert_eq!(entry.get("ok"), Some(&Value::Bool(true)), "{what}: {entry}");
    }
}

#[test]
fn ac_206_read_back() {
    let mut edits: BTreeSet<&str> = BTreeSet::new();
    let mut notes: BTreeSet<&str> = BTreeSet::new();
    for row in ROWS {
        run_row(row.steps);
        edits.extend(row.edits);
        notes.extend(row.notes);
    }

    // RemoveRef and DeleteFunction are destructive, so direct calls write them.
    let mut s = demo();
    let add = r#"{"action":"add_ref","ref":{"from":"0x10f8","to":"0x2004","kind":"read"}}"#;
    data(&call(&mut s, "func_edit", add));
    let remove = r#"{"action":"remove_ref","ref":{"from":"0x10f8","to":"0x2004","kind":"read"}}"#;
    data(&call(&mut s, "func_edit", remove));
    let read = batch(
        &mut s,
        r#"{"steps":[{"id":"r","tool":"xref_list","args":{"targets":["0x2004"]}}]}"#,
    );
    check_all(&read, "remove_ref");
    let agent = read
        .pointer("/data/steps/0/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .any(|i| text_at(i, "/source") == "agent");
    assert!(!agent, "{read}");
    edits.insert("RemoveRef");

    let mut s = demo();
    data(&call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x11d0"}"#,
    ));
    data(&call(
        &mut s,
        "func_edit",
        r#"{"action":"delete","target":"fn:0x11d0"}"#,
    ));
    let read = batch(
        &mut s,
        r#"{"steps":[{"id":"r","tool":"func_list","args":{"filter":{"start_reason":["agent"]}},"expect":[{"ptr":"/data/items","op":"len_eq","value":0}]}]}"#,
    );
    check_all(&read, "delete");
    edits.insert("DeleteFunction");

    // ReplaceAnalysis: the analysis run of a load writes a marker that history_list shows.
    let mut s = crate::support::session();
    data(&call(&mut s, "binary_load", r#"{"builtin":"demo"}"#));
    let read = batch(
        &mut s,
        r#"{"steps":[{"id":"r","tool":"history_list","args":{"coalesce":false},"expect":[{"ptr":"/data/items/*/kind","op":"contains","value":"analysis"}]}]}"#,
    );
    check_all(&read, "analysis_run");
    edits.insert("ReplaceAnalysis");

    let want_edits: BTreeSet<&str> = EditKind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(edits, want_edits, "every edit kind has a read-back row");
    let want_notes: BTreeSet<&str> = NoteKind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(notes, want_notes, "every note kind has a read-back row");
}

//! Keyset cursors of `func_list` across renames (AC-136a to AC-136c).

use ghidorah_json::Value;

use crate::support::{STRIPPED, call, call_value, code, fixture, ids, json, next0, text_at};

/// Gives the IDs of every function in the order of `sort`.
fn order(session: &mut ghidorah_tools::Session, sort: &str) -> Vec<String> {
    let args = format!(r#"{{"sort":"{sort}","limit":1000}}"#);
    ids(&call(session, "func_list", &args))
}

/// Gives the first page of `sort` with `limit` items and its cursor.
fn first_page(
    session: &mut ghidorah_tools::Session,
    sort: &str,
    limit: u32,
) -> (Vec<String>, String) {
    let args = format!(r#"{{"sort":"{sort}","limit":{limit}}}"#);
    let envelope = call(session, "func_list", &args);
    let cursor = text_at(&envelope, "/page/next_cursor");
    assert!(!cursor.is_empty(), "the page has a cursor: {envelope}");
    (ids(&envelope), cursor)
}

/// Gives the page of `sort` after `cursor`.
fn next_page(session: &mut ghidorah_tools::Session, sort: &str, limit: u32, cursor: &str) -> Value {
    let args = Value::object([
        ("sort", Value::from(sort)),
        ("limit", Value::from(limit)),
        ("cursor", Value::from(cursor)),
    ]);
    call_value(session, "func_list", args)
}

/// Renames the function `id` with `symbol_rename` and makes sure that the call commits.
fn rename(session: &mut ghidorah_tools::Session, id: &str, name: &str) {
    let args = Value::object([("target", Value::from(id)), ("name", Value::from(name))]);
    let envelope = call_value(session, "symbol_rename", args);
    assert_eq!(code(&envelope), "", "{envelope}");
    assert_eq!(
        envelope.get("noop"),
        Some(&Value::Bool(false)),
        "{envelope}"
    );
}

#[test]
fn ac_136a_rename_keeps_cursors() {
    for sort in ["addr", "priority"] {
        let (mut session, _) = fixture(crate::support::STRIPPED);
        let all = order(&mut session, sort);
        let (page, cursor) = first_page(&mut session, sort, 3);
        assert_eq!(page, all[..3].to_vec());
        rename(&mut session, &page[2], "boundary_item");
        rename(&mut session, &all[4], "later_item");
        let next = next_page(&mut session, sort, 3, &cursor);
        assert_eq!(code(&next), "", "{sort}: {next}");
        assert_eq!(ids(&next), all[3..6].to_vec(), "{sort}");
    }
}

#[test]
fn ac_136b_name_sort_stale() {
    let (mut session, _) = fixture(STRIPPED);
    let all = order(&mut session, "name");
    let (page, cursor) = first_page(&mut session, "name", 3);
    assert_eq!(page, all[..3].to_vec());
    rename(&mut session, &page[0], "zz_not_the_boundary");
    let kept = next_page(&mut session, "name", 3, &cursor);
    assert_eq!(
        code(&kept),
        "",
        "a rename of another item keeps the cursor: {kept}"
    );
    rename(&mut session, &page[2], "aa_boundary");
    let stale = next_page(&mut session, "name", 3, &cursor);
    assert_eq!(code(&stale), "CURSOR_STALE", "{stale}");
    let (tool, args) = next0(&stale);
    assert_eq!(tool, "func_list");
    assert_eq!(args, json(r#"{"sort":"name","limit":3}"#), "{stale}");
    let again = call_value(&mut session, &tool, args);
    assert_eq!(code(&again), "", "{again}");
}

#[test]
fn ac_136c_tampered_cursor() {
    let (mut session, _) = fixture(STRIPPED);
    let (page, cursor) = first_page(&mut session, "addr", 3);
    rename(&mut session, &page[1], "renamed_first_page");
    let mut bytes: Vec<char> = cursor.chars().collect();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == '0' { '1' } else { '0' };
    let tampered: String = bytes.into_iter().collect();
    for bad in [tampered.as_str(), "zz", "0123"] {
        let envelope = next_page(&mut session, "addr", 3, bad);
        assert_eq!(code(&envelope), "CURSOR_INVALID", "{bad}: {envelope}");
        let (tool, args) = next0(&envelope);
        assert_eq!(tool, "func_list");
        assert_eq!(args, json(r#"{"sort":"addr","limit":3}"#));
    }
    let other = Value::object([
        ("sort", Value::from("name")),
        ("limit", Value::from(3)),
        ("cursor", Value::from(cursor.as_str())),
    ]);
    let envelope = call_value(&mut session, "func_list", other);
    assert_eq!(
        code(&envelope),
        "CURSOR_INVALID",
        "another query: {envelope}"
    );
}

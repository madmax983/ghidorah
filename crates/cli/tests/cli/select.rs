//! `ghidorah call --select` (AC-185).

use ghidorah_cli::select;
use ghidorah_json::pointer;

use crate::common::registry::TestHost;
use crate::common::{json, run};

#[test]
fn ac_185_cli_select() {
    let output = run::<TestHost>(
        &["call", "item_list", r#"{"count":3}"#, "--select", "/data/items/*/id"],
        "",
    );
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "fn:0x401000\nfn:0x401010\nfn:0x401020\n");

    let output = run::<TestHost>(
        &["call", "item_list", r#"{"count":2}"#, "--select=/page"],
        "",
    );
    assert_eq!(output.lines().len(), 1, "an object prints on one line");
    assert_eq!(output.lines()[0], r#"{"returned":2,"total":2,"truncated":false}"#);

    let failed = run::<TestHost>(
        &["call", "echo_text", r#"{"text":1}"#, "--select", "/error/code"],
        "",
    );
    assert_eq!(failed.code, 1);
    assert_eq!(failed.stdout, "INVALID_ARGUMENT\n");

    let none = run::<TestHost>(&["call", "item_list", "{}", "--select", "/data/nope"], "");
    assert_eq!(none.code, 0);
    assert_eq!(none.stdout, "", "a missing path prints nothing");
}

#[test]
fn select_value_lines() {
    let envelope = json(r#"{"a":["x","y\nz",3,null,{"k":true}]}"#);
    let ptr = pointer::parse("/a/*").expect("a pointer");
    assert_eq!(
        select::lines(&envelope, &ptr),
        ["x", r#""y\nz""#, "3", "null", r#"{"k":true}"#]
    );
    assert_eq!(select::value_line(&json(r#""plain""#)), "plain");
}

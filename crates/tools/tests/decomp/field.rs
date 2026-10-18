//! AC-236: after `type_edit` sets `struct sockaddr_in *` on a variable, the decompile text
//! shows the field access `->sin_port` (design Section 8.4).
//!
//! `connect_to` of `socket_client.gcc-O2` fills a `struct sockaddr_in` on the stack. Its base
//! variable gets the type `const struct sockaddr *` from the prototype of `connect`, so the
//! text shows `->sa_family` at offset 0. The port at offset 2 has no field in that record.

use std::path::PathBuf;
use std::sync::OnceLock;

use ghidorah_base::FixedClock;
use ghidorah_json::Value;
use ghidorah_tools::{Registry, Roots, Session, SessionConfig, ToolSpec, handlers};

use crate::support::{TOOLS, call, call_value, data, decomp, root, text_at, text_of};

/// The fixture of the test.
const FIXTURE: &str = "fixtures/bin/socket_client.gcc-O2";

/// Gives the registry of the decompile tests with `type_edit` at the end.
fn registry() -> Registry<Session> {
    static CELL: OnceLock<Registry<Session>> = OnceLock::new();
    *CELL.get_or_init(|| {
        let mut tools: Vec<&'static ToolSpec<Session>> = TOOLS.to_vec();
        tools.push(&handlers::type_edit::SPEC);
        Registry::new(Box::leak(tools.into_boxed_slice()))
    })
}

/// Makes a session of [`registry`] with the fixture open and analyzed.
fn session() -> Session {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid");
    let mut s = Session::with_registry(
        registry(),
        SessionConfig::new(roots),
        Box::new(FixedClock::new(0)),
    );
    handlers::analysis_run::install(&mut s);
    let args = Value::object([("path", Value::from(FIXTURE))]);
    data(&call_value(&mut s, "binary_load", args));
    s
}

/// Gives the name of the base variable of the field `field` in `text`: the name before
/// `->field`.
fn base_of(text: &str, field: &str) -> String {
    let at = text
        .find(&format!("->{field}"))
        .unwrap_or_else(|| panic!("the text has ->{field}:\n{text}"));
    let head = text.get(..at).unwrap_or_default();
    let start = head
        .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .map_or(0, |i| i + 1);
    head.get(start..).unwrap_or_default().to_owned()
}

/// Gives the `var:` ID of the variable named `name` in a decompile section.
fn var_id(section: &Value, name: &str) -> String {
    section
        .get("vars")
        .and_then(Value::as_array)
        .and_then(|vars| vars.iter().find(|v| text_at(v, "/name") == name))
        .map_or_else(
            || panic!("no variable {name}: {section}"),
            |v| text_at(v, "/id"),
        )
}

#[test]
fn ac_236_field_access() {
    let mut s = session();
    let before = decomp(&mut s, "connect_to", "{}");
    let text = text_of(&before);
    assert!(!text.contains("->sin_port"), "{text}");
    let base = base_of(&text, "sa_family");
    let id = var_id(&before, &base);
    let args = Value::object([
        ("target", Value::from(id.as_str())),
        ("type", Value::from("struct sockaddr_in *")),
    ]);
    let edited = call_value(&mut s, "type_edit", args);
    assert_eq!(
        text_at(data(&edited), "/applied/new"),
        "struct sockaddr_in *",
        "{edited}"
    );
    let after = decomp(&mut s, "connect_to", "{}");
    let text = text_of(&after);
    assert!(text.contains(&format!("{base}->sin_port")), "{text}");
    assert!(text.contains(&format!("{base}->sin_family")), "{text}");
    let row = after
        .get("vars")
        .and_then(Value::as_array)
        .and_then(|vars| vars.iter().find(|v| text_at(v, "/id") == id).cloned())
        .unwrap_or_else(|| panic!("no variable {id}: {after}"));
    assert_eq!(text_at(&row, "/type"), "struct sockaddr_in *", "{row}");
    let other = call(
        &mut s,
        "func_get",
        r#"{"target":"main","include":["decomp"]}"#,
    );
    assert!(
        !text_at(data(&other), "/decomp/text").contains("sin_port"),
        "the type stays on its variable"
    );
}

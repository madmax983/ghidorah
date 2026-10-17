//! Shared helpers of the tools tests.

use std::path::PathBuf;

use ghidorah_json::{Limits, Value};
use ghidorah_tools::{ContentMode, Envelope, Request, dispatch_with};

use crate::test_registry::{TestHost, registry};

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &Limits::DEFAULT).expect("the test JSON parses")
}

/// Runs one call on `host` through the test registry.
pub fn run_on(host: &mut TestHost, tool: &str, args: &str) -> Envelope {
    dispatch_with(&registry(), host, &Request::new(tool, json(args)))
}

/// Runs one call on `host` in `mode` and gives the envelope JSON.
pub fn run_mode(host: &mut TestHost, tool: &str, args: &str, mode: ContentMode) -> Value {
    let mut request = Request::new(tool, json(args));
    request.content = mode;
    dispatch_with(&registry(), host, &request).to_json()
}

/// Runs one call on a new test host and gives the envelope JSON.
pub fn run(tool: &str, args: &str) -> Value {
    run_on(&mut TestHost::default(), tool, args).to_json()
}

/// Gives the error code of an envelope, or an empty text for a success.
pub fn code(envelope: &Value) -> String {
    envelope
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the compact text of a value.
pub fn text(value: &Value) -> String {
    ghidorah_json::write(value)
}

/// Gives the number of characters of a text.
pub fn chars(text: &str) -> usize {
    text.chars().count()
}

/// Calls `f` for each object key and each string of `value` with its pointer.
pub fn walk(value: &Value, path: &str, f: &mut dyn FnMut(&str, Option<&str>, &Value)) {
    match value {
        Value::Object(object) => {
            for (key, member) in object.iter() {
                let sub = format!("{path}/{key}");
                f(&sub, Some(key), member);
                walk(member, &sub, f);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let sub = format!("{path}/{i}");
                f(&sub, None, item);
                walk(item, &sub, f);
            }
        }
        _ => {}
    }
}

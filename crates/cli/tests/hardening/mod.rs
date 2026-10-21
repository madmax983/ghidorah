//! Shared helpers of the determinism and metamorphic tests (design Sections 10.11 and 13.4):
//! the fixture list, `ghidorah jsonl` runs and JSON walks.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use ghidorah_json::{Limits, Object, Value};

use crate::common::{binary, json, root, wait_for};

/// The longest run of one `ghidorah jsonl` process in seconds.
pub const RUN_SECS: u64 = 60;

/// One fixture of `fixtures/manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    /// The fixture name, for example `hello.gcc-O2`.
    pub name: String,
    /// The path relative to the workspace root.
    pub path: String,
    /// The binary ID: the first 16 hex digits of the SHA-256.
    pub id: String,
}

/// Gives the fixtures of `tier` (`T1`, `T2` or `PE`) in manifest order.
pub fn fixtures(tier: &str) -> Vec<Fixture> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    let manifest = json(&text);
    manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("the fixture list")
        .iter()
        .filter(|f| f.get("tier").and_then(Value::as_str) == Some(tier))
        .map(|f| {
            let field = |k: &str| f.get(k).and_then(Value::as_str).expect("a text").to_owned();
            Fixture {
                name: field("name"),
                path: field("path"),
                id: field("sha256").chars().take(16).collect(),
            }
        })
        .collect()
}

/// Gives one `jsonl` request line `{ id, tool, args }`.
pub fn request(id: &str, tool: &str, args: Value) -> String {
    ghidorah_json::write(&Value::object([
        ("id", Value::from(id)),
        ("tool", Value::from(tool)),
        ("args", args),
    ]))
}

/// Gives JSON arguments from text.
pub fn args(text: &str) -> Value {
    json(text)
}

/// Gives a new empty directory under the cargo temp directory.
pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("hardening")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Runs `command` with `input` on stdin and gives its stdout. The process must exit with 0
/// or 1 (a tool error).
pub fn output_of(mut command: Command, input: &str) -> String {
    let mut child = command.spawn().expect("the binary starts");
    let mut stdin = child.stdin.take().expect("the stdin pipe");
    let text = input.to_owned();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(text.as_bytes());
    });
    let mut stderr = child.stderr.take().expect("the stderr pipe");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("the stdout pipe")
        .read_to_string(&mut out)
        .expect("the stdout text");
    let status = wait_for(&mut child, RUN_SECS);
    writer.join().expect("the stdin writer");
    let err = reader.join().expect("the stderr reader");
    assert!(
        matches!(status.code(), Some(0 | 1)),
        "the run ends with {status}: {err}"
    );
    out
}

/// Gives a `ghidorah jsonl` command with the projects root `projects` and the workspace root.
pub fn jsonl_command(projects: &Path) -> Command {
    let projects = projects.to_string_lossy().into_owned();
    let workspace = root().to_string_lossy().into_owned();
    binary(&[
        "jsonl",
        "--project-root",
        projects.as_str(),
        "--root",
        workspace.as_str(),
    ])
}

/// Runs `ghidorah jsonl` with the projects root `projects` on `lines`. Gives the stdout.
pub fn jsonl(projects: &Path, lines: &[String]) -> String {
    let mut input = lines.join("\n");
    input.push('\n');
    output_of(jsonl_command(projects), &input)
}

/// Gives the parsed result lines of a `jsonl` stdout by their `id`.
pub fn by_id(stdout: &str) -> BTreeMap<String, Value> {
    stdout
        .lines()
        .map(|line| {
            ghidorah_json::parse(line, &Limits::DEFAULT)
                .unwrap_or_else(|e| panic!("a result line parses: {e}: {line}"))
        })
        .map(|v| {
            let id = v
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            (id, v)
        })
        .collect()
}

/// Gives the bytes of each `snapshot.json` under the projects root `projects`, by binary ID.
pub fn snapshots(projects: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(projects) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let file = entry.path().join("snapshot.json");
        if let Ok(bytes) = std::fs::read(&file) {
            out.insert(entry.file_name().to_string_lossy().into_owned(), bytes);
        }
    }
    out
}

/// Gives the numbers of `value` with a fraction or an exponent, as their JSON pointers.
pub fn float_paths(value: &Value, at: &str, out: &mut Vec<String>) {
    match value {
        Value::Number(n) if n.as_str().contains(['.', 'e', 'E']) => {
            out.push(format!("{at} = {}", n.as_str()));
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                float_paths(item, &format!("{at}/{i}"), out);
            }
        }
        Value::Object(members) => {
            for (key, item) in members.iter() {
                float_paths(item, &format!("{at}/{key}"), out);
            }
        }
        _ => {}
    }
}

/// Gives `value` without the members whose key is in `drop`, at any depth.
pub fn without(value: &Value, drop: &[&str]) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| without(v, drop)).collect()),
        Value::Object(members) => {
            let mut out = Object::new();
            for (key, item) in members.iter() {
                if !drop.contains(&key) {
                    out.push(key, without(item, drop));
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Gives `value` with each string changed by `f`, at any depth.
pub fn map_strings(value: &Value, f: &dyn Fn(&str) -> String) -> Value {
    match value {
        Value::String(text) => Value::from(f(text)),
        Value::Array(items) => Value::Array(items.iter().map(|v| map_strings(v, f)).collect()),
        Value::Object(members) => {
            let mut out = Object::new();
            for (key, item) in members.iter() {
                out.push(key, map_strings(item, f));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Tells if `c` is a character of a name token.
pub const fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '$')
}

/// Replaces each whole name token of `text` that `map` holds.
pub fn replace_tokens(text: &str, map: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        out.push_str(
            map.get(token.as_str())
                .map_or(token.as_str(), String::as_str),
        );
        token.clear();
    };
    for c in text.chars() {
        if name_char(c) {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// Gives the first difference of two JSON values as text, or `None`.
pub fn first_difference(a: &Value, b: &Value) -> Option<String> {
    if a == b {
        return None;
    }
    let (x, y) = (ghidorah_json::write(a), ghidorah_json::write(b));
    let at = x
        .chars()
        .zip(y.chars())
        .position(|(p, q)| p != q)
        .unwrap_or_else(|| x.len().min(y.len()));
    let cut = |s: &str| {
        s.chars()
            .skip(at.saturating_sub(100))
            .take(240)
            .collect::<String>()
    };
    Some(format!("\n  {}\n  {}", cut(&x), cut(&y)))
}

//! Unit tests of the path roots (design Section 10.16, ADR-0022).

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ghidorah_base::ErrorCode;
use ghidorah_json::Value;

use super::Roots;
use crate::errors::ToolError;

/// A temporary directory that the test removes at the end.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ghidorah-roots-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes `bytes` to `path` and makes the parent directories.
fn write(path: &Path, bytes: &[u8]) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("the parent dir");
    }
    std::fs::write(path, bytes).expect("the file");
}

/// Gives the workspace root.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives a JSON array of the texts `names`.
fn texts(names: &[&str]) -> Value {
    Value::Array(names.iter().map(|n| Value::from(*n)).collect())
}

/// Gives the detail `key` of `error`, or `None`.
fn detail<'a>(error: &'a ToolError, key: &str) -> Option<&'a Value> {
    error.details.as_ref().and_then(|d| d.get(key))
}

#[test]
#[cfg(unix)]
fn regress_fifo_under_root_refused() {
    let dir = TempDir::new("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(dir.0.join("fifo"))
        .status()
        .expect("mkfifo runs");
    assert!(status.success(), "mkfifo makes the FIFO");
    let roots = Roots::new(&dir.0, &[PathBuf::from(".")]).expect("the temp root");
    let (send, receive) = mpsc::channel();
    // The read runs on its own thread. A blocked open must not stop the test.
    std::thread::spawn(move || {
        let result = roots
            .read("fifo", 1 << 20)
            .map(|file| file.bytes.len())
            .map_err(|e| e.code);
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("the read of a FIFO does not block");
    assert_eq!(result, Err(ErrorCode::FileUnreadable));
    // A regular file under the same root still reads.
    write(&dir.0.join("file.bin"), b"bytes");
    let roots = Roots::new(&dir.0, &[PathBuf::from(".")]).expect("the temp root");
    let file = roots.read("file.bin", 16).expect("a regular file reads");
    assert_eq!(file.bytes, b"bytes");
    assert_eq!(file.file_name, "file.bin");
}

#[test]
fn regress_relative_path_under_second_root() {
    let dir = TempDir::new("two_roots");
    write(&dir.0.join("a/x.bin"), b"in a");
    write(&dir.0.join("b/y.bin"), b"in b");
    write(&dir.0.join("outside.bin"), b"outside");
    let roots = Roots::new(&dir.0, &[PathBuf::from("a"), PathBuf::from("b")]).expect("two roots");
    // A relative path tries each root in order. The first file that exists wins.
    let file = roots
        .read("y.bin", 64)
        .expect("y.bin is under the second root");
    assert_eq!(file.bytes, b"in b");
    assert_eq!(roots.read("x.bin", 64).expect("x.bin").bytes, b"in a");
    // A first part that is a root name selects that root.
    let named = roots
        .read("b/y.bin", 64)
        .expect("the root name b selects b");
    assert_eq!(named.bytes, b"in b");

    // The root name of an absolute root is its last part, and that name selects the root.
    let bin = std::fs::canonicalize(repo_root().join("fixtures/bin")).expect("fixtures/bin");
    let absolute = Roots::new(&repo_root(), std::slice::from_ref(&bin)).expect("the root");
    assert_eq!(absolute.names(), texts(&["bin"]));
    let want = bin.join("hello.gcc-O0");
    assert_eq!(absolute.check("bin/hello.gcc-O0").ok(), Some(want.clone()));
    assert_eq!(absolute.check("hello.gcc-O0").ok(), Some(want.clone()));
    let relative =
        Roots::new(&repo_root(), &[PathBuf::from("fixtures/bin")]).expect("the relative root");
    assert_eq!(relative.names(), texts(&["fixtures/bin"]));
    assert_eq!(relative.check("fixtures/bin/hello.gcc-O0").ok(), Some(want));

    // The errors of a relative path give the roots and the order of the tries.
    let missing = roots.check("nope.bin").expect_err("no root holds nope.bin");
    assert_eq!(missing.code, ErrorCode::FileUnreadable);
    assert_eq!(detail(&missing, "roots"), Some(&texts(&["a", "b"])));
    assert_eq!(detail(&missing, "relative_to"), Some(&texts(&["a", "b"])));
    let missing = roots
        .read("b/nope.bin", 64)
        .expect_err("no root holds b/nope.bin");
    assert_eq!(missing.code, ErrorCode::FileUnreadable);
    assert_eq!(detail(&missing, "relative_to"), Some(&texts(&["b", "a"])));
    let outside = roots
        .check("../outside.bin")
        .expect_err("the path leaves the roots");
    assert_eq!(outside.code, ErrorCode::PathOutsideRoot);
    assert_eq!(detail(&outside, "roots"), Some(&texts(&["a", "b"])));
    assert_eq!(detail(&outside, "relative_to"), Some(&texts(&["a", "b"])));
    // An absolute path gives the roots only.
    let path = dir.0.join("outside.bin").display().to_string();
    let outside = roots.check(&path).expect_err("the path leaves the roots");
    assert_eq!(outside.code, ErrorCode::PathOutsideRoot);
    assert_eq!(detail(&outside, "roots"), Some(&texts(&["a", "b"])));
    assert_eq!(detail(&outside, "relative_to"), None);
}

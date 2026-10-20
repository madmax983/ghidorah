//! Unit tests of the path roots (design Section 10.16, ADR-0022).

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ghidorah_base::ErrorCode;

use super::Roots;

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

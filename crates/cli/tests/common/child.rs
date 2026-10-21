//! A spawned `ghidorah mcp` for the persistence tests: legacy handshake, tool calls, a clean
//! close and a SIGKILL.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ChildStdin;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use ghidorah_json::Value;

use crate::common::{binary, json, root, wait_for};

/// The binary ID of the demo binary and the golden v1 project.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// A running `ghidorah mcp`.
pub struct Server {
    child: std::process::Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next: u64,
}

impl Server {
    /// Starts `ghidorah mcp` with `args` and the workspace root as its one root.
    pub fn spawn(args: &[&str]) -> Self {
        let workspace = root();
        let workspace = workspace.to_string_lossy().into_owned();
        let mut all = vec!["mcp", "--root", workspace.as_str()];
        all.extend_from_slice(args);
        let mut child = binary(&all).spawn().expect("the server starts");
        let stdout = child.stdout.take().expect("the stdout pipe");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        let mut server = Self {
            child,
            stdin,
            lines: rx,
            next: 1,
        };
        server.request(
            "initialize",
            Value::object([
                ("protocolVersion", Value::from("2025-11-25")),
                ("capabilities", Value::object(Vec::<(&str, Value)>::new())),
                (
                    "clientInfo",
                    Value::object([("name", Value::from("test")), ("version", Value::from("1"))]),
                ),
            ]),
        );
        server.send(&Value::object([
            ("jsonrpc", Value::from("2.0")),
            ("method", Value::from("notifications/initialized")),
        ]));
        server
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("the stdin pipe");
        let mut bytes = ghidorah_json::write(message).into_bytes();
        bytes.push(b'\n');
        stdin.write_all(&bytes).expect("the server reads");
        stdin.flush().expect("the server reads");
    }

    /// Sends one request and gives its reply.
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&Value::object([
            ("jsonrpc", Value::from("2.0")),
            ("id", Value::from(id)),
            ("method", Value::from(method)),
            ("params", params),
        ]));
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(20))
                .expect("the server answers");
            let reply = json(&line);
            if reply.get("id").and_then(Value::as_u64) == Some(id) {
                return reply;
            }
        }
    }

    /// Calls a tool and gives the envelope of the result.
    pub fn call(&mut self, tool: &str, args: Value) -> Value {
        let reply = self.request(
            "tools/call",
            Value::object([("name", Value::from(tool)), ("arguments", args)]),
        );
        reply
            .pointer("/result/structuredContent")
            .cloned()
            .unwrap_or_else(|| panic!("a tool result: {reply}"))
    }

    /// Gives the names of the tools of `tools/list`.
    pub fn tools(&mut self) -> Vec<String> {
        let reply = self.request("tools/list", Value::object(Vec::<(&str, Value)>::new()));
        reply
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| t.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Stops the server with SIGKILL: no clean close runs.
    pub fn kill(mut self) {
        self.child.kill().expect("the kill works");
        let _ = self.child.wait();
    }

    /// Closes stdin and waits for exit code 0.
    pub fn close(mut self) {
        drop(self.stdin.take());
        let status = wait_for(&mut self.child, 20);
        assert!(status.success(), "the server exits with 0: {status}");
    }
}

/// Copies the golden v1 project into the projects root `to`.
pub fn copy_golden(to: &Path) -> PathBuf {
    let from = root().join("tests/golden/projects/v1").join(DEMO_ID);
    let dir = to.join(DEMO_ID);
    copy_dir(&from, &dir);
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the directory exists");
    for entry in std::fs::read_dir(from).expect("the golden directory") {
        let entry = entry.expect("an entry");
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            std::fs::copy(&path, &target).expect("the copy");
        }
    }
}

/// Gives the arguments `{"binary_id": <demo>}`.
pub fn demo_args() -> Value {
    Value::object([("binary_id", Value::from(DEMO_ID))])
}

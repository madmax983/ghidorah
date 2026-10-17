//! Golden MCP transcripts (design Section 13.7).
//!
//! A transcript file under `tests/golden/mcp/` has the golden header line and then one line
//! per message:
//!
//! - `{"c":<message>}`: a client line, written as compact JSON.
//! - `{"c_raw":"<text>"}`: a client line that is not JSON.
//! - `{"s":<message>}`: a server line. The server lines of a client line follow it.
//!
//! The test reads the client lines of the file, sends them to the server and renders the
//! transcript again. The rendered text must equal the file byte for byte. With
//! `GHIDORAH_BLESS=1` the test writes the server lines again. The server version in
//! `serverInfo` becomes `<version>`.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use ghidorah_cli::Backend;
use ghidorah_cli::mcp::server::Server;
use ghidorah_json::{Object, Value};
use ghidorah_testkit::golden::{self, Header};

use super::{binary, json, root, wait_for};

/// The ID prefix of the sync probes of a spawned run.
const PROBE_ID: &str = "~sync-";

/// One client line of a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientLine {
    /// A JSON message.
    Msg(Value),
    /// A line that is not JSON.
    Raw(String),
}

impl ClientLine {
    /// Gives the bytes that the client sends, without the line end.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Msg(value) => ghidorah_json::write(value).into_bytes(),
            Self::Raw(text) => text.clone().into_bytes(),
        }
    }

    /// Gives the transcript line of the client line.
    pub fn render(&self) -> String {
        let (key, value) = match self {
            Self::Msg(value) => ("c", value.clone()),
            Self::Raw(text) => ("c_raw", Value::from(text.as_str())),
        };
        ghidorah_json::write(&Value::object([(key, value)]))
    }
}

/// The header of every transcript.
pub fn header() -> Header {
    Header::new("mcp_transcript", "1")
}

/// Gives the path of the transcript `name`.
pub fn path(name: &str) -> PathBuf {
    root().join("tests/golden/mcp").join(format!("{name}.jsonl"))
}

/// Reads the client lines of the transcript `name`.
pub fn clients(name: &str) -> Vec<ClientLine> {
    let (_, body) = golden::read(&path(name)).unwrap_or_else(|e| panic!("{e}"));
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let value = json(line);
            if let Some(message) = value.get("c") {
                Some(ClientLine::Msg(message.clone()))
            } else {
                value
                    .get("c_raw")
                    .and_then(Value::as_str)
                    .map(|text| ClientLine::Raw(text.to_owned()))
            }
        })
        .collect()
}

/// Gives a server line with the server version replaced by `<version>`.
pub fn normalize(line: &str) -> Value {
    let mut value = json(line);
    let info = value
        .as_object_mut()
        .and_then(|o| o.get_mut("result"))
        .and_then(Value::as_object_mut)
        .and_then(|r| r.get_mut("serverInfo"))
        .and_then(Value::as_object_mut);
    if let Some(info) = info
        && info.contains_key("version")
    {
        let _ = info.insert("version", Value::from("<version>"));
    }
    value
}

/// Renders a transcript from its client lines and their server lines.
pub fn render(steps: &[(ClientLine, Vec<String>)]) -> String {
    let mut out = String::new();
    for (client, lines) in steps {
        out.push_str(&client.render());
        out.push('\n');
        for line in lines {
            let mut object = Object::new();
            object.push("s", normalize(line));
            out.push_str(&ghidorah_json::write(&Value::Object(object)));
            out.push('\n');
        }
    }
    out
}

/// Sends each client line to `server` in order, with no threads.
pub fn run_in_process<B: Backend>(
    server: &mut Server<B>,
    clients: &[ClientLine],
) -> Vec<(ClientLine, Vec<String>)> {
    clients
        .iter()
        .map(|client| (client.clone(), server.handle_line(&client.bytes())))
        .collect()
}

/// Checks the transcript `name` against the server lines of `steps`.
pub fn check(name: &str, steps: &[(ClientLine, Vec<String>)]) {
    golden::assert_json(&path(name), &header(), &render(steps));
}

fn reader(child: &mut Child) -> Receiver<String> {
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
    rx
}

/// Sends each client line to a spawned `ghidorah mcp` with `args`.
///
/// After each client line, the run sends a `server/discover` probe with a reserved ID. The
/// lines before the probe reply belong to the client line. The probe replies do not count.
pub fn run_spawned(args: &[&str], clients: &[ClientLine]) -> Vec<(ClientLine, Vec<String>)> {
    let mut command_args = vec!["mcp"];
    command_args.extend_from_slice(args);
    let mut child = binary(&command_args).spawn().expect("the server starts");
    let lines = reader(&mut child);
    let mut stdin = child.stdin.take().expect("the stdin pipe");
    let mut steps = Vec::new();
    for (k, client) in clients.iter().enumerate() {
        let probe_id = format!("{PROBE_ID}{k}");
        let probe = Value::object([
            ("jsonrpc", Value::from("2.0")),
            ("id", Value::from(probe_id.as_str())),
            ("method", Value::from("server/discover")),
        ]);
        let mut bytes = client.bytes();
        bytes.push(b'\n');
        bytes.extend_from_slice(ghidorah_json::write(&probe).as_bytes());
        bytes.push(b'\n');
        stdin.write_all(&bytes).expect("the server reads");
        stdin.flush().expect("the server reads");
        let mut out = Vec::new();
        loop {
            let line = lines
                .recv_timeout(Duration::from_secs(20))
                .expect("the server answers the probe");
            if json(&line).get("id").and_then(Value::as_str) == Some(probe_id.as_str()) {
                break;
            }
            out.push(line);
        }
        steps.push((client.clone(), out));
    }
    drop(stdin);
    let status = wait_for(&mut child, 20);
    assert!(status.success(), "the server exits with 0: {status}");
    steps
}

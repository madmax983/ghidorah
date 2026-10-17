//! The 16 MiB line cap (AC-194) and the line framing.

use std::io::Cursor;

use ghidorah_cli::mcp::frame::{Frame, LineReader, MAX_LINE};
use ghidorah_cli::mcp::rpc;
use ghidorah_cli::mcp::{ServeOptions, serve};
use ghidorah_cli::{Exit, Options};
use ghidorah_json::Value;

use crate::common::registry::TestHost;
use crate::common::{env, json, streams};

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;

/// Gives a ping request with a padding member, so the line has exactly `len` bytes.
fn padded_ping(id: u64, len: usize) -> String {
    let head = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping","params":{{"pad":""#);
    let tail = r#""}}"#;
    let pad = len - head.len() - tail.len();
    format!("{head}{}{tail}", "x".repeat(pad))
}

#[test]
fn ac_194_line_cap() {
    let mut input = String::new();
    for line in [
        INIT.to_owned(),
        padded_ping(2, MAX_LINE + 1),
        padded_ping(3, MAX_LINE),
        r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#.to_owned(),
    ] {
        input.push_str(&line);
        input.push('\n');
    }
    let (streams, out, _err) = streams(input.as_bytes());
    let options = Options::new(&env("line_cap"), "mcp-1");
    let exit = serve::<TestHost>(options, &ServeOptions::default(), streams);
    assert_eq!(exit, Exit::Ok);
    let text = out.text();
    let replies: Vec<Value> = text.lines().map(json).collect();
    assert_eq!(replies.len(), 4, "one reply per line");
    assert_eq!(
        replies[1].pointer("/error/code").and_then(Value::as_i64),
        Some(rpc::INVALID_REQUEST)
    );
    assert_eq!(replies[1].get("id"), Some(&Value::Null));
    assert_eq!(replies[2].get("id"), Some(&json("3")), "a line at the cap is a request");
    assert_eq!(replies[2].get("result"), Some(&json("{}")));
    assert_eq!(replies[3].get("id"), Some(&json("4")), "the server answers the next request");
}

#[test]
fn line_reader_frames_lines() {
    let input = b"a\r\nbb\n\ntoolong\nlast";
    let mut reader = LineReader::new(Cursor::new(&input[..]), 4);
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().expect("the input reads") {
        frames.push(frame);
    }
    assert_eq!(
        frames,
        [
            Frame::Line(b"a".to_vec()),
            Frame::Line(b"bb".to_vec()),
            Frame::Line(Vec::new()),
            Frame::TooLong { bytes: 7 },
            Frame::Line(b"last".to_vec()),
        ]
    );
    let mut long_tail = LineReader::new(Cursor::new(&b"123456"[..]), 4);
    assert_eq!(
        long_tail.next_frame().expect("reads"),
        Some(Frame::TooLong { bytes: 6 })
    );
    assert_eq!(long_tail.next_frame().expect("reads"), None);
}

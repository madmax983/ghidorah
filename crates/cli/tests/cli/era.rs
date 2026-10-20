//! The era rules and the framing of the MCP server (AC-169a to AC-169d).

use ghidorah_base::FixedClock;
use ghidorah_cli::Backend;
use ghidorah_cli::mcp::era::{self, EraState, Method};
use ghidorah_cli::mcp::rpc;
use ghidorah_cli::mcp::server::Server;
use ghidorah_cli::{Options, RunConfig};
use ghidorah_json::Value;
use ghidorah_tools::ContentMode;

use crate::common::registry::TestHost;
use crate::common::transcript::{self, ClientLine};
use crate::common::{FIXED_TIME, env, json};

/// Gives a server over the test registry in mode `both`.
pub fn server() -> Server<TestHost> {
    let mut options = Options::new(&env("era"), "mcp-1");
    options.run = RunConfig {
        fixed_time: Some(FIXED_TIME),
        eval_mode: false,
    };
    let host = TestHost::open(&options).expect("the test host opens");
    Server::new(
        host,
        ContentMode::Both,
        Box::new(FixedClock::new(FIXED_TIME)),
    )
}

/// Runs the transcript `name` on a new server and checks it.
pub fn check(name: &str) -> Vec<(ClientLine, Vec<String>)> {
    let clients = transcript::clients(name);
    let steps = transcript::run_in_process(&mut server(), &clients);
    transcript::check(name, &steps);
    steps
}

/// Gives the parsed server lines of the client line `index`.
pub fn replies(steps: &[(ClientLine, Vec<String>)], index: usize) -> Vec<Value> {
    steps[index].1.iter().map(|line| json(line)).collect()
}

fn code(reply: &Value) -> Option<i64> {
    reply.pointer("/error/code").and_then(Value::as_i64)
}

#[test]
fn ac_169a_legacy_handshakes() {
    for (name, version) in [
        ("legacy_2025_11_25", "2025-11-25"),
        ("legacy_2025_06_18", "2025-06-18"),
        ("legacy_fallback", "2025-11-25"),
    ] {
        let steps = check(name);
        let init = &replies(&steps, 0)[0];
        assert_eq!(
            init.pointer("/result/protocolVersion")
                .and_then(Value::as_str),
            Some(version),
            "{name}"
        );
        assert_eq!(
            init.pointer("/result/capabilities"),
            Some(&json(r#"{"tools":{"listChanged":false}}"#)),
            "{name}: tools only"
        );
        assert!(init.pointer("/result/resultType").is_none(), "{name}");
        assert!(init.pointer("/result/instructions").is_some(), "{name}");
    }
    let steps = check("legacy_2025_11_25");
    assert!(
        steps[1].1.is_empty(),
        "notifications/initialized gets no reply"
    );
    assert_eq!(replies(&steps, 2)[0].get("result"), Some(&json("{}")));
    let list = &replies(&steps, 3)[0];
    let names: Vec<&str> = list
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("a tool list")
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(names, ["item_list", "echo_text", "wait_cancel"]);
    let call = &replies(&steps, 4)[0];
    assert_eq!(
        call.pointer("/result/structuredContent/data/text")
            .and_then(Value::as_str),
        Some("hello")
    );
    assert_eq!(call.pointer("/result/isError"), Some(&Value::Bool(false)));
}

#[test]
fn ac_169b_modern_era() {
    let steps = check("modern");
    let discover = &replies(&steps, 0)[0];
    assert_eq!(
        discover.pointer("/result/supportedVersions"),
        Some(&json(r#"["2026-07-28","2025-11-25","2025-06-18"]"#))
    );
    for index in 0..3 {
        let reply = &replies(&steps, index)[0];
        assert_eq!(
            reply.pointer("/result/resultType").and_then(Value::as_str),
            Some("complete"),
            "step {index}"
        );
    }
    let call = &replies(&steps, 2)[0];
    assert_eq!(
        call.pointer("/result/structuredContent/session")
            .and_then(Value::as_str),
        Some("agent-7")
    );
    assert_eq!(code(&replies(&steps, 3)[0]), Some(rpc::METHOD_NOT_FOUND));
}

#[test]
fn ac_169c_era_errors() {
    let steps = check("era_errors");
    let missing_all = &replies(&steps, 0)[0];
    assert_eq!(code(missing_all), Some(rpc::INVALID_PARAMS));
    assert_eq!(
        missing_all.pointer("/error/data/missing"),
        Some(&json(&format!(
            r#"["{}","{}"]"#,
            era::VERSION_KEY,
            era::CAPABILITIES_KEY
        )))
    );
    let missing_one = &replies(&steps, 1)[0];
    assert_eq!(code(missing_one), Some(rpc::INVALID_PARAMS));
    assert_eq!(
        missing_one.pointer("/error/data/missing"),
        Some(&json(&format!(r#"["{}"]"#, era::CAPABILITIES_KEY)))
    );
    let version = &replies(&steps, 2)[0];
    assert_eq!(code(version), Some(rpc::UNSUPPORTED_VERSION));
    assert_eq!(
        version.pointer("/error/data"),
        Some(&json(
            r#"{"supported":["2026-07-28","2025-11-25","2025-06-18"],"requested":"2025-03-26"}"#
        ))
    );
    assert_eq!(code(&replies(&steps, 3)[0]), Some(rpc::INVALID_PARAMS));
    assert_eq!(
        replies(&steps, 4)[0].get("result"),
        Some(&json("{}")),
        "a ping needs no handshake"
    );
}

#[test]
fn ac_169d_framing() {
    let steps = check("framing");
    for index in [0, 1, 7] {
        assert!(steps[index].1.is_empty(), "line {index} gets no reply");
    }
    let expect = [
        (2, rpc::INVALID_REQUEST, true),
        (3, rpc::PARSE_ERROR, true),
        (4, rpc::INVALID_REQUEST, true),
        (5, rpc::INVALID_REQUEST, false),
        (6, rpc::METHOD_NOT_FOUND, false),
        (8, rpc::INVALID_REQUEST, true),
        (9, rpc::INVALID_PARAMS, false),
        (10, rpc::INVALID_REQUEST, true),
    ];
    for (index, error, null_id) in expect {
        let reply = &replies(&steps, index)[0];
        assert_eq!(code(reply), Some(error), "line {index}");
        assert_eq!(
            reply.get("id") == Some(&Value::Null),
            null_id,
            "line {index}"
        );
    }
    assert_eq!(replies(&steps, 12)[0].get("result"), Some(&json("{}")));
}

#[test]
fn regress_ping_before_initialize() {
    let mut state = EraState::default();
    assert_eq!(
        era::decide(&mut state, "ping", None),
        Ok((era::Era::Legacy, Method::Ping)),
        "a ping needs no handshake"
    );
    assert_eq!(state.legacy(), None, "a ping starts no era");
    let mut s = server();
    let lines = s.handle_line(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        json(&lines[0]).get("result"),
        Some(&json("{}")),
        "{lines:?}"
    );
    // Other methods still need initialize or the modern keys.
    let lines = s.handle_line(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    assert_eq!(code(&json(&lines[0])), Some(rpc::INVALID_PARAMS));
}

#[test]
fn decide_follows_the_rule_order() {
    let modern = json(&format!(
        r#"{{"_meta":{{"{}":"2026-07-28","{}":{{}}}}}}"#,
        era::VERSION_KEY,
        era::CAPABILITIES_KEY
    ));
    let mut state = EraState::default();
    assert_eq!(
        era::decide(&mut state, "tools/list", Some(&modern)),
        Ok((era::Era::Modern, Method::ToolsList))
    );
    assert_eq!(state.legacy(), None);
    let rejected = era::decide(&mut state, "tools/list", None).expect_err("no handshake yet");
    assert_eq!(rejected.code, rpc::INVALID_PARAMS);
    let init = json(r#"{"protocolVersion":"2025-06-18"}"#);
    assert_eq!(
        era::decide(&mut state, "initialize", Some(&init)),
        Ok((era::Era::Legacy, Method::Initialize("2025-06-18")))
    );
    assert_eq!(state.legacy(), Some("2025-06-18"));
    assert_eq!(
        era::decide(&mut state, "ping", None),
        Ok((era::Era::Legacy, Method::Ping))
    );
    assert_eq!(
        era::decide(&mut state, "tools/call", Some(&modern)),
        Ok((era::Era::Modern, Method::ToolsCall))
    );
    let unknown = era::decide(&mut state, "prompts/list", None).expect_err("unknown");
    assert_eq!(unknown.code, rpc::METHOD_NOT_FOUND);
    assert_eq!(era::negotiate(Some("2025-11-25")), "2025-11-25");
    assert_eq!(era::negotiate(Some("1999-01-01")), "2025-11-25");
    assert_eq!(era::negotiate(None), "2025-11-25");
    let finished = era::finish(era::Era::Modern, json("{}"));
    assert_eq!(finished, json(r#"{"resultType":"complete"}"#));
    assert_eq!(era::finish(era::Era::Legacy, json("{}")), json("{}"));
}

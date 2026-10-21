//! One registry on every surface (AC-149a, AC-149b, AC-174, AC-214).
//!
//! These tests run over the test registry and over the shipped registry. AC-149a, AC-149b,
//! AC-174 and AC-214 close in WP-25 over all 23 tools.

use ghidorah_base::FixedClock;
use ghidorah_cli::argv::{self, Command};
use ghidorah_cli::call::{call_on, jsonl_on};
use ghidorah_cli::mcp::era;
use ghidorah_cli::mcp::server::{CHARS_PER_TOKEN, Server};
use ghidorah_cli::{Backend, Options, Shipped};
use ghidorah_json::{Object, Value, write, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_tools::content::result_chars;
use ghidorah_tools::{ContentMode, Profile};

use crate::common::registry::TestHost;
use crate::common::{env, json, root, run, run_binary, streams};

/// The session label of every surface in these tests.
const LABEL: &str = "s";

fn modern_meta() -> Value {
    Value::object([
        (era::VERSION_KEY, Value::from(era::MODERN)),
        (era::CAPABILITIES_KEY, Value::Object(Object::new())),
        (era::SESSION_KEY, Value::from(LABEL)),
    ])
}

/// Gives the reply of one modern `tools/call` on a new example backend in `mode`.
fn mcp_call<B: Backend>(options: &Options, tool: &str, args: &Value, mode: ContentMode) -> Value {
    let backend = B::for_examples(options).expect("the backend opens");
    let mut server = Server::new(backend, mode, Box::new(FixedClock::new(0)));
    let request = Value::object([
        ("jsonrpc", Value::from("2.0")),
        ("id", Value::from(1u64)),
        ("method", Value::from("tools/call")),
        (
            "params",
            Value::object([
                ("name", Value::from(tool)),
                ("arguments", args.clone()),
                ("_meta", modern_meta()),
            ]),
        ),
    ]);
    let lines = server.handle_line(write(&request).as_bytes());
    json(lines.last().expect("a reply"))
}

/// Gives the `tools/list` result of a legacy session with `options`.
fn mcp_tools_list<B: Backend>(options: &Options) -> Value {
    let backend = B::open(options).expect("the backend opens");
    let mut server = Server::new(backend, ContentMode::Both, Box::new(FixedClock::new(0)));
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    let _ = server.handle_line(init.as_bytes());
    let lines = server.handle_line(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    json(lines.last().expect("a reply"))
        .get("result")
        .cloned()
        .expect("a result")
}

/// Gives each example of the registry of `B`: `(tool, golden, args)`.
fn examples<B: Backend>() -> Vec<(&'static str, &'static str, Value)> {
    B::registry()
        .tools()
        .iter()
        .flat_map(|tool| {
            tool.examples
                .iter()
                .map(|e| (tool.name, e.golden, json(e.args)))
        })
        .collect()
}

fn surfaces<B: Backend>(name: &str, goldens: bool) -> usize {
    let env = env(name);
    let options = Options::new(&env, LABEL);
    let mut count = 0;
    for (tool, golden_path, args) in examples::<B>() {
        let line = vec![
            "call".to_owned(),
            tool.to_owned(),
            write(&args),
            "--format".to_owned(),
            "jsonl".to_owned(),
            "--session".to_owned(),
            LABEL.to_owned(),
        ];
        let Ok(Command::Call(call)) = argv::parse(&line) else {
            panic!("the call line parses: {line:?}");
        };
        let mut backend = B::for_examples(&options).expect("the backend opens");
        let (mut cli_streams, out, _) = streams(b"");
        let _ = call_on(&mut backend, &call, &mut cli_streams);
        let cli = json(out.text().trim());

        let mut backend = B::for_examples(&options).expect("the backend opens");
        let request = Value::object([
            ("id", Value::from(1u64)),
            ("tool", Value::from(tool)),
            ("args", args.clone()),
        ]);
        let (mut jsonl_streams, out, _) = streams(write(&request).as_bytes());
        let _ = jsonl_on(&mut backend, Some(LABEL), &mut jsonl_streams);
        let mut line = json(out.text().trim());
        let id = line.as_object_mut().and_then(|o| o.remove("id"));
        assert_eq!(id, Some(json("1")), "{tool}");

        let reply = mcp_call::<B>(&options, tool, &args, ContentMode::Structured);
        let mcp = reply
            .pointer("/result/structuredContent")
            .cloned()
            .expect("structured content");
        assert_eq!(cli, mcp, "{tool} {args}: CLI and MCP");
        assert_eq!(line, mcp, "{tool} {args}: jsonl and MCP");
        if goldens {
            golden::assert_json(
                &root().join(golden_path),
                &Header::new("cli_examples", "1"),
                &write_pretty(&mcp),
            );
        }
        count += 1;
    }
    count
}

#[test]
fn ac_149a_surface_equivalence() {
    assert_eq!(surfaces::<TestHost>("surface_test", true), 4);
    let shipped = surfaces::<Shipped>("surface_shipped", false);
    assert!(shipped >= 12, "{shipped} shipped examples");
}

fn tools_json<B: Backend>(profile: Profile) -> Value {
    let output = run::<B>(&["tools", "--json", "--profile", profile.as_str()], "");
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert_eq!(output.lines().len(), 1);
    json(&output.stdout)
}

#[test]
fn ac_149b_tools_json() {
    for profile in Profile::ALL {
        let mut options = Options::new(&env("tools_json"), LABEL);
        options.profile = profile;
        assert_eq!(
            tools_json::<TestHost>(profile),
            mcp_tools_list::<TestHost>(&options),
            "{profile:?}"
        );
        assert_eq!(
            tools_json::<Shipped>(profile),
            mcp_tools_list::<Shipped>(&options),
            "{profile:?}"
        );
    }
    let cli = run_binary(&["tools", "--json"], "");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    let mcp = run_binary(&["mcp"], &format!("{init}\n{list}\n"));
    let reply = mcp.lines().last().map(|l| json(l)).expect("a reply");
    assert_eq!(Some(&json(&cli.stdout)), reply.get("result"));
    let text = run::<TestHost>(&["tools"], "");
    assert_eq!(text.lines().len(), 3, "{}", text.stdout);
    assert!(
        text.lines()[0].starts_with("item_list  "),
        "{}",
        text.stdout
    );
}

fn check_result(tool: &str, reply: &Value, mode: ContentMode) {
    let result = reply.get("result").expect("a tool result");
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .expect("content");
    let structured = result.get("structuredContent");
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .expect("isError");
    let envelope = if mode == ContentMode::Text {
        assert!(
            structured.is_none(),
            "{tool}: mode text has no structuredContent"
        );
        let text = content[0]
            .get("text")
            .and_then(Value::as_str)
            .expect("a text");
        json(text)
    } else {
        let envelope = structured.cloned().expect("structuredContent");
        assert!(envelope.as_object().is_some(), "{tool}: an object");
        envelope
    };
    let blocks = usize::from(mode != ContentMode::Structured);
    assert_eq!(content.len(), blocks, "{tool} {mode:?}: text blocks");
    if let Some(block) = content.first() {
        assert_eq!(block.get("type"), Some(&json(r#""text""#)));
        assert_eq!(
            block.get("text").and_then(Value::as_str),
            Some(write(&envelope).as_str()),
            "{tool}: the text block is the compact envelope"
        );
    }
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(!is_error)), "{tool}");
    let chars = result_chars(&envelope, is_error, mode);
    let size = Value::object([
        ("chars", Value::from(chars)),
        ("copies", Value::from(mode.copies())),
        ("est_tokens", Value::from(chars.div_ceil(CHARS_PER_TOKEN))),
    ]);
    assert_eq!(
        result.pointer("/_meta/dev.ghidorah~1size"),
        Some(&size),
        "{tool} {mode:?}: the size report"
    );
    assert_eq!(result.get("resultType"), Some(&json(r#""complete""#)));
}

fn list_shapes<B: Backend>(name: &str) {
    for profile in Profile::ALL {
        let mut options = Options::new(&env(name), LABEL);
        options.profile = profile;
        let backend = B::open(&options).expect("the backend opens");
        let expected: Vec<&str> = B::registry()
            .tools()
            .iter()
            .filter(|t| t.profiles.contains(&profile) && backend.in_profile(t.name))
            .map(|t| t.name)
            .collect();
        let list = mcp_tools_list::<B>(&options);
        let names: Vec<&str> = list
            .get("tools")
            .and_then(Value::as_array)
            .expect("tools")
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        assert_eq!(names, expected, "{profile:?}: the fixed order");
    }
    let options = Options::new(&env(name), LABEL);
    for (tool, _, args) in examples::<B>() {
        for mode in [
            ContentMode::Both,
            ContentMode::Structured,
            ContentMode::Text,
        ] {
            check_result(tool, &mcp_call::<B>(&options, tool, &args, mode), mode);
        }
    }
}

/// The 23 tools of the full profile in the fixed `tools/list` order of design Section 10.3.
const CATALOG: [&str; 23] = [
    "binary_load",
    "binary_survey",
    "analysis_run",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "mem_read",
    "addr_info",
    "calc",
    "fact_check",
    "type_get",
    "history_list",
    "session_brief",
    "tool_search",
    "symbol_rename",
    "comment_set",
    "note_write",
    "func_edit",
    "type_edit",
    "history_undo",
    "batch_run",
    "func_similar",
];

/// The `mini` tools of design Section 10.3 in the catalog order.
const MINI: [&str; 10] = [
    "binary_load",
    "binary_survey",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "tool_search",
    "symbol_rename",
    "note_write",
    "batch_run",
];

/// The `readonly` tools of design Section 10.3 in the catalog order: tools 2, 4 to 15, 22
/// (`batch_run`) and 23.
const READONLY: [&str; 15] = [
    "binary_survey",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "mem_read",
    "addr_info",
    "calc",
    "fact_check",
    "type_get",
    "history_list",
    "session_brief",
    "tool_search",
    "batch_run",
    "func_similar",
];

/// Gives the tool names of the shipped `tools/list` of `profile`, in list order.
fn shipped_names(name: &str, profile: Profile) -> Vec<String> {
    let mut options = Options::new(&env(name), LABEL);
    options.profile = profile;
    mcp_tools_list::<Shipped>(&options)
        .get("tools")
        .and_then(Value::as_array)
        .expect("tools")
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

#[test]
fn ac_174_tools_list_shape() {
    // The fixed order of the design, not of the registry.
    for (profile, want) in [
        (Profile::Full, &CATALOG[..]),
        (Profile::Mini, &MINI[..]),
        (Profile::Readonly, &READONLY[..]),
    ] {
        let names = shipped_names("shape_fixed", profile);
        assert_eq!(names, want, "{profile:?}: the fixed order of Section 10.3");
        let mut at = CATALOG.iter();
        assert!(
            want.iter().all(|w| at.any(|c| c == w)),
            "{profile:?}: an ordered subsequence of the catalog"
        );
    }
    list_shapes::<TestHost>("shape_test");
    list_shapes::<Shipped>("shape_shipped");
    let options = Options::new(&env("shape_error"), LABEL);
    let reply = mcp_call::<TestHost>(
        &options,
        "echo_text",
        &json(r#"{"text":3}"#),
        ContentMode::Both,
    );
    check_result("echo_text", &reply, ContentMode::Both);
    assert_eq!(reply.pointer("/result/isError"), Some(&Value::Bool(true)));
}

fn sizes<B: Backend>(name: &str, extra: &[(&'static str, Value)]) {
    let options = Options::new(&env(name), LABEL);
    let mut calls = examples::<B>();
    calls.extend(extra.iter().map(|(tool, args)| (*tool, "", args.clone())));
    for (tool, _, args) in calls {
        for mode in [
            ContentMode::Both,
            ContentMode::Structured,
            ContentMode::Text,
        ] {
            let reply = mcp_call::<B>(&options, tool, &args, mode);
            let result = reply.get("result").expect("a result");
            let chars = write(result).chars().count();
            assert!(
                chars <= 60_000,
                "{tool} {args} {mode:?}: {chars} characters"
            );
            let cap = args
                .get("max_chars")
                .and_then(Value::as_u64)
                .unwrap_or(16_000);
            assert!(
                u64::try_from(chars).expect("a count") <= cap,
                "{tool} {args} {mode:?}: {chars} > {cap}"
            );
        }
    }
}

#[test]
fn ac_214_content_sizes() {
    sizes::<TestHost>(
        "sizes_test",
        &[
            ("item_list", json(r#"{"count":200,"max_chars":60000}"#)),
            ("item_list", json(r#"{"count":200}"#)),
            ("item_list", json(r#"{"count":200,"max_chars":3000}"#)),
        ],
    );
    sizes::<Shipped>("sizes_shipped", &[]);
}

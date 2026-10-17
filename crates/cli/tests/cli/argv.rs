//! The command-line parser (design Section 10.14).

use std::collections::BTreeSet;
use std::path::PathBuf;

use ghidorah_cli::Source;
use ghidorah_cli::argv::{ArgsInput, Command, DoctorArgs, PrintFormat, parse};
use ghidorah_json::pointer;
use ghidorah_tools::{ContentMode, Profile};

fn args(text: &[&str]) -> Vec<String> {
    text.iter().map(|a| (*a).to_owned()).collect()
}

#[test]
fn parse_call_flags() {
    let command = parse(&args(&[
        "call",
        "item_list",
        r#"{"count":2}"#,
        "--select",
        "/data/items/*/id",
        "--format=jsonl",
        "--source",
        "user",
        "--session",
        "s1",
        "--root",
        "a",
        "--root=b",
        "--project-root",
        "p",
    ]))
    .expect("the command line parses");
    let Command::Call(call) = command else {
        panic!("a call command: {command:?}");
    };
    assert_eq!(call.tool, "item_list");
    assert_eq!(call.input, ArgsInput::Inline(r#"{"count":2}"#.to_owned()));
    assert_eq!(
        call.select,
        Some(pointer::parse("/data/items/*/id").expect("a pointer"))
    );
    assert_eq!(call.format, PrintFormat::Jsonl);
    assert_eq!(call.session.source, Source::User);
    assert_eq!(call.session.session.as_deref(), Some("s1"));
    assert_eq!(
        call.session.roots,
        vec![PathBuf::from("a"), PathBuf::from("b")]
    );
    assert_eq!(call.session.project_root, Some(PathBuf::from("p")));
}

#[test]
fn parse_call_inputs() {
    for (text, input) in [
        ("@args.json", ArgsInput::File(PathBuf::from("args.json"))),
        ("-", ArgsInput::Stdin),
        ("{}", ArgsInput::Inline("{}".to_owned())),
    ] {
        let Ok(Command::Call(call)) = parse(&args(&["call", "echo_text", text])) else {
            panic!("{text} parses");
        };
        assert_eq!(call.input, input, "{text}");
        assert_eq!(call.format, PrintFormat::Json);
    }
    let Ok(Command::Call(call)) = parse(&args(&["call", "echo_text"])) else {
        panic!("a call with no arguments parses");
    };
    assert_eq!(call.input, ArgsInput::Empty);
}

#[test]
fn parse_mcp_flags() {
    let command = parse(&args(&[
        "mcp",
        "--profile",
        "mini",
        "--tools",
        "item_list,echo_text",
        "--read-only",
        "--open",
        "x1",
        "--open",
        "x2",
        "--record",
        "calls.jsonl",
        "--content",
        "text",
        "--break-lock",
    ]))
    .expect("the command line parses");
    let Command::Mcp(mcp) = command else {
        panic!("an mcp command: {command:?}");
    };
    assert_eq!(mcp.session.profile, Some(Profile::Mini));
    let tools: BTreeSet<String> = ["item_list", "echo_text"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(mcp.session.tools, Some(tools));
    assert!(mcp.session.read_only);
    assert!(mcp.session.break_lock);
    assert_eq!(mcp.session.open, vec!["x1".to_owned(), "x2".to_owned()]);
    assert_eq!(mcp.record, Some(PathBuf::from("calls.jsonl")));
    assert_eq!(mcp.content, ContentMode::Text);
    let Ok(Command::Mcp(plain)) = parse(&args(&["mcp"])) else {
        panic!("a plain mcp command parses");
    };
    assert_eq!(plain.content, ContentMode::Both);
}

#[test]
fn parse_other_commands() {
    let cases: [(&[&str], Command); 6] = [
        (&["--version"], Command::Version),
        (&["-V"], Command::Version),
        (&["--help"], Command::Help),
        (&["-h"], Command::Help),
        (&["doctor"], Command::Doctor(DoctorArgs::default())),
        (
            &["tools", "--json", "--profile", "readonly"],
            Command::Tools(ghidorah_cli::argv::ToolsArgs {
                json: true,
                profile: Profile::Readonly,
            }),
        ),
    ];
    for (line, expected) in cases {
        assert_eq!(parse(&args(line)), Ok(expected), "{line:?}");
    }
    let Ok(Command::Jsonl(flags)) = parse(&args(&["jsonl", "--session", "j"])) else {
        panic!("a jsonl command parses");
    };
    assert_eq!(flags.session.as_deref(), Some("j"));
}

#[test]
fn usage_errors_name_candidates() {
    let cases: [(&[&str], Option<&str>); 13] = [
        (&[], None),
        (&["mpc"], Some("mcp")),
        (&["mcp", "--profil", "mini"], Some("--profile")),
        (&["call"], None),
        (&["call", "t", "{}", "extra"], None),
        (&["mcp", "--content", "html"], None),
        (&["mcp", "--profile", "huge"], None),
        (&["call", "t", "--format", "xml"], None),
        (&["call", "t", "--select", "data"], None),
        (&["call", "t", "--source", "robot"], None),
        (&["tools", "--json", "--json"], None),
        (&["mcp", "--root"], None),
        (&["doctor", "--selec", "/x"], None),
    ];
    for (line, best) in cases {
        let error = parse(&args(line)).expect_err("the command line is not valid");
        assert_eq!(
            error.candidates.first().map(String::as_str),
            best,
            "{line:?}"
        );
        let text = error.to_string();
        assert!(
            text.ends_with("Run ghidorah --help to see the usage."),
            "{text}"
        );
    }
}

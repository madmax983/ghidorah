//! `tool_search`: levels, ranking, synonyms and topics (AC-152a, AC-152b).

use ghidorah_json::Value;
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::tool_search::{
    KEYWORDS, Level, MAX_TOPIC_CHARS, SYNONYMS, TOPIC_NAMES, TOPICS, item, query_tokens, rank,
    tokens, topic,
};
use ghidorah_tools::{
    ActionSpec, Annotations, ArgKind, ArgSpec, Example, ProfileSet, Role, Session, ToolSpec,
};

use crate::profiles::CATALOG;
use crate::support::{call, call_value, code, data, registry, session, text_at};

/// Queries of the level test.
const QUERIES: [&str; 7] = [
    "disassemble a function",
    "load a file",
    "calculate a hex address",
    "search the tools",
    "",
    "zzzz",
    "the of a",
];

fn search(session: &mut Session, query: &str, level: &str) -> Value {
    call_value(
        session,
        "tool_search",
        Value::object([("query", Value::from(query)), ("level", Value::from(level))]),
    )
}

fn item_names(envelope: &Value) -> Vec<String> {
    data(envelope)
        .get("items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|i| text_at(i, "/name"))
        .collect()
}

/// The largest number of pages that [`all_names`] reads.
const MAX_PAGES: usize = 16;

/// Gives the item names of all pages of `query` at `level`. The output budget can cut the
/// list of the level `full`, and the next cursor then gives the next page.
fn all_names(session: &mut Session, query: &str, level: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut args = vec![("query", Value::from(query)), ("level", Value::from(level))];
        if let Some(next) = &cursor {
            args.push(("cursor", Value::from(next.as_str())));
        }
        let envelope = call_value(session, "tool_search", Value::object(args));
        names.extend(item_names(&envelope));
        cursor = envelope
            .pointer("/page/next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            return names;
        }
    }
    panic!("{query} {level}: more than {MAX_PAGES} pages");
}

fn keys(item: &Value) -> Vec<String> {
    item.as_object()
        .map(|o| o.iter().map(|(k, _)| k.to_owned()).collect())
        .unwrap_or_default()
}

#[test]
fn ac_152a_tool_search_levels() {
    let mut s = session();
    for query in QUERIES {
        let mut ranked: Option<Vec<String>> = None;
        for level in Level::ALL {
            let first = search(&mut s, query, level.name());
            let second = search(&mut s, query, level.name());
            assert_eq!(
                ghidorah_json::write(&first),
                ghidorah_json::write(&second),
                "{query} {}",
                level.name()
            );
            let names = all_names(&mut s, query, level.name());
            match &ranked {
                Some(want) => assert_eq!(&names, want, "{query} {}", level.name()),
                None => ranked = Some(names),
            }
            for got in data(&first)
                .get("items")
                .and_then(Value::as_array)
                .unwrap_or_default()
            {
                let want: &[&str] = match level {
                    Level::Names => &["name", "annotations"],
                    Level::Summaries => &["name", "summary", "annotations"],
                    Level::Full => &["name", "summary", "schema", "examples", "annotations"],
                };
                assert_eq!(keys(got), want, "{query} {}", level.name());
            }
        }
    }
    let all = search(&mut s, "", "names");
    assert_eq!(item_names(&all), registry().names());
    let none = search(&mut s, "zzzz", "names");
    assert!(item_names(&none).is_empty(), "{none}");
}

#[test]
fn ac_152b_topics() {
    let names: Vec<&str> = TOPICS.iter().map(|t| t.name).collect();
    assert_eq!(names, TOPIC_NAMES);
    let mut s = session();
    for name in TOPIC_NAMES {
        let entry = topic(name).expect("every topic has a text");
        assert!(!entry.text.is_empty(), "{name}");
        assert!(entry.text.chars().count() <= MAX_TOPIC_CHARS, "{name}");
        let found = check_agent_text(entry.text);
        assert!(found.is_empty(), "{name}: {found:?}");
        let envelope = call_value(
            &mut s,
            "tool_search",
            Value::object([("topic", Value::from(name))]),
        );
        let items = data(&envelope)
            .get("items")
            .and_then(Value::as_array)
            .unwrap_or_default();
        assert_eq!(items.len(), 1, "{envelope}");
        assert_eq!(text_at(&items[0], "/topic"), name);
        assert_eq!(text_at(&items[0], "/text"), entry.text);
    }
    assert!(topic("nope").is_none());
}

#[test]
fn tool_search_ranking() {
    assert_eq!(
        tokens("Get one func_get, Fn:0x10!"),
        ["get", "one", "func", "get", "fn", "0x10"]
    );
    assert_eq!(query_tokens("The functions of a fn"), ["func"]);
    assert_eq!(query_tokens("disassemble"), ["func_get"]);
    let reg = registry();
    let tools = reg.tools();
    let first = |query: &str| {
        rank(tools, query)
            .first()
            .and_then(|(i, _)| tools.get(*i))
            .map(|t| t.name)
    };
    assert_eq!(first("load a file"), Some("binary_load"));
    assert_eq!(first("calculate a hex address"), Some("calc"));
    assert_eq!(first("discover the tools and topics"), Some("tool_search"));
    // A query word that is the whole name of a tool ranks that tool first.
    assert_eq!(first("search the strings"), Some("search"));
    assert_eq!(first("disassemble a function"), Some("func_get"));
    assert_eq!(first("an overview of the binary"), Some("binary_survey"));
    let ranked = rank(tools, "");
    let order: Vec<usize> = ranked.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        order,
        (0..tools.len()).collect::<Vec<_>>(),
        "ties keep the registry order"
    );
    assert!(rank(tools, "zzzz").is_empty());
    let scores: Vec<u64> = rank(tools, "binary").iter().map(|(_, s)| *s).collect();
    assert!(scores.windows(2).all(|w| w[0] >= w[1]), "{scores:?}");
    for (word, target) in SYNONYMS {
        assert!(!word.is_empty() && !target.is_empty());
        assert_eq!(query_tokens(word), [*target], "{word}");
    }
    for (tool, words) in KEYWORDS {
        assert!(CATALOG.contains(tool), "{tool}");
        assert!(!words.is_empty(), "{tool}");
    }
    assert_eq!(KEYWORDS.len(), CATALOG.len());
}

const PICK: ArgSpec = ArgSpec::new(
    "action",
    Role::Selector,
    ArgKind::Enum(&["one", "two"]),
    "The action.",
);

/// A selector tool for the full level.
const SELECTOR: ToolSpec<Session> = ToolSpec {
    title: "Select",
    summary: "Select an action.",
    description: "Select an action.",
    args: &[PICK],
    actions: &[
        ActionSpec {
            value: "one",
            line: "The first action.",
            example: r#"{"action":"one"}"#,
            destructive: false,
        },
        ActionSpec {
            value: "two",
            line: "The second action.",
            example: r#"{"action":"two"}"#,
            destructive: true,
        },
    ],
    annotations: Annotations::EDIT,
    examples: &[
        Example {
            args: r#"{"action":"one"}"#,
            golden: "tests/golden/tools/select.1.json",
        },
        Example {
            args: r#"{"action":"two"}"#,
            golden: "tests/golden/tools/select.2.json",
        },
        Example {
            args: r#"{"action":"one","x":1}"#,
            golden: "tests/golden/tools/select.3.json",
        },
    ],
    ..ToolSpec::base("select_tool", nothing)
};

fn nothing(
    _s: &mut Session,
    _args: &ghidorah_tools::Args,
    _ctx: &mut ghidorah_tools::Ctx,
) -> Result<ghidorah_tools::Payload, ghidorah_tools::ToolError> {
    Ok(ghidorah_tools::Payload::Object(ghidorah_json::Object::new()))
}

#[test]
fn tool_search_items_and_errors() {
    let profile = ProfileSet::default();
    let full = item(&SELECTOR, Level::Full, &profile);
    let examples = full
        .get("examples")
        .and_then(Value::as_array)
        .unwrap_or_default();
    let actions: Vec<String> = examples.iter().map(|e| text_at(e, "/action")).collect();
    assert_eq!(actions, ["one", "two"], "one example per action");
    assert_eq!(full.pointer("/schema/type"), Some(&Value::from("object")));
    let calc = item(&ghidorah_tools::handlers::calc::SPEC, Level::Full, &profile);
    assert_eq!(
        calc.get("examples")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(1)
    );
    assert_eq!(text_at(&calc, "/examples/0/args/expr"), "main+0x10");

    let mut s = session();
    let envelope = call(&mut s, "tool_search", r#"{"name":"calc"}"#);
    assert_eq!(item_names(&envelope), ["calc"]);
    let envelope = call(&mut s, "tool_search", r#"{"name":"cacl"}"#);
    assert_eq!(code(&envelope), "NOT_FOUND", "{envelope}");
    assert_eq!(text_at(&envelope, "/error/candidates/0/value"), "calc");
    for args in [
        r#"{"name":"calc","query":"load"}"#,
        r#"{"name":"calc","topic":"ids"}"#,
        r#"{"topic":"ids","query":"load"}"#,
    ] {
        let envelope = call(&mut s, "tool_search", args);
        assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{args}: {envelope}");
    }
    let envelope = call(&mut s, "tool_search", r#"{"topic":"nope"}"#);
    assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{envelope}");
    let listed = item_names(&call(&mut s, "tool_search", r#"{"query":"load"}"#)).len();
    assert!(listed >= 1);
    let envelope = call(
        &mut s,
        "tool_search",
        r#"{"query":"load","count_only":true}"#,
    );
    assert_eq!(
        data(&envelope).get("count"),
        Some(&Value::from(listed)),
        "{envelope}"
    );
}

//! Profiles, catalog sizes and the server instructions (AC-130a to AC-131c).

use ghidorah_base::{ErrorCode, FixedClock};
use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::instructions::{self, LINES, MAX_CHARS};
use ghidorah_tools::profiles::{MAX_FULL, MAX_FULL_CHARS, MAX_MINI, MAX_MINI_CHARS, parse_profile};
use ghidorah_tools::spec::{ArgKind, ArgSpec, BinaryArg, Role};
use ghidorah_tools::{
    Args, Ctx, Host, Payload, Profile, ProfileSet, Registry, Session, ToolError, ToolSpec,
};

use crate::support::{call, code, config, demo, json, registry, root, session_with};

/// The 23 tools of the catalog in `tools/list` order (design Section 10.3).
pub const CATALOG: [&str; 23] = [
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

/// The `mini` profile of the design.
const MINI: [&str; 10] = [
    "binary_load",
    "binary_survey",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "symbol_rename",
    "note_write",
    "batch_run",
    "tool_search",
];

/// The `readonly` profile of the design: tools 2, 4 to 15 and 23, and `batch_run`.
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

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

fn sets() -> Vec<ProfileSet> {
    let mut out: Vec<ProfileSet> = Profile::ALL
        .iter()
        .map(|p| ProfileSet::new(*p, None))
        .collect();
    out.push(ProfileSet::new(
        Profile::Full,
        Some(vec!["calc".to_owned()]),
    ));
    out.push(ProfileSet::new(
        Profile::Mini,
        Some(vec!["tool_search".to_owned(), "calc".to_owned()]),
    ));
    out
}

#[test]
fn ac_130a_profile_sizes() {
    let reg = registry();
    let full = ProfileSet::new(Profile::Full, None).tools(&reg);
    assert!(!full.is_empty());
    assert!(full.len() <= MAX_FULL, "{} tools in full", full.len());
    assert_eq!(full.len(), reg.tools().len(), "full holds every tool");
    let mini = ProfileSet::new(Profile::Mini, None).tools(&reg);
    assert!(mini.len() <= MAX_MINI, "{} tools in mini", mini.len());
    for tool in reg.tools() {
        let in_mini = mini.iter().any(|t| t.name == tool.name);
        assert_eq!(in_mini, MINI.contains(&tool.name), "{}", tool.name);
        assert!(
            CATALOG.contains(&tool.name),
            "{} is in the catalog",
            tool.name
        );
    }
}

#[test]
fn ac_130b_readonly_profile() {
    let reg = registry();
    let set = ProfileSet::new(Profile::Readonly, None);
    for tool in reg.tools() {
        let held = set.holds(&reg, tool.name);
        assert_eq!(held, READONLY.contains(&tool.name), "{}", tool.name);
        if held {
            assert!(
                tool.annotations.read_only || tool.name == "batch_run",
                "{}",
                tool.name
            );
        }
    }
    assert!(!set.holds(&reg, "binary_load"));
    let list = set.tools_list(&reg);
    for entry in list.as_array().unwrap_or_default() {
        assert_eq!(
            entry.pointer("/annotations/readOnlyHint"),
            Some(&Value::Bool(true)),
            "{entry}"
        );
        assert_eq!(
            entry.pointer("/annotations/destructiveHint"),
            Some(&Value::Bool(false)),
            "{entry}"
        );
    }
    let full = ProfileSet::new(Profile::Full, None);
    let load = reg.get("binary_load").map(|(_, t)| full.annotations(t));
    assert_eq!(
        load.as_ref().and_then(|a| a.get("readOnlyHint")),
        Some(&Value::Bool(false))
    );
}

#[test]
fn ac_130c_profile_order() {
    let reg = registry();
    let order: Vec<&str> = reg.names();
    assert_eq!(names(&ProfileSet::default().tools_list(&reg)), order);
    for set in sets() {
        let listed = names(&set.tools_list(&reg));
        let positions: Vec<usize> = listed
            .iter()
            .map(|n| {
                order
                    .iter()
                    .position(|o| o == n)
                    .expect("a registered tool")
            })
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{listed:?}");
        let tools: Vec<&str> = set.tools(&reg).iter().map(|t| t.name).collect();
        assert_eq!(listed, tools);
    }
}

/// Gives the size of `tools/list` in characters. The list must hold the active tools.
fn catalog_chars(set: &ProfileSet, reg: &Registry<Session>) -> usize {
    let tools = set.tools_list(reg);
    let active: Vec<&str> = set.tools(reg).iter().map(|t| t.name).collect();
    assert!(!active.is_empty());
    assert_eq!(names(&tools), active);
    let list = Value::object([("tools", tools)]);
    ghidorah_json::write(&list).chars().count()
}

#[test]
fn ac_131a_full_catalog_size() {
    let reg = registry();
    let chars = catalog_chars(&ProfileSet::new(Profile::Full, None), &reg);
    assert!(chars > 0 && chars <= MAX_FULL_CHARS, "{chars} characters");
}

#[test]
fn ac_131b_mini_catalog_size() {
    let reg = registry();
    let chars = catalog_chars(&ProfileSet::new(Profile::Mini, None), &reg);
    assert!(chars > 0 && chars <= MAX_MINI_CHARS, "{chars} characters");
}

#[test]
fn ac_131c_instructions() {
    let reg = registry();
    for set in sets() {
        let text = instructions::generate(&reg, &set);
        assert!(!text.is_empty());
        assert!(
            text.chars().count() <= MAX_CHARS,
            "{} characters",
            text.chars().count()
        );
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some(instructions::first_line().as_str()));
        for line in text.lines() {
            for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                if CATALOG.contains(&token) {
                    assert!(set.holds(&reg, token), "{token} is not active: {line}");
                }
            }
            let found = check_agent_text(line);
            assert!(found.is_empty(), "{line}: {found:?}");
        }
    }
    let first = instructions::first_line();
    assert!(first.contains("ELF"), "{first}");
    assert!(first.ends_with(instructions::OFFLINE), "{first}");
    // A line goes when one of its tools is not active.
    let only_calc = ProfileSet::new(Profile::Full, Some(vec!["calc".to_owned()]));
    let text = instructions::generate(&reg, &only_calc);
    assert!(!text.contains("tool_search"), "{text}");
    let every = text.lines().count();
    let kept = LINES.iter().filter(|l| l.tools.is_empty()).count();
    assert_eq!(every, kept + 1, "{text}");
    let s = session_with(config());
    assert_eq!(
        s.instructions(),
        instructions::generate(&reg, &ProfileSet::default())
    );
}

#[test]
fn tools_list_golden() {
    let reg = registry();
    let list = ProfileSet::new(Profile::Full, None).tools_list(&reg);
    assert_eq!(names(&list), reg.names());
    golden::assert_json(
        &root().join("tests/golden/tools.json"),
        &Header::new("tools_list", "1"),
        &write_pretty(&list),
    );
}

#[test]
fn profile_parse_and_allowlist() {
    assert_eq!(parse_profile("full"), Some(Profile::Full));
    assert_eq!(parse_profile("readonly"), Some(Profile::Readonly));
    assert_eq!(parse_profile("mini"), Some(Profile::Mini));
    assert_eq!(parse_profile("lazy"), None);
    let reg = registry();
    let set = ProfileSet::new(
        Profile::Full,
        Some(vec!["calc".to_owned(), "nope".to_owned()]),
    );
    assert!(set.holds(&reg, "calc"));
    assert!(!set.holds(&reg, "tool_search"));
    assert!(!set.holds(&reg, "nope"));
    assert_eq!(set.unknown(&reg), ["nope"]);
    assert_eq!(
        set.allowlist().map(std::collections::BTreeSet::len),
        Some(2)
    );
    let mut c = config();
    c.profile = set;
    let mut s = session_with(c);
    assert!(s.in_profile("calc"));
    assert!(!s.in_profile("tool_search"));
    let envelope = call(&mut s, "tool_search", "{}");
    assert_eq!(code(&envelope), "TOOL_NOT_IN_PROFILE", "{envelope}");
    let envelope = call(&mut s, "calc", r#"{"expr":"0x1"}"#);
    assert_eq!(code(&envelope), "", "{envelope}");
    assert_eq!(s.active_tools().len(), 1);
}

/// Gives the tool names of `line` that the catalog holds.
fn tools_of(line: &str) -> Vec<&str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| CATALOG.contains(token))
        .collect()
}

/// Every shipped profile gets a workflow line with active tools only. The batch line of
/// `readonly` has no edit sentence, and `mini` keeps the rev and `dry_run` line for its edits.
#[test]
fn regress_every_profile_has_workflow() {
    let reg = registry();
    for profile in Profile::ALL {
        let set = ProfileSet::new(profile, None);
        let text = instructions::generate(&reg, &set);
        let workflow = text.lines().find(|l| l.starts_with("Workflow:"));
        let Some(workflow) = workflow else {
            panic!("{} has no workflow line:\n{text}", profile.as_str());
        };
        for tool in tools_of(workflow) {
            assert!(set.holds(&reg, tool), "{tool}: {workflow}");
        }
        for name in ["binary_survey", "func_get"] {
            assert!(workflow.contains(name), "{workflow}");
        }
        let batch = text.lines().find(|l| l.starts_with("batch_run"));
        let edits = text.lines().find(|l| l.contains("dry_run"));
        match profile {
            Profile::Readonly => {
                let batch = batch.expect("readonly has batch_run");
                assert!(!batch.contains("edits"), "{batch}");
                assert!(edits.is_none(), "{text}");
            }
            Profile::Mini => {
                let edits = edits.expect("mini has edit tools");
                assert!(edits.contains("rev"), "{edits}");
                assert!(!edits.contains("history_undo"), "{edits}");
                assert!(text.contains("binary_load {path}"), "{text}");
            }
            Profile::Full => {
                // In full, each built line gives the text of design Section 10.15.
                let active = |tool: &str| set.holds(&reg, tool);
                for line in LINES {
                    assert_eq!(line.render(&active).as_deref(), Some(line.text));
                }
            }
        }
    }
}

/// Gives the property names of each tool of the `tools/list` of `profile`.
fn published(profile: Profile) -> Vec<(String, Vec<String>)> {
    let list = ProfileSet::new(profile, None).tools_list(&registry());
    list.as_array()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let props = entry
                .pointer("/inputSchema/properties")
                .and_then(Value::as_object)
                .map(|o| o.iter().map(|(k, _)| k.to_owned()).collect())
                .unwrap_or_default();
            (name.to_owned(), props)
        })
        .collect()
}

/// Gives the global keys that `text` tells the agent to send. A key is a word of the text. It
/// holds `_`, or a value comes after it, for example `force true` or `session *`.
fn named_globals(text: &str) -> Vec<&'static str> {
    let words: Vec<&str> = text
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | '.' | ':' | ';'))
        .filter(|w| !w.is_empty())
        .collect();
    let value = |w: Option<&&str>| {
        w.is_some_and(|w| {
            matches!(*w, "true" | "false" | "*") || w.starts_with(|c: char| c.is_ascii_digit())
        })
    };
    ghidorah_tools::args::GLOBALS
        .iter()
        .map(|g| g.name)
        .filter(|name| {
            words
                .iter()
                .enumerate()
                .any(|(i, w)| *w == *name && (name.contains('_') || value(words.get(i + 1))))
        })
        .collect()
}

/// Each argument key that a tool tells the agent to send is a property of its published
/// schema (agent-protocol-09). The keys come from the examples, the text, the `force` repair
/// and the repair calls of a session.
#[test]
fn regress_repairs_fit_published_schema() {
    let reg = registry();
    // (tool, key, source, full only): the mini catalog publishes the summary, not the
    // description.
    let mut wanted: Vec<(String, String, &str, bool)> = Vec::new();
    for tool in reg.tools() {
        let name = tool.name.to_owned();
        for example in tool.examples {
            let args = json(example.args);
            for (key, _) in args
                .as_object()
                .into_iter()
                .flat_map(ghidorah_json::Object::iter)
            {
                wanted.push((name.clone(), key.to_owned(), "example", false));
            }
        }
        for key in named_globals(tool.description) {
            wanted.push((name.clone(), key.to_owned(), "description", true));
        }
        for key in named_globals(tool.summary) {
            wanted.push((name.clone(), key.to_owned(), "summary", false));
        }
        if tool.force {
            wanted.push((name.clone(), "force".to_owned(), "force repair", false));
        }
    }
    let mut s = demo();
    assert_eq!(code(&call(&mut s, "analysis_run", "{}")), "");
    let blocked = call(
        &mut s,
        "symbol_rename",
        r#"{"target":"main","name":"entry"}"#,
    );
    assert_eq!(
        code(&blocked),
        "BLOCKED_BY_HIGHER_PRIORITY_SOURCE",
        "{blocked}"
    );
    let steps = r#"{"steps":[
        {"id":"a","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
        {"id":"b","tool":"search","args":{"kind":"name","query":"read"}}
    ],"max_steps":2}"#;
    let stopped = call(&mut s, "batch_run", steps);
    assert_eq!(code(&stopped), "BUDGET_EXCEEDED", "{stopped}");
    for envelope in [&blocked, &stopped] {
        let repair = envelope.pointer("/next/0").expect("a repair call");
        let tool = repair
            .get("tool")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = repair.get("args").and_then(Value::as_object).expect("args");
        for (key, _) in args.iter() {
            wanted.push((tool.to_owned(), key.to_owned(), "repair call", false));
        }
    }
    let has = |tool: &str, key: &str| wanted.iter().any(|(t, k, ..)| t == tool && k == key);
    assert!(has("history_undo", "session") && has("func_edit", "max_steps"));
    assert!(has("symbol_rename", "force") && has("batch_run", "max_steps"));
    for profile in [Profile::Full, Profile::Mini] {
        let tools = published(profile);
        for (tool, key, why, full_only) in &wanted {
            let Some((_, props)) = tools.iter().find(|(name, _)| name == tool) else {
                continue;
            };
            if *full_only && profile == Profile::Mini {
                continue;
            }
            assert!(
                props.contains(key),
                "{}: {tool} names {key} in its {why}, but its schema has {props:?}",
                profile.as_str()
            );
        }
    }
}

/// Gives the default of the global `name` in the full schema of `tool`.
fn full_default(s: &mut Session, tool: &str, name: &str) -> Option<Value> {
    let args = format!(r#"{{"name":"{tool}","level":"full"}}"#);
    let envelope = call(s, "tool_search", &args);
    assert_eq!(code(&envelope), "", "{envelope}");
    let path = format!("/data/items/0/schema/properties/{name}");
    assert!(envelope.pointer(&path).is_some(), "{envelope}");
    envelope.pointer(&format!("{path}/default")).cloned()
}

/// The full schema gives the defaults of the tool for its global arguments. A tool with no
/// binary has no `in` (maintainability-docs-06, agent-protocol-13).
#[test]
fn regress_full_schema_has_tool_defaults() {
    let reg = registry();
    let mut s = session_with(config());
    let (_, func_list) = reg.get("func_list").expect("func_list");
    let (_, binary_load) = reg.get("binary_load").expect("binary_load");
    let page = func_list
        .list
        .map(|l| l.default_limit)
        .expect("a list tool");
    assert_eq!(page, 100);
    assert_eq!(
        full_default(&mut s, "func_list", "limit"),
        Some(json("100"))
    );
    let chars = func_list.max_chars.to_string();
    assert_eq!(
        full_default(&mut s, "func_list", "max_chars"),
        Some(json(&chars))
    );
    let fuel = binary_load.fuel.map(|f| f.default.to_string());
    assert_eq!(
        full_default(&mut s, "binary_load", "max_steps"),
        fuel.as_deref().map(json)
    );
    let undo = call(&mut s, "tool_search", r#"{"query":"undo","in":"set:foo"}"#);
    assert_eq!(code(&undo), "UNKNOWN_ARGUMENT", "{undo}");
    assert_eq!(
        undo.pointer("/error/field_path").and_then(Value::as_str),
        Some("/in"),
        "{undo}"
    );
}

/// The argument of the test tool: the number of an error code.
const NUM: ArgSpec = ArgSpec::new(
    "num",
    Role::Param,
    ArgKind::Int { min: 0, max: 1000 },
    "The number of the error code.",
);

/// The test tool that fails with the error code `num`, in every profile.
static RAISE: ToolSpec<Session> = ToolSpec {
    title: "Raise an error",
    summary: "Raise an error: a test tool.",
    description: "Raise an error: a test tool.",
    args: &[NUM],
    binary: BinaryArg::None,
    ..ToolSpec::base("test_raise", raise)
};

fn raise(_: &mut Session, args: &Args, _: &mut Ctx) -> Result<Payload, ToolError> {
    let num = args.int("num").and_then(|n| u16::try_from(n).ok());
    let code = num
        .and_then(ErrorCode::from_num)
        .unwrap_or(ErrorCode::InternalError);
    Err(ToolError::new(code))
}

/// Makes a session of `registry` that runs `profile`.
fn in_profile(registry: Registry<Session>, profile: Profile) -> Session {
    let mut c = config();
    c.profile = ProfileSet::new(profile, None);
    Session::with_registry(registry, c, Box::new(FixedClock::new(0)))
}

/// Makes sure that each tool that the hint and the repair calls of `envelope` name is active
/// in `profile`.
fn assert_active_hint(envelope: &Value, profile: Profile) {
    let reg = registry();
    let set = ProfileSet::new(profile, None);
    let hint = envelope
        .pointer("/error/hint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(!hint.is_empty(), "{}: {envelope}", profile.as_str());
    for tool in tools_of(hint) {
        assert!(
            set.holds(&reg, tool),
            "{}: the hint names {tool}: {envelope}",
            profile.as_str()
        );
    }
    for repair in envelope
        .get("next")
        .and_then(Value::as_array)
        .unwrap_or_default()
    {
        let tool = repair
            .get("tool")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(set.holds(&reg, tool), "{}: {envelope}", profile.as_str());
    }
}

/// A hint names only tools of the active profile (r2-surface-04). Each code fails once in
/// each shipped profile. The mini `CONFLICT` and the readonly `UNKNOWN_BINARY` also come from
/// real calls.
#[test]
fn regress_plain_hint_names_active_tools() {
    let mut tools: Vec<&'static ToolSpec<Session>> = registry().tools().to_vec();
    tools.push(&RAISE);
    let with_raise = Registry::new(Box::leak(tools.into_boxed_slice()));
    for profile in Profile::ALL {
        for error in ErrorCode::ALL {
            let mut s = in_profile(with_raise, profile);
            let args = format!(r#"{{"num":{}}}"#, error.info().num);
            let envelope = call(&mut s, "test_raise", &args);
            assert_eq!(code(&envelope), error.info().name, "{envelope}");
            assert_active_hint(&envelope, profile);
        }
    }
    // Mini: a stale expected_rev gives CONFLICT, and mini has no history_list.
    let mut s = in_profile(registry(), Profile::Mini);
    let load = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(code(&load), "", "{load}");
    let rename = r#"{"target":"0x1090","name":"read_input"}"#;
    assert_eq!(code(&call(&mut s, "symbol_rename", rename)), "");
    let stale = r#"{"target":"0x1090","name":"read_line","expected_rev":0}"#;
    let conflict = call(&mut s, "symbol_rename", stale);
    assert_eq!(code(&conflict), "CONFLICT", "{conflict}");
    assert_active_hint(&conflict, Profile::Mini);
    let hint = conflict
        .pointer("/error/hint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(hint.contains("expected_rev"), "{conflict}");
    // Readonly: an unknown binary_id gives UNKNOWN_BINARY, and readonly has no binary_load.
    let mut s = in_profile(registry(), Profile::Readonly);
    let unknown = call(&mut s, "func_list", r#"{"binary_id":"0123456789abcdef"}"#);
    assert_eq!(code(&unknown), "UNKNOWN_BINARY", "{unknown}");
    assert_active_hint(&unknown, Profile::Readonly);
}

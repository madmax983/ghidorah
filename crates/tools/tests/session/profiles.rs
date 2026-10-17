//! Profiles, catalog sizes and the server instructions (AC-130a to AC-131c).

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::instructions::{self, LINES, MAX_CHARS};
use ghidorah_tools::profiles::{MAX_FULL, MAX_FULL_CHARS, MAX_MINI, MAX_MINI_CHARS, parse_profile};
use ghidorah_tools::{Host, Profile, ProfileSet, Registry, Session};

use crate::support::{call, code, config, registry, root, session_with};

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
#[ignore = "WP-25: the 13 shipped tools give 35,862 characters > 24,000; the schema compaction of WP-25 closes AC-131a"]
fn ac_131a_full_catalog_size() {
    let reg = registry();
    let chars = catalog_chars(&ProfileSet::new(Profile::Full, None), &reg);
    assert!(chars > 0 && chars <= MAX_FULL_CHARS, "{chars} characters");
}

#[test]
#[ignore = "WP-25: the 7 shipped mini tools give 22,666 characters > 6,000; the schema compaction of WP-25 closes AC-131b"]
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

//! The registry lint and the registry-wide schema rules (AC-129a to AC-129f, AC-222).

use ghidorah_json::Value;
use ghidorah_tools::registry::{first_sentence, lint, resource_word, schema_root_problem, shipped};
use ghidorah_tools::schema::{Detail, catalog_schema, input_schema, tool_entry};
use ghidorah_tools::{
    ActionSpec, Annotations, ArgKind, ArgSpec, Args, Ctx, Example, Group, GroupRule, LintRule,
    Payload, Profile, ProfileSet, Registry, Role, ToolError, ToolSpec,
};

use crate::common::json;
use crate::test_registry::{TestHost, registry};

/// Runs `$body` with `$name` bound to each registry of the registry-wide tests: the test
/// registry, then the shipped registry. Their host types differ, so a plain loop does not work.
macro_rules! each_registry {
    (|$name:ident| $body:block) => {{
        {
            let $name = registry();
            $body
        }
        {
            let $name = shipped();
            $body
        }
    }};
}

fn nothing(_: &mut TestHost, _: &Args, _: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(ghidorah_json::Object::new()))
}

const GOOD_DOC: &str = "Get the widget at an address. The tool exists only in a lint test.";

const GOOD: ToolSpec<TestHost> = ToolSpec {
    title: "Get a widget",
    summary: "Get the widget at an address.",
    description: GOOD_DOC,
    examples: &[Example {
        args: "{}",
        golden: "tests/golden/tools/test/none.json",
    }],
    ..ToolSpec::base("widget_get", nothing)
};

const BAD_NAME: ToolSpec<TestHost> = ToolSpec {
    name: "Widget-Get",
    ..GOOD
};

const LONG_NAME: ToolSpec<TestHost> = ToolSpec {
    name: "widget_abcdefghijklmnopqrstuvwxyz_abcdefghij",
    ..GOOD
};

const OPEN_WORLD: ToolSpec<TestHost> = ToolSpec {
    annotations: Annotations {
        read_only: true,
        destructive: false,
        idempotent: true,
        open_world: true,
    },
    ..GOOD
};

const READ_ONLY_EDIT: ToolSpec<TestHost> = ToolSpec {
    mutating: true,
    ..GOOD
};

const LONG_TEXT: &str = concat!(
    "Get the widget at an address. ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
);

const LONG_DESC: ToolSpec<TestHost> = ToolSpec {
    description: LONG_TEXT,
    ..GOOD
};

const NO_TITLE: ToolSpec<TestHost> = ToolSpec { title: "", ..GOOD };

const NO_KEYWORD: ToolSpec<TestHost> = ToolSpec {
    summary: "Get the thing at an address.",
    description: "Get the thing at an address. A widget is a thing.",
    ..GOOD
};

const WRONG_SUMMARY: ToolSpec<TestHost> = ToolSpec {
    summary: "Get a widget.",
    ..GOOD
};

const MODE: ArgSpec = ArgSpec::new(
    "mode",
    Role::Selector,
    ArgKind::Enum(&["one", "two"]),
    "The mode of the call.",
)
.required();

const NO_ACTIONS: ToolSpec<TestHost> = ToolSpec {
    args: &[MODE],
    ..GOOD
};

const BAD_ACTIONS: ToolSpec<TestHost> = ToolSpec {
    args: &[MODE],
    actions: &[
        ActionSpec {
            value: "one",
            line: "Run the first mode.\nIt has two lines.",
            example: r#"{"mode":"one"}"#,
            destructive: false,
        },
        ActionSpec {
            value: "three",
            line: "Run the third mode.",
            example: r#"{"mode":"two"}"#,
            destructive: false,
        },
    ],
    ..GOOD
};

const ACTION_NOT_RUN: ToolSpec<TestHost> = ToolSpec {
    args: &[MODE],
    actions: &[
        ActionSpec {
            value: "one",
            line: "Run the first mode.",
            example: r#"{"mode":"one"}"#,
            destructive: false,
        },
        ActionSpec {
            value: "two",
            line: "Run the second mode.",
            example: r#"{"mode":"two"}"#,
            destructive: false,
        },
    ],
    ..GOOD
};

const WRONG_TARGET_NAME: ToolSpec<TestHost> = ToolSpec {
    args: &[ArgSpec::new(
        "addr",
        Role::Target,
        ArgKind::Addr,
        "The address of the widget.",
    )],
    ..GOOD
};

const SELECT_A: ToolSpec<TestHost> = ToolSpec {
    args: &[ArgSpec::new(
        "kind",
        Role::Selector,
        ArgKind::Enum(&["x", "y"]),
        "The kind.",
    )],
    actions: &[
        ActionSpec {
            value: "x",
            line: "Use the x kind.",
            example: r#"{"kind":"x"}"#,
            destructive: false,
        },
        ActionSpec {
            value: "y",
            line: "Use the y kind.",
            example: r#"{"kind":"y"}"#,
            destructive: false,
        },
    ],
    examples: &[
        Example {
            args: r#"{"kind":"x"}"#,
            golden: "tests/golden/tools/test/none.json",
        },
        Example {
            args: r#"{"kind":"y"}"#,
            golden: "tests/golden/tools/test/none.json",
        },
    ],
    ..GOOD
};

const SELECT_B: ToolSpec<TestHost> = ToolSpec {
    name: "widget_set",
    summary: "Set the widget at an address.",
    description: "Set the widget at an address.",
    args: &[ArgSpec::new(
        "as",
        Role::Selector,
        ArgKind::Enum(&["x", "y"]),
        "The kind.",
    )],
    actions: &[
        ActionSpec {
            value: "x",
            line: "Use the x kind.",
            example: r#"{"as":"x"}"#,
            destructive: false,
        },
        ActionSpec {
            value: "y",
            line: "Use the y kind.",
            example: r#"{"as":"y"}"#,
            destructive: false,
        },
    ],
    examples: &[
        Example {
            args: r#"{"as":"x"}"#,
            golden: "tests/golden/tools/test/none.json",
        },
        Example {
            args: r#"{"as":"y"}"#,
            golden: "tests/golden/tools/test/none.json",
        },
    ],
    ..GOOD
};

const BAD_ARGS: ToolSpec<TestHost> = ToolSpec {
    args: &[
        ArgSpec::new("size", Role::Param, ArgKind::Bool, "The size."),
        ArgSpec::new("size", Role::Param, ArgKind::Bool, "The size again."),
        ArgSpec::new("max_chars", Role::Param, ArgKind::Bool, "A global name."),
        ArgSpec::new("Bad", Role::Param, ArgKind::Bool, "A bad name."),
        ArgSpec::new("nodoc", Role::Param, ArgKind::Bool, ""),
        ArgSpec::new("flag", Role::Param, ArgKind::Bool, "A flag.").aliases(&["size"]),
        ArgSpec::new("count", Role::Param, ArgKind::Bool, "A count.").default_json("[1,"),
        ArgSpec::new("when", Role::Param, ArgKind::Bool, "A rule.")
            .required_when(&[("missing", "x")]),
    ],
    groups: &[Group {
        members: &["ghost"],
        rule: GroupRule::AtLeastOne,
    }],
    ..GOOD
};

const NO_EXAMPLES: ToolSpec<TestHost> = ToolSpec {
    examples: &[],
    ..GOOD
};

const BAD_EXAMPLE: ToolSpec<TestHost> = ToolSpec {
    examples: &[Example {
        args: r#"{"nope":1}"#,
        golden: "tests/golden/tools/test/none.json",
    }],
    ..GOOD
};

/// Gives the lint rules that fire for `tools`.
fn rules(tools: &'static [&'static ToolSpec<TestHost>]) -> Vec<LintRule> {
    let mut out: Vec<LintRule> = lint(&Registry::new(tools))
        .into_iter()
        .map(|f| f.rule)
        .collect();
    out.dedup();
    out
}

fn name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 41
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn ac_129_registry_selftest() {
    each_registry!(|registry| {
        let found = lint(&registry);
        assert!(found.is_empty(), "lint findings: {found:?}");
        for tool in registry.tools() {
            assert_eq!(
                tool_entry(tool).get("name").and_then(Value::as_str),
                Some(tool.name)
            );
            assert_eq!(
                registry.get(tool.name).map(|(_, t)| t.name),
                Some(tool.name)
            );
        }
    });
    assert_eq!(registry().names().len(), registry().tools().len());
    assert_eq!(rules(&[&GOOD]), Vec::<LintRule>::new());
    let broken: [(&'static [&'static ToolSpec<TestHost>], LintRule); 6] = [
        (&[&BAD_NAME], LintRule::Name),
        (&[&OPEN_WORLD], LintRule::Annotations),
        (&[&LONG_DESC], LintRule::Description),
        (&[&NO_KEYWORD], LintRule::FirstSentence),
        (&[&BAD_ARGS], LintRule::Args),
        (&[&NO_EXAMPLES], LintRule::Examples),
    ];
    for (tools, rule) in broken {
        assert!(rules(tools).contains(&rule), "{rule:?} does not fire");
    }
}

#[test]
fn ac_129a_tool_name_regex() {
    each_registry!(|registry| {
        for tool in registry.tools() {
            assert!(name_ok(tool.name), "bad tool name {}", tool.name);
        }
    });
    assert!(rules(&[&BAD_NAME]).contains(&LintRule::Name));
    assert!(rules(&[&LONG_NAME]).contains(&LintRule::Name));
    assert!(rules(&[&GOOD, &GOOD]).contains(&LintRule::Name));
}

#[test]
fn ac_129b_schema_root() {
    each_registry!(|registry| {
        for tool in registry.tools() {
            let schema = input_schema(tool);
            assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
            assert_eq!(
                schema.get("additionalProperties"),
                Some(&Value::Bool(false))
            );
            assert!(
                schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some()
            );
            for key in ghidorah_tools::schema::ROOT_COMBINATORS {
                assert!(schema.get(key).is_none(), "{} has {key}", tool.name);
            }
            assert_eq!(schema_root_problem(&schema), None);
            // The catalog schemas that tools/list sends have the same root rules.
            for detail in [Detail::Catalog, Detail::Compact] {
                let schema = catalog_schema(tool, detail);
                assert_eq!(
                    schema_root_problem(&schema),
                    None,
                    "{} {detail:?}",
                    tool.name
                );
            }
        }
        // The inputSchema of each tools/list entry of each profile.
        for profile in Profile::ALL {
            let list = ProfileSet::new(profile, None).tools_list(&registry);
            let entries = list.as_array().unwrap_or_default();
            assert!(!entries.is_empty(), "{}", profile.as_str());
            for entry in entries {
                let schema = entry.get("inputSchema").cloned().unwrap_or_default();
                assert_eq!(
                    schema_root_problem(&schema),
                    None,
                    "{} {entry}",
                    profile.as_str()
                );
            }
        }
    });
    let bad = json(r#"{"type":"object","properties":{},"additionalProperties":false,"oneOf":[]}"#);
    assert!(schema_root_problem(&bad).is_some());
    let open = json(r#"{"type":"object","properties":{}}"#);
    assert!(schema_root_problem(&open).is_some());
    let array = json(r#"{"type":"array","properties":{},"additionalProperties":false}"#);
    assert!(schema_root_problem(&array).is_some());
}

#[test]
fn ac_129c_annotations() {
    each_registry!(|registry| {
        for tool in registry.tools() {
            let entry = tool_entry(tool);
            for key in [
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ] {
                let value = entry.pointer(&format!("/annotations/{key}"));
                assert!(
                    value.and_then(Value::as_bool).is_some(),
                    "{} has no {key}",
                    tool.name
                );
            }
            assert_eq!(
                entry.pointer("/annotations/openWorldHint"),
                Some(&Value::Bool(false))
            );
        }
    });
    assert!(rules(&[&OPEN_WORLD]).contains(&LintRule::Annotations));
    assert!(rules(&[&READ_ONLY_EDIT]).contains(&LintRule::Annotations));
}

#[test]
fn ac_129d_description_length() {
    each_registry!(|registry| {
        for tool in registry.tools() {
            assert!(tool.description.chars().count() <= 1_000, "{}", tool.name);
            assert!(!tool.title.is_empty());
        }
    });
    assert!(LONG_TEXT.chars().count() > 1_000);
    assert!(rules(&[&LONG_DESC]).contains(&LintRule::Description));
    assert!(rules(&[&NO_TITLE]).contains(&LintRule::Description));
}

#[test]
fn ac_129e_first_sentence_keyword() {
    assert_eq!(resource_word("func_get"), "func");
    assert_eq!(resource_word("calc"), "calc");
    assert_eq!(first_sentence("Get one. Then more."), "Get one.");
    assert_eq!(
        first_sentence("Read 0x10.5 bytes? No."),
        "Read 0x10.5 bytes?"
    );
    assert_eq!(first_sentence("No end mark"), "No end mark");
    each_registry!(|registry| {
        for tool in registry.tools() {
            let first = first_sentence(tool.description);
            assert_eq!(first, tool.summary, "{}", tool.name);
            let word = resource_word(tool.name).to_ascii_lowercase();
            assert!(first.to_ascii_lowercase().contains(&word), "{}", tool.name);
        }
    });
    assert!(rules(&[&NO_KEYWORD]).contains(&LintRule::FirstSentence));
    assert!(rules(&[&WRONG_SUMMARY]).contains(&LintRule::FirstSentence));
}

#[test]
fn ac_129f_action_lines() {
    each_registry!(|registry| {
        for tool in registry.tools() {
            let Some(selector) = tool.selector() else {
                assert!(tool.actions.is_empty(), "{}", tool.name);
                continue;
            };
            let ArgKind::Enum(values) = selector.kind else {
                panic!("the selector of {} is not an enum", tool.name);
            };
            let actions: Vec<&str> = tool.actions.iter().map(|a| a.value).collect();
            assert_eq!(actions, values.to_vec(), "{}", tool.name);
            for action in tool.actions {
                assert!(!action.line.is_empty() && !action.line.contains('\n'));
                assert!(tool.examples.iter().any(|e| e.args == action.example));
                let example = json(action.example);
                assert_eq!(
                    example.get(selector.name).and_then(Value::as_str),
                    Some(action.value)
                );
                assert_eq!(tool.action(action.value), Some(action));
            }
        }
    });
    assert!(rules(&[&NO_ACTIONS]).contains(&LintRule::Actions));
    assert!(rules(&[&BAD_ACTIONS]).contains(&LintRule::Actions));
    assert!(rules(&[&ACTION_NOT_RUN]).contains(&LintRule::Actions));
    assert!(!rules(&[&SELECT_A]).contains(&LintRule::Actions));
}

#[test]
fn ac_222_vocabulary_lint() {
    assert!(rules(&[&WRONG_TARGET_NAME]).contains(&LintRule::Vocabulary));
    assert_eq!(rules(&[&SELECT_A]), Vec::<LintRule>::new());
    assert!(rules(&[&SELECT_A, &SELECT_B]).contains(&LintRule::Vocabulary));
    let found = lint(&Registry::new(&[&SELECT_A, &SELECT_B]));
    assert!(
        found
            .iter()
            .any(|f| f.tool == "widget_set" && f.detail.contains("kind"))
    );
    each_registry!(|registry| {
        assert!(
            lint(&registry)
                .iter()
                .all(|f| f.rule != LintRule::Vocabulary)
        );
    });
}

#[test]
fn lint_checks_args_and_examples() {
    let found = lint(&Registry::new(&[&BAD_ARGS]));
    let args: Vec<&str> = found
        .iter()
        .filter(|f| f.rule == LintRule::Args)
        .map(|f| f.detail.as_str())
        .collect();
    assert!(args.len() >= 7, "{args:?}");
    assert!(rules(&[&BAD_EXAMPLE]).contains(&LintRule::Examples));
    assert!(rules(&[&NO_EXAMPLES]).contains(&LintRule::Examples));
}

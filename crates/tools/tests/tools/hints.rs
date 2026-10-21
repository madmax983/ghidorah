//! Executable hints (AC-143).

use std::path::PathBuf;

use ghidorah_base::{ErrorCode, FixedClock, WarningCode};
use ghidorah_json::Value;
use ghidorah_tools::args::parse_strict;
use ghidorah_tools::errors::Inactive;
use ghidorah_tools::hints::{HintError, MAX_NEXT, check, keep_valid};
use ghidorah_tools::{
    AnalysisInfo, AnalysisState, Args, Call, Candidate, Ctx, Host, Payload, Profile, ProfileSet,
    Registry, Request, Roots, Session, SessionConfig, ToolError, ToolSpec, Warning, dispatch_with,
};

use crate::common::{code, json, root, run_on, text};
use crate::test_registry::{ECHO_VALUE, ITEM_GET, ITEM_LIST, TestHost, registry};

fn call(tool: &str, args: &str) -> Call {
    Call::new(tool, json(args), "Read the item.")
}

fn hinter(_: &mut TestHost, _: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    ctx.hint(call("nosuch", "{}"));
    ctx.hint(call("item_get", r#"{"target":true}"#));
    ctx.hint(call("item_get", r#"{"target":"0x401000"}"#));
    ctx.hint(call("item_get", r#"{"id":"0x401000"}"#));
    ctx.hint(call("item_list", "{}"));
    ctx.hint(call("item_get", r#"{"target":"0x401010"}"#));
    ctx.hint(call("item_get", r#"{"target":"0x401020"}"#));
    let mut good = Warning::new(WarningCode::NoreturnSuspect);
    good.at = Some("0x401000".to_owned());
    good.remedy = Some(call("item_get", r#"{"target":"0x401000"}"#));
    ctx.warn(good);
    let mut bad = Warning::new(WarningCode::IndirectCallUnresolved);
    bad.remedy = Some(call("item_get", r#"{"targets":"x"}"#));
    ctx.warn(bad);
    Ok(Payload::Object(ghidorah_json::Object::new()))
}

const HINTER: ToolSpec<TestHost> = ToolSpec {
    title: "Hinter",
    summary: "Hinter gives many hints.",
    description: "Hinter gives many hints.",
    binary: ghidorah_tools::BinaryArg::None,
    ..ToolSpec::base("hinter", hinter)
};

static WITH_HINTER: &[&ToolSpec<TestHost>] = &[&ITEM_LIST, &ITEM_GET, &ECHO_VALUE, &HINTER];

/// Gives the problems of AC-143 in one envelope.
fn problems(registry: &Registry<TestHost>, host: &TestHost, envelope: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut calls: Vec<&Value> = Vec::new();
    let next = envelope
        .get("next")
        .and_then(Value::as_array)
        .unwrap_or_default();
    if next.len() > MAX_NEXT {
        out.push(format!("{} next calls", next.len()));
    }
    calls.extend(next);
    let warnings = envelope
        .get("warnings")
        .and_then(Value::as_array)
        .unwrap_or_default();
    calls.extend(warnings.iter().filter_map(|w| w.get("remedy")));
    for c in calls {
        let tool = c.get("tool").and_then(Value::as_str).unwrap_or_default();
        let Some((_, spec)) = registry.get(tool) else {
            out.push(format!("unknown tool {tool}"));
            continue;
        };
        if !ghidorah_tools::Host::in_profile(host, tool) {
            out.push(format!("{tool} is not in the profile"));
        }
        if let Err(e) = parse_strict(spec, c.get("args").unwrap_or(&Value::Null)) {
            out.push(format!("{tool}: {e}"));
        }
        if c.get("why")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            out.push(format!("{tool} has no why"));
        }
    }
    out
}

#[test]
fn ac_143_executable_hints() {
    let registry = registry();
    let calls = [
        ("item_list", "{}"),
        ("item_get", r#"{"target":"nosuch"}"#),
        ("item_get", r#"{"targt":"0x401010"}"#),
        ("item_list", r#"{"count":30000}"#),
        (
            "item_get",
            r#"{"targets":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51]}"#,
        ),
        (
            "item_edit",
            r#"{"action":"rename","target":"0x401000","name":"x","expected_rev":3}"#,
        ),
        ("fuel_run", r#"{"work":5000}"#),
        ("item_get", r#"{"target":9007199254740993}"#),
        ("item_list", r#"{"cursor":"c:9:0x1"}"#),
    ];
    let mut with_next = 0;
    for (tool, args) in calls {
        let mut host = TestHost::default();
        let envelope = run_on(&mut host, tool, args).to_json();
        let found = problems(&registry, &host, &envelope);
        assert!(found.is_empty(), "{tool} {args}: {found:?}");
        // A CONFLICT keeps its resend as a candidate. Its next[0] is history_list, which the
        // test registry does not hold.
        let candidate = envelope.pointer("/error/candidates/0").is_some();
        if envelope.pointer("/next/0").is_some() || candidate {
            with_next += 1;
        }
    }
    assert_eq!(
        with_next,
        calls.len(),
        "every case has a repair, a hint or a choice"
    );

    let host = TestHost {
        analysis: Some(AnalysisInfo {
            state: AnalysisState::BudgetStopped,
            rev: 6,
        }),
        ..TestHost::default()
    };
    let mut host = host;
    let envelope = run_on(&mut host, "item_list", "{}").to_json();
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(true)));
    assert!(problems(&registry, &host, &envelope).is_empty());

    let mut host = TestHost {
        profile: Some(std::iter::once("item_list").collect()),
        ..TestHost::default()
    };
    let envelope = run_on(&mut host, "item_list", "{}").to_json();
    assert!(envelope.get("next").is_none(), "{envelope}");

    let hinted = Registry::new(WITH_HINTER);
    let mut host = TestHost::default();
    let envelope = dispatch_with(&hinted, &mut host, &Request::new("hinter", json("{}"))).to_json();
    assert!(problems(&hinted, &host, &envelope).is_empty());
    let next: Vec<String> = envelope
        .get("next")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(text)
        .collect();
    assert_eq!(next.len(), 3);
    assert!(next[0].contains("0x401000") && next[1].contains("item_list"));
    let warnings = envelope
        .get("warnings")
        .and_then(Value::as_array)
        .expect("warnings");
    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].get("remedy").is_some());
    assert!(warnings[1].get("remedy").is_none());
}

#[test]
fn hint_check_reasons() {
    let registry = registry();
    let all = |_: &str| true;
    let none = |_: &str| false;
    assert_eq!(
        check(
            &registry,
            &all,
            &call("item_get", r#"{"target":"0x401000"}"#)
        ),
        Ok(())
    );
    assert_eq!(
        check(&registry, &all, &call("nosuch", "{}")),
        Err(HintError::UnknownTool)
    );
    assert_eq!(
        check(
            &registry,
            &none,
            &call("item_get", r#"{"target":"0x401000"}"#)
        ),
        Err(HintError::NotInProfile)
    );
    assert_eq!(
        check(&registry, &all, &call("item_get", r#"{"target":[]}"#)),
        Err(HintError::Args(ErrorCode::InvalidArgument))
    );
    assert_eq!(
        check(&registry, &all, &call("item_get", r#"{"id":"0x401000"}"#)),
        Err(HintError::Args(ErrorCode::UnknownArgument))
    );
    let kept = keep_valid(
        &registry,
        &all,
        vec![
            call("item_list", "{}"),
            call("nosuch", "{}"),
            call("item_list", r#"{"limit":2}"#),
            call("item_list", r#"{"limit":3}"#),
            call("item_list", r#"{"limit":4}"#),
        ],
    );
    assert_eq!(kept.len(), 3);
    assert_eq!(kept[1].args, json(r#"{"limit":2}"#));
    assert!(!HintError::UnknownTool.to_string().is_empty());
    assert!(
        HintError::Args(ErrorCode::InvalidArgument)
            .to_string()
            .contains("INVALID_ARGUMENT")
    );
    assert!(!HintError::NotInProfile.to_string().is_empty());
}

/// Each hint and each plain hint of the catalog keeps a sentence when every registry tool is
/// inactive. So a `--tools` list never gives an empty hint (r3-surface-05).
#[test]
fn regress_hint_has_tool_free_sentence() {
    let shipped = ghidorah_tools::registry::shipped();
    let none = Inactive::of(&shipped, &|_: &str| false);
    let mut empty = Vec::new();
    for code in ErrorCode::ALL {
        let hinted = ToolError::new(code).candidates(vec![Candidate::text("x", "x")]);
        let plain = ToolError::new(code).plain_hint();
        for (what, error, has_next) in [("hint", &hinted, true), ("plain hint", &plain, false)] {
            if error.hint_in(has_next, &none).is_empty() {
                empty.push(format!("{} {what}", code.name()));
            }
        }
    }
    assert!(empty.is_empty(), "these hints are empty: {empty:?}");
}

/// Gives a session of the shipped registry in `profile` with `config`.
fn shipped_in(profile: Profile, mut config: SessionConfig) -> Session {
    config.profile = ProfileSet::new(profile, None);
    Session::with_registry(
        <Session as Host>::registry(),
        config,
        Box::new(FixedClock::new(0)),
    )
}

/// Runs one call on `s` through its active registry and gives the envelope JSON.
fn send(s: &mut Session, tool: &str, args: &str) -> Value {
    let registry = s.active_registry();
    dispatch_with(&registry, s, &Request::new(tool, json(args))).to_json()
}

/// Gives the text at `pointer` of `value`, or an empty text.
fn text_at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The mini profile has no `history_list`, so a `CONFLICT` has no `next`. Its hint then tells
/// the agent to read the current facts first. Only then does it send the call again with
/// `details.current_rev`, in line with the message (r3-surface-09).
#[test]
fn regress_conflict_hint_reads_first() {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid");
    let mut s = shipped_in(Profile::Mini, SessionConfig::new(roots));
    assert_eq!(
        code(&send(&mut s, "binary_load", r#"{"builtin":"demo"}"#)),
        ""
    );
    let first = r#"{"target":"0x1090","name":"read_input"}"#;
    assert_eq!(code(&send(&mut s, "symbol_rename", first)), "");
    let stale = r#"{"target":"0x1090","name":"read_line","expected_rev":0}"#;
    let conflict = send(&mut s, "symbol_rename", stale);
    assert_eq!(code(&conflict), "CONFLICT", "{conflict}");
    assert!(conflict.get("next").is_none(), "{conflict}");
    let message = text_at(&conflict, "/error/message");
    assert!(
        message.contains("Read the later edits before"),
        "{conflict}"
    );
    let hint = text_at(&conflict, "/error/hint");
    let read = hint.find("Read the current facts of the target");
    let resend = hint.find("details.current_rev");
    assert!(
        read.is_some() && resend.is_some() && read < resend,
        "the hint reads first: {hint}"
    );
    assert!(hint.starts_with("Read"), "{hint}");
    assert!(!hint.contains("history_list"), "{hint}");
}

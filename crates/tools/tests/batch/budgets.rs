//! The budgets of a batch: shared `max_chars`, fuel stops, time stops and resume bindings
//! (AC-181a, AC-181b).

use std::cell::Cell;

use ghidorah_base::Clock;
use ghidorah_json::Value;
use ghidorah_tools::{OpenBinary, Session};

use crate::support::{
    analyzed, batch, call, call_value, chars, config, data, demo, demo_id, int_at, registry, steps,
    text_at,
};

#[test]
fn ac_181a_budgets() {
    let mut s = demo();
    let text = r#"{"steps":[
        {"id":"all","tool":"search","args":{"kind":"name","query":"","limit":40}},
        {"id":"part","tool":"search","args":{"kind":"name","query":"","limit":40}}
    ],"return":["part"],"max_chars":2500}"#;
    let envelope = batch(&mut s, text);
    let entries = steps(&envelope);
    assert_eq!(entries.len(), 2, "{envelope}");
    assert!(chars(&envelope) <= 2_500, "{} characters", chars(&envelope));
    // The step outside return is not trimmed: its size is the size of the direct call.
    let direct = call(
        &mut s,
        "search",
        r#"{"kind":"name","query":"","limit":40,"max_chars":60000}"#,
    );
    assert_eq!(int_at(&entries[0], "/chars"), chars(&direct));
    assert!(int_at(&entries[0], "/chars") > 2_500, "{}", entries[0]);
    // The returned step shares the batch budget and keeps its own cursor.
    assert_eq!(
        entries[1].pointer("/page/truncated"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    let cursor = text_at(&entries[1], "/page/next_cursor");
    assert!(!cursor.is_empty(), "{envelope}");
    let shown = entries[1]
        .pointer("/data/items")
        .and_then(Value::as_array)
        .map_or(0, <[Value]>::len);
    let next = call_value(
        &mut s,
        "search",
        Value::object([
            ("kind", Value::from("name")),
            ("query", Value::from("")),
            ("limit", Value::from(40)),
            ("cursor", Value::from(cursor.as_str())),
        ]),
    );
    let rest = next
        .pointer("/data/items")
        .and_then(Value::as_array)
        .map_or(0, <[Value]>::len);
    assert!(shown > 0 && rest > 0, "{next}");
    assert_eq!(
        int_at(&envelope, "/data/budget_used/chars"),
        int_at(&entries[1], "/chars")
    );
}

const RESUMABLE: &str = r#"[
    {"id":"base","tool":"calc","args":{"expr":"0x11e0"}},
    {"id":"names","tool":"search","args":{"kind":"name","query":"pass"}},
    {"id":"look","tool":"func_get","args":{"target":{"$ref":"base","ptr":"/data/value"}}}
]"#;

#[test]
fn ac_181b_resume_bindings() {
    let mut s = demo();
    let envelope = batch(
        &mut s,
        &format!(r#"{{"steps":{RESUMABLE},"return":["look"],"max_steps":3}}"#),
    );
    let got = data(&envelope);
    assert_eq!(text_at(got, "/stopped_by"), "fuel", "{envelope}");
    let entries = steps(&envelope);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].get("ok"), Some(&Value::Bool(true)));
    assert_eq!(text_at(&entries[1], "/error/code"), "BUDGET_EXCEEDED");
    assert_eq!(text_at(got, "/resume/from_step"), "names");
    let bindings = got.pointer("/resume/bindings").cloned().expect("bindings");
    assert_eq!(
        bindings,
        crate::support::json(r#"[{"step":"base","ptr":"/data/value","value":"0x11e0"}]"#)
    );
    // The replay binds the values and runs only the steps that did not complete.
    let replay = Value::object([
        ("steps", crate::support::json(RESUMABLE)),
        ("return", crate::support::json(r#"["look"]"#)),
        ("resume", got.get("resume").cloned().unwrap_or_default()),
    ]);
    let envelope = call_value(&mut s, "batch_run", replay);
    let entries = steps(&envelope);
    assert_eq!(
        entries[0].get("resumed"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    assert_eq!(int_at(&entries[0], "/fuel"), 0);
    assert_eq!(int_at(&envelope, "/data/budget_used/steps"), 2);
    assert!(data(&envelope).get("stopped_by").is_none());
    assert_eq!(
        text_at(&entries[2], "/data/name"),
        "check_password",
        "{envelope}"
    );
    // A binding that the replay does not have gives BAD_REFERENCE.
    let replay = Value::object([
        ("steps", crate::support::json(RESUMABLE)),
        (
            "resume",
            crate::support::json(r#"{"from_step":"names","bindings":[]}"#),
        ),
    ]);
    let envelope = call_value(&mut s, "batch_run", replay);
    assert_eq!(
        text_at(&envelope, "/data/steps/2/error/code"),
        "BAD_REFERENCE",
        "{envelope}"
    );
}

/// A clock whose monotonic time moves 1,000 ms at each read.
#[derive(Debug, Default)]
struct StepClock {
    now: Cell<u64>,
}

impl Clock for StepClock {
    fn unix_ms(&self) -> u64 {
        0
    }

    fn monotonic_ms(&self) -> u64 {
        let now = self.now.get();
        self.now.set(now + 1_000);
        now
    }
}

/// Makes a session with the stepping clock and the analyzed demo binary.
fn slow_demo(eval_mode: bool) -> Session {
    let mut config = config();
    config.run.eval_mode = eval_mode;
    let mut session = Session::with_registry(registry(), config, Box::<StepClock>::default());
    ghidorah_tools::handlers::analysis_run::install(&mut session);
    let found = analyzed();
    let label = session.new_label();
    session.open(OpenBinary {
        id: demo_id(),
        program: found.program.clone(),
        file_name: found.file_name.clone(),
        read_only: false,
        label,
        analysis: found.analysis,
    });
    session
}

#[test]
fn time_stop_gives_warning_and_resume() {
    let text = r#"{"steps":[
        {"id":"a","tool":"calc","args":{"expr":"0x1"}},
        {"id":"b","tool":"calc","args":{"expr":"0x2"}},
        {"id":"c","tool":"calc","args":{"expr":"0x3"}},
        {"id":"d","tool":"calc","args":{"expr":"0x4"}}
    ],"max_ms":1500}"#;
    let mut s = slow_demo(false);
    let envelope = batch(&mut s, text);
    let got = data(&envelope);
    assert_eq!(text_at(got, "/stopped_by"), "time", "{envelope}");
    assert_eq!(got.get("deterministic"), Some(&Value::Bool(false)));
    let warned = envelope
        .get("warnings")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .any(|w| text_at(w, "/code") == "W_TIME_STOP");
    assert!(warned, "{envelope}");
    assert!(got.get("resume").is_some(), "{envelope}");
    // The eval mode turns the time guard off.
    let mut s = slow_demo(true);
    let envelope = batch(&mut s, text);
    assert!(data(&envelope).get("stopped_by").is_none(), "{envelope}");
}

#[test]
fn mutating_batch_out_of_fuel_rolls_back() {
    let mut s = demo();
    let rev0 = crate::support::rev(&s);
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"a","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
            {"id":"b","tool":"search","args":{"kind":"name","query":"read"}}
        ],"max_steps":2}"#,
    );
    assert_eq!(
        text_at(&envelope, "/error/code"),
        "BUDGET_EXCEEDED",
        "{envelope}"
    );
    assert_eq!(crate::support::rev(&s), rev0);
}

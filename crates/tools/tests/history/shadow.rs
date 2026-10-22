//! The analysis state of a reopened project: a changed analysis inputs hash starts a shadow
//! re-analysis (design Sections 3.9 and 3.10).

use std::sync::{Arc, Mutex};

use ghidorah_base::Fuel;
use ghidorah_db::codec::tables_from_json;
use ghidorah_db::{Edit, SessionLabel, Source};
use ghidorah_json::Value;
use ghidorah_tools::session::{AnalysisEngine, OpenBinary, RunReport, Until};
use ghidorah_tools::{AnalysisState, ToolError};

use crate::support::{DEMO_ID, call, config_in, data, json, load_demo, session_with, tmp};

/// The analysis layer of the test engine: one code unit at the entry of `main`.
const SET: &str = r#"{"comments":[],"data":[],"funcs":[],"jumptables":[],"overrides":[],"refs":[],
"strings":[],"symbols":[],"units":[{"at":"0x1080","len":4,"flow":"seq","flags":0}],"vars":[],
"why":[{"key":{"k":"code_unit","at":"0x1080"},"order":0,"rule":"R_TEST_UNIT","premises":[]}],
"why_next":1}"#;

/// A test engine: it puts [`SET`] in place of the analysis layer and logs each call.
struct TestEngine {
    tag: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl TestEngine {
    fn publish(binary: &mut OpenBinary) -> Result<(), ToolError> {
        let set = tables_from_json(&json(SET)).expect("the test set decodes");
        let label = SessionLabel::new(SessionLabel::ANALYSIS).expect("a label");
        let mut tx = binary
            .program
            .begin("analysis_run", Source::Analysis, label)
            .expect("a transaction");
        tx.apply(Edit::ReplaceAnalysis(Arc::new(set)))
            .expect("the set applies");
        tx.commit().expect("the commit works");
        Ok(())
    }
}

impl AnalysisEngine for TestEngine {
    fn run(
        &mut self,
        binary: &mut OpenBinary,
        until: Until,
        _fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        self.calls
            .lock()
            .expect("the log")
            .push(format!("run {until:?}"));
        Self::publish(binary)?;
        Ok(RunReport {
            state: AnalysisState::Complete,
            steps_used: 10,
            capped: false,
        })
    }

    fn inputs_tag(&self) -> Value {
        Value::from(self.tag)
    }

    fn reanalyze(
        &mut self,
        _binary: &mut OpenBinary,
        band: u16,
        _fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        self.calls
            .lock()
            .expect("the log")
            .push(format!("reanalyze {band}"));
        Ok(RunReport {
            state: AnalysisState::Complete,
            steps_used: 5,
            capped: false,
        })
    }
}

fn engine(tag: &'static str) -> (Box<TestEngine>, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let engine = Box::new(TestEngine {
        tag,
        calls: Arc::clone(&calls),
    });
    (engine, calls)
}

fn reopen(dir: &std::path::Path, tag: &'static str) -> (Value, Vec<String>) {
    let mut s = session_with(config_in(dir));
    let (e, calls) = engine(tag);
    s.set_engine(e);
    let args = format!(r#"{{"binary_id":"{DEMO_ID}","analysis":"full"}}"#);
    let envelope = call(&mut s, "binary_load", &args);
    data(&envelope);
    let log = calls.lock().expect("the log").clone();
    (envelope, log)
}

#[test]
fn inputs_hash_mismatch_starts_shadow() {
    let dir = tmp("shadow");
    {
        let mut s = session_with(config_in(&dir));
        let (e, calls) = engine("analyzers-v1");
        s.set_engine(e);
        load_demo(&mut s);
        assert_eq!(*calls.lock().expect("the log"), vec!["run Full".to_owned()]);
    }
    // The same analyzers: the analysis of the project is current, so no run starts.
    let (same, log) = reopen(&dir, "analyzers-v1");
    assert!(log.is_empty(), "{log:?}");
    assert_eq!(
        same.pointer("/analysis/state").and_then(Value::as_str),
        Some("complete"),
        "{same}"
    );
    assert_eq!(same.get("rev").and_then(Value::as_u64), Some(1));
    // Other analyzers: the inputs hash differs, so the state is stale and a shadow starts.
    let (changed, log) = reopen(&dir, "analyzers-v2");
    assert_eq!(log, vec!["reanalyze 100".to_owned()], "{changed}");
}

#[test]
fn analysis_runs_write_markers() {
    let dir = tmp("markers");
    let mut s = session_with(config_in(&dir));
    let (e, _) = engine("analyzers-v1");
    s.set_engine(e);
    let id = load_demo(&mut s);
    let rows = call(
        &mut s,
        "history_list",
        r#"{"since_rev":0,"kinds":["analysis"]}"#,
    );
    let items = crate::support::items(&rows);
    assert_eq!(items.len(), 1, "{rows}");
    let first = items.first().expect("a marker row");
    assert_eq!(
        first.pointer("/fields/state").and_then(Value::as_str),
        Some("complete")
    );
    assert_eq!(
        first.pointer("/fields/fuel_used").and_then(Value::as_u64),
        Some(10)
    );
    let history = s.history(id).expect("the history");
    assert_eq!(history.lines().len(), 1);
}

//! `analysis_run`: fuel slices, resume, the analyzer table, the change counts and dry runs.
//! The shipped engine also gives the analysis inputs tag of a project and the shadow
//! re-analysis of a reopen with changed inputs.

use std::path::{Path, PathBuf};

use ghidorah_base::{Address, BinaryId, Fuel, Range};
use ghidorah_db::{Edit, FuncRecord, Function, Source, StartReason};
use ghidorah_json::Value;
use ghidorah_tools::handlers::analysis_run::{self, Engine, SLICE_STEPS};
use ghidorah_tools::session::{AnalysisEngine, FULL_BAND, ProjectsConfig};
use ghidorah_tools::{AnalysisState, Session, ToolError};

use crate::support::{
    DEMO_ID, DEMO_MAIN, call, config, data, fixture, session, session_with, text_at,
};

fn int(v: &Value, pointer: &str) -> u64 {
    v.pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX)
}

#[test]
fn analysis_run_completes_and_reports() {
    let (mut s, id) = fixture("noreturn_wrappers.gcc-O2");
    let envelope = call(&mut s, "analysis_run", "{}");
    let got = data(&envelope);
    assert_eq!(text_at(got, "/state"), "complete");
    assert_eq!(got.get("resume"), Some(&Value::Bool(false)));
    assert!(int(got, "/steps_used") > 0);
    assert!(int(got, "/changed/functions") > 10);
    assert!(int(got, "/changed/refs") > 10);
    assert!(
        int(got, "/changed/strings") > 0,
        "Strings (650) finds strings"
    );
    let rows = got
        .get("analyzers")
        .and_then(Value::as_array)
        .expect("rows");
    let names: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(
        names,
        [
            "Entry",
            "Symbols",
            "ImportStubs",
            "FdeSeeds",
            "PdataSeeds",
            "Overrides",
            "Disasm",
            "NoReturnKnown",
            "NoReturnDiscovered",
            "CallTargets",
            "IatThunks",
            "JumpTables",
            "TailCallsAndParts",
            "MainDiscovery",
            "EndbrSeeds",
            "DataPtrSeeds",
            "AddrTakenSeeds",
            "GapComponents",
            "References",
            "Strings",
            "StackFrames",
            "CallingConvention",
            "Syscalls"
        ]
    );
    assert!(rows.iter().all(|r| int(r, "/pending") == 0));
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(false)));
    assert_eq!(text_at(&envelope, "/binary_id"), id);
    assert_eq!(int(&envelope, "/rev"), 1, "one publish commit");

    let again = call(&mut s, "analysis_run", "{}");
    let got = data(&again);
    assert_eq!(int(got, "/steps_used"), 0);
    assert_eq!(int(got, "/changed/functions"), 0);
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)));
    assert_eq!(int(&again, "/rev"), 1);
}

#[test]
fn analysis_run_resumes_after_a_budget_stop() {
    let (mut s, _) = fixture("large.gcc-O2");
    let first = call(&mut s, "analysis_run", r#"{"max_steps":10}"#);
    let got = data(&first);
    assert_eq!(text_at(got, "/state"), "budget_stopped");
    assert_eq!(got.get("resume"), Some(&Value::Bool(true)));
    assert!(int(got, "/steps_used") >= 10);
    assert!(int(got, "/steps_used") < SLICE_STEPS * 4);
    assert_eq!(first.get("partial"), Some(&Value::Bool(true)));
    assert_eq!(text_at(&first, "/next/0/tool"), "analysis_run");
    let pending: u64 = got
        .get("analyzers")
        .and_then(Value::as_array)
        .expect("rows")
        .iter()
        .map(|r| int(r, "/pending"))
        .sum();
    assert!(pending > 0);

    let dry = call(&mut s, "analysis_run", r#"{"dry_run":true}"#);
    assert_eq!(int(data(&dry), "/steps_used"), 0);
    assert_eq!(text_at(data(&dry), "/state"), "budget_stopped");
    assert_eq!(dry.get("noop"), Some(&Value::Bool(true)));

    let rest = call(&mut s, "analysis_run", "{}");
    assert_eq!(text_at(data(&rest), "/state"), "complete");
    assert_eq!(rest.get("partial"), Some(&Value::Bool(false)));
}

#[test]
fn analysis_run_triage_and_an_installed_engine() {
    let (mut s, _) = fixture("hello.gcc-O2");
    analysis_run::install(&mut s);
    let got = call(&mut s, "analysis_run", r#"{"until":"triage"}"#);
    assert_eq!(
        text_at(data(&got), "/state"),
        "budget_stopped",
        "bands 800 and 810 wait for a full run"
    );
    let load = call(
        &mut s,
        "binary_load",
        r#"{"path":"fixtures/bin/two_helpers.gcc-O2"}"#,
    );
    assert_eq!(
        text_at(data(&load), "/analysis/state"),
        "complete",
        "binary_load runs the installed engine"
    );
}

#[test]
fn regress_triage_done_resume_false() {
    let (mut s, id) = fixture("hello.gcc-O2");
    for round in 0..2 {
        let envelope = call(&mut s, "analysis_run", r#"{"until":"triage"}"#);
        let got = data(&envelope);
        assert_eq!(text_at(got, "/state"), "budget_stopped", "{envelope}");
        assert_eq!(
            got.get("resume"),
            Some(&Value::Bool(false)),
            "the triage bands are done, so the same call has no more work: {envelope}"
        );
        if round == 1 {
            assert_eq!(int(got, "/steps_used"), 0, "{envelope}");
        }
        assert_eq!(text_at(&envelope, "/next/0/tool"), "analysis_run");
        assert_eq!(
            text_at(&envelope, "/next/0/args/until"),
            "full",
            "{envelope}"
        );
        assert_eq!(text_at(&envelope, "/next/0/args/binary_id"), id);
        assert_eq!(
            text_at(&envelope, "/next/0/why"),
            analysis_run::WHY_TRIAGE_DONE
        );
    }
    // A fuel stop inside the triage bands keeps resume, and the hint keeps the bound.
    let (mut s, _) = fixture("large.gcc-O2");
    let stopped = call(
        &mut s,
        "analysis_run",
        r#"{"until":"triage","max_steps":10}"#,
    );
    assert_eq!(data(&stopped).get("resume"), Some(&Value::Bool(true)));
    assert_eq!(
        text_at(&stopped, "/next/0/args/until"),
        "triage",
        "{stopped}"
    );
    assert_eq!(text_at(&stopped, "/next/0/why"), analysis_run::WHY_RESUME);
}

#[test]
fn analysis_run_texts_are_ste() {
    let spec = &analysis_run::SPEC;
    let mut texts = vec![spec.summary, spec.description];
    texts.extend(analysis_run::TEXTS);
    texts.extend(spec.args.iter().map(|a| a.doc));
    for text in texts {
        let found = ghidorah_testkit::ste::check_agent_text(text);
        assert!(found.is_empty(), "{text}: {found:?}");
    }
}

#[test]
fn engine_tag_and_rows_of_a_session() {
    let tag = Engine::default().inputs_tag();
    let versions = tag
        .get("analyzers")
        .and_then(Value::as_array)
        .expect("the tag lists the analyzers");
    assert_eq!(versions.len(), ghidorah_analysis::ANALYZERS.len());
    assert_eq!(
        versions
            .first()
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(2),
        "each analyzer has a name and a version"
    );

    let mut s = session();
    assert!(!s.has_engine());
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    assert!(s.analyzer_rows(id).is_empty(), "no engine gives no rows");
    analysis_run::install(&mut s);
    assert!(s.has_engine());
    assert!(s.analyzer_rows(id).is_empty(), "no run gives no rows");
}

#[test]
fn engine_reanalyze_runs_a_shadow() {
    let (mut s, id) = fixture("two_helpers.gcc-O2");
    analysis_run::install(&mut s);
    let id = BinaryId::parse(&id).expect("the ID parses");
    let done = call(&mut s, "analysis_run", "{}");
    assert_eq!(text_at(data(&done), "/state"), "complete");
    let rev = s.binary(id).expect("open").program.rev();
    let funcs = s.binary(id).expect("open").program.analysis().clone();

    // One work unit stops the shadow run: reads keep the committed set.
    let mut fuel = Fuel::new(1);
    let report = s
        .reanalyze(id, FULL_BAND, &mut fuel)
        .expect("the run starts")
        .expect("the session has an engine");
    assert_eq!(report.state, AnalysisState::Stale);
    let binary = s.binary(id).expect("open");
    assert_eq!(
        binary.program.rev(),
        rev,
        "a stopped shadow publishes nothing"
    );
    assert_eq!(binary.program.analysis(), &funcs);
    assert_eq!(binary.analysis.map(|a| a.state), Some(AnalysisState::Stale));

    // The next call resumes the shadow. The same inputs give the same set.
    let rest = call(&mut s, "analysis_run", "{}");
    assert_eq!(text_at(data(&rest), "/state"), "complete");
    let binary = s.binary(id).expect("open");
    assert_eq!(binary.program.analysis(), &funcs, "the shadow set is equal");
    assert_eq!(
        binary.analysis.map(|a| a.state),
        Some(AnalysisState::Complete)
    );
}

/// Gives a new empty projects root for one test.
fn projects(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("session_projects")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Makes a session with the projects root `dir` and the shipped engine.
fn engine_session(dir: &Path) -> Session {
    let mut cfg = config();
    cfg.projects = Some(ProjectsConfig {
        root: dir.to_path_buf(),
        named: true,
        break_lock: false,
    });
    let mut s = session_with(cfg);
    analysis_run::install(&mut s);
    s
}

/// Commits one agent function at `main` through the journal: a base fact of the inputs hash.
fn journal_function(s: &mut Session, id: BinaryId) {
    let (commit, ()) = s
        .transact(id, "func_edit", "cli", |tx| {
            let mut func = Function::new(
                Address::ram(DEMO_MAIN),
                StartReason::Agent,
                100,
                Source::Agent,
            );
            func.body
                .insert(Range::new(DEMO_MAIN, DEMO_MAIN + 0x52).expect("a range"));
            let record = FuncRecord {
                func,
                vars: Vec::new(),
                plate: None,
            };
            tx.apply(Edit::CreateFunction(Box::new(record)))
                .map(drop)
                .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the function commits");
    assert!(commit.rev.0 > 1);
}

#[test]
fn reopen_with_changed_inputs_runs_the_engine() {
    let dir = projects("reopen_engine");
    let reopen = format!(r#"{{"binary_id":"{DEMO_ID}"}}"#);
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    {
        let mut s = engine_session(&dir);
        let load = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
        assert_eq!(text_at(data(&load), "/analysis/state"), "complete");
    }
    {
        // The inputs are the same: the analysis of the project is current.
        let mut s = engine_session(&dir);
        let again = call(&mut s, "binary_load", &reopen);
        assert_eq!(text_at(data(&again), "/analysis/state"), "complete");
        assert_eq!(
            data(&again).pointer("/analysis/steps_used"),
            Some(&Value::from(0u64))
        );
        journal_function(&mut s, id);
    }
    // A base function changes the inputs hash: the reopen runs the shadow re-analysis.
    let mut s = engine_session(&dir);
    let stale = call(&mut s, "binary_load", &reopen);
    assert_eq!(
        text_at(data(&stale), "/analysis/state"),
        "complete",
        "{stale}"
    );
    let used = data(&stale)
        .pointer("/analysis/steps_used")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    assert!(used > 0, "the reopen runs the engine: {stale}");
    let history = call(&mut s, "history_list", r#"{"kinds":["analysis"]}"#);
    assert!(
        data(&history)
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty()),
        "{history}"
    );
}

#[test]
fn regress_reopen_keeps_the_committed_analysis() {
    let dir = projects("regress_reopen_run");
    let reopen = format!(r#"{{"binary_id":"{DEMO_ID}"}}"#);
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    {
        let mut s = engine_session(&dir);
        let load = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
        assert_eq!(text_at(data(&load), "/analysis/state"), "complete");
    }
    {
        // A current analysis needs no new run: analysis_run reports it complete.
        let mut s = engine_session(&dir);
        let again = call(&mut s, "binary_load", &reopen);
        let rev = int(&again, "/rev");
        let funcs = s.binary(id).expect("open").program.analysis().clone();
        let run = call(&mut s, "analysis_run", r#"{"max_steps":50}"#);
        assert_eq!(text_at(data(&run), "/state"), "complete", "{run}");
        assert_eq!(int(data(&run), "/steps_used"), 0, "{run}");
        assert_eq!(run.get("partial"), Some(&Value::Bool(false)), "{run}");
        assert_eq!(run.get("noop"), Some(&Value::Bool(true)), "{run}");
        assert_eq!(int(&run, "/rev"), rev);
        assert_eq!(s.binary(id).expect("open").program.analysis(), &funcs);
        journal_function(&mut s, id);
    }
    // A stale analysis resumes as a shadow: reads keep the committed set until it completes.
    let mut s = engine_session(&dir);
    let stale = call(
        &mut s,
        "binary_load",
        &format!(r#"{{"binary_id":"{DEMO_ID}","analysis":"none"}}"#),
    );
    assert_eq!(text_at(data(&stale), "/analysis/state"), "stale", "{stale}");
    let rev = int(&stale, "/rev");
    let funcs = s.binary(id).expect("open").program.analysis().clone();
    let run = call(&mut s, "analysis_run", r#"{"max_steps":50}"#);
    assert_eq!(text_at(data(&run), "/state"), "stale", "{run}");
    assert_eq!(
        int(&run, "/rev"),
        rev,
        "a stopped shadow publishes nothing: {run}"
    );
    assert_eq!(s.binary(id).expect("open").program.analysis(), &funcs);
    let rest = call(&mut s, "analysis_run", "{}");
    assert_eq!(text_at(data(&rest), "/state"), "complete", "{rest}");
}

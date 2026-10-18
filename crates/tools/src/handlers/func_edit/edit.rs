//! The commit steps of the edit tools `func_edit` and `type_edit` (design Sections 3.7 and
//! 3.9).
//!
//! | Step | Effect |
//! |---|---|
//! | dry run | the edits run in a transaction that rolls back. `diff` lists the planned edits. |
//! | commit | one transaction and its journal line. A commit with no change gives `noop: true`. |
//! | re-analysis | the shadow run from the start band of the edits within `max_steps` |
//! | warnings | `W_ANALYSIS_STALE`, `W_FACT_ORPHANED` and `W_AGENT_OVERRIDE_CONFLICT` |

use std::collections::BTreeSet;

use ghidorah_analysis::orphans;
use ghidorah_base::{ErrorCode, FuncId, WarningCode};
use ghidorah_db::codec::{edit_to_json, key_to_json};
use ghidorah_db::{Applied, EditError, FactKey, Invalid, Program, Tx};
use ghidorah_json::{Object, Value};

use super::{WHY_CONFLICT, WHY_CREATE, WHY_FORCE, WHY_RESUME};
use crate::args::Args;
use crate::dispatch::Ctx;
use crate::envelope::{AnalysisState, Mutation, Warning};
use crate::errors::ToolError;
use crate::handlers::func_sections as fs;
use crate::hints::Call;
use crate::session::{RunReport, Session, session_label};

/// The result of one edit call.
pub struct Outcome<T> {
    /// The value of the edit step.
    pub value: T,
    /// The rev after the call.
    pub rev: u64,
    /// The report of the re-analysis, or `None` when no re-analysis ran.
    pub report: Option<RunReport>,
}

/// Gives the planned edit list of a dry run: `[{ op, key, old, new }]`.
fn diff(planned: &[Applied]) -> Value {
    let rows = planned
        .iter()
        .map(|a| {
            let key = a
                .edit
                .keys()
                .into_iter()
                .chain(a.inverse.keys())
                .next()
                .map_or(Value::Null, |k| key_to_json(&k));
            Value::object([
                ("op", Value::from(a.edit.kind().name())),
                ("key", key),
                ("old", edit_to_json(&a.inverse)),
                ("new", edit_to_json(&a.edit)),
            ])
        })
        .collect();
    Value::Array(rows)
}

/// Gives the canonical arguments of the call with `force: true`.
fn forced(args: &Args) -> Value {
    let mut object = args.canonical().as_object().cloned().unwrap_or_default();
    let _ = object.remove("force");
    object.push("force", Value::Bool(true));
    Value::Object(object)
}

/// Gives the tool error of an edit error of the call `args`.
#[must_use]
pub fn edit_error(error: &EditError, args: &Args) -> ToolError {
    match error {
        EditError::Blocked(b) => {
            let mut out = ToolError::new(ErrorCode::BlockedByHigherPrioritySource)
                .detail("current", b.value.clone())
                .detail("source", Value::from(b.current.source.name()))
                .detail("key", key_to_json(&b.key));
            if b.force_applies() {
                out = out.next(Call::new(args.tool(), forced(args), WHY_FORCE));
            }
            out
        }
        EditError::NotCode(at) => ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "ref.from")
            .path("/ref/from")
            .detail("addr", fs::addr(*at))
            .detail(
                "expected",
                Value::from("the start of an instruction or of a data definition"),
            ),
        EditError::BadTarget(at) => ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "targets")
            .path("/targets")
            .detail("addr", fs::addr(*at))
            .detail(
                "expected",
                Value::from("an instruction start in an executable region, or an import"),
            ),
        EditError::Invalid(Invalid::NoFunc(id)) => not_found("function", &id.to_string()),
        other => ToolError::new(other.code()),
    }
}

/// Gives `NOT_FOUND` for the entity `text` of `kind`.
#[must_use]
pub fn not_found(kind: &str, text: &str) -> ToolError {
    ToolError::new(ErrorCode::NotFound)
        .var("kind", kind)
        .detail("kind", Value::from(kind))
        .detail("input", Value::from(text))
}

/// Gives the keys of the orphaned agent facts of `program`.
fn orphan_keys(program: &Program) -> BTreeSet<FactKey> {
    orphans::find(program).into_iter().map(|o| o.key).collect()
}

/// Runs `edit` in one transaction on the bound binary and commits it, or rolls it back for a
/// dry run. Then the re-analysis runs from the start band of the edits within the fuel of
/// the call. `focus` names the function whose override conflicts the result reports.
///
/// # Errors
///
/// Returns the error of `edit`, `READ_ONLY_PROJECT`, or the error of the journal or the
/// engine.
pub fn run<T>(
    session: &mut Session,
    args: &Args,
    ctx: &mut Ctx,
    focus: Option<FuncId>,
    edit: impl FnOnce(&mut Tx<'_>) -> Result<T, ToolError>,
) -> Result<Outcome<T>, ToolError> {
    let id = session.bound(&ctx.frame)?.id;
    let force = args.globals().force;
    let label = session_label(&ctx.frame.session)?;
    let source = session.config().source;
    if args.globals().dry_run {
        let binary = session
            .binary_mut(id)
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
        let mut tx = binary
            .program
            .begin(args.tool(), source, label)
            .map_err(|e| ToolError::new(e.code()))?;
        tx.set_force(force);
        let value = edit(&mut tx)?;
        let planned = tx.edits().to_vec();
        tx.abort();
        ctx.mutation = Some(Mutation {
            tx: None,
            noop: true,
            diff: Some(diff(&planned)),
        });
        let rev = binary.program.rev().0;
        return Ok(Outcome {
            value,
            rev,
            report: None,
        });
    }
    let before = orphan_keys(&session.bound(&ctx.frame)?.program);
    let session_text = ctx.frame.session.clone();
    let (commit, value) = session.transact(id, args.tool(), &session_text, |tx| {
        tx.set_force(force);
        edit(tx)
    })?;
    ctx.mutation = Some(Mutation {
        tx: (!commit.noop).then(|| commit.tx.to_string()),
        noop: commit.noop,
        diff: None,
    });
    let report = if commit.noop {
        None
    } else {
        session.after_edit(id, commit.start_band(), &mut ctx.fuel)?
    };
    let binary = session
        .binary(id)
        .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
    ctx.frame.rev = binary.program.rev().0;
    ctx.frame.analysis = binary.analysis;
    if let Some(r) = report {
        warn(
            &binary.program,
            ctx,
            r,
            &before,
            focus,
            &binary.id.to_string(),
        );
    }
    Ok(Outcome {
        value,
        rev: ctx.frame.rev,
        report,
    })
}

/// Adds the warnings of a re-analysis to the call.
fn warn(
    program: &Program,
    ctx: &mut Ctx,
    report: RunReport,
    before: &BTreeSet<FactKey>,
    focus: Option<FuncId>,
    binary_id: &str,
) {
    if report.state != AnalysisState::Complete {
        let mut w = Warning::new(WarningCode::AnalysisStale);
        w.remedy = Some(Call::new(
            "analysis_run",
            Value::object([("binary_id", Value::from(binary_id))]),
            WHY_RESUME,
        ));
        ctx.warnings.push(w);
        return;
    }
    for orphan in orphans::find(program) {
        if before.contains(&orphan.key) {
            continue;
        }
        let mut w = Warning::new(WarningCode::FactOrphaned);
        w.at = Some(orphan.id());
        if orphan.lost_function() {
            w.remedy = Some(Call::new(
                "func_edit",
                Value::object([
                    ("action", Value::from("create")),
                    ("target", fs::addr(orphan.at)),
                ]),
                WHY_CREATE,
            ));
        }
        ctx.warnings.push(w);
    }
    if let Some(func) = focus {
        conflicts(program, ctx, func);
    }
}

/// Adds `W_AGENT_OVERRIDE_CONFLICT` for each conflict caveat of the function `func`.
fn conflicts(program: &Program, ctx: &mut Ctx, func: FuncId) {
    let Some(view) = program.func(func) else {
        return;
    };
    let agent = program
        .base()
        .funcs()
        .get(func)
        .and_then(|f| f.flags.noreturn.as_ref())
        .map(|f| f.value);
    for caveat in view
        .func
        .caveats
        .iter()
        .filter(|c| c.code == WarningCode::AgentOverrideConflict)
    {
        let mut w = Warning::new(WarningCode::AgentOverrideConflict);
        let at = caveat.at.unwrap_or(func.0);
        w.at = Some(at.to_string());
        match agent {
            Some(value) if at == func.0 => {
                w.remedy = Some(Call::new(
                    "func_edit",
                    Value::object([
                        ("action", Value::from("set_noreturn")),
                        ("target", Value::from(func.to_string())),
                        ("noreturn", Value::Bool(!value)),
                    ]),
                    WHY_CONFLICT,
                ));
            }
            _ => {
                let mut details = Object::new();
                if let Some(text) = &caveat.remedy {
                    details.push("analysis", Value::from(text.as_str()));
                }
                w.details = Some(details);
            }
        }
        ctx.warnings.push(w);
    }
}

/// Gives the `analysis` member of a result: the state and the fuel of the re-analysis. A call
/// with no re-analysis gives the state of the binary and 0.
#[must_use]
pub fn analysis(report: Option<RunReport>, ctx: &Ctx) -> Value {
    let state = report
        .map(|r| r.state)
        .or_else(|| ctx.frame.analysis.map(|a| a.state))
        .unwrap_or(AnalysisState::Stale);
    Value::object([
        ("state", Value::from(state.as_str())),
        (
            "steps_used",
            Value::from(report.map_or(0, |r| r.steps_used)),
        ),
    ])
}

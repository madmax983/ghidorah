//! The fuel slices of one analysis call (design Section 2.4, ADR-0016).
//!
//! [`Session::analyze_sliced`] and [`Session::reanalyze_sliced`] run the engine in fuel
//! slices with a progress report, a cancel check and a `max_ms` check per slice. The engine
//! holds the publish of a first analysis during the slices. The call publishes once at its
//! end, and records one run.

use ghidorah_base::{BinaryId, Fuel, Rev, WarningCode};

use super::{RunReport, Session, Until};
use crate::api::Progress;
use crate::dispatch::Ctx;
use crate::envelope::{AnalysisInfo, AnalysisState, Warning};
use crate::errors::ToolError;
use crate::handlers::analysis_run::{SLICE_STEPS, SliceStop, Sliced};

impl Session {
    /// Runs the analysis of the open binary `id` until `until` in the fuel slices of the call
    /// `ctx` (design Section 2.4). Gives `None` when the session has no engine or no such
    /// binary.
    ///
    /// A slice has [`SLICE_STEPS`] work units or a quarter of the units so far, whichever is
    /// more. Each slice with work sends one progress report. After each slice the run can
    /// stop. It stops when the analysis is complete, the slice does no work, the fuel is
    /// empty, the client cancels, or the `max_ms` guard fires. A time stop adds
    /// `W_TIME_STOP`. Eval mode turns the time guard off.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn analyze_sliced(
        &mut self,
        id: BinaryId,
        until: Until,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        self.sliced(id, None, until, ctx)
    }

    /// Runs the re-analysis of the open binary `id` from the start band `band` with the
    /// checkpoints of [`Session::analyze_sliced`]. With no engine, the analysis state becomes
    /// `stale`.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn reanalyze_sliced(
        &mut self,
        id: BinaryId,
        band: u16,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        self.sliced(id, Some(band), Until::Full, ctx)
    }

    /// Starts the re-analysis after an analysis-affecting commit like [`Session::after_edit`],
    /// with the checkpoints of [`Session::analyze_sliced`].
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn after_edit_sliced(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        ctx: &mut Ctx,
    ) -> Result<Option<RunReport>, ToolError> {
        let Some(band) = band else {
            return Ok(None);
        };
        if self.batch_band(id, band) {
            return Ok(None);
        }
        Ok(self.reanalyze_sliced(id, band, ctx)?.map(|s| s.report()))
    }

    /// Tells if the `max_ms` guard of a call fires: the work started at the monotonic time
    /// `began` of the session clock. Eval mode turns the guard off (design Section 10.11).
    #[must_use]
    pub fn past_max_ms(&self, began: u64, max_ms: Option<u64>) -> bool {
        !self.config.run.eval_mode
            && max_ms.is_some_and(|ms| self.clock.monotonic_ms().saturating_sub(began) > ms)
    }

    /// Runs the slices of [`Session::analyze_sliced`] with one publish for the call
    /// (ADR-0016). The engine holds the publish of a first analysis during the slices. At the
    /// end of the call, the session releases the hold and flushes the work. It also does this
    /// after a stop or an error. Then it records one run with the work units of all slices.
    fn sliced(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        until: Until,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        let before = self.binaries.get(&id).map(|b| b.program.rev());
        if let Some(engine) = self.engine.as_mut() {
            engine.hold(id, true);
        }
        let out = self.slices(id, band, until, ctx);
        if let Some(engine) = self.engine.as_mut() {
            engine.hold(id, false);
        }
        let recorded = match before {
            Some(before) => self.flush_run(id, before, out.as_ref().ok().copied().flatten()),
            None => Ok(()),
        };
        let out = out?;
        recorded?;
        Ok(out)
    }

    /// Flushes the held analysis work of the binary `id` and records the run of a call. A
    /// call that failed records its new revisions with no work units.
    fn flush_run(
        &mut self,
        id: BinaryId,
        before: Rev,
        last: Option<Sliced>,
    ) -> Result<(), ToolError> {
        let (Some(engine), Some(binary)) = (self.engine.as_mut(), self.binaries.get_mut(&id))
        else {
            return Ok(());
        };
        engine.flush(binary)?;
        let advanced = binary.program.rev() > before;
        let report = match last {
            Some(run) => run.report(),
            None if advanced => RunReport {
                state: AnalysisState::BudgetStopped,
                steps_used: 0,
                capped: false,
            },
            None => return Ok(()),
        };
        self.finish_run(id, before, report)
    }

    /// Runs one slice of the engine with no record: a re-analysis from `band`, or a run until
    /// `until`. With no engine, a re-analysis makes the analysis state `stale`.
    fn engine_slice(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<Option<RunReport>, ToolError> {
        let (Some(engine), Some(binary)) = (self.engine.as_mut(), self.binaries.get_mut(&id))
        else {
            if let (Some(_), Some(binary)) = (band, self.binaries.get_mut(&id)) {
                binary.analysis = binary.analysis.map(|a| AnalysisInfo {
                    state: AnalysisState::Stale,
                    rev: a.rev,
                });
            }
            return Ok(None);
        };
        let report = match band {
            Some(band) => engine.reanalyze(binary, band, fuel)?,
            None => engine.run(binary, until, fuel)?,
        };
        Ok(Some(report))
    }

    /// Runs the fuel slices of a call and its checkpoints, with no record.
    fn slices(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        until: Until,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        let began = self.clock.monotonic_ms();
        let mut out: Option<Sliced> = None;
        loop {
            let used = out.map_or(0, |s| s.steps_used);
            let mut fuel = Fuel::new(SLICE_STEPS.max(used / 4).min(ctx.fuel.remaining()));
            let first = if out.is_none() { band } else { None };
            let report = self.engine_slice(id, first, until, &mut fuel)?;
            let Some(report) = report else {
                return Ok(out);
            };
            let _ = ctx.fuel.take(report.steps_used.min(ctx.fuel.remaining()));
            let total = used.saturating_add(report.steps_used);
            let was_capped = out.is_some_and(|s| s.capped);
            if report.capped && !was_capped {
                ctx.warn(Warning::new(WarningCode::AnalysisLimit));
            }
            let mut run = Sliced {
                state: report.state,
                steps_used: total,
                stop: None,
                idle: report.steps_used == 0,
                capped: report.capped || was_capped,
            };
            if !run.idle {
                ctx.progress(Progress {
                    progress: total,
                    total: None,
                    message: format!("The analysis used {total} work units."),
                });
            }
            let done = run.state == AnalysisState::Complete || run.idle;
            if !done && ctx.cancelled() {
                run.stop = Some(SliceStop::Cancel);
            } else if !done && self.past_max_ms(began, ctx.max_ms) {
                run.stop = Some(SliceStop::Time);
                ctx.warn(Warning::new(WarningCode::TimeStop));
            }
            out = Some(run);
            if done || run.stop.is_some() || ctx.fuel.remaining() == 0 {
                return Ok(out);
            }
        }
    }
}

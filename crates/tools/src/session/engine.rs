//! The analysis engine API of a session: how far a run goes, the report of a run and the
//! engine trait. The analysis WP installs an engine with [`super::Session::set_engine`].

use ghidorah_base::{BinaryId, Fuel};
use ghidorah_json::Value;

use super::OpenBinary;
use crate::envelope::AnalysisState;
use crate::errors::ToolError;

/// How far an analysis runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Until {
    /// The fast discovery bands.
    Triage,
    /// Every band.
    Full,
}

/// The report of one analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunReport {
    /// The state after the run.
    pub state: AnalysisState,
    /// The fuel that the run used.
    pub steps_used: u64,
    /// `true` when the analysis stopped at the cap of the code units.
    pub capped: bool,
}

/// The analysis engine of a session. The analysis WP installs it with [`super::Session::set_engine`].
pub trait AnalysisEngine: Send {
    /// Runs the analysis of `binary` until `until` within `fuel`.
    ///
    /// # Errors
    ///
    /// Returns a tool error when the analysis cannot start.
    fn run(
        &mut self,
        binary: &mut OpenBinary,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError>;

    /// Gives the analyzer rows of the open binary `id` in registry order: the name, the
    /// priority band, the pending ranges and the runs. An engine with no table gives none.
    fn analyzers(&self, id: BinaryId) -> Vec<ghidorah_analysis::AnalyzerRow> {
        let _ = id;
        Vec::new()
    }

    /// Gives the analyzer versions and the analysis config for the analysis inputs hash
    /// (design Section 3.9). The default is `null`.
    fn inputs_tag(&self) -> Value {
        Value::Null
    }

    /// Runs a re-analysis of `binary` from the start band `band` within `fuel`: the shadow run
    /// of design Section 3.9. The default runs the full analysis.
    ///
    /// # Errors
    ///
    /// Returns a tool error when the analysis cannot start.
    fn reanalyze(
        &mut self,
        binary: &mut OpenBinary,
        band: u16,
        fuel: &mut Fuel,
    ) -> Result<RunReport, ToolError> {
        let _ = band;
        self.run(binary, Until::Full, fuel)
    }

    /// Holds or releases the publish of the first analysis of the binary `id` (ADR-0016).
    /// While the hold is on, a run publishes only at completion. The default does nothing.
    fn hold(&mut self, id: BinaryId, on: bool) {
        let _ = (id, on);
    }

    /// Gives the engine a store for the pages of the work state of the binary `id`
    /// (ADR-0031 stage 3). The session calls it once for each binary with a project that
    /// takes writes. The default drops the store.
    fn set_pages(&mut self, id: BinaryId, store: Box<dyn ghidorah_analysis::pages::PageStore>) {
        let _ = (id, store);
    }

    /// Publishes the analysis work of `binary` that a hold kept back. The default does
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns a tool error when the publish step fails.
    fn flush(&mut self, binary: &mut OpenBinary) -> Result<(), ToolError> {
        let _ = binary;
        Ok(())
    }
}

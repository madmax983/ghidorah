//! The session: the host of the shipped tools (design Sections 10.2, 10.6 and 10.11).
//!
//! A [`Session`] owns the open binaries, the roots, the active profile, the [`RunConfig`], the
//! [`Clock`] and the session labels. It implements [`Host`], so the dispatcher can bind a
//! binary, coerce arguments, filter by sets and page with cursors.
//!
//! Binding rules of the global `binary_id` (Section 10.2):
//!
//! | Call | Open binaries | Result |
//! |---|---|---|
//! | `binary_id` names an open binary | any | that binary |
//! | `binary_id` names no open binary | any | `UNKNOWN_BINARY` with the open binaries |
//! | no `binary_id` | one | that binary, and the envelope echoes it |
//! | no `binary_id` | none | `NO_BINARY_OPEN`, or no binary for an optional binary |
//! | no `binary_id` | more than one | `BINARY_REQUIRED` with `details.binary_id` of the most recent binary |
//!
//! Session labels: the `session` argument, else the label of the transport, else the label of
//! the bound binary. A binary gets its label from the [`LabelRule`] when it opens.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{BinaryId, Clock, ErrorCode, FixedClock, Fuel, Limits};
use ghidorah_db::Program;
use ghidorah_json::Value;

use crate::api::Host;
use crate::args::Globals;
use crate::cursor::Spill;
use crate::dispatch::{Crash, CursorCall, Members, SortKey};
use crate::envelope::{AnalysisInfo, AnalysisState, Frame};
use crate::errors::ToolError;
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use crate::roots::Roots;
use crate::spec::{ArgKind, ToolSpec};

/// The largest number of crash records that a session keeps.
pub const MAX_CRASHES: usize = 64;

/// The run settings that the `cli` crate reads once from the environment (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunConfig {
    /// `GHIDORAH_FIXED_TIME`: the fixed time in milliseconds since the Unix epoch.
    pub fixed_time: Option<u64>,
    /// `GHIDORAH_EVAL`: `true` turns the `max_ms` guards off.
    pub eval_mode: bool,
}

/// The rule of the default session label of a binary (Section 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelRule {
    /// One fixed label, for example `cli`.
    Fixed(String),
    /// `mcp-<k>` per process and binary. A new project gives `mcp-1`.
    Mcp,
}

impl LabelRule {
    /// Gives the label of a binary whose journal holds `known` distinct `mcp-` labels.
    #[must_use]
    pub fn label(&self, known: u64) -> String {
        let _ = known;
        String::new()
    }
}

/// The settings of one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// The roots of `binary_load`.
    pub roots: Roots,
    /// The active profile and the allowlist.
    pub profile: ProfileSet,
    /// The run settings.
    pub run: RunConfig,
    /// The rule of the default session labels.
    pub labels: LabelRule,
    /// `true` opens every binary in read-only mode.
    pub read_only: bool,
    /// The caps of each load.
    pub limits: Limits,
}

impl SessionConfig {
    /// Makes the settings with `roots`, the `full` profile, the label `cli` and the default
    /// caps.
    #[must_use]
    pub fn new(roots: Roots) -> Self {
        Self {
            roots,
            profile: ProfileSet::default(),
            run: RunConfig::default(),
            labels: LabelRule::Fixed("cli".to_owned()),
            read_only: false,
            limits: Limits::DEFAULT,
        }
    }
}

/// One open binary.
#[derive(Debug, Clone)]
pub struct OpenBinary {
    /// The binary ID.
    pub id: BinaryId,
    /// The program.
    pub program: Program,
    /// The file name: the last part of the path, or the name of a built-in binary.
    pub file_name: String,
    /// `true` when the binary accepts no edits.
    pub read_only: bool,
    /// The default session label of the binary.
    pub label: String,
    /// The analysis state, or `None` when no analysis ran.
    pub analysis: Option<AnalysisInfo>,
}

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
}

/// The analysis engine of a session. The analysis WP installs it with [`Session::set_engine`].
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
}

/// The session: the host of the shipped tools.
pub struct Session {
    registry: Registry<Self>,
    config: SessionConfig,
    clock: Box<dyn Clock + Send>,
    binaries: BTreeMap<BinaryId, OpenBinary>,
    recent: Vec<BinaryId>,
    engine: Option<Box<dyn AnalysisEngine>>,
    spill: RefCell<Spill>,
    crashes: Vec<Crash>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("registry", &self.registry)
            .field("config", &self.config)
            .field("binaries", &self.binaries.keys().collect::<Vec<_>>())
            .field("engine", &self.engine.is_some())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Makes a session of the shipped registry. A `fixed_time` in the run settings replaces
    /// `clock` with a [`FixedClock`].
    #[must_use]
    pub fn new(config: SessionConfig, clock: Box<dyn Clock + Send>) -> Self {
        Self::with_registry(<Self as Host>::registry(), config, clock)
    }

    /// Makes a session of `registry`, for example a test registry.
    #[must_use]
    pub fn with_registry(
        registry: Registry<Self>,
        config: SessionConfig,
        clock: Box<dyn Clock + Send>,
    ) -> Self {
        let clock: Box<dyn Clock + Send> = match config.run.fixed_time {
            Some(ms) => Box::new(FixedClock::new(ms)),
            None => clock,
        };
        Self {
            registry,
            config,
            clock,
            binaries: BTreeMap::new(),
            recent: Vec::new(),
            engine: None,
            spill: RefCell::new(Spill::new()),
            crashes: Vec::new(),
        }
    }

    /// Gives the registry of the session: tool search, profiles and instructions read it.
    #[must_use]
    pub const fn active_registry(&self) -> Registry<Self> {
        self.registry
    }

    /// Gives the settings.
    #[must_use]
    pub const fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Gives the clock.
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Gives the active tools of the registry in registry order.
    #[must_use]
    pub fn active_tools(&self) -> Vec<&'static ToolSpec<Self>> {
        self.config.profile.tools(&self.registry)
    }

    /// Gives the server instructions for the active tools.
    #[must_use]
    pub fn instructions(&self) -> String {
        crate::instructions::generate(&self.registry, &self.config.profile)
    }

    /// Installs the analysis engine.
    pub fn set_engine(&mut self, engine: Box<dyn AnalysisEngine>) {
        self.engine = Some(engine);
    }

    /// Runs the analysis engine on the open binary `id`. Gives `None` when the session has no
    /// engine or no such binary.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn analyze(
        &mut self,
        id: BinaryId,
        until: Until,
        fuel: &mut Fuel,
    ) -> Result<Option<RunReport>, ToolError> {
        let _ = (id, until, fuel);
        Ok(None)
    }

    /// Gives the default label of a new binary.
    #[must_use]
    pub fn new_label(&self) -> String {
        String::new()
    }

    /// Adds an open binary and makes it the most recent one. A binary with the same ID goes.
    pub fn open(&mut self, binary: OpenBinary) {
        let _ = binary;
    }

    /// Gives the open binary `id`.
    #[must_use]
    pub fn binary(&self, id: BinaryId) -> Option<&OpenBinary> {
        self.binaries.get(&id)
    }

    /// Gives the open binary `id` for a change.
    #[must_use]
    pub fn binary_mut(&mut self, id: BinaryId) -> Option<&mut OpenBinary> {
        self.binaries.get_mut(&id)
    }

    /// Gives the open binaries in ID order.
    pub fn binaries(&self) -> impl Iterator<Item = &OpenBinary> {
        self.binaries.values()
    }

    /// Gives the most recent open binary.
    #[must_use]
    pub fn recent(&self) -> Option<BinaryId> {
        None
    }

    /// Gives the open binary of a call frame.
    ///
    /// # Errors
    ///
    /// Returns `NO_BINARY_OPEN` when the frame binds no binary.
    pub fn bound(&self, frame: &Frame) -> Result<&OpenBinary, ToolError> {
        let _ = frame;
        Err(ToolError::new(ErrorCode::InternalError))
    }

    /// Gives the crash records of the handler panics, oldest first.
    #[must_use]
    pub fn crashes(&self) -> &[Crash] {
        &self.crashes
    }
}

impl Host for Session {
    fn registry() -> Registry<Self> {
        crate::registry::shipped()
    }

    fn in_profile(&self, name: &str) -> bool {
        self.config.profile.holds(&self.registry, name)
    }

    fn frame(
        &mut self,
        tool: &ToolSpec<Self>,
        globals: &Globals,
        request_session: Option<&str>,
    ) -> Result<Frame, ToolError> {
        let _ = (tool, globals, request_session);
        Err(ToolError::new(ErrorCode::InternalError))
    }

    fn coerce(&self, kind: &ArgKind, value: &Value) -> Option<Value> {
        crate::coerce::lenient(kind, value)
    }

    fn members(&self, frame: &Frame, set: &str) -> Result<Members, ToolError> {
        let _ = (frame, set);
        Err(ToolError::new(ErrorCode::InternalError))
    }

    fn encode_cursor(&self, call: &CursorCall<'_>, key: &SortKey) -> String {
        crate::cursor::encode(call, key, 0, &mut self.spill.borrow_mut())
    }

    fn decode_cursor(&self, call: &CursorCall<'_>, cursor: &str) -> Result<SortKey, ToolError> {
        crate::cursor::decode(call, cursor, 0, &self.spill.borrow())
    }

    fn on_panic(&mut self, crash: &Crash) {
        let _ = crash;
    }
}

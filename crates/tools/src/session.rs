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
//! the bound binary. A binary gets its label from the [`LabelRule`] when it opens. A project
//! that opens gives the rule the number of distinct `mcp-` labels in its journal.
//!
//! The `store` module keeps the history and the project of each binary. Tool handlers commit
//! through [`Session::transact`] and [`Session::undo`], so each commit gets its journal line.
//! The `open` module opens and closes projects. [`batch`] makes one transaction of a batch.
//! The `cache` module keeps the decompile cache of each binary ([`Session::decompile`]).

pub mod batch;
mod cache;
mod engine;
mod open;
mod slices;
mod store;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{BinaryId, Clock, ErrorCode, FixedClock, Fuel, Limits, SetName, did_you_mean};
pub use ghidorah_db::Source;
use ghidorah_db::{Fs, LockInfo, Program, RealFs, SetMembers};
use ghidorah_json::Value;

pub use open::{Admitted, FULL_BAND};
pub(crate) use store::session_label;
pub use store::{ProjectsConfig, Store};

use crate::api::Host;
use crate::args::Globals;
use crate::cursor::Spill;
use crate::dispatch::{Crash, CursorCall, Members, SortKey};
use crate::envelope::{AnalysisInfo, Frame};
use crate::errors::{Candidate, ToolError};
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use crate::roots::Roots;
use crate::spec::{ArgKind, BinaryArg, ToolSpec};

pub use engine::{AnalysisEngine, RunReport, Until};

/// The largest number of crash records that a session keeps.
pub const MAX_CRASHES: usize = 64;

/// The fuel of the did-you-mean scan of a set name.
const DYM_FUEL: u64 = 100_000;

/// The `why` of the reopen hint of `UNKNOWN_BINARY`.
pub const WHY_REOPEN: &str = "Open the project of the binary.";

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
        match self {
            Self::Fixed(text) => text.clone(),
            Self::Mcp => format!("mcp-{}", known.saturating_add(1)),
        }
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
    /// The projects root, or `None` for a session that keeps no projects.
    pub projects: Option<ProjectsConfig>,
    /// The provenance source of the edits: `agent`, or `user` for a human.
    pub source: Source,
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
            projects: None,
            source: Source::Agent,
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

/// The session: the host of the shipped tools.
pub struct Session {
    registry: Registry<Self>,
    config: SessionConfig,
    clock: Box<dyn Clock + Send>,
    binaries: BTreeMap<BinaryId, OpenBinary>,
    recent: Vec<BinaryId>,
    engine: Option<Box<dyn AnalysisEngine>>,
    spill: RefCell<Spill>,
    decomp: RefCell<cache::DecompCaches>,
    crashes: Vec<Crash>,
    stores: BTreeMap<BinaryId, Store>,
    fs: Box<dyn Fs>,
    me: LockInfo,
    current: Option<BinaryId>,
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
        let mut fs: Box<dyn Fs> = Box::new(RealFs);
        let me = ghidorah_db::lock::current(fs.as_mut()).unwrap_or_else(|| LockInfo {
            pid: std::process::id(),
            start_time: 0,
            boot_id: String::new(),
        });
        Self {
            registry,
            config,
            clock,
            binaries: BTreeMap::new(),
            recent: Vec::new(),
            engine: None,
            spill: RefCell::new(Spill::new()),
            decomp: RefCell::new(cache::DecompCaches::default()),
            crashes: Vec::new(),
            stores: BTreeMap::new(),
            fs,
            me,
            current: None,
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
        let (Some(engine), Some(binary)) = (self.engine.as_mut(), self.binaries.get_mut(&id))
        else {
            return Ok(None);
        };
        let before = binary.program.rev();
        let report = engine.run(binary, until, fuel)?;
        self.finish_run(id, before, report)?;
        Ok(Some(report))
    }

    /// Gives the analyzer rows of the engine for the open binary `id`. A session with no
    /// engine gives none.
    #[must_use]
    pub fn analyzer_rows(&self, id: BinaryId) -> Vec<ghidorah_analysis::AnalyzerRow> {
        self.engine
            .as_ref()
            .map(|e| e.analyzers(id))
            .unwrap_or_default()
    }

    /// Tells if the session has an analysis engine.
    #[must_use]
    pub fn has_engine(&self) -> bool {
        self.engine.is_some()
    }

    /// Gives the default label of a new binary.
    #[must_use]
    pub fn new_label(&self) -> String {
        self.config.labels.label(0)
    }

    /// Makes `id` the most recent binary.
    fn touch(&mut self, id: BinaryId) {
        self.recent.retain(|r| *r != id);
        self.recent.push(id);
    }

    /// Gives the open binaries as candidates, the most recent first.
    fn candidates(&self) -> Vec<Candidate> {
        self.recent
            .iter()
            .rev()
            .filter_map(|id| self.binaries.get(id))
            .map(|b| {
                let mut c = Candidate::text(&b.id.to_string(), &b.file_name);
                c.kind = Some("binary".to_owned());
                c
            })
            .collect()
    }

    /// Gives the `UNKNOWN_BINARY` error with the open binaries as candidates.
    #[must_use]
    pub fn unknown_binary(&self) -> ToolError {
        ToolError::new(ErrorCode::UnknownBinary)
            .path("/binary_id")
            .candidates(self.candidates())
    }

    /// Gives the `UNKNOWN_BINARY` error of the call text `text`. When the projects root holds
    /// the project of `text`, `next[0]` is `binary_load { binary_id }`.
    pub fn unknown_binary_id(&mut self, text: &str) -> ToolError {
        let error = self.unknown_binary();
        match BinaryId::parse(text) {
            Ok(id) if self.has_project(id) => error.next(crate::hints::Call::new(
                "binary_load",
                Value::object([("binary_id", Value::from(id.to_string()))]),
                WHY_REOPEN,
            )),
            _ => error,
        }
    }

    /// Gives the `BINARY_REQUIRED` error with `details.binary_id` of the most recent binary.
    #[must_use]
    pub fn binary_required(&self) -> ToolError {
        let mut error = ToolError::new(ErrorCode::BinaryRequired).candidates(self.candidates());
        if let Some(id) = self.recent() {
            error = error.detail("binary_id", Value::from(id.to_string()));
        }
        error
    }

    /// Gives the binary that a call binds, or `None` for a call with no binary.
    fn bind(
        &mut self,
        given: Option<&str>,
        mode: BinaryArg,
    ) -> Result<Option<BinaryId>, ToolError> {
        if let Some(text) = given {
            let open = BinaryId::parse(text)
                .ok()
                .filter(|id| self.binaries.contains_key(id));
            return match open {
                Some(id) => Ok(Some(id)),
                None => Err(self.unknown_binary_id(text)),
            };
        }
        match (self.binaries.len(), mode) {
            (1, _) => Ok(self.binaries.keys().next().copied()),
            (_, BinaryArg::Optional | BinaryArg::None) => Ok(None),
            (0, BinaryArg::Bound) => Err(ToolError::new(ErrorCode::NoBinaryOpen)),
            (_, BinaryArg::Bound) => Err(self.binary_required()),
        }
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
        self.recent.last().copied()
    }

    /// Gives the open binary of a call frame.
    ///
    /// # Errors
    ///
    /// A frame with no binary gives `NO_BINARY_OPEN` when the session has no binary, else
    /// `BINARY_REQUIRED`. A frame binary that is not open gives `UNKNOWN_BINARY`.
    pub fn bound(&self, frame: &Frame) -> Result<&OpenBinary, ToolError> {
        let Some(text) = &frame.binary_id else {
            return Err(match self.binaries.len() {
                0 => ToolError::new(ErrorCode::NoBinaryOpen),
                _ => self.binary_required(),
            });
        };
        BinaryId::parse(text)
            .ok()
            .and_then(|id| self.binaries.get(&id))
            .ok_or_else(|| self.unknown_binary())
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
        let bound = match tool.binary {
            BinaryArg::None => None,
            mode => self.bind(globals.binary_id.as_deref(), mode)?,
        };
        if let Some(id) = bound {
            self.touch(id);
        }
        self.current = bound;
        let binary = bound.and_then(|id| self.binaries.get(&id));
        let session = globals
            .session
            .clone()
            .or_else(|| request_session.map(str::to_owned))
            .or_else(|| binary.map(|b| b.label.clone()))
            .unwrap_or_else(|| self.new_label());
        Ok(Frame {
            binary_id: binary.map(|b| b.id.to_string()),
            rev: binary.map_or(0, |b| b.program.rev().0),
            session,
            analysis: binary.and_then(|b| b.analysis),
        })
    }

    fn coerce(&self, kind: &ArgKind, value: &Value) -> Option<Value> {
        crate::coerce::lenient(kind, value)
    }

    fn members(&self, frame: &Frame, set: &str) -> Result<Members, ToolError> {
        let binary = self.bound(frame)?;
        let notes = binary.program.notes();
        let name = set.strip_prefix("set:").unwrap_or(set);
        let found = SetName::new(name)
            .ok()
            .and_then(|n| notes.set(&n))
            .and_then(|note| note.set.as_ref());
        let Some(found) = found else {
            let names: Vec<String> = notes
                .sets()
                .map(|(n, _)| format!("set:{}", n.as_str()))
                .collect();
            let mut fuel = Fuel::new(DYM_FUEL);
            let candidates = did_you_mean(set, names.iter().map(String::as_str), &mut fuel)
                .into_iter()
                .map(|s| Candidate::text(&s.name, "set"))
                .collect();
            return Err(ToolError::new(ErrorCode::NotFound)
                .var("kind", "set")
                .path("/in")
                .detail("kind", Value::from("set"))
                .candidates(candidates));
        };
        Ok(match &found.members {
            SetMembers::Ids(ids) => Members {
                ids: ids.iter().cloned().collect(),
                ranges: Vec::new(),
            },
            SetMembers::Addrs(set) => Members {
                ids: BTreeSet::new(),
                ranges: set
                    .ranges()
                    .iter()
                    .map(|r| (r.first, r.last.saturating_add(1)))
                    .collect(),
            },
        })
    }

    fn encode_cursor(&self, call: &CursorCall<'_>, key: &SortKey) -> String {
        crate::cursor::encode(call, key, 0, &mut self.spill.borrow_mut())
    }

    fn decode_cursor(&self, call: &CursorCall<'_>, cursor: &str) -> Result<SortKey, ToolError> {
        crate::cursor::decode(call, cursor, 0, &self.spill.borrow())
    }

    fn on_panic(&mut self, crash: &Crash) {
        self.crashes.push(crash.clone());
        if self.crashes.len() > MAX_CRASHES {
            self.crashes.remove(0);
        }
        self.write_crash(crash);
        if let Some(id) = self.current {
            let _ = self.reload(id);
            self.decomp.get_mut().renew(id);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let ids: Vec<BinaryId> = self.binaries.keys().copied().collect();
        for id in ids {
            self.close(id);
        }
    }
}

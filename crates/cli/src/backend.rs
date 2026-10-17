//! The backend of the command line: the session side of every command.
//!
//! A [`Backend`] is a [`Host`] of the tools crate that the command line can open from the
//! [`Options`] of a command. The worker thread opens it, so a backend needs no `Send`.
//! The binary uses [`crate::Shipped`]. Tests use a test backend over a test registry.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use ghidorah_tools::{Host, Profile};

use crate::argv::SessionFlags;
use crate::config::{Env, RunConfig};

/// The provenance source of the edits of a run (design Section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Source {
    /// An agent makes the edits. This is the default.
    #[default]
    Agent,
    /// A human makes the edits.
    User,
}

impl Source {
    /// Gives the source name: `agent` or `user`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
        }
    }

    /// Parses a source name, or gives `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "agent" => Some(Self::Agent),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

/// Parses a profile name: `full`, `readonly` or `mini`.
#[must_use]
pub fn parse_profile(text: &str) -> Option<Profile> {
    Profile::ALL.into_iter().find(|p| p.as_str() == text)
}

/// The session settings of one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The projects root, or `None` when the environment gives no default.
    pub project_root: Option<PathBuf>,
    /// The roots that `binary_load { path }` can read under.
    pub roots: Vec<PathBuf>,
    /// The active profile.
    pub profile: Profile,
    /// The tool allowlist on top of the profile, or `None` for all tools of the profile.
    pub tools: Option<BTreeSet<String>>,
    /// `true` opens every project in read-only mode.
    pub read_only: bool,
    /// The projects to open at the start, by `binary_id`.
    pub open: Vec<String>,
    /// `true` replaces a stale project lock.
    pub break_lock: bool,
    /// The provenance source of the edits.
    pub source: Source,
    /// The session label of calls that name no session.
    pub session: String,
    /// The run configuration.
    pub run: RunConfig,
}

impl Options {
    /// Makes the default options of `env`: the current directory as the one root, the
    /// default projects root, profile `full` and session label `session`.
    #[must_use]
    pub fn new(env: &Env, session: &str) -> Self {
        Self {
            project_root: env.projects_root(),
            roots: vec![env.cwd.clone()],
            profile: Profile::Full,
            tools: None,
            read_only: false,
            open: Vec::new(),
            break_lock: false,
            source: Source::Agent,
            session: session.to_owned(),
            run: env.run,
        }
    }

    /// Makes the options of the session flags `flags` in `env`.
    ///
    /// The session label is `--session`, else `session`. Relative paths start at the
    /// current directory of `env`.
    #[must_use]
    pub fn with_flags(env: &Env, flags: &SessionFlags, session: &str) -> Self {
        let mut options = Self::new(env, flags.session.as_deref().unwrap_or(session));
        if let Some(root) = &flags.project_root {
            options.project_root = Some(env.cwd.join(root));
        }
        if !flags.roots.is_empty() {
            options.roots = flags.roots.iter().map(|r| env.cwd.join(r)).collect();
        }
        if let Some(profile) = flags.profile {
            options.profile = profile;
        }
        options.tools.clone_from(&flags.tools);
        options.read_only = flags.read_only;
        options.open.clone_from(&flags.open);
        options.break_lock = flags.break_lock;
        options.source = flags.source;
        options
    }
}

/// A backend that does not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenError {
    /// What failed, why and what to do, in STE.
    pub message: String,
}

impl OpenError {
    /// Makes an error with `message`.
    #[must_use]
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OpenError {}

/// The session side of the command line.
pub trait Backend: Host {
    /// Opens the backend of one command.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError`] when a project of [`Options::open`] does not open.
    fn open(options: &Options) -> Result<Self, OpenError>;

    /// Opens a backend that runs the registry examples, for example with the demo binary.
    ///
    /// The default opens the backend with [`Backend::open`].
    ///
    /// # Errors
    ///
    /// Returns [`OpenError`] when the backend does not open.
    fn for_examples(options: &Options) -> Result<Self, OpenError> {
        Self::open(options)
    }

    /// Gives the server instructions of the active profile (design Section 10.15).
    fn instructions(&self) -> String;
}

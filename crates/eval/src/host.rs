//! The in-process host of the harness: sessions, calls, sizes and scratch directories.
//!
//! The runner calls the dispatcher of `ghidorah-tools` in process (design Section 12.1).
//! Every session has a fixed clock, so two runs give byte-equal responses.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ghidorah_json::Value;
use ghidorah_tools::session::ProjectsConfig;
use ghidorah_tools::{Profile, ProfileSet, Request, Roots, Session, SessionConfig, dispatch};

use crate::error::EvalError;

/// The fixed time of every eval session, in milliseconds since the Unix epoch.
pub const FIXED_TIME: u64 = 1_760_000_000_000;

/// Makes a session of the shipped registry with the analysis engine.
///
/// The session reads binaries under `root`. With `projects`, it keeps its projects in that
/// directory, so a new session can open them again after a restart.
///
/// # Errors
///
/// Returns [`EvalError::Data`] when `root` is not a directory that the roots accept.
pub fn session(
    root: &Path,
    projects: Option<&Path>,
    profile: Profile,
) -> Result<Session, EvalError> {
    let roots = Roots::new(root, &[PathBuf::from(".")])
        .map_err(|e| EvalError::data(&root.display().to_string(), &e.to_string()))?;
    let mut config = SessionConfig::new(roots);
    config.profile = ProfileSet::new(profile, None);
    config.projects = projects.map(|p| ProjectsConfig {
        root: p.to_path_buf(),
        named: true,
        break_lock: false,
    });
    let mut s = Session::fixed(config, FIXED_TIME);
    ghidorah_tools::handlers::analysis_run::install(&mut s);
    Ok(s)
}

/// Gives an empty JSON object: the arguments of a call with no arguments.
#[must_use]
pub fn empty() -> Value {
    Value::Object(ghidorah_json::Object::new())
}

/// Tells if an envelope is a success: `ok` is `true`.
#[must_use]
pub fn ok(envelope: &Value) -> bool {
    envelope.get("ok").and_then(Value::as_bool) == Some(true)
}

/// Gives a JSON array of texts.
#[must_use]
pub fn texts(v: &[String]) -> Value {
    Value::Array(v.iter().map(|s| Value::from(s.as_str())).collect())
}

/// Runs one call and gives the envelope JSON.
pub fn call(session: &mut Session, tool: &str, args: Value) -> Value {
    dispatch(session, &Request::new(tool, args)).to_json()
}

/// Gives the size of a response: the characters of its compact JSON text.
#[must_use]
pub fn chars(value: &Value) -> u64 {
    u64::try_from(ghidorah_json::write(value).chars().count()).unwrap_or(u64::MAX)
}

/// Gives `ceil(chars / per_token)`, the token estimate of design Section 10.9.
#[must_use]
pub fn est_tokens(chars: u64, per_token: u64) -> u64 {
    chars.div_ceil(per_token.max(1))
}

/// A scratch directory that the harness removes when it drops.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

static NEXT: AtomicU64 = AtomicU64::new(0);

impl Scratch {
    /// Makes a new empty directory under the temporary directory of the system.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the system does not make the directory.
    pub fn new(tag: &str) -> std::io::Result<Self> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ghidorah-eval-{}-{tag}-{n}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Gives the path of the directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

//! `ghidorah doctor`: the self-test of the build (design Section 10.14).
//!
//! The command prints one JSON object
//! `{ ok, version, run_config, checks: [{ name, ok, .. }] }`:
//!
//! | Check | Test |
//! |---|---|
//! | `registry_lint` | The registry lint finds nothing. |
//! | `examples` | Each registry example runs with no `INTERNAL_ERROR`, and each result fits 60,000 characters in each content mode. The check gives the sizes. |
//! | `project_dir` | A probe file in the projects root writes and syncs. |
//! | `era` | The era rules answer both handshakes. |
//!
//! The exit code is 0 when all checks pass, else 1. Output holds no absolute path.

use ghidorah_json::Value;

use crate::Streams;
use crate::argv::DoctorArgs;
use crate::backend::{Backend, Options};
use crate::config::Env;
use crate::exit::Exit;

/// The name of the probe file in the projects root.
pub const PROBE: &str = ".ghidorah-doctor-probe";

/// Gives the doctor report of the backend `B` with `options`.
#[must_use]
pub fn report<B: Backend>(options: &Options) -> Value {
    let _ = options;
    Value::Null
}

/// Runs `ghidorah doctor` with the backend `B`.
pub fn doctor<B: Backend>(args: &DoctorArgs, env: &Env, streams: &mut Streams) -> Exit {
    let _ = (args, env, streams);
    Exit::Usage
}

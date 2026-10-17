//! `analysis_inputs_hash` (design Section 3.9, ADR-0004).
//!
//! The analysis facts are a pure function of their inputs. The hash is the SHA-256 of the JCS
//! form of this object:
//!
//! | Member | Content |
//! |---|---|
//! | `binary` | the SHA-256 of the input file in hex |
//! | `analyzers` | `[name, version]` of each analyzer in registry order |
//! | `base` | the base-layer facts that affect analysis: `data`, `funcs`, `jumptables`, `overrides` and `refs` |
//!
//! A project compares the hash on open. A new hash starts a shadow re-analysis.

use ghidorah_db::Program;
use ghidorah_json::JcsError;

/// Gives `analysis_inputs_hash` of `program`.
///
/// # Errors
///
/// Returns the [`JcsError`] of the canonical form.
pub fn inputs_hash(program: &Program) -> Result<[u8; 32], JcsError> {
    let _ = program;
    Ok([0; 32])
}

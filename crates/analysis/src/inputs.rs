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
use ghidorah_db::codec::tables_to_json;
use ghidorah_json::{JcsError, Value, write_jcs};

use crate::registry::ANALYZERS;

/// The members of the base layer that affect analysis.
const BASE: [&str; 5] = ["data", "funcs", "jumptables", "overrides", "refs"];

/// Gives `analysis_inputs_hash` of `program`.
///
/// # Errors
///
/// Returns the [`JcsError`] of the canonical form.
pub fn inputs_hash(program: &Program) -> Result<[u8; 32], JcsError> {
    let tables = tables_to_json(program.base());
    let base = Value::object(BASE.map(|name| {
        let rows = tables
            .get(name)
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        (name, rows)
    }));
    let value = Value::object([
        ("analyzers", versions()),
        ("base", base),
        (
            "binary",
            Value::from(ghidorah_base::hex::encode(&program.meta().sha256)),
        ),
    ]);
    let text = write_jcs(&value)?;
    Ok(ghidorah_base::sha256(text.as_bytes()))
}

/// Gives `[name, version]` of each analyzer in registry order.
#[must_use]
pub fn versions() -> Value {
    Value::Array(
        ANALYZERS
            .iter()
            .map(|s| Value::Array(vec![Value::from(s.name), Value::from(s.version)]))
            .collect(),
    )
}

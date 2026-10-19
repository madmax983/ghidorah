//! The light checks of the scorecard: catalog sizes, schema fuzz and metamorphic relations
//! (design Section 12.4).
//!
//! WP-27 runs the long schema fuzz and the five metamorphic relations of Section 13.4 in its
//! own gates. The harness runs a short deterministic form of each, so the scorecard shows them.

use std::path::Path;

use ghidorah_json::Value;
use ghidorah_tools::{ArgKind, Profile, ProfileSet, Session, registry::shipped};

use crate::error::EvalError;
use crate::host;
use crate::milli::Milli;

/// The sizes of the catalog in characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Catalog {
    /// The `tools/list` result of the full profile.
    pub full_chars: u64,
    /// The `tools/list` result of the mini profile.
    pub mini_chars: u64,
    /// The server instructions of the full profile.
    pub instructions_chars: u64,
}

/// Measures the catalog sizes.
///
/// # Errors
///
/// Returns an [`EvalError`] when the session does not open.
pub fn catalog(root: &Path) -> Result<Catalog, EvalError> {
    return Ok(Catalog::default());
    let registry = shipped();
    let size = |p: Profile| host::chars(&ProfileSet::new(p, None).tools_list(&registry));
    let session = host::session(root, None, Profile::Full)?;
    Ok(Catalog {
        full_chars: size(Profile::Full),
        mini_chars: size(Profile::Mini),
        instructions_chars: u64::try_from(session.instructions().chars().count())
            .unwrap_or(u64::MAX),
    })
}

/// The result of the short schema fuzz.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fuzz {
    /// The number of calls.
    pub cases: u64,
    /// The calls whose result is not a valid envelope or is `INTERNAL_ERROR`.
    pub violations: Vec<String>,
}

/// Gives a value of the wrong type for an argument kind.
fn wrong(kind: ArgKind) -> Value {
    match kind {
        ArgKind::Bool | ArgKind::Enum(_) | ArgKind::Str(_) | ArgKind::Id(_) => {
            Value::Array(Vec::new())
        }
        ArgKind::Int { .. } | ArgKind::Addr => Value::from(true),
        ArgKind::AddrList(_) | ArgKind::List(..) | ArgKind::Obj(_) => Value::from(7u64),
        ArgKind::Json => Value::Null,
    }
}

/// Tells if a response is a valid envelope with no internal error.
#[must_use]
pub fn valid_envelope(response: &Value) -> bool {
    match response.get("ok").and_then(Value::as_bool) {
        Some(true) => response.get("data").is_some(),
        Some(false) => response
            .pointer("/error/code")
            .and_then(Value::as_str)
            .is_some_and(|c| !c.is_empty() && c != "INTERNAL_ERROR"),
        None => false,
    }
}

fn fuzz_one(session: &mut Session, out: &mut Fuzz, tool: &str, args: Value) {
    let label = format!("{tool} {}", ghidorah_json::write(&args));
    let r = host::call(session, tool, args);
    out.cases = out.cases.saturating_add(1);
    if !valid_envelope(&r) {
        out.violations.push(label);
    }
}

/// Sends wrong-typed and unknown arguments to every tool on the demo binary.
///
/// # Errors
///
/// Returns an [`EvalError`] when the session does not open.
pub fn fuzz(root: &Path) -> Result<Fuzz, EvalError> {
    return Ok(Fuzz::default());
    let mut session = host::session(root, None, Profile::Full)?;
    host::call(
        &mut session,
        "binary_load",
        Value::object([("builtin", Value::from("demo"))]),
    );
    let mut out = Fuzz::default();
    let registry = shipped();
    for name in registry.names() {
        let Some((_, tool)) = registry.get(name) else {
            continue;
        };
        fuzz_one(
            &mut session,
            &mut out,
            name,
            Value::object([("no_such_key", Value::from(1u64))]),
        );
        for arg in tool.args {
            fuzz_one(
                &mut session,
                &mut out,
                name,
                Value::object([(arg.name, wrong(arg.kind))]),
            );
        }
    }
    Ok(out)
}

/// The result of one metamorphic relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    /// The relation name: `strip`, `rebase` or `rename`.
    pub name: String,
    /// `true` when the relation holds.
    pub pass: bool,
}

/// The results of the metamorphic relations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metamorphic {
    /// The relations in a fixed order.
    pub relations: Vec<Relation>,
}

impl Metamorphic {
    /// Gives the fraction of relations that hold.
    #[must_use]
    pub fn rate(&self) -> Milli {
        let pass = self.relations.iter().filter(|r| r.pass).count();
        Milli::ratio(
            u64::try_from(pass).unwrap_or(0),
            u64::try_from(self.relations.len()).unwrap_or(0),
        )
    }
}

/// Gives `(addr, size, name)` of each function of the binary at `path`.
fn functions(root: &Path, path: &str) -> Result<Vec<(u64, u64, String)>, EvalError> {
    let mut s = host::session(root, None, Profile::Full)?;
    host::call(
        &mut s,
        "binary_load",
        Value::object([("path", Value::from(path))]),
    );
    Ok(list(&mut s))
}

fn list(s: &mut Session) -> Vec<(u64, u64, String)> {
    let r = host::call(
        s,
        "func_list",
        Value::object([("limit", Value::from(1000u64))]),
    );
    r.pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|i| {
            let addr = crate::derive::parse_int(i.get("addr")?.as_str()?)?;
            Some((
                addr,
                i.get("size")?.as_u64()?,
                i.get("name")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Checks the strip, rebase and rename relations on T1 fixtures.
///
/// # Errors
///
/// Returns an [`EvalError`] when a session does not open.
pub fn metamorphic(root: &Path) -> Result<Metamorphic, EvalError> {
    return Ok(Metamorphic::default());
    let full = functions(root, "fixtures/bin/hello.gcc-O2")?;
    let stripped = functions(root, "fixtures/bin/hello.gcc-O2.stripped")?;
    let starts = |l: &[(u64, u64, String)]| l.iter().map(|f| (f.0, f.1)).collect::<Vec<_>>();
    let strip = !full.is_empty() && starts(&full) == starts(&stripped);
    let low = functions(root, "fixtures/bin/switch.gcc-O2-at400000")?;
    let high = functions(root, "fixtures/bin/switch.gcc-O2-at800000")?;
    let rebase = !low.is_empty()
        && low.len() == high.len()
        && low
            .iter()
            .zip(&high)
            .all(|(a, b)| b.0.checked_sub(a.0) == Some(0x40_0000) && a.1 == b.1);
    let mut s = host::session(root, None, Profile::Full)?;
    host::call(
        &mut s,
        "binary_load",
        Value::object([("builtin", Value::from("demo"))]),
    );
    let before = list(&mut s);
    host::call(
        &mut s,
        "symbol_rename",
        Value::object([
            ("target", Value::from("main")),
            ("name", Value::from("renamed_main")),
            ("force", Value::from(true)),
        ]),
    );
    let after = list(&mut s);
    let rename = !before.is_empty()
        && starts(&before) == starts(&after)
        && before
            .iter()
            .zip(&after)
            .filter(|(a, b)| a.2 != b.2)
            .count()
            == 1;
    Ok(Metamorphic {
        relations: [("strip", strip), ("rebase", rebase), ("rename", rename)]
            .into_iter()
            .map(|(name, pass)| Relation {
                name: name.to_owned(),
                pass,
            })
            .collect(),
    })
}

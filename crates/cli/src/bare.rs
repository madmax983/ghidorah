//! [`Bare`]: a backend with no session state.
//!
//! A bare backend holds no binary and no project. It serves the shipped registry, the
//! profile filter and the protocol. A call of a tool that needs a binary gives
//! `NO_BINARY_OPEN`, or `UNKNOWN_BINARY` when the call names a `binary_id`.

use std::collections::BTreeSet;

use ghidorah_base::{ErrorCode, hex};
use ghidorah_json::Value;
use ghidorah_tools::dispatch::{Crash, CursorCall};
use ghidorah_tools::{
    ArgKind, BinaryArg, Frame, Globals, Host, KeyPart, Members, Profile, Registry, SortKey,
    ToolError, ToolSpec,
};

use crate::backend::{Backend, OpenError, Options};

/// The server instructions of a bare backend.
pub const INSTRUCTIONS: &str = "ghidorah analyzes x86-64 binaries for reverse engineering. All tools work offline and never run the binary.";

/// A backend with no open binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bare {
    profile: Profile,
    tools: Option<BTreeSet<String>>,
    session: String,
}

impl Bare {
    /// Makes a bare backend with the profile, the allowlist and the session label of `options`.
    #[must_use]
    pub fn new(options: &Options) -> Self {
        Self {
            profile: options.profile,
            tools: options.tools.clone(),
            session: options.session.clone(),
        }
    }
}

/// Gives the cursor text of one sort key part: `i<hex>` for a number, `t<hex bytes>` for a text.
fn part_text(part: &KeyPart) -> String {
    match part {
        KeyPart::Int(v) => format!("i{v:x}"),
        KeyPart::Text(t) => format!("t{}", hex::encode(t.as_bytes())),
    }
}

/// Parses one sort key part of a cursor, or gives `None`.
fn parse_part(text: &str) -> Option<KeyPart> {
    if let Some(digits) = text.strip_prefix('i') {
        return u64::from_str_radix(digits, 16).ok().map(KeyPart::Int);
    }
    let bytes = hex::decode(text.strip_prefix('t')?).ok()?;
    String::from_utf8(bytes).ok().map(KeyPart::Text)
}

impl Host for Bare {
    fn registry() -> Registry<Self> {
        ghidorah_tools::registry::shipped()
    }

    fn in_profile(&self, name: &str) -> bool {
        Self::registry().get(name).is_some_and(|(_, tool)| {
            tool.profiles.contains(&self.profile)
                && self.tools.as_ref().is_none_or(|list| list.contains(name))
        })
    }

    fn frame(
        &mut self,
        tool: &ToolSpec<Self>,
        globals: &Globals,
        request_session: Option<&str>,
    ) -> Result<Frame, ToolError> {
        if tool.binary == BinaryArg::Bound {
            let code = if globals.binary_id.is_some() {
                ErrorCode::UnknownBinary
            } else {
                ErrorCode::NoBinaryOpen
            };
            return Err(ToolError::new(code));
        }
        let session = globals
            .session
            .as_deref()
            .or(request_session)
            .unwrap_or(&self.session);
        Ok(Frame {
            session: session.to_owned(),
            ..Frame::default()
        })
    }

    fn coerce(&self, _kind: &ArgKind, _value: &Value) -> Option<Value> {
        None
    }

    fn members(&self, _frame: &Frame, _set: &str) -> Result<Members, ToolError> {
        Err(ToolError::new(ErrorCode::NotFound)
            .var("kind", "set")
            .detail("kind", Value::from("set")))
    }

    fn encode_cursor(&self, call: &CursorCall<'_>, key: &SortKey) -> String {
        let mut out = format!("{:x}", call.tool_index);
        for part in &key.0 {
            out.push('.');
            out.push_str(&part_text(part));
        }
        out
    }

    fn decode_cursor(&self, call: &CursorCall<'_>, cursor: &str) -> Result<SortKey, ToolError> {
        let invalid = || ToolError::new(ErrorCode::CursorInvalid);
        let mut parts = cursor.split('.');
        let index = parts
            .next()
            .and_then(|t| usize::from_str_radix(t, 16).ok())
            .ok_or_else(invalid)?;
        if index != call.tool_index {
            return Err(invalid());
        }
        parts
            .map(parse_part)
            .collect::<Option<Vec<_>>>()
            .map(SortKey)
            .ok_or_else(invalid)
    }

    fn on_panic(&mut self, _crash: &Crash) {}
}

impl Backend for Bare {
    fn open(options: &Options) -> Result<Self, OpenError> {
        if let Some(id) = options.open.first() {
            return Err(OpenError::new(&format!(
                "The project {id} does not open. This build keeps no projects. Remove the --open flag."
            )));
        }
        Ok(Self::new(options))
    }

    fn instructions(&self) -> String {
        INSTRUCTIONS.to_owned()
    }
}

#[cfg(test)]
mod tests;

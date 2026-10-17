//! The rules of the two MCP eras (design Section 10.13, ADR-0006).
//!
//! The specification snapshot is commit `86f6e0c675afea9a8f233e09b6faf566b126086c` of
//! `https://github.com/modelcontextprotocol/modelcontextprotocol` (2026-10-14).
//!
//! [`decide`] applies the rules to one request in this order:
//!
//! 1. `initialize` starts the legacy era for the process. The reply names the requested
//!    version when it is `2025-11-25` or `2025-06-18`, else `2025-11-25`.
//! 2. `server/discover` needs no handshake. It names all supported versions.
//! 3. A method outside `ping`, `tools/list` and `tools/call` gives -32601.
//! 4. `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` gives the modern era.
//!    A missing modern key then gives -32602 with the missing key names.
//! 5. Another version in that key gives -32022 with `{ supported, requested }`.
//! 6. A request without the version key uses the legacy era after `initialize`.
//!    Before `initialize` it gives -32602 with the missing key names.
//! 7. `ping` exists only in the legacy era. A modern `ping` gives -32601.
//!
//! A modern result carries `resultType: "complete"`. A legacy result does not.

use ghidorah_json::Value;

/// The modern protocol version.
pub const MODERN: &str = "2026-07-28";

/// The legacy versions, newest first.
pub const LEGACY: [&str; 2] = ["2025-11-25", "2025-06-18"];

/// All supported versions, newest first.
pub const SUPPORTED: [&str; 3] = [MODERN, "2025-11-25", "2025-06-18"];

/// The `_meta` key of the protocol version.
pub const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// The `_meta` key of the client capabilities.
pub const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// The `_meta` keys that each modern request carries.
pub const REQUIRED_KEYS: [&str; 2] = [VERSION_KEY, CAPABILITIES_KEY];

/// The `_meta` key of the session label of a tool call.
pub const SESSION_KEY: &str = "dev.ghidorah/session";

/// The `_meta` key of the size report of a tool result.
pub const SIZE_KEY: &str = "dev.ghidorah/size";

/// The era of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// The legacy era: `initialize` came first.
    Legacy,
    /// The stateless 2026-07-28 era.
    Modern,
}

/// A method that the server serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `initialize`, with the version of the reply.
    Initialize(&'static str),
    /// `server/discover`.
    Discover,
    /// `ping`.
    Ping,
    /// `tools/list`.
    ToolsList,
    /// `tools/call`.
    ToolsCall,
}

/// A request that the era rules reject: the parts of a JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// The JSON-RPC error code.
    pub code: i64,
    /// The message, in STE.
    pub message: String,
    /// The `data` member.
    pub data: Option<Value>,
}

/// The era state of one process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EraState {
    legacy: Option<&'static str>,
}

impl EraState {
    /// Gives the negotiated legacy version, or `None` before `initialize`.
    #[must_use]
    pub const fn legacy(&self) -> Option<&'static str> {
        self.legacy
    }
}

/// Gives the version of the `initialize` reply for the requested version.
#[must_use]
pub fn negotiate(requested: Option<&str>) -> &'static str {
    let _ = requested;
    MODERN
}

/// Applies the era rules to one request.
///
/// # Errors
///
/// Returns the [`Rejection`] of rules 3, 4, 5, 6 and 7.
pub fn decide(
    state: &mut EraState,
    method: &str,
    params: Option<&Value>,
) -> Result<(Era, Method), Rejection> {
    let _ = (state, method, params);
    Err(Rejection {
        code: 0,
        message: String::new(),
        data: None,
    })
}

/// Gives the server capabilities: tools only, `{ tools: { listChanged: false } }`.
#[must_use]
pub fn capabilities() -> Value {
    Value::Null
}

/// Gives the server info `{ name: "ghidorah", version }`.
#[must_use]
pub fn server_info(version: &str) -> Value {
    let _ = version;
    Value::Null
}

/// Gives the `initialize` result `{ protocolVersion, capabilities, serverInfo, instructions }`.
#[must_use]
pub fn initialize_result(version: &str, server_info: &Value, instructions: &str) -> Value {
    let _ = (version, server_info, instructions);
    Value::Null
}

/// Gives the `server/discover` result
/// `{ supportedVersions, capabilities, serverInfo, instructions, resultType }`.
#[must_use]
pub fn discover_result(server_info: &Value, instructions: &str) -> Value {
    let _ = (server_info, instructions);
    Value::Null
}

/// Gives `result` in `era`: a modern result gains `resultType: "complete"`.
#[must_use]
pub fn finish(era: Era, result: Value) -> Value {
    let _ = era;
    result
}

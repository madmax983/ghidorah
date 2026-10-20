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
//! 5. Another version in that key gives -32022 with `{ supported, requested }`. The list
//!    `supported` holds only the versions that `_meta` takes ([`META_VERSIONS`]). A legacy
//!    version needs `initialize`, and the message of a legacy version says so.
//! 6. A request without the version key uses the legacy era after `initialize`.
//!    Before `initialize` it gives -32602 with the missing key names. A `ping` is the
//!    exception: it gets `{}` in every state and starts no era.
//! 7. `ping` exists only in the legacy era. A modern `ping` gives -32601.
//!
//! A modern result carries `resultType: "complete"`. A legacy result does not.

use ghidorah_json::Value;

use crate::mcp::rpc;

/// The name of the server in `serverInfo`.
pub const SERVER_NAME: &str = "ghidorah";

/// The modern protocol version.
pub const MODERN: &str = "2026-07-28";

/// The legacy versions, newest first.
pub const LEGACY: [&str; 2] = ["2025-11-25", "2025-06-18"];

/// All supported versions, newest first.
pub const SUPPORTED: [&str; 3] = [MODERN, "2025-11-25", "2025-06-18"];

/// The versions that the `_meta` key of the protocol version takes. A legacy version needs
/// `initialize`.
pub const META_VERSIONS: [&str; 1] = [MODERN];

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
    LEGACY
        .into_iter()
        .find(|v| Some(*v) == requested)
        .unwrap_or(LEGACY[0])
}

/// The message of rule 3.
const UNKNOWN_METHOD: &str = "The method is not available. The server serves initialize, server/discover, ping, tools/list and tools/call.";

/// The message of a modern `ping` (rule 7).
const MODERN_PING: &str = "The method ping is not available in protocol version 2026-07-28. Send server/discover to check the server.";

/// The message of a missing key (rules 4 and 6).
const MISSING_KEYS: &str = "The request has no protocol keys in _meta. Send initialize first, or add the keys of data.missing to params._meta.";

/// The message of rule 5.
const BAD_VERSION: &str =
    "The protocol version of the request is not supported. Use a version of data.supported.";

/// The message of rule 5 for a legacy version in `_meta`.
const LEGACY_IN_META: &str = "A legacy protocol version needs initialize. The _meta key takes only the versions of data.supported. Send initialize first, or use a version of data.supported.";

fn method_of(name: &str) -> Option<Method> {
    match name {
        "ping" => Some(Method::Ping),
        "tools/list" => Some(Method::ToolsList),
        "tools/call" => Some(Method::ToolsCall),
        _ => None,
    }
}

fn strings(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|v| Value::from(*v)).collect())
}

fn missing(meta: Option<&Value>) -> Rejection {
    let absent: Vec<&str> = REQUIRED_KEYS
        .into_iter()
        .filter(|key| meta.and_then(|m| m.get(key)).is_none())
        .collect();
    Rejection {
        code: rpc::INVALID_PARAMS,
        message: MISSING_KEYS.to_owned(),
        data: Some(Value::object([("missing", strings(&absent))])),
    }
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
    match method {
        "initialize" => {
            let requested = params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str);
            let version = negotiate(requested);
            state.legacy = Some(version);
            return Ok((Era::Legacy, Method::Initialize(version)));
        }
        "server/discover" => return Ok((Era::Modern, Method::Discover)),
        _ => {}
    }
    let reject = |code, message: &str| Rejection {
        code,
        message: message.to_owned(),
        data: None,
    };
    let call = method_of(method).ok_or_else(|| reject(rpc::METHOD_NOT_FOUND, UNKNOWN_METHOD))?;
    let meta = params.and_then(|p| p.get("_meta"));
    let era = match meta.and_then(|m| m.get(VERSION_KEY)) {
        Some(Value::String(version)) if version == MODERN => {
            if REQUIRED_KEYS
                .iter()
                .any(|key| meta.and_then(|m| m.get(key)).is_none())
            {
                return Err(missing(meta));
            }
            Era::Modern
        }
        Some(other) => {
            let legacy = other.as_str().is_some_and(|v| LEGACY.contains(&v));
            let message = if legacy { LEGACY_IN_META } else { BAD_VERSION };
            return Err(Rejection {
                code: rpc::UNSUPPORTED_VERSION,
                message: message.to_owned(),
                data: Some(Value::object([
                    ("supported", strings(&META_VERSIONS)),
                    ("requested", other.clone()),
                ])),
            });
        }
        // A ping needs no handshake: the MCP lifecycle allows it before initialize.
        None if state.legacy.is_some() || call == Method::Ping => Era::Legacy,
        None => return Err(missing(meta)),
    };
    if era == Era::Modern && call == Method::Ping {
        return Err(reject(rpc::METHOD_NOT_FOUND, MODERN_PING));
    }
    Ok((era, call))
}

/// Gives the server capabilities: tools only, `{ tools: { listChanged: false } }`.
#[must_use]
pub fn capabilities() -> Value {
    Value::object([(
        "tools",
        Value::object([("listChanged", Value::Bool(false))]),
    )])
}

/// Gives the server info `{ name: "ghidorah", version }`.
#[must_use]
pub fn server_info(version: &str) -> Value {
    Value::object([
        ("name", Value::from(SERVER_NAME)),
        ("version", Value::from(version)),
    ])
}

/// Gives the `initialize` result `{ protocolVersion, capabilities, serverInfo, instructions }`.
#[must_use]
pub fn initialize_result(version: &str, server_info: &Value, instructions: &str) -> Value {
    Value::object([
        ("protocolVersion", Value::from(version)),
        ("capabilities", capabilities()),
        ("serverInfo", server_info.clone()),
        ("instructions", Value::from(instructions)),
    ])
}

/// Gives the `server/discover` result
/// `{ supportedVersions, capabilities, serverInfo, instructions, resultType }`.
#[must_use]
pub fn discover_result(server_info: &Value, instructions: &str) -> Value {
    finish(
        Era::Modern,
        Value::object([
            ("supportedVersions", strings(&SUPPORTED)),
            ("capabilities", capabilities()),
            ("serverInfo", server_info.clone()),
            ("instructions", Value::from(instructions)),
        ]),
    )
}

/// Gives `result` in `era`: a modern result gains `resultType: "complete"`.
#[must_use]
pub fn finish(era: Era, result: Value) -> Value {
    match (era, result) {
        (Era::Modern, Value::Object(mut object)) => {
            let _ = object.insert("resultType", Value::from("complete"));
            Value::Object(object)
        }
        (_, result) => result,
    }
}

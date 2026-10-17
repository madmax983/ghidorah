//! JSON-RPC 2.0 messages of the MCP server (design Section 10.8).
//!
//! [`classify`] reads one line. It gives a [`Message`] or the error reply of a protocol fault:
//!
//! | Input | Reply |
//! |---|---|
//! | Not JSON | -32700 with `id: null` |
//! | A JSON array (batch) | -32600 with `id: null` |
//! | Not an object, no `jsonrpc: "2.0"`, a bad `method` or a bad `id` | -32600 |
//! | `params` that is not an object | -32602 |
//!
//! A request ID is a string or an integer. A message with `result` or `error` and no
//! `method` is a reply of the client. The server ignores it.

use std::fmt;

use ghidorah_json::{Limits, Number, Value};

/// The JSON-RPC version.
pub const JSONRPC: &str = "2.0";

/// Parse error.
pub const PARSE_ERROR: i64 = -32_700;
/// Invalid request.
pub const INVALID_REQUEST: i64 = -32_600;
/// Method not found.
pub const METHOD_NOT_FOUND: i64 = -32_601;
/// Invalid params.
pub const INVALID_PARAMS: i64 = -32_602;
/// Internal protocol error.
pub const INTERNAL_ERROR: i64 = -32_603;
/// Unsupported protocol version (MCP 2026-07-28).
pub const UNSUPPORTED_VERSION: i64 = -32_022;

/// The parse limits of one line: depth 128 and 16 MiB.
pub const LIMITS: Limits = Limits::DEFAULT;

/// The ID of a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestId {
    /// An integer ID.
    Int(i128),
    /// A string ID.
    Str(String),
}

impl RequestId {
    /// Gives the ID of a JSON value: a string or an integer, else `None`.
    #[must_use]
    pub fn of(value: &Value) -> Option<Self> {
        match value {
            Value::String(text) => Some(Self::Str(text.clone())),
            Value::Number(n) if n.is_integer() => n
                .as_i64()
                .map(i128::from)
                .or_else(|| n.as_u64().map(i128::from))
                .map(Self::Int),
            _ => None,
        }
    }

    /// Gives the JSON form of the ID.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Int(v) => Number::parse(&v.to_string()).map_or(Value::Null, Value::Number),
            Self::Str(text) => Value::from(text.as_str()),
        }
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Str(text) => write!(f, "{text:?}"),
        }
    }
}

/// One request of the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request ID.
    pub id: RequestId,
    /// The method name.
    pub method: String,
    /// The params object, or `None`.
    pub params: Option<Value>,
    /// The whole message, for the call recorder.
    pub message: Value,
}

/// One classified message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A request: it gets one reply.
    Request(Request),
    /// A notification: it gets no reply.
    Notification {
        /// The method name.
        method: String,
        /// The params object, or `None`.
        params: Option<Value>,
    },
    /// A reply of the client. The server ignores it.
    Reply,
}

/// Gives the error reply `{ jsonrpc, id, error: { code, message, data? } }`.
///
/// `id` is `None` when the request has no valid ID. The reply then has `id: null`.
#[must_use]
pub fn error(id: Option<&RequestId>, code: i64, message: &str, data: Option<Value>) -> Value {
    let _ = (id, code, message, data);
    Value::Null
}

/// Gives the result reply `{ jsonrpc, id, result }`.
#[must_use]
pub fn result(id: &RequestId, result: Value) -> Value {
    let _ = (id, result);
    Value::Null
}

/// Gives the notification `{ jsonrpc, method, params }`.
#[must_use]
pub fn notification(method: &str, params: Value) -> Value {
    let _ = (method, params);
    Value::Null
}

/// Classifies one input line.
///
/// # Errors
///
/// Returns the error reply of a protocol fault (see the module table).
pub fn classify(line: &[u8]) -> Result<Message, Value> {
    let _ = line;
    Err(Value::Null)
}

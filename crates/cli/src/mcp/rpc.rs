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

use ghidorah_json::{Limits, Number, Object, Value};

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
    let mut body = Object::new();
    body.push("code", Value::from(code));
    body.push("message", Value::from(message));
    if let Some(data) = data {
        body.push("data", data);
    }
    Value::object([
        ("jsonrpc", Value::from(JSONRPC)),
        ("id", id.map_or(Value::Null, RequestId::to_json)),
        ("error", Value::Object(body)),
    ])
}

/// Gives the result reply `{ jsonrpc, id, result }`.
#[must_use]
pub fn result(id: &RequestId, result: Value) -> Value {
    Value::object([
        ("jsonrpc", Value::from(JSONRPC)),
        ("id", id.to_json()),
        ("result", result),
    ])
}

/// Gives the notification `{ jsonrpc, method, params }`.
#[must_use]
pub fn notification(method: &str, params: Value) -> Value {
    Value::object([
        ("jsonrpc", Value::from(JSONRPC)),
        ("method", Value::from(method)),
        ("params", params),
    ])
}

/// The message of a line that is not JSON.
const NOT_JSON: &str = "The line is not valid JSON. Each line must hold one JSON-RPC message.";

/// The message of a batch array.
const BATCH: &str = "The line holds a batch array. No supported protocol version allows batches. Send one message on each line.";

/// The message of a message that is not a valid request.
const NOT_REQUEST: &str = "The message is not a valid JSON-RPC 2.0 request. Send an object with jsonrpc \"2.0\", a string method and a string or integer id.";

/// The message of params that are not an object.
const PARAMS_NOT_OBJECT: &str = "The params member is not an object. Send the params as an object.";

/// Classifies one input line.
///
/// # Errors
///
/// Returns the error reply of a protocol fault (see the module table).
pub fn classify(line: &[u8]) -> Result<Message, Value> {
    let value = ghidorah_json::parse_bytes(line, &LIMITS)
        .map_err(|_| error(None, PARSE_ERROR, NOT_JSON, None))?;
    let object = match &value {
        Value::Object(object) => object,
        Value::Array(_) => return Err(error(None, INVALID_REQUEST, BATCH, None)),
        _ => return Err(error(None, INVALID_REQUEST, NOT_REQUEST, None)),
    };
    let id = match object.get("id") {
        None => None,
        Some(raw) => Some(
            RequestId::of(raw).ok_or_else(|| error(None, INVALID_REQUEST, NOT_REQUEST, None))?,
        ),
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC) {
        return Err(error(id.as_ref(), INVALID_REQUEST, NOT_REQUEST, None));
    }
    let Some(method) = object.get("method") else {
        let reply = object.contains_key("result") || object.contains_key("error");
        return match (reply, id) {
            (true, Some(_)) => Ok(Message::Reply),
            (_, id) => Err(error(id.as_ref(), INVALID_REQUEST, NOT_REQUEST, None)),
        };
    };
    let Some(method) = method.as_str().map(str::to_owned) else {
        return Err(error(id.as_ref(), INVALID_REQUEST, NOT_REQUEST, None));
    };
    let params = object.get("params");
    let Some(id) = id else {
        // A notification never gets a reply, so params that are not an object drop silently.
        let params = params.filter(|p| p.as_object().is_some()).cloned();
        return Ok(Message::Notification { method, params });
    };
    let params = match params {
        None => None,
        Some(Value::Object(params)) => Some(Value::Object(params.clone())),
        Some(Value::Array(_)) => {
            return Err(error(Some(&id), INVALID_PARAMS, PARAMS_NOT_OBJECT, None));
        }
        Some(_) => return Err(error(Some(&id), INVALID_REQUEST, NOT_REQUEST, None)),
    };
    Ok(Message::Request(Request {
        id,
        method,
        params,
        message: value,
    }))
}

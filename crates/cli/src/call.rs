//! `ghidorah call` and `ghidorah jsonl` (design Section 10.14).
//!
//! `call` runs one tool call and prints its envelope on stdout. The exit code is 0 for
//! `ok: true` and 1 for `ok: false`. Bad arguments of the command line give exit code 2. A
//! call with the `binary_id` of a project in the projects root opens that project first, so
//! one `call` can follow another (read-only when another writer holds the lock).
//!
//! `jsonl` reads independent requests `{ "id", "tool", "args" }` from stdin, one per line.
//! It writes one line per request: the envelope with the `id` of the request as its first
//! member. A line that is not a request gives a failure line with `INVALID_ARGUMENT`.
//! The exit code is the most severe code of all lines: 2 for a bad line, else 1 for a tool
//! error, else 0.

use std::io::Read;
use std::path::Path;

use ghidorah_base::{BinaryId, ErrorCode};
use ghidorah_json::{Limits, Object, Value};
use ghidorah_tools::{Request, ToolError, dispatch};

use crate::Streams;
use crate::argv::{ArgsInput, CallArgs, PrintFormat, SessionFlags};
use crate::backend::{Backend, OpenError, Options};
use crate::config::Env;
use crate::exit::Exit;
use crate::mcp::frame::{Frame, LineReader, MAX_LINE};
use crate::out;
use crate::select;

/// The default session label of `call` and `jsonl`.
pub const SESSION: &str = "cli";

/// The shape of one `jsonl` request, for the `details.expected` of a bad line.
const REQUEST_SHAPE: &str = "one JSON object {\"id\", \"tool\", \"args\"} on each line";

/// Gives a JSON pointer token: `~` becomes `~0` and `/` becomes `~1`.
fn token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Gives the text lines of format [`PrintFormat::Text`]: one line per scalar value, with
/// the JSON pointer, a space and the value. A string prints without quotes.
///
/// An empty object or array prints as `{}` or `[]`.
#[must_use]
pub fn text_lines(value: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let mut stack = vec![(String::new(), value)];
    while let Some((path, value)) = stack.pop() {
        match value {
            Value::Object(object) if !object.is_empty() => {
                for (key, member) in object.members().iter().rev() {
                    stack.push((format!("{path}/{}", token(key)), member));
                }
            }
            Value::Array(items) if !items.is_empty() => {
                for (index, item) in items.iter().enumerate().rev() {
                    stack.push((format!("{path}/{index}"), item));
                }
            }
            leaf => {
                let text = select::value_line(leaf);
                lines.push(if path.is_empty() {
                    text
                } else {
                    format!("{path} {text}")
                });
            }
        }
    }
    lines
}

/// Gives the stdout text of `envelope` in `format`, without the last line end.
#[must_use]
pub fn render(envelope: &Value, format: PrintFormat) -> String {
    match format {
        PrintFormat::Json => ghidorah_json::write_pretty(envelope),
        PrintFormat::Jsonl => ghidorah_json::write(envelope),
        PrintFormat::Text => text_lines(envelope).join("\n"),
    }
}

/// Reads at most [`MAX_LINE`] bytes of argument text from `source`.
fn read_capped(source: &mut dyn Read, what: &str) -> Result<String, String> {
    let mut text = String::new();
    let cap = u64::try_from(MAX_LINE)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    source
        .take(cap)
        .read_to_string(&mut text)
        .map_err(|e| format!("The {what} does not read: {e}. Send UTF-8 JSON text."))?;
    if text.len() > MAX_LINE {
        return Err(format!(
            "The {what} is longer than 16 MiB. Send smaller arguments."
        ));
    }
    Ok(text)
}

/// Gives the tool arguments of `input`.
fn read_args(input: &ArgsInput, stdin: &mut dyn Read) -> Result<Value, String> {
    let text = match input {
        ArgsInput::Empty => return Ok(Value::Object(Object::new())),
        ArgsInput::Inline(text) => text.clone(),
        ArgsInput::Stdin => read_capped(stdin, "argument text on stdin")?,
        ArgsInput::File(path) => {
            let mut file = std::fs::File::open(path).map_err(|e| {
                format!(
                    "The argument file {} does not open: {e}. Check the path.",
                    path.display()
                )
            })?;
            read_capped(&mut file, "argument file")?
        }
    };
    match ghidorah_json::parse(text.trim(), &Limits::DEFAULT) {
        Ok(Value::Object(object)) => Ok(Value::Object(object)),
        Ok(_) => {
            Err("The tool arguments are not a JSON object. Send an object such as {}.".to_owned())
        }
        Err(e) => Err(format!(
            "The tool arguments are not valid JSON: {e}. Send a JSON object."
        )),
    }
}

/// Opens the backend of one `ghidorah call`.
///
/// Each call is a new process, so a `binary_id` names no open binary. A call with a valid
/// `binary_id`, other than `binary_load`, opens the project of that binary from the projects
/// root first. A project that another writer holds opens read-only. A project that does not
/// open leaves the call to give its own error, for example `UNKNOWN_BINARY`.
fn open_for<B: Backend>(options: &Options, tool: &str, tool_args: &Value) -> Result<B, OpenError> {
    let id = tool_args
        .get("binary_id")
        .and_then(Value::as_str)
        .filter(|text| BinaryId::parse(text).is_ok());
    if let Some(id) = id.filter(|_| tool != "binary_load") {
        let mut with = options.clone();
        with.open.push(id.to_owned());
        if let Ok(backend) = B::open(&with) {
            return Ok(backend);
        }
        with.read_only = true;
        if let Ok(backend) = B::open(&with) {
            return Ok(backend);
        }
    }
    B::open(options)
}

/// Runs `ghidorah call` with the backend `B`.
pub fn call<B: Backend>(args: &CallArgs, env: &Env, streams: &mut Streams) -> Exit {
    let mut args = args.clone();
    if let ArgsInput::File(path) = &args.input {
        args.input = ArgsInput::File(env.cwd.join(Path::new(path)));
    }
    let tool_args = match read_args(&args.input, &mut streams.stdin) {
        Ok(value) => value,
        Err(message) => {
            out::log(&mut streams.stderr, &message);
            return Exit::Usage;
        }
    };
    let options = Options::with_flags(env, &args.session, SESSION);
    let mut backend = match open_for::<B>(&options, &args.tool, &tool_args) {
        Ok(backend) => backend,
        Err(error) => {
            out::log(&mut streams.stderr, &error.message);
            return Exit::Usage;
        }
    };
    call_with(&mut backend, &args, tool_args, streams)
}

/// Runs `ghidorah call` on the open backend `backend`.
pub fn call_on<B: Backend>(backend: &mut B, args: &CallArgs, streams: &mut Streams) -> Exit {
    let tool_args = match read_args(&args.input, &mut streams.stdin) {
        Ok(value) => value,
        Err(message) => {
            out::log(&mut streams.stderr, &message);
            return Exit::Usage;
        }
    };
    call_with(backend, args, tool_args, streams)
}

/// Runs the tool call of `args` with the arguments `tool_args` on `backend`, and prints it.
fn call_with<B: Backend>(
    backend: &mut B,
    args: &CallArgs,
    tool_args: Value,
    streams: &mut Streams,
) -> Exit {
    let mut request = Request::new(&args.tool, tool_args);
    request.session.clone_from(&args.session.session);
    let envelope = dispatch(backend, &request);
    let json = envelope.to_json();
    let text = match &args.select {
        Some(pointer) => select::lines(&json, pointer).join("\n"),
        None => render(&json, args.format),
    };
    if !text.is_empty()
        && let Err(stop) = out::line(&mut streams.stdout, &text)
    {
        return stop.exit();
    }
    Exit::of_ok(envelope.ok())
}

/// Runs `ghidorah jsonl` with the backend `B`.
pub fn jsonl<B: Backend>(flags: &SessionFlags, env: &Env, streams: &mut Streams) -> Exit {
    let mut backend = match B::open(&Options::with_flags(env, flags, SESSION)) {
        Ok(backend) => backend,
        Err(error) => {
            out::log(&mut streams.stderr, &error.message);
            return Exit::Usage;
        }
    };
    jsonl_on(&mut backend, flags.session.as_deref(), streams)
}

/// The parts of one `jsonl` request: `(id, tool, args)`.
type Parts = (Value, String, Value);

/// Reads one `jsonl` request. A bad line gives its `id` and the bad member.
fn request_of(bytes: &[u8]) -> Result<Parts, (Value, &'static str)> {
    let Ok(Value::Object(object)) = ghidorah_json::parse_bytes(bytes, &Limits::DEFAULT) else {
        return Err((Value::Null, "line"));
    };
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    let Some(tool) = object.get("tool").and_then(Value::as_str) else {
        return Err((id, "tool"));
    };
    let args = match object.get("args") {
        None => Value::Object(Object::new()),
        Some(Value::Object(args)) => Value::Object(args.clone()),
        Some(_) => return Err((id, "args")),
    };
    Ok((id, tool.to_owned(), args))
}

/// Gives the failure line of a bad request line.
fn bad_line(id: Value, field: &'static str) -> Value {
    let error = ToolError::new(ErrorCode::InvalidArgument)
        .var("field", field)
        .path(&format!("/{field}"))
        .detail("expected", Value::from(REQUEST_SHAPE));
    Value::object([
        ("id", id),
        ("ok", Value::Bool(false)),
        ("error", error.to_json()),
    ])
}

/// Gives `envelope` with `id` as its first member.
fn with_id(id: Value, envelope: Value) -> Value {
    let mut out = Object::new();
    out.push("id", id);
    if let Value::Object(members) = envelope {
        for (key, value) in members.into_members() {
            out.push(key, value);
        }
    }
    Value::Object(out)
}

/// Runs `ghidorah jsonl` on the open backend `backend` with the session label `session`.
pub fn jsonl_on<B: Backend>(backend: &mut B, session: Option<&str>, streams: &mut Streams) -> Exit {
    let mut exit = Exit::Ok;
    let mut reader = LineReader::new(&mut streams.stdin, MAX_LINE);
    loop {
        let frame = match reader.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                out::log(
                    &mut streams.stderr,
                    &format!("stdin does not read: {error}."),
                );
                return exit.worst(Exit::Usage);
            }
        };
        let line = match frame {
            Frame::Line(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => continue,
            Frame::Line(bytes) => match request_of(&bytes) {
                Ok((id, tool, args)) => {
                    let mut request = Request::new(&tool, args);
                    request.session = session.map(str::to_owned);
                    let envelope = dispatch(backend, &request);
                    exit = exit.worst(Exit::of_ok(envelope.ok()));
                    with_id(id, envelope.to_json())
                }
                Err((id, field)) => {
                    exit = exit.worst(Exit::Usage);
                    bad_line(id, field)
                }
            },
            Frame::TooLong { .. } => {
                exit = exit.worst(Exit::Usage);
                bad_line(Value::Null, "line")
            }
        };
        if let Err(stop) = out::line(&mut streams.stdout, &ghidorah_json::write(&line)) {
            return stop.exit();
        }
    }
    exit
}

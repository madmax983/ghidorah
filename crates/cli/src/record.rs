//! The call recorder and its replay (design Sections 10.14 and 12.7, AC-201).
//!
//! `ghidorah mcp --record FILE` appends one JSON line per answered request:
//! `{ seq, request, response, chars, copies, ms }`.
//!
//! | Field | Content |
//! |---|---|
//! | `seq` | The number of the line, from 1 |
//! | `request` | The JSON-RPC request |
//! | `response` | The JSON-RPC reply |
//! | `chars` | The characters of the compact reply |
//! | `copies` | The envelope copies in the reply: 2 for mode `both`, 1 for the other modes, 0 for a reply that is not a tool result |
//! | `ms` | The time of the call in milliseconds. With `GHIDORAH_FIXED_TIME` it is 0. |
//!
//! [`replay`] answers the recorded requests again on a new backend. It compares each reply
//! with the recorded reply. It ignores `ms`. The recorder never writes to stdout.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use ghidorah_base::FixedClock;
use ghidorah_json::{Limits, Value};
use ghidorah_tools::ContentMode;

use crate::backend::{Backend, OpenError, Options};
use crate::mcp::server::Server;

/// One line of a call record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The number of the line, from 1.
    pub seq: u64,
    /// The JSON-RPC request.
    pub request: Value,
    /// The JSON-RPC reply.
    pub response: Value,
    /// The characters of the compact reply.
    pub chars: u64,
    /// The envelope copies in the reply.
    pub copies: u64,
    /// The time of the call in milliseconds.
    pub ms: u64,
}

impl Entry {
    /// Gives the JSON form `{ seq, request, response, chars, copies, ms }`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("seq", Value::from(self.seq)),
            ("request", self.request.clone()),
            ("response", self.response.clone()),
            ("chars", Value::from(self.chars)),
            ("copies", Value::from(self.copies)),
            ("ms", Value::from(self.ms)),
        ])
    }

    /// Reads an entry from its JSON form.
    ///
    /// # Errors
    ///
    /// Returns a message when a member is missing or has the wrong type.
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let number = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("the member {key} is not a number"))
        };
        let member = |key: &str| {
            value
                .get(key)
                .cloned()
                .ok_or_else(|| format!("the member {key} is missing"))
        };
        Ok(Self {
            seq: number("seq")?,
            request: member("request")?,
            response: member("response")?,
            chars: number("chars")?,
            copies: number("copies")?,
            ms: number("ms")?,
        })
    }
}

/// A record file that does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    /// The 1-based line of the fault.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Line {} of the record is not valid: {}",
            self.line, self.message
        )
    }
}

impl std::error::Error for RecordError {}

/// The writer of a call record.
pub struct Recorder {
    out: Box<dyn Write + Send>,
    seq: u64,
    error: Option<io::Error>,
}

impl Recorder {
    /// Makes a recorder that writes to `out`.
    #[must_use]
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            out,
            seq: 0,
            error: None,
        }
    }

    /// Opens the record file at `path` for append. It makes the file when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns the open error of the file.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::new(Box::new(file)))
    }

    /// Writes the line of one answered request.
    ///
    /// After the first write error, the recorder keeps the error and writes no more lines.
    pub fn record(&mut self, request: &Value, response: &Value, copies: u64, ms: u64) {
        if self.error.is_some() {
            return;
        }
        self.seq = self.seq.saturating_add(1);
        let chars = ghidorah_json::write(response).chars().count();
        let entry = Entry {
            seq: self.seq,
            request: request.clone(),
            response: response.clone(),
            chars: u64::try_from(chars).unwrap_or(u64::MAX),
            copies,
            ms,
        };
        let mut line = ghidorah_json::write(&entry.to_json());
        line.push('\n');
        if let Err(error) = self
            .out
            .write_all(line.as_bytes())
            .and_then(|()| self.out.flush())
        {
            self.error = Some(error);
        }
    }

    /// Takes the first write error, if any.
    pub const fn take_error(&mut self) -> Option<io::Error> {
        self.error.take()
    }
}

/// Reads the lines of a call record. Blank lines do not count.
///
/// # Errors
///
/// Returns [`RecordError`] for a line that is not an entry.
pub fn parse(text: &str) -> Result<Vec<Entry>, RecordError> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = |message: String| RecordError {
            line: index.saturating_add(1),
            message,
        };
        let value = ghidorah_json::parse(line, &Limits::DEFAULT).map_err(|e| at(e.to_string()))?;
        entries.push(Entry::from_json(&value).map_err(at)?);
    }
    Ok(entries)
}

/// One reply of a replay that differs from the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// The `seq` of the entry.
    pub seq: u64,
    /// The recorded reply.
    pub expected: Value,
    /// The reply of the replay, or `None` when the replay gave no reply.
    pub actual: Option<Value>,
}

/// Answers the requests of `entries` again on a new backend of `options` in mode `content`.
///
/// Gives the replies that differ from the record. The `ms` field does not count.
///
/// # Errors
///
/// Returns [`OpenError`] when the backend does not open.
pub fn replay<B: Backend>(
    entries: &[Entry],
    options: &Options,
    content: ContentMode,
) -> Result<Vec<Diff>, OpenError> {
    let backend = B::open(options)?;
    let mut server = Server::new(backend, content, Box::new(FixedClock::new(0)));
    let mut diffs = Vec::new();
    for entry in entries {
        let line = ghidorah_json::write(&entry.request);
        let actual = server
            .handle_line(line.as_bytes())
            .into_iter()
            .filter_map(|text| ghidorah_json::parse(&text, &Limits::DEFAULT).ok())
            .find(|message| message.get("id").is_some());
        if actual.as_ref() != Some(&entry.response) {
            diffs.push(Diff {
                seq: entry.seq,
                expected: entry.response.clone(),
                actual,
            });
        }
    }
    Ok(diffs)
}
